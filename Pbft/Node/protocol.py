import json
from typing import Any, Dict, List

# crypto helper used by equivocation attack
from keys import create_authenticator

from common import (
    MSG_PREPREPARE,
    MSG_PREPARE,
    MSG_COMMIT,
    MSG_REPLY,
    leader_for_view,
)
from node import sha256_digest, F

# all functions expect 'node' as first arg

def handle_request(node, envelope: Dict[str, Any]):
    # handle client write request
    if not node.active:
        return

    msg = envelope.get("msg")
    sender = envelope.get("sender")
    op = msg.get("op", {})
    client_id = msg.get("c")
    tstamp = msg.get("t")

    if op.get("type") == "read":
        node.handle_read_request(envelope)
        return

    node.log_message("REQUEST", msg, "RECEIVED")

    if node.in_view_change:
        node.deferred_client_requests.append(envelope)
        return

    if node.id != leader_for_view(node.view, node.n):
        if not node.in_view_change and not (node.timer and node.timer.is_alive()):
            node.start_request_timer()
        return

    request_key = (client_id, tstamp)

    with node.state_lock:
        if request_key in node.processed_requests:
            existing_seq = node.processed_requests[request_key]
            existing_st = node.seq_state.get(existing_seq)
            if existing_st and existing_st.get("executed"):
                result = existing_st.get("result")
                if result:
                    reply_msg = {"type": MSG_REPLY, "v": node.view, "t": tstamp, "c": client_id, "i": node.id, "r": result}
                    node.send_to_client(client_id, reply_msg)
            return

    seq = node.next_seq
    if seq >= node.high:
        return
    node.next_seq += 1

    d = sha256_digest(msg)

    with node.state_lock:
        node.processed_requests[request_key] = seq
        st = node.seq_state.setdefault(seq, {
            "preprepare": None, "prepares": {}, "prepare_multicast": None,
            "commits": {}, "commit_multicast": None, "executed": False, "status": "PP",
            "sent_prepare": False, "result": None
        })
        st["preprepare"] = {"view": node.view, "seq": seq, "digest": d, "request": msg, "sender": node.id}
        st["prepares"][node.id] = {"type": MSG_PREPARE, "v": node.view, "seq": seq, "d": d, "i": node.id}
        st["sent_prepare"] = True

    if getattr(node.attack_config, "equivocation_attack", False):
        node._handle_equivocation_attack(seq, msg, d)
    else:
        preprepare_msg = {"type": MSG_PREPREPARE, "v": node.view, "seq": seq, "d": d, "m": msg}
        node.multicast_with_authenticator(preprepare_msg)
        node.log_message("PREPREPARE", preprepare_msg, "SENT")


def _handle_equivocation_attack(node, base_seq: int, msg: Dict, digest: str):
    # equivocation: leader sends conflicting preprepares
    all_recipients = [r for r in list(node.out_queues.keys()) if r != node.id]

    for target in all_recipients:
        if target in getattr(node.attack_config, "equivocation_targets", []):
            alt_seq = base_seq + 1
            preprepare_msg = {"type": MSG_PREPREPARE, "v": node.view, "seq": alt_seq, "d": digest, "m": msg}
        else:
            preprepare_msg = {"type": MSG_PREPREPARE, "v": node.view, "seq": base_seq, "d": digest, "m": msg}

        msg_bytes = json.dumps(preprepare_msg, sort_keys=True).encode("utf-8")
        auth = create_authenticator(node.keyring, node.id, [target], msg_bytes)

        if getattr(node.attack_config, "sign_attack", False):
            auth = node.attack_config.corrupt_signature(auth)

        envelope = {"msg": preprepare_msg, "auth": auth, "sender": node.id}

        if getattr(node.attack_config, "dark_attack", False) and target in getattr(node.attack_config, "dark_targets", set()):
            continue

        q = node.out_queues.get(target)
        if q:
            q.put(envelope)


def handle_preprepare(node, envelope: Dict[str, Any]):
    # backup receives PRE-PREPARE
    if not node.active:
        return

    if not node.verify_authenticator_for_self(envelope):
        return

    msg = envelope.get("msg")
    v = msg.get("v")
    seq = msg.get("seq")
    d = msg.get("d")
    m = msg.get("m")
    leader = envelope.get("sender")

    node.log_message("PREPREPARE", msg, "RECEIVED")

    if node.in_view_change:
        return
    if v != node.view:
        return
    if seq < node.low or seq >= node.high:
        return
    if sha256_digest(m) != d:
        return

    with node.state_lock:
        st = node.seq_state.setdefault(seq, {
            "preprepare": None, "prepares": {}, "prepare_multicast": None,
            "commits": {}, "commit_multicast": None, "executed": False, "status": "PP",
            "sent_prepare": False, "result": None
        })
        st["preprepare"] = {"view": v, "seq": seq, "digest": d, "request": m, "sender": leader}

        if getattr(node.attack_config, "crash_attack", False) and getattr(node.attack_config, "should_send_preprepare_only", None) and node.attack_config.should_send_preprepare_only():
            st["sent_prepare"] = True
        else:
            if not st.get("sent_prepare", False):
                prepare_msg = {"type": MSG_PREPARE, "v": v, "seq": seq, "d": d, "i": node.id}
                leader_id = leader_for_view(node.view, node.n)
                node.send_to_node(leader_id, prepare_msg)
                node.log_message("PREPARE", prepare_msg, "SENT")
                st["sent_prepare"] = True

    if not node.in_view_change:
        node.stop_request_timer()
        node.start_request_timer()


def handle_prepare_point_to_point(node, envelope: Dict[str, Any]):
    # leader receives PREPARE from backup
    if not node.active:
        return

    if not node.verify_single_mac_for_self(envelope):
        return

    msg = envelope.get("msg")
    seq = msg.get("seq")
    i = msg.get("i")

    node.log_message("PREPARE", msg, "RECEIVED")

    with node.state_lock:
        st = node.seq_state.setdefault(seq, {
            "preprepare": None, "prepares": {}, "prepare_multicast": None,
            "commits": {}, "commit_multicast": None, "executed": False, "status": "PP",
            "sent_prepare": False, "result": None
        })
        st["prepares"][i] = msg

    node._try_to_multicast_prepare(seq)


def _try_to_multicast_prepare(node, seq: int):
    # leader checks 2f+1 prepares and multicasts PREPARE_MULTICAST
    if not node.active:
        return
    if node.id != leader_for_view(node.view, node.n):
        return

    if getattr(node.attack_config, "crash_attack", False) and node.attack_config.should_block_prepare(True):
        return

    pm = None

    with node.state_lock:
        st = node.seq_state.get(seq)
        if not st:
            return
        if st.get("prepare_multicast") is not None:
            return

        prepares = st["prepares"]
        num_prepares = len(prepares)

        if num_prepares >= (2 * F + 1):
            pm_list = list(prepares.values())
            d = st["preprepare"]["digest"]
            prepare_multicast = {"type": "PREPARE_MULTICAST", "v": node.view, "seq": seq, "d": d, "prepares": pm_list}
            st["prepare_multicast"] = prepare_multicast
            st["status"] = "P"

            commit_msg = {"type": MSG_COMMIT, "v": node.view, "seq": seq, "d": d, "i": node.id}
            st["commits"][node.id] = commit_msg

            pm = prepare_multicast

    if pm is not None:
        node.multicast_with_authenticator(pm)
        node.log_message("PREPARE_MULTICAST", pm, "SENT")


def handle_prepare_multicast(node, envelope: Dict[str, Any]):
    # backup receives PREPARE_MULTICAST
    if not node.active:
        return

    if not node.verify_authenticator_for_self(envelope):
        return

    msg = envelope.get("msg")
    v = msg.get("v")
    seq = msg.get("seq")
    d = msg.get("d")
    prepares = msg.get("prepares", [])

    node.log_message("PREPARE_MULTICAST", msg, "RECEIVED")

    if v != node.view:
        return

    with node.state_lock:
        st = node.seq_state.setdefault(seq, {
            "preprepare": None, "prepares": {}, "prepare_multicast": None,
            "commits": {}, "commit_multicast": None, "executed": False, "status": "P",
            "sent_prepare": False, "result": None
        })
        st["prepare_multicast"] = msg
        for p in prepares:
            pid = p.get("i")
            st["prepares"][pid] = p

    if getattr(node.attack_config, "crash_attack", False) and getattr(node.attack_config, "should_send_preprepare_only", None) and node.attack_config.should_send_preprepare_only():
        return

    commit_msg = {"type": MSG_COMMIT, "v": v, "seq": seq, "d": d, "i": node.id}
    leader_id = leader_for_view(node.view, node.n)
    node.send_to_node(leader_id, commit_msg)
    node.log_message("COMMIT", commit_msg, "SENT")


def handle_commit_point_to_point(node, envelope: Dict[str, Any]):
    # leader receives COMMIT from backup
    if not node.active:
        return

    if not node.verify_single_mac_for_self(envelope):
        return

    msg = envelope.get("msg")
    seq = msg.get("seq")
    i = msg.get("i")

    node.log_message("COMMIT", msg, "RECEIVED")

    with node.state_lock:
        st = node.seq_state.setdefault(seq, {
            "preprepare": None, "prepares": {}, "prepare_multicast": None,
            "commits": {}, "commit_multicast": None, "executed": False, "status": "P",
            "sent_prepare": False, "result": None
        })
        st["commits"][i] = msg

    node._try_to_multicast_commit(seq)


def _try_to_multicast_commit(node, seq: int):
    # leader checks 2f+1 commits and multicasts COMMIT_MULTICAST
    if not node.active:
        return
    if node.id != leader_for_view(node.view, node.n):
        return

    if getattr(node.attack_config, "crash_attack", False) and node.attack_config.should_block_commit(True):
        return

    cm = None

    with node.state_lock:
        st = node.seq_state.get(seq)
        if not st:
            return
        if st.get("commit_multicast") is not None:
            return

        commits = st["commits"]
        num_commits = len(commits)

        if num_commits >= (2 * F + 1):
            cm_list = list(commits.values())
            d = st["preprepare"]["digest"]
            commit_multicast = {"type": "COMMIT_MULTICAST", "v": node.view, "seq": seq, "d": d, "commits": cm_list}
            st["commit_multicast"] = commit_multicast
            st["status"] = "C"

            cm = commit_multicast

    if cm is not None:
        node.multicast_with_authenticator(cm)
        node.log_message("COMMIT_MULTICAST", cm, "SENT")
        node._try_to_execute(seq)


def handle_commit_multicast(node, envelope: Dict[str, Any]):
    # backup receives COMMIT_MULTICAST
    if not node.active:
        return

    if not node.verify_authenticator_for_self(envelope):
        return

    msg = envelope.get("msg")
    v = msg.get("v")
    seq = msg.get("seq")
    d = msg.get("d")
    commits = msg.get("commits", [])

    node.log_message("COMMIT_MULTICAST", msg, "RECEIVED")

    if v != node.view:
        return

    with node.state_lock:
        st = node.seq_state.setdefault(seq, {
            "preprepare": None, "prepares": {}, "prepare_multicast": None,
            "commits": {}, "commit_multicast": None, "executed": False, "status": "C",
            "sent_prepare": False, "result": None
        })
        st["commit_multicast"] = msg
        for c in commits:
            pid = c.get("i")
            st["commits"][pid] = c

    node._try_to_execute(seq)


def _try_to_execute(node, seq: int):
    # attempt to execute a sequence
    if not node.active:
        return

    with node.state_lock:
        st = node.seq_state.get(seq)
        if not st or st.get("executed"):
            return

        if st.get("preprepare") is None:
            return
        if st.get("prepare_multicast") is None:
            return
        if st.get("commit_multicast") is None:
            return

        d1 = st["preprepare"]["digest"]
        d2 = st["prepare_multicast"]["d"]
        d3 = st["commit_multicast"]["d"]

        if not (d1 == d2 == d3):
            return

        req = st["preprepare"]["request"]
        op = req.get("op", {})
        client_id = req.get("c")
        tstamp = req.get("t")

        result = {}
        if op.get("type") == "transfer":
            sname = op.get("s")
            rname = op.get("r")
            amt = int(op.get("amt", 0))
            if node.datastore.get(sname, 0) >= amt:
                node.datastore[sname] -= amt
                node.datastore[rname] = node.datastore.get(rname, 0) + amt
                result = {"status": "EXECUTED", "detail": f"{sname}->{rname}:{amt}"}
            else:
                result = {"status": "FAILED", "detail": "insufficient"}
        else:
            sname = op.get("s")
            result = {"status": "EXECUTED", "balance": node.datastore.get(sname, 0)}

        st["executed"] = True
        st["status"] = "E"
        st["result"] = result

    exec_msg = {"seq": seq, "result": result, "v": node.view}
    node.log_message("EXECUTE", exec_msg, "PROCESSED")

    reply_msg = {"type": MSG_REPLY, "v": node.view, "t": tstamp, "c": client_id, "i": node.id, "r": result}
    node.send_to_client(client_id, reply_msg)
    node.log_message("REPLY", reply_msg, "SENT")

    node.stop_request_timer()

    if node.monitor_queue is not None:
        try:
            snapshot = dict(node.datastore)
            node.monitor_queue.put({"type": "EXECUTED_NOTIFY", "t": tstamp, "node": node.id, "seq": seq, "op": op, "result": result})
            node.monitor_queue.put({"type": "DB_SNAPSHOT", "node": node.id, "seq": seq, "db": snapshot, "t": tstamp})
        except Exception:
            pass


def handle_read_request(node, envelope: Dict[str, Any]):
    # handle immediate read request
    if not node.active:
        return

    msg = envelope.get("msg")
    op = msg.get("op", {})
    client_id = msg.get("c")
    tstamp = msg.get("t")

    if op.get("type") == "read":
        sname = op.get("s")
        balance = node.datastore.get(sname, 0)
        result = {"status": "OK", "balance": balance}
        reply_msg = {"type": MSG_REPLY, "v": node.view, "t": tstamp, "c": client_id, "i": node.id, "r": result}
        node.send_to_client(client_id, reply_msg)
