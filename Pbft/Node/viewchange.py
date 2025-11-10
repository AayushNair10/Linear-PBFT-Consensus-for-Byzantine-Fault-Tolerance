import json
import time
from typing import Any, Dict


from common import leader_for_view, MSG_PREPARE, MSG_COMMIT

from node import sha256_digest, F, WINDOW_SIZE
from attacks import AttackConfig

# functions receive 'node' as first arg

def start_view_change(node, target_view: int):
    # start view-change and multicast VIEW_CHANGE
    if not node.active:
        return

    node.stop_request_timer()
    node.start_view_change_timer(target_view)

    with node.state_lock:
        if node.id in node.view_change_msgs.get(target_view, {}):
            return

    node.in_view_change = True

    with node.state_lock:
        P = []
        for seq, st in node.seq_state.items():
            if seq <= node.low:
                continue
            pre = st.get("preprepare")
            prepares = st.get("prepares", {})
            if pre is not None and len(prepares) >= (2 * F + 1):
                pm = {"seq": seq, "view": pre.get("view"), "digest": pre.get("digest"),
                    "prepares": list(prepares.values()), "request": pre.get("request", None)}
                P.append(pm)

        view_change_msg = {"type": "VIEW_CHANGE", "v": target_view, "n": node.low, "C": [], "P": P, "i": node.id}
        node.view_change_msgs.setdefault(target_view, {})[node.id] = view_change_msg

    if getattr(node.attack_config, "crash_attack", False) and getattr(node.attack_config, "should_send_preprepare_only", None) and node.attack_config.should_send_preprepare_only():
        return

    failed_leader = leader_for_view(node.view, node.n)
    recipients = [nid for nid in list(node.out_queues.keys()) if nid != failed_leader]

    node.multicast_with_authenticator(view_change_msg, recipients=recipients)


def _delayed_view_change(node, target_view: int):
    # small delay to avoid storms
    time.sleep(0.1)
    with node.state_lock:
        if node.id in node.view_change_msgs.get(target_view, {}):
            return
    node.start_view_change(target_view)


def handle_view_change(node, envelope: Dict[str, Any]):
    # process VIEW_CHANGE
    if not node.active:
        return

    ok_auth = node.verify_authenticator_for_self(envelope)
    ok_mac = node.verify_single_mac_for_self(envelope)
    if not (ok_auth or ok_mac):
        return

    msg = envelope.get("msg")
    target_view = msg.get("v")
    sender = envelope.get("sender")

    if target_view is None:
        return

    if target_view <= node.view:
        return

    node.stop_request_timer()
    node.start_view_change_timer(target_view)
    node.in_view_change = True

    with node.state_lock:
        node.view_change_msgs.setdefault(target_view, {})[sender] = msg

    with node.state_lock:
        already_sent = (node.id in node.view_change_msgs.get(target_view, {}))

    if not already_sent:
        P = []
        with node.state_lock:
            for seq, st in node.seq_state.items():
                if seq <= node.low:
                    continue
                pre = st.get("preprepare")
                prepares = st.get("prepares", {})
                if pre is not None and len(prepares) >= (2 * F + 1):
                    pm = {"seq": seq, "view": pre.get("view"), "digest": pre.get("digest"),
                        "prepares": list(prepares.values()), "request": pre.get("request", None)}
                    P.append(pm)
            our_vc_msg = {"type": "VIEW_CHANGE", "v": target_view, "n": node.low, "C": [], "P": P, "i": node.id}
            node.view_change_msgs.setdefault(target_view, {})[node.id] = our_vc_msg

        if getattr(node.attack_config, "crash_attack", False) and getattr(node.attack_config, "should_send_preprepare_only", None) and node.attack_config.should_send_preprepare_only():
            pass
        else:
            leader_id = leader_for_view(target_view, node.n)
            recipients_node_ids = [r for r in list(node.out_queues.keys()) if r != leader_id and r != node.id]

            node.multicast_with_authenticator(our_vc_msg, recipients=recipients_node_ids)

    new_leader = leader_for_view(target_view, node.n)
    if new_leader == node.id:
        with node.state_lock:
            num_vc_msgs = len(node.view_change_msgs.get(target_view, {}))
        if num_vc_msgs >= (2 * F + 1):
            node._form_and_multicast_new_view(target_view)


def _form_and_multicast_new_view(node, target_view: int):
    # form NEW-VIEW and multicast
    if getattr(node.attack_config, "crash_attack", False) and node.attack_config.should_block_newview():
        return

    with node.state_lock:
        V_msgs = list(node.view_change_msgs.get(target_view, {}).values())

    min_s = max(vc.get("n", 0) for vc in V_msgs) if V_msgs else 0

    max_s = min_s
    seq_to_P_entries = {}

    for vc in V_msgs:
        for pentry in vc.get("P", []):
            seq = int(pentry.get("seq"))
            if seq > max_s:
                max_s = seq
            seq_to_P_entries.setdefault(seq, []).append(pentry)

    O = []
    for seq in range(min_s + 1, max_s + 1):
        if seq in seq_to_P_entries:
            candidates = seq_to_P_entries[seq]
            best_entry = max(candidates, key=lambda p: p.get("view", -1))

            request = best_entry.get("request")
            if request:
                digest_val = sha256_digest(request)
            else:
                digest_val = best_entry.get("digest")

            preprepare_entry = {
                "view": target_view,
                "seq": seq,
                "digest": digest_val,
                "m": request
            }
            O.append(preprepare_entry)
        else:
            null_request = {"type": "NULL_REQUEST", "seq": seq}
            dnull = sha256_digest(null_request)
            preprepare_entry = {
                "view": target_view,
                "seq": seq,
                "digest": dnull,
                "m": None
            }
            O.append(preprepare_entry)

    new_view_msg = {"type": "NEW_VIEW", "v": target_view, "V": V_msgs, "O": O, "i": node.id}
    node.multicast_with_authenticator(new_view_msg)

    with node.state_lock:
        node.new_view_msgs.append(new_view_msg)

    node._install_new_view_local(new_view_msg)


def _install_new_view_local(node, new_view_msg: Dict[str, Any]):
    # install NEW-VIEW locally and send prepares if needed
    target_view = new_view_msg.get("v")
    O = new_view_msg.get("O", [])

    node.view = target_view
    node.in_view_change = False
    node.stop_request_timer()
    node.stop_view_change_timer()

    with node.state_lock:
        for pre in O:
            seq = int(pre.get("seq"))
            digest_val = pre.get("digest")
            req_maybe = pre.get("m")
            st = node.seq_state.setdefault(seq, {
                "preprepare": None, "prepares": {}, "prepare_multicast": None,
                "commits": {}, "commit_multicast": None, "executed": False, "status": "PP",
                "sent_prepare": False, "result": None
            })
            if st.get("preprepare") is None:
                st["preprepare"] = {"view": target_view, "seq": seq, "digest": digest_val, "request": req_maybe, "sender": node.id}
            st["prepares"][node.id] = {"type": MSG_PREPARE, "v": target_view, "seq": seq, "d": digest_val, "i": node.id}
            st["sent_prepare"] = True

    for pre in O:
        seq = int(pre.get("seq"))
        node._try_to_multicast_prepare(seq)

    if not hasattr(node, "deferred_client_requests"):
        node.deferred_client_requests = []

    while node.deferred_client_requests:
        env = node.deferred_client_requests.pop(0)
        try:
            node.handle_request(env)
        except Exception:
            pass


def handle_new_view(node, envelope: Dict[str, Any]):
    # process NEW-VIEW from primary
    if not node.active:
        return

    if not node.verify_authenticator_for_self(envelope):
        return

    msg = envelope.get("msg")
    target_view = msg.get("v")
    V_msgs = msg.get("V", [])
    O = msg.get("O", [])
    primary = envelope.get("sender")

    if len(V_msgs) < (2 * F + 1):
        return

    with node.state_lock:
        node.new_view_msgs.append(msg)
        for pre in O:
            seq = int(pre.get("seq"))
            digest_val = pre.get("digest")
            req_maybe = pre.get("m")

            st = node.seq_state.setdefault(seq, {
                "preprepare": None, "prepares": {}, "prepare_multicast": None,
                "commits": {}, "commit_multicast": None, "executed": False, "status": "PP",
                "sent_prepare": False, "result": None
            })

            if st.get("preprepare") is None:
                st["preprepare"] = {
                    "view": target_view,
                    "seq": seq,
                    "digest": digest_val,
                    "request": req_maybe,
                    "sender": primary
                }

    node.view = target_view
    node.in_view_change = False
    node.stop_request_timer()
    node.stop_view_change_timer()

    with node.state_lock:
        for seq, st in list(node.seq_state.items()):
            pre = st.get("preprepare")
            if pre is not None and pre.get("view") == target_view and st.get("status") == "PP":
                if not st.get("sent_prepare", False):
                    v = pre.get("view")
                    d = pre.get("digest")

                    if pre.get("request") is None:
                        continue

                    prepare_msg = {"type": MSG_PREPARE, "v": v, "seq": seq, "d": d, "i": node.id}
                    leader_id = leader_for_view(node.view, node.n)
                    node.send_to_node(leader_id, prepare_msg)
                    node.log_message("PREPARE", prepare_msg, "SENT")
                    st["sent_prepare"] = True

    if not hasattr(node, "deferred_client_requests"):
        node.deferred_client_requests = []

    while node.deferred_client_requests:
        env = node.deferred_client_requests.pop(0)
        try:
            node.handle_request(env)
        except Exception:
            pass


def handle_reset(node, envelope: Dict[str, Any]):
    # reset node state (driver -> RESET)
    try:
        node.stop_request_timer()
    except Exception:
        pass

    try:
        node.stop_view_change_timer()
    except Exception:
        pass

    if not node.active:
        pass

    msg = envelope.get("msg", {})
    attack_map_raw = msg.get("attack_map")
    if attack_map_raw and isinstance(attack_map_raw, dict):
        node.attack_map = {}
        for k, v in attack_map_raw.items():
            try:
                nid = int(k)
            except Exception:
                nid = int(k)
            try:
                ac = AttackConfig.from_dict(v)
            except Exception:
                ac = AttackConfig(nid)
            node.attack_map[nid] = ac
        node.attack_config = node.attack_map.get(node.id, AttackConfig(node.id))
    else:
        node.attack_config = get_attack_config(node.id)
        node.attack_map = {node.id: node.attack_config}

    node.reset_datastore()
    node.in_view_change = False
    node.view = 0
    node.next_seq = 1
    node.low = 0
    node.high = node.low + WINDOW_SIZE

    with node.state_lock:
        node.processed_requests.clear()
        node.seq_state.clear()
        node.view_change_msgs.clear()
        node.new_view_msgs.clear()

    with node.message_log_lock:
        node.message_log.clear()


def handle_get_log(node, envelope: Dict[str, Any]):
    # return message log to driver
    msg = envelope.get("msg", {})
    reply_queue = envelope.get("reply_queue")

    if reply_queue is None:
        return

    try:
        log_copy = node.get_message_log()
        response = {
            "type": "LOG_RESPONSE",
            "node_id": node.id,
            "log": log_copy
        }
        reply_queue.put(response)
    except Exception:
        pass


def handle_get_status(node, envelope: Dict[str, Any]):
    # return sequence statuses
    msg = envelope.get("msg", {})
    reply_queue = envelope.get("reply_queue")

    if reply_queue is None:
        return

    statuses = {}
    with node.state_lock:
        for seq, st in node.seq_state.items():
            status = st.get("status", "X")
            statuses[seq] = status

    try:
        response = {
            "type": "STATUS_RESPONSE",
            "node_id": node.id,
            "statuses": statuses
        }
        reply_queue.put(response)
    except Exception:
        pass


def handle_get_new_view(node, envelope: Dict[str, Any]):
    # return NEW-VIEW messages to driver
    msg = envelope.get("msg", {})
    reply_queue = envelope.get("reply_queue")

    if reply_queue is None:
        return

    try:
        with node.state_lock:
            nv_copy = list(node.new_view_msgs)

        response = {
            "type": "NEW_VIEW_RESPONSE",
            "node_id": node.id,
            "new_view_msgs": nv_copy
        }
        reply_queue.put(response)
    except Exception:
        pass

