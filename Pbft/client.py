# PBFT client process
import time
import threading
import queue
import json
import uuid
from typing import Dict, Any
from common import leader_for_view, MSG_REQUEST, MSG_REPLY


def _short_hex():
    return uuid.uuid4().hex[:6]


def _now_tag(client_id: int, attempt: int):
    return f"{client_id}-{attempt}-{_short_hex()}"


def client_process_main(client_id: int, control_queue, reply_queue, node_inboxes: Dict[int, Any], timeout: float = 5.0):
    # start client
    cid = int(client_id)
    running = True
    view = 0
    try:
        n_replicas = len(node_inboxes)
    except Exception:
        n_replicas = 0
    F = (n_replicas - 1) // 3 if n_replicas > 0 else 0

    internal_reply_q = queue.Queue()

    # listen for replies
    def _reply_listener():
        while True:
            try:
                env = reply_queue.get(timeout=0.5)
            except Exception:
                if not running:
                    break
                continue
            try:
                internal_reply_q.put(env)
            except Exception:
                pass

    threading.Thread(target=_reply_listener, daemon=True).start()

    # send to one node
    def _send_to_node(target: int, msg: Dict[str, Any]):
        q = node_inboxes.get(target)
        if not q:
            return False
        try:
            q.put({"msg": msg, "sender": cid})
            return True
        except Exception:
            return False

    # broadcast to all nodes
    def _broadcast(msg: Dict[str, Any]):
        for q in node_inboxes.values():
            try:
                q.put({"msg": msg, "sender": cid})
            except Exception:
                pass

    # collect enough replies
    def _collect_replies_for_tag(tag: str, target_count: int, wait_timeout: float):
        deadline = time.time() + wait_timeout
        groups = {}
        all_replies = []
        while time.time() < deadline:
            try:
                env = internal_reply_q.get(timeout=0.2)
            except queue.Empty:
                continue
            msg = env.get("msg", {})
            if msg.get("type") != MSG_REPLY or msg.get("t") != tag:
                continue
            sender = env.get("sender")
            r = msg.get("r")
            try:
                k = json.dumps(r, sort_keys=True)
            except Exception:
                k = str(r)
            if k not in groups:
                groups[k] = {"count": 0, "senders": set(), "result": r}
            if sender not in groups[k]["senders"]:
                groups[k]["senders"].add(sender)
                groups[k]["count"] += 1
            all_replies.append((sender, r))
            for g in groups.values():
                if g["count"] >= target_count:
                    return g["result"], g["count"], all_replies
        return None, sum(len(v["senders"]) for v in groups.values()), all_replies

    attempt_counter = 0
    try:
        while True:
            try:
                task = control_queue.get(timeout=0.5)
            except Exception:
                continue
            if not isinstance(task, dict):
                continue

            ttype = task.get("type")
            if ttype not in ("write", "read"):
                continue

            attempt_counter += 1
            tag = _now_tag(cid, attempt_counter)
            reply_to = task.get("reply_to")
            op = task.get("op", {})
            req_msg = {"type": "REQUEST", "op": op, "t": tag, "c": cid}

            try:
                n_replicas = len(node_inboxes)
                F = (n_replicas - 1) // 3 if n_replicas > 0 else 0
            except Exception:
                pass

            needed = 2 * F + 1 if n_replicas > 0 else 1

            # read: broadcast to all
            if op.get("type") == "read":
                _broadcast(req_msg)
                accepted_result, _, _ = _collect_replies_for_tag(tag, needed, timeout)
                if not accepted_result:
                    _broadcast(req_msg)
                    accepted_result, _, _ = _collect_replies_for_tag(tag, needed, timeout * 1.5)
                ack = {"status": "DONE" if accepted_result else "FAILED", "t": tag,
                       "detail": accepted_result or "timeout"}
                if reply_to:
                    try:
                        reply_to.put(ack)
                    except Exception:
                        pass
                continue

            # write: send to leader first
            leader = None
            try:
                leader = leader_for_view(view, n_replicas)
            except Exception:
                pass

            sent = False
            if leader and node_inboxes.get(leader):
                sent = _send_to_node(leader, req_msg)
            if not sent:
                _broadcast(req_msg)

            accepted_result, _, _ = _collect_replies_for_tag(tag, needed, timeout)
            if not accepted_result:
                _broadcast(req_msg)
                accepted_result, _, _ = _collect_replies_for_tag(tag, needed, timeout * 1.5)

            ack = {"status": "DONE" if accepted_result else "FAILED", "t": tag,
                   "detail": accepted_result or "timeout"}
            if reply_to:
                try:
                    reply_to.put(ack)
                except Exception:
                    pass

    except KeyboardInterrupt:
        pass
    finally:
        running = False
        time.sleep(0.1)
