# client.py
"""
Client process for PBFT simulator.

Provides client_process_main(client_id, control_queue, reply_queue, node_inboxes, timeout)

Behavior:
- Accepts control messages from driver via control_queue
- Sends REQUEST to leader (or broadcasts if leader not available).
- Collects replies from nodes via reply_queue and returns an ack to driver via reply_to.
- Retries indefinitely until 2f+1 matching replies are collected for the request.
"""

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
    """
    Entry point for a client process.
    control_queue: manager.Queue where driver posts control commands
    reply_queue: manager.Queue where nodes post REPLY envelopes for this client
    node_inboxes: dict {node_id: manager.Queue} used to send REQUESTs to nodes
    timeout: default waiting timeout (seconds) per attempt
    """
    cid = int(client_id)
    running = True
    view = 0
    # number of replicas determined from node_inboxes passed by driver
    try:
        n_replicas = len(node_inboxes)
    except Exception:
        # fallback
        n_replicas = 0

    # fault tolerance parameter (integer)
    if n_replicas > 0:
        F = (n_replicas - 1) // 3
    else:
        F = 0

    # internal thread-safe queue for replies coming from the manager.Queue
    internal_reply_q = queue.Queue()

    def _reply_listener():
        """Background thread: move replies from manager.Queue (reply_queue) into internal deque."""
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

    tlistener = threading.Thread(target=_reply_listener, daemon=True)
    tlistener.start()

    def _send_to_node(target: int, msg: Dict[str, Any]):
        """Put an envelope directly into a node's inbox."""
        try:
            q = node_inboxes.get(target)
        except Exception:
            q = None
        if q is None:
            return False
        try:
            q.put({"msg": msg, "sender": cid})
            return True
        except Exception:
            return False

    def _broadcast(msg: Dict[str, Any]):
        for nid, q in list(node_inboxes.items()):
            try:
                q.put({"msg": msg, "sender": cid})
            except Exception:
                pass

    def _collect_replies_for_tag(tag: str, target_count: int, wait_timeout: float):
        """
        Collect replies for a given tag 't' until `target_count` matching results are seen
        or wait_timeout seconds pass.
        Returns: (accepted_result, replies_seen_count, all_replies_list)
        accepted_result is the result dict (r) if target_count is reached, else None.
        """
        deadline = time.time() + wait_timeout
        groups = {}
        all_replies = []
        while time.time() < deadline:
            try:
                env = internal_reply_q.get(timeout=0.2)
            except queue.Empty:
                continue
            if not isinstance(env, dict):
                continue
            msg = env.get("msg", {})
            if msg.get("type") != MSG_REPLY:
                continue
            t = msg.get("t")
            if t != tag:
                # reply for different request, ignore for this collection
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
                    return (g["result"], g["count"], all_replies)
        # timed out
        return (None, sum(len(v["senders"]) for v in groups.values()), all_replies)

    # main loop: wait for driver commands on control_queue
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
            reply_to = task.get("reply_to")  # driver's ack queue (manager.Queue)
            op = task.get("op", {})
            # Build request envelope expected by nodes
            req_msg = {"type": "REQUEST", "op": op, "t": tag, "c": cid}

            # recompute n_replicas & F in case node_inboxes changed across driver runs
            try:
                n_replicas = len(node_inboxes)
                F = (n_replicas - 1) // 3 if n_replicas > 0 else 0
            except Exception:
                pass

            needed = 2 * F + 1 if n_replicas > 0 else 1

            # We'll retry until success. Use an exponential backoff between attempts.
            send_attempt = 0
            accepted_result = None

            while accepted_result is None:
                send_attempt += 1

                # Attempt sending to leader first
                leader = None
                try:
                    leader = leader_for_view(view, n_replicas)
                except Exception:
                    leader = None

                sent_to_leader = False
                if leader is not None and node_inboxes.get(leader) is not None:
                    sent_to_leader = _send_to_node(leader, req_msg)
                    if sent_to_leader:
                        print(f"[Client {cid}] WRITE/READ t={tag} sent to leader {leader}; waiting for replies (timeout={timeout}s)")
                else:
                    # Broadcast to all replicas
                    _broadcast(req_msg)
                    print(f"[Client {cid}] Broadcasted request to all replicas: {req_msg}")

                # Collect replies (need 2f+1 matching replies)
                accepted_result, group_size, all_replies = _collect_replies_for_tag(tag, needed, timeout)

                if accepted_result is not None:
                    # Success — inform driver and break
                    ack = {"status": "DONE", "t": tag, "detail": accepted_result}
                    try:
                        if reply_to is not None:
                            reply_to.put(ack)
                    except Exception:
                        pass
                    print(f"[Client {cid}] WRITE/READ accepted t={tag} result={accepted_result}")
                    break

                # No success yet — retry. Broadcast to all as a robust retry.
                print(f"[Client {cid}] WRITE/READ timeout for t={tag}, retrying (attempt {send_attempt})")
                _broadcast(req_msg)

                # Wait again with a slightly longer wait (backoff)
                accepted_result, group_size, all_replies = _collect_replies_for_tag(tag, needed, timeout * 1.5)
                if accepted_result is not None:
                    ack = {"status": "DONE", "t": tag, "detail": accepted_result}
                    try:
                        if reply_to is not None:
                            reply_to.put(ack)
                    except Exception:
                        pass
                    print(f"[Client {cid}] WRITE/READ accepted after retry t={tag} result={accepted_result}")
                    break

                # Still no success — sleep with exponential backoff then retry indefinitely.
                sleep_time = min(2 ** min(send_attempt, 6), 60)
                print(f"[Client {cid}] Still no consensus for t={tag}. Backing off {sleep_time}s before retrying.")
                time.sleep(sleep_time)
                # Loop continues until accepted_result is found (or the process is killed)

    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"[Client {cid}] Exception in client main loop: {e}")
    finally:
        # ensure the reply-listener thread will terminate
        running = False
        time.sleep(0.1)
