# monitor.py
"""
Monitor process for PBFT simulator.

Now stores **per-node** snapshots in monitor_db:
  monitor_db[node_id] = { 'A':10, 'B':10, ... }

Accepted incoming messages (from nodes / driver):
 - {"type":"EXECUTED_NOTIFY","t":tstamp,"node":id,"op":op,"result":result}
 - {"type":"DB_SNAPSHOT","node":id,"db":{...}}
 - {"type":"RESET"}
 - {"type":"SHUTDOWN"}
 - {"type":"GET_DB","reply_to":queue}
 - {"type":"DUMP_LOG","reply_to":queue}
"""

import time
from typing import Any, Dict

def monitor_main(monitor_queue, monitor_db, applied_set, monitor_log, stop_event, num_nodes=7):
    """
    monitor_queue: multiprocessing.Queue where nodes/driver send events
    monitor_db: Manager().dict for per-node snapshots (node_id -> dict)
    applied_set: Manager().dict to track which request IDs have been applied (avoid duplicates)
    monitor_log: Manager().list to record events for debugging
    stop_event: multiprocessing.Event() to request shutdown (optional)
    num_nodes: number of nodes to initialize snapshots for
    """
    def _initial_accounts():
        # accounts A..J initialized to 10
        return {chr(ord("A") + i): 10 for i in range(10)}

    def reset_db():
        # initialize monitor_db to have a snapshot for every node
        for nid in range(1, num_nodes + 1):
            monitor_db[nid] = dict(_initial_accounts())
        # clear applied_set and monitor_log
        try:
            for k in list(applied_set.keys()):
                del applied_set[k]
        except Exception:
            pass
        try:
            monitor_log[:] = []
        except Exception:
            pass

    reset_db()
    running = True
    while running and (stop_event is None or not stop_event.is_set()):
        try:
            msg = monitor_queue.get(timeout=0.5)
        except Exception:
            # timeout - loop and check stop_event
            continue
        if not isinstance(msg, dict):
            continue
        mtype = msg.get("type")

        if mtype == "EXECUTED_NOTIFY":
            t = msg.get("t")
            node = msg.get("node")
            op = msg.get("op", {})
            result = msg.get("result", {})
            ts = time.time()
            monitor_log.append({"time": ts, "type": "EXECUTED_NOTIFY", "t": t, "node": node, "op": op, "result": result})
            # avoid duplicate application
            existing = applied_set.get(t)
            if existing is None:
                applied_set[t] = [node]
            else:
                if node not in existing:
                    existing.append(node)
                    applied_set[t] = existing

        elif mtype == "DB_SNAPSHOT":
            # Node sends a snapshot: store it under monitor_db[node]
            node = msg.get("node")
            db = msg.get("db", {})
            ts = time.time()
            monitor_log.append({"time": ts, "type": "DB_SNAPSHOT", "node": node})
            try:
                monitor_db[node] = dict(db)
            except Exception:
                # best effort
                monitor_db[node] = dict(db)

        elif mtype == "RESET":
            reset_db()
            monitor_log.append({"time": time.time(), "type": "RESET"})

        elif mtype == "SHUTDOWN":
            monitor_log.append({"time": time.time(), "type": "SHUTDOWN"})
            running = False
            break

        elif mtype == "GET_DB":
            reply_q = msg.get("reply_to")
            if reply_q is not None:
                snapshot = dict(monitor_db)
                try:
                    reply_q.put(snapshot)
                except Exception:
                    pass

        elif mtype == "DUMP_LOG":
            reply_q = msg.get("reply_to")
            if reply_q is not None:
                try:
                    reply_q.put(list(monitor_log))
                except Exception:
                    pass

        else:
            # unknown message types logged
            monitor_log.append({"time": time.time(), "type": "UNKNOWN", "msg": msg})

    return