# Tracks per-node DB snapshots and executed ops
import time
from typing import Any, Dict


def monitor_main(monitor_queue, monitor_db, applied_set, monitor_log, stop_event, num_nodes=7):
    # queue: events from nodes/driver, db: per-node state

    def _initial_accounts():
        # accounts A..J start with 10
        return {chr(ord("A") + i): 10 for i in range(10)}

    def reset_db():
        # reset all node DBs and clear logs
        for nid in range(1, num_nodes + 1):
            monitor_db[nid] = dict(_initial_accounts())
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
            continue
        if not isinstance(msg, dict):
            continue

        mtype = msg.get("type")

        if mtype == "EXECUTED_NOTIFY":
            # node executed op
            t = msg.get("t")
            node = msg.get("node")
            op = msg.get("op", {})
            result = msg.get("result", {})
            ts = time.time()
            monitor_log.append({"time": ts, "type": "EXECUTED_NOTIFY", "t": t, "node": node, "op": op, "result": result})
            existing = applied_set.get(t)
            if existing is None:
                applied_set[t] = [node]
            elif node not in existing:
                existing.append(node)
                applied_set[t] = existing

        elif mtype == "DB_SNAPSHOT":
            # node sent DB snapshot
            node = msg.get("node")
            db = msg.get("db", {})
            ts = time.time()
            monitor_log.append({"time": ts, "type": "DB_SNAPSHOT", "node": node})
            try:
                monitor_db[node] = dict(db)
            except Exception:
                monitor_db[node] = dict(db)

        elif mtype == "RESET":
            reset_db()
            monitor_log.append({"time": time.time(), "type": "RESET"})

        elif mtype == "SHUTDOWN":
            monitor_log.append({"time": time.time(), "type": "SHUTDOWN"})
            running = False
            break

        elif mtype == "GET_DB":
            # send DB snapshot back
            reply_q = msg.get("reply_to")
            if reply_q:
                try:
                    reply_q.put(dict(monitor_db))
                except Exception:
                    pass

        elif mtype == "DUMP_LOG":
            # send event log back
            reply_q = msg.get("reply_to")
            if reply_q:
                try:
                    reply_q.put(list(monitor_log))
                except Exception:
                    pass

        else:
            # log unknown messages
            monitor_log.append({"time": time.time(), "type": "UNKNOWN", "msg": msg})

    return