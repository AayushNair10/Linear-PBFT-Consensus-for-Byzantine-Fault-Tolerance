import multiprocessing as mp
import sys
import time
from keys import create_keyring
from Node.node import node_process_main
from client import client_process_main
from monitor import monitor_main
from common import leader_for_view

from attacks import initialize_orchestrator, get_orchestrator
from csv_parser import parse_csv_with_attacks

# system size
NUM_NODES = 7
NUM_CLIENTS = 10

# client id <-> name maps
CLIENT_NAMES = {i + 1: chr(ord("A") + i) for i in range(10)}
CLIENT_NAME_TO_ID = {v: k for k, v in CLIENT_NAMES.items()}

# set of nodes considered live in current set
LAST_LIVE_NODES = set(range(1, NUM_NODES + 1))

# per-set caches (updated after each set)
NODE_MESSAGE_LOGS = {}  # {node_id: [message_log_entries]}
NEW_VIEW_MESSAGES = []  # list of NEW-VIEW msgs


# simple DB print helper using monitor_db snapshots
def PrintDB(monitor_db, _applied_set=None):
    # default DB snapshot if monitor has none
    default_db = {chr(ord("A") + i): 10 for i in range(10)}
    orchestrator = get_orchestrator()

    for node_id in range(1, NUM_NODES + 1):
        try:
            db = monitor_db.get(node_id, None)
        except Exception:
            db = None

        if not db:
            db = default_db

        parts = []
        for name in sorted(db.keys()):
            parts.append(f"{name}:{db.get(name)}")

        line = f"Node {node_id}: " + " ".join(parts)
        if node_id not in LAST_LIVE_NODES:
            line += " (simulated down)"

        if orchestrator and orchestrator.is_byzantine(node_id):
            line += " [BYZANTINE]"

        print(line)


# format and print protocol logs collected from nodes
def PrintLog(node_id, node_inboxes):
    # header
    print(f"\n=== PrintLog for Node {node_id} ===")

    # if no cached logs available, inform user
    if node_id not in NODE_MESSAGE_LOGS or not NODE_MESSAGE_LOGS[node_id]:
        print(f"No message log available for Node {node_id}")
        print("Note: Logs are collected at the end of each set.")
        return

    log_entries = NODE_MESSAGE_LOGS[node_id]
    if not log_entries:
        print(f"Node {node_id} has no messages in its log.")
        return

    print(f"Total messages: {len(log_entries)}\n")

    # iterate and pretty-print per-message
    for entry in log_entries:
        direction = entry.get('direction', '')
        message = entry.get('message', {})
        msg_type = message.get('type', 'UNKNOWN')

        if msg_type == 'PREPREPARE':
            v = message.get('v', '?')
            n = message.get('seq', '?')
            d = message.get('d', '?')
            m = message.get('m', {})
            print(f"[{direction:9s}] <<PRE-PREPARE,{v},{n},{d}>,{m}>")

        elif msg_type == 'PREPARE':
            v = message.get('v', '?')
            n = message.get('seq', '?')
            d = message.get('d', '?')
            i = message.get('i', '?')
            print(f"[{direction:9s}] <<PREPARE,{v},{n},{d},{i}>>")

        elif msg_type == 'PREPARE_MULTICAST':
            v = message.get('v', '?')
            n = message.get('seq', '?')
            d = message.get('d', '?')
            prepares = message.get('prepares', [])
            print(f"[{direction:9s}] <<PREPARE_MULTICAST,{v},{n},{d}>,[{len(prepares)} prepares]>")

        elif msg_type == 'COMMIT':
            v = message.get('v', '?')
            n = message.get('seq', '?')
            d = message.get('d', '?')
            i = message.get('i', '?')
            print(f"[{direction:9s}] <<COMMIT,{v},{n},{d},{i}>>")

        elif msg_type == 'COMMIT_MULTICAST':
            v = message.get('v', '?')
            n = message.get('seq', '?')
            d = message.get('d', '?')
            commits = message.get('commits', [])
            print(f"[{direction:9s}] <<COMMIT_MULTICAST,{v},{n},{d}>,[{len(commits)} commits]>")

        elif msg_type == 'REPLY':
            v = message.get('v', '?')
            t = message.get('t', '?')
            c = message.get('c', '?')
            i = message.get('i', '?')
            r = message.get('r', {})
            print(f"[{direction:9s}] <<REPLY,{v},{t},{c},{i},{r}>>")

        elif msg_type == 'REQUEST':
            op = message.get('op', {})
            t = message.get('t', '?')
            c = message.get('c', '?')
            print(f"[{direction:9s}] <<REQUEST,{op},{t},{c}>>")

        elif msg_type == 'VIEW_CHANGE':
            v = message.get('v', '?')
            n = message.get('n', '?')
            C = message.get('C', [])
            P = message.get('P', [])
            i = message.get('i', '?')
            print(f"[{direction:9s}] <<VIEW-CHANGE,{v},{n},{len(C)} C-entries,{len(P)} P-entries,{i}>>")

        elif msg_type == 'NEW_VIEW':
            v = message.get('v', '?')
            V = message.get('V', [])
            O = message.get('O', [])
            i = message.get('i', '?')
            print(f"[{direction:9s}] <<NEW-VIEW,{v},{len(V)} V-msgs,{len(O)} O-entries,{i}>>")

        else:
            print(f"[{direction:9s}] {message}")

    print()


# print status for a given sequence number across nodes
def PrintStatus(seq_no, node_inboxes, node_status_cache):
    print(f"\n=== PrintStatus for Sequence {seq_no} ===")

    if seq_no not in node_status_cache or not node_status_cache[seq_no]:
        print(f"No status information available for sequence {seq_no}")
        print("Note: Status is collected at the end of each set.")
        return

    statuses = node_status_cache[seq_no]

    # table header
    print(f"{'Node':<10} {'Status':<10} {'Details'}")
    print("-" * 60)

    # show each node's status and mark down nodes
    for node_id in range(1, NUM_NODES + 1):
        status = statuses.get(node_id, 'X')
        details = ""
        if status == 'X':
            details = "No information"
        elif status == 'E':
            details = "Transaction executed"
        elif status == 'C':
            details = "Committed, awaiting execution"
        elif status == 'P':
            details = "Prepared, awaiting commits"
        elif status == 'PP':
            details = "Pre-prepared, awaiting prepares"

        down_marker = " (DOWN)" if node_id not in LAST_LIVE_NODES else ""
        print(f"Node {node_id:<5} {status:<10} {details}{down_marker}")

    print()


# print a readable summary of collected NEW-VIEW messages
def PrintView(new_view_messages_list):
    print("\n=== PrintView: All NEW-VIEW Messages ===")

    if not new_view_messages_list:
        print("No view changes have occurred in this set.")
        return

    print(f"Total view changes: {len(new_view_messages_list)}\n")

    for idx, nv_msg in enumerate(new_view_messages_list, 1):
        view = nv_msg.get('v', 'N/A')
        primary = nv_msg.get('i', 'N/A')
        V_msgs = nv_msg.get('V', [])
        O_entries = nv_msg.get('O', [])

        print(f"--- NEW-VIEW #{idx} ---")
        print(f"  View: {view}")
        print(f"  New Primary: Node {primary}")
        print(f"  VIEW-CHANGE messages received: {len(V_msgs)}")
        vc_senders = [vc.get('i', '?') for vc in V_msgs]
        print(f"    From nodes: {sorted(vc_senders)}")
        print(f"  Pre-prepares in O: {len(O_entries)}")
        if O_entries:
            print(f"    Sequence range: {min(o.get('seq', 0) for o in O_entries)} - {max(o.get('seq', 0) for o in O_entries)}")
            for o in O_entries:
                seq = o.get('seq', '?')
                is_null = o.get('m') is None
                status = "NULL" if is_null else "REAL"
                print(f"      Seq {seq}: {status} request")
        print()


# ask nodes for their message logs and collect replies from reply_queue
def collect_node_logs(node_inboxes, reply_queue, timeout=2.0):
    logs = {}

    # request logs from every live node
    for node_id in range(1, NUM_NODES + 1):
        if node_id not in LAST_LIVE_NODES:
            continue
        q = node_inboxes.get(node_id)
        if q:
            try:
                q.put({
                    "msg": {"type": "GET_LOG", "reply_to_driver": True},
                    "sender": "driver",
                    "reply_queue": reply_queue
                })
            except Exception:
                pass

    # wait for responses up to timeout
    start = time.time()
    collected = 0
    expected = len([n for n in range(1, NUM_NODES + 1) if n in LAST_LIVE_NODES])

    while collected < expected and (time.time() - start) < timeout:
        try:
            response = reply_queue.get(timeout=0.5)
            if isinstance(response, dict) and response.get("type") == "LOG_RESPONSE":
                node_id = response.get("node_id")
                log_entries = response.get("log", [])
                logs[node_id] = log_entries
                collected += 1
        except Exception:
            continue

    return logs


# ask nodes for per-sequence statuses and build a seq->node->status map
def collect_node_status(node_inboxes, reply_queue, timeout=2.0):
    all_statuses = {}

    # send GET_STATUS to live nodes
    for node_id in range(1, NUM_NODES + 1):
        if node_id not in LAST_LIVE_NODES:
            continue
        q = node_inboxes.get(node_id)
        if q:
            try:
                q.put({
                    "msg": {"type": "GET_STATUS", "reply_to_driver": True},
                    "sender": "driver",
                    "reply_queue": reply_queue
                })
            except Exception:
                pass

    # collect and merge responses
    start = time.time()
    collected = 0
    expected = len([n for n in range(1, NUM_NODES + 1) if n in LAST_LIVE_NODES])

    while collected < expected and (time.time() - start) < timeout:
        try:
            response = reply_queue.get(timeout=0.5)
            if isinstance(response, dict) and response.get("type") == "STATUS_RESPONSE":
                node_id = response.get("node_id")
                seq_statuses = response.get("statuses", {})
                for seq, status in seq_statuses.items():
                    if seq not in all_statuses:
                        all_statuses[seq] = {}
                    all_statuses[seq][node_id] = status
                collected += 1
        except Exception:
            continue

    # fill missing entries with 'X'
    for seq in all_statuses:
        for node_id in range(1, NUM_NODES + 1):
            if node_id not in all_statuses[seq]:
                all_statuses[seq][node_id] = 'X'

    return all_statuses


# request NEW-VIEW messages from nodes and deduplicate by view number
def collect_new_view_messages(node_inboxes, reply_queue, timeout=2.0):
    all_nv_msgs = []
    seen_views = set()

    # request from each live node
    for node_id in range(1, NUM_NODES + 1):
        if node_id not in LAST_LIVE_NODES:
            continue
        q = node_inboxes.get(node_id)
        if q:
            try:
                q.put({
                    "msg": {"type": "GET_NEW_VIEW", "reply_to_driver": True},
                    "sender": "driver",
                    "reply_queue": reply_queue
                })
            except Exception:
                pass

    # collect up to expected responses
    start = time.time()
    collected = 0
    expected = len([n for n in range(1, NUM_NODES + 1) if n in LAST_LIVE_NODES])

    while collected < expected and (time.time() - start) < timeout:
        try:
            response = reply_queue.get(timeout=0.5)
            if isinstance(response, dict) and response.get("type") == "NEW_VIEW_RESPONSE":
                nv_msgs = response.get("new_view_msgs", [])
                for nv in nv_msgs:
                    view = nv.get('v')
                    if view not in seen_views:
                        all_nv_msgs.append(nv)
                        seen_views.add(view)
                collected += 1
        except Exception:
            continue

    # sort by view for readability
    all_nv_msgs.sort(key=lambda x: x.get('v', 0))
    return all_nv_msgs


# terminate all spawned processes cleanly
def cleanup(node_procs, client_procs, monitor_proc):
    for p in client_procs:
        try:
            p.terminate()
            p.join(timeout=1.0)
        except Exception:
            pass
    for p in node_procs:
        try:
            p.terminate()
            p.join(timeout=1.0)
        except Exception:
            pass
    try:
        monitor_proc.terminate()
        monitor_proc.join(timeout=1.0)
    except Exception:
        pass


# send a simple control message (PAUSE/UNPAUSE) to a node's inbox
def _send_control_to_node(node_inboxes, nid, msg_type):
    q = node_inboxes.get(nid)
    if q:
        try:
            q.put({"msg": {"type": msg_type}, "sender": "driver"})
            return True
        except Exception:
            return False
    return False


# main driver: setup, run sets, interactive menus
def main(csvfile):
    global LAST_LIVE_NODES, NODE_MESSAGE_LOGS, NEW_VIEW_MESSAGES

    # use spawn start method for multiprocessing
    mp.set_start_method("spawn", force=True)
    manager = mp.Manager()
    keyring = create_keyring(NUM_NODES)

    # orchestrator controls attack scenario per set
    orchestrator = initialize_orchestrator(NUM_NODES)

    # read sets from CSV
    sets = parse_csv_with_attacks(csvfile)
    if not sets:
        return

    # create manager queues used across processes
    node_inboxes = {nid: manager.Queue() for nid in range(1, NUM_NODES + 1)}
    client_control_queues = {cid: manager.Queue() for cid in range(1, NUM_CLIENTS + 1)}
    client_reply_queues = {cid: manager.Queue() for cid in range(1, NUM_CLIENTS + 1)}
    driver_ack_queues = {cid: manager.Queue() for cid in range(1, NUM_CLIENTS + 1)}
    driver_reply_queue = manager.Queue()

    monitor_queue = manager.Queue()
    monitor_db = manager.dict()
    applied_set = manager.dict()
    monitor_log = manager.list()
    monitor_stop = manager.Event()

    # start the monitor process (records DB snapshots, executed notifications)
    monitor_proc = mp.Process(target=monitor_main, args=(
        monitor_queue, monitor_db, applied_set, monitor_log, monitor_stop, NUM_NODES
    ))
    monitor_proc.start()

    readiness_queue = manager.Queue()

    # spawn node processes
    node_procs = []
    for nid in range(1, NUM_NODES + 1):
        p = mp.Process(target=node_process_main, args=(
            nid, NUM_NODES, keyring,
            node_inboxes[nid],
            node_inboxes,
            client_reply_queues,
            monitor_queue,
            readiness_queue,
            5.0
        ))
        p.start()
        node_procs.append(p)

    # wait for all nodes to signal readiness (or timeout)
    ready_count = 0
    timeout = 10.0 + NUM_NODES * 0.5
    start = time.time()
    while ready_count < NUM_NODES and (time.time() - start) < timeout:
        try:
            msg = readiness_queue.get(timeout=timeout - (time.time() - start))
        except Exception:
            break
        if isinstance(msg, dict) and msg.get("type") == "NODE_READY":
            ready_count += 1

    # spawn client processes
    client_procs = []
    for cid in range(1, NUM_CLIENTS + 1):
        p = mp.Process(target=client_process_main, args=(
            cid,
            client_control_queues[cid],
            client_reply_queues[cid],
            node_inboxes,
            8.0
        ))
        p.start()
        client_procs.append(p)

    time.sleep(0.5)

    # initial interactive prompt before first set
    print("All nodes are up and ready.")
    print("-" * 60)
    print("Commands: [Enter= Process set 1, PrintDB, quit]")

    while True:
        cmd = input("> ").strip()
        if cmd == "":
            break
        tok = cmd.strip().split()
        if len(tok) == 0:
            break
        c0 = tok[0].lower()
        if c0 in ("start", "begin", "continue"):
            break
        if c0 in ("quit", "exit"):
            cleanup(node_procs, client_procs, monitor_proc)
            return
        if c0 == "printdb":
            PrintDB(monitor_db, applied_set)
            continue
        print("Invalid command")

    # iterate through each set defined in CSV
    for s in sets:
        NODE_MESSAGE_LOGS = {}
        NEW_VIEW_MESSAGES = []
        node_status_cache = {}

        sid = s["set_no"]
        entries = s["transactions"]
        live_nodes = s.get("live", list(range(1, NUM_NODES + 1)))
        byzantine_nodes = s.get("byzantine", [])
        attack_strings = s.get("attacks", [])

        # configure orchestrator for this set
        orchestrator.configure_set(live_nodes, byzantine_nodes, attack_strings)

        # compute crashed nodes from orchestrator
        crashed = orchestrator.get_crashed_nodes()

        # live nodes after removing crashed ones
        live_nodes_set = set(live_nodes) - set(crashed)
        LAST_LIVE_NODES = set(live_nodes_set)

        leader_info = leader_for_view(0, NUM_NODES)

        # pause/unpause nodes according to live set
        for nid in range(1, NUM_NODES + 1):
            if nid in live_nodes_set:
                _send_control_to_node(node_inboxes, nid, "UNPAUSE")
            else:
                _send_control_to_node(node_inboxes, nid, "PAUSE")

        # build serializable attack_map and send RESET to nodes
        attack_map = orchestrator.to_serializable_map()
        print(f"\n=== Starting Set {sid} ===")
        for nid in range(1, NUM_NODES + 1):
            if nid in live_nodes_set:
                node_inboxes[nid].put({"msg": {"type": "RESET", "attack_map": attack_map}, "sender": "driver"})
        monitor_queue.put({"type": "RESET"})
        time.sleep(0.3)

        # send transactions sequentially to clients
        for txn_idx, txn in enumerate(entries, 1):
            if txn.get("type") == "read":
                cname = txn.get("s")
                cid = CLIENT_NAME_TO_ID.get(cname)
                if cid is None:
                    continue
                client_control_queues[cid].put({
                    "type": "read",
                    "op": {"type": "read", "s": cname},
                    "reply_to": driver_ack_queues[cid]
                })
                try:
                    driver_ack_queues[cid].get(timeout=15.0)
                except Exception:
                    pass

            elif txn.get("type") == "write":
                op = txn.get("op")
                sname = op.get("s")
                cid = CLIENT_NAME_TO_ID.get(sname)
                if cid is None:
                    continue
                client_control_queues[cid].put({
                    "type": "write",
                    "op": op,
                    "reply_to": driver_ack_queues[cid]
                })
                try:
                    driver_ack_queues[cid].get(timeout=15.0)
                except Exception:
                    pass

            time.sleep(0.2)

        # let protocol quiet down
        time.sleep(2.0)

        # collect logs, statuses and NEW-VIEW messages from nodes
        NODE_MESSAGE_LOGS = collect_node_logs(node_inboxes, driver_reply_queue)
        node_status_cache = collect_node_status(node_inboxes, driver_reply_queue)
        NEW_VIEW_MESSAGES = collect_new_view_messages(node_inboxes, driver_reply_queue)

        # end-of-set messages
        print(f"\n=== Set {sid} Complete ===")
        time.sleep(0.5)

        # interactive menu after set (inspect results or continue)
        print(f"\nSet {sid} complete. Commands: [Enter=next set, PrintDB, PrintLog <n>, PrintStatus <n>, PrintView, quit]")

        while True:
            cmd = input("> ").strip()
            if cmd == "":
                break
            tok = cmd.strip().split()
            if len(tok) == 0:
                break
            c0 = tok[0].lower()
            if c0 in ("continue", "c", "next"):
                break
            if c0 in ("quit", "exit"):
                cleanup(node_procs, client_procs, monitor_proc)
                return
            if c0 == "printdb":
                PrintDB(monitor_db, applied_set)
                continue
            if c0 == "printlog":
                if len(tok) == 2 and tok[1].isdigit():
                    PrintLog(int(tok[1]), node_inboxes)
                else:
                    print("Usage: PrintLog <node_id>")
                continue
            if c0 == "printstatus":
                if len(tok) == 2 and tok[1].isdigit():
                    PrintStatus(int(tok[1]), node_inboxes, node_status_cache)
                else:
                    print("Usage: PrintStatus <seq_no>")
                continue
            if c0 == "printview":
                PrintView(NEW_VIEW_MESSAGES)
                continue
            print("Invalid command")

    # finished all sets: final inspection loop
    print("\n=== All sets complete ===")
    print("\nFinal system state:")
    PrintDB(monitor_db, applied_set)

    print("\nInteractive commands: printdb, printlog <node>, printstatus <seq>, printview, quit")
    while True:
        cmd = input("> ").strip()
        if cmd.lower() in ("quit", "exit"):
            break
        if cmd.lower() == "printdb":
            PrintDB(monitor_db, applied_set)
        elif cmd.lower().startswith("printlog"):
            parts = cmd.split()
            if len(parts) == 2 and parts[1].isdigit():
                PrintLog(int(parts[1]), node_inboxes)
            else:
                print("Usage: printlog <node_id>")
        elif cmd.lower().startswith("printstatus"):
            parts = cmd.split()
            if len(parts) == 2 and parts[1].isdigit():
                if node_status_cache:
                    PrintStatus(int(parts[1]), node_inboxes, node_status_cache)
                else:
                    print("No status cache available. Run a set first.")
            else:
                print("Usage: printstatus <seq_no>")
        elif cmd.lower() == "printview":
            PrintView(NEW_VIEW_MESSAGES)
        else:
            print("Unknown command")

    cleanup(node_procs, client_procs, monitor_proc)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run_driver.py test.csv")
        sys.exit(1)
    csvfile = sys.argv[1]
    main(csvfile)
