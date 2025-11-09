# run_driver.py - With Byzantine attack support and complete menu functions
"""
Driver that configures attacks via AttackOrchestrator and serializes attack_map
into RESET messages so spawned node processes can reconstruct AttackConfig locally.

Includes PrintLog, PrintStatus, and PrintView functions for debugging.
"""

import multiprocessing as mp
import sys
import time
from keys import create_keyring
from node import node_process_main
from client import client_process_main
from monitor import monitor_main
from common import leader_for_view

from attacks import initialize_orchestrator, get_orchestrator
from csv_parser import parse_csv_with_attacks

NUM_NODES = 7
NUM_CLIENTS = 10

CLIENT_NAMES = {i + 1: chr(ord("A") + i) for i in range(10)}
CLIENT_NAME_TO_ID = {v: k for k, v in CLIENT_NAMES.items()}

LAST_LIVE_NODES = set(range(1, NUM_NODES + 1))

# Global storage for node logs and view messages (reset per set)
NODE_MESSAGE_LOGS = {}  # {node_id: [message_log_entries]}
NEW_VIEW_MESSAGES = []  # List of NEW-VIEW messages


def PrintDB(monitor_db, _applied_set=None):
    """Print per-node DB snapshots."""
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


def PrintLog(node_id, node_inboxes):
    """
    Print protocol message log for a specific node.
    Shows raw messages in PBFT format.
    """
    print(f"\n=== PrintLog for Node {node_id} ===")
    
    # Check if we have cached logs for this node
    if node_id not in NODE_MESSAGE_LOGS or not NODE_MESSAGE_LOGS[node_id]:
        print(f"No message log available for Node {node_id}")
        print("Note: Logs are collected at the end of each set.")
        return
    
    log_entries = NODE_MESSAGE_LOGS[node_id]
    
    if not log_entries:
        print(f"Node {node_id} has no messages in its log.")
        return
    
    print(f"Total messages: {len(log_entries)}\n")
    
    # Print each message as-is
    for entry in log_entries:
        direction = entry.get('direction', '')
        message = entry.get('message', {})
        
        # Format based on message type
        msg_type = message.get('type', 'UNKNOWN')
        
        if msg_type == 'PREPREPARE':
            # <<PRE-PREPARE,v,n,d>,m>
            v = message.get('v', '?')
            n = message.get('seq', '?')
            d = message.get('d', '?')
            m = message.get('m', {})
            print(f"[{direction:9s}] <<PRE-PREPARE,{v},{n},{d}>,{m}>")
            
        elif msg_type == 'PREPARE':
            # <<PREPARE,v,n,d,i>>
            v = message.get('v', '?')
            n = message.get('seq', '?')
            d = message.get('d', '?')
            i = message.get('i', '?')
            print(f"[{direction:9s}] <<PREPARE,{v},{n},{d},{i}>>")
            
        elif msg_type == 'PREPARE_MULTICAST':
            # Leader multicasts prepares - show the collection
            v = message.get('v', '?')
            n = message.get('seq', '?')
            d = message.get('d', '?')
            prepares = message.get('prepares', [])
            print(f"[{direction:9s}] <<PREPARE_MULTICAST,{v},{n},{d}>,[{len(prepares)} prepares]>")
            
        elif msg_type == 'COMMIT':
            # <<COMMIT,v,n,d,i>>
            v = message.get('v', '?')
            n = message.get('seq', '?')
            d = message.get('d', '?')
            i = message.get('i', '?')
            print(f"[{direction:9s}] <<COMMIT,{v},{n},{d},{i}>>")
            
        elif msg_type == 'COMMIT_MULTICAST':
            # Leader multicasts commits - show the collection
            v = message.get('v', '?')
            n = message.get('seq', '?')
            d = message.get('d', '?')
            commits = message.get('commits', [])
            print(f"[{direction:9s}] <<COMMIT_MULTICAST,{v},{n},{d}>,[{len(commits)} commits]>")
            
        elif msg_type == 'REPLY':
            # <<REPLY,v,t,c,i,r>>
            v = message.get('v', '?')
            t = message.get('t', '?')
            c = message.get('c', '?')
            i = message.get('i', '?')
            r = message.get('r', {})
            print(f"[{direction:9s}] <<REPLY,{v},{t},{c},{i},{r}>>")
            
        elif msg_type == 'REQUEST':
            # <<REQUEST,op,t,c>>
            op = message.get('op', {})
            t = message.get('t', '?')
            c = message.get('c', '?')
            print(f"[{direction:9s}] <<REQUEST,{op},{t},{c}>>")
            
        elif msg_type == 'VIEW_CHANGE':
            # <<VIEW-CHANGE,v,n,C,P,i>>
            v = message.get('v', '?')
            n = message.get('n', '?')
            C = message.get('C', [])
            P = message.get('P', [])
            i = message.get('i', '?')
            print(f"[{direction:9s}] <<VIEW-CHANGE,{v},{n},{len(C)} C-entries,{len(P)} P-entries,{i}>>")
            
        elif msg_type == 'NEW_VIEW':
            # <<NEW-VIEW,v,V,O,i>>
            v = message.get('v', '?')
            V = message.get('V', [])
            O = message.get('O', [])
            i = message.get('i', '?')
            print(f"[{direction:9s}] <<NEW-VIEW,{v},{len(V)} V-msgs,{len(O)} O-entries,{i}>>")
            
        else:
            # Generic format for other messages
            print(f"[{direction:9s}] {message}")
    
    print()


def PrintStatus(seq_no, node_inboxes, node_status_cache):
    """
    Print status for a specific sequence number across all nodes.
    Status labels: PP (Pre-prepared), P (Prepared), C (Committed), E (Executed), X (No Status)
    """
    print(f"\n=== PrintStatus for Sequence {seq_no} ===")
    
    if seq_no not in node_status_cache or not node_status_cache[seq_no]:
        print(f"No status information available for sequence {seq_no}")
        print("Note: Status is collected at the end of each set.")
        return
    
    statuses = node_status_cache[seq_no]
    
    # Print header
    print(f"{'Node':<10} {'Status':<10} {'Details'}")
    print("-" * 60)
    
    # Print status for each node
    for node_id in range(1, NUM_NODES + 1):
        status = statuses.get(node_id, 'X')
        
        # Add details based on status
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
        
        # Mark byzantine nodes
        orchestrator = get_orchestrator()
        
        # Mark down nodes
        down_marker = " (DOWN)" if node_id not in LAST_LIVE_NODES else ""
        
        print(f"Node {node_id:<5} {status:<10} {details}{down_marker}")
    
    print()


def PrintView(new_view_messages_list):
    """
    Print all NEW-VIEW messages exchanged since the start of the current test case (set).
    """
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
        
        # Show which nodes sent VIEW-CHANGE
        vc_senders = [vc.get('i', '?') for vc in V_msgs]
        print(f"    From nodes: {sorted(vc_senders)}")
        
        print(f"  Pre-prepares in O: {len(O_entries)}")
        if O_entries:
            print(f"    Sequence range: {min(o.get('seq', 0) for o in O_entries)} - {max(o.get('seq', 0) for o in O_entries)}")
            
            # Show details of each pre-prepare
            for o in O_entries:
                seq = o.get('seq', '?')
                is_null = o.get('m') is None
                status = "NULL" if is_null else "REAL"
                print(f"      Seq {seq}: {status} request")
        
        print()


def collect_node_logs(node_inboxes, reply_queue, timeout=2.0):
    """
    Request and collect message logs from all nodes.
    Returns: dict {node_id: [log_entries]}
    """
    logs = {}
    
    # Send GET_LOG request to each node
    for node_id in range(1, NUM_NODES + 1):
        if node_id not in LAST_LIVE_NODES:
            continue  # Skip nodes that are down
        
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
    
    # Collect responses
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


def collect_node_status(node_inboxes, reply_queue, timeout=2.0):
    """
    Request and collect sequence status from all nodes.
    Returns: dict {seq_no: {node_id: status}}
    """
    all_statuses = {}
    
    # Send GET_STATUS request to each node
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
    
    # Collect responses
    start = time.time()
    collected = 0
    expected = len([n for n in range(1, NUM_NODES + 1) if n in LAST_LIVE_NODES])
    
    while collected < expected and (time.time() - start) < timeout:
        try:
            response = reply_queue.get(timeout=0.5)
            if isinstance(response, dict) and response.get("type") == "STATUS_RESPONSE":
                node_id = response.get("node_id")
                seq_statuses = response.get("statuses", {})  # {seq: status}
                
                for seq, status in seq_statuses.items():
                    if seq not in all_statuses:
                        all_statuses[seq] = {}
                    all_statuses[seq][node_id] = status
                
                collected += 1
        except Exception:
            continue
    
    # Fill in 'X' for nodes that didn't respond or don't have status
    for seq in all_statuses:
        for node_id in range(1, NUM_NODES + 1):
            if node_id not in all_statuses[seq]:
                all_statuses[seq][node_id] = 'X'
    
    return all_statuses


def collect_new_view_messages(node_inboxes, reply_queue, timeout=2.0):
    """
    Request and collect NEW-VIEW messages from all nodes.
    Returns: list of NEW-VIEW message dicts
    """
    all_nv_msgs = []
    seen_views = set()
    
    # Send GET_NEW_VIEW request to each node
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
    
    # Collect responses
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
    
    # Sort by view number
    all_nv_msgs.sort(key=lambda x: x.get('v', 0))
    
    return all_nv_msgs


def cleanup(node_procs, client_procs, monitor_proc):
    """Terminate all processes."""
    print("Terminating clients...")
    for p in client_procs:
        try:
            p.terminate()
            p.join(timeout=1.0)
        except Exception:
            pass
    print("Terminating nodes...")
    for p in node_procs:
        try:
            p.terminate()
            p.join(timeout=1.0)
        except Exception:
            pass
    print("Terminating monitor...")
    try:
        monitor_proc.terminate()
        monitor_proc.join(timeout=1.0)
    except Exception:
        pass
    print("Cleanup done")


def _send_control_to_node(node_inboxes, nid, msg_type):
    """Send control message to a node."""
    q = node_inboxes.get(nid)
    if q:
        try:
            q.put({"msg": {"type": msg_type}, "sender": "driver"})
            return True
        except Exception:
            return False
    return False


def main(csvfile):
    global LAST_LIVE_NODES, NODE_MESSAGE_LOGS, NEW_VIEW_MESSAGES

    mp.set_start_method("spawn", force=True)
    manager = mp.Manager()
    keyring = create_keyring(NUM_NODES)

    # Initialize attack orchestrator
    orchestrator = initialize_orchestrator(NUM_NODES)
    print(f"Initialized attack orchestrator for {NUM_NODES} nodes")

    # Parse CSV with attack support
    print(f"\nParsing CSV file: {csvfile}")
    sets = parse_csv_with_attacks(csvfile)
    if not sets:
        print("No sets parsed; exiting.")
        return

    print(f"\nParsed {len(sets)} sets:")
    for s in sets:
        print(f"  Set {s['set_no']}: {len(s['transactions'])} txns, "
              f"live={s.get('live')}, byzantine={s.get('byzantine')}, attacks={s.get('attacks')}")

    # Create queues
    node_inboxes = {nid: manager.Queue() for nid in range(1, NUM_NODES + 1)}
    client_control_queues = {cid: manager.Queue() for cid in range(1, NUM_CLIENTS + 1)}
    client_reply_queues = {cid: manager.Queue() for cid in range(1, NUM_CLIENTS + 1)}
    driver_ack_queues = {cid: manager.Queue() for cid in range(1, NUM_CLIENTS + 1)}
    driver_reply_queue = manager.Queue()  # For collecting logs/status from nodes

    monitor_queue = manager.Queue()
    monitor_db = manager.dict()
    applied_set = manager.dict()
    monitor_log = manager.list()
    monitor_stop = manager.Event()

    # Start monitor
    monitor_proc = mp.Process(target=monitor_main, args=(
        monitor_queue, monitor_db, applied_set, monitor_log, monitor_stop, NUM_NODES
    ))
    monitor_proc.start()

    readiness_queue = manager.Queue()

    # Start nodes
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

    # Wait for NODE_READY
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
            print(f"Driver: NODE_READY from node {msg.get('node')} ({ready_count}/{NUM_NODES})")
    if ready_count < NUM_NODES:
        print(f"Warning: only {ready_count}/{NUM_NODES} nodes ready")

    # Start clients
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

    # Initial menu before first set
    print("\n" + "="*60)
    print("All nodes are up and ready.")
    print("="*60)
    print("Commands: [Enter=start first set, PrintDB, quit]")
    
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

    # Process each set
    for s in sets:
        # Reset per-set data structures
        NODE_MESSAGE_LOGS = {}
        NEW_VIEW_MESSAGES = []
        node_status_cache = {}
        
        sid = s["set_no"]
        entries = s["transactions"]
        live_nodes = s.get("live", list(range(1, NUM_NODES + 1)))
        byzantine_nodes = s.get("byzantine", [])
        attack_strings = s.get("attacks", [])

        # Note: CSV parser now handles replicating single attack to multiple Byzantine nodes
        # No need for additional logic here

        # Configure orchestrator
        orchestrator.configure_set(live_nodes, byzantine_nodes, attack_strings)

        # Determine crashed nodes
        crashed = orchestrator.get_crashed_nodes()
        if crashed:
            print(f"⚠️  Crashed nodes for this set (will be PAUSED even if listed live): {crashed}")

        # Effective live nodes
        live_nodes_set = set(live_nodes) - set(crashed)
        LAST_LIVE_NODES = set(live_nodes_set)

        leader_info = leader_for_view(0, NUM_NODES)

        # PAUSE/UNPAUSE nodes based on live set
        for nid in range(1, NUM_NODES + 1):
            if nid in live_nodes_set:
                _send_control_to_node(node_inboxes, nid, "UNPAUSE")
            else:
                _send_control_to_node(node_inboxes, nid, "PAUSE")

        # Build attack_map and send RESET (this resets sequence numbers to start from 1)
        attack_map = orchestrator.to_serializable_map()

        print(f"\n=== Starting Set {sid} ===")
        print(f"Leader: Node {leader_info}")
        print(f"Live nodes (CSV): {sorted(list(live_nodes))}")
        print(f"Effective live nodes (after crash): {sorted(list(live_nodes_set))}")
        
        for nid in range(1, NUM_NODES + 1):
            if nid in live_nodes_set:
                node_inboxes[nid].put({"msg": {"type": "RESET", "attack_map": attack_map}, "sender": "driver"})
        monitor_queue.put({"type": "RESET"})
        time.sleep(0.3)

        # Process transactions sequentially
        for txn_idx, txn in enumerate(entries, 1):
            print(f"\n--- Transaction {txn_idx}/{len(entries)} ---")

            if txn.get("type") == "read":
                cname = txn.get("s")
                cid = CLIENT_NAME_TO_ID.get(cname)
                if cid is None:
                    print(f"Unknown client name {cname}")
                    continue

                print(f"Dispatching READ from {cname}: {txn}")
                client_control_queues[cid].put({
                    "type": "read",
                    "op": {"type": "read", "s": cname},
                    "reply_to": driver_ack_queues[cid]
                })

                try:
                    ack = driver_ack_queues[cid].get(timeout=15.0)
                    print(f"✓ READ by {cname} completed: {ack}")
                except Exception as e:
                    print(f"✗ READ by {cname} TIMEOUT/ERROR: {e}")

            elif txn.get("type") == "write":
                op = txn.get("op")
                sname = op.get("s")
                cid = CLIENT_NAME_TO_ID.get(sname)
                if cid is None:
                    print(f"Unknown client name {sname}")
                    continue

                print(f"Dispatching WRITE from {sname}: {op}")
                client_control_queues[cid].put({
                    "type": "write",
                    "op": op,
                    "reply_to": driver_ack_queues[cid]
                })

                try:
                    ack = driver_ack_queues[cid].get(timeout=15.0)
                    print(f"✓ WRITE by {sname} completed: {ack}")
                except Exception as e:
                    print(f"✗ WRITE by {sname} TIMEOUT/ERROR: {e}")

            time.sleep(0.2)

        # Wait a moment for any final messages to propagate
        print("\n--- Waiting for protocol to settle ---")
        time.sleep(2.0)

        # Collect logs and status at end of set
        print("\n--- Collecting node logs and status ---")
        NODE_MESSAGE_LOGS = collect_node_logs(node_inboxes, driver_reply_queue)
        node_status_cache = collect_node_status(node_inboxes, driver_reply_queue)
        NEW_VIEW_MESSAGES = collect_new_view_messages(node_inboxes, driver_reply_queue)
        
        print(f"Collected logs from {len(NODE_MESSAGE_LOGS)} nodes")
        print(f"Collected status for {len(node_status_cache)} sequences")
        print(f"Collected {len(NEW_VIEW_MESSAGES)} NEW-VIEW messages")

        # Print final state
        print(f"\n=== Set {sid} Complete ===")
        time.sleep(0.5)
        print("\nFinal state after set:")
        PrintDB(monitor_db, applied_set)

        # Post-set interactive menu (only menu, removed pre-set menu)
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

    # After all sets
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