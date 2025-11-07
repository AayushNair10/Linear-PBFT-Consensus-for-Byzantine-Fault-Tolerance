# run_driver.py - With Byzantine attack support (driver sends attack_map to nodes)
"""
Driver that configures attacks via AttackOrchestrator and serializes attack_map
into RESET messages so spawned node processes can reconstruct AttackConfig locally.
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


def PrintLog(node_id, node_processes_dict=None):
    """
    Print protocol message log for a specific node.
    node_processes_dict: dict mapping node_id to Node object (for accessing message_log)
    """
    print("[PrintLog] (This driver prints only DB/status. Node message logs are shown by Node 'PrintLog' log function.)")


def PrintStatus(seq_no, applied_set=None, monitor_log=None):
    """Print status for a sequence number."""
    if monitor_log is not None:
        try:
            found = []
            for entry in list(monitor_log):
                if isinstance(entry, dict) and entry.get("seq") == seq_no:
                    found.append(entry)
            if found:
                print(f"[PrintStatus] Found {len(found)} entries for seq {seq_no}:")
                for e in found:
                    print(e)
                return
        except Exception:
            pass

    if applied_set is None:
        print(f"[PrintStatus] No applied_set available for seq {seq_no}.")
        return
    try:
        val = applied_set.get(seq_no, None)
        if val is None:
            val = applied_set.get(str(seq_no), None)
        if val is None:
            print(f"[PrintStatus] No status found for seq {seq_no}.")
        else:
            print(f"[PrintStatus] seq {seq_no}: {val}")
    except Exception as e:
        print(f"[PrintStatus] Error: {e}")


def PrintView(monitor_log=None):
    """Print NEW_VIEW related information."""
    if monitor_log is None:
        print("[PrintView] No monitor_log available.")
        return
    found = 0
    try:
        for entry in list(monitor_log):
            if isinstance(entry, dict) and entry.get("type") == "NEW_VIEW":
                print(entry)
                found += 1
            else:
                s = str(entry)
                if "NEW_VIEW" in s or "new view" in s.lower():
                    print(entry)
                    found += 1
        if found == 0:
            print("[PrintView] No NEW_VIEW messages recorded.")
    except Exception as e:
        print(f"[PrintView] Error: {e}")


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
    global LAST_LIVE_NODES

    mp.set_start_method("spawn", force=True)
    manager = mp.Manager()
    keyring = create_keyring(NUM_NODES)

    # NEW: Initialize attack orchestrator
    orchestrator = initialize_orchestrator(NUM_NODES)
    print(f"Initialized attack orchestrator for {NUM_NODES} nodes")

    # NEW: Parse CSV with attack support
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
            node_inboxes[nid],      # node's inbox
            node_inboxes,           # all node inboxes for node-to-node communication
            client_reply_queues,    # client reply queues for sending REPLY messages
            monitor_queue,
            readiness_queue,
            5.0                     # base timer = 5 seconds
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
            8.0  # client timeout = 8 seconds (you can increase this)
        ))
        p.start()
        client_procs.append(p)

    time.sleep(0.5)

    # Process each set
    for s in sets:
        sid = s["set_no"]
        entries = s["transactions"]
        live_nodes = s.get("live", list(range(1, NUM_NODES + 1)))
        byzantine_nodes = s.get("byzantine", [])
        attack_strings = s.get("attacks", [])

        # Ensure attack_strings length matches byzantine_nodes
        while len(attack_strings) < len(byzantine_nodes):
            attack_strings.append("")

        # Configure orchestrator BEFORE we pause/unpause nodes
        orchestrator.configure_set(live_nodes, byzantine_nodes, attack_strings)

        # Determine crashed nodes from orchestrator (driver simulates crash via PAUSE)
        crashed = orchestrator.get_crashed_nodes()
        if crashed:
            print(f"⚠️  Crashed nodes for this set (will be PAUSED even if listed live): {crashed}")

        # Effective live nodes: CSV live_nodes minus crashed nodes
        live_nodes_set = set(live_nodes) - set(crashed)
        LAST_LIVE_NODES = set(live_nodes_set)

        leader_info = leader_for_view(0, NUM_NODES)

        # Interactive menu BEFORE configuring attacks and pausing crashed nodes
        while True:
            cmd = input(
                f"\nReady to process Set {sid} ({len(entries)} txns).\n"
                f"Leader: Node {leader_info}\n"
                f"Live nodes (CSV): {sorted(list(live_nodes))}\n"
                f"Effective live nodes (after crash): {sorted(list(live_nodes_set))}\n"
                "Commands: [Enter=continue, PrintDB, PrintLog <n>, PrintStatus <n>, PrintView, quit]\n> "
            ).strip()

            if cmd == "":
                break
            tok = cmd.strip().split()
            if len(tok) == 0:
                break
            c0 = tok[0].lower()

            if c0 in ("continue", "c"):
                break
            if c0 in ("quit", "exit"):
                cleanup(node_procs, client_procs, monitor_proc)
                return
            if c0 == "printdb":
                PrintDB(monitor_db, applied_set)
                continue
            if c0 == "printlog":
                if len(tok) == 2 and tok[1].isdigit():
                    PrintLog(int(tok[1]))
                else:
                    print("Usage: PrintLog <node_id>")
                continue
            if c0 == "printstatus":
                if len(tok) == 2 and tok[1].isdigit():
                    PrintStatus(int(tok[1]), applied_set, monitor_log)
                else:
                    print("Usage: PrintStatus <seq_no>")
                continue
            if c0 == "printview":
                PrintView(monitor_log)
                continue
            print("Invalid command")

        # PAUSE crashed nodes and nodes not in live set
        for nid in range(1, NUM_NODES + 1):
            if nid in live_nodes_set:
                _send_control_to_node(node_inboxes, nid, "UNPAUSE")
            else:
                _send_control_to_node(node_inboxes, nid, "PAUSE")

        # Build attack_map (serializable) for all nodes and include it in RESET
        attack_map = orchestrator.to_serializable_map()

        # Reset only effective live nodes: include attack_map so every node knows configs
        print(f"=== Starting Set {sid} ===")
        for nid in range(1, NUM_NODES + 1):
            if nid in live_nodes_set:
                # send RESET with attack_map to each live node
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

        # Print final state
        print(f"\n=== Set {sid} Complete ===")
        time.sleep(0.5)
        print("\nFinal state after set:")
        PrintDB(monitor_db, applied_set)

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
                PrintLog(int(parts[1]))
            else:
                print("Usage: printlog <node_id>")
        elif cmd.lower().startswith("printstatus"):
            parts = cmd.split()
            if len(parts) == 2 and parts[1].isdigit():
                PrintStatus(int(parts[1]), applied_set, monitor_log)
            else:
                print("Usage: printstatus <seq_no>")
        elif cmd.lower() == "printview":
            PrintView(monitor_log)
        else:
            print("Unknown command")

    cleanup(node_procs, client_procs, monitor_proc)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run_driver.py test.csv")
        sys.exit(1)
    csvfile = sys.argv[1]
    main(csvfile)
