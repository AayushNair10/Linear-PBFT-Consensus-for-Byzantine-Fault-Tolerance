# node.py - COMPLETE with Byzantine Attack Support (UPDATED view-change logic)
"""
PBFT Node with updated view-change behavior:

Changes implemented:
- When a node's timer expires it multicasts VIEW-CHANGE to all replicas (as before).
- When any node *receives* a VIEW-CHANGE for a higher view, it:
    - stops its request timer,
    - marks that it's participating in view-change (in_view_change=True),
    - sends its *own* VIEW-CHANGE message directly to the new-view leader (point-to-point via send_to_node),
      instead of multicasting to all replicas.
- The designated new leader (leader_for_view(target_view, n)) collects VIEW-CHANGE messages (point-to-point or
  multicast originals). Once the new leader has 2f+1 VIEW-CHANGE messages (including its own), it forms and
  multicasts NEW-VIEW to all replicas.
- Incoming VIEW-CHANGE envelopes are accepted if they carry either an authenticator vector ("auth") or a single MAC.
  (So both the original multicast and the point-to-point forwarded ones are accepted.)
- Timers are stopped/reset on observing any VIEW-CHANGE for a higher view.

All other behavior is preserved.
"""

import json
import time
import threading
import queue
import hashlib
from typing import Any, Dict, Tuple, List, Optional

from keys import create_authenticator, mac_for_pair, verify_authenticator, verify_mac
from common import (
    MSG_REQUEST,
    MSG_PREPREPARE,
    MSG_PREPARE,
    MSG_COMMIT,
    MSG_REPLY,
    MSG_EXECUTE,
    leader_for_view,
)
from attacks import get_attack_config

F = 2
WINDOW_SIZE = 100


def sha256_digest(obj: Any) -> str:
    """Deterministic SHA-256 digest of a JSON-serializable object."""
    b = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b).hexdigest()


class Node:
    def __init__(
        self,
        node_id: int,
        n_replicas: int,
        keyring: Dict[Tuple[int, int], bytes],
        inbox_queue,
        out_queues: Dict[int, Any],
        client_queues: Dict[int, Any],
        monitor_queue=None,
        readiness_queue=None,
        base_timer: float = 10.0,
    ):
        self.id = int(node_id)
        self.n = int(n_replicas)
        self.keyring = keyring
        self.inbox = inbox_queue
        self.out_queues = out_queues
        self.client_queues = client_queues
        self.monitor_queue = monitor_queue
        self.readiness_queue = readiness_queue

        # Message log for PrintLog - stores all protocol messages
        self.message_log: List[Dict[str, Any]] = []
        self.message_log_lock = threading.Lock()

        self.view = 0
        self.next_seq = 1
        self.low = 0
        self.high = self.low + WINDOW_SIZE

        self.seq_state: Dict[int, Dict] = {}
        self.state_lock = threading.Lock()

        self.processed_requests: Dict[Tuple[int, str], int] = {}

        self.view_change_msgs: Dict[int, Dict[int, Dict]] = {}
        self.new_view_msgs: List[Dict] = []
        self.in_view_change = False

        self.datastore: Dict[str, int] = {}
        self.timer = None
        self.timer_timeout = base_timer + float(self.id)

        self._stop = threading.Event()
        self.active = True

        # ATTACK: Get attack configuration
        self.attack_config = get_attack_config(self.id)

        self.reset_datastore()

        try:
            self._broadcast_auth_init()
            time.sleep(0.05)
        except Exception as e:
            self.log_event(f"Auth-init broadcast exception: {e}")

        if self.readiness_queue is not None:
            try:
                self.readiness_queue.put({"type": "NODE_READY", "node": self.id})
                self.log_event(f"Sent NODE_READY (Byzantine={self.attack_config.is_byzantine})")
            except Exception:
                self.log_event("Failed to send NODE_READY")

    def log_event(self, s: str):
        """Timestamped event logging."""
        ts = time.time()
        prefix = "[BYZ]" if self.attack_config.is_byzantine else ""
        print(f"[Node {self.id} | view {self.view}]{prefix} {s}")
    
    def log_message(self, msg_type: str, msg: Dict[str, Any], direction: str = "SENT"):
        """Log protocol messages for PrintLog."""
        with self.message_log_lock:
            log_entry = {
                "timestamp": time.time(),
                "type": msg_type,
                "direction": direction,  # "SENT", "RECEIVED", "PROCESSED"
                "view": msg.get("v", self.view),
                "seq": msg.get("seq", None),
                "digest": msg.get("d", None),
                "sender": msg.get("i", self.id),
                "client": msg.get("c", None),
                "request_id": msg.get("t", None),
                "message": msg
            }
            self.message_log.append(log_entry)
    
    def get_message_log(self) -> List[Dict[str, Any]]:
        """Get copy of message log for PrintLog."""
        with self.message_log_lock:
            return list(self.message_log)

    def reset_datastore(self):
        """Populate datastore with clients A..J with balance 10."""
        self.datastore.clear()
        for i in range(10):
            name = chr(ord("A") + i)
            self.datastore[name] = 10
        self.log_event("Datastore reset to initial balances (10 each)")

    def _broadcast_auth_init(self):
        """Broadcast AUTH_INIT with authenticator to other replicas (exclude self)."""
        msg = {"type": "AUTH_INIT", "node": self.id, "time": time.time()}
        recipients = [r for r in list(self.out_queues.keys()) if r != self.id]
        msg_bytes = json.dumps(msg, sort_keys=True).encode("utf-8")
        auth = create_authenticator(self.keyring, self.id, recipients, msg_bytes)
        
        # ATTACK: Corrupt signatures if sign attack
        if self.attack_config.sign_attack:
            auth = self.attack_config.corrupt_signature(auth)
            self.log_event("🔴 ATTACK: Corrupted AUTH_INIT signatures")
        
        envelope = {"msg": msg, "auth": auth, "sender": self.id}
        sent = 0
        for r in recipients:
            # ATTACK: Skip if dark attack targets this node
            if self.attack_config.should_drop_message_to(r):
                self.log_event(f"🔴 ATTACK: Dropped AUTH_INIT to node {r} (dark)")
                continue
                
            q = self.out_queues.get(r)
            if q:
                q.put(envelope)
                sent += 1
        self.log_event(f"Broadcasted AUTH_INIT to {sent} replicas")

    def start_request_timer(self):
        """Start the node's request timer if not already running."""
        if self.timer and self.timer.is_alive():
            return
        self.log_event(f"Starting request timer ({self.timer_timeout}s)")
        self.timer = threading.Timer(self.timer_timeout, self._on_timer_expiry)
        self.timer.daemon = True
        self.timer.start()

    def stop_request_timer(self):
        """Cancel the request timer if running."""
        if self.timer:
            try:
                self.timer.cancel()
            except Exception:
                pass
            self.timer = None
            self.log_event("Stopped request timer")

    def _on_timer_expiry(self):
        """Called when request timer expires."""
        self.log_event(f"Request timer expired in view {self.view}: initiating view-change")
        try:
            self.start_view_change(self.view + 1)
        except Exception as e:
            self.log_event(f"Exception starting view-change: {e}")

    def multicast_with_authenticator(self, msg: Dict[str, Any], recipients: Optional[List[int]] = None):
        """Multicast a message with authenticator vector to given recipients (exclude self)."""
        if recipients is None:
            recipients = list(self.out_queues.keys())

        recipients_to_send = [r for r in recipients if r != self.id]

        msg_bytes = json.dumps(msg, sort_keys=True).encode("utf-8")
        auth = create_authenticator(self.keyring, self.id, recipients_to_send, msg_bytes)
        
        # ATTACK: Corrupt signatures if sign attack
        if self.attack_config.sign_attack:
            auth = self.attack_config.corrupt_signature(auth)
            self.log_event(f"🔴 ATTACK: Corrupted signatures for {msg.get('type')}")
        
        envelope = {"msg": msg, "auth": auth, "sender": self.id}
        
        # ATTACK: Apply time delay if time attack
        if self.attack_config.time_attack:
            self.attack_config.apply_time_delay()
            self.log_event(f"🔴 ATTACK: Applied time delay of {self.attack_config.time_delay_ms}ms")

        sent = 0
        for r in recipients_to_send:
            # ATTACK: Skip if dark attack targets this node
            if self.attack_config.should_drop_message_to(r):
                self.log_event(f"🔴 ATTACK: Dropped {msg.get('type')} to node {r} (dark)")
                continue
                
            q = self.out_queues.get(r)
            if q:
                q.put(envelope)
                sent += 1

        self.log_event(f"Multicasted {msg.get('type')} seq={msg.get('seq','')} to {sent} replicas")

    def send_to_node(self, target: int, msg: Dict[str, Any]):
        """Send a point-to-point message to another node with a single MAC."""
        msg_bytes = json.dumps(msg, sort_keys=True).encode("utf-8")
        try:
            mac = mac_for_pair(self.keyring, self.id, target, msg_bytes)
            envelope = {"msg": msg, "mac": mac, "sender": self.id}
        except Exception:
            envelope = {"msg": msg, "sender": self.id}
        
        # ATTACK: Skip if dark attack targets this node
        if self.attack_config.should_drop_message_to(target):
            self.log_event(f"🔴 ATTACK: Dropped {msg.get('type')} to node {target} (dark)")
            return
        
        q = self.out_queues.get(target)
        if q:
            q.put(envelope)
        else:
            self.log_event(f"ERROR: No queue to send to node {target}")

    def send_to_client(self, client_id: int, msg: Dict[str, Any]):
        """Send a REPLY message to a client with a single MAC."""
        # ATTACK: Crash attack - don't send replies
        if msg.get("type") == MSG_REPLY and self.attack_config.should_block_reply():
            self.log_event(f"🔴 ATTACK: Crash - not sending REPLY to client {client_id}")
            return
        
        msg_bytes = json.dumps(msg, sort_keys=True).encode("utf-8")
        try:
            mac = mac_for_pair(self.keyring, self.id, client_id, msg_bytes)
            envelope = {"msg": msg, "mac": mac, "sender": self.id}
        except Exception:
            envelope = {"msg": msg, "sender": self.id}
        
        q = self.client_queues.get(client_id)
        if q:
            q.put(envelope)
            self.log_event(f"Sent REPLY to client {client_id}")
        else:
            self.log_event(f"ERROR: No client queue for client {client_id}")

    def verify_authenticator_for_self(self, envelope: Dict[str, Any]) -> bool:
        """Verify an incoming envelope that carries an authenticator vector."""
        if "auth" not in envelope:
            return False
        sender = envelope.get("sender")
        msg = envelope.get("msg")
        msg_bytes = json.dumps(msg, sort_keys=True).encode("utf-8")
        ok = verify_authenticator(self.keyring, sender, self.id, msg_bytes, envelope.get("auth"))
        if not ok:
            self.log_event(f"Auth verification FAILED for {msg.get('type')} from {sender} (possibly sign attack)")
        return ok

    def verify_single_mac_for_self(self, envelope: Dict[str, Any]) -> bool:
        """Verify a point-to-point envelope with a single MAC."""
        if "mac" not in envelope:
            return False
        sender = envelope.get("sender")
        msg = envelope.get("msg")
        msg_bytes = json.dumps(msg, sort_keys=True).encode("utf-8")
        ok = verify_mac(self.keyring, sender, self.id, msg_bytes, envelope.get("mac"))
        if not ok:
            self.log_event(f"MAC verification FAILED for {msg.get('type')} from {sender}")
        return ok

    def handle_request(self, envelope: Dict[str, Any]):
        """Handle client WRITE REQUEST."""
        if not self.active:
            return

        msg = envelope.get("msg")
        sender = envelope.get("sender")
        op = msg.get("op", {})
        client_id = msg.get("c")
        tstamp = msg.get("t")

        if op.get("type") == "read":
            self.handle_read_request(envelope)
            return

        self.log_event(f"Received WRITE REQUEST from client {sender}")
        self.log_message("REQUEST", msg, "RECEIVED")

        if self.in_view_change:
            self.log_event("In view-change: ignoring request")
            return

        # NON-PRIMARY: Start timer to detect Byzantine/failed leader
        if self.id != leader_for_view(self.view, self.n):
            self.log_event(f"Not leader (leader is {leader_for_view(self.view, self.n)}): waiting for PRE-PREPARE")
            
            # Start timer if not already running - expecting PRE-PREPARE from leader
            if not self.in_view_change and not (self.timer and self.timer.is_alive()):
                self.start_request_timer()
                self.log_event("Started timer (expecting PRE-PREPARE from leader)")
            
            return

        # PRIMARY: Check for duplicates
        request_key = (client_id, tstamp)
        
        with self.state_lock:
            if request_key in self.processed_requests:
                existing_seq = self.processed_requests[request_key]
                self.log_event(f"Duplicate request (seq={existing_seq}): ignoring")
                
                existing_st = self.seq_state.get(existing_seq)
                if existing_st and existing_st.get("executed"):
                    result = existing_st.get("result")
                    if result:
                        reply_msg = {"type": MSG_REPLY, "v": self.view, "t": tstamp, "c": client_id, "i": self.id, "r": result}
                        self.send_to_client(client_id, reply_msg)
                return

        seq = self.next_seq
        if seq >= self.high:
            self.log_event(f"Seq {seq} >= high {self.high}: dropping")
            return
        self.next_seq += 1

        d = sha256_digest(msg)
        
        with self.state_lock:
            self.processed_requests[request_key] = seq
            
            st = self.seq_state.setdefault(seq, {
                "preprepare": None, "prepares": {}, "prepare_multicast": None,
                "commits": {}, "commit_multicast": None, "executed": False, "status": "PP",
                "sent_prepare": False, "result": None
            })
            st["preprepare"] = {"view": self.view, "seq": seq, "digest": d, "request": msg, "sender": self.id}
            # Leader adds its own prepare immediately
            st["prepares"][self.id] = {"type": MSG_PREPARE, "v": self.view, "seq": seq, "d": d, "i": self.id}
            st["sent_prepare"] = True

        # ATTACK: Equivocation - send conflicting preprepares
        if self.attack_config.equivocation_attack:
            self._handle_equivocation_attack(seq, msg, d)
        else:
            # Normal flow
            preprepare_msg = {"type": MSG_PREPREPARE, "v": self.view, "seq": seq, "d": d, "m": msg}
            self.multicast_with_authenticator(preprepare_msg)
            self.log_message("PREPREPARE", preprepare_msg, "SENT")
            self.log_event(f"Leader multicasted PREPREPARE seq={seq}")

    def _handle_equivocation_attack(self, base_seq: int, msg: Dict, digest: str):
        """
        ATTACK: Equivocation - send conflicting preprepares to different nodes.
        Send base_seq to some nodes and base_seq+1 to equivocation targets.
        """
        self.log_event(f"🔴 ATTACK: Equivocation - sending seq={base_seq} and seq={base_seq+1}")
        
        all_recipients = [r for r in list(self.out_queues.keys()) if r != self.id]
        
        for target in all_recipients:
            if target in self.attack_config.equivocation_targets:
                # Send conflicting preprepare with seq+1
                alt_seq = base_seq + 1
                preprepare_msg = {"type": MSG_PREPREPARE, "v": self.view, "seq": alt_seq, "d": digest, "m": msg}
                self.log_event(f"🔴 ATTACK: Sending PREPREPARE seq={alt_seq} to node {target}")
            else:
                # Send normal preprepare
                preprepare_msg = {"type": MSG_PREPREPARE, "v": self.view, "seq": base_seq, "d": digest, "m": msg}
            
            # Send individually
            msg_bytes = json.dumps(preprepare_msg, sort_keys=True).encode("utf-8")
            auth = create_authenticator(self.keyring, self.id, [target], msg_bytes)
            
            # ATTACK: Corrupt signature if sign attack also active
            if self.attack_config.sign_attack:
                auth = self.attack_config.corrupt_signature(auth)
            
            envelope = {"msg": preprepare_msg, "auth": auth, "sender": self.id}
            
            # ATTACK: Skip if dark attack targets this node
            if self.attack_config.should_drop_message_to(target):
                continue
            
            q = self.out_queues.get(target)
            if q:
                q.put(envelope)

    def handle_preprepare(self, envelope: Dict[str, Any]):
        """Backup receives PRE-PREPARE from leader."""
        if not self.active:
            return

        if not self.verify_authenticator_for_self(envelope):
            return
        
        msg = envelope.get("msg")
        v = msg.get("v")
        seq = msg.get("seq")
        d = msg.get("d")
        m = msg.get("m")
        leader = envelope.get("sender")
        
        self.log_event(f"Received PREPREPARE seq={seq} from leader {leader}")
        self.log_message("PREPREPARE", msg, "RECEIVED")

        if self.in_view_change:
            self.log_event("In view-change: ignoring")
            return
        if v != self.view:
            self.log_event(f"View mismatch: {v} != {self.view}")
            return
        if seq < self.low or seq >= self.high:
            self.log_event(f"Seq {seq} outside window [{self.low},{self.high})")
            return
        if sha256_digest(m) != d:
            self.log_event("Digest mismatch")
            return

        with self.state_lock:
            st = self.seq_state.setdefault(seq, {
                "preprepare": None, "prepares": {}, "prepare_multicast": None,
                "commits": {}, "commit_multicast": None, "executed": False, "status": "PP",
                "sent_prepare": False, "result": None
            })
            st["preprepare"] = {"view": v, "seq": seq, "digest": d, "request": m, "sender": leader}

            # ATTACK: Crash attack - backup doesn't send prepare
            if self.attack_config.should_block_prepare(False):
                self.log_event(f"🔴 ATTACK: Crash - not sending PREPARE for seq={seq}")
                st["sent_prepare"] = True  # Mark as sent to prevent resend
                return

            if not st.get("sent_prepare", False):
                prepare_msg = {"type": MSG_PREPARE, "v": v, "seq": seq, "d": d, "i": self.id}
                leader_id = leader_for_view(self.view, self.n)
                self.send_to_node(leader_id, prepare_msg)
                self.log_message("PREPARE", prepare_msg, "SENT")
                st["sent_prepare"] = True
                self.log_event(f"Sent PREPARE to leader {leader_id} for seq={seq}")

        # Reset timer - received PRE-PREPARE from leader (leader is alive)
        # Now wait for execution
        if not self.in_view_change:
            self.stop_request_timer()
            self.start_request_timer()
            self.log_event("Reset timer (now waiting for execution)")

    def handle_prepare_point_to_point(self, envelope: Dict[str, Any]):
        """Leader receives PREPARE from a backup."""
        if not self.active:
            return

        if not self.verify_single_mac_for_self(envelope):
            return
        
        msg = envelope.get("msg")
        seq = msg.get("seq")
        i = msg.get("i")
        
        self.log_event(f"Leader received PREPARE from node {i} for seq={seq}")
        self.log_message("PREPARE", msg, "RECEIVED")
        
        with self.state_lock:
            st = self.seq_state.setdefault(seq, {
                "preprepare": None, "prepares": {}, "prepare_multicast": None,
                "commits": {}, "commit_multicast": None, "executed": False, "status": "PP",
                "sent_prepare": False, "result": None
            })
            st["prepares"][i] = msg
            
        self._try_to_multicast_prepare(seq)

    def _try_to_multicast_prepare(self, seq: int):
        """Leader checks for 2f+1 prepares and multicasts PREPARE_MULTICAST."""
        if not self.active:
            return
        if self.id != leader_for_view(self.view, self.n):
            return
        
        # ATTACK: Crash attack - leader doesn't send prepare_multicast
        if self.attack_config.should_block_prepare(True):
            self.log_event(f"🔴 ATTACK: Crash - blocking PREPARE_MULTICAST for seq={seq}")
            return
        
        pm = None  # MUST initialize BEFORE any lock blocks
        
        with self.state_lock:
            st = self.seq_state.get(seq)
            if not st:
                return
            if st.get("prepare_multicast") is not None:
                return  # Already multicasted
                
            prepares = st["prepares"]
            num_prepares = len(prepares)
            
            self.log_event(f"Leader has {num_prepares} prepares for seq={seq} (need {2*F+1})")
            
            if num_prepares >= (2 * F + 1):
                pm_list = list(prepares.values())
                d = st["preprepare"]["digest"]
                prepare_multicast = {"type": "PREPARE_MULTICAST", "v": self.view, "seq": seq, "d": d, "prepares": pm_list}
                st["prepare_multicast"] = prepare_multicast
                st["status"] = "P"
                
                # Leader adds its own commit BEFORE multicasting
                commit_msg = {"type": MSG_COMMIT, "v": self.view, "seq": seq, "d": d, "i": self.id}
                st["commits"][self.id] = commit_msg
                
                pm = prepare_multicast  # Assign to pm so we can multicast outside lock
                
                self.log_event(f"Leader ready to multicast PREPARE_MULTICAST for seq={seq} with {num_prepares} prepares")
        
        # Multicast outside lock if we created the message
        if pm is not None:
            self.multicast_with_authenticator(pm)
            self.log_message("PREPARE_MULTICAST", pm, "SENT")
            self.log_event(f"Leader multicasted PREPARE_MULTICAST and added self-commit for seq={seq}")

    def handle_prepare_multicast(self, envelope: Dict[str, Any]):
        """Backup receives PREPARE_MULTICAST."""
        if not self.active:
            return

        if not self.verify_authenticator_for_self(envelope):
            return
        
        msg = envelope.get("msg")
        v = msg.get("v")
        seq = msg.get("seq")
        d = msg.get("d")
        prepares = msg.get("prepares", [])
        
        self.log_event(f"Received PREPARE_MULTICAST seq={seq} with {len(prepares)} prepares")
        self.log_message("PREPARE_MULTICAST", msg, "RECEIVED")
        
        if v != self.view:
            self.log_event("View mismatch")
            return
            
        with self.state_lock:
            st = self.seq_state.setdefault(seq, {
                "preprepare": None, "prepares": {}, "prepare_multicast": None,
                "commits": {}, "commit_multicast": None, "executed": False, "status": "P",
                "sent_prepare": False, "result": None
            })
            st["prepare_multicast"] = msg
            for p in prepares:
                pid = p.get("i")
                st["prepares"][pid] = p
        
        # ATTACK: Crash attack - backup doesn't send commit
        if self.attack_config.should_block_commit(False):
            self.log_event(f"🔴 ATTACK: Crash - not sending COMMIT for seq={seq}")
            return
                
        commit_msg = {"type": MSG_COMMIT, "v": v, "seq": seq, "d": d, "i": self.id}
        leader_id = leader_for_view(self.view, self.n)
        self.send_to_node(leader_id, commit_msg)
        self.log_message("COMMIT", commit_msg, "SENT")
        self.log_event(f"Sent COMMIT to leader {leader_id} for seq={seq}")

    def handle_commit_point_to_point(self, envelope: Dict[str, Any]):
        """Leader receives COMMIT from a backup."""
        if not self.active:
            return

        if not self.verify_single_mac_for_self(envelope):
            return
        
        msg = envelope.get("msg")
        seq = msg.get("seq")
        i = msg.get("i")
        
        self.log_event(f"Leader received COMMIT from node {i} for seq={seq}")
        self.log_message("COMMIT", msg, "RECEIVED")
        
        with self.state_lock:
            st = self.seq_state.setdefault(seq, {
                "preprepare": None, "prepares": {}, "prepare_multicast": None,
                "commits": {}, "commit_multicast": None, "executed": False, "status": "P",
                "sent_prepare": False, "result": None
            })
            st["commits"][i] = msg
            
        self._try_to_multicast_commit(seq)

    def _try_to_multicast_commit(self, seq: int):
        """Leader checks for 2f+1 commits and multicasts COMMIT_MULTICAST."""
        if not self.active:
            return
        if self.id != leader_for_view(self.view, self.n):
            return
        
        # ATTACK: Crash attack - leader doesn't send commit_multicast
        if self.attack_config.should_block_commit(True):
            self.log_event(f"🔴 ATTACK: Crash - blocking COMMIT_MULTICAST for seq={seq}")
            return
        
        cm = None  # MUST initialize BEFORE any lock blocks
        
        with self.state_lock:
            st = self.seq_state.get(seq)
            if not st:
                return
            if st.get("commit_multicast") is not None:
                return  # Already multicasted
                
            commits = st["commits"]
            num_commits = len(commits)
            
            self.log_event(f"Leader has {num_commits} commits for seq={seq} (need {2*F+1})")
            
            if num_commits >= (2 * F + 1):
                cm_list = list(commits.values())
                d = st["preprepare"]["digest"]
                commit_multicast = {"type": "COMMIT_MULTICAST", "v": self.view, "seq": seq, "d": d, "commits": cm_list}
                st["commit_multicast"] = commit_multicast
                st["status"] = "C"
                
                cm = commit_multicast  # Assign to cm so we can multicast outside lock
                
                self.log_event(f"Leader ready to multicast COMMIT_MULTICAST for seq={seq} with {num_commits} commits")
        
        # Multicast outside lock if we created the message
        if cm is not None:
            self.multicast_with_authenticator(cm)
            self.log_message("COMMIT_MULTICAST", cm, "SENT")
            self.log_event(f"Leader multicasted COMMIT_MULTICAST for seq={seq}")
            
            # Try to execute immediately after multicasting
            self._try_to_execute(seq)

    def handle_commit_multicast(self, envelope: Dict[str, Any]):
        """Backup receives COMMIT_MULTICAST."""
        if not self.active:
            return

        if not self.verify_authenticator_for_self(envelope):
            return
        
        msg = envelope.get("msg")
        v = msg.get("v")
        seq = msg.get("seq")
        d = msg.get("d")
        commits = msg.get("commits", [])
        
        self.log_event(f"Received COMMIT_MULTICAST seq={seq} with {len(commits)} commits")
        self.log_message("COMMIT_MULTICAST", msg, "RECEIVED")
        
        if v != self.view:
            self.log_event("View mismatch")
            return
            
        with self.state_lock:
            st = self.seq_state.setdefault(seq, {
                "preprepare": None, "prepares": {}, "prepare_multicast": None,
                "commits": {}, "commit_multicast": None, "executed": False, "status": "C",
                "sent_prepare": False, "result": None
            })
            st["commit_multicast"] = msg
            for c in commits:
                pid = c.get("i")
                st["commits"][pid] = c
                
        self._try_to_execute(seq)

    def _try_to_execute(self, seq: int):
        """Execute the request for seq."""
        if not self.active:
            return

        with self.state_lock:
            st = self.seq_state.get(seq)
            if not st or st.get("executed"):
                return
                
            if st.get("preprepare") is None:
                self.log_event(f"Cannot execute seq={seq}: missing preprepare")
                return
            if st.get("prepare_multicast") is None:
                self.log_event(f"Cannot execute seq={seq}: missing prepare_multicast")
                return
            if st.get("commit_multicast") is None:
                self.log_event(f"Cannot execute seq={seq}: missing commit_multicast")
                return
                
            d1 = st["preprepare"]["digest"]
            d2 = st["prepare_multicast"]["d"]
            d3 = st["commit_multicast"]["d"]
            
            if not (d1 == d2 == d3):
                self.log_event(f"Digest mismatch for seq={seq}")
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
                if self.datastore.get(sname, 0) >= amt:
                    self.datastore[sname] -= amt
                    self.datastore[rname] = self.datastore.get(rname, 0) + amt
                    result = {"status": "EXECUTED", "detail": f"{sname}->{rname}:{amt}"}
                    self.log_event(f"✓ EXECUTED seq={seq}: {sname}->{rname}:{amt}")
                else:
                    result = {"status": "FAILED", "detail": "insufficient"}
                    self.log_event(f"✗ FAILED seq={seq}: insufficient balance")
            else:
                sname = op.get("s")
                result = {"status": "EXECUTED", "balance": self.datastore.get(sname, 0)}
                self.log_event(f"✓ EXECUTED seq={seq}: balance query")

            st["executed"] = True
            st["status"] = "E"
            st["result"] = result

        # Log execution
        exec_msg = {"seq": seq, "result": result, "v": self.view}
        self.log_message("EXECUTE", exec_msg, "PROCESSED")

        # Send reply and update monitor
        reply_msg = {"type": MSG_REPLY, "v": self.view, "t": tstamp, "c": client_id, "i": self.id, "r": result}
        self.send_to_client(client_id, reply_msg)
        self.log_message("REPLY", reply_msg, "SENT")

        self.stop_request_timer()

        if self.monitor_queue is not None:
            try:
                snapshot = dict(self.datastore)
                self.monitor_queue.put({"type": "EXECUTED_NOTIFY", "t": tstamp, "node": self.id, "seq": seq, "op": op, "result": result})
                self.monitor_queue.put({"type": "DB_SNAPSHOT", "node": self.id, "seq": seq, "db": snapshot, "t": tstamp})
            except Exception as e:
                self.log_event(f"Failed to send to monitor: {e}")

    def handle_read_request(self, envelope: Dict[str, Any]):
        """Handle read request."""
        if not self.active:
            return

        msg = envelope.get("msg")
        op = msg.get("op", {})
        client_id = msg.get("c")
        tstamp = msg.get("t")

        if op.get("type") == "read":
            sname = op.get("s")
            balance = self.datastore.get(sname, 0)
            result = {"status": "OK", "balance": balance}
            reply_msg = {"type": MSG_REPLY, "v": self.view, "t": tstamp, "c": client_id, "i": self.id, "r": result}
            self.send_to_client(client_id, reply_msg)

    def start_view_change(self, target_view: int):
        """Initiate view-change (originating node multicasts VIEW-CHANGE)."""
        if not self.active:
            return

        self.stop_request_timer()

        if self.in_view_change:
            self.log_event(f"Already in view-change for view {target_view}")
            return

        self.in_view_change = True
        self.log_event(f"🔄 Starting view-change to view {target_view}")

        with self.state_lock:
            if self.id in self.view_change_msgs.get(target_view, {}):
                self.log_event(f"Already sent VIEW-CHANGE for view {target_view}")
                return

            P = []
            for seq, st in self.seq_state.items():
                if seq <= self.low:
                    continue
                pre = st.get("preprepare")
                prepares = st.get("prepares", {})
                if pre is not None and len(prepares) >= (2 * F + 1):
                    pm = {"seq": seq, "view": pre.get("view"), "digest": pre.get("digest"),
                          "prepares": list(prepares.values()), "request": pre.get("request", None)}
                    P.append(pm)
            
            view_change_msg = {"type": "VIEW_CHANGE", "v": target_view, "n": self.low, "C": [], "P": P, "i": self.id}
            # record own view-change
            self.view_change_msgs.setdefault(target_view, {})[self.id] = view_change_msg

        # Originating node multicasts VIEW-CHANGE to inform all replicas that VC process started
        self.multicast_with_authenticator(view_change_msg)
        self.log_event(f"✅ Multicasted VIEW-CHANGE for view {target_view} with {len(P)} P-entries")

    def _delayed_view_change(self, target_view: int):
        """Delayed view-change to avoid message storms."""
        self.log_event(f"_delayed_view_change triggered for view {target_view}")
        time.sleep(0.1)
        with self.state_lock:
            if self.id in self.view_change_msgs.get(target_view, {}):
                self.log_event(f"Already sent VIEW-CHANGE for view {target_view}, skipping")
                return
        self.log_event(f"Calling start_view_change for view {target_view}")
        self.start_view_change(target_view)

    def handle_view_change(self, envelope: Dict[str, Any]):
        """Process VIEW_CHANGE messages.

        NEW LOGIC:
         - Accept envelopes that have either 'auth' (multicast original) or 'mac' (point-to-point).
         - When observing a VIEW-CHANGE for a higher view V:
             * stop own request timer, set in_view_change=True
             * store the received VIEW-CHANGE in view_change_msgs[V]
             * if we haven't sent our own VIEW-CHANGE for V, send our VIEW-CHANGE directly to the new leader
               (leader_for_view(V, n)) using point-to-point send_to_node (this uses a single MAC).
             * if we are the leader for V, check if we have >= 2f+1 VIEW-CHANGE messages; if so, form NEW-VIEW.
        """
        if not self.active:
            return

        # Accept either authenticator vector or single MAC
        ok_auth = self.verify_authenticator_for_self(envelope)
        ok_mac = self.verify_single_mac_for_self(envelope)
        if not (ok_auth or ok_mac):
            return
        
        msg = envelope.get("msg")
        target_view = msg.get("v")
        sender = envelope.get("sender")
        
        if target_view is None:
            return

        if target_view <= self.view:
            # not interested in older/equal view
            return

        self.log_event(f"Received/Observed VIEW-CHANGE for view {target_view} from {sender}")

        # Stop timer and mark participation in view-change
        self.stop_request_timer()
        self.in_view_change = True

        # Store incoming view-change message (store the message dict itself)
        with self.state_lock:
            self.view_change_msgs.setdefault(target_view, {})[sender] = msg

        # If we haven't yet recorded/sent our own view-change for this target, send it to the new leader (point-to-point)
        with self.state_lock:
            already_sent = (self.id in self.view_change_msgs.get(target_view, {}))
        if not already_sent:
            # Build our VIEW-CHANGE message (P entries collected locally)
            P = []
            with self.state_lock:
                for seq, st in self.seq_state.items():
                    if seq <= self.low:
                        continue
                    pre = st.get("preprepare")
                    prepares = st.get("prepares", {})
                    if pre is not None and len(prepares) >= (2 * F + 1):
                        pm = {"seq": seq, "view": pre.get("view"), "digest": pre.get("digest"),
                              "prepares": list(prepares.values()), "request": pre.get("request", None)}
                        P.append(pm)
                our_vc_msg = {"type": "VIEW_CHANGE", "v": target_view, "n": self.low, "C": [], "P": P, "i": self.id}
                # store our own VC locally so leader can count it
                self.view_change_msgs.setdefault(target_view, {})[self.id] = our_vc_msg

            leader_id = leader_for_view(target_view, self.n)
            # send point-to-point to leader (single MAC)
            self.send_to_node(leader_id, our_vc_msg)
            self.log_event(f"Observed VIEW-CHANGE for higher view {target_view}; sent our VIEW-CHANGE to leader {leader_id}")

        # If I am the new leader for target_view, check if I have 2f+1 view-change msgs
        new_leader = leader_for_view(target_view, self.n)
        if new_leader == self.id:
            with self.state_lock:
                num_vc_msgs = len(self.view_change_msgs.get(target_view, {}))
            self.log_event(f"🔑 I am the new leader for view {target_view}! Have {num_vc_msgs}/{2*F+1} VIEW-CHANGEs")
            if num_vc_msgs >= (2 * F + 1):
                self.log_event(f"✅ Forming NEW-VIEW for view {target_view}")
                self._form_and_multicast_new_view(target_view)
            else:
                self.log_event(f"⏳ Waiting for more VIEW-CHANGEs ({num_vc_msgs}/{2*F+1})")

    def _form_and_multicast_new_view(self, target_view: int):
        """
        Form NEW-VIEW according to PBFT paper.
        V = set of 2f+1 valid VIEW-CHANGE messages (including primary's own)
        O = set of pre-prepare messages for view v+1
        """
        # ATTACK: Crash attack - don't send new-view
        if self.attack_config.should_block_newview():
            self.log_event(f"🔴 ATTACK: Crash - not sending NEW-VIEW for view {target_view}")
            return
        
        with self.state_lock:
            V_msgs = list(self.view_change_msgs.get(target_view, {}).values())
        
        self.log_event(f"Forming NEW-VIEW with {len(V_msgs)} VIEW-CHANGE messages")
        
        # Step 1: Determine min-s (highest stable checkpoint)
        min_s = max(vc.get("n", 0) for vc in V_msgs) if V_msgs else 0
        
        # Step 2: Determine max-s (highest sequence number in any prepare in V)
        max_s = min_s
        seq_to_P_entries = {}
        
        for vc in V_msgs:
            for pentry in vc.get("P", []):
                seq = int(pentry.get("seq"))
                if seq > max_s:
                    max_s = seq
                seq_to_P_entries.setdefault(seq, []).append(pentry)
        
        self.log_event(f"NEW-VIEW range: min-s={min_s}, max-s={max_s}")
        
        # Step 3: Create O set - pre-prepares for view v+1
        O = []
        for seq in range(min_s + 1, max_s + 1):
            if seq in seq_to_P_entries:
                # Case 1: At least one prepare message in P with sequence number seq
                # Choose the one with highest view number
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
                self.log_event(f"O: seq={seq} from view {best_entry.get('view')} (real request)")
            else:
                # Case 2: No prepare in P - create null pre-prepare
                null_request = {"type": "NULL_REQUEST", "seq": seq}
                dnull = sha256_digest(null_request)
                preprepare_entry = {
                    "view": target_view,
                    "seq": seq,
                    "digest": dnull,
                    "m": None  # null request
                }
                O.append(preprepare_entry)
                self.log_event(f"O: seq={seq} null request (no prepare in V)")

        new_view_msg = {"type": "NEW_VIEW", "v": target_view, "V": V_msgs, "O": O, "i": self.id}
        self.multicast_with_authenticator(new_view_msg)
        self.log_event(f"📢 Multicasted NEW-VIEW for view {target_view} with {len(O)} pre-prepares")
        
        with self.state_lock:
            self.new_view_msgs.append(new_view_msg)
        
        # Primary installs the new view locally
        self._install_new_view_local(new_view_msg)

    def _install_new_view_local(self, new_view_msg: Dict[str, Any]):
        """Install NEW-VIEW locally."""
        target_view = new_view_msg.get("v")
        O = new_view_msg.get("O", [])
        
        self.view = target_view
        self.in_view_change = False
        self.stop_request_timer()
        self.log_event(f"Installed NEW-VIEW, now in view {self.view}")
        
        with self.state_lock:
            for pre in O:
                seq = int(pre.get("seq"))
                digest_val = pre.get("digest")
                req_maybe = pre.get("m")
                st = self.seq_state.setdefault(seq, {
                    "preprepare": None, "prepares": {}, "prepare_multicast": None,
                    "commits": {}, "commit_multicast": None, "executed": False, "status": "PP",
                    "sent_prepare": False, "result": None
                })
                if st.get("preprepare") is None:
                    st["preprepare"] = {"view": target_view, "seq": seq, "digest": digest_val, "request": req_maybe, "sender": self.id}
                st["prepares"][self.id] = {"type": MSG_PREPARE, "v": target_view, "seq": seq, "d": digest_val, "i": self.id}
                st["sent_prepare"] = True

        for pre in O:
            seq = int(pre.get("seq"))
            self._try_to_multicast_prepare(seq)

    def handle_new_view(self, envelope: Dict[str, Any]):
        """
        Process NEW-VIEW from primary.
        Validate that V contains 2f+1 valid VIEW-CHANGE messages and O is correct.
        """
        if not self.active:
            return

        if not self.verify_authenticator_for_self(envelope):
            return
        
        msg = envelope.get("msg")
        target_view = msg.get("v")
        V_msgs = msg.get("V", [])
        O = msg.get("O", [])
        primary = envelope.get("sender")
        
        self.log_event(f"📨 Received NEW-VIEW for view {target_view} from primary {primary}")
        
        # Validate: V should contain at least 2f+1 valid VIEW-CHANGE messages
        if len(V_msgs) < (2 * F + 1):
            self.log_event(f"❌ NEW-VIEW rejected: only {len(V_msgs)} VIEW-CHANGEs (need {2*F+1})")
            return
        
        # TODO: In full implementation, verify that O is correct by recomputing it from V
        # For now, we trust the primary if we have enough VIEW-CHANGE messages
        
        self.log_event(f"✅ NEW-VIEW validated: {len(V_msgs)} VIEW-CHANGEs, {len(O)} pre-prepares")

        # Add O entries to our log
        with self.state_lock:
            self.new_view_msgs.append(msg)
            for pre in O:
                seq = int(pre.get("seq"))
                digest_val = pre.get("digest")
                req_maybe = pre.get("m")
                
                st = self.seq_state.setdefault(seq, {
                    "preprepare": None, "prepares": {}, "prepare_multicast": None,
                    "commits": {}, "commit_multicast": None, "executed": False, "status": "PP",
                    "sent_prepare": False, "result": None
                })
                
                # Only add pre-prepare if we don't have one yet
                if st.get("preprepare") is None:
                    st["preprepare"] = {
                        "view": target_view,
                        "seq": seq,
                        "digest": digest_val,
                        "request": req_maybe,
                        "sender": primary
                    }

        # Enter the new view
        self.view = target_view
        self.in_view_change = False
        self.stop_request_timer()
        self.log_event(f"🎉 Entered view {self.view} with primary {leader_for_view(self.view, self.n)}")

        # Send PREPARE messages for all entries in O to the new primary
        with self.state_lock:
            for seq, st in list(self.seq_state.items()):
                pre = st.get("preprepare")
                if pre is not None and pre.get("view") == target_view and st.get("status") == "PP":
                    if not st.get("sent_prepare", False):
                        v = pre.get("view")
                        d = pre.get("digest")
                        
                        # Skip null requests
                        if pre.get("request") is None:
                            self.log_event(f"Skipping null request at seq={seq}")
                            continue
                        
                        prepare_msg = {"type": MSG_PREPARE, "v": v, "seq": seq, "d": d, "i": self.id}
                        leader_id = leader_for_view(self.view, self.n)
                        self.send_to_node(leader_id, prepare_msg)
                        self.log_message("PREPARE", prepare_msg, "SENT")
                        st["sent_prepare"] = True
                        self.log_event(f"Sent PREPARE to new leader {leader_id} for seq={seq}")

    def handle_reset(self, envelope: Dict[str, Any]):
        """Handle RESET."""
        if not self.active:
            return

        self.reset_datastore()
        self.in_view_change = False
        self.view = 0
        with self.state_lock:
            self.processed_requests.clear()
            self.seq_state.clear()
        
        # Clear message log for new set
        with self.message_log_lock:
            self.message_log.clear()
        
        # Refresh attack configuration
        self.attack_config = get_attack_config(self.id)
        self.log_event(f"Reset complete (Byzantine={self.attack_config.is_byzantine})")

    def run(self):
        """Main event loop."""
        self.log_event("Node starting")
        while not self._stop.is_set():
            try:
                envelope = self.inbox.get(timeout=0.5)
            except queue.Empty:
                continue
            if not isinstance(envelope, dict):
                continue

            msg = envelope.get("msg", {})
            mtype = msg.get("type")

            if mtype == "PAUSE":
                if self.active:
                    self.active = False
                    self.log_event("PAUSED (simulated down)")
                continue
            if mtype == "UNPAUSE":
                if not self.active:
                    self.active = True
                    self.log_event("UNPAUSED (resuming)")
                continue

            if mtype == "AUTH_INIT":
                if self.verify_authenticator_for_self(envelope):
                    self.log_event(f"Verified AUTH_INIT from {envelope.get('sender')}")
                continue

            # while in view-change only accept VC / NEW_VIEW / RESET
            if self.in_view_change and mtype not in ("VIEW_CHANGE", "NEW_VIEW", "RESET"):
                continue

            if mtype == MSG_REQUEST:
                op = msg.get("op", {})
                if op.get("type") == "read":
                    self.handle_read_request(envelope)
                else:
                    self.handle_request(envelope)

            elif mtype == MSG_PREPREPARE:
                self.handle_preprepare(envelope)
            elif mtype == MSG_PREPARE:
                self.handle_prepare_point_to_point(envelope)
            elif mtype == "PREPARE_MULTICAST":
                self.handle_prepare_multicast(envelope)
            elif mtype == MSG_COMMIT:
                self.handle_commit_point_to_point(envelope)
            elif mtype == "COMMIT_MULTICAST":
                self.handle_commit_multicast(envelope)
            elif mtype == "VIEW_CHANGE":
                self.handle_view_change(envelope)
            elif mtype == "NEW_VIEW":
                self.handle_new_view(envelope)
            elif mtype == "RESET":
                self.handle_reset(envelope)

        self.log_event("Node stopped")

    def stop(self):
        """Stop the node."""
        self._stop.set()
        if self.timer:
            try:
                self.timer.cancel()
            except Exception:
                pass


def node_process_main(
    node_id: int,
    n_replicas: int,
    keyring,
    inbox_queue,
    out_queues,
    client_queues,
    monitor_queue=None,
    readiness_queue=None,
    base_timer: float = 10.0,
):
    """Entrypoint for node process."""
    node = Node(
        node_id=node_id,
        n_replicas=n_replicas,
        keyring=keyring,
        inbox_queue=inbox_queue,
        out_queues=out_queues,
        client_queues=client_queues,
        monitor_queue=monitor_queue,
        readiness_queue=readiness_queue,
        base_timer=base_timer,
    )
    try:
        node.run()
    except KeyboardInterrupt:
        pass
    finally:
        node.stop()
