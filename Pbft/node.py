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
from attacks import get_attack_config, get_orchestrator, AttackConfig

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
        self.view_change_timer = None
        self.view_change_timeout = 8.0 #12
        self.target_view = None

        self.deferred_client_requests = []
        self.deferred_executions = set()

        self._stop = threading.Event()
        self.active = True

        self.attack_config: AttackConfig = get_attack_config(self.id)
        self.attack_map: Dict[int, AttackConfig] = {}

        self.reset_datastore()

        try:
            self._broadcast_auth_init()
            time.sleep(0.05)
        except Exception:
            pass

        if self.readiness_queue is not None:
            try:
                self.readiness_queue.put({"type": "NODE_READY", "node": self.id})
            except Exception:
                pass

    def log_message(self, msg_type: str, msg: Dict[str, Any], direction: str = "SENT"):
        """Log protocol messages for PrintLog."""
        with self.message_log_lock:
            log_entry = {
                "timestamp": time.time(),
                "type": msg_type,
                "direction": direction,
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

    def _broadcast_auth_init(self):
        """Broadcast AUTH_INIT with authenticator to other replicas (exclude self)."""
        msg = {"type": "AUTH_INIT", "node": self.id, "time": time.time()}
        recipients = [r for r in list(self.out_queues.keys()) if r != self.id]
        msg_bytes = json.dumps(msg, sort_keys=True).encode("utf-8")
        auth = create_authenticator(self.keyring, self.id, recipients, msg_bytes)

        if getattr(self.attack_config, "sign_attack", False):
            auth = self.attack_config.corrupt_signature(auth)

        envelope = {"msg": msg, "auth": auth, "sender": self.id}

        for r in recipients:
            if getattr(self.attack_config, "dark_attack", False) and r in getattr(self.attack_config, "dark_targets", set()):
                continue
            q = self.out_queues.get(r)
            if q:
                q.put(envelope)

    def start_request_timer(self):
        """Start the node's request timer if not already running."""
        if self.timer and self.timer.is_alive():
            return

        timeout = float(self.timer_timeout)
        leader_id = leader_for_view(self.view, self.n)
        leader_cfg = self.attack_map.get(leader_id)
        if leader_cfg and getattr(leader_cfg, "time_attack", False):
            total_delay_buffer = (3 * float(leader_cfg.time_delay_ms) / 1000.0) + 2.5
            timeout = timeout + total_delay_buffer

        self.timer = threading.Timer(timeout, self._on_timer_expiry)
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

    def start_view_change_timer(self, target_view: int):
        """Start timer for waiting for NEW-VIEW (handles consecutive leader failures)."""
        if self.view_change_timer and self.view_change_timer.is_alive():
            return
        
        self.target_view = target_view
        
        self.view_change_timer = threading.Timer(self.view_change_timeout, self._on_view_change_timer_expiry)
        self.view_change_timer.daemon = True
        self.view_change_timer.start()

    def stop_view_change_timer(self):
        """Cancel the view-change timer if running."""
        if self.view_change_timer:
            try:
                self.view_change_timer.cancel()
            except Exception:
                pass
            self.view_change_timer = None
            self.target_view = None

    def _on_view_change_timer_expiry(self):
        """Called when view-change timer expires (no NEW-VIEW received)."""
        if not self.in_view_change:
            return
        
        next_target = self.target_view + 1 if self.target_view is not None else self.view + 2
        
        try:
            self.start_view_change(next_target)
        except Exception:
            pass
            
    def _on_timer_expiry(self):
        """Called when request timer expires."""
        try:
            self.start_view_change(self.view + 1)
        except Exception:
            pass

    def multicast_with_authenticator(self, msg: Dict[str, Any], recipients: Optional[List[int]] = None, skip_time_delay: bool = False):
        """
        Multicast a message (authenticator vector) to recipients (exclude self).
        Uses self.attack_config to decide time delay and dark drops.
        """
        if recipients is None:
            recipients = list(self.out_queues.keys())

        recipients_to_send = [r for r in recipients if r != self.id]

        if not skip_time_delay and getattr(self.attack_config, "time_attack", False):
            self.attack_config.apply_time_delay()

        msg_bytes = json.dumps(msg, sort_keys=True).encode("utf-8")
        auth = create_authenticator(self.keyring, self.id, recipients_to_send, msg_bytes)

        if getattr(self.attack_config, "sign_attack", False):
            auth = self.attack_config.corrupt_signature(auth)

        envelope = {"msg": msg, "auth": auth, "sender": self.id}

        for r in recipients_to_send:
            if getattr(self.attack_config, "dark_attack", False) and r in getattr(self.attack_config, "dark_targets", set()):
                continue
            q = self.out_queues.get(r)
            if q:
                q.put(envelope)

    def send_to_node(self, target: int, msg: Dict[str, Any]):
        """Send a point-to-point message to another node with a single MAC."""
        msg_bytes = json.dumps(msg, sort_keys=True).encode("utf-8")
        try:
            mac = mac_for_pair(self.keyring, self.id, target, msg_bytes)
            envelope = {"msg": msg, "mac": mac, "sender": self.id}
        except Exception:
            envelope = {"msg": msg, "sender": self.id}

        if self.attack_config.should_drop_message_to(target):
            return

        if getattr(self.attack_config, "sign_attack", False) and "mac" in envelope:
            mac_val = envelope["mac"]
            corrupted = None
            if isinstance(mac_val, (bytes, bytearray)):
                ba = bytearray(mac_val)
                if len(ba) == 0:
                    ba = bytearray(b'\x01')
                else:
                    ba[-1] ^= 0x01
                corrupted = bytes(ba)
            elif isinstance(mac_val, str):
                try:
                    b = bytes.fromhex(mac_val)
                    ba = bytearray(b)
                    if len(ba) == 0:
                        ba = bytearray(b'\x01')
                    else:
                        ba[-1] ^= 0x01
                    corrupted = ba.hex()
                except Exception:
                    if len(mac_val) == 0:
                        corrupted = "X"
                    else:
                        last = ord(mac_val[-1])
                        newch = chr((last ^ 0x01) % 256)
                        corrupted = mac_val[:-1] + newch
            else:
                corrupted = b"CORRUPT"

            envelope["mac"] = corrupted

        q = self.out_queues.get(target)
        if q:
            q.put(envelope)

    def send_to_client(self, client_id: int, msg: Dict[str, Any]):
        """Send a REPLY message to a client with a single MAC."""
        if msg.get("type") == MSG_REPLY and self.attack_config.should_block_reply():
            return

        msg_bytes = json.dumps(msg, sort_keys=True).encode("utf-8")
        try:
            mac = mac_for_pair(self.keyring, self.id, client_id, msg_bytes)
            envelope = {"msg": msg, "mac": mac, "sender": self.id}
        except Exception:
            envelope = {"msg": msg, "sender": self.id}

        if getattr(self.attack_config, "sign_attack", False) and "mac" in envelope:
            mac_val = envelope["mac"]
            corrupted = None
            if isinstance(mac_val, (bytes, bytearray)):
                ba = bytearray(mac_val)
                if len(ba) == 0:
                    ba = bytearray(b'\x01')
                else:
                    ba[-1] ^= 0x01
                corrupted = bytes(ba)
            elif isinstance(mac_val, str):
                try:
                    b = bytes.fromhex(mac_val)
                    ba = bytearray(b)
                    if len(ba) == 0:
                        ba = bytearray(b'\x01')
                    else:
                        ba[-1] ^= 0x01
                    corrupted = ba.hex()
                except Exception:
                    if len(mac_val) == 0:
                        corrupted = "X"
                    else:
                        last = ord(mac_val[-1])
                        newch = chr((last ^ 0x01) % 256)
                        corrupted = mac_val[:-1] + newch
            else:
                corrupted = b"CORRUPT"

            envelope["mac"] = corrupted

        q = self.client_queues.get(client_id)
        if q:
            q.put(envelope)

    def verify_authenticator_for_self(self, envelope: Dict[str, Any]) -> bool:
        """Verify an incoming envelope that carries an authenticator vector."""
        if "auth" not in envelope:
            return False
        sender = envelope.get("sender")
        msg = envelope.get("msg")
        msg_bytes = json.dumps(msg, sort_keys=True).encode("utf-8")
        ok = verify_authenticator(self.keyring, sender, self.id, msg_bytes, envelope.get("auth"))
        return ok

    def verify_single_mac_for_self(self, envelope: Dict[str, Any]) -> bool:
        """Verify a point-to-point envelope with a single MAC."""
        if "mac" not in envelope:
            return False
        sender = envelope.get("sender")
        msg = envelope.get("msg")
        msg_bytes = json.dumps(msg, sort_keys=True).encode("utf-8")
        ok = verify_mac(self.keyring, sender, self.id, msg_bytes, envelope.get("mac"))
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

        self.log_message("REQUEST", msg, "RECEIVED")

        if self.in_view_change:
            if not hasattr(self, "deferred_client_requests"):
                self.deferred_client_requests = []
            self.deferred_client_requests.append(envelope)
            return

        if self.id != leader_for_view(self.view, self.n):
            if not self.in_view_change and not (self.timer and self.timer.is_alive()):
                self.start_request_timer()
            return

        request_key = (client_id, tstamp)

        with self.state_lock:
            if request_key in self.processed_requests:
                existing_seq = self.processed_requests[request_key]

                existing_st = self.seq_state.get(existing_seq)
                if existing_st and existing_st.get("executed"):
                    result = existing_st.get("result")
                    if result:
                        reply_msg = {"type": MSG_REPLY, "v": self.view, "t": tstamp, "c": client_id, "i": self.id, "r": result}
                        self.send_to_client(client_id, reply_msg)
                return

        seq = self.next_seq
        if seq >= self.high:
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
            st["prepares"][self.id] = {"type": MSG_PREPARE, "v": self.view, "seq": seq, "d": d, "i": self.id}
            st["sent_prepare"] = True

        if getattr(self.attack_config, "equivocation_attack", False):
            self._handle_equivocation_attack(seq, msg, d)
        else:
            preprepare_msg = {"type": MSG_PREPREPARE, "v": self.view, "seq": seq, "d": d, "m": msg}
            self.multicast_with_authenticator(preprepare_msg)
            self.log_message("PREPREPARE", preprepare_msg, "SENT")

    def _handle_equivocation_attack(self, base_seq: int, msg: Dict, digest: str):
        """
        ATTACK: Equivocation - send conflicting preprepares to different nodes.
        """
        all_recipients = [r for r in list(self.out_queues.keys()) if r != self.id]

        for target in all_recipients:
            if target in getattr(self.attack_config, "equivocation_targets", []):
                alt_seq = base_seq + 1
                preprepare_msg = {"type": MSG_PREPREPARE, "v": self.view, "seq": alt_seq, "d": digest, "m": msg}
            else:
                preprepare_msg = {"type": MSG_PREPREPARE, "v": self.view, "seq": base_seq, "d": digest, "m": msg}

            msg_bytes = json.dumps(preprepare_msg, sort_keys=True).encode("utf-8")
            auth = create_authenticator(self.keyring, self.id, [target], msg_bytes)

            if getattr(self.attack_config, "sign_attack", False):
                auth = self.attack_config.corrupt_signature(auth)

            envelope = {"msg": preprepare_msg, "auth": auth, "sender": self.id}

            if getattr(self.attack_config, "dark_attack", False) and target in getattr(self.attack_config, "dark_targets", set()):
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

        self.log_message("PREPREPARE", msg, "RECEIVED")

        if self.in_view_change:
            return
        if v != self.view:
            return
        if seq < self.low or seq >= self.high:
            return
        if sha256_digest(m) != d:
            return

        with self.state_lock:
            st = self.seq_state.setdefault(seq, {
                "preprepare": None, "prepares": {}, "prepare_multicast": None,
                "commits": {}, "commit_multicast": None, "executed": False, "status": "PP",
                "sent_prepare": False, "result": None
            })
            st["preprepare"] = {"view": v, "seq": seq, "digest": d, "request": m, "sender": leader}

            if getattr(self.attack_config, "crash_attack", False) and getattr(self.attack_config, "should_send_preprepare_only", None) and self.attack_config.should_send_preprepare_only():
                st["sent_prepare"] = True
            else:
                if not st.get("sent_prepare", False):
                    prepare_msg = {"type": MSG_PREPARE, "v": v, "seq": seq, "d": d, "i": self.id}
                    leader_id = leader_for_view(self.view, self.n)
                    self.send_to_node(leader_id, prepare_msg)
                    self.log_message("PREPARE", prepare_msg, "SENT")
                    st["sent_prepare"] = True

        if not self.in_view_change:
            self.stop_request_timer()
            self.start_request_timer()

    def handle_prepare_point_to_point(self, envelope: Dict[str, Any]):
        """Leader receives PREPARE from a backup."""
        if not self.active:
            return

        if not self.verify_single_mac_for_self(envelope):
            return

        msg = envelope.get("msg")
        seq = msg.get("seq")
        i = msg.get("i")

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

        if getattr(self.attack_config, "crash_attack", False) and self.attack_config.should_block_prepare(True):
            return

        pm = None

        with self.state_lock:
            st = self.seq_state.get(seq)
            if not st:
                return
            if st.get("prepare_multicast") is not None:
                return

            prepares = st["prepares"]
            num_prepares = len(prepares)

            if num_prepares >= (2 * F + 1):
                pm_list = list(prepares.values())
                d = st["preprepare"]["digest"]
                prepare_multicast = {"type": "PREPARE_MULTICAST", "v": self.view, "seq": seq, "d": d, "prepares": pm_list}
                st["prepare_multicast"] = prepare_multicast
                st["status"] = "P"

                commit_msg = {"type": MSG_COMMIT, "v": self.view, "seq": seq, "d": d, "i": self.id}
                st["commits"][self.id] = commit_msg

                pm = prepare_multicast

        if pm is not None:
            self.multicast_with_authenticator(pm)
            self.log_message("PREPARE_MULTICAST", pm, "SENT")

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

        self.log_message("PREPARE_MULTICAST", msg, "RECEIVED")

        if v != self.view:
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

        if getattr(self.attack_config, "crash_attack", False) and getattr(self.attack_config, "should_send_preprepare_only", None) and self.attack_config.should_send_preprepare_only():
            return

        commit_msg = {"type": MSG_COMMIT, "v": v, "seq": seq, "d": d, "i": self.id}
        leader_id = leader_for_view(self.view, self.n)
        self.send_to_node(leader_id, commit_msg)
        self.log_message("COMMIT", commit_msg, "SENT")

    def handle_commit_point_to_point(self, envelope: Dict[str, Any]):
        """Leader receives COMMIT from a backup."""
        if not self.active:
            return

        if not self.verify_single_mac_for_self(envelope):
            return

        msg = envelope.get("msg")
        seq = msg.get("seq")
        i = msg.get("i")

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

        if getattr(self.attack_config, "crash_attack", False) and self.attack_config.should_block_commit(True):
            return

        cm = None

        with self.state_lock:
            st = self.seq_state.get(seq)
            if not st:
                return
            if st.get("commit_multicast") is not None:
                return

            commits = st["commits"]
            num_commits = len(commits)

            if num_commits >= (2 * F + 1):
                cm_list = list(commits.values())
                d = st["preprepare"]["digest"]
                commit_multicast = {"type": "COMMIT_MULTICAST", "v": self.view, "seq": seq, "d": d, "commits": cm_list}
                st["commit_multicast"] = commit_multicast
                st["status"] = "C"

                cm = commit_multicast

        if cm is not None:
            self.multicast_with_authenticator(cm)
            self.log_message("COMMIT_MULTICAST", cm, "SENT")
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

        self.log_message("COMMIT_MULTICAST", msg, "RECEIVED")

        if v != self.view:
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
                if self.datastore.get(sname, 0) >= amt:
                    self.datastore[sname] -= amt
                    self.datastore[rname] = self.datastore.get(rname, 0) + amt
                    result = {"status": "EXECUTED", "detail": f"{sname}->{rname}:{amt}"}
                else:
                    result = {"status": "FAILED", "detail": "insufficient"}
            else:
                sname = op.get("s")
                result = {"status": "EXECUTED", "balance": self.datastore.get(sname, 0)}

            st["executed"] = True
            st["status"] = "E"
            st["result"] = result

        exec_msg = {"seq": seq, "result": result, "v": self.view}
        self.log_message("EXECUTE", exec_msg, "PROCESSED")

        reply_msg = {"type": MSG_REPLY, "v": self.view, "t": tstamp, "c": client_id, "i": self.id, "r": result}
        self.send_to_client(client_id, reply_msg)
        self.log_message("REPLY", reply_msg, "SENT")

        self.stop_request_timer()

        if self.monitor_queue is not None:
            try:
                snapshot = dict(self.datastore)
                self.monitor_queue.put({"type": "EXECUTED_NOTIFY", "t": tstamp, "node": self.id, "seq": seq, "op": op, "result": result})
                self.monitor_queue.put({"type": "DB_SNAPSHOT", "node": self.id, "seq": seq, "db": snapshot, "t": tstamp})
            except Exception:
                pass

    def handle_read_request(self, envelope: Dict[str, Any]):
        """Handle read request by replying immediately (to client) with local state."""
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
        self.start_view_change_timer(target_view)

        with self.state_lock:
            if self.id in self.view_change_msgs.get(target_view, {}):
                return

        self.in_view_change = True

        with self.state_lock:
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
            self.view_change_msgs.setdefault(target_view, {})[self.id] = view_change_msg

        if getattr(self.attack_config, "crash_attack", False) and getattr(self.attack_config, "should_send_preprepare_only", None) and self.attack_config.should_send_preprepare_only():
            return

        failed_leader = leader_for_view(self.view, self.n)
        recipients = [nid for nid in list(self.out_queues.keys()) if nid != failed_leader]

        self.multicast_with_authenticator(view_change_msg, recipients=recipients)

    def _delayed_view_change(self, target_view: int):
        """Delayed view-change to avoid message storms."""
        time.sleep(0.1)
        with self.state_lock:
            if self.id in self.view_change_msgs.get(target_view, {}):
                return
        self.start_view_change(target_view)

    def handle_view_change(self, envelope: Dict[str, Any]):
        """Process VIEW_CHANGE messages."""
        if not self.active:
            return

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
            return

        self.stop_request_timer()
        self.start_view_change_timer(target_view)
        self.in_view_change = True

        with self.state_lock:
            self.view_change_msgs.setdefault(target_view, {})[sender] = msg

        with self.state_lock:
            already_sent = (self.id in self.view_change_msgs.get(target_view, {}))

        if not already_sent:
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
                self.view_change_msgs.setdefault(target_view, {})[self.id] = our_vc_msg

            if getattr(self.attack_config, "crash_attack", False) and getattr(self.attack_config, "should_send_preprepare_only", None) and self.attack_config.should_send_preprepare_only():
                pass
            else:
                leader_id = leader_for_view(target_view, self.n)
                recipients_node_ids = [r for r in list(self.out_queues.keys()) if r != leader_id and r != self.id]

                self.multicast_with_authenticator(our_vc_msg, recipients=recipients_node_ids)

        new_leader = leader_for_view(target_view, self.n)
        if new_leader == self.id:
            with self.state_lock:
                num_vc_msgs = len(self.view_change_msgs.get(target_view, {}))
            if num_vc_msgs >= (2 * F + 1):
                self._form_and_multicast_new_view(target_view)

    def _form_and_multicast_new_view(self, target_view: int):
        """Form NEW-VIEW and multicast."""
        if getattr(self.attack_config, "crash_attack", False) and self.attack_config.should_block_newview():
            return

        with self.state_lock:
            V_msgs = list(self.view_change_msgs.get(target_view, {}).values())

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

        new_view_msg = {"type": "NEW_VIEW", "v": target_view, "V": V_msgs, "O": O, "i": self.id}
        self.multicast_with_authenticator(new_view_msg)

        with self.state_lock:
            self.new_view_msgs.append(new_view_msg)

        self._install_new_view_local(new_view_msg)

    def _install_new_view_local(self, new_view_msg: Dict[str, Any]):
        """Install NEW-VIEW locally and send any prepares needed to new primary."""
        target_view = new_view_msg.get("v")
        O = new_view_msg.get("O", [])

        self.view = target_view
        self.in_view_change = False
        self.stop_request_timer()
        self.stop_view_change_timer()

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

        if not hasattr(self, "deferred_client_requests"):
            self.deferred_client_requests = []

        while self.deferred_client_requests:
            env = self.deferred_client_requests.pop(0)
            try:
                self.handle_request(env)
            except Exception:
                pass

    def handle_new_view(self, envelope: Dict[str, Any]):
        """Process NEW-VIEW from primary."""
        if not self.active:
            return

        if not self.verify_authenticator_for_self(envelope):
            return

        msg = envelope.get("msg")
        target_view = msg.get("v")
        V_msgs = msg.get("V", [])
        O = msg.get("O", [])
        primary = envelope.get("sender")

        if len(V_msgs) < (2 * F + 1):
            return

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

                if st.get("preprepare") is None:
                    st["preprepare"] = {
                        "view": target_view,
                        "seq": seq,
                        "digest": digest_val,
                        "request": req_maybe,
                        "sender": primary
                    }

        self.view = target_view
        self.in_view_change = False
        self.stop_request_timer()
        self.stop_view_change_timer()

        with self.state_lock:
            for seq, st in list(self.seq_state.items()):
                pre = st.get("preprepare")
                if pre is not None and pre.get("view") == target_view and st.get("status") == "PP":
                    if not st.get("sent_prepare", False):
                        v = pre.get("view")
                        d = pre.get("digest")

                        if pre.get("request") is None:
                            continue

                        prepare_msg = {"type": MSG_PREPARE, "v": v, "seq": seq, "d": d, "i": self.id}
                        leader_id = leader_for_view(self.view, self.n)
                        self.send_to_node(leader_id, prepare_msg)
                        self.log_message("PREPARE", prepare_msg, "SENT")
                        st["sent_prepare"] = True

        if not hasattr(self, "deferred_client_requests"):
            self.deferred_client_requests = []

        while self.deferred_client_requests:
            env = self.deferred_client_requests.pop(0)
            try:
                self.handle_request(env)
            except Exception:
                pass

    def handle_reset(self, envelope: Dict[str, Any]):
        try:
            self.stop_request_timer()
        except Exception:
            pass
        
        try:
            self.stop_view_change_timer()
        except Exception:
            pass

        if not self.active:
            pass

        msg = envelope.get("msg", {})
        attack_map_raw = msg.get("attack_map")
        if attack_map_raw and isinstance(attack_map_raw, dict):
            self.attack_map = {}
            for k, v in attack_map_raw.items():
                try:
                    nid = int(k)
                except Exception:
                    nid = int(k)
                try:
                    ac = AttackConfig.from_dict(v)
                except Exception:
                    ac = AttackConfig(nid)
                self.attack_map[nid] = ac
            self.attack_config = self.attack_map.get(self.id, AttackConfig(self.id))
        else:
            self.attack_config = get_attack_config(self.id)
            self.attack_map = {self.id: self.attack_config}

        self.reset_datastore()
        self.in_view_change = False
        self.view = 0
        self.next_seq = 1
        self.low = 0
        self.high = self.low + WINDOW_SIZE
        
        with self.state_lock:
            self.processed_requests.clear()
            self.seq_state.clear()
            self.view_change_msgs.clear()
            self.new_view_msgs.clear()

        with self.message_log_lock:
            self.message_log.clear()

    def handle_get_log(self, envelope: Dict[str, Any]):
        """Handle GET_LOG request from driver - return message log."""
        msg = envelope.get("msg", {})
        reply_queue = envelope.get("reply_queue")
        
        if reply_queue is None:
            return
        
        try:
            log_copy = self.get_message_log()
            response = {
                "type": "LOG_RESPONSE",
                "node_id": self.id,
                "log": log_copy
            }
            reply_queue.put(response)
        except Exception:
            pass

    def handle_get_status(self, envelope: Dict[str, Any]):
        """Handle GET_STATUS request from driver - return sequence statuses."""
        msg = envelope.get("msg", {})
        reply_queue = envelope.get("reply_queue")
        
        if reply_queue is None:
            return
        
        statuses = {}
        with self.state_lock:
            for seq, st in self.seq_state.items():
                status = st.get("status", "X")
                statuses[seq] = status
        
        try:
            response = {
                "type": "STATUS_RESPONSE",
                "node_id": self.id,
                "statuses": statuses
            }
            reply_queue.put(response)
        except Exception:
            pass

    def handle_get_new_view(self, envelope: Dict[str, Any]):
        """Handle GET_NEW_VIEW request from driver - return NEW-VIEW messages."""
        msg = envelope.get("msg", {})
        reply_queue = envelope.get("reply_queue")
        
        if reply_queue is None:
            return
        
        try:
            with self.state_lock:
                nv_copy = list(self.new_view_msgs)
            
            response = {
                "type": "NEW_VIEW_RESPONSE",
                "node_id": self.id,
                "new_view_msgs": nv_copy
            }
            reply_queue.put(response)
        except Exception:
            pass

    def run(self):
        """Main event loop."""
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
                    try:
                        self.stop_request_timer()
                    except Exception:
                        pass
                    self.active = False
                continue
            if mtype == "UNPAUSE":
                if not self.active:
                    self.active = True
                continue

            if mtype == "AUTH_INIT":
                if self.verify_authenticator_for_self(envelope):
                    pass
                continue

            if self.in_view_change and mtype not in ("VIEW_CHANGE", "NEW_VIEW", "RESET", "GET_LOG", "GET_STATUS", "GET_NEW_VIEW"):
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
            elif mtype == "GET_LOG":
                self.handle_get_log(envelope)
            elif mtype == "GET_STATUS":
                self.handle_get_status(envelope)
            elif mtype == "GET_NEW_VIEW":
                self.handle_get_new_view(envelope)

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