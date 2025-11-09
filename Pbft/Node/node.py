import json
import time
import threading
import queue
import hashlib
from types import MethodType
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

from . import comms
from . import protocol
from . import viewchange


# constants
F = 2
WINDOW_SIZE = 100


def sha256_digest(obj: Any) -> str:
    # deterministic sha256 of a json-serializable object
    b = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b).hexdigest()


class Node:
    # Node core attributes and run loop. Many methods are bound from helper modules.
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
        # basic config
        self.id = int(node_id)
        self.n = int(n_replicas)
        self.keyring = keyring
        self.inbox = inbox_queue
        self.out_queues = out_queues
        self.client_queues = client_queues
        self.monitor_queue = monitor_queue
        self.readiness_queue = readiness_queue

        # logs and locks
        self.message_log: List[Dict[str, Any]] = []
        self.message_log_lock = threading.Lock()

        # view and sequence window
        self.view = 0
        self.next_seq = 1
        self.low = 0
        self.high = self.low + WINDOW_SIZE

        # per-sequence state
        self.seq_state: Dict[int, Dict] = {}
        self.state_lock = threading.Lock()

        # processed requests mapping (client, tstamp) -> seq
        self.processed_requests: Dict[Tuple[int, str], int] = {}

        # view-change tracking
        self.view_change_msgs: Dict[int, Dict[int, Dict]] = {}
        self.new_view_msgs: List[Dict] = []
        self.in_view_change = False

        # simple datastore and timers
        self.datastore: Dict[str, int] = {}
        self.timer = None
        self.timer_timeout = base_timer + float(self.id)
        self.view_change_timer = None
        self.view_change_timeout = 8.0 #12
        self.target_view = None

        # deferrals and stop flag
        self.deferred_client_requests = []
        self.deferred_executions = set()
        self._stop = threading.Event()
        self.active = True

        # attack config
        self.attack_config: AttackConfig = get_attack_config(self.id)
        self.attack_map: Dict[int, AttackConfig] = {}

        # init db and bind helper functions
        self.reset_datastore()

        # bind functions from modules to preserve self.method(...) style
        # comms
        self._broadcast_auth_init = MethodType(comms._broadcast_auth_init, self)
        self.multicast_with_authenticator = MethodType(comms.multicast_with_authenticator, self)
        self.send_to_node = MethodType(comms.send_to_node, self)
        self.send_to_client = MethodType(comms.send_to_client, self)
        self.verify_authenticator_for_self = MethodType(comms.verify_authenticator_for_self, self)
        self.verify_single_mac_for_self = MethodType(comms.verify_single_mac_for_self, self)
        self.start_request_timer = MethodType(comms.start_request_timer, self)
        self.stop_request_timer = MethodType(comms.stop_request_timer, self)
        self.start_view_change_timer = MethodType(comms.start_view_change_timer, self)
        self.stop_view_change_timer = MethodType(comms.stop_view_change_timer, self)
        self._on_timer_expiry = MethodType(comms._on_timer_expiry, self)
        self._on_view_change_timer_expiry = MethodType(comms._on_view_change_timer_expiry, self)

        # protocol handlers
        self.handle_request = MethodType(protocol.handle_request, self)
        self._handle_equivocation_attack = MethodType(protocol._handle_equivocation_attack, self)
        self.handle_preprepare = MethodType(protocol.handle_preprepare, self)
        self.handle_prepare_point_to_point = MethodType(protocol.handle_prepare_point_to_point, self)
        self._try_to_multicast_prepare = MethodType(protocol._try_to_multicast_prepare, self)
        self.handle_prepare_multicast = MethodType(protocol.handle_prepare_multicast, self)
        self.handle_commit_point_to_point = MethodType(protocol.handle_commit_point_to_point, self)
        self._try_to_multicast_commit = MethodType(protocol._try_to_multicast_commit, self)
        self.handle_commit_multicast = MethodType(protocol.handle_commit_multicast, self)
        self._try_to_execute = MethodType(protocol._try_to_execute, self)
        self.handle_read_request = MethodType(protocol.handle_read_request, self)
        self.handle_reset = MethodType(viewchange.handle_reset, self)  # reset uses viewchange module

        # view-change handlers
        self.start_view_change = MethodType(viewchange.start_view_change, self)
        self._delayed_view_change = MethodType(viewchange._delayed_view_change, self)
        self.handle_view_change = MethodType(viewchange.handle_view_change, self)
        self._form_and_multicast_new_view = MethodType(viewchange._form_and_multicast_new_view, self)
        self._install_new_view_local = MethodType(viewchange._install_new_view_local, self)
        self.handle_new_view = MethodType(viewchange.handle_new_view, self)

        # small helpers for driver
        self.handle_get_log = MethodType(viewchange.handle_get_log, self)
        self.handle_get_status = MethodType(viewchange.handle_get_status, self)
        self.handle_get_new_view = MethodType(viewchange.handle_get_new_view, self)

        # try to broadcast auth-init
        try:
            self._broadcast_auth_init()
            time.sleep(0.05)
        except Exception:
            pass

        # readiness signal
        if self.readiness_queue is not None:
            try:
                self.readiness_queue.put({"type": "NODE_READY", "node": self.id})
            except Exception:
                pass

    # logging helpers
    def log_message(self, msg_type: str, msg: Dict[str, Any], direction: str = "SENT"):
        # log protocol messages for print/debug
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
        # return a copy of message log
        with self.message_log_lock:
            return list(self.message_log)

    def reset_datastore(self):
        # set A..J balances to 10
        self.datastore.clear()
        for i in range(10):
            name = chr(ord("A") + i)
            self.datastore[name] = 10

    # main loop
    def run(self):
        # main event loop
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
        # stop the node
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
    # entrypoint for multiprocess/thread driver
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