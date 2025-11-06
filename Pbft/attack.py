# attack.py
"""
Attack toolkit for PBFT simulator.

Purpose:
 - Implement attacks (sign, crash, dark, time, equivocation) as a separate module.
 - Provide AttackManager.wrap_out_queues(...) to produce proxy queues that intercept
   outgoing envelopes from a given sender and enforce attack behavior.
 - Provide parsing helpers to convert CSV-style fields into attack specs.

IMPORTANT:
 - This module does NOT alter your node.py. Instead it supplies wrappers you can
   apply to your node's `out_queues` mapping (where node code calls `q.put(envelope)`).
 - To integrate: in your driver (or right before constructing the Node) call:
       attack_mgr = AttackManager()
       wrapped_out_queues = attack_mgr.wrap_out_queues(out_queues, owner_id,
                                                       live_nodes=..., byzantine_nodes=..., attack_specs=...)
       pass wrapped_out_queues to Node(...) instead of the raw out_queues.
 - Because Node expects mapping node_id->object-with-put(...), the ProxyQueue implements .put(envelope).

Limitations / Assumptions:
 - For 'crash', we simulate a replica that stops sending (outgoing messages are dropped).
   We also buffer messages intended for a crashed target so they can be flushed later with reinstate_node().
 - For 'equivocation', we implement a simple behavior: for PRE-PREPARE messages, we mutate the 'm' (request)
   slightly (if it's a transfer, we change the amount by +1) when sending to the targeted recipients. This
   demonstrates conflicting pre-prepares; edit logic later for your precise experimental needs.
 - For 'time', the delay is implemented with threading.Timer; it's coarse but sufficient for simulation.
"""

from dataclasses import dataclass
import re
import json
import time
import threading
from typing import Dict, Any, List, Optional, Tuple
import hashlib

# Import message type constants from your common.py if available
# We'll use string comparison to be safe. You can import MSG_PREPREPARE etc as needed.
MSG_PREPREPARE = "PREPREPARE"
MSG_PREPARE = "PREPARE"
MSG_COMMIT = "COMMIT"
MSG_REPLY = "REPLY"
MSG_REQUEST = "REQUEST"
MSG_EXECUTE = "EXECUTE"
MSG_AUTH_INIT = "AUTH_INIT"
MSG_PREPARE_MULTICAST = "PREPARE_MULTICAST"
MSG_COMMIT_MULTICAST = "COMMIT_MULTICAST"
MSG_VIEW_CHANGE = "VIEW_CHANGE"
MSG_NEW_VIEW = "NEW_VIEW"


@dataclass
class AttackSpec:
    """
    Represent a single attack specification.
      - kind: one of "sign", "crash", "dark", "time", "equivocation"
      - params: optional list of parameters (e.g., [6,7] for equivocation(n6,n7) or [2] for dark(n2))
      - raw: original raw string, for debugging
    """
    kind: str
    params: Optional[List[Any]] = None
    raw: Optional[str] = None


def sha256_digest(obj: Any) -> str:
    b = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b).hexdigest()


# --------------- Parsing helpers ---------------
def parse_node_list_field(s: str) -> List[int]:
    """
    Parse a string like "[n1, n2, n3]" or "n1,n2" or "n1" into [1,2,3].
    Returns empty list for "", "[]", None.
    """
    if not s:
        return []
    s = s.strip()
    if s == "[]" or s == "None":
        return []
    # remove square brackets if present
    s_clean = s.strip()
    if s_clean.startswith("[") and s_clean.endswith("]"):
        s_clean = s_clean[1:-1]
    if not s_clean:
        return []
    parts = re.split(r"[,\s]+", s_clean.strip())
    nodes = []
    for p in parts:
        if not p:
            continue
        # accept 'n1' or '1'
        m = re.match(r"n?(\d+)", p.strip())
        if m:
            nodes.append(int(m.group(1)))
    return nodes


def parse_attack_field(field: str) -> List[AttackSpec]:
    """
    Parse the CSV attack field into a list of AttackSpec objects.
    Supports examples:
      - "sign"
      - "crash"
      - "time" or "time(200)"  # ms
      - "dark(n2)" or "dark(n2,n3)"
      - "equivocation(n6,n7)"
      - "time; dark(n2); equivocation(n6,n7)"
    """
    if not field:
        return []
    if isinstance(field, list):
        # already parsed externally
        return field
    result: List[AttackSpec] = []
    # split by semicolon (multiple attack types possible)
    parts = [p.strip() for p in re.split(r";", field) if p.strip()]
    for p in parts:
        # simple names
        if p.lower() in ("sign", "crash"):
            result.append(AttackSpec(kind=p.lower(), params=None, raw=p))
            continue
        # time(optional ms)
        m = re.match(r"time(?:\((\d+)\))?$", p, flags=re.IGNORECASE)
        if m:
            val = int(m.group(1)) if m.group(1) else None
            result.append(AttackSpec(kind="time", params=[val] if val else [], raw=p))
            continue
        # dark(...)
        m = re.match(r"dark\(\s*([^\)]+)\s*\)$", p, flags=re.IGNORECASE)
        if m:
            inner = m.group(1)
            nodes = parse_node_list_field(inner)
            result.append(AttackSpec(kind="dark", params=nodes, raw=p))
            continue
        # equivocation(...)
        m = re.match(r"equivocation\(\s*([^\)]+)\s*\)$", p, flags=re.IGNORECASE)
        if m:
            inner = m.group(1)
            nodes = parse_node_list_field(inner)
            result.append(AttackSpec(kind="equivocation", params=nodes, raw=p))
            continue
        # fallback: unknown token -> store as raw 'unknown' attack
        result.append(AttackSpec(kind="unknown", params=[p], raw=p))
    return result


# ---------------- Proxy queue & AttackManager --------------

class ProxyQueue:
    """
    Wraps a real target_queue so that put(envelope) can be intercepted.
    owner_id = id of sending node (the node whose out_queues mapping this proxy sits in).
    target_id = id of recipient node.
    attack_mgr = AttackManager instance that will decide what to do.
    """
    def __init__(self, owner_id: int, target_id: int, real_queue, attack_mgr: "AttackManager"):
        self.owner_id = owner_id
        self.target_id = target_id
        self._real_q = real_queue
        self.attack_mgr = attack_mgr

    def put(self, envelope: Dict[str, Any], block: bool = True, timeout: Optional[float] = None):
        """
        Intercept the outgoing envelope and pass to attack manager for possible
        modification/delay/drop/buffer.
        """
        # Defer full logic to attack manager; it will call _deliver(envelope) if needed.
        self.attack_mgr.handle_outgoing(owner=self.owner_id, target=self.target_id, envelope=envelope, real_queue=self._real_q)


class AttackManager:
    """
    Central manager for attack behaviors.

    Typical usage:
      attack_mgr = AttackManager()
      # for each set, configure:
      attack_mgr.configure_for_set(live_nodes=[...], byzantine_nodes=[...], attack_specs_by_node={node: [AttackSpec,...]})
      # wrap a node's out_queues before starting that node:
      wrapped = attack_mgr.wrap_out_queues(original_out_queues, owner_id=node_id)
      pass wrapped to Node(...)

    Notes:
      - out_queues is expected to be a mapping {node_id: multiprocessing.Queue}
      - wrap_out_queues returns a mapping {node_id: ProxyQueue} where ProxyQueue has .put
      - To reinstate a crashed/down node and flush buffered messages:
          attack_mgr.reinstate_node(node_id)
    """
    def __init__(self, debug: bool = False):
        self.debug = debug
        # configuration for current set:
        self.live_nodes: List[int] = []          # nodes that are currently "up" for the set
        self.byzantine_nodes: List[int] = []     # nodes that are Byzantine (subset of live nodes)
        # mapping node -> list[AttackSpec]
        self.attack_specs_by_node: Dict[int, List[AttackSpec]] = {}

        # buffer for messages targeted at nodes that are currently down (crashed)
        # mapping target_node -> list[ (owner, envelope, real_queue) ]
        self.buffers: Dict[int, List[Tuple[int, Dict[str, Any], Any]]] = {}

        # small default delay if time attack present without parameter (ms)
        self.default_time_ms = 200

        # lock for thread-safe buffer operations
        self._lock = threading.Lock()

    def configure_for_set(self, live_nodes: List[int], byzantine_nodes: List[int], attack_specs_by_node: Dict[int, List[AttackSpec]]):
        """Configure behavior for the current test set."""
        self.live_nodes = list(live_nodes)
        self.byzantine_nodes = list(byzantine_nodes)
        self.attack_specs_by_node = attack_specs_by_node or {}
        # ensure buffers exist for all nodes
        with self._lock:
            for n in range(1, max(self.live_nodes + self.byzantine_nodes + [0]) + 1):
                self.buffers.setdefault(n, [])

    def wrap_out_queues(self, out_queues: Dict[int, Any], owner_id: int) -> Dict[int, ProxyQueue]:
        """
        Given a node's plain out_queues mapping (node_id -> real_queue),
        return a new mapping node_id -> ProxyQueue(owner_id, target_id, real_queue, self).
        Use the returned mapping in place of the original out_queues when creating the Node.
        """
        wrapped = {}
        for target_id, real_q in out_queues.items():
            wrapped[target_id] = ProxyQueue(owner_id=owner_id, target_id=target_id, real_queue=real_q, attack_mgr=self)
        return wrapped

    def handle_outgoing(self, owner: int, target: int, envelope: Dict[str, Any], real_queue):
        """
        Central decision point whenever a node `owner` tries to send `envelope` to `target`.
        This function applies configured attacks and either:
          - immediately puts envelope into the real_queue,
          - drops envelope,
          - delays envelope (timer),
          - buffers envelope (if target is down/crashed),
          - modifies envelope (sign/equivocation).
        """
        # defensive: ensure envelope shape
        if not isinstance(envelope, dict) or "msg" not in envelope:
            return

        msg = envelope["msg"]
        mtype = msg.get("type")
        sender = envelope.get("sender", owner)

        if self.debug:
            print(f"[ATTACK] owner={owner} -> target={target} msg={mtype} sender_field={sender}")

        # 1) If target is not in live_nodes, buffer the message (simulate target down)
        if target not in self.live_nodes:
            # buffer it for later reinstate_node(target)
            with self._lock:
                self.buffers.setdefault(target, []).append((owner, envelope, real_queue))
            if self.debug:
                print(f"[ATTACK] buffered message for down target {target}: {mtype} from {owner}")
            return

        # 2) If owner is Byzantine and has attack specs, evaluate them
        specs = self.attack_specs_by_node.get(owner, [])

        # Crash attack: malicious owner simply drops outgoing messages (simulates crash or silent failure)
        if any(spec.kind == "crash" for spec in specs):
            # drop everything outgoing from owner
            if self.debug:
                print(f"[ATTACK] owner {owner} under CRASH attack, dropping outgoing {mtype} -> {target}")
            return

        # Dark attack: owner avoids sending messages to certain targets
        dark_specs = [spec for spec in specs if spec.kind == "dark"]
        for ds in dark_specs:
            targets = ds.params or []
            if target in targets:
                if self.debug:
                    print(f"[ATTACK] DARK: owner {owner} dropping message to target {target} per dark({targets})")
                return

        # Sign attack: when specified, tamper MACs/authenticators in message so recipients cannot verify
        sign_specs = [spec for spec in specs if spec.kind == "sign"]
        if sign_specs:
            # mutate the envelope to invalidate signatures/mac fields
            envelope = self._tamper_signature(envelope)
            if self.debug:
                print(f"[ATTACK] SIGN: tampered envelope from {owner} to {target}")

        # Equivocation: if owner is malicious leader and is sending PREPREPARE, create different envelope for certain targets
        equiv_specs = [spec for spec in specs if spec.kind == "equivocation"]
        if equiv_specs and isinstance(msg, dict) and msg.get("type") == MSG_PREPREPARE:
            # Use the first equivocation spec for now (support multiple if needed)
            spec = equiv_specs[0]
            targets = spec.params or []
            if target in targets:
                # create mutated PREPREPARE for this targeted recipient
                mutated = self._mutate_preprepare_for_equivocation(msg)
                mutated_envelope = dict(envelope)
                mutated_envelope["msg"] = mutated
                # If there is an authenticator or mac, it should be recomputed by the sender side.
                # Here we simply forward mutated envelope; when integrated, recompute authenticator/mac before sending.
                # We'll deliver mutated envelope (recipient will likely reject if verifying signature/mac; that's intended).
                # For simulation, deliver mutated envelope as-is.
                if self.debug:
                    print(f"[ATTACK] EQUIVOCATION: owner {owner} sending mutated PREPREPARE to {target}")
                # schedule for (possibly delayed) delivery below
                envelope = mutated_envelope

        # Time attack: delay messages by ta ms if specified
        time_specs = [spec for spec in specs if spec.kind == "time"]
        if time_specs:
            # use first time spec (support multiple later)
            spec = time_specs[0]
            ms_param = spec.params[0] if spec.params and len(spec.params) > 0 else None
            delay_ms = ms_param if ms_param is not None else self.default_time_ms
            delay_s = float(delay_ms) / 1000.0
            if self.debug:
                print(f"[ATTACK] TIME: delaying message from {owner} -> {target} by {delay_ms} ms")
            # schedule delivery via timer (strongly recommend not to block simulator's main thread)
            timer = threading.Timer(delay_s, lambda: self._deliver(envelope, real_queue, owner, target))
            timer.daemon = True
            timer.start()
            return

        # No special blocking/delay/modification -> deliver immediately
        self._deliver(envelope, real_queue, owner, target)

    def _deliver(self, envelope: Dict[str, Any], real_queue, owner: int, target: int):
        """Perform the actual put to the real_queue (safely)."""
        try:
            real_queue.put(envelope)
            if self.debug:
                print(f"[ATTACK] Delivered envelope owner={owner} -> target={target} type={envelope.get('msg',{}).get('type')}")
        except Exception as e:
            if self.debug:
                print(f"[ATTACK] Delivery failed owner={owner} -> target={target}: {e}")

    def _tamper_signature(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        """
        Tamper a MAC/authenticator in the envelope to simulate invalid signature.
        - If envelope has 'mac', replace with invalid string
        - If envelope has 'auth' (authenticator vector), replace entries with invalid strings
        Returns a mutated copy.
        """
        mutated = dict(envelope)
        if "mac" in mutated:
            mutated["mac"] = "BAD_MAC"
        if "auth" in mutated and isinstance(mutated["auth"], dict):
            # Replace each entry with 'BAD_MAC' (or remove one entry optionally)
            bad_auth = {k: "BAD_AUTH" for k in mutated["auth"].keys()}
            mutated["auth"] = bad_auth
        return mutated

    def _mutate_preprepare_for_equivocation(self, preprepare_msg: Dict[str, Any]) -> Dict[str, Any]:
        """
        Produce a mutated PREPREPARE message for equivocation:
        - If preprepare carries a full request 'm' and it's a transfer, tweak the amount by +1.
        - Recompute digest 'd' based on mutated 'm' so the message appears self-consistent.
        Note: In real equivocation the leader signs different digests; here we emulate that by changing 'm'/'d'.
        """
        m = dict(preprepare_msg)  # shallow copy
        req = preprepare_msg.get("m")
        mutated_req = None
        if isinstance(req, dict):
            op = req.get("op", {})
            if op.get("type") == "transfer":
                mutated_req = dict(req)
                mutated_op = dict(op)
                try:
                    mutated_op["amt"] = int(op.get("amt", 0)) + 1
                except Exception:
                    mutated_op["amt"] = op.get("amt", 0)
                mutated_req["op"] = mutated_op
            else:
                # for non-write, set request to None (null request) to create difference
                mutated_req = None
        else:
            mutated_req = None

        mutated_msg = dict(preprepare_msg)
        mutated_msg["m"] = mutated_req
        mutated_msg["d"] = sha256_digest(mutated_req or {"null": True})
        return mutated_msg

    # -------------------------
    # Buffering / reinstate
    # -------------------------
    def reinstate_node(self, node_id: int):
        """
        Mark node as live and flush any buffered messages intended for that node.
        This simulates the node coming back up / catching up: previously buffered
        envelopes will now be delivered in FIFO order.
        """
        with self._lock:
            self.live_nodes = list(set(self.live_nodes) | {node_id})
            buf = self.buffers.get(node_id, [])
            # locally copy and clear buffer
            self.buffers[node_id] = []
        # deliver buffered messages
        for owner, envelope, real_q in buf:
            try:
                real_q.put(envelope)
                if self.debug:
                    print(f"[ATTACK] Flushed buffered envelope owner={owner} -> reinstated node={node_id} type={envelope.get('msg',{}).get('type')}")
            except Exception:
                if self.debug:
                    print(f"[ATTACK] Failed flushing buffered envelope owner={owner} -> node={node_id}")

    # -------------------------
    # Utilities used by driver to construct attack spec mapping
    # -------------------------
    @staticmethod
    def build_attack_map_from_csv_fields(byzantine_field: str, attack_field: str) -> Tuple[List[int], Dict[int, List[AttackSpec]]]:
        """
        Convenience helper to parse CSV fields (one set's 'Byzantine' and 'Attack' columns)
        into (byzantine_nodes_list, attack_specs_by_node).
        Input examples:
          byzantine_field = "[n4, n6]" or "n4,n6"
          attack_field = "[time; dark(n2)]" or "time; dark(n2)"
        NOTE: the CSV format in your examples sometimes puts the attack description only on the first transaction line
        for the set. The driver should call this helper once per set, passing the byzantine and attack description.
        For simplicity this helper will apply the same attack specs to ALL byzantine nodes listed.
        """
        bnodes = parse_node_list_field(byzantine_field)
        raw_attacks = attack_field or ""
        # remove surrounding brackets if CSV quoted like "[time; dark(n2)]"
        raw_attacks = raw_attacks.strip()
        if raw_attacks.startswith("[") and raw_attacks.endswith("]"):
            raw_attacks = raw_attacks[1:-1].strip()
        specs = parse_attack_field(raw_attacks)
        attack_map = {}
        for n in bnodes:
            attack_map[n] = list(specs)  # shallow copy for each node
        return bnodes, attack_map
