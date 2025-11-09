import json
import time
import threading
from typing import Any, Dict, List, Optional

from keys import create_authenticator, mac_for_pair, verify_authenticator, verify_mac
from attacks import get_attack_config, AttackConfig

# helpers expect a 'node' instance as first arg

def _broadcast_auth_init(node):
    # broadcast AUTH_INIT authenticator to others
    msg = {"type": "AUTH_INIT", "node": node.id, "time": time.time()}
    recipients = [r for r in list(node.out_queues.keys()) if r != node.id]
    msg_bytes = json.dumps(msg, sort_keys=True).encode("utf-8")
    auth = create_authenticator(node.keyring, node.id, recipients, msg_bytes)

    if getattr(node.attack_config, "sign_attack", False):
        auth = node.attack_config.corrupt_signature(auth)

    envelope = {"msg": msg, "auth": auth, "sender": node.id}

    for r in recipients:
        if getattr(node.attack_config, "dark_attack", False) and r in getattr(node.attack_config, "dark_targets", set()):
            continue
        q = node.out_queues.get(r)
        if q:
            q.put(envelope)


def multicast_with_authenticator(node, msg: Dict[str, Any], recipients: Optional[List[int]] = None, skip_time_delay: bool = False):
    # multicast with authenticator vector
    if recipients is None:
        recipients = list(node.out_queues.keys())

    recipients_to_send = [r for r in recipients if r != node.id]

    if not skip_time_delay and getattr(node.attack_config, "time_attack", False):
        node.attack_config.apply_time_delay()

    msg_bytes = json.dumps(msg, sort_keys=True).encode("utf-8")
    auth = create_authenticator(node.keyring, node.id, recipients_to_send, msg_bytes)

    if getattr(node.attack_config, "sign_attack", False):
        auth = node.attack_config.corrupt_signature(auth)

    envelope = {"msg": msg, "auth": auth, "sender": node.id}

    for r in recipients_to_send:
        if getattr(node.attack_config, "dark_attack", False) and r in getattr(node.attack_config, "dark_targets", set()):
            continue
        q = node.out_queues.get(r)
        if q:
            q.put(envelope)


def send_to_node(node, target: int, msg: Dict[str, Any]):
    # point-to-point send with single MAC
    msg_bytes = json.dumps(msg, sort_keys=True).encode("utf-8")
    try:
        mac = mac_for_pair(node.keyring, node.id, target, msg_bytes)
        envelope = {"msg": msg, "mac": mac, "sender": node.id}
    except Exception:
        envelope = {"msg": msg, "sender": node.id}

    if node.attack_config.should_drop_message_to(target):
        return

    if getattr(node.attack_config, "sign_attack", False) and "mac" in envelope:
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

    q = node.out_queues.get(target)
    if q:
        q.put(envelope)


def send_to_client(node, client_id: int, msg: Dict[str, Any]):
    # send reply to client with MAC
    if msg.get("type") == "REPLY" and node.attack_config.should_block_reply():
        return

    msg_bytes = json.dumps(msg, sort_keys=True).encode("utf-8")
    try:
        mac = mac_for_pair(node.keyring, node.id, client_id, msg_bytes)
        envelope = {"msg": msg, "mac": mac, "sender": node.id}
    except Exception:
        envelope = {"msg": msg, "sender": node.id}

    if getattr(node.attack_config, "sign_attack", False) and "mac" in envelope:
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

    q = node.client_queues.get(client_id)
    if q:
        q.put(envelope)


def verify_authenticator_for_self(node, envelope: Dict[str, Any]) -> bool:
    # verify incoming authenticator vector
    if "auth" not in envelope:
        return False
    sender = envelope.get("sender")
    msg = envelope.get("msg")
    msg_bytes = json.dumps(msg, sort_keys=True).encode("utf-8")
    ok = verify_authenticator(node.keyring, sender, node.id, msg_bytes, envelope.get("auth"))
    return ok


def verify_single_mac_for_self(node, envelope: Dict[str, Any]) -> bool:
    # verify incoming single-MAC envelope
    if "mac" not in envelope:
        return False
    sender = envelope.get("sender")
    msg = envelope.get("msg")
    msg_bytes = json.dumps(msg, sort_keys=True).encode("utf-8")
    ok = verify_mac(node.keyring, sender, node.id, msg_bytes, envelope.get("mac"))
    return ok


# timers

def start_request_timer(node):
    # start request timer unless running
    if node.timer and node.timer.is_alive():
        return

    timeout = float(node.timer_timeout)
    # adjust for leader time-attack if present
    leader_id = (node.view % node.n)  # placeholder; leader_for_view used in protocol when needed
    leader_cfg = node.attack_map.get(leader_id)
    if leader_cfg and getattr(leader_cfg, "time_attack", False):
        total_delay_buffer = (3 * float(leader_cfg.time_delay_ms) / 1000.0) + 2.5
        timeout = timeout + total_delay_buffer

    node.timer = threading.Timer(timeout, lambda: node._on_timer_expiry())
    node.timer.daemon = True
    node.timer.start()


def stop_request_timer(node):
    # cancel request timer
    if node.timer:
        try:
            node.timer.cancel()
        except Exception:
            pass
        node.timer = None


def start_view_change_timer(node, target_view: int):
    # start view-change timer
    if node.view_change_timer and node.view_change_timer.is_alive():
        return

    node.target_view = target_view
    node.view_change_timer = threading.Timer(node.view_change_timeout, lambda: node._on_view_change_timer_expiry())
    node.view_change_timer.daemon = True
    node.view_change_timer.start()


def stop_view_change_timer(node):
    # cancel view-change timer
    if node.view_change_timer:
        try:
            node.view_change_timer.cancel()
        except Exception:
            pass
        node.view_change_timer = None
        node.target_view = None


def _on_view_change_timer_expiry(node):
    # fired if no NEW-VIEW arrives
    if not node.in_view_change:
        return

    next_target = node.target_view + 1 if node.target_view is not None else node.view + 2
    try:
        node.start_view_change(next_target)
    except Exception:
        pass


def _on_timer_expiry(node):
    # called when request timer expires
    try:
        node.start_view_change(node.view + 1)
    except Exception:
        pass
