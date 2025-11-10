# Key and MAC helpers for PBFT
import os
import hmac
import hashlib
from typing import Dict, Tuple, List

# map (i, j) -> shared key
KeyRing = Dict[Tuple[int, int], bytes]


def create_keyring(n: int) -> KeyRing:
    # make random 256-bit keys for every node pair
    keyring: KeyRing = {}
    for i in range(1, n + 1):
        for j in range(i + 1, n + 1):
            keyring[(i, j)] = os.urandom(32)
    return keyring


def _pair_key(keyring: KeyRing, a: int, b: int) -> bytes:
    # get key for node pair (a,b)
    if a == b:
        raise KeyError("same id")
    key = keyring.get((min(a, b), max(a, b)))
    if key is None:
        raise KeyError(f"no key for ({a},{b})")
    return key


def mac_for_pair(keyring: KeyRing, sender: int, recipient: int, message_bytes: bytes) -> str:
    # return HMAC-SHA256 for (sender, recipient)
    key = _pair_key(keyring, sender, recipient)
    return hmac.new(key, message_bytes, hashlib.sha256).hexdigest()


def create_authenticator(keyring: KeyRing, sender: int, recipients: List[int], message_bytes: bytes) -> Dict[int, str]:
    # build MACs for each recipient (skip self)
    auth: Dict[int, str] = {}
    for r in recipients:
        if r == sender:
            continue
        auth[r] = mac_for_pair(keyring, sender, r, message_bytes)
    return auth


def verify_mac(keyring: KeyRing, sender: int, recipient: int, message_bytes: bytes, mac_hex: str) -> bool:
    # check if MAC matches expected value
    try:
        expected = mac_for_pair(keyring, sender, recipient, message_bytes)
    except KeyError:
        return False
    return hmac.compare_digest(expected, mac_hex)


def verify_authenticator(keyring: KeyRing, sender: int, recipient: int, message_bytes: bytes, authenticator: Dict[int, str]) -> bool:
    # verify sender's MAC for this recipient
    if not authenticator or recipient not in authenticator:
        return False
    mac_hex = authenticator[recipient]
    return verify_mac(keyring, sender, recipient, message_bytes, mac_hex)
