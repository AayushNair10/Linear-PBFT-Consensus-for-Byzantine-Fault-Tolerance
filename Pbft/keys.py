# keys.py
"""
Key generation and MAC utilities for PBFT simulator.

We model pairwise symmetric keys between replicas and use HMAC-SHA256 for MACs.
- create_keyring(n): create symmetric keys for every pair (i, j) with i < j.
- mac_for_pair(keyring, sender, recipient, message_bytes): compute MAC hex using pair key.
- create_authenticator(keyring, sender, recipients, message_bytes):
    produce a dict mapping recipient -> mac_hex. The sender **omits** the entry for itself.
- verify_mac / verify_authenticator: verify MAC or authenticator entries.
"""

import os
import hmac
import hashlib
from typing import Dict, Tuple, List

# type alias for readability
KeyRing = Dict[Tuple[int, int], bytes]

def create_keyring(n: int) -> KeyRing:
    """
    Create random symmetric keys for each unordered pair (i,j) with 1 <= i < j <= n.
    Return mapping {(i,j): key_bytes} where i < j.
    """
    keyring: KeyRing = {}
    for i in range(1, n + 1):
        for j in range(i + 1, n + 1):
            keyring[(i, j)] = os.urandom(32)  # 256-bit random key
    return keyring

def _pair_key(keyring: KeyRing, a: int, b: int) -> bytes:
    """
    Lookup the symmetric key for pair (a,b). The stored key uses (min,max) ordering.
    """
    if a == b:
        raise KeyError("No key for identical identities")
    key = keyring.get((min(a, b), max(a, b)))
    if key is None:
        raise KeyError(f"No key for pair ({a},{b})")
    return key

def mac_for_pair(keyring: KeyRing, sender: int, recipient: int, message_bytes: bytes) -> str:
    """
    Compute HMAC-SHA256 using the symmetric key of (sender,recipient).
    Return MAC as hex string for ease of transport/storage.
    """
    key = _pair_key(keyring, sender, recipient)
    mac = hmac.new(key, message_bytes, hashlib.sha256).hexdigest()
    return mac

def create_authenticator(keyring: KeyRing, sender: int, recipients: List[int], message_bytes: bytes) -> Dict[int, str]:
    """
    Build an authenticator vector mapping recipient_id -> mac_hex. **Important**:
    The sender should omit its own entry (no MAC for sender).
    This follows the common PBFT practice where the sender does not include a MAC
    for itself in the authenticator vector (it doesn't need to authenticate to itself).
    """
    auth: Dict[int, str] = {}
    for r in recipients:
        if r == sender:
            # intentionally skip self
            continue
        auth[r] = mac_for_pair(keyring, sender, r, message_bytes)
    return auth

def verify_mac(keyring: KeyRing, sender: int, recipient: int, message_bytes: bytes, mac_hex: str) -> bool:
    """
    Verify a single MAC hex for (sender -> recipient).
    Returns True if MAC matches expected HMAC under the shared key.
    """
    try:
        expected = mac_for_pair(keyring, sender, recipient, message_bytes)
    except KeyError:
        return False
    return hmac.compare_digest(expected, mac_hex)

def verify_authenticator(keyring: KeyRing, sender: int, recipient: int, message_bytes: bytes, authenticator: Dict[int, str]) -> bool:
    """
    Verify an authenticator vector produced by sender. The function:
    - returns False if the authenticator is missing or doesn't contain an entry for recipient
    - otherwise verifies the MAC for (sender -> recipient)
    """
    if authenticator is None:
        return False
    mac_hex = authenticator.get(recipient)
    if mac_hex is None:
        # missing entry for recipient: verification fails
        return False
    return verify_mac(keyring, sender, recipient, message_bytes, mac_hex)