# attacks.py
"""
Byzantine attack implementations for PBFT simulator.

Attacks supported:
- sign: Invalid signatures
- crash: Simulated node crash (node behaves as if down)
- dark: Selective message dropping to specific targets
- time: Message delays (leader waits extra before multicasting)
- equivocation: Conflicting pre-prepares to different backups

This file also provides serialization helpers so the driver can send a
serializable attack map to each node process (spawned), which reconstructs a
local AttackConfig per node.
"""

import time
import random
import re
from typing import Dict, List, Any, Optional, Set


class AttackConfig:
    """Configuration for Byzantine attacks on a node."""

    def __init__(self, node_id: int):
        self.node_id = int(node_id)

        # Whether this node is considered Byzantine for this set
        self.is_byzantine: bool = False

        # Concrete attack toggles
        self.sign_attack: bool = False
        self.crash_attack: bool = False
        self.dark_attack: bool = False
        self.time_attack: bool = False
        self.equivocation_attack: bool = False

        # Parameters
        self.dark_targets: Set[int] = set()
        self.time_delay_ms: float = 1000.0
        self.equivocation_targets: List[int] = []

        # Fine-grained blocking flags
        self.crash_block_prepares: bool = False
        self.crash_block_commits: bool = False
        self.crash_block_replies: bool = False
        self.crash_block_newview: bool = False

    def configure_from_attack_string(self, attack_str: str, all_live_nodes: List[int]):
        """
        Parse attack string and configure attacks.

        Examples:
            "crash"
            "sign"
            "dark(n6)"
            "time"
            "equivocation(n6, n7)"
            "time(1500); dark(n6)"
        """
        if not attack_str:
            return

        parts = [p.strip() for p in attack_str.split(";") if p.strip()]
        for p in parts:
            pl = p.lower()
            if pl == "crash":
                self.is_byzantine = True
                self.crash_attack = True
                self.crash_block_prepares = True
                self.crash_block_commits = True
                self.crash_block_replies = True
                self.crash_block_newview = True

            elif pl == "sign":
                self.is_byzantine = True
                self.sign_attack = True

            elif pl.startswith("time"):
                self.is_byzantine = True
                self.time_attack = True
                m = re.search(r"time\((\d+)\)", p, flags=re.IGNORECASE)
                if m:
                    try:
                        self.time_delay_ms = float(m.group(1))
                    except Exception:
                        pass
                else:
                    self.time_delay_ms = 1000.0

            elif pl.startswith("dark"):
                self.is_byzantine = True
                self.dark_attack = True
                targets = self._parse_node_list(p)
                if targets:
                    self.dark_targets = set(targets)
                else:
                    self.dark_targets = set()

            elif pl.startswith("equivocation"):
                self.is_byzantine = True
                self.equivocation_attack = True
                targets = self._parse_node_list(p)
                self.equivocation_targets = targets if targets else []

            else:
                if "crash" in pl:
                    self.is_byzantine = True
                    self.crash_attack = True
                elif "dark" in pl:
                    self.is_byzantine = True
                    self.dark_attack = True
                    targets = self._parse_node_list(p)
                    self.dark_targets = set(targets) if targets else set()
                elif "time" in pl:
                    self.is_byzantine = True
                    self.time_attack = True
                    m = re.search(r"time\((\d+)\)", p, flags=re.IGNORECASE)
                    if m:
                        try:
                            self.time_delay_ms = float(m.group(1))
                        except Exception:
                            pass
                    else:
                        self.time_delay_ms = 1000.0

    def _parse_node_list(self, s: str) -> List[int]:
        """Extract n<num> occurrences from parentheses."""
        match = re.search(r'\((.*?)\)', s)
        if not match:
            return []
        content = match.group(1)
        nums = re.findall(r'n(\d+)', content)
        return [int(n) for n in nums]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize AttackConfig to a JSON-friendly dict."""
        return {
            "node_id": self.node_id,
            "is_byzantine": self.is_byzantine,
            "sign_attack": self.sign_attack,
            "crash_attack": self.crash_attack,
            "dark_attack": self.dark_attack,
            "time_attack": self.time_attack,
            "equivocation_attack": self.equivocation_attack,
            "dark_targets": list(self.dark_targets),
            "time_delay_ms": float(self.time_delay_ms),
            "equivocation_targets": list(self.equivocation_targets),
            "crash_block_prepares": self.crash_block_prepares,
            "crash_block_commits": self.crash_block_commits,
            "crash_block_replies": self.crash_block_replies,
            "crash_block_newview": self.crash_block_newview
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AttackConfig":
        """Reconstruct AttackConfig from a dict produced by to_dict()."""
        nid = int(data.get("node_id", 0))
        ac = cls(nid)
        ac.is_byzantine = bool(data.get("is_byzantine", False))
        ac.sign_attack = bool(data.get("sign_attack", False))
        ac.crash_attack = bool(data.get("crash_attack", False))
        ac.dark_attack = bool(data.get("dark_attack", False))
        ac.time_attack = bool(data.get("time_attack", False))
        ac.equivocation_attack = bool(data.get("equivocation_attack", False))
        ac.dark_targets = set(int(x) for x in data.get("dark_targets", []))
        ac.time_delay_ms = float(data.get("time_delay_ms", ac.time_delay_ms))
        ac.equivocation_targets = [int(x) for x in data.get("equivocation_targets", [])]
        ac.crash_block_prepares = bool(data.get("crash_block_prepares", False))
        ac.crash_block_commits = bool(data.get("crash_block_commits", False))
        ac.crash_block_replies = bool(data.get("crash_block_replies", False))
        ac.crash_block_newview = bool(data.get("crash_block_newview", False))
        return ac

    def should_drop_message_to(self, target_node: int) -> bool:
        """Return True if messages to the target_node should be dropped (dark attack)."""
        if not self.dark_attack:
            return False
        return target_node in self.dark_targets

    def apply_time_delay(self):
        """If time attack enabled, sleep for configured milliseconds (per-phase)."""
        if self.time_attack and self.time_delay_ms and self.time_delay_ms > 0:
            time.sleep(self.time_delay_ms / 1000.0)

    def should_block_prepare(self, is_leader: bool) -> bool:
        """Return True if this node should block sending PREPARE messages (crash semantics)."""
        if not self.crash_attack:
            return False
        return self.crash_block_prepares

    def should_block_commit(self, is_leader: bool) -> bool:
        """Return True if this node should block sending COMMIT messages."""
        if not self.crash_attack:
            return False
        return self.crash_block_commits

    def should_block_reply(self) -> bool:
        """Return True if this node should block sending REPLY to clients."""
        if not self.crash_attack:
            return False
        return self.crash_block_replies

    def should_block_newview(self) -> bool:
        """Return True if this node (primary) should not form/multicast NEW_VIEW."""
        if not self.crash_attack:
            return False
        return self.crash_block_newview

    def corrupt_signature(self, authenticator: Dict[int, str]) -> Dict[int, str]:
        """Corrupt signatures (simple perturbation) if sign attack active."""
        if not self.sign_attack:
            return authenticator
        corrupted = {}
        for nid, mac in authenticator.items():
            if not isinstance(mac, str) or len(mac) == 0:
                corrupted[nid] = "X"
                continue
            pos = random.randint(0, max(0, len(mac) - 1))
            mac_list = list(mac)
            mac_list[pos] = 'X' if mac_list[pos] != 'X' else 'Y'
            corrupted[nid] = "".join(mac_list)
        return corrupted

    def get_equivocation_sequence(self, base_seq: int, target_node: int) -> Optional[int]:
        """Return alternate seq for equivocation targets (base_seq + 1), else None."""
        if not self.equivocation_attack:
            return None
        if target_node in self.equivocation_targets:
            return base_seq + 1
        return None

    def is_crash(self) -> bool:
        """Convenience: is this node configured to crash (driver should PAUSE it)?"""
        return bool(self.crash_attack)

    def __repr__(self):
        parts = []
        if self.crash_attack:
            parts.append("crash")
        if self.sign_attack:
            parts.append("sign")
        if self.dark_attack:
            if self.dark_targets:
                parts.append(f"dark({','.join('n'+str(x) for x in sorted(self.dark_targets))})")
            else:
                parts.append("dark()")
        if self.time_attack:
            parts.append(f"time({int(self.time_delay_ms)}ms/phase, {int(self.time_delay_ms * 3)}ms total)")
        if self.equivocation_attack:
            parts.append(f"equivocation({','.join('n'+str(x) for x in self.equivocation_targets)})")
        return f"AttackConfig(node={self.node_id}, byzantine={self.is_byzantine}, attacks={';'.join(parts)})"
    
    def should_send_preprepare_only(self) -> bool:
        """In crash attack, node only sends pre-prepare, nothing else."""
        return bool(self.crash_attack)


class AttackOrchestrator:
    """Manage AttackConfig for all nodes."""

    def __init__(self, num_nodes: int):
        self.num_nodes = num_nodes
        self.configs: Dict[int, AttackConfig] = {}
        for nid in range(1, num_nodes + 1):
            self.configs[nid] = AttackConfig(nid)

    def configure_set(self, live_nodes: List[int], byzantine_nodes: List[int], attack_strings: List[str]):
        """Configure each byzantine node from attack_strings (parallel lists)."""
        # Reset all
        for nid in range(1, self.num_nodes + 1):
            self.configs[nid] = AttackConfig(nid)

        # Configure specified byzantine nodes
        for i, nid in enumerate(byzantine_nodes):
            if nid not in self.configs:
                continue
            attack_str = attack_strings[i] if i < len(attack_strings) else ""
            self.configs[nid].configure_from_attack_string(attack_str, live_nodes)

    def to_serializable_map(self) -> Dict[int, Dict[str, Any]]:
        """Return a dict mapping node_id -> attack_config_dict (serializable)."""
        return {nid: cfg.to_dict() for nid, cfg in self.configs.items()}

    def get_config(self, node_id: int) -> AttackConfig:
        return self.configs.get(node_id, AttackConfig(node_id))

    def is_byzantine(self, node_id: int) -> bool:
        return self.configs.get(node_id, AttackConfig(node_id)).is_byzantine

    def get_byzantine_nodes(self) -> List[int]:
        return [nid for nid, cfg in self.configs.items() if cfg.is_byzantine]

    def get_crashed_nodes(self) -> List[int]:
        """Return nodes that are configured to 'crash' (driver should PAUSE these)."""
        return [nid for nid, cfg in self.configs.items() if cfg.is_crash()]

    def __repr__(self):
        return f"AttackOrchestrator(num_nodes={self.num_nodes}, byzantine={self.get_byzantine_nodes()})"


# Global orchestrator (driver sets it up)
_global_orchestrator: Optional[AttackOrchestrator] = None


def initialize_orchestrator(num_nodes: int) -> AttackOrchestrator:
    global _global_orchestrator
    _global_orchestrator = AttackOrchestrator(num_nodes)
    return _global_orchestrator


def get_orchestrator() -> Optional[AttackOrchestrator]:
    return _global_orchestrator


def get_attack_config(node_id: int) -> AttackConfig:
    if _global_orchestrator is None:
        return AttackConfig(node_id)
    return _global_orchestrator.get_config(node_id)