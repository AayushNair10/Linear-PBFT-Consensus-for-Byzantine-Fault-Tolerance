# attacks.py
"""
Byzantine attack implementations for PBFT simulator.

Attacks supported:
- sign: Invalid signatures
- crash: Silent failures (leader/backup specific behaviors)
- dark: Selective message dropping to specific targets
- time: Message delays
- equivocation: Conflicting pre-prepares to different backups
"""

import time
import random
from typing import Dict, List, Any, Optional, Set


class AttackConfig:
    """Configuration for Byzantine attacks on a node."""
    
    def __init__(self, node_id: int):
        self.node_id = node_id
        self.is_byzantine = False
        
        # Attack types
        self.sign_attack = False
        self.crash_attack = False
        self.dark_attack = False
        self.time_attack = False
        self.equivocation_attack = False
        
        # Attack parameters
        self.dark_targets: Set[int] = set()  # Nodes to exclude from messages
        self.time_delay_ms: float = 0.0  # Delay in milliseconds
        self.equivocation_targets: List[int] = []  # Nodes to send conflicting preprepares
        
        # State tracking for crash attack
        self.crash_block_prepares = False
        self.crash_block_commits = False
        self.crash_block_replies = False
        self.crash_block_newview = False
        
    def configure_from_attack_string(self, attack_str: str, all_live_nodes: List[int]):
        """
        Parse attack string and configure attacks.
        
        Examples:
        - "crash"
        - "sign"
        - "dark(n6)"
        - "time"
        - "equivocation(n6, n7)"
        - "time; dark(n6); equivocation(n7)"
        """
        if not attack_str or attack_str.strip() == "":
            return
        
        # Split by semicolon for multiple attacks
        attack_parts = [a.strip() for a in attack_str.split(";") if a.strip()]
        
        for part in attack_parts:
            if part.lower() == "crash":
                self.is_byzantine = True
                self.crash_attack = True
                self.crash_block_prepares = True
                self.crash_block_commits = True
                self.crash_block_replies = True
                self.crash_block_newview = True
                
            elif part.lower() == "sign":
                self.is_byzantine = True
                self.sign_attack = True
                
            elif part.lower() == "time":
                self.is_byzantine = True
                self.time_attack = True
                # Default delay: 30% of base timer (e.g., 3 seconds if base is 10s)
                self.time_delay_ms = 3000.0
                
            elif part.lower().startswith("dark"):
                self.is_byzantine = True
                self.dark_attack = True
                # Parse dark(n1, n2, ...) or dark(n1)
                targets = self._parse_node_list(part)
                self.dark_targets = set(targets) if targets else set(all_live_nodes)
                
            elif part.lower().startswith("equivocation"):
                self.is_byzantine = True
                self.equivocation_attack = True
                # Parse equivocation(n6, n7)
                targets = self._parse_node_list(part)
                self.equivocation_targets = targets if targets else []
    
    def _parse_node_list(self, attack_str: str) -> List[int]:
        """Parse node list from attack string like 'dark(n1, n2)'."""
        import re
        # Find content inside parentheses
        match = re.search(r'\((.*?)\)', attack_str)
        if not match:
            return []
        
        content = match.group(1)
        # Extract all n<digit> patterns
        nodes = re.findall(r'n(\d+)', content)
        return [int(n) for n in nodes]
    
    def should_drop_message_to(self, target_node: int) -> bool:
        """Check if message to target should be dropped (dark attack)."""
        if not self.dark_attack:
            return False
        return target_node in self.dark_targets
    
    def apply_time_delay(self):
        """Apply time delay if time attack is active."""
        if self.time_attack and self.time_delay_ms > 0:
            time.sleep(self.time_delay_ms / 1000.0)
    
    def should_block_prepare(self, is_leader: bool) -> bool:
        """Check if prepare should be blocked (crash attack)."""
        if not self.crash_attack:
            return False
        return self.crash_block_prepares
    
    def should_block_commit(self, is_leader: bool) -> bool:
        """Check if commit should be blocked (crash attack)."""
        if not self.crash_attack:
            return False
        return self.crash_block_commits
    
    def should_block_reply(self) -> bool:
        """Check if reply should be blocked (crash attack)."""
        if not self.crash_attack:
            return False
        return self.crash_block_replies
    
    def should_block_newview(self) -> bool:
        """Check if new-view should be blocked (crash attack)."""
        if not self.crash_attack:
            return False
        return self.crash_block_newview
    
    def corrupt_signature(self, authenticator: Dict[int, str]) -> Dict[int, str]:
        """Corrupt signatures if sign attack is active."""
        if not self.sign_attack:
            return authenticator
        
        # Corrupt all MACs by flipping random bits
        corrupted = {}
        for node_id, mac in authenticator.items():
            # Flip a random character in the MAC
            if len(mac) > 0:
                pos = random.randint(0, len(mac) - 1)
                mac_list = list(mac)
                mac_list[pos] = 'X' if mac_list[pos] != 'X' else 'Y'
                corrupted[node_id] = ''.join(mac_list)
            else:
                corrupted[node_id] = "CORRUPTED"
        return corrupted
    
    def get_equivocation_sequence(self, base_seq: int, target_node: int) -> Optional[int]:
        """
        Get alternate sequence number for equivocation attack.
        Returns base_seq + 1 if target_node is in equivocation targets.
        """
        if not self.equivocation_attack:
            return None
        
        if target_node in self.equivocation_targets:
            return base_seq + 1
        else:
            return None
    
    def __repr__(self):
        parts = []
        if self.crash_attack:
            parts.append("crash")
        if self.sign_attack:
            parts.append("sign")
        if self.dark_attack:
            parts.append(f"dark({','.join(f'n{t}' for t in self.dark_targets)})")
        if self.time_attack:
            parts.append(f"time({self.time_delay_ms}ms)")
        if self.equivocation_attack:
            parts.append(f"equivocation({','.join(f'n{t}' for t in self.equivocation_targets)})")
        
        return f"AttackConfig(node={self.node_id}, byzantine={self.is_byzantine}, attacks={';'.join(parts)})"


class AttackOrchestrator:
    """Manages attack configurations for all nodes."""
    
    def __init__(self, num_nodes: int):
        self.num_nodes = num_nodes
        self.configs: Dict[int, AttackConfig] = {}
        
        # Initialize all nodes as honest
        for nid in range(1, num_nodes + 1):
            self.configs[nid] = AttackConfig(nid)
    
    def configure_set(self, live_nodes: List[int], byzantine_nodes: List[int], attack_strings: List[str]):
        """
        Configure attacks for a new set.
        
        Args:
            live_nodes: List of active node IDs
            byzantine_nodes: List of Byzantine node IDs
            attack_strings: List of attack specifications (parallel to byzantine_nodes)
        """
        # Reset all nodes to honest
        for nid in range(1, self.num_nodes + 1):
            self.configs[nid] = AttackConfig(nid)
        
        # Configure Byzantine nodes
        for i, byz_node in enumerate(byzantine_nodes):
            if byz_node not in self.configs:
                continue
            
            attack_str = attack_strings[i] if i < len(attack_strings) else ""
            self.configs[byz_node].configure_from_attack_string(attack_str, live_nodes)
        
        # Log configuration
        print("\n=== Attack Configuration ===")
        for nid in sorted(self.configs.keys()):
            if self.configs[nid].is_byzantine:
                print(f"  {self.configs[nid]}")
        print("============================\n")
    
    def get_config(self, node_id: int) -> AttackConfig:
        """Get attack configuration for a node."""
        return self.configs.get(node_id, AttackConfig(node_id))
    
    def is_byzantine(self, node_id: int) -> bool:
        """Check if a node is Byzantine."""
        return self.configs.get(node_id, AttackConfig(node_id)).is_byzantine
    
    def get_byzantine_nodes(self) -> List[int]:
        """Get list of all Byzantine node IDs."""
        return [nid for nid, cfg in self.configs.items() if cfg.is_byzantine]


# Global orchestrator instance (will be initialized by driver)
_global_orchestrator: Optional[AttackOrchestrator] = None


def initialize_orchestrator(num_nodes: int) -> AttackOrchestrator:
    """Initialize global attack orchestrator."""
    global _global_orchestrator
    _global_orchestrator = AttackOrchestrator(num_nodes)
    return _global_orchestrator


def get_orchestrator() -> Optional[AttackOrchestrator]:
    """Get global attack orchestrator."""
    return _global_orchestrator


def get_attack_config(node_id: int) -> AttackConfig:
    """Get attack configuration for a node (convenience function)."""
    if _global_orchestrator is None:
        return AttackConfig(node_id)
    return _global_orchestrator.get_config(node_id)