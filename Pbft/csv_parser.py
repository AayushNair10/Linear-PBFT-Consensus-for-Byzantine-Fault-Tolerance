# csv_parser.py - Fixed parser for multiple Byzantine nodes with single attack
"""
Parse CSV with Live, Byzantine, and Attack columns.

IMPORTANT FIX: When Byzantine column has multiple nodes like [n1, n2]
and Attack column has single attack like [crash], that attack applies
to ALL Byzantine nodes listed.
"""

import csv
import re
from typing import List, Dict, Any, Optional


def _parse_live_field(live_field: str) -> Optional[List[int]]:
    """
    Parse Live field: "[n1, n2, n3]" -> [1, 2, 3]
    """
    if not live_field or live_field.strip() == "":
        return None
    s = live_field.strip()
    nums = re.findall(r'n?(\d+)', s)
    if not nums:
        return None
    try:
        return [int(x) for x in nums]
    except Exception:
        return None


def _parse_byzantine_field(byz_field: str) -> List[int]:
    """
    Parse Byzantine field: "[n2]" or "[n1, n2]" -> [2] or [1, 2]
    """
    if not byz_field or byz_field.strip() == "" or byz_field.strip() == "[]":
        return []
    nums = re.findall(r'n?(\d+)', byz_field)
    try:
        return [int(x) for x in nums]
    except Exception:
        return []


def _parse_attack_field(attack_field: str) -> List[str]:
    """
    Parse Attack field.
    
    Examples:
        "[crash]" -> ["crash"]
        "[time; dark(n6)]" -> ["time; dark(n6)"]
        "[crash], [sign]" -> ["crash", "sign"]  (comma-separated for multiple nodes)
    
    Returns list of attack strings. If single attack in brackets, returns one element.
    If comma-separated attacks, returns multiple elements (one per Byzantine node).
    """
    if not attack_field or attack_field.strip() == "" or attack_field.strip() == "[]":
        return []
    
    s = attack_field.strip()
    
    # Check if it contains comma-separated attacks like "[crash], [sign]"
    if '],' in s or '], [' in s:
        # Split by comma and clean each part
        parts = []
        for part in s.split(','):
            part = part.strip()
            if part.startswith('[') and part.endswith(']'):
                part = part[1:-1].strip()
            if part:
                parts.append(part)
        return parts if parts else []
    
    # Single attack in brackets: "[crash]" or "[time; dark(n6)]"
    if s.startswith('[') and s.endswith(']'):
        s = s[1:-1].strip()
    
    if not s:
        return []
    
    # Return the entire attack string as one element
    return [s]


def parse_csv_with_attacks(filename: str) -> List[Dict[str, Any]]:
    """
    Parse CSV file with Live, Byzantine, and Attack columns.
    
    IMPORTANT: If Byzantine has multiple nodes [n1, n2] and Attack has single value [crash],
    that attack is applied to ALL Byzantine nodes.
    
    Returns list of sets, each containing:
    {
        "set_no": int,
        "transactions": [{"type": "read"/"write", "op": {...}}, ...],
        "live": [node_ids] or None,
        "byzantine": [node_ids],
        "attacks": [attack_string]  # parallel to byzantine
    }
    """
    sets = {}
    
    with open(filename, newline="") as csvfile:
        reader = csv.DictReader(csvfile, skipinitialspace=True)
        last_set = None
        
        for row in reader:
            # Parse Set Number
            set_field = row.get("Set Number", "").strip()
            if set_field == "":
                set_no = last_set
            else:
                try:
                    set_no = int(set_field)
                except Exception:
                    set_no = last_set
            
            if set_no is None:
                continue
            
            # Initialize set if not exists
            if set_no not in sets:
                sets[set_no] = {
                    "set_no": set_no,
                    "transactions": [],
                    "live": None,
                    "byzantine": [],
                    "attacks": []
                }
            
            # Parse Live column (only on first row of set typically)
            live_field = row.get("Live", "")
            if live_field and live_field.strip() != "":
                live_list = _parse_live_field(live_field)
                if live_list is not None:
                    sets[set_no]["live"] = live_list
            
            # Parse Byzantine column (only on first row of set typically)
            byz_field = row.get("Byzantine", "")
            if byz_field and byz_field.strip() != "":
                byz_list = _parse_byzantine_field(byz_field)
                if byz_list:
                    sets[set_no]["byzantine"] = byz_list
            
            # Parse Attack column (only on first row of set typically)
            attack_field = row.get("Attack", "")
            if attack_field and attack_field.strip() != "":
                attack_list = _parse_attack_field(attack_field)
                if attack_list:
                    sets[set_no]["attacks"] = attack_list
            
            # Parse Transaction
            txn_field = row.get("Transactions", "").strip()
            if txn_field == "":
                continue
            
            # Remove quotes and parentheses
            inside = txn_field.strip().strip('"').strip().strip("()")
            parts = [p.strip() for p in inside.split(",") if p.strip() != ""]
            
            if len(parts) == 1:
                # Read operation
                op = {"type": "read", "s": parts[0]}
            elif len(parts) >= 2:
                # Write operation
                s = parts[0]
                r = parts[1]
                try:
                    amt = int(parts[2]) if len(parts) >= 3 else 0
                except Exception:
                    amt = 0
                op = {"type": "write", "op": {"type": "transfer", "s": s, "r": r, "amt": amt}}
            else:
                continue
            
            sets[set_no]["transactions"].append(op)
            last_set = set_no
    
    # Convert to sorted list
    parsed = [sets[k] for k in sorted(sets.keys())]
    
    # Set default live nodes if not specified
    for s in parsed:
        if s["live"] is None:
            s["live"] = list(range(1, 8))  # Default: all 7 nodes
        
        # IMPORTANT FIX: If multiple Byzantine nodes but single attack,
        # replicate that attack for all Byzantine nodes
        # This handles cases like Byzantine: [n1, n2], Attack: [crash]
        # Result should be: attacks = ["crash", "crash"]
        if len(s["byzantine"]) > len(s["attacks"]) and len(s["attacks"]) == 1:
            # Single attack for multiple nodes - replicate it
            single_attack = s["attacks"][0]
            s["attacks"] = [single_attack] * len(s["byzantine"])
        
        # Ensure attacks list matches byzantine list length (padding with empty if needed)
        while len(s["attacks"]) < len(s["byzantine"]):
            s["attacks"].append("")
    
    return parsed