import csv
import re
from typing import List, Dict, Any, Optional


def _parse_live_field(live_field: str) -> Optional[List[int]]:
    # parse "[n1, n2]" -> [1, 2]
    if not live_field or live_field.strip() == "":
        return None
    nums = re.findall(r'n?(\d+)', live_field.strip())
    return [int(x) for x in nums] if nums else None


def _parse_byzantine_field(byz_field: str) -> List[int]:
    # parse "[n1, n2]" -> [1, 2]
    if not byz_field or byz_field.strip() in ("", "[]"):
        return []
    nums = re.findall(r'n?(\d+)', byz_field)
    return [int(x) for x in nums]


def _parse_attack_field(attack_field: str) -> List[str]:
    # parse "[crash]" or "[crash], [sign]" -> ["crash"] / ["crash", "sign"]
    if not attack_field or attack_field.strip() in ("", "[]"):
        return []
    s = attack_field.strip()

    if '],' in s or '], [' in s:
        parts = []
        for part in s.split(','):
            part = part.strip()
            if part.startswith('[') and part.endswith(']'):
                part = part[1:-1].strip()
            if part:
                parts.append(part)
        return parts

    if s.startswith('[') and s.endswith(']'):
        s = s[1:-1].strip()
    return [s] if s else []


def parse_csv_with_attacks(filename: str) -> List[Dict[str, Any]]:
    # parse CSV into structured PBFT sets
    sets = {}
    with open(filename, newline="") as csvfile:
        reader = csv.DictReader(csvfile, skipinitialspace=True)
        last_set = None

        for row in reader:
            set_field = row.get("Set Number", "").strip()
            set_no = int(set_field) if set_field.isdigit() else last_set
            if set_no is None:
                continue

            if set_no not in sets:
                sets[set_no] = {
                    "set_no": set_no,
                    "transactions": [],
                    "live": None,
                    "byzantine": [],
                    "attacks": []
                }

            live_field = row.get("Live", "")
            if live_field.strip():
                live_list = _parse_live_field(live_field)
                if live_list:
                    sets[set_no]["live"] = live_list

            byz_field = row.get("Byzantine", "")
            if byz_field.strip():
                byz_list = _parse_byzantine_field(byz_field)
                if byz_list:
                    sets[set_no]["byzantine"] = byz_list

            attack_field = row.get("Attack", "")
            if attack_field.strip():
                attack_list = _parse_attack_field(attack_field)
                if attack_list:
                    sets[set_no]["attacks"] = attack_list

            txn_field = row.get("Transactions", "").strip()
            if not txn_field:
                continue

            inside = txn_field.strip().strip('"').strip("()")
            parts = [p.strip() for p in inside.split(",") if p.strip()]

            if len(parts) == 1:
                op = {"type": "read", "s": parts[0]}
            elif len(parts) >= 2:
                s, r = parts[0], parts[1]
                try:
                    amt = int(parts[2]) if len(parts) >= 3 else 0
                except Exception:
                    amt = 0
                op = {"type": "write", "op": {"type": "transfer", "s": s, "r": r, "amt": amt}}
            else:
                continue

            sets[set_no]["transactions"].append(op)
            last_set = set_no

    parsed = [sets[k] for k in sorted(sets.keys())]

    for s in parsed:
        if s["live"] is None:
            s["live"] = list(range(1, 8))  # default all nodes
        if len(s["byzantine"]) > len(s["attacks"]) and len(s["attacks"]) == 1:
            s["attacks"] = [s["attacks"][0]] * len(s["byzantine"])
        while len(s["attacks"]) < len(s["byzantine"]):
            s["attacks"].append("")

    return parsed