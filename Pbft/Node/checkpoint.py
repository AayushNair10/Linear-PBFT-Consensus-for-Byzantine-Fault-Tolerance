# Checkpointing protocol for PBFT
# Creates stable checkpoints every CHECKPOINT_INTERVAL requests
# Used for garbage collection signaling and state synchronization

import json
import hashlib
from typing import Dict, Any, List
from common import MSG_CHECKPOINT

# checkpoint every 100 requests
CHECKPOINT_INTERVAL = 100


# compute deterministic digest of current datastore state
def compute_state_digest(datastore: Dict[str, int]) -> str:
    # sort items so serialization is deterministic
    sorted_items = sorted(datastore.items())
    # stringify and hash
    state_str = json.dumps(sorted_items, sort_keys=True)
    return hashlib.sha256(state_str.encode('utf-8')).hexdigest()


# check if this seq is a checkpoint boundary
def should_create_checkpoint(node, seq: int) -> bool:
    # checkpoint at multiples of CHECKPOINT_INTERVAL
    return seq > 0 and seq % CHECKPOINT_INTERVAL == 0


# create and broadcast a CHECKPOINT for an executed seq
def create_checkpoint(node, seq: int):
    # don't do anything if node is paused
    if not node.active:
        return

    # only checkpoint fully executed sequences
    with node.state_lock:
        st = node.seq_state.get(seq)
        if not st or not st.get("executed"):
            return

    # compute digest of current DB
    state_digest = compute_state_digest(node.datastore)

    # build checkpoint message
    checkpoint_msg = {
        "type": MSG_CHECKPOINT,
        "seq": seq,
        "d": state_digest,
        "i": node.id
    }

    # record our own checkpoint under the lock
    with node.checkpoint_lock:
        if seq not in node.checkpoints:
            node.checkpoints[seq] = {}
        node.checkpoints[seq][node.id] = checkpoint_msg

    # multicast to replicas (authenticator will be added by comms)
    node.multicast_with_authenticator(checkpoint_msg)
    # log the send for debugging
    node.log_message("CHECKPOINT", checkpoint_msg, "SENT")


# handle incoming checkpoint envelopes
def handle_checkpoint(node, envelope: Dict[str, Any]):
    # ignore if node paused
    if not node.active:
        return

    # verify auth
    if not node.verify_authenticator_for_self(envelope):
        return

    msg = envelope.get("msg")
    seq = msg.get("seq")
    state_digest = msg.get("d")
    sender = msg.get("i")

    # log receipt
    node.log_message("CHECKPOINT", msg, "RECEIVED")

    # store checkpoint under lock
    with node.checkpoint_lock:
        if seq not in node.checkpoints:
            node.checkpoints[seq] = {}
        node.checkpoints[seq][sender] = msg

    # try to form a stable checkpoint if possible
    _try_to_create_stable_checkpoint(node, seq)


# check if any digest for seq has 2f+1 matches and mark stable
def _try_to_create_stable_checkpoint(node, seq: int):
    with node.checkpoint_lock:
        if seq not in node.checkpoints:
            return

        checkpoints = node.checkpoints[seq]
        # need at least 2f+1 messages overall to consider grouping
        if len(checkpoints) < (2 * node.F + 1):
            return

        # group messages by digest
        digest_groups = {}
        for nid, cp_msg in checkpoints.items():
            d = cp_msg.get("d")
            digest_groups.setdefault(d, []).append(nid)

        # if any group reaches 2f+1 mark it stable
        for digest, node_ids in digest_groups.items():
            if len(node_ids) >= (2 * node.F + 1):
                if seq not in node.stable_checkpoints:
                    node.stable_checkpoints[seq] = {
                        "seq": seq,
                        "digest": digest,
                        "nodes": node_ids,
                        "proof": [checkpoints[nid] for nid in node_ids]
                    }

                    # advance low-water mark but keep data (no GC here)
                    if seq > node.low:
                        node.low = seq
                        node.high = node.low + node.WINDOW_SIZE

                    # quick console hint
                    print(f"[Node {node.id}] Stable checkpoint at seq={seq}, digest={digest[:8]}...")

                    # log stable checkpoint formation
                    node.log_message("STABLE_CHECKPOINT", {
                        "seq": seq,
                        "digest": digest,
                        "nodes": node_ids
                    }, "PROCESSED")

                break


# return most recent stable checkpoint or None
def get_latest_stable_checkpoint(node) -> Dict[str, Any]:
    with node.checkpoint_lock:
        if not node.stable_checkpoints:
            return None
        max_seq = max(node.stable_checkpoints.keys())
        return node.stable_checkpoints[max_seq]


# build checkpoint data to include in VIEW-CHANGE
def get_stable_checkpoint_for_viewchange(node) -> Dict[str, Any]:
    latest = get_latest_stable_checkpoint(node)
    if not latest:
        # empty/default certificate
        return {"seq": 0, "digest": "", "proof": []}
    return {
        "seq": latest["seq"],
        "digest": latest["digest"],
        "proof": latest["proof"]  # list of CHECKPOINT messages
    }


# verify a checkpoint certificate has 2f+1 matching CHECKPOINT messages
def verify_checkpoint_proof(node, checkpoint_data: Dict[str, Any]) -> bool:
    if not checkpoint_data:
        return False

    seq = checkpoint_data.get("seq", 0)
    # seq==0 means "no checkpoint" and is acceptable
    if seq == 0:
        return True

    digest = checkpoint_data.get("digest")
    proof = checkpoint_data.get("proof", [])

    if len(proof) < (2 * node.F + 1):
        return False

    # count proofs that match claimed seq and digest
    matching = 0
    for cp_msg in proof:
        if cp_msg.get("d") == digest and cp_msg.get("seq") == seq:
            matching += 1

    return matching >= (2 * node.F + 1)


# restore node low/high from a validated checkpoint cert (no state transfer)
def restore_from_checkpoint(node, checkpoint_data: Dict[str, Any]):
    # validate proof first
    if not verify_checkpoint_proof(node, checkpoint_data):
        return False

    seq = checkpoint_data.get("seq")
    # update window pointers if checkpoint is newer
    if seq > node.low:
        node.low = seq
        node.high = node.low + node.WINDOW_SIZE
        print(f"[Node {node.id}] Restored from checkpoint at seq={seq}")
        return True

    return False
