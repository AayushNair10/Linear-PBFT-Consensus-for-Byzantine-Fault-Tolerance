# Common constants & helpers used across the PBFT simulator.


# PBFT message type constants
MSG_REQUEST = "REQUEST"
MSG_PREPREPARE = "PREPREPARE"
MSG_PREPARE = "PREPARE"
MSG_COMMIT = "COMMIT"
MSG_REPLY = "REPLY"
MSG_EXECUTE = "EXECUTE"

# Additional message types
MSG_AUTH_INIT = "AUTH_INIT"
MSG_PREPARE_MULTICAST = "PREPARE_MULTICAST"
MSG_COMMIT_MULTICAST = "COMMIT_MULTICAST"
MSG_VIEW_CHANGE = "VIEW_CHANGE"
MSG_NEW_VIEW = "NEW_VIEW"
MSG_RESET = "RESET"
MSG_CHECKPOINT = "CHECKPOINT"

DEFAULT_N = 7

def leader_for_view(view: int, n: int = DEFAULT_N) -> int: 
    # Formula: primary = (view % n) + 1
    if n <= 0:
        n = DEFAULT_N
    return (view % n) + 1
