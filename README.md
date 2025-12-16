# Linear PBFT Consensus for Byzantine Fault Tolerance

A Byzantine fault-tolerant distributed banking application implementing the **Linear PBFT** consensus protocol. This system tolerates up to 2 Byzantine (malicious) nodes in a 7-node cluster while maintaining safety and liveness guarantees, with **O(n)** communication complexity during normal operation.

---

## Features

- **Linear PBFT Consensus**: Optimized communication pattern reducing O(n²) to O(n) complexity
- **Byzantine Fault Tolerance**: Tolerates up to `f=2` malicious nodes in a `3f+1=7` node cluster
- **Digital Signatures**: Cryptographic authentication for all protocol messages
- **View Change Protocol**: Automatic leader replacement when Byzantine behavior is detected
- **Read-Only Optimization**: Balance queries bypass consensus for improved performance
- **Attack Simulation**: Built-in support for testing various Byzantine attack vectors
- **Checkpointing** *(Bonus)*: Periodic state snapshots for garbage collection and recovery

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CLIENTS (10)                                │
│   ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ...     │
│   │ C1  │ │ C2  │ │ C3  │ │ C4  │ │ C5  │ │ C6  │ │ C7  │         │
│   └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘         │
└──────┼───────┼───────┼───────┼───────┼───────┼───────┼─────────────┘
       │       │       │       │       │       │       │
       ▼       ▼       ▼       ▼       ▼       ▼       ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    LINEAR PBFT CLUSTER (7 nodes)                    │
│  ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐
│  │  n1   │ │  n2   │ │  n3   │ │  n4   │ │  n5   │ │  n6   │ │  n7   │
│  │Leader │ │Backup │ │Backup │ │Backup │ │Backup │ │Backup │ │Backup │
│  └───────┘ └───────┘ └───────┘ └───────┘ └───────┘ └───────┘ └───────┘
│       │         │         │         │         │         │         │
│       └─────────┴─────────┴─────────┴─────────┴─────────┴─────────┘
│                      Replicated State Machine                       │
│                    (Byzantine Fault Tolerant)                       │
└─────────────────────────────────────────────────────────────────────┘
```

### Linear PBFT vs Traditional PBFT

```
Traditional PBFT (O(n²)):          Linear PBFT (O(n)):
                                   
    ┌───┐                              ┌───┐
    │ L │──────┬──────┐                │ L │ (Collector)
    └───┘      │      │                └─┬─┘
      │        │      │                  │
    ┌─┴─┐    ┌─┴─┐  ┌─┴─┐            ┌──┴──┐
    │ B │◄──►│ B │◄►│ B │            │     │
    └───┘    └───┘  └───┘          ┌─┴─┐ ┌─┴─┐ ┌───┐
       ▲───────┴───────▲           │ B │ │ B │ │ B │
                                   └───┘ └───┘ └───┘
```

---

## Project Structure

```
Pbft/
├── Node/
│   ├── __init__.py        # Node package initialization
│   ├── node.py            # Core PBFT replica implementation
│   ├── protocol.py        # Protocol message handlers
│   ├── comms.py           # Network communication layer
│   ├── checkpoint.py      # Checkpointing mechanism (bonus)
│   └── viewchange.py      # View change protocol logic
├── attacks.py             # Byzantine attack simulations
├── client.py              # Client implementation
├── common.py              # Shared utilities and constants
├── csv_parser.py          # Test input file parser
├── keys.py                # Cryptographic key management
├── monitor.py             # System monitoring utilities
├── run_driver.py          # Test driver and orchestration
└── test.csv               # Sample test transactions
```

---

## Quick Start

### Prerequisites

- Python 3.8+
- Required packages: `pip install -r requirements.txt`
- Cryptographic libraries for digital signatures

### Running the System

1. **Start the PBFT cluster**:
   ```bash
   python run_driver.py
   ```

2. **Process test transactions**:
   ```bash
   # The driver will prompt you to process each transaction set
   # Press Enter to process the next set
   # System state resets between sets
   ```

### Configuration

Edit configuration files to modify node addresses, ports, timeout durations, and attack parameters.

---

## Protocol Messages

| Phase | Message | Format | Description |
|-------|---------|--------|-------------|
| **Request** | REQUEST | `⟨REQUEST, op, timestamp, client⟩σc` | Client request with signature |
| **Pre-prepare** | PRE-PREPARE | `⟨PRE-PREPARE, view, seq, digest⟩σL` | Leader assigns sequence number |
| **Prepare** | PREPARE | `⟨PREPARE, view, seq, digest, replica⟩σi` | Replica confirms order |
| **Commit** | COMMIT | `⟨COMMIT, view, seq, digest, replica⟩σi` | Replica ready to execute |
| **Reply** | REPLY | `⟨REPLY, view, timestamp, client, result⟩σi` | Response to client |
| **View-Change** | VIEW-CHANGE | `⟨VIEW-CHANGE, view+1, P, replica⟩σi` | Request leader change |
| **New-View** | NEW-VIEW | `⟨NEW-VIEW, view+1, V, O⟩σL` | New leader announcement |

### Linear Communication Pattern

In Linear PBFT, the collector (leader) aggregates `n-f` signed messages and broadcasts a combined certificate:

```
Replicas → Collector: Individual signed PREPARE messages
Collector → Replicas: Combined PREPARE certificate (n-f signatures)

Replicas → Collector: Individual signed COMMIT messages  
Collector → Replicas: Combined COMMIT certificate (n-f signatures)
```

---

## Byzantine Attack Simulations

The system supports testing various Byzantine failure modes:

| Attack | Command | Description |
|--------|---------|-------------|
| **Invalid Signature** | `sign` | Malicious nodes send improperly signed messages |
| **Crash** | `crash` | Nodes stop participating in protocol phases |
| **In-Dark** | `dark(ni, nj)` | Selectively withhold messages from specific nodes |
| **Timing** | `time` | Leader delays messages (within timer bounds) |
| **Equivocation** | `equivocation(ni, nj)` | Leader sends conflicting sequence numbers |

### Attack Examples

```csv
# Crash attack - nodes stop sending prepare messages
Set,Transactions,Live,Byzantine,Attack
1,"(A,B,5)","[n1,n2,n3,n4,n5,n6,n7]","[n4,n6]","[crash]"

# Combined timing + in-dark attack
2,"(C,D,3)","[n1,n2,n3,n5,n6,n7]","[n1,n3]","[time; dark(n2)]"

# Equivocation - leader sends conflicting orders
3,"(E,F,2)","[n1,n2,n3,n4,n5,n6,n7]","[n1]","[equivocation(n2,n3)]"
```

---

## Testing

### Test Input Format

Tests are provided as CSV files with five columns:

| Set | Transactions | Live | Byzantine | Attack |
|-----|--------------|------|-----------|--------|
| 1 | (A, C, 1) | [n1-n7] | [n4, n6] | [crash] |
| 1 | (G) | [n1-n7] | [n4, n6] | [crash] |
| 2 | (A, E, 6) | [n1-n7 except n4] | [n1, n3] | [time; dark(n2)] |

### Transaction Types

```
Transfer: (sender, receiver, amount)
  → Example: (A, B, 5) - Client A sends 5 units to Client B

Balance Query: (client)
  → Example: (G) - Read-only query for Client G's balance
  → Bypasses consensus, requires 2f+1 matching replies
```

### Debug Functions

```python
PrintLog(node_id)       # Display node's message log
PrintDB()               # Show all client balances  
PrintStatus(seq_num)    # Transaction status at each node (PP/P/C/E/X)
PrintView()             # All NEW-VIEW messages exchanged
```

### Status Labels

| Status | Meaning |
|--------|---------|
| **PP** | Pre-prepared (leader sent or backup received valid pre-prepare) |
| **P** | Prepared (received 2f matching prepare messages) |
| **C** | Committed (received 2f+1 matching commit messages) |
| **E** | Executed (transaction applied to state) |
| **X** | No Status |

---

## Implementation Details

### Quorum Requirements

- **Pre-prepare**: Leader broadcasts to all replicas
- **Prepare**: Requires `2f` matching messages (guarantees intra-view safety)
- **Commit**: Requires `2f+1` matching messages (guarantees cross-view safety)
- **Client Reply**: Requires `f+1` matching results
- **Read-only**: Requires `2f+1` matching replies

### View Change Protocol

```
1. Backup timer expires → Send VIEW-CHANGE to new leader
2. New leader collects 2f+1 VIEW-CHANGE messages
3. New leader computes O (set of PRE-PREPARE for pending requests)
4. New leader broadcasts NEW-VIEW message
5. Backups validate and accept new view
6. Normal operation resumes
```

### Cryptographic Security

- All messages are digitally signed
- Signatures verified before processing
- Invalid signatures trigger message rejection
- Keys managed in `keys.py`

---

## Transaction Processing

```
Initial Balance: All clients start with 10 units

Transfer Transaction: (A, B, 4)
  → Requires full PBFT consensus
  → A's balance: 10 - 4 = 6
  → B's balance: 10 + 4 = 14
  → Result: SUCCESS or FAILED (insufficient balance)

Balance Query: (A)
  → Read-only optimization
  → Multicast to all replicas
  → Wait for 2f+1 matching replies
  → Returns: Current balance
```

---

## Bonus Features

### Checkpointing (`checkpoint.py`)
- Periodic state snapshots every N requests
- Garbage collection of old protocol messages
- Recovery support for lagging replicas
- Checkpoint certificates in view-change messages

### Additional Optimizations Available
- Threshold signatures for constant-size certificates
- Optimistic phase reduction (SBFT-style fast path)
- SmallBank benchmark integration

---

## References

- Castro, M., & Liskov, B. (1999). *Practical Byzantine Fault Tolerance*. OSDI.
- Castro, M., & Liskov, B. (2002). *Practical Byzantine Fault Tolerance and Proactive Recovery*. TOCS.
- Gueta, G. G., et al. (2019). *SBFT: A Scalable Decentralized Trust Infrastructure*. DSN.

---

