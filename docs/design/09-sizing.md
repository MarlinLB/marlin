# Marlin — Constants and Memory

## Constants

| Constant | Value |
|---|---|
| `MAX_EXT_HDRS` | 8 |
| `TABLE_SIZE` | 65536 |
| `MAX_VIPS` | 100 |
| `MAX_BACKENDS` | 4096 |
| `MAX_TX_PORTS` | 64 |
| `MAX_ACL_ENTRIES` | 65536 |
| `MAX_RL_ENTRIES` | 262144 |
| `RL_CAS_RETRIES` | 4 |
| `RL_TOKEN_SHIFT` | 8 |
| `RL_TICK_SHIFT` | 20 |
| `DROP_REASON_MAX` | 48 |

`tx_ports` is a **`DEVMAP_HASH` keyed by kernel ifindex**, so the ifindex `bpf_fib_lookup()`
returns is the redirect key directly.

A plain `DEVMAP` is a dense array whose keys are bounded by `max_entries`, and a host
interface index may exceed 64, so it would have required a control-plane-assigned slot per
egress interface, a stored ifindex→slot mapping, and a reverse lookup on every redirected
packet. `DEVMAP_HASH` exists for sparse ifindex ranges and removes all three, along with the
bidirectional invariant the control plane would have had to maintain between the slot table
and the devmap. `MAX_TX_PORTS` is a capacity bound here, not an index space.

`bpf_redirect_map()` with flags 0 returns `XDP_ABORTED` when the key is absent, so an egress
device the control plane has not added is a countable drop rather than a silent one.
Deployments where every backend is reachable out the ingress interface never touch this map,
since `XDP_TX` needs no devmap.

## Memory

| Map | Size |
|---|---|
| `fwd_table` (100 × 65536 × 4 B) | 26 MB |
| `ratelimit` (262144 × 28 B of key and value) | 7.3 MB, plus per-element allocator and bucket overhead |
| `backends` (4096 × 32 B) | 128 KB |
| ACL tries | proportional to populated rules; nothing when empty |
| everything else | negligible |

`ratelimit`'s overhead beyond key and value bytes is allocator-dependent and has not been
measured; no total is stated for it and none should be quoted operationally until it is.
`MAX_RL_ENTRIES` was chosen so the addition is of the same order as `fwd_table` rather than a
multiple of it.

Approximately 26 MB of `fwd_table`, preallocated at load, independent of how many VIPs are
configured. Compile-time sizing was chosen over load-time sizing deliberately: it removes
map pre-creation, the `map name … pinned …` reuse mechanism and its pin-path collision risk,
reducing the load script to two commands. 26 MB is not worth that machinery.
