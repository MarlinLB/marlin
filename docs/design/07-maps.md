# Marlin — Maps


## Map inventory

| Map | BPF type | Key | Value | Entries |
|---|---|---|---|---|
| `vip_map` | `HASH` | `struct vip_key` | `struct vip_meta` | `MAX_VIPS` |
| `fwd_table` | `ARRAY` | `__u32` | `__u32` | `MAX_VIPS × TABLE_SIZE` |
| `backends` | `ARRAY` | `__u32` | `struct backend` | `MAX_BACKENDS` |
| `config` | `ARRAY` | `__u32` | `struct marlin_config` | 1 |
| `tx_ports` | `DEVMAP_HASH` | `__u32` (ifindex) | `__u32` (ifindex) | `MAX_TX_PORTS` |
| `acl_allow_v4` | `LPM_TRIE` | `struct acl_key4` | `__u32` (rule id) | `MAX_ACL_ENTRIES` |
| `acl_block_v4` | `LPM_TRIE` | `struct acl_key4` | `__u32` (rule id) | `MAX_ACL_ENTRIES` |
| `acl_allow_v6` | `LPM_TRIE` | `struct acl_key6` | `__u32` (rule id) | `MAX_ACL_ENTRIES` |
| `acl_block_v6` | `LPM_TRIE` | `struct acl_key6` | `__u32` (rule id) | `MAX_ACL_ENTRIES` |
| `ratelimit` | `LRU_HASH` | `struct rl_key` | `struct rl_bucket` | `MAX_RL_ENTRIES` |
| `vip_stats` | `PERCPU_ARRAY` | `__u32` | `struct stats` | `MAX_VIPS` |
| `backend_stats` | `PERCPU_ARRAY` | `__u32` | `struct stats` | `MAX_BACKENDS` |
| `drop_stats` | `PERCPU_ARRAY` | `__u32` | `__u64` | `DROP_REASON_MAX` |

All created from BTF declarations at load. No map is pre-created.

## Map type rationale

**`vip_map` = HASH.** VIPs are sparse and matched exactly, so the key is not a dense
integer. Not LPM — CIDR VIPs are out of scope. Preallocated; at 100 entries
`BPF_F_NO_PREALLOC` would only add cost.

**`fwd_table` = ARRAY.** The key is a dense computed index. Hashing it would mean hashing a
value already derived from a hash, and this is the hottest read in the program.

`ARRAY_OF_MAPS` — one inner array per VIP — was considered because it would allow a
regenerated table to be swapped atomically. Rejected: it adds a second lookup to every
packet, and the tearing it prevents is harmless under `docs/design/12-selection.md`'s write
ordering and `docs/design/10-map-invariants.md`'s sentinel rule.

**`backends` = ARRAY.** `backend_id` is a dense integer namespace allocated by the control
plane, and the array slot *is* the backend's identity.

**None of the three are per-CPU.** All are read-only in the datapath. Per-CPU variants would
multiply memory and complicate control-plane writes for no benefit.

**ACL maps = LPM_TRIE.** Prefix matching is the requirement; a hash map would need one entry
per address in a range. All four carry `BPF_F_NO_PREALLOC`, which the type requires, so an
empty list allocates nothing. A binary trie with N leaves also holds up to N−1 internal nodes,
so allocation scales with roughly twice the rule count. `docs/design/27-source-filtering.md` covers why allow and block are
separate maps and why the families are not merged.

**`ratelimit` = LRU_HASH.** Eviction at capacity is what bounds memory against a
high-cardinality source flood — the same mechanism and reasoning as Katran's connection table.
Both families share one map, since hash lookup cost does not scale with key size the way trie
depth does.
