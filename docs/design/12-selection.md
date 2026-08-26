# Marlin — Backend Selection


## Algorithm

Weighted rendezvous hashing, precomputed by the control plane into `fwd_table`. Per packet:

```
row        = siphash(client_address, vip_meta.hash_key) % TABLE_SIZE
backend_id = fwd_table[vip_num * TABLE_SIZE + row]
backend    = backends[backend_id]
```

Table generation, per VIP, in the control plane. For each row:

1. `row_seed = siphash(row_index, table_seed)`
2. For each member backend `b`: `u = normalise(siphash(row_seed, b.address))`, then
   `score = u^(1/w_b)`
3. The row takes the backend with the highest score.

**Every instance generates its own table.** The configuration store holds the per-VIP
`table_seed` and the member set; each control plane reads them and generates `fwd_table`
locally. Generated tables are not distributed. This makes `table_seed` a value that must
match across instances exactly as `hash_key` must — see `docs/design/21-active-active.md` — because the generation is
deterministic in the seed and the member set, and nothing else.

The alternative, having one designated writer generate and distribute the table itself, was
considered and not taken: it removes the seed-matching requirement but introduces a
distribution path and a writer whose loss stalls reconfiguration, in exchange for a
requirement that two configuration values agree.

The **weighted** score is required, not row repetition. `u^(1/w)` preserves the property
that any two backends hold the same relative order in a row regardless of which others are
present, and that invariant is what makes removal non-disruptive (`docs/design/17-reconfiguration.md`). Assigning extra rows
to a backend by repetition would break it, and with it the removal guarantee.

## Why rendezvous, and why precomputed

Rendezvous hashing is optimal on disruption: adding a backend moves approximately
`1/(N+1)` of rows — an expected value over 65536 rows, not an exact figure — and moves them
only *to* the newcomer. No row moves between two pre-existing backends. Evaluating it per
packet is O(N) and not viable at line rate, so the result is materialised into a table and
the datapath does one array read.

## Why the table is not simply `backends[hash % N]`

`fwd_table` is not a lookup optimisation layered on top of `backends`. It *is* the consistent
hash, memoised. Removing it means modulo:

| | `backends[h % N]` | `backends[fwd_table[h % 65536]]` |
|---|---|---|
| Remove a backend (10 → 9) | ~90% of clients remap | ~10%, only the removed backend's rows |
| Add a backend (9 → 10) | ~90% remap | ~10% |
| Weighted backends | unexpressible | weighted score |
| Client → row mapping | divisor changes with N | constant |
| Datapath cost | one array read | two array reads |

Under modulo, removing one backend breaks connections on every *other* backend, because the
divisor changed for all of them. The failure behaviour described in `docs/design/17-reconfiguration.md`
depends entirely on the table existing.

Because the divisor is a constant 65536 rather than N, a client always maps to the same
*row* however the fleet changes; only what the row points at can move. Disruption analysis is
therefore about row reassignment, never about remapping the key space.

## Hash input: client address only

Not the 5-tuple. Non-first IP fragments carry no L4 header, so a 5-tuple hash would send them
to a different backend than the first fragment — in steady state, with no reconfiguration
involved. The client address is present in every fragment.

The cost is poorer distribution behind CGNAT and large proxy egresses, where many clients
share a source address. It is accepted rather than made configurable: the skew is observable
directly in `backend_stats` (`docs/design/22-observability.md`), whereas a 5-tuple option's failure mode — non-first fragments
landing on the wrong backend — is silent. `vip_meta.flags` defines no bit for it (`docs/design/08-types.md`).

## Weights

Expressed in the score at generation time. Nothing in the datapath changes; the weight is
never present in a map.

## Write ordering and tearing

A flat `fwd_table` is regenerated row by row, so it is momentarily part old and part new.
Every individual row remains valid provided writes are ordered:

- **Adding a backend:** write `backends[id]` **before** any row references it.
- **Removing a backend:** rewrite all referencing rows to 0 **before** zeroing
  `backends[id]`.

This ordering guarantees no row ever references an unpopulated slot. It says nothing about
the atomicity of a `backends[id]` value update, which userspace performs as a multi-word
copy — see `docs/design/17-reconfiguration.md`.

## Backend ID lifecycle

`fwd_table` rows hold IDs, so reusing an ID for a different address makes stale rows point
silently at the wrong backend. IDs are retired, not promptly reused: the control plane
allocates from unused slots and does not recycle a retired slot within the same
reconfiguration cycle. Index 0 is never allocated (`docs/design/10-map-invariants.md`).
