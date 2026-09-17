# Marlin — Backend Selection


## Algorithm

Weighted rendezvous hashing, precomputed by the control plane into `fwd_table`. Per packet:

```
hash_input = vip_meta.flags & VIP_HASH_5TUPLE ? packet_tuple : client_address
row        = siphash(hash_input, vip_meta.hash_key) % TABLE_SIZE
backend_id = fwd_table[vip_num * TABLE_SIZE + row]
backend    = backends[backend_id]
```

The default input is `client_address`; `VIP_HASH_5TUPLE` widens it per VIP, at the cost of
dropping that VIP's fragments — see "Hash input" below.

Table generation, per VIP, in the control plane. For each row:

1. `row_seed = siphash(row_index, table_seed)`
2. For each member backend `b`: `u = normalise(siphash(row_seed, b.addr, b.vni, b.inner_mac))`,
   then `score = u^(1/w_b)`
3. The row takes the backend with the highest score.

**Hash input: `addr`, `vni` and `inner_mac` together, not `addr` alone.** VXLAN's VNI exists
precisely so that distinct backends may sit behind one VTEP address — the same `addr`
disambiguated by which overlay network, and which inner host, it answers for. Once VXLAN
backends can share `addr`, `addr` alone stops being a unique per-backend discriminator in the
score: two backends that score identically in every row leave the row's winner to the
generator's iteration order rather than to the algorithm, which both misweights the combined
share those backends were assigned and breaks the relative-order invariant above — that any two
backends hold the same relative order in a row regardless of which others are present — on which
`docs/design/17-reconfiguration.md`'s non-disruptive-removal guarantee rests. Hashing the full
identity restores a unique input per backend without a configuration rule forbidding duplicate
addresses; the wider hash input is the whole fix.

**Every instance generates its own table.** The configuration store holds the per-VIP
`table_seed` and the member set; each control plane reads them and generates `fwd_table`
locally. Generated tables are not distributed. This makes `table_seed` a value that must
match across instances exactly as `hash_key` must — see `docs/design/21-active-active.md` — because the generation is
deterministic in the seed, the member set and the hash input above, and nothing else. The hash
input is now part of that determinism too: every instance must run generation logic that hashes
the same fields, or two instances score the same VIP differently from identical `table_seed` and
member-set inputs. `docs/design/21-active-active.md` documents `hash_key`/`table_seed` agreement
specifically and does not yet name this; it is the same class of cross-instance divergence,
reached by a control-plane version skew rather than a configuration mismatch, and is noted here
rather than asserted there.

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

## Hash input: client address by default, the whole tuple by opt-in

The default is the client address alone. Non-first IP fragments carry no L4 header, so hashing
ports would send them to a different backend than the first fragment — in steady state, with no
reconfiguration involved. The client address is present in every fragment.

**This is an argument about the hash input, not about admission.** `vip_map` lookup
(`docs/design/11-pipeline.md`) is keyed on the parsed destination port, which a fragment tail
never has; address-only hashing gives a tail the same row as its head only once the tail has
already resolved to the same `vip_num`. On a VIP configured with an explicit port and no
`port == 0` companion, it does not: the tail is `vip_miss`. On an explicit-port VIP that has
such a companion, the tail resolves to the companion's `vip_num`, not the head's — the same
split into two backends that "Why there is no third option" below rejects as a hash input,
reached instead through admission. Client-address hashing removes the fragment problem from
row selection; it does not remove it from VIP lookup.

The lookup key's protocol field can diverge the same way, and no `port == 0` companion recovers
it: an IPv6 head and tail agree on `tuple.proto` only when nothing sits between the Fragment
header and the upper-layer protocol (`docs/design/11-pipeline.md`). Where something does, the
parser refuses both halves as `unsupported_proto` rather than let admission split them on a
mismatched protocol the way it already can on a mismatched port.

The cost is that clients sharing a source address share a row, and therefore a backend: CGNAT,
large proxy egresses, and VPN concentrators, where one address stands for a whole client
population. The skew is observable directly in `backend_stats`
(`docs/design/22-observability.md`).

Where that population dominates a VIP's traffic the default is not merely skewed, it is
inoperative — a VIP reached only through one VPN egress has every client on one backend, and the
fleet is effectively N=1 however many backends are configured. `VIP_HASH_5TUPLE`
(`docs/design/08-types.md`) exists for that case: set on a VIP, row selection hashes the whole
`packet_tuple` — source address, source port, VIP, service port, protocol — instead of the
source address alone.

**A flagged VIP drops every fragment**, first and non-first alike, counted as
`frag_unsupported`. This is what makes the flag admissible: the objection to hashing ports is
not the loss of fragmenting traffic but that the loss is *silent*, and a counted drop is not
silent. Dropping both halves rather than the non-first half alone loses the datagram either way
and spares the backend reassembly state it could never complete.

The trade is therefore stated plainly rather than hidden: the flag is correct on a VIP whose
traffic does not fragment — TCP with MSS clamping, in practice — and is a loss of function on
one whose traffic does. No validation can tell the two apart, so nothing rejects the mistake and
only the counter reveals it (`DEPLOYMENT.md`).

### Why there is no third option, among hash inputs

Any hash input richer than what appears in *every* fragment must either drop fragments or split
them, and nothing without per-flow state can do otherwise. That closes the design space to the
two positions above, for a hash-based input:

- **Hashing ports with fragments falling back to the address** splits one datagram across two
  backends silently — strictly worse than either position, and rejected in
  `docs/design/25-rejected.md`.
- **Reuniting fragments** requires tracking them, which is the rejected flow cache under
  another name (`docs/design/25-rejected.md`).
- **Reseeding or reweighting to cool a hot row** does not address it: weights act per backend,
  not per row, and reseeding remaps every client on the VIP while breaking the cross-instance
  agreement `docs/design/21-active-active.md` requires.

**A QUIC connection ID is a third selection input, and it is not a hash input at all.**
`VIP_QUIC` (`docs/design/30-quic.md`) steers short-header packets by decoding a `backend_id`
the *server* embedded in the connection ID, bypassing `siphash(...) % TABLE_SIZE` and
`fwd_table` for the packets it steers. It survives client address migration, which no hash
input can: RFC 9000 §9.5 requires the connection ID to change whenever the client does, so
nothing observable in a migrated packet is both constant across the connection and
discriminating between connections. It is admitted on a different ground than the two
positions above — not because it solves the fragment problem, but because the backend
cooperates in generating the value. That cooperation is the actual cost; see
`docs/design/30-quic.md` and `docs/design/25-rejected.md`.

### Prior art

Meta's Katran hashes the 5-tuple by default and narrows it per VIP through the same kind of flag
— `HASH_NO_SRC_PORT` for protocols needing address affinity, `HASH_DPORT_ONLY`, `QUIC_VIP` — and
affords the wider input by not forwarding fragmented packets on its fast path at all. Marlin's
default is the inverse, because a load balancer that silently breaks large UDP is a worse
default than one that distributes shared egresses poorly, but the mechanism and its fragment
cost are the same. GitHub's GLB hashes packet data with a primary/secondary pair, which requires
the secondary mechanism `docs/design/25-rejected.md` rejects.

**Katran's `QUIC_VIP` is not only a hash-narrowing flag.** It also gates a connection-ID decode
paired with mvfst, Meta's own QUIC implementation, emitting Katran-format connection IDs by
default. `docs/design/30-quic.md` adopts that half of the mechanism as `VIP_QUIC`, on the same
backend-cooperation terms Katran requires.

`VIP_HASH_5TUPLE` is hash input, so every instance serving the VIP must set it identically
(`docs/design/21-active-active.md`). It does not affect table generation: it selects a row, and
the table's contents are unchanged.

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

`fwd_table` rows hold IDs, so reusing an ID for a different backend identity — `addr`, `vni` or
`inner_mac`, any of which the score now hashes — makes stale rows point silently at the wrong
backend. IDs are retired, not promptly reused: the control plane
allocates from unused slots and does not recycle a retired slot within the same
reconfiguration cycle. Index 0 is never allocated (`docs/design/10-map-invariants.md`).

The ID is now recorded in the value as well as being the key (`struct backend.id`,
`docs/design/08-types.md`), and it is the retire-don't-recycle rule above that keeps the two
consistent across a reconfiguration cycle: reusing a retired slot's index for a different backend
before it is safe to do so would leave stale `fwd_table` rows pointing at a `backends[id]` whose
own `id` still matches, masking exactly the staleness this lifecycle rule exists to prevent.
