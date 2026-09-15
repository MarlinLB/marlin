# Marlin — QUIC Connection-ID Steering


## Problem

A QUIC connection is not defined by its 4-tuple. A client that changes address —
Wi-Fi→cellular, VPN flap, CGNAT reassignment — keeps the same connection but presents a new
tuple, so a hash-based selection (`docs/design/12-selection.md`) sends it to a different
backend and the connection dies. The default hash input, the client address alone, already
survives a NAT port rebind — the more common cause of tuple churn — so the residual problem is
address migration specifically, not the 5-tuple in general.

`VIP_QUIC` (`vip_meta.flags`, `docs/design/08-types.md`) steers a migrated packet to the
backend that was already serving the connection, by decoding a `backend_id` the backend itself
embedded in the connection ID it issued.

## Why no stateless, non-cooperative variant exists

The first thing anyone proposes is hashing the connection ID directly, with no backend
involvement. It fails before migration is even relevant.

**The DCID a client sends changes once, mid-handshake.** RFC 9000 §7.2: the client's first
Initial packet carries "an unpredictable value" it invents; upon receiving the server's first
packet, the client switches to the Source Connection ID the *server* chose, for every
subsequent packet. `hash(DCID)` therefore sends the Initial to one backend and the Handshake to
another — every connection, immediately, independent of migration.

**Migration adds a second, independent failure.** RFC 9000 §9.5 requires an endpoint not to
reuse a connection ID when sending from more than one local address, precisely so an on-path
observer cannot correlate the two paths. Marlin is that observer. No packet ever carries both
the pre- and post-migration connection ID — that is what the requirement means — so no amount
of learned state can bridge one to the other, and Marlin is DSR and never sees
`NEW_CONNECTION_ID` frames in any case.

**Conclusion: the only value stable across a connection's connection IDs is one the server put
there deliberately.** Routability and RFC 9000 §9.5's unlinkability guarantee are the same
property with opposite signs; nothing can be discovered, only volunteered by the party that
knows a given connection ID belongs to a given connection. This is the same conclusion
draft-ietf-quic-load-balancers reached, and the same contract Katran has with mvfst (see Prior
art, below).

## The routing rule

**Long-header packets route by hash. Short-header packets route by connection ID.**

RFC 9000 §9: an endpoint "MUST NOT initiate connection migration before the handshake is
confirmed". The entire long-header phase — Initial, 0-RTT, Handshake, Retry — therefore happens
within one flight on one 4-tuple, where the existing hash already gives the right answer.
Migration only affects 1-RTT traffic, which is short-header only.

Three things fall out:

- **No version parsing.** Long-header packet-type codepoints are version-specific — QUIC v2
  (RFC 9369) remaps Initial and 0-RTT relative to v1 — and RFC 8999 does not pin them across
  versions. Not interpreting them at all avoids a wire-format dependency this project has
  nowhere to track (`docs/design/29-versions.md` covers kernel and toolchain versions only —
  Marlin's own build version, `data-plane/include/marlin/build.h`, tracks neither and is not a
  substitute).
- **No Initial/0-RTT special case.** Katran needs one, because it steers long headers; this
  design does not. This is a correctness requirement, not only simplicity: a client's Initial
  DCID is client-invented, so a false accept in the check field (below) would repeat
  deterministically on retransmission — the client resends the same DCID — and would kill that
  connection attempt outright rather than merely misrouting one packet.
- **Retry is handled for free.** The post-Retry Initial is same-flight, same tuple.

The residual gap: a NAT rebind *during* the handshake moves the tuple. Under the
address-only hash default the row does not move, so it is harmless; under `VIP_HASH_5TUPLE` it
breaks, exactly as it would for TCP.

## Wire format

Plaintext is not viable and AES is unavailable: the kernel floor is 6.0
(`docs/design/01-scope.md`) and `bpf_crypto_*` kfuncs arrived in 6.7, so
draft-ietf-quic-load-balancers' single-pass and four-pass algorithms are out of reach. The
datapath already needs SipHash for row selection (`docs/design/12-selection.md`), so the format
is built on that.

```
CID byte 0    bits 7-6   config generation, reserved -- MUST be 0
              bits 5-0   check, keyed over the entropy bytes
CID bytes 1-2            backend_id, obfuscated
CID bytes 3..n           server-chosen entropy, >= 4 bytes
```

```
mask       = siphash(cid[3..len], hash_key, domain = QUIC)
backend_id = be16(cid[1..2]) ^ (mask & 0xffff)
check      = (mask >> 16) & 0x3f
```

**Byte layout of the SipHash input.** `marlin_siphash()` requires a compile-time-constant length
in whole 8-byte blocks (`data-plane/include/marlin/siphash.h:108-114`), and the entropy field's
length varies with the configured connection-ID length (4-17 bytes, `VIP_QUIC_CID_LEN`). The
formula above is computed over a fixed 24-byte buffer, not the entropy bytes at their actual
length:

```
buffer offset 0        domain tag, MARLIN_QUIC_SIPHASH_DOMAIN (0x51)
buffer offsets 1-17     entropy, left-aligned, zero-padded past the configured length
buffer offsets 18-23    zero
```

hashed whole with `hash_key` regardless of the configured length — the trailing zeroes are part
of the digest. A backend generating connection IDs must reproduce this padding exactly, or the
check field never verifies against it. `data-plane/bpf/balancer.c`'s `struct marlin_quic_input`
is this layout.

Minimum connection-ID length **7**. A short header does not carry its DCID length on the wire
(RFC 8999 §4.2 — "not encoded in packets with a short header and is not constrained by this
specification"), so the length is per-VIP configuration (`VIP_QUIC_CID_LEN`,
`docs/design/08-types.md`).

**Why obfuscated rather than plaintext.** A plaintext `backend_id` is not merely an
enumeration leak — it is a targeting primitive. Any client could address a chosen backend
directly and bypass load balancing entirely. One SipHash per steered packet removes it.

**Why a check field.** Without it, a non-cooperating backend's random connection ID decodes to
a plausible-looking `backend_id` essentially always, and its connections would be *misrouted*
rather than falling back to the hash path. Six bits gives a 1/64 false-accept rate against an
uncooperative connection ID, which is what makes backend-by-backend rollout safe
(`DEPLOYMENT.md` §1.7.2).

**Key reuse.** `vip_meta.hash_key` is already a per-VIP 128-bit secret with the cross-instance
agreement discipline this needs (`docs/design/21-active-active.md`). Reusing it, with a
domain-separation tag in the SipHash input, costs no ABI and adds no fourth must-match value
beyond what §"ABI" below already adds. A distinct `quic_key` was considered and rejected here on
those grounds; see Open decisions.

## ABI: zero struct growth

`vip_meta` stays 24 bytes and `marlin_config` is untouched.

- `VIP_QUIC` is `vip_meta.flags` bit 3.
- The configured connection-ID length is `vip_meta.flags` bits 8–12 (`VIP_QUIC_CID_LEN_MASK`,
  `VIP_QUIC_CID_LEN_SHIFT`, `docs/design/08-types.md`) — five bits, values 7–20, 0 meaning
  unset.
- `VIP_FLAGS_RESERVED` and its `_Static_assert` (`data-plane/include/marlin/abi/defines.h`)
  cover both additions.

`marlin_ctx` stays 104 bytes. `MARLIN_CTX_F_QUIC` is `marlin_ctx.flags` bit 3, of which bits
3–31 were free (`data-plane/include/marlin/marlin.h`). No stack-budget decision is required,
and `docs/design/05-budgets.md`'s stated admission test for a shared field — read in a unit
other than the one that writes it — is satisfied: the flag is written by `parser.c` and read by
`balancer.c`.

## How the two halves divide

**Classification is `parser.c`'s.** `marlin_parse_quic()` reads the first UDP-payload byte once
a UDP header is present and sets `MARLIN_CTX_F_QUIC` when the QUIC header-form bit
(RFC 8999 §4.1) is clear. It never fails on its own; a packet too short to classify, or on a
protocol other than UDP, simply carries no flag. `parser.c` reads no map and calls no `bpf_*`
helper either way, so the property `data-plane/tests/parser_test.c`'s native tier depends on
(`docs/design/24-testing.md`) is unaffected.

**Steering is `balancer.c`'s**, because it reads `vip_map`, which `parser.c` has no access to:

- Gate on `VIP_QUIC`, so the step follows the VIP lookup (`docs/design/11-pipeline.md`).
- Bounds-check the connection ID against the configured length, decode per the formula above,
  and index `backends[]` directly — bypassing `fwd_table` for the packets it steers
  (`docs/design/12-selection.md`).
- Fall through to the hash path on every failure: check mismatch, `backend_id == 0` or
  `>= MAX_BACKENDS`, or a row that is down or unpopulated. **No new drop reason** — a QUIC
  packet Marlin cannot steer is handled as any other packet is.
- Two `MARLIN_COUNT_*` counters, `quic_cid_routed` and `quic_cid_check_failed`
  (`docs/design/22-observability.md`). The remaining fall-through paths are uncounted, for the
  reason that document gives.

**Distribution is the control plane's:** `backend_id`, `hash_key` and the connection-ID length
to each backend's QUIC server, and the rotation story (`DEPLOYMENT.md` §1.7.2).

## Decided rather than left open

The check field width (6 bits) and the reuse of `vip_meta.hash_key` rather than a distinct
`quic_key` (see Wire format, above) are settled by this document and by the ABI reservation
already made (`docs/design/08-types.md`), not deferred choices — `CLAUDE.md`'s rule against
re-litigating a closed decision applies to both.

**A connection ID naming a backend that is not `MARLIN_UP` falls through to hash**, as does one
naming a row the control plane has not populated — an ARRAY row reads as a zeroed `struct
backend`, so the `MARLIN_BE_F_STATE` test covers a retired `backend_id` as well as a drained
one. Dropping instead would turn a drain into connection resets, where falling through costs
only the migration affinity that the drain was already ending. The check is in
`balancer.c`'s `marlin_balancer_select_backend()`, before the `MARLIN_COUNT_QUIC_CID_ROUTED`
counter, so the counter records packets actually steered rather than connection IDs
successfully decoded.

The fall-through is uncounted. `enum marlin_ret` carries `MARLIN_COUNT_QUIC_CID_ROUTED` and
`MARLIN_COUNT_QUIC_CID_CHECK_FAILED` and no others, so a decoded connection ID losing to a down
or unpopulated row is visible only as `backend_stats` moving to the hash-selected backend.

## Open decisions

Each belongs in `docs/PHASES.md`'s open-decision table, carried at the line it affects.

| Decision | Options | Phase |
|---|---|---|
| Whether `VIP_QUIC` and `VIP_HASH_5TUPLE` may coexist, or configuration validation rejects the combination | Independent by construction (the routing rule above), but a VIP whose QUIC survives migration and whose other UDP does not is hard to reason about operationally | 3 (`docs/design/20-configuration-validation.md`) |

**Config-generation rotation is not an open decision requiring a phase.** The two reserved bits
exist so a future mechanism has somewhere to live, but nothing today generates or checks a
second key, and generation MUST be 0 until a rotation requirement is real — matching
`docs/PHASES.md`'s "Not phased" precedent for a mechanism deferred rather than blocking.

## Prior art

Meta's Katran gates a connection-ID decode on a `QUIC_VIP` flag, paired with mvfst — Meta's own
QUIC implementation — which generates Katran-compatible connection IDs by default, encoding a
host/worker/process identifier. `docs/design/12-selection.md`'s Prior art section already names
`QUIC_VIP` among Katran's hash-narrowing flags; this document adopts the connection-ID-routing
half of the same mechanism, on the same backend-cooperation terms.

draft-ietf-quic-load-balancers (QUIC-LB) specifies the general problem this design narrows:
config-rotation bits, a server-ID/nonce connection-ID split, and three algorithms of increasing
cost (plaintext, four-pass, single-pass AES). Marlin implements only the plaintext-equivalent
shape, obfuscated with SipHash rather than left bare, and does not implement QUIC-LB's
stateful fallback chain (4-tuple+SCID, then DCID, then 4-tuple) — that fallback is the flow
cache `docs/design/25-rejected.md` rejects, and is additionally unsound here: a migrated packet
may arrive at a *different* Marlin instance under upstream ECMP rehash
(`docs/design/21-active-active.md`), where no learned table exists.

GitHub's GLB carries routing information in a similar spirit via a primary/secondary backend
pair in the encapsulation header; `docs/design/25-rejected.md` rejects that mechanism for
Marlin on grounds — a component required on every backend, and no header room under two of the
four forwarding modes — that only partly transfer to `VIP_QUIC`: the connection ID lives in the
payload, so it needs no header room and works identically under all four modes, but it still
requires cooperation from software Marlin does not control. `docs/design/01-scope.md` already
requires every backend to be configurable for DSR's sake; `VIP_QUIC` is the first requirement
that reaches into the backend's *application* software rather than its host or network stack —
a distinction this document draws rather than one available to cite.
