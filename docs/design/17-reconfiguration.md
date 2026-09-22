# Marlin — Reconfiguration, Failure and Drain


## Backend state

`backend.flags` bit `MARLIN_BE_F_STATE` is set for `MARLIN_UP`, clear for `MARLIN_DOWN`.
`MARLIN_UP` is non-zero so a zeroed slot reads as not-UP (`docs/design/10-map-invariants.md`).
State changes are a single `backends[id]` write and take effect across every VIP the backend
serves simultaneously.

A per-VIP down-set was considered, allowing a backend to be down for one VIP and up for
another. Rejected: the control plane health-checks backends rather than per-VIP endpoints, so
the extra granularity has no source of truth behind it, and it would add a lookup to the hot
path.

**There is no `DRAINING` state.** Graceful drain of existing connections is not achievable
without per-flow state: keeping a backend for existing flows while diverting new ones requires
the datapath to distinguish them, and diverting new flows elsewhere reintroduces the
cross-instance consistency problem that drop-on-down avoids. Draining, if operators want the
concept, is control-plane metadata with no datapath meaning. See `docs/design/25-rejected.md`.

## In-place `backends` updates

`bpf_map_update_elem()` on an `ARRAY` copies the whole 32-byte value and is **not** atomic
against a concurrent datapath read, so a reader may observe a torn value.

This is harmless, but not for a reason to do with alignment. Only `flags` (its state and FIB
bits) and `egress_ifindex` ever change at runtime, and the control plane writes the full struct
with every other field carrying its existing value. A torn read therefore observes either the
old or the new value of those, with every other field correct — because those bytes were
rewritten with the values they already held.

`egress_ifindex` is mutable because topology is: a bond failover or a re-cabling changes which
interface reaches a backend without changing the backend. It tolerates tearing better than the
others — it is advisory (`docs/design/16-fib-lookup.md`), 4-byte aligned at offset 16 so it cannot straddle a word, and the
worst a stale read produces is a spurious `egress_mismatch`, never a misdirected frame. The
`flags` bit beside it is the one that matters: `MARLIN_BE_F_FIB` and `egress_ifindex` should be
updated in the same read-modify-write, since a topology change usually moves both.

**The invariant is a control-plane one, not a layout one.** Every in-place update must be a
read-modify-write of the complete struct. Constructing a partial `struct backend` and writing it
would corrupt `addr`, `mac`, `encap_dport`, `vni` or `inner_mac` in a way that a torn read could
expose.

`addr`, `mac`, `encap_dport`, `vni`, `inner_mac`, `id` and the mode bits of `flags` are never
modified in place; changing any of them is a removal followed by an addition under a new backend
ID. `id` introduces no new rule here — changing a backend's ID is already a removal followed by
an addition, so this makes an existing one apply to one more field.

## `vip_map` held live in `lb_core.c`

`marlin_lb_process()` keeps the `bpf_map_lookup_elem()` result from `vip_map` as a
`const struct vip_meta *` for the rest of the packet's processing, rather than copying it onto
the stack — the copy cost a 24-byte struct plus the register pressure it added around the
SipHash unrolls that follow, on a 512-byte combined budget (`docs/design/05-budgets.md`).

`hash_key` is established once at VIP creation and never rewritten at reconcile time
(`docs/design/10-map-invariants.md`), so holding a pointer to it changes nothing. `flags` is
mutable at runtime and is read at several points across one packet's processing (ACL
enforcement, rate-limit gating, the fragment check, 5-tuple selection); a control-plane write to
that VIP concurrent with those reads may be observed at some of them and not others. This is the
same class of exposure the `backends` section above already accepts for `flags` and
`egress_ifindex` — a live field may be read mid-update — extended from `backends` (`ARRAY`) to
`vip_map` (`HASH`). The previous stack-copy was not a point-in-time snapshot either: `*out =
*meta` is itself a non-atomic multi-word copy racing the same concurrent write.

## Rows pointing at a down backend drop

They do not fall through to the next candidate in the rendezvous order. Falling through would
be failover, which is attractive, but it reintroduces a consistency requirement: under
active/active, one instance believing a backend is down while another believes it is up would
send the same connection to two different backends. Dropping means instances may disagree
about health harmlessly. Any fallthrough scheme is a secondary by another name (`docs/design/25-rejected.md`).

## The removal/addition asymmetry

| Event | Rows changed | Connections affected |
|---|---|---|
| Backend fails (marked DOWN) | **none** | only its own, which are lost regardless |
| Backend recovers (marked UP) | **none** | none |
| Backend removed from a VIP | rows where it won | only its own |
| **Backend added to a VIP** | ~`1/(N+1)` of rows | **live connections on healthy backends** |

Failure and recovery change no rows at all — they are a single `backends[id]` state write, and
the rows continue to point at the same backend. That is why both are zero-disruption.

Removal is free for other backends because a rendezvous maximum over a set does not change
when a non-maximal member is deleted. The rows that change are exactly those whose connections
were already lost.

Addition is not free. **Accepted:** approximately `1/(N+1)` of established connections reset
when a backend is added, on the basis that clients reconnect immediately. At 75 backends that
is ~1.3%.

Reserving rows for backends that do not exist yet does not help: those rows would either drop
their share of traffic while waiting, or require a fallthrough whose connections break when the
real backend arrives. Fixed-set reservation covers failure and recovery — which the state flag
already covers at zero cost — not capacity growth.

Scenarios where "clients reconnect immediately" does not hold, and which should therefore avoid
scale-up under load: long-lived sessions with expensive re-establishment, connections
mid-TLS-handshake or mid-upload where the client surfaces a hard error rather than retrying, and
non-idempotent requests in flight.

## Mode changes

A backend's mode (the low bits of `flags`) is never edited in place. Changing it is a removal
followed by an addition under a new backend ID. Editing in place would switch live flows to a
different encapsulation mid-connection, and would violate the single-8-byte-word invariant above.

## Table regeneration

Per `docs/design/12-selection.md`'s write ordering. Regeneration is per VIP; other VIPs' blocks are untouched.

**Widening the score's hash input is a one-time exception to that scoping.** VXLAN's rendezvous
score hashes `addr`, `vni` and `inner_mac` together (`docs/design/12-selection.md`); a control
plane upgrading from a version that hashed `addr` alone recomputes a different score for every
row of every existing VIP, not just VXLAN ones, because the hash input changed for the whole
algorithm rather than per backend. This is a single full-fleet regeneration performed once at
upgrade, following the write ordering above per VIP as it is applied — not a new steady-state
behaviour, and not a per-packet cost.
