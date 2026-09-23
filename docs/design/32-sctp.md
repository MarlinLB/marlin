# Marlin — SCTP


## What is forwarded, and what is read

SCTP (RFC 9260) is forwarded like TCP and UDP: `parser.c` reads the first four bytes of its
common header — source port, destination port, the same word `marlin_l4_ports` already
overlays for TCP and UDP (`docs/design/08-types.md`) — and nothing else. No checksum work is
needed in any of the four modes: SCTP's CRC32c (RFC 9260 §6.8) covers the whole packet including
the common header, with no IP pseudo-header folded in, so changing the outer IP addresses under
IPIP, GUE or VXLAN never invalidates it. `docs/design/14-forwarding-modes.md`'s "inner headers
are never modified" already covers this; SCTP adds no exception.

**No per-flow state is added.** Marlin's core property — output is a function of the packet and
map contents, nothing else (`docs/design/01-scope.md`, `docs/PHASES.md`) — holds for SCTP exactly
as it does for TCP and UDP. `VIP_HASH_PORTS` and address groups, both below, are stateless: they
change what a VIP's `vip_meta` or `vip_map` keys look like, not what the datapath remembers
between packets.

An ICMP error quoting an SCTP packet is steered the same way a quoted TCP or UDP packet is
(`docs/design/13-icmp.md`): `parser.c`'s embedded-header parse reads the same four-byte port
word from the quote and recovers the tuple. SCTP validates a quoted ICMP error using the
verification tag in the quoted header (RFC 9260 §10), which needs the same 4 bytes past the
common header's ports that Marlin's own threshold already requires for TCP/UDP quotes
(`docs/design/13-icmp.md`'s destination-port threshold), so nothing about SCTP's own validation
is weakened by what Marlin forwards.

## The multi-homing problem

SCTP's headline feature relative to TCP/UDP is multi-homing: an association can span several
addresses per endpoint. Both directions interact badly with hash-based selection.

**The failure mode is the same in both directions.** A backend has no association for a packet
that reaches it by mistake, so RFC 9260 §8.4 rule 8 has it reply with an ABORT that reflects the
verification tag with the T bit set. The client accepts a tag-reflecting ABORT (§8.5.1 B) and
removes the whole association (§9.1) — not just the misrouted path. One wrong row kills every
path of the association, including the ones that were routing correctly.

**Client side.** A Linux client whose server is bound to a single VIP keeps exactly one
transport and one cached source address for the whole association — HEARTBEAT-ACKs included
(verified against Linux v6.12: `net/sctp/sm_make_chunk.c` sets a reply's transport from the
chunk it answers, and `net/sctp/protocol.c`'s `sctp_v4_get_dst()` caches the source address per
transport). That cached source changes only when the client's own route to the VIP changes —
client-side failover, not steady-state multi-homing. Under the default address hash, the new
source address hashes to a different row, and the association is gone: this is exactly TCP's
contract (the client's address is what a connection is defined by), applied to an association
that would otherwise have survived the failover.

**Server side.** A backend bound to several VIPs advertises every one of them in its INIT-ACK's
address parameters (RFC 9260 §3.3.2.1), and the client sends HEARTBEATs to each one starting at
ESTABLISHED (§5.4), typically within a few round-trip times. If those VIPs hash to different
rows — because they are different `vip_map` keys with independently-generated tables — the
first HEARTBEAT to the second VIP reaches a backend with no association for it, and the whole
association is aborted, usually before the operator has finished configuring the second VIP.

## Three per-VIP modes

| Mode | Distribution | Client failover | Server multi-homing | Fragments |
|---|---|---|---|---|
| Address hash (default) | by client address | lost (TCP's contract) | same-family group, single-source clients | forwarded |
| `VIP_HASH_5TUPLE` | by 5-tuple | lost | rejected on a group | dropped |
| `VIP_HASH_PORTS` | by source port | survives on every instance | any group, mixed family included | dropped |

**`VIP_HASH_PORTS`** (`vip_meta.flags` bit 4) hashes only the port pair — `tuple.sport` and
`tuple.dport`, padded into a zeroed `struct marlin_ports_input` for `marlin_siphash()`'s
multiple-of-8 length contract (`data-plane/include/marlin/siphash.h`) — with no address and no
family. An SCTP endpoint keeps one port for the life of an association (RFC 9260 §3.1), on every
path and in both families for a dual-stack client, so the port pair is the one selection input
that is stable across everything client-side failover and server-side multi-homing can do to the
address. The cost is `docs/design/12-selection.md`'s general one for any input richer than
"present in every fragment": a flagged VIP drops every fragment, counted `frag_unsupported`,
exactly as `VIP_HASH_5TUPLE` already does. It is SCTP-only and mutually exclusive with
`VIP_HASH_5TUPLE` (`data-plane/marlind/conf_check.c`).

**The residual gap.** Peers that share a fixed source port collapse onto one backend under
`VIP_HASH_PORTS`, the same skew the address hash gives CGNAT populations
(`docs/design/12-selection.md`). A VIP is chosen per protocol-and-port, so a fixed-port
population and an ephemeral-port population cannot both get the address hash's distribution and
the ports hash's failover survival on the *same* VIP; splitting them across two VIPs is the only
stateless answer this design has.

## Address groups

An address group is one VIP entity — one `hash_key`, one `table_seed`, one member list, one set
of flags — spanning several addresses, each its own `vip_map` key, all sharing one `vip_num`,
one `fwd_table` block and one `vip_stats` counter. This is what makes server-side multi-homing
safe: every address a multi-homed backend advertises resolves through the same table, so no
HEARTBEAT to a group address can land on a backend the association never reached.

**Groups are not SCTP-specific in the map ABI** — `struct vip_key` and `struct vip_meta` are
unchanged, and nothing in `types.h` grows. They are `marlind`'s (and, in Phase 3, the C# control
plane's) accounting: `data-plane/include/marlind/conf.h`'s `struct conf_vip` holds `keys[]` and
`key_count` rather than a single key, and `data-plane/include/marlind/vip_alloc.h`'s allocator
assigns one `vip_num` per entry regardless of how many addresses it holds.

**Why a group must be one entity rather than several single-address VIPs given identical
`hash_key`/`table_seed`/members.** Nothing stops an operator from doing that today, and two such
VIPs already route identically — `docs/design/12-selection.md`'s table generation is a
deterministic function of `table_seed` and the member set, nothing else. What a group buys over
that is that the two addresses *cannot* disagree: identical twins cost two `fwd_table` blocks and
two `vip_stats` counters, and nothing checks that a later edit to one twin's `hash_key` or
members is mirrored to the other. One entity makes disagreement a type error, not an operator
discipline.

**Validation** (`data-plane/marlind/conf_check.c`, `check_vip_group()`), on an SCTP group only
— `docs/design/20-configuration-validation.md`:

- `VIP_HASH_5TUPLE` is rejected on a group: it hashes the VIP address, which a group exists
  precisely to make interchangeable.
- A group mixing IPv4 and IPv6 addresses must set `VIP_HASH_PORTS`: the address hash picks a
  different row per family by construction (`packet_tuple.family` sits in the hashed bytes),
  so a dual-stack backend's association would fail exactly the way an unrelated pair of VIPs
  would.
- A single-family group on the address hash is accepted, with a warning: it is safe only for a
  client that reaches every group address from one source address, and nothing in the file
  format can verify that a deployment's clients do.

**Allocation.** `vip_alloc()` (`data-plane/marlind/vip_alloc.c`) is a pure function over plain
arrays, deliberately independent of `marlind/conf.h` the way `fwd_gen.c` is
(`docs/REPO-STRUCTURE.md`), so it links and tests without libbpf. An entry claims the first
baseline `vip_num` any of its own addresses already holds, in address order, skipping a value an
earlier entry already claimed; the entries this matters for:

- **Adding an address to an existing group** inherits the group's block through whichever
  address survived.
- **Removing an address from a group** does not release the block: the surviving address still
  claims it.
- **Merging two previously-separate VIPs into one group** keeps one of their two blocks and
  releases the other.
- **Splitting a group into two entries** lets whichever entry is processed first keep the
  shared block; the other takes a fresh one.

`reconcile.c` writes every entry's `fwd_table` block and every one of its `vip_map` keys before
zeroing any released block (`docs/design/31-file-configuration.md`'s block-before-key ordering,
extended to groups) — a block a surviving key still references is never observed zeroed, and a
block released by a merge or a split is zeroed only once nothing points at it any more.

## Rejected: stateful and cooperative alternatives

Every one of these would have protected more of the multi-homing surface than the two stateless
mechanisms above. All are rejected on the same grounds `docs/design/25-rejected.md` already
gives the flow cache: they buy affinity at the cost of the property that makes Marlin's tests,
its active/active story and its restart behaviour simple.

**Learning client addresses from INIT** (record a client's other addresses from INIT's address
parameters, route them like the primary). INIT carries no secret: an attacker sends one INIT per
source port from their own real address, listing a victim's address in the parameter list, and
misroutes — kills — that victim's association without ever spoofing anything BCP38 would catch.

**Verification-tag pinning** (learn the server's tag from a client's COOKIE ECHO, steer later
packets carrying it regardless of source address). This is the flow cache
(`docs/design/25-rejected.md`) narrowed to one protocol, and it fails the same argument
`docs/design/30-quic.md` already makes about its own stateful alternative: "a migrated packet
may arrive at a *different* Marlin instance under upstream ECMP rehash... where no learned table
exists." With M active/active instances and C the chance two client addresses hash to the same
backend (`docs/design/12-selection.md`'s skew constant), a pin protects a failover with
probability `1/M + (1 − 1/M)·C` — full protection only at M = 1, and no better than the address
hash's baseline `C` once M grows. It also turns the accepted, scheduled `1/(N+1)` scale-up reset
(`docs/design/17-reconfiguration.md`) into an unscheduled one every time a pin is evicted or an
instance restarts.

**Replicating pins across instances.** Everything wrong with pinning, plus a distribution path
between instances and a race window between a COOKIE ECHO and the first replicated read — a
packet arriving in that window takes the un-pinned hash path and ABORTs the association anyway.

**Backend-encoded verification tags** (the `VIP_QUIC` pattern: have the backend embed routing
information in a value Marlin already reads). SCTP's verification tag is the candidate, and it
fails on the mechanism itself, not merely on cost: Linux generates it with `get_random_u32()`
(`net/sctp/sm_make_chunk.c`'s `sctp_generate_tag()`) and offers no socket option, sysctl or hook
to influence it, so cooperation would need a kernel patch on every backend rather than an
application-level change as `VIP_QUIC` needs of mvfst. It also runs into an active patent
(US11973822B2) covering exactly this construction. `docs/design/30-quic.md`'s backend-cooperation
terms are not available here.

## Prior art

No stateless DSR load balancer fully supports SCTP multi-homing; this document's two mechanisms
are the stateless maximum, not a gap relative to prior art.

- **Meta's Katran and GitHub's GLB** forward no SCTP at all: Katran's protocol switch handles
  only TCP and UDP, falling through to `XDP_PASS` for anything else, and GLB's protocol
  configuration accepts only `"tcp"`/`"udp"`.
- **Cilium** added SCTP support in 1.13 but lists multi-homing as explicitly unsupported, along
  with any port rewrite — its kube-proxy replacement requires the target port to equal the
  service port for the same reason DSR does: neither can translate ports.
- **loxilb** supports SCTP multi-homing only in its stateful fullNAT mode, rewriting the address
  lists inside INIT and INIT-ACK and tracking one conntrack entry per path, synced across cluster
  nodes on a five-second async ticker. Its own documentation states plainly that its DSR mode
  "can't support multihoming features since different 5-tuples might belong to the same
  connection" — the same conclusion this document reaches, from the same DSR constraint.
  Marlin does not adopt fullNAT: `docs/design/25-rejected.md`'s reasons against NAT (a
  stateful mode, an SNAT addressing scheme, dependence on upstream ECMP behaviour) apply to
  loxilb's mechanism as much as to Marlin's own rejected NAT mode.
- **Linux IPVS** schedules a new connection only on INIT and (with `sloppy_sctp`) on any packet;
  either way each path is an independent 5-tuple with no cross-path awareness, so a client
  failover works only by accident of hashing to the same real server twice.
  Netfilter conntrack's SCTP tracker is the one prior-art system with anything like a group: it
  learns secondary paths from HEARTBEAT and tracks the tag, which is a smaller version of the
  rejected pinning mechanism above, with the same active/active weakness.
- **Nordix nfqlb**, a stateless DSR balancer, hashes SCTP on the port pair for exactly this
  document's reason: "the addresses... are different for the paths but the ports are always the
  same." `VIP_HASH_PORTS` is the same mechanism, and `docs/design/12-selection.md`'s Katran
  `HASH_DPORT_ONLY` flag is the same idea applied to TCP/UDP server-port affinity rather than
  SCTP path stability.

## Open decisions

Each belongs in `docs/PHASES.md`'s open-decision table, carried at the line it affects.

| Decision | Options | Phase |
|---|---|---|
| The SCTP health-probe protocol, and which group address a probe targets | `docs/design/18-health.md` specifies no probe protocol for any VIP today; an SCTP-specific answer (probe association, or fall back to a TCP/ICMP proxy check) is needed before Phase 3's health checking covers SCTP VIPs | 3 |
