# Marlin — Rejected


## Rejected

**L3 NAT.** Originally in scope; removed. It was the only mode that would have served
backends that cannot be configured, and that is the sole thing its removal costs. Against it:
it was the only stateful mode, and it accounted for roughly 22 of the 50 defects found in the
first review — including a destructive sweep primitive, a port-capacity miscalculation, and a
per-instance SNAT addressing scheme with an unresolved instance-loss hole. Removing it deleted
four maps, ~256 MB of memory, the reverse-path classifier, and every dependency on upstream
ECMP behaviour. Revisit only if a deployment presents unmodifiable backends.

**Half-NAT.** Would have required Marlin to be the backends' default gateway. Moot with NAT
gone.

**PROXY protocol.** Only relevant because NAT loses the client address. DSR preserves it
natively.

**Secondaries and second chance** (carry a secondary backend identifier in the encapsulation
header and have the primary forward what it does not recognise). It genuinely eliminates
LB-side flow state and makes drain non-disruptive. Rejected because it requires a component on
every backend and restricts the fleet to one non-active backend at a time — neither of which
VXLAN's addition changes. It was also only ever going to work for the modes with header room to
carry the secondary's identity: originally GUE alone; VXLAN's reserved header bytes could now
serve the same purpose, but L2 DSR and IPIP still have nowhere to carry one, so the mechanism
remains mode-specific rather than universal. Marlin serves backend fleets it does not control.

**A flow cache.** It would not deliver a guarantee: entries are lost to eviction, per-CPU
skew, CPU migration, and arrival at a different instance after an upstream rehash. It would
move a known `1/(N+1)` disruption to an unpredictable smaller one while converting the
datapath into a per-packet read-modify-write, coupling affinity to NIC queue configuration, and
making tests order-dependent. Since connection resets on scale-up are accepted, it buys nothing
required.

**Fallthrough to the next rendezvous candidate on backend down.** `docs/design/17-reconfiguration.md` — reintroduces a
cross-instance consistency requirement and is a secondary by another name.

**A `DRAINING` state with datapath meaning.** Requires distinguishing new from existing flows,
which requires per-flow state.

**More than one backend per `fwd_table` row.** Rows are a single `__u32`, and an ordered list
per row is only useful with a fallthrough or second-chance mechanism, both rejected.

**`ARRAY_OF_MAPS` for `fwd_table`.** `docs/design/07-maps.md` — buys atomic table swap at the cost of a second
lookup per packet, to prevent tearing that the write ordering and sentinel rule already make
harmless.

**A general-purpose C loader** was rejected for load-time map sizing, CO-RE and preflight:
compile-time sizing removed the sizing need, and `bpftool` covered the rest. Those grounds still
hold and do not apply to `data-plane/marlind/`, which exists for an unrelated reason: `bpftool link`
has no `create` verb and `bpftool net attach` is netlink-only, so making a `bpf_link` attachment
(which a resident process can hold, tying `systemctl status`'s truth to the kernel's) requires
libbpf code to exist somewhere. `data-plane/marlind/` is that code — it attaches, pins and holds the
link, and does not reintroduce load-time sizing or CO-RE. See `docs/design/02-architecture.md`.

**Load-time map sizing.** 26 MB of `fwd_table` regardless of VIP count, in exchange for
deleting map pre-creation, the `map name … pinned …` reuse mechanism and its pin-path collision
risk. A short attach sequence with no sizing logic of its own.

**IPv6 outer encapsulation.** Backends are on IPv4 networks. Fixing the outer family halves
the encapsulation paths, keeps `backend.addr` at 4 bytes rather than 16, removes the `ip6tnl`
cases, and eliminates the zero-UDPv6-checksum problem.

**L4 protocol and port matching in the ACL.** Removed from scope. Recorded in full because the
structure it requires is not obvious and would otherwise be rediscovered.

An LPM trie matches a contiguous bit prefix from bit 0, so a field is wildcardable only if it is
last. "`10.0.0.0/8` on TCP" needs the rest of the address wildcarded *and* the protocol matched —
a prefix cannot skip a hole — so an `[addr][proto][port]` layout can only express it by
enumerating every `/32` in the range. This is the documented root cause of Cilium issue #41121.

The working structure is fixed-width fields first, address last, one trie per specificity level:
`[addr]`, `[proto][addr]`, `[proto][port][addr]`, with stored `prefixlen` being the fixed-field
width plus the address prefix. Three tiers × two families × two lists is twelve maps, six
conditional lookups per packet, a per-tier non-empty bitmask to keep the common case affordable,
packed keys to keep alignment holes out of the compared bit string, and a fragment-shaped hole in
the port tier — non-first fragments carry no L4 header — that needs its own counter. It also moves
the ACL out of a header and into its own translation unit (`docs/design/03-translation-units.md`).

**One ACL trie per family with the verdict in the value.** Halves the map count; returns one
match, the most specific, which is longest-prefix-wins and contradicts `docs/design/27-source-filtering.md`'s allow-wins
precedence.

**IPv4 as `::ffff:a.b.c.d` in the IPv6 ACL tries.** Two maps instead of four, at 96 extra trie
levels on every IPv4 lookup — the common case.

**Matching the on-the-wire source rather than `packet_tuple.src`.** `docs/design/27-source-filtering.md`. It would let the ACL run
before L4 and IPv6 extension-header parsing, so a blocked source would not pay for the
extension-header walk — real if modest hardening, since that walk is bounded at `MAX_EXT_HDRS`
and already counted. Rejected because it requires `parser.c` to publish a second, wire-oriented
address before the tuple is built, and `docs/design/13-icmp.md` collapses the two orientations into one precisely so
that no stage after parsing needs an ICMP branch.

**A Count-Min sketch for per-source rates.** The technique of the P4 literature — Jaqen,
Patronum, INDDoS — where it exists because a switch ASIC cannot perform a general hash lookup per
packet. That constraint does not apply to a CPU running XDP, and `LRU_HASH` gives exact counts
with bounded memory.

**Sampling to a userspace decision daemon** — the Cloudflare `L4Drop`/`dosd`/`gatebot` and Meta
Droplet shape. Rejected in favour of same-packet enforcement. It remains the only way to detect a
distributed attack in which every source stays below its own threshold, and that blind spot is
accepted: userspace attack classification is a non-goal (`docs/design/01-scope.md`).

**An aggregate packets-per-second ceiling** as a backstop during detection latency. There is no
detection latency once enforcement is same-packet, and an aggregate ceiling cannot separate
attacker from victim — it would drop legitimate traffic exactly when the per-source limiter is
already working.

**`bpf_spin_lock` in the rate-limit bucket.** `docs/design/28-rate-limiting.md` — packing timestamp and tokens into one word
makes the question moot, and a lock would serialise precisely the CPUs contending an attacker's
bucket.

**Per-VIP rate buckets.** Multiplies the map by the VIP count and needs a composite key. The rate
a source may send at is a property of the source, so the extra granularity has no source of truth
behind it — the same argument as the per-VIP down-set above.

**Dropping non-first fragments to enforce a port-granular ACL tier on them.** Closes a hole that
does not exist under `docs/design/27-source-filtering.md`'s address-only matching, at the cost of breaking large UDP for every
source. Note this is the ACL case only; `docs/design/12-selection.md`'s `VIP_HASH_5TUPLE` does
drop fragments, per VIP and counted, because there the wider input buys something the ACL's
address-only matching does not need.

**A port-bearing selection hash with fragments falling back to the source address.** The
apparent way to widen the hash input without losing fragments, and the reason it is not: the
first fragment hashes one way and its siblings another, so one datagram is split across two
backends and never reassembles — silently, with no counter moving. Strictly worse than either
position `docs/design/12-selection.md` offers, since address-only keeps the datagram whole and
`VIP_HASH_5TUPLE` at least counts what it drops.

**Fragment tracking to reunite a datagram's fragments on one backend.** Would make a
port-bearing hash safe for fragmenting traffic. It is the flow cache of the entry above under
another name — a per-packet read-modify-write over evictable state — and inherits every
objection to it.

**Reseeding or reweighting to relieve a hot `fwd_table` row.** The reflex when `backend_stats`
shows one backend carrying a shared egress's whole population. Weights act per backend and
cannot target a row (`docs/design/12-selection.md`), and reseeding remaps every client on the
VIP while breaking the cross-instance agreement of `docs/design/21-active-active.md`. The row is
hot because of what the hash reads, so the hash input is the only lever.

**A `.bss` global for `acl_lists`.** `marlin_config` keeps every control-plane write on one
pinned-map path (`docs/design/02-architecture.md`). A `volatile const` global would let the verifier delete the branches
outright but requires a program reload per transition between empty and populated, which drops
connections (`docs/design/01-scope.md`).

**A `.data` global for the whole of `marlin_config`.** The reload objection above does not
transfer — it is specific to `volatile const` in `.rodata`, and a writable `.data` global is
updatable at runtime — so this was considered on its own terms and rejected on the other half of
the argument. It would give the datapath a direct memory read with no lookup and no `NULL`
check, but it puts control-plane writes on a second pinned path whose map name libbpf derives
(`marlin.data`), and it does not remove the need for a per-packet snapshot: reads still race the
writer, so each unit would end up copying to its stack anyway. That is the per-unit lookup
below, with a cheaper load.

**A `cfg` parameter threaded through the global subprograms.** `marlin_config` crosses the
translation unit boundary — `balancer.c` plus all three encapsulation units, for `tunnel_src` (`docs/design/14-forwarding-modes.md`)
— so the snapshot has to reach four units somehow. Passing it as an extra argument is legal:
struct pointer arguments have been available since 5.13 and the signatures stay inside the
five-register limit. It was rejected because it costs *the same stack* as carrying it on
`marlin_ctx` — the snapshot lives in the entry frame either way — while adding a parameter to
every global subprogram and to the static stage functions beneath them. `docs/design/04-calling-convention.md`'s output-parameter
convention exists for exactly this case; a second, parallel convention for the second thing that
crosses the boundary is a worse arrangement than extending the first.

**A `config` lookup per translation unit.** An `ARRAY` map consulted wherever a control value
is needed. Cheap in isolation — a bounds check and pointer arithmetic — and it
suits a program that is one translation unit of inlined helpers, which Marlin is not. Rejected
on two counts. It is *more* expensive against the combined stack budget than one snapshot,
because each unit's local copy occupies a frame that coexists with the others on the chain
(`xdp_marlin` → `marlin_balance()` → `marlin_gue_encapsulate()` would hold two copies where the entry
frame holds one). And it reopens the cross-generation read: two units could observe
`marlin_config` either side of a control-plane write within one packet, which would have to be
re-argued field by field rather than closed once.

**Probing the backend's own address for health checks.** `docs/design/18-health.md` — it avoids the martian problem but
cannot detect a wrong VIP-on-loopback or missing ARP/NDP suppression, because the probe never
carries the VIP. Isolating the prober in a VRF keeps the detection instead.
