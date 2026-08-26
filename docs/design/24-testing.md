# Marlin — Test Strategy


## Packet-level tests from phase 0

`bpf_prog_test_run` with crafted packets, asserting exact output bytes. Built first, not last.

This is affordable because of a deliberate design property: **Marlin holds no per-flow state**,
so output depends only on the packet and on map contents. Tests are deterministic and
order-independent. Statistics counters are written but do not affect forwarding, so they can be
asserted separately or ignored. Preserving this property is one of the reasons a flow cache was
rejected (`docs/design/25-rejected.md`).

Coverage: every mode, both inner families, IPv6-inner over IPv4-outer, malformed and truncated
headers, fragments in both families, IPv6 extension-header chains — including one at
`MAX_EXT_HDRS` and one beyond it — ICMP errors including the embedded-header path,
port-agnostic VIPs, the sentinel and down-backend paths, and the header-adjustment paths where
pointer invalidation bites.

**The `NO_NEIGH` fallback fires only on its exact conditions.** Five cases against one flagged
L2 DSR backend with a stored MAC and no neighbour entry: on-link route, FIB returns the ingress
interface → emit on the stored MAC, count `neigh_fallback`; on-link but FIB returns another
interface → drop `fib_no_neigh`, no frame; **gatewayed route, FIB returns the ingress interface
→ drop, no frame** — the case that separates a correct implementation from one that blackholes
whenever a router's neighbour entry expires; the on-link ingress case again with an all-zero MAC
→ drop; the same missing neighbour under IPIP → drop. Assert the emitted frame's source MAC is
Marlin's ingress MAC in the first case — the fallback does not have `fib.smac` and must not be
reading one.

**`NO_NEIGH` drops on every path but that one.** L2 DSR with an all-zero `backend.mac` and no neighbour for
`backend.addr` must drop and count `fib_no_neigh`, and so must an encapsulation backend taking
the FIB path with no neighbour for the outer next hop. Assert that neither emits a frame: a
regression here reintroduces the `XDP_PASS` the datapath carried until `docs/design/16-fib-lookup.md`'s argument was
completed.

**The FIB fallback asks about the backend, not the VIP.** L2 DSR with an all-zero
`backend.mac`, a populated `backend.addr` and a neighbour entry for that address must emit a
frame carrying that neighbour's MAC — not one resolved from the VIP. A separate case with both
fields zero must drop and count `backend_unresolved` rather than reaching the helper at all.
Both are cheap and they are what pin `docs/design/15-nexthop-l2dsr.md`'s lookup destination.

**`MARLIN_BE_F_FIB` beats a resolved MAC.** An L2 DSR backend carrying the flag *and* a non-zero
`backend.mac` must take the FIB path. Assert the emitted frame's source MAC is the egress
interface's, not the ingress one — that is the property the ordering exists for, and testing
only the destination MAC would pass with the branches reversed. Pair it with the unflagged case
on the same backend, which must `XDP_TX` on the stored MAC without touching the helper.

**L2 DSR refuses a gatewayed next hop.** A backend whose `addr` is reachable only via a router
must drop and count `fib_gatewayed`, with no frame emitted. The same route under IPIP must
forward normally — the mode split is the whole content of the check, so a test that exercises
one mode proves nothing. The route in question is the reachable-but-wrong case, so it is
constructed rather than a misconfiguration: a host route via a gateway on an attached segment.

**`egress_mismatch` counts without changing the verdict.** A backend whose `egress_ifindex` names
an interface the FIB does not choose, where that interface *is* in `tx_ports`, must still emit
the frame on the FIB's interface with the counter incremented. Assert both halves: a test that
only checks the counter would pass an implementation that dropped, which is the failure mode `docs/design/16-fib-lookup.md`
rejects. A second case with the FIB's interface absent from `tx_ports` must increment
`egress_mismatch` *and* drop `no_tx_port` — the counter is not a claim that the frame left.

**The ACL preserves this property and needs no exemption.** `marlin_acl()` is a pure function of
`packet_tuple.src` and map contents. Coverage: block and allow matched and missed in both
families; longest-prefix selection, a `/32` block inside a `/8` and a `/24` inside a `/8`; allow
beating block at every relative specificity including a `/8` allow over a `/32` block;
empty-list skipping, since clearing an `acl_lists` bit must stop enforcement; non-first fragments
filtered identically to first fragments, which is the assertion that the fragment hole a
port-granular design would have had does not exist; an ICMP error whose embedded client is
blocked dropped while one whose transit router is blocked is not (`docs/design/27-source-filtering.md`); and `sizeof` on both key
structs, 8 and 20, since a layout change alters what the trie compares.

**One of those assertions is about placement, not semantics, and is the one worth naming.** A
blocked source addressed to a destination that is *not* a VIP must drop with `acl_blocked`, not
pass with `vip_miss`. That is the whole of `docs/design/11-pipeline.md`'s host-firewall property and `docs/design/27-source-filtering.md`'s lockout
argument, it is invisible to every test above — each of which uses a configured VIP — and it
fails silently if step 3 is ever moved after step 4. The other half of the placement, that an
allow verdict survives the VIP lookup, is already covered below by "an allowlisted source at any
rate is never `ratelimited`".

**The rate limiter does not, and is off by default.** A token bucket is time-dependent and its
result depends on preceding packets, which violates order-independence — one of the reasons a
flow cache was rejected (`docs/design/25-rejected.md`). `CFG_RL_ENABLE` defaults off so all coverage above stays
deterministic. Its own regime: seed `ratelimit` with a known `state` word and assert one
update's arithmetic — refill, clamp to `rl_burst`, the sub-one-token drop, the timestamp wrap
clamp, and a tick delta large enough that the refill product would overflow 32 bits; exhaust a
bucket across successive invocations asserting bounds rather than exact token counts; insert
beyond `MAX_RL_ENTRIES` distinct sources and assert capacity holds with no failed insertion; and
an allowlisted source at any rate is never `ratelimited`.

**Concurrency is out of reach of `bpf_prog_test_run`**, which is single-threaded. The
compare-and-swap loop's contention behaviour and `rl_cas_exhausted` need the integration
environment below with concurrent senders across multiple receive queues.

## Integration tests

Network namespaces and veth pairs with real tunnel devices on simulated backends. Validates
what packet tests cannot: that a real kernel FOU/GUE listener and `ipip`/`sit` device accept
what Marlin emits, including the zero UDP checksum.

## Deliberately harder

- **`backend.mac` freshness** depends on netlink event handling in the control plane, which
  needs its own tests against neighbour churn.
- **Verifier limits** are a build-time property. CI should fail on a load failure and track
  reported complexity as a regression signal, since it degrades gradually as code is added.
- **Table regeneration under traffic** needs a test that asserts no packet is ever forwarded
  using a row that references an unpopulated slot.
