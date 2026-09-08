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

**`VIP_HASH_5TUPLE` doubles the selection regime rather than replacing it**
(`docs/design/12-selection.md`). The determinism above makes each assertion exact:

- With the flag clear, two packets differing only in source port select the same backend. With
  it set, the row is a function of the whole tuple — asserted as "the flag changes the selected
  row for some tuple", not as a distribution claim, which 65536 rows cannot support in a
  single-packet harness.
- With the flag set, a first fragment and a non-first fragment both drop `frag_unsupported`. The
  first-fragment half is the assertion that `MARLIN_CTX_F_FRAG_FIRST` is actually produced by
  `parser.c` — the failure it guards is a first fragment forwarded and reassembly state stranded,
  which no other test would notice.
- With the flag clear, both fragments still forward, and to the same backend as an unfragmented
  packet of the same flow. This is the existing guarantee, and it must not move.
- An ICMP error on a flagged VIP selects the same row as the flow it reports on. This fails
  unless `parser.c` recovers the embedded destination port into `tuple.sport`
  (`docs/design/13-icmp.md`), and it is the only test that catches that omission.
- `tuple.pad` non-zero changes the selected row on a flagged VIP and does not on an unflagged
  one — the assertion behind `docs/design/10-map-invariants.md`'s zeroing rule for a struct that
  is hashed whole rather than used as a map key.

**`VIP_QUIC` steers a flagged short-header packet by connection ID instead of the hash, once
`balancer.c` exists** (`docs/design/30-quic.md`). `parser.c`'s classification is native-unit-tested
today (`data-plane/tests/parser_test.c`); the assertions below are packet-level and register as
`MARLIN_SKIP` placeholders (`docs/PHASES.md`) until the steering step lands:

- Two packets with the same connection ID and different source addresses select the same
  backend — the migration assertion, and the whole point of the feature.
- The same two packets on a VIP without `VIP_QUIC` select by hash and may therefore differ —
  proving the flag is what does it.
- A connection ID whose check field fails, or whose decoded `backend_id` is 0, `>= MAX_BACKENDS`,
  or not `MARLIN_UP`, falls through to the hash path and counts — never an out-of-bounds
  `backends[]` read.
- A non-QUIC UDP packet and a long-header QUIC packet on a `VIP_QUIC` VIP both route by hash,
  unchanged.
- An ICMP error on a `VIP_QUIC` VIP routes by hash: an embedded header carries at most 8 bytes of
  L4 (`data-plane/include/marlin/proto.h`) and never a connection ID. A known gap, asserted
  rather than fixed.
- A fragmented UDP datagram on a `VIP_QUIC` VIP routes by hash. QUIC's 1200-byte floor and
  DPLPMTUD keep it unfragmented in practice (`docs/design/23-mtu.md`), but the path must be
  explicit.

**The `NO_NEIGH` fallback fires only on its exact conditions.** Five cases against one flagged
L2 DSR backend with a stored MAC and no neighbour entry: on-link route, FIB returns the ingress
interface → emit on the stored MAC, count `neigh_fallback`; on-link but FIB returns another
interface → drop `fib_no_neigh`, no frame; **gatewayed route, FIB returns the ingress interface
→ drop, no frame** — the case that separates a correct implementation from one that blackholes
whenever a router's neighbour entry expires; the on-link ingress case again with an all-zero MAC
→ drop; the same missing neighbour under IPIP → drop. `docs/design/16-fib-lookup.md`'s FIB
handling does not vary by mode, so this one case stands for GUE and VXLAN as well — exercising
it under all three would assert the same code path three times. Assert the emitted frame's
source MAC is
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
must drop and count `fib_gatewayed`, with no frame emitted. The same route under IPIP, GUE or
VXLAN must forward normally — the mode split is the whole content of the check, so a test that
exercises one mode proves nothing. The route in question is the reachable-but-wrong case, so it
is constructed rather than a misconfiguration: a host route via a gateway on an attached segment.

**`egress_mismatch` counts without changing the verdict.** A backend whose `egress_ifindex` names
an interface the FIB does not choose, where that interface *is* in `tx_ports`, must still emit
the frame on the FIB's interface with the counter incremented. Assert both halves: a test that
only checks the counter would pass an implementation that dropped, which is the failure mode `docs/design/16-fib-lookup.md`
rejects. A second case with the FIB's interface absent from `tx_ports` must increment
`egress_mismatch` *and* count `no_tx_port` — an `XDP_ABORTED` verdict, not `XDP_DROP`
(`docs/PHASES.md`'s Phase 2b exit criterion 4), so that a redirect to an unregistered interface
is distinguishable from every other drop reason. The counter is not a claim that the frame left.

**The ACL preserves this property and needs no exemption.** `marlin_acl_check()` is a pure function of
`packet_tuple.src` and map contents. Coverage, split across two tiers (see "Native unit tests"
below): the verdict matrix runs at both — block and allow matched and missed in both families;
longest-prefix selection, a `/32` block inside a `/8` and a `/24` inside a `/8`; allow beating
block at every relative specificity including a `/8` allow over a `/32` block; empty-list
skipping, since clearing an `acl_lists` bit must stop enforcement; and `sizeof` on both key
structs, 8 and 20, since a layout change alters what the trie compares. Four assertions are
native-tier-only, because the packet tier cannot observe them from the XDP verdict alone: that a
cleared `acl_lists` bit *skips* the lookup rather than merely tolerating a miss; that an allow hit
returns `MARLIN_ACL_ALLOW` and not `MARLIN_ACL_NONE` — indistinguishable by verdict until the rate
limiter exists; that the lookup key is presented at full width (32/128 bits) with the address
copied verbatim out of `tuple.src`; and that a NULL `mctx` returns `MARLIN_ACL_ABORT` on the
branch the verifier proves unreachable, which `main.c` maps to `MARLIN_ABORT_NULLREF`
(`docs/design/04-calling-convention.md`). Packet-tier-only, because `marlin_acl_check()` reads nothing outside
`tuple.src` and `tuple.family` and these are properties of `parser.c` and `main.c`'s step
ordering instead: non-first fragments filtered identically to first fragments, which is the
assertion that the fragment hole a port-granular design would have had does not exist; an ICMP
error whose embedded client is blocked dropped while one whose transit router is blocked is not
(`docs/design/27-source-filtering.md`); and the placement assertion below.

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

## Native unit tests

A second mechanism, alongside `bpf_prog_test_run` above: `data-plane/tests/` compiles a
`src/*.c` file with the host toolchain — no `-target bpf` — and `#include`s it directly to call
its `static` helpers with real pointers. `parser.c` qualifies trivially: it makes no `bpf_*`
helper call and reads no map, so its behaviour cannot depend on which target compiled it. `acl.c`
qualifies through `data-plane/tests/stubs/`, which shadows libbpf's `<bpf/bpf_helpers.h>` — whose
helpers are function-pointer literals holding helper ids, `(void *)1` for `bpf_map_lookup_elem`,
so calling one natively jumps to address 1 — and answers the helper out of a host longest-prefix
scan keyed by the map object's address.

A map-reading translation unit is soundly native-testable when three things hold. First, every
helper it calls is answered by the stub; `acl.c` calls exactly one. Second, the stubbed map's
semantics are a pure function of the arguments — no time, no per-CPU state, no eviction; four
`BPF_F_NO_PREALLOC` LPM tries queried and never written satisfy this. Third, some other tier
exercises the same map semantics against the real kernel, which `data-plane/tests/packet/` does.

The same three conditions generalise to a translation unit that calls a packet-adjusting helper
instead of reading a map: every helper it calls is answered by a stub that reproduces the
helper's real bounds contract; that contract is a pure function of the arguments and the frame
bounds, not of time or per-CPU state; and some other tier exercises the same helper against the
real kernel. `ipip.c` satisfies this shape — see below.

The cost is that such a case asserts two things at once: that `acl.c` queries the right map with
the right key, and that the stub's longest-match scan agrees with the kernel's trie. Only the
first is what the tier is for. The second is bounded by rule: every prefix-arithmetic case in
`data-plane/tests/acl_test.c` has a named counterpart in `data-plane/tests/packet/xdp_test.c`, and
a native case with no counterpart asserts only lookup bookkeeping — which map, how many times,
with what key — never a prefix outcome. `ipip.c` carries the equivalent rule: every case in
`data-plane/tests/ipip_test.c` that duplicates a `tests/packet/xdp_test.c` assertion names its
counterpart, and a native case with none asserts only what the packet tier cannot observe — an
`mctx` write-back, a NULL argument, a headroom failure, or a helper call count.

`main.c` and `nexthop.c` still do not qualify: they write maps and call `bpf_redirect_map`,
`bpf_fib_lookup` and `bpf_ktime_get_ns`, `ratelimit` is an LRU whose eviction is not a function of
the arguments, and the stats maps are per-CPU. `ipip.c` does qualify — its only helper is
`bpf_xdp_adjust_head` (`data-plane/tests/stubs/xdp_stub.h`), and it reads no map. `gue.c` and
`vxlan.c` are still placeholders (a NULL check and `return MARLIN_OK`) with nothing to test yet.

The NULL-argument abort convention (`docs/design/04-calling-convention.md`) is native-tier-only
for the same reason as the ACL case above: a global subprogram's BTF struct-pointer argument is
non-NULL by verifier contract, so `bpf_prog_test_run` can never drive the branch, and calling the
`static` function directly on the host is the only way to. `parser_test.c` asserts it once for
each of `marlin_parse()`'s two parameters; `data-plane/tests/nexthop_test.c` does the same for
`marlin_nexthop_l2dsr()` and `marlin_nexthop_encapsulate()`, four cases in total. `nexthop_test.c`
does not make `nexthop.c` a qualifying translation unit under the three-part test above — its
FIB fallback and redirect path stay real-kernel-only, per `main.c` above — the file exists solely
for the two branches that return before either helper is reached.

What it buys over the packet-level harness: the `static` helpers (`marlin_parse_frag6`,
`marlin_walk_ext6`, `marlin_parse_icmp`, …) are otherwise unreachable except through
`marlin_parse`'s one entry point, so a bug confined to one helper's boundary condition — an IPv6
extension-header chain at exactly `MAX_EXT_HDRS`, a fragment header truncated to 3 of its 8 bytes —
is exercised directly rather than inferred from `marlin_parse`'s return value. It also runs in
milliseconds with no root privilege and no kernel involved, so it is the tier a change to
`parser.c` should be checked against first.

What it cannot do: assert an emitted frame, a map write, or anything downstream of
`marlin_parse` — that stays with `bpf_prog_test_run`, which is the only tier that runs the code as
compiled for the datapath. The map stub answers reads only; the packet-adjusting stub
(`data-plane/tests/stubs/xdp_stub.h`) is the one exception, answering `bpf_xdp_adjust_head()`.
`make tests` (not part of `make all`; part of `make ci`) builds and runs one binary per test
file — `data-plane/tests/csum_test.c`, `data-plane/tests/mtu_test.c`,
`data-plane/tests/entropy_test.c`, `data-plane/tests/parser_test.c`, `data-plane/tests/acl_test.c`,
`data-plane/tests/nexthop_test.c` and `data-plane/tests/ipip_test.c` today; `docs/PHASES.md`
tracks which translation units the mechanism covers as more are added.

This is also why a sub-`ETH_HLEN` truncation case cannot move to the packet-level harness: the
kernel's XDP `BPF_PROG_TEST_RUN` path rejects `data_size_in` below `ETH_HLEN` (14 bytes) before
the program ever runs, so `parser_test.c`'s 13-byte Ethernet truncation case is native-tier-only
by construction, not by choice.

`data-plane/tests/packet/` (`docs/REPO-STRUCTURE.md` §7.2) is the packet-level harness above,
made concrete: it loads the real `marlin.bpf.o` and drives `xdp_main` through
`bpf_prog_test_run_opts`, asserting `data_out` for the exact-byte half of this document's opening
sentence. Coverage there is bounded by what `xdp_main` can satisfy before Phase 2's VIP lookup
and forwarding land — parse verdicts, `drop_stats` deltas, and that a passing frame is not
mutated — plus, for `nexthop.c` specifically, the `bpf_fib_lookup()` matrix above under real FIB
state (`data-plane/tests/packet/fib.h`), reached through `main.c`'s interim
`xdp_interim_nexthop()` pending `balancer.c`. What still needs the VIP lookup, the rate limiter,
or an encapsulation mode not yet written is registered as a `MARLIN_SKIP` placeholder
(`docs/PHASES.md`) that reports as a named `skip` line rather than as a pass, so a green run is
never mistaken for complete coverage.

Passing `ctx_in` to `bpf_prog_test_run_opts` for an XDP program carries two kernel-enforced
obligations easy to miss and silent to get wrong: `ctx->data_end` must equal `data_size_in`
exactly, and a non-zero `ingress_ifindex` is only accepted for an interface with registered XDP
rxq info — most cases in this tier pass `0` and rely on the loopback binding described below, since
they need no FIB state. `data-plane/tests/packet/fib.h` is the exception: it builds veth pairs
inside the same unshared namespace and attaches a two-instruction `XDP_PASS` anchor to register
rxq info on them, giving `nexthop.c`'s `bpf_fib_lookup()` cases a real device and real routes —
this is the packet tier extended with FIB state, not the netns/veth integration tier below, which
still owns the real-device assertions of Phase 2b exit criterion 2 (a real kernel FOU/GUE
listener, a real `ipip`/`sit` device, a real `vxlan` device). Getting either obligation wrong
fails every case identically with `-EINVAL` before `xdp_main` ever runs, which reads as a wall of
unrelated assertion failures rather than the one setup bug it is.

A zero `ingress_ifindex` in `ctx_in` is not the same as the program observing `ctx->ingress_ifindex
== 0`: the kernel leaves the run bound to the calling process's network namespace's loopback
device in that case, and the verifier rewrites `ctx->ingress_ifindex` to that device's ifindex —
1, not 0. The packet-level harness `unshare(CLONE_NEWNET)`s before loading the program so that
ifindex, and what `bpf_fib_lookup()` makes of it, do not depend on the host's own routing table or
`net.ipv4.ip_forward`.

## Integration tests

Network namespaces and veth pairs with real tunnel devices on simulated backends. Validates
what packet tests cannot: that a real kernel FOU/GUE listener, a real `ipip`/`sit` device, and a
real `vxlan` device accept what Marlin emits, including the zero UDP checksum.

**VXLAN-specific assertions,** alongside the packet-level coverage above: that the emitted inner
Ethernet header carries `backend.inner_mac` as its destination and Marlin's own MAC as its
source (`docs/design/14-forwarding-modes.md` §7.4); that the emitted **outer** Ethernet header
carries the arriving frame's source MAC as its destination and Marlin's own as its source — the
assertion that catches an implementation which rewrote the inner header before saving those
addresses, which is the ordering hazard §7.4 exists to prevent and which no other mode can
exercise, because no other mode consumes the arriving header; that the VNI occupies the header's
3-byte field with the reserved byte behind it zero, the observable consequence of the
`bpf_htonl(vni << 8)` conversion; that the inner EtherType correctly distinguishes IPv4 from
IPv6 inner traffic arriving on the same `vxlan` device, since that is the mechanism the
single-device simplification depends on; and that a 50-byte headroom shortfall on the egress
interface is counted `adjust_head_failed` rather than emitting a truncated frame.

## Deliberately harder

- **`backend.mac` freshness** depends on netlink event handling in the control plane, which
  needs its own tests against neighbour churn.
- **Verifier limits** are a build-time property. CI should fail on a load failure and track
  reported complexity as a regression signal, since it degrades gradually as code is added.
- **Table regeneration under traffic** needs a test that asserts no packet is ever forwarded
  using a row that references an unpopulated slot.
