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

## Native unit tests

A second mechanism, alongside `bpf_prog_test_run` above, for the one translation unit where it
is cheap: `data-plane/tests/` compiles `parser.c` with the host toolchain — no `-target bpf` — and
`#include`s it directly to call its `static` helpers with real pointers. This is sound only
because `parser.c` makes no `bpf_*` helper call and reads no map; it is a pure function of a byte
buffer plus two offsets, so its behaviour does not depend on which target compiled it. No other
translation unit has that property yet — `main.c` and the encapsulation units read and write maps,
so a native build of those would test a different program than the one that loads.

What it buys over the packet-level harness: the `static` helpers (`marlin_parse_frag6`,
`marlin_walk_ext6`, `marlin_parse_icmp`, …) are otherwise unreachable except through
`marlin_parse`'s one entry point, so a bug confined to one helper's boundary condition — an IPv6
extension-header chain at exactly `MAX_EXT_HDRS`, a fragment header truncated to 3 of its 8 bytes —
is exercised directly rather than inferred from `marlin_parse`'s return value. It also runs in
milliseconds with no root privilege and no kernel involved, so it is the tier a change to
`parser.c` should be checked against first.

What it cannot do: assert an emitted frame, a map write, or anything downstream of
`marlin_parse` — that stays with `bpf_prog_test_run`, which is the only tier that runs the code as
compiled for the datapath. `make tests` (not part of `make all`; part of `make ci`) runs this tier;
`docs/PHASES.md` tracks whether the mechanism extends past `parser.c`.

This is also why a sub-`ETH_HLEN` truncation case cannot move to the packet-level harness: the
kernel's XDP `BPF_PROG_TEST_RUN` path rejects `data_size_in` below `ETH_HLEN` (14 bytes) before
the program ever runs, so `parser_test.c`'s 13-byte Ethernet truncation case is native-tier-only
by construction, not by choice.

`data-plane/tests/packet/` (`docs/REPO-STRUCTURE.md` §7.2) is the packet-level harness above,
made concrete: it loads the real `marlin.bpf.o` and drives `xdp_main` through
`bpf_prog_test_run_opts`, asserting `data_out` for the exact-byte half of this document's opening
sentence. Coverage there is bounded by what `xdp_main` can satisfy before Phase 2's VIP lookup
and forwarding land — parse verdicts, `drop_stats` deltas, and that a passing frame is not
mutated — with the rest of this document's matrix registered as `MARLIN_SKIP` placeholders
(`docs/PHASES.md`) that report as a named `skip` line rather than as a pass, so a green run is
never mistaken for complete coverage.

Passing `ctx_in` to `bpf_prog_test_run_opts` for an XDP program carries two kernel-enforced
obligations easy to miss and silent to get wrong: `ctx->data_end` must equal `data_size_in`
exactly, and a non-zero `ingress_ifindex` is only accepted for an interface with registered XDP
rxq info — no interface in this harness has one, so it stays `0` until the netns/veth integration
tier supplies a real one. Getting either wrong fails every case identically with `-EINVAL` before
`xdp_main` ever runs, which reads as a wall of unrelated assertion failures rather than the one
setup bug it is.

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
