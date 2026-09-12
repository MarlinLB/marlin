# Marlin — Implementation Phases

**Status:** established 2026-08-20
**Reconciled against:** `docs/design/README.md` revision 10, `DEPLOYMENT.md` first revision

Five boundaries. Each states what must be **true** to cross it, not what someone intends to
work on. A phase closes when its exit criteria hold in CI, not when its code is written.

`docs/design/24-testing.md`'s "phase 0" predates this document and means **Phase 1**.

---

## Overview

| Phase | Name | Closes when |
|---|---|---|
| 1 | Project setup | one L2 DSR packet forwards, configured by the C# service |
| 2a | The map ABI | `types.h` is frozen and the C# mirror is reviewed against it |
| 2b | Datapath completion | all four modes and both inner families forward correctly |
| 3 | Control plane: basic features | Marlin runs unattended: health, reconciliation, ACL |
| 4 | Control plane: complex features | the rate limiter is safe to enable under attack |

### Why Phase 2 is split

Phase 2 carries two boundaries because they fail differently:

- **2a is a decision, not a milestone.** Freezing `types.h` fixes what a second implementation
  mirrors by hand, and `marlin.h:141-145` makes the `drop_stats` indices ABI from first
  release. Both are irreversible in a way that writing an encapsulation unit is not.
- **2b is where the modes are exercised.** Encapsulation reads `backend` fields and
  `config.tunnel_src`; doing that before the layout is frozen means writing the C# mirror
  twice.

An earlier proposal was one phase per forwarding mode. IPIP, GUE and VXLAN share
`nexthop.c`, the MTU check (`docs/design/23-mtu.md`) and the checksum arithmetic
(`docs/design/14-forwarding-modes.md`), so all three are one boundary here rather than three
separate ones. L2 DSR is separated out — into Phase 1 — because it is the mode with no
encapsulation and therefore
the shortest path to a forwarding packet.

### Why the ACL is in Phase 3 and not Phase 4

`docs/design/20-configuration-validation.md` rejects `CFG_RL_ENABLE` set while `CFG_ACL_ENABLE` is clear: without the ACL
no packet carries an allow verdict, so the rate limiter would meter management prefixes with
no escape hatch. It rejects `VIP_RATELIMIT` on a `VIP_ACL`-clear VIP for the same reason, so the
dependency is per-VIP as well as instance-wide. **The ACL is therefore a prerequisite of Phase 4,
not a peer of it.** Its
control-plane work — reconciling four `LPM_TRIE` maps and maintaining `config.acl_lists` — is
the same kind of work as backend reconciliation, and its datapath cost is two trie lookups on
a pure function of `packet_tuple.src`. Neither belongs with the rate limiter.

---

## What holds in every phase

- **Packet tests are built first, not last** (`docs/design/24-testing.md`). They are affordable because Marlin holds
  no per-flow state, so output is a deterministic function of the packet and map contents.
  Anything that breaks that property is a design change, not an implementation detail.
- **Both feature flags stay off until their phase.** The phase gate is `CFG_ACL_ENABLE`
  (Phase 3) and `CFG_RL_ENABLE` (Phase 4) plus the control-plane side, not the datapath code:
  `acl.c` and `ratelimit.c` are written and called well before either flag may be set.
- **The verifier is a build product.** CI fails on a load failure and records reported
  complexity as a regression signal, because it degrades gradually as code is added
  (`docs/design/24-testing.md`).
- **A phase does not close with an open decision assigned to it.** The decisions are named per
  phase below, and collected at the end of this document.

---

## Phase 1 — Project setup

**Goal:** one packet arrives on a VIP and leaves for a backend, and a C# process put the
configuration there. Nothing beyond that.

### Scope

Phase 1 is about making the datapath compile, load and be driven, not about completing it. It
owns the build system, the test harness, the loader and its systemd unit, CI — whose
obligations `docs/design/24-testing.md` states without naming a system — the control-plane tree
and version control. The forwarding work it needs is the vertical slice below and nothing
further.

### Build

- Per-translation-unit `clang -target bpf -g`, linked with `bpftool gen object` into
  `marlin.bpf.o`. Every input carries BTF (`docs/design/03-translation-units.md`).
- `data-plane/marlind/main.c` (`marlind`) and its systemd unit, `Type=notify`, ordered before the
  control plane (`docs/design/02-architecture.md`).
- `clang-format` and `clang-tidy` wired into CI, blocking per `.clang-tidy`'s
  `WarningsAsErrors`.
- Load and attach verified in a network namespace: `marlind attach` loading, pinning
  and attaching with `bpf_link_create()`. The attach must fail rather than degrade to SKB mode
  (`docs/design/02-architecture.md`).
- `make tests` builds and runs the native unit tests, one binary per test file — `parser.c`,
  `acl.c`, `csum.h`, `mtu.h`, `entropy.h`, `nexthop.c`'s NULL-argument aborts, and `ipip.c` today
  (`docs/design/24-testing.md`, "Native unit tests"). Not part of `make all`; part of `make ci`.
- `make packet-tests` builds `marlin.bpf.o`, loads it, and drives it through `bpf_prog_test_run`
  for what `xdp_main` can satisfy today — parse verdicts and `drop_stats` deltas
  (`docs/design/24-testing.md`, "Packet-level tests"; `data-plane/tests/packet/`). Needs root or
  `CAP_BPF`+`CAP_NET_ADMIN`+`CAP_PERFMON` to load a program, so it is not part of `make tests`;
  `make ci` runs it only when invoked as root and prints an explicit skip line otherwise.

### Datapath — the vertical slice

One path only. IPv4 inner, L2 DSR, one VIP with an explicit port, one `MARLIN_UP` backend with
a stored `mac` and `MARLIN_BE_F_FIB` clear, `XDP_TX`.

Included because omitting them would build the wrong thing:

- Rendezvous selection over `fwd_table` as specified in `docs/design/12-selection.md`, not
  `backends[hash % N]`. The table is generated for real even with one member
  (`docs/design/12-selection.md`, "Why the table is not simply …").
- SipHash-2-4 over the client address with `vip_meta.hash_key` (`docs/design/12-selection.md`).
- `marlin_ctx` fully zeroed before the first `marlin_*` call, and the `config` snapshot taken
  once in `marlin.c` (`docs/design/04-calling-convention.md`).
- `drop_stats`, `vip_stats` and `backend_stats` written.

Deliberately absent: IPv6 inner, extension headers, fragments, the ICMP branch, port-agnostic
VIPs, `bpf_fib_lookup()`, `XDP_REDIRECT` and `tx_ports`, all three encapsulation modes, ACL and
rate-limit enforcement.

### Control plane

The real C#/.NET 10 service, minimal surface. It opens pinned paths and performs map I/O only;
it never creates maps (`docs/design/02-architecture.md`, `docs/design/19-control-plane.md`).

- `vip_map`, `fwd_table`, `backends`, `config` written over `bpf_obj_get` +
  `bpf_map_update_elem`.
- Hand-written mirrors for `vip_key`, `vip_meta`, `backend` and `marlin_config`, under
  `docs/design/06-map-abi.md`'s parity discipline: every struct is `[StructLayout(Explicit)]`
  with `[FieldOffset]` stated per field, `vip_key`'s anonymous union has both arms at
  `FieldOffset(0)`, and fixed-size arrays are `[InlineArray]` or `fixed`, never managed arrays.
- No health checking, no reconciliation loop, no APIs, no netlink.

**Two decisions are required in this phase.**

- **C# map access:** P/Invoke to `libbpf`, or a direct `bpf(2)` syscall wrapper. It determines
  the deployment dependency set and is cheapest to settle before any map I/O is written.
- **Indentation.** `.clang-format` sets `UseTab: Never` and `.editorconfig` sets
  `indent_style = space`, but every existing source indents with tabs — no line in any of
  them carries two or more leading spaces, and every leading-space line is a `^ *`
  block-comment continuation. CI cannot enforce formatting until this is resolved, and
  `clang-format` as configured today rewrites every file, comment continuations included.
  Either the configuration adopts tabs, or the sources are reformatted once, in a commit
  containing nothing else.

### Exit criteria

1. `marlin.bpf.o` builds with BTF, loads, and attaches in `xdpdrv` mode in a netns.
2. `bpf_prog_test_run` asserts exact output bytes for: a VIP hit rewriting the destination MAC
   and returning `XDP_TX`; a miss returning `XDP_PASS` counting `vip_miss`; `backend_id == 0`
   dropping `no_backend`; `state != MARLIN_UP` dropping `backend_down`. Each is registered in
   `data-plane/tests/packet/xdp_test.c` and, for as long as the path it asserts is unreachable,
   carries a `MARLIN_SKIP` naming this line — so `make packet-tests` reports it as `skip` rather
   than a pass.
3. The C# service configures that VIP and backend from scratch on a running datapath, and the
   forwarding change is observed in `vip_stats` and `backend_stats` — not in service logs.
4. Restarting the C# service disturbs neither the attachment nor forwarding
   (`docs/design/02-architecture.md`, `docs/design/19-control-plane.md`).
5. CI blocks on `clang-tidy` findings and on a verifier load failure, and records reported
   complexity.
6. Both Phase 1 decisions above are settled and written down — the C# map-access mechanism,
   and indentation. The second is what criterion 5's format check depends on.

---

## Phase 2a — The map ABI

**Goal:** `types.h` stops changing, and the C# mirror is known to match it by review.

Two open decisions must close here, because both alter layout or index meaning and neither is
revisable once a control plane has recorded a counter or read a struct in the field.

| Decision | Where | Question |
|---|---|---|
| D4 | `types.h:203` | `backend.mac` straddles the 8-byte boundary at bytes 4-9. `docs/design/17-reconfiguration.md` calls `mac` immutable; `docs/design/15-nexthop-l2dsr.md` and `docs/design/19-control-plane.md` refresh it from neighbour events. If it is mutable, a torn read yields four bytes of the new MAC and two of the old. Field order is `docs/design/08-types.md`'s as written, pending this. |
| D6 | `marlin.h:44` | `MAP_BOUNDS`, `NO_TX_PORT`, `ENCAP_LENGTH`, `FIB_UNSPEC`, `NOT_FORWARDED`, `FRAG_UNSUPPORTED` and the counted ICMP echo pass are in `enum marlin_ret` but not in `docs/design/22-observability.md`'s enumerated list of 23 reasons. |

### Deliverables

- `types.h` frozen: all 13 maps, their keys and values, and every constant of `docs/design/09-sizing.md`.
- `VIP_HASH_5TUPLE` and `MARLIN_DROP_FRAG_UNSUPPORTED` land here or not at all
  (`docs/design/12-selection.md`). The flag is a `vip_meta.flags` bit and the reason is a
  `drop_stats` index, so both are exactly what this phase freezes; adding either afterwards is a
  post-freeze `types.h` change under exit criterion 4. Its datapath consumers are `balancer.c`'s
  frag and hash stages; the flag stays unusable until Phase 2b supplies its producer, below.
- `VIP_QUIC` and the CID-length field land here or not at all (`docs/design/30-quic.md`), on the
  same freeze logic as `VIP_HASH_5TUPLE` above. `parser.c` classifies short- from long-header
  packets; the steering step that consumes the flag is `balancer.c`'s, in Phase 2b.
- `VIP_ACL` lands here or not at all, on the same freeze logic again
  (`docs/design/27-source-filtering.md`). It takes `vip_meta.flags` bit 0, which both sides of the
  ABI otherwise fold into `VIP_FLAGS_RESERVED` — `data-plane/include/marlin/abi/defines.h` and
  `control-plane/Marlin.Abi/Defines/VipFlags.cs` — so the two reserved masks and the
  `_Static_assert` guarding them are one commit spanning both languages, exactly as exit criterion
  3 requires. Its only consumer is Phase 2b's enforcement gate.
- Byte offsets stated in comments on both the C and C# sides for every mirrored struct, so
  parity is reviewable by reading — which `docs/design/06-map-abi.md` records as the only mechanism there is.
- `drop_stats` enumerators appended from here, never reordered (`marlin.h:142`).
- The C# mirror extended to every struct the later phases need, not only Phase 1's four.

### Exit criteria

1. D4, D6 and D7 closed, with the resolution written into `docs/design/08-types.md` (D4 and D7)
   and `docs/design/22-observability.md` (D6), and the header comment replaced rather than
   annotated.
2. `docs/design/22-observability.md`'s reason list and `enum marlin_ret` agree, and `DROP_REASON_MAX` still bounds them.
3. Every mirrored struct carries byte offsets on both sides and has been reviewed for parity
   as a single commit spanning both languages (`docs/design/06-map-abi.md`).
4. No `types.h` change lands after this point without the justification written into
   `docs/design/06-map-abi.md` and `docs/design/08-types.md` in the same commit.

---

## Phase 2b — Datapath completion

**Goal:** every forwarding mode and every parse path in `docs/design/11-pipeline.md` works. After this phase the
datapath is feature-complete and further work is control-plane work.

### Deliverables

- `parser.c`: IPv6 extension-header walking to `MAX_EXT_HDRS`, fragments in both families, ESP
  and AH as `unsupported_proto`, and the ICMP branch including the embedded-header path
  (`docs/design/11-pipeline.md`).
- `balancer.c`'s VIP lookup: the port-agnostic double lookup of `vip_map` — the parsed
  destination port first, then port 0 on a miss — both with a fully zeroed key
  (`docs/design/11-pipeline.md`). `parser.c` has no access to `vip_map`; this is step 4, not
  parsing.
- **`balancer.c`'s ACL enforcement gate**, which is the other half of the same step: the block
  verdict enforced instance-wide on the `vip_map` miss, and gated on `VIP_ACL` on the hit
  (`docs/design/27-source-filtering.md`). It lands here because it is datapath code reading
  `vip_meta.flags`, and it is inert until Phase 3 makes `CFG_ACL_ENABLE` usable. Moving
  Retiring the duplicate site in `src/main.c` is what closes the enforcement-placement decision
  below. The assertions that cover it are Phase 3's exit criterion 4 and not this phase's
  criterion 1, because two of the three need a VIP configured with the bit and an enabled ACL,
  which Phase 3 is where the control plane can supply.
- **`parser.c` supplies what `VIP_HASH_5TUPLE` consumes.** The flag is inert without two
  additions, and both are silent if omitted rather than failing visibly:
  `MARLIN_CTX_F_FRAG_FIRST` set on the first fragment of a fragmented datagram — without it
  `marlin_balance_frag()` admits first fragments and strands reassembly state on the backend —
  and the embedded *destination* port recovered into `tuple.sport` on the ICMP error path, which
  address-only selection never needed and without which ICMP errors hash to the wrong row and
  path MTU discovery breaks for the encapsulation modes (`docs/design/13-icmp.md`). The
  `icmp_unparseable` threshold moves from two bytes of embedded L4 header to four with it.
  `tuple.pad` must stay zero, because the flag hashes the tuple whole
  (`docs/design/10-map-invariants.md`).
- **`balancer.c`'s `VIP_QUIC` steering step.** On a `VIP_QUIC` VIP, a `MARLIN_CTX_F_QUIC` packet
  decodes a `backend_id` from its connection ID and indexes `backends[]` directly, bypassing
  `fwd_table`; any decode failure — check mismatch, an out-of-range or unpopulated
  `backend_id`, or a backend not `MARLIN_UP` — falls through to the existing hash path, uncounted
  as a drop (`docs/design/30-quic.md`). It needs two `MARLIN_COUNT_*` counters,
  `quic_cid_routed` and `quic_cid_check_failed`; the other fall-through paths are deliberately
  uncounted (`docs/design/22-observability.md`).
- `ipip.c`, `gue.c`, `vxlan.c`, `csum.h`, `entropy.h`: IPIP, GUE and VXLAN,
  IPv6 inner over IPv4 outer, VXLAN's VNI, its inner Ethernet header rewrite and its outer
  Ethernet header, the entropy source port shared by GUE and VXLAN, and the zero UDP checksum
  (`docs/design/14-forwarding-modes.md`).
- `nexthop.c` completed: `bpf_fib_lookup()` with its seven return codes, the `neigh_fallback`
  path, the L2 DSR gatewayed-next-hop refusal, `egress_mismatch`, and `XDP_REDIRECT` through
  `tx_ports` (`docs/design/16-fib-lookup.md`).
- The MTU and fragmentation checks of `docs/design/23-mtu.md`: `frag_needed` and `frame_too_big`. Encapsulation
  also introduces `adjust_head_failed`, which is a driver-headroom failure counted under
  `docs/design/22-observability.md`, not an MTU check.
- Control plane gains only what the modes need: `config.tunnel_src`, a static
  `config.max_frame`, `tx_ports` population, and, for VXLAN backends, `backend.vni` and
  `backend.inner_mac` (`docs/design/19-control-plane.md`). Refreshing `max_frame` from netlink
  link events is Phase 3.

**Decision required in this phase:** `nexthop.c:80` — `docs/design/16-fib-lookup.md` calls
`BPF_FIB_LOOKUP_DIRECT` optional but gives it no configuration surface, so policy routing rules
currently apply. The same decision covers `fib.ipv4_src`/`tos`/`l4_protocol`
(`nexthop.c:75-78`): they are left unseeded because the correct per-mode value is not one
`nexthop.c` has in hand (`cfg` is not among its readers, `04-calling-convention.md:48-51`), and
configuration surface for either would resolve both.

### Exit criteria

1. `docs/design/24-testing.md`'s full packet-test matrix passes, including every named assertion: the **five**
   `NO_NEIGH` fallback cases; `NO_NEIGH` dropping in every other mode; the FIB fallback
   resolving the backend rather than the VIP; `MARLIN_BE_F_FIB` beating a resolved MAC with
   the emitted source MAC asserted; L2 DSR refusing a gatewayed next hop while the same route
   forwards under IPIP; `egress_mismatch` counting without changing the verdict in the
   `tx_ports`-present case; and `egress_mismatch` **plus** a `no_tx_port` drop when **the
   FIB's** interface is absent from `tx_ports` — the redirect keys on the FIB result, never on
   `egress_ifindex` (`nexthop.c:218`), and the counter is not a claim that the frame left.
2. Integration tests in network namespaces confirm a real kernel FOU/GUE listener, real
   `ipip`/`sit` devices, and a real `vxlan` device accept what Marlin emits, including the zero
   UDP checksum (`docs/design/24-testing.md`). `data-plane/scripts/gue_wsl.sh` and
   `vxlan_wsl.sh` cover this: `test_http_get` is the acceptance evidence (a real FOU listener,
   real `ipip`/`sit` receive devices, and a real `vxlan` device each complete a request), and
   `verify` captures one run and asserts the emitted frame byte-for-byte against
   `docs/design/24-testing.md`'s VXLAN assertion list — including the zero UDP checksum, the
   VNI's 3-byte field with its trailing reserved byte, and the outer-Ethernet-carries-the-
   arriving-source-MAC property the ordering hazard in §7.4 exists to prevent. Two items on
   that list stay open under generic XDP: a 50-byte headroom shortfall cannot be produced
   (`netif_receive_generic_xdp()` guarantees 256 bytes of headroom), and the inner-EtherType
   v4/v6 distinction needs a v6 client leg neither rig has yet — both remain for the packet
   tier or a native-driver rig.
3. An extension-header chain at `MAX_EXT_HDRS` and one beyond it are distinguishable —
   `ext_hdr_limit`, not `parse_error`
   (`data-plane/tests/packet/xdp_test.c`,
   `ext_hdr_limit_nine_headers_is_drop_and_distinct_from_parse_error`). Parsing does not depend
   on Phase 2b's forwarding code, so this criterion is that forwarding not regress it.
4. A redirect to an ifindex absent from `tx_ports` is a countable `XDP_ABORTED`, not a silent
   loss (`docs/design/09-sizing.md`).
5. Reported verifier complexity is inside budget with all four modes and both families
   linked. If it is not, `docs/design/05-budgets.md`'s `PROG_ARRAY` fallback is taken **with its
   three consequences accepted explicitly**: `marlin_ctx` moves to a per-CPU scratch map, the
   accumulated stack cap drops to 256 bytes, and tail calls do not return. **Measured**, with
   `make verifier-stats`, over a reachable set that includes `marlin_balancer_process()`, both
   `marlin_nexthop_*` entry points and all three encapsulation units — against limits of
   1,000,000 processed instructions and a 512-byte worst combined stack depth
   (`docs/design/05-budgets.md`). The measurement is a build product, so this criterion is the
   run, not a figure recorded here.

---

## Phase 3 — Control plane: basic features

**Goal:** Marlin runs unattended. Everything in `docs/design/19-control-plane.md`,
`docs/design/20-configuration-validation.md` and `docs/design/21-active-active.md` except the
rate-limiter conversion.

### Deliverables

- **Health checking** with the prober bound in a VRF that does not contain the VIP but
  **does** contain the probe source address and the host `ipip`/`sit`/GUE/`vxlan` devices the
  probes traverse (`docs/design/18-health.md`; `DEPLOYMENT.md` §1.9).
- **Reconciliation.** The configuration store is authoritative; maps are not. Startup
  reconciles idempotently (`docs/design/19-control-plane.md`).
- **Table generation** from the stored `table_seed` and member set, including regeneration
  under traffic.
- **Neighbour and MAC maintenance** from netlink: `backend.mac`, outer next-hop entries, and
  the two cases `docs/design/15-nexthop-l2dsr.md`'s `neigh_fallback` cannot cover — a genuinely
  off-segment flagged L2 DSR backend, and any backend configured without a `mac`
  (`docs/design/19-control-plane.md`).
- **Reachability as asserted opt-out.** `MARLIN_BE_F_FIB` set on every backend not positively
  confirmed on the ingress segment; `backend.egress_ifindex` populated wherever the
  determination produced an interface (`docs/design/19-control-plane.md`).
- **`config.max_frame`** refreshed from the attach interface's MTU on netlink link events,
  replacing the static value Phase 2b set.
- **ACL**: four tries reconciled, `config.acl_lists` maintained, `CFG_ACL_ENABLE` and the
  per-VIP `VIP_ACL` both usable (`docs/design/27-source-filtering.md`).
- **Configuration validation** — every rule in `docs/design/20-configuration-validation.md`, rejected at configuration time.
- **Configuration and status APIs**, including the per-VIP non-reversible digest of
  `hash_key` and `table_seed` that makes active/active divergence detectable
  (`docs/design/21-active-active.md`). Extended to cover `VIP_QUIC`, the connection-ID length
  and `hash_key`'s QUIC use once Phase 2b lands the steering step
  (`docs/design/21-active-active.md`).
- **`VIP_QUIC` backend distribution.** Assigning and distributing `backend_id`, `hash_key` and
  the connection-ID length to each backend's QUIC server, and the rotation story
  (`docs/design/30-quic.md`; `DEPLOYMENT.md` §1.7.2).

### Exit criteria

1. One test per `docs/design/20-configuration-validation.md` validation rule, asserting
   rejection rather than a warning, and one per rule accepted with a warning.
2. Table regeneration under traffic never forwards through a row referencing an unpopulated
   slot (`docs/design/24-testing.md`).
3. `backend.mac` freshness tested against neighbour churn, which needs its own netlink-level
   tests (`docs/design/24-testing.md`).
4. `docs/design/24-testing.md`'s ACL coverage passes at both tiers — `make tests`'s
   `data-plane/tests/acl_test.c` and `make packet-tests`'s `xdp_test.c` — **including the
   placement assertions**, packet-tier-only since they depend on step ordering: a blocked source
   addressed to a destination that is not a VIP drops with `acl_blocked`, not `vip_miss`; the same
   source addressed to a `VIP_ACL` VIP drops `acl_blocked`; and addressed to a VIP with the bit
   clear, forwards. The first is the whole of `docs/design/11-pipeline.md`'s host-firewall property
   and fails silently if step 4's host-bound arm stops enforcing; the third is what tells a
   per-VIP exemption apart from an ACL that has stopped working.
5. `sizeof` asserted on both ACL key structs, 8 and 20 — a layout change alters what the trie
   compares (`docs/design/24-testing.md`), at both tiers.
6. A control-plane restart reconciles a partially applied write to the same end state, twice
   in succession, with no forwarding interruption.
7. `DEPLOYMENT.md`'s prerequisites are reviewed against what Phase 3 actually requires of the
   integrator, and its §9 checklist is complete. The first revision already carries the five
   requirements named for it: LRO disabled (§1.3), the router hairpin
   (§1.11), backend packet size (§2.6), management prefixes allowlisted ahead of the first
   blocklist rule together with ingress source-address validation (§7, §4.3), and the probe
   VRF (§1.9).

---

## Phase 4 — Control plane: complex features

**Goal:** the rate limiter is safe to enable on a link carrying production traffic.

The datapath token bucket is `ratelimit.c`'s, gated at its `balancer.c` call site by
`VIP_RATELIMIT` and instance-wide by `CFG_RL_ENABLE`, and covered at both the native
(`data-plane/tests/ratelimit_test.c`) and packet (`data-plane/tests/packet/xdp_test.c`'s `rl_*`
cases) tiers. What this phase adds is the measurement that decides whether it may be turned on,
the control-plane conversion, and the concurrency evidence.

### Deliverables

- **The insert-cost measurement `docs/design/28-rate-limiting.md` demands.** Insert-per-packet
  throughput in native XDP, under a spoofed flood presenting a fresh source per packet, relative
  to line rate. `docs/design/28-rate-limiting.md` states that bounded memory is achieved and
  bounded cost is not: the mitigation is chosen *on the measurement*, and adding machinery before
  it is what `docs/design/28-rate-limiting.md` rules out.
- **Unit conversion in the control plane.** Operator tokens-per-second and burst-in-packets
  become `config.rl_refill` and the scaled `config.rl_burst`. The datapath performs no unit
  conversion (`docs/design/19-control-plane.md`).
- **`ratelimit` is datapath-owned.** The control plane reads it for diagnostics and never
  writes it (`docs/design/19-control-plane.md`).
- `CFG_RL_ENABLE` usable, gated on `CFG_ACL_ENABLE`.

### Exit criteria

1. The insert cost measured and its outcome recorded as a policy decision, not a silent
   optimisation. If
   the cheapest correction is taken — admitting without inserting once insert pressure is
   detected — that is a documented trade of enforcement against novel sources for bounded
   cost.
2. `docs/design/24-testing.md`'s rate-limiter regime passes: one update's arithmetic from a
   seeded `state` word including refill, the clamp to `rl_burst`, the sub-one-token drop, the
   timestamp wrap clamp, and a tick delta whose refill product would overflow 32 bits; bucket
   exhaustion asserted as bounds rather than exact token counts; insertion beyond
   `MAX_RL_ENTRIES` distinct sources holding capacity with no failed insertion.
3. An allowlisted source at any rate is never `ratelimited` — the assertion that an allow
   verdict survives the VIP lookup on `marlin_ctx.acl_verdict` (`docs/design/11-pipeline.md`).
4. `rl_cas_exhausted` characterised under concurrent senders across multiple receive queues.
   `bpf_prog_test_run` is single-threaded and cannot reach this; it needs the integration
   environment (`docs/design/24-testing.md`).
5. Every `docs/design/24-testing.md` packet test from earlier phases still passes with
   `CFG_RL_ENABLE` off, which is what keeps that coverage order-independent.

---

## Open decisions, by phase

Every decision a phase must close before it closes. Each is carried at the line or in the
section it affects, not in a document of its own.

| Decision | Carried in | Phase |
|---|---|---|
| C# map access: `libbpf` P/Invoke or direct `bpf(2)` | Phase 1, "Control plane" above | 1 |
| Indentation: `.clang-format`/`.editorconfig` say spaces, every source uses tabs | `.clang-format`/`.editorconfig` | 1 |
| Whether `data-plane/tests/` joins `make format`/`make tidy`, or takes its own `.clang-format`/`.clang-tidy` | `docs/REPO-STRUCTURE.md` §7.2 | 1 |
| Whether the indentation row above covers shell as well as C: `.editorconfig` mandates 4 spaces for `*.sh`, every `data-plane/scripts/*.sh` is tab-indented, and nothing rewrites shell the way `clang-format` rewrites C | `.editorconfig` `[*.{sh,bash}]` | 1 |
| Whether the control plane runs as a non-root user, and what mechanism grants it access to pins `bpf_obj_pin` creates `0600` | `docs/DEPLOYMENT.md` §1.6 | 1 |
| The loader's real capability set: this table's "Build" section above and `data-plane/Makefile` both assert `CAP_PERFMON` is needed to load this object; `docs/DEPLOYMENT.md` §1.6 lists only `CAP_BPF`+`CAP_NET_ADMIN`. `data-plane/marlind/main.c` is now what calls `BPF_PROG_LOAD`, so this is where the real set gets measured, not merely asserted | `data-plane/marlind/main.c`, `docs/DEPLOYMENT.md` §1.6 | 1 |
| Whether `/etc/sysctl.d/90-marlin.conf` (`docs/DEPLOYMENT.md` §1.8) is a shipped `deploy/` artefact or integrator host state | `docs/REPO-STRUCTURE.md` §2 | 1 |
| Whether `deploy/marlind.service` stays flat or becomes a `marlind@.service` template keyed on `IFACE`, the only form that can express `BindsTo=sys-subsystem-net-devices-%i.device`. The loader's own `RTM_DELLINK` watch (`docs/design/02-architecture.md`) now covers the netdev-disappears case without it, so a template is no longer the only answer — but it remains the systemd-native one | `docs/REPO-STRUCTURE.md` §2 | 1 |
| D4 — `backend.mac` field order and mutability | `types.h:203` | 2a |
| D6 — `enum marlin_ret` versus `docs/design/22-observability.md`'s reason list | `marlin.h:44` | 2a |
| Whether a CI check diffs the compiled BTF against the C# `[FieldOffset]` set — the only thing that would catch a C-side reorder of two same-sized fields | `docs/REPO-STRUCTURE.md` §7.7 | 2a |
| `BPF_FIB_LOOKUP_DIRECT` has no configuration surface, and neither does `fib.ipv4_src`/`tos`/`l4_protocol`/`sport`/`dport`, left unseeded for the same reason | `nexthop.c:75-80` | 2b |
| Duplicate call site: `src/main.c` calls `marlin_acl_check()` as well as `balancer.c`, so the rule set is evaluated twice per packet against the two trie lookups `docs/design/11-pipeline.md` budgets | `src/main.c`, `docs/design/11-pipeline.md` step 3 | 2b |
| Duplicate call site: `src/main.c` enforces the block verdict ahead of the VIP lookup, so a block drops instance-wide for every destination rather than only where `VIP_ACL` is set — over-enforcement that `CFG_ACL_ENABLE` defaulting off is what keeps safe. `balancer.c`'s gate is the one `docs/design/27-source-filtering.md` specifies | `src/main.c`, `docs/design/27-source-filtering.md` "Evaluation and enforcement" | 2b |
| Duplicate call site: `src/main.c` calls `marlin_ratelimit()` ahead of the VIP lookup and discards its verdict, so a metered packet spends a token there as well as at `balancer.c`'s step-5 site and a refusal on that path neither drops nor counts. Acceptable only because `CFG_RL_ENABLE` defaults off | `src/main.c`, `docs/design/11-pipeline.md` step 5 | 2b |
| Duplicate call site: `xdp_interim_nexthop()` in `src/main.c` reaches `marlin_nexthop_l2dsr()`/`marlin_nexthop_encapsulate()` on a path `balancer.c` already owns at `docs/design/11-pipeline.md` step 9 | `src/main.c`, `docs/design/11-pipeline.md` step 9 | 2b |
| Whether a parse-terminal `XDP_PASS` (`MARLIN_PASS_NOT_FORWARDED` for a non-IP-forwardable protocol) must still pass through the ACL, so a blocked source's non-forwarded traffic is dropped rather than reaching the host stack — `docs/design/27-source-filtering.md`'s "Operator lockout" argues yes, but only sanctions the exemption for ICMP echo explicitly | `docs/design/11-pipeline.md` step 3 | 2b |
| VXLAN backend VIP placement: loopback/dummy interface, as under L2 DSR, or the `vxlan` device itself. The `data-plane/scripts/vxlan_wsl.sh` and `netns-topo.sh` rigs assume `lo`/a dummy device, matching every other mode's rig — an operational default for development, not a resolution of the question | `docs/design/01-scope.md` | 2b |
| Netns integration rigs: `tests/integration/` versus `data-plane/scripts/`, where all five currently live | `docs/REPO-STRUCTURE.md` §7.8 | 2b |
| `nexthop.c` maps ten kernel `bpf_fib_lookup()` return codes onto seven named `drop_stats` reasons. `BPF_FIB_LKUP_RET_NOT_FWDED` (the ordinary no-route outcome), `UNSUPP_LWT` and `NO_SRC_ADDR` all fall to the `default:` arm, `MARLIN_DROP_FIB_UNSPEC` — so "no route" is indistinguishable from a helper contract violation in `drop_stats` | `docs/design/16-fib-lookup.md:56-66`, `nexthop.c:82-111` | 2b |
| Whether `ipip.c`'s, `gue.c`'s and `vxlan.c`'s `tot_len`/`pkt_len` arithmetic needs a `__u32` guard against `__u16` wraparound when `cfg.max_frame == 0` disables `frame_fits()` — unreachable from the datapath today (`pkt_len` derives from `data_end - data`), covered by `ipip_test.c`, `gue_test.c` and `vxlan_test.c` only at the boundary that does not wrap; one guard for all three once decided, the same reasoning that makes them one boundary rather than three (`docs/PHASES.md:34-39`) | `ipip.c:77,85`, `gue.c:85,105`, `vxlan.c:120,143` | 2b |
| Whether `VIP_QUIC` and `VIP_HASH_5TUPLE` may coexist, or configuration validation rejects the combination | `docs/design/20-configuration-validation.md` | 3 |
| The rate limiter's insert cost under a spoofed flood, and the mitigation it selects | `docs/design/28-rate-limiting.md` | 4 |

---

## Not phased

Recorded so their absence is not read as an omission.

- **Datapath upgrade without dropping connections.** A non-goal (`docs/design/01-scope.md`).
  Control-plane upgrades are non-disruptive at every phase because the maps are pinned; datapath
  upgrades are not, at any phase.
- **The accepted residual risks.** Not scheduled, because each is accepted rather than
  outstanding, and each is argued where it arises: the `~1/(N+1)` reset on backend addition
  (`docs/design/12-selection.md`, `docs/design/17-reconfiguration.md`; `DEPLOYMENT.md` §2), the
  GUE-specific probe blind spot (`docs/design/18-health.md`; `DEPLOYMENT.md` §1.9), silent
  `hash_key`/`table_seed` divergence (`docs/design/10-map-invariants.md`,
  `docs/design/21-active-active.md`), distributed sub-threshold attacks
  (`docs/design/25-rejected.md`, `docs/design/28-rate-limiting.md`), and the unchecked map ABI
  (`docs/design/06-map-abi.md`).
- **Extending the firewall beyond `docs/design/27-source-filtering.md` and
  `docs/design/28-rate-limiting.md`.** L4-granular rules, stateful matching and userspace attack
  classification are non-goals (`docs/design/01-scope.md`), and nothing beyond what those two
  documents specify is in scope until an operational need names it.
