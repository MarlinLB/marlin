# Marlin — Observability


Marlin is delivered as software and deployed into networks its authors cannot inspect.
Observability is the primary support mechanism, not an accessory.

Per-packet statistics are always enabled. The datapath therefore performs per-packet map
writes to `vip_stats`, `backend_stats` and `drop_stats`. **Marlin holds no per-flow state**,
and output is a deterministic function of the packet plus map contents — but it is not
literally write-free, and the earlier "three reads, no writes" formulation was wrong.

## Drop reasons are enumerated

A single drop counter is insufficient. `drop_stats` is indexed by reason:

`vip_miss` (a pass, counted), `no_backend`, `backend_down`, `backend_unresolved`
(`docs/design/15-nexthop-l2dsr.md`),
`parse_error`, `ext_hdr_limit`, `unsupported_proto`, `icmp_unparseable`, `fib_no_neigh`
(`docs/design/16-fib-lookup.md`),
`fib_fwd_disabled`, `fib_blackhole`, `fib_unreachable`,
`fib_prohibit`, `fib_gatewayed` (L2 DSR only; `docs/design/16-fib-lookup.md`), `frag_needed`,
`frame_too_big` (`docs/design/23-mtu.md`), `mac_fallback` (not a drop, counted), `adjust_head_failed`,
`acl_blocked` (`docs/design/27-source-filtering.md`), `ratelimited` (`docs/design/28-rate-limiting.md`), `rl_cas_exhausted` (an admit, counted; `docs/design/28-rate-limiting.md`),
`rl_insert_failed` (an admit, counted; `docs/design/28-rate-limiting.md`),
`egress_mismatch` (not a drop, counted; `docs/design/16-fib-lookup.md`), `neigh_fallback` (not a drop, counted; `docs/design/16-fib-lookup.md`).

Twenty-four of `DROP_REASON_MAX`. `enum marlin_ret` carries several more that this list does not
name; reconciling the two is `marlin.h`'s open decision D6. One of those unnamed values gets its
meaning fixed here regardless, since it is otherwise a footgun for whoever implements the
encapsulation units: **`encap_length`** means the measured inner length will not fit the outer
header's length field, or is shorter than the mode's minimum. It is not expected to fire in
practice — `pkt_len` is `__u16` and no mode's overhead threatens overflow — so its absence from
a running instance's counters is not evidence of anything; it exists so an implementation bug
that produces an impossible length has a named reason instead of falling to a `default:` arm.

Reasons that are passes or fallbacks rather than drops are marked as such, so the sum of
`drop_stats` is not mistaken for total drops.

**Two counters belong to `VIP_QUIC`, and `balancer.c` is their producer**
(`docs/design/30-quic.md`): `quic_cid_routed`, a packet steered by connection ID, and
`quic_cid_check_failed`, a connection ID whose check field or generation field did not verify.
Neither is a drop, so neither changes the count above; both are `MARLIN_COUNT_*` enumerators
(`marlin.h`), kept out of the enumerated reason list above for the same reason as the other
`MARLIN_COUNT_*` values.

**The other ways a steered packet falls through are deliberately uncounted.** A connection ID
decoding to an out-of-range `backend_id`, or to a row that is down or was never written, takes
the hash path with no counter of its own. `drop_stats` would need two more reasons to separate
them, and the fall-through is already visible where it matters: `backend_stats` shows the
traffic arriving at the hash-selected backend instead. `quic_cid_routed` failing to track a
VIP's short-header volume is the aggregate signal that steering is not landing.

## Counters

| Signal | Scope | Diagnoses |
|---|---|---|
| packets, bytes | per VIP, per backend | distribution, hotspots, dead backends |
| `mac_fallback` | instance | control plane not maintaining `backend.mac` — **unless** the deployment omits MACs deliberately (below), where it is the steady state and carries no signal |
| `neigh_fallback` | instance | the kernel neighbour table is behind the control plane: a MAC was stored and usable, the neighbour entry for the same address was missing (`docs/design/16-fib-lookup.md`) |
| `egress_mismatch` | instance | `backend.egress_ifindex` disagrees with the FIB — a stale reachability determination (`docs/design/16-fib-lookup.md`) |
| `fib_gatewayed` | instance | an L2 DSR backend is off-link; either the flag is wrong or the backend moved (`docs/design/16-fib-lookup.md`) |
| `backend_unresolved` | instance | control plane populated neither `backend.mac` nor `backend.addr` (`docs/design/15-nexthop-l2dsr.md`) |
| `frag_needed` | instance | backend MSS or tunnel MTU misconfigured (`docs/design/23-mtu.md`) |
| `adjust_head_failed` | instance | insufficient driver headroom for encapsulation — VXLAN's 50-byte requirement is the largest of the three and makes this materially more likely than under IPIP or GUE (`DEPLOYMENT.md` §1.3) |
| `frame_too_big` | instance | encapsulated frame exceeds the egress MTU, under any of the three encapsulating modes (`docs/design/23-mtu.md`) |
| `icmp_unparseable` | instance | PMTUD errors being dropped |
| `unsupported_proto` | instance | ESP or AH traffic, or an IPv6 fragment being forwarded (head or tail) whose Fragmentable Part opens with an extension header instead of the upper-layer protocol — Marlin cannot reach the ports behind either case. Does not apply to the same shape inside an ICMP error's quote, which parses instead (`docs/design/11-pipeline.md`, `docs/design/13-icmp.md`) |
| `no_backend` | instance | table rows pointing at 0 — a control-plane reconciliation fault |
| `acl_blocked` | instance | the blocklist is matching; volume shows whether it is load-bearing, but mixes VIP-matched blocks with host-bound ones (`docs/design/11-pipeline.md` step 4) |
| `vip_miss` | instance | traffic addressed to no configured VIP, or the fragment tail of one — an explicit-port VIP with no `port == 0` companion never admits its tails, which read here exactly like host-bound traffic (`docs/design/11-pipeline.md`, `docs/design/12-selection.md`) |
| `ratelimited` | instance | a source is over budget |
| `frag_unsupported` | instance | a fragment arrived for a `VIP_HASH_5TUPLE` VIP; non-zero means the flag is set on a VIP whose traffic fragments (`docs/design/12-selection.md`) |
| `rl_cas_exhausted` | instance | `RL_CAS_RETRIES` too low under contention (`docs/design/28-rate-limiting.md`) |
| `rl_insert_failed` | instance | the `ratelimit` map is rejecting inserts — the insert-cost signal `docs/design/28-rate-limiting.md`'s Phase 4 measurement needs |

`bytes` in both maps counts the ingress frame length, not the emitted one, so a VIP's four
forwarding modes stay comparable against each other and the figure matches what the client
sent; per-mode encapsulation overhead is a known constant and is not this map's job to carry.
`backend_stats` is written at selection — **before** the validity and state checks
(`docs/design/11-pipeline.md` step 7), not after — so it reflects every backend hashing or QUIC
steering chose, including one currently down or one a later stage drops for any other reason,
which is what keeps it usable as the hash-skew signal below. `backend.id` is read back from the
resolved struct, not from the `fwd_table`/`backends[]` lookup key, so a slot that is stale or
was never populated reads back `id 0` (`docs/design/10-map-invariants.md`) and its packets and
bytes are counted there instead of being discarded unmeasured: `backend_stats[0]` is the signal
that a row is pointing somewhere it should not — the class of control-plane drift
`docs/PHASES.md`'s "Not phased" section names as caught by nothing else — not a real backend's
traffic.

Backend distribution is derivable from `backend_stats` alone, which makes hash skew behind
CGNAT observable without additional instrumentation. It is also the measurement that decides
whether a VIP wants `VIP_HASH_5TUPLE` (`docs/design/12-selection.md`): a single backend holding
a share of the VIP's traffic that no weight explains is the symptom of a shared egress
concentrated on one row, and `frag_unsupported` above is the counter that says whether setting
the flag cost anything.

`drop_stats` is keyed by reason with no VIP dimension, so every reason above is instance-scoped.
Three consequences are worth stating rather than rediscovering: `no_backend` cannot be attributed
to the VIP whose table is faulty; `acl_blocked` covers two unlike drops under one counter — a
VIP-matched packet, where a `vip_num` does exist at the enforcement point but `drop_stats` has no
dimension to hold it, and a host-bound one, where there is none even in principle
(`docs/design/11-pipeline.md` step 4); and identifying *which* source was rate limited means the
control plane reading `ratelimit` and observing drained buckets, which is a diagnostic action
rather than a continuous signal.

Per-rule ACL hit counts are deliberately absent. They would need a counter map keyed by rule id
and a per-packet write on the match path; the rule id in the ACL maps exists for reconciliation
(`docs/design/27-source-filtering.md`), and reusing it for accounting is a separate feature with its own cost.
