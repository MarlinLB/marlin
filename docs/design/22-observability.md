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
`egress_mismatch` (not a drop, counted; `docs/design/16-fib-lookup.md`), `neigh_fallback` (not a drop, counted; `docs/design/16-fib-lookup.md`).

Twenty-three of `DROP_REASON_MAX`. `enum marlin_ret` carries several more that this list does not
name; reconciling the two is `marlin.h`'s open decision D6.

Reasons that are passes or fallbacks rather than drops are marked as such, so the sum of
`drop_stats` is not mistaken for total drops.

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
| `no_backend` | instance | table rows pointing at 0 — a control-plane reconciliation fault |
| `acl_blocked` | instance | the blocklist is matching; volume shows whether it is load-bearing |
| `ratelimited` | instance | a source is over budget |
| `frag_unsupported` | instance | a fragment arrived for a `VIP_HASH_5TUPLE` VIP; non-zero means the flag is set on a VIP whose traffic fragments (`docs/design/12-selection.md`) |
| `rl_cas_exhausted` | instance | `RL_CAS_RETRIES` too low under contention (`docs/design/28-rate-limiting.md`) |

Backend distribution is derivable from `backend_stats` alone, which makes hash skew behind
CGNAT observable without additional instrumentation. It is also the measurement that decides
whether a VIP wants `VIP_HASH_5TUPLE` (`docs/design/12-selection.md`): a single backend holding
a share of the VIP's traffic that no weight explains is the symptom of a shared egress
concentrated on one row, and `frag_unsupported` above is the counter that says whether setting
the flag cost anything.

`drop_stats` is keyed by reason with no VIP dimension, so every reason above is instance-scoped.
Three consequences are worth stating rather than rediscovering: `no_backend` cannot be attributed
to the VIP whose table is faulty; the ACL runs before the VIP lookup (`docs/design/11-pipeline.md`) so `acl_blocked` has no
`vip_num` available even in principle; and identifying *which* source was rate limited means the
control plane reading `ratelimit` and observing drained buckets, which is a diagnostic action
rather than a continuous signal.

Per-rule ACL hit counts are deliberately absent. They would need a counter map keyed by rule id
and a per-packet write on the match path; the rule id in the ACL maps exists for reconciliation
(`docs/design/27-source-filtering.md`), and reusing it for accounting is a separate feature with its own cost.
