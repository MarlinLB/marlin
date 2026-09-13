# Marlin — Design

**Status:** design settled, pre-implementation
**Last updated:** 2026-09-13
**Revision:** 11 — `struct backend` gained `id` at bytes 30-31 (`08-types.md`), replacing
`pad_end[2]`; `sizeof` stays 32 and `marlin_ctx` stays 104. It records the backend's own index in
`backends`, removing the output-parameter chain selection would otherwise thread the index
through alongside the pointer that already identifies it. `07-maps.md`, `04-calling-convention.md`,
`17-reconfiguration.md`, `10-map-invariants.md`, `20-configuration-validation.md`,
`19-control-plane.md`, `DEPLOYMENT.md` and `12-selection.md` follow the consequence.
Revision 10 — ACL enforcement made per-VIP (`27-source-filtering.md`): `vip_meta.flags` bit 0
becomes `VIP_ACL` (`08-types.md`), an opt-in gate mirroring `VIP_RATELIMIT`. Evaluation stays
ahead of the VIP lookup and enforcement moves after it (`11-pipeline.md` step 4), with the
host-bound arm enforcing instance-wide so the host-firewall property survives the split;
`20-configuration-validation.md` gains the per-VIP twin of the rate limiter's escape-hatch
rejection, and `04-calling-convention.md`, `22-observability.md`, `24-testing.md` and
`28-rate-limiting.md` follow the consequences. `VIP_ACL` takes `vip_meta.flags` bit 0 out of
`VIP_FLAGS_RESERVED` on both sides of the ABI, and the enforcement gate is `balancer.c`'s
(`PHASES.md`, Phases 2a and 2b). Revision 9 — QUIC connection-ID steering added (`30-quic.md`): `VIP_QUIC` decodes a
`backend_id` a cooperating backend embeds in its connection IDs, steering short-header packets
around client address migration without a hash. It takes `vip_meta.flags` bits 3 and 8–12
(`08-types.md`), classification is `parser.c`'s and steering is `balancer.c`'s.
Revision 8 — VXLAN's outer Ethernet header specified
(`14-forwarding-modes.md` §7.4): `vxlan.c` writes it, because the MAC-swap default
(`15-nexthop-l2dsr.md`) cannot once the arriving header has been consumed as the inner one;
`backend.vni`'s host byte order and conversion site are stated. Revision 7 added VXLAN as a
fourth per-backend forwarding mode — `struct backend` gained `vni` and `inner_mac`, the
rendezvous score (`12-selection.md`) became keyed on `addr`, `vni` and `inner_mac` together, and
the stack budget target was raised to accommodate the wider struct (`05-budgets.md`)

Marlin is an eBPF/XDP layer-4 load balancer. The datapath is C compiled with clang and
attached as a native-mode XDP program. The control plane is a C#/.NET 10 service.

Marlin is delivered as software. Deployment, network configuration and backend
provisioning are the integrator's responsibility; see `DEPLOYMENT.md`.

| File | Holds |
|---|---|
| 01-scope.md | Forwarding modes, targets, and non-goals |
| 02-architecture.md | Load sequence, object lifetime, and privileges |
| 03-translation-units.md | Translation units and linking rules |
| 04-calling-convention.md | The BPF calling convention and `marlin_ctx` layout |
| 05-budgets.md | Stack and verifier budget constraints |
| 06-map-abi.md | Why the map ABI is hand-written, not generated |
| 07-maps.md | Map inventory and per-map type rationale |
| 08-types.md | Map key/value struct definitions and flag bits |
| 09-sizing.md | Compile-time constants and map memory sizing |
| 10-map-invariants.md | Sentinel, zeroing, and hash-key invariants |
| 11-pipeline.md | The packet pipeline steps and pointer invalidation |
| 12-selection.md | Rendezvous hashing, table design, and backend ID lifecycle |
| 13-icmp.md | ICMP error handling and embedded-header steering |
| 14-forwarding-modes.md | L2 DSR, IPIP, GUE, VXLAN modes, families, and checksums |
| 15-nexthop-l2dsr.md | MAC swap and L2 DSR stored-MAC/FIB fallback |
| 16-fib-lookup.md | `bpf_fib_lookup()` return codes and gateway handling |
| 17-reconfiguration.md | Backend state changes, updates, and disruption analysis |
| 18-health.md | Active health probing and the VRF isolation requirement |
| 19-control-plane.md | Control-plane responsibilities, map access, and reconciliation |
| 20-configuration-validation.md | Rejected and warned configuration combinations |
| 21-active-active.md | Cross-instance `hash_key` and `table_seed` agreement |
| 22-observability.md | Enumerated drop reasons and per-signal counters |
| 23-mtu.md | MTU strategy, MSS clamping, and frame-size checks |
| 24-testing.md | Packet-level, integration, and hard-to-test areas |
| 25-rejected.md | Rejected designs and mechanisms, with reasons |
| 26-superseded.md | Superseded design claims, corrected in later sections |
| 27-source-filtering.md | ACL matching, precedence, evaluation, and lockout risk |
| 28-rate-limiting.md | Token-bucket rate limiting design and update algorithm |
| 29-versions.md | Minimum kernel and toolchain version requirements |
| 30-quic.md | QUIC connection-ID steering: wire format, ABI, and the backend contract |
