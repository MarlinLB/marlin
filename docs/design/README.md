# Marlin — Design

**Status:** design settled, pre-implementation
**Last updated:** 2026-08-20
**Revision:** 6 — source filtering and rate limiting incorporated (`27-source-filtering.md`,
`28-rate-limiting.md`); ICMP branch narrowed to replace step 2 only; health probes isolated in
a VRF

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
| 14-forwarding-modes.md | L2 DSR, IPIP, GUE modes, families, and checksums |
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
