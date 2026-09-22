# Changelog

All notable changes to `marlin.bpf.o` will be documented in this file. Versioned in
`data-plane/bpf/VERSION`. See the root `CHANGELOG.md` for how this fits the other components.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Implement the load-balancer core in `lb_core.c`. With this translation unit (TU), `balancer.c`
  TU can be decomissioned. The `lb_core` TU is responsible for VIP lookup, ACL enforcement,
  backend selection (including QUIC steering) and DSCP marking.
- Add operator-controlled per-VIP outer DSCP marking for IPIP, GUE and VXLAN. `vip_meta.flags`
  bits 16-21 (`VIP_DSCP`) hold a six-bit codepoint, `0` (CS0) by default and byte-identical to
  every frame emitted before this field existed. `struct vip_meta` does not grow.
- `lb_core.c` copies the VIP's `VIP_DSCP` bits into `marlin_ctx.flags` before dispatching to
  the three encapsulation units; `marlin_ctx` stays 104 bytes. L2 DSR is unaffected — the copy
  happens only on the encapsulating arm.
- `ipip.c`, `gue.c` and `vxlan.c` each write the resolved DSCP, shifted `<< 2`, into the outer
  IPv4 header's `tos` byte before computing the outer checksum. The field is six bits wide, so
  no configuration can set the ECN pair.
- `nexthop.c` seeds `bpf_fib_lookup()`'s `fib.tos` from the same value, so a policy-routing rule
  matching `dsfield` resolves the next hop the way the wire will actually see the frame.
- This is not a copy of the client's own DSCP or ECN, and it is not the RFC 6040 ECN-remapping
  work `docs/design/14-forwarding-modes.md` excludes — a configured value needs neither an
  inner-header read nor a remapping rule.
- Restrict the fragment/extension-header refusal below to the packet being forwarded: it no
  longer reaches a quoted header inside an ICMP error. A quoted first fragment whose Fragment
  header is immediately followed by another extension header — e.g. `Fragment → Destination
  Options → UDP` — was dropped as `icmp_unparseable` even with both ports present, although the
  quote is a whole, unfragmented packet with no head/tail to split. It parses again.
- Drop an IPv6 fragment, head or tail, as `unsupported_proto` when its Fragment header is
  immediately followed by another extension header. The Fragment header's Next Header field is
  the first header of the Fragmentable Part (RFC 8200 §4.5), not necessarily the upper-layer
  protocol, so a tail stopping there and a head walking past it could resolve `tuple.proto`
  differently for the same datagram and key `vip_map` on two different protocols.

## [0.2.0] - 2026-09-17

- `marlin_ipv4_csum` sums the header as raw 16-bit words instead of taking a second 20-byte
  copy and summing it byte-wise; `marlin_vxlan_write_outer` stores each outer header right
  after building it instead of batching all four stores at the end, and
  `marlin_vxlan_build_outer_eth` now writes directly into the packet instead of staging a
  local `struct ethhdr`. No behaviour change; the combined stack frame shrinks from 88 to 32
  bytes for `marlin_vxlan_encap_packet`, from 32 to 16 for `marlin_ipip_encap_packet`, and
  from 24 to 8 for `marlin_gue_encap_packet`.

## [0.1.3] - 2026-09-17

- Split the `marlin_vxlan_encap_packet` function into multiple functions that are inlined by the
  compiler.

## [0.1.2] - 2026-09-17

- Split `marlin_gue_encap_packet` into `static __always_inline` helpers
  (`marlin_gue_validate`, `marlin_gue_build_outer_eth`, `marlin_gue_build_outer_ipv4`,
  `marlin_gue_build_outer_udp`, `marlin_gue_build_gue_hdr`, `marlin_gue_write_outer_l3`,
  `marlin_gue_write_outer_l4`) for readability. No behaviour change; the combined stack frame
  shrinks from 56 to 24 bytes, since each header's store now happens right after it is built
  instead of all four surviving live to a batched end.

## [0.1.1] - 2026-09-17

- Split `marlin_ipip_encap_packet` into `static __always_inline` helpers
  (`marlin_ipip_validate`, `marlin_ipip_build_outer_eth`, `marlin_ipip_build_outer_ipv4`,
  `marlin_ipip_write_outer`) for readability. No behaviour change; the combined stack frame
  is unchanged at 32 bytes.

## [0.1.0] - 2026-09-17

- Label the parser's `not_forwarded` and `icmp_echo` passes as early returns rather than parse
  failures in the `MARLIN_DEBUG` trace, and report the resulting XDP action with the code.

## [0.0.3] - 2026-09-16

- Replace the rate-limit clock-skew tolerance in the rate limiter with reading bucket state before
  sampling time on every CAS attempt, closing the same bypass without a fixed skew window.

## [0.0.2] - 2026-09-16

- Fix a rate-limit bucket refilling to burst when a losing CAS retry's clock sample read
  slightly behind a concurrent CPU's winning exchange; the loser now re-samples the clock per
  retry and tolerates the resulting skew instead of treating it as a 32-bit wrap.
- Drop ESP and AH non-first fragments as `unsupported_proto` in both families, matching the
  unfragmented head instead of admitting the tail.

## [0.0.1] - 2026-09-16

- Implement the DSR load balancing mechanism.
- Implement support for the following forwarding modes:
  - GUE;
  - IP in IP;
  - VXLAN;
  - L2 DSR.
- Implement traffic control via IP based ACL.
- Prevent DDoS via rate limiting.
