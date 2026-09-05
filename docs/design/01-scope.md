# Marlin — Scope and Requirements


## Forwarding modes

| Mode | Inner families | Outer family | Backend requirement |
|---|---|---|---|
| L2 DSR | IPv4, IPv6 | n/a | VIP on loopback, ARP/NDP suppression, same L2 segment |
| IPIP | IPv4, IPv6 | IPv4 | `ipip` and/or `sit` tunnel device |
| GUE | IPv4, IPv6 | IPv4 | one FOU/GUE listener |
| VXLAN | IPv4, IPv6 | IPv4 | a `vxlan` device with the matching VNI and dstport |

Mode is a property of the individual backend. A single VIP may be served by backends using
different modes.

**Marlin holds no per-flow state.** All four modes are direct server return: backends reply
to clients without traversing Marlin.

**VXLAN's backend requirement is a hybrid of L2 DSR's and the encapsulating modes'.** The
`vxlan` device decapsulates to an ordinary Ethernet frame addressed to `backend.inner_mac`
(`docs/design/08-types.md`) and carrying the VIP as its IP destination — so, as under L2 DSR, the
backend must hold the VIP and suppress ARP/NDP for it (`docs/design/14-forwarding-modes.md`
§7.4), rather than simply owning a tunnel endpoint as IPIP and GUE backends do. What is not
derivable from the design documents as they stand is **where** the VIP must be configured
relative to the `vxlan` device — on a loopback or dummy interface as under L2 DSR, or on the
`vxlan` device itself, since that is where the decapsulated frame is delivered. This is left open
rather than guessed; see `PHASES.md`'s open-decision table, closed by Phase 2b.

## Targets

- Up to 100 VIPs, compile-time maximum.
- Close to line rate with minimum added latency. Native XDP is mandatory, not preferred.
- Minimum kernel 6.0.

## Source filtering and rate limiting

- Allow and block listing of source addresses and ranges, both families (`docs/design/27-source-filtering.md`).
- A per-source token bucket, enabled per VIP, enforced in the datapath (`docs/design/28-rate-limiting.md`).

## Non-goals

- **L3 NAT.** Removed from scope. Every mode is DSR, so every backend must be configurable.
  Backends that cannot be modified cannot be served. See `docs/design/25-rejected.md`.
- **L4-granular filtering.** ACL rules match an address or prefix only. A source is permitted
  or it is not, uniformly across every VIP and port. See `docs/design/25-rejected.md` for what
  reinstating this costs.
- **Stateful filtering.** No established/related matching; Marlin holds no per-flow state.
- **Userspace attack classification.** Rate limiting is same-packet and threshold-driven. See
  `docs/design/25-rejected.md`.
- Layer 7 processing, TLS termination, HTTP awareness.
- IPv6 underlay. Outer encapsulation family is IPv4 only; inner may be either.
- Port translation. DSR cannot rewrite ports.
- PROXY protocol — unnecessary, since DSR preserves the client address natively.
- Preserving connections across a datapath upgrade. Control plane upgrades are
  non-disruptive; datapath upgrades may drop connections.
