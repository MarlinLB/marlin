# Marlin — Forwarding Modes


## 7.1 L2 DSR

Rewrite the destination MAC to the backend's and leave the IP header untouched. `XDP_TX` where
the backend's segment is the ingress segment, which is the common case; where the FIB fallback
below resolves the backend out another interface, `XDP_REDIRECT` via `tx_ports` (`docs/design/16-fib-lookup.md`). The
packet still carries the VIP as destination, so the backend must hold the VIP on a loopback or
dummy interface with ARP/NDP suppression. Replies go directly to the client and never traverse
Marlin.

- No packet growth and the lowest latency of the three modes. MTU exposure is not quite nil:
  a backend taking the FIB path is subject to `RET_FRAG_NEEDED` against the egress interface's
  MTU, so an L2 DSR backend reached over a lower-MTU segment can drop `frag_needed` where the
  stored-MAC path would have transmitted (`docs/design/16-fib-lookup.md`, `docs/design/23-mtu.md`). Nothing is encapsulated, so there is no
  *added* overhead — but the check is real once the helper is involved.
- Requires backend and Marlin in a **directly attached** L2 broadcast domain — not necessarily
  the ingress one, but attached. The packet is not encapsulated, so a gateway in the path would
  route on the VIP rather than on the backend behind it; `docs/design/16-fib-lookup.md` rejects a
  gatewayed next hop under this mode rather than forwarding into that loop.
- No port translation.
- IPv4 and IPv6 identical apart from neighbour-discovery suppression.

MAC source: `backend.mac`, populated by the control plane, with `bpf_fib_lookup()` in its place
when the backend carries `MARLIN_BE_F_FIB` or when `backend.mac` is all-zero (`docs/design/15-nexthop-l2dsr.md`).

## 7.2 IPIP

Prepend an outer IPv4 header: source is `config.tunnel_src`, destination is `backend.addr`.
Next-header is 4 for an IPv4 inner packet and 41 for IPv6. The inner packet retains the VIP,
so the backend decapsulates and replies directly to the client.

- Overhead 20 bytes.
- Crosses L3 boundaries, unlike L2 DSR.
- All traffic to one backend shares a single outer tuple, so the underlay cannot spread it
  across equal-cost paths and the backend NIC cannot spread it across receive queues. This is
  why GUE exists as a mode.

Backend side: `ipip` for IPv4 inner (protocol 4), `sit` for IPv6 inner (protocol 41). A
backend serving both inner families needs both devices.

## 7.3 GUE

Outer IPv4, then UDP, then a 4-byte GUE header carrying the inner IP protocol number.
Destination port is `backend.gue_dport` or 6080. Overhead 32 bytes.

**Outer UDP source port — the entropy field.** Once encapsulated, everything a router can see
is identical for every packet to a given backend: same source address, same destination
address, UDP. Routers hash those fields to choose among equal-cost paths, and the backend NIC
hashes them to choose a receive queue, so without variation all traffic to a backend follows
one path and lands on one CPU. The UDP source port is 16 bits nothing else needs, so it
carries a value derived from the inner connection:

- **Different connections → different values**, spreading them across paths and queues.
- **Same connection → the same value every time**, so its packets keep one path and do not
  reorder.

This uses its own hash over the inner 5-tuple (`marlin_ctx.tuple`), distinct from the selection
hash, which deliberately uses the client address only. Reusing the selection hash here would
collapse all of one client's connections onto a single path and a single receive queue,
discarding the reason to choose GUE over IPIP.

The entropy hash degrades to whatever fields are readable. Inner fragments have no ports, so
their fragments spread across paths and may reorder slightly before the backend reassembles —
same backend either way, so reordering rather than misrouting.

Backend side: one FOU/GUE listener on the configured port. GUE carries the inner protocol in
its own header, so a single listener covers both inner families — but the kernel demultiplexes
into the protocol-4 and protocol-41 receive paths, so the corresponding tunnel receive devices
(or the `tunl0`/`sit0` fallbacks) must still exist. GUE removes the second *listener*, not the
second device.

## 7.4 Inner and outer address families

An encapsulated packet has two families:

- **Inner** — the client's original packet, addressed to the VIP. Either family.
- **Outer** — the tunnel from Marlin to the backend. **IPv4 only** (`docs/design/01-scope.md`).

They therefore differ whenever a VIP serves IPv6 clients, which is the normal case: IPv6
inner over IPv4 outer is a required combination, not an optional one.

Fixing the outer family at IPv4 removes the `ip6tnl` cases, halves the encapsulation code
paths, keeps the tunnel destination in `struct backend` at 4 bytes rather than 16, and
eliminates the zero-UDPv6-checksum problem entirely (see Checksums, below).

## 7.5 Checksums

`bpf_l3_csum_replace()` and `bpf_l4_csum_replace()` are tc-only and unavailable in XDP.
Checksum arithmetic is done by hand in `csum.h`; `bpf_csum_diff()` is available in XDP and is
used where a diff is cheaper than recomputation.

- **Outer IPv4 header checksum** is computed over known fields — cheap and exact.
- **GUE outer UDP checksum** may be zero. With an IPv4 outer this is unconditionally
  permitted, so Marlin emits zero and the receiver requires no special configuration. This is
  a direct benefit of the IPv4-only outer decision; an IPv6 outer would have required
  RFC 6935/6936 handling and matching receiver configuration.
- **Inner headers are never modified** in any mode, so no inner checksum is ever recomputed.
