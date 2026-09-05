# Marlin — Forwarding Modes


## 7.1 L2 DSR

Rewrite the destination MAC to the backend's and leave the IP header untouched. `XDP_TX` where
the backend's segment is the ingress segment, which is the common case; where the FIB fallback
below resolves the backend out another interface, `XDP_REDIRECT` via `tx_ports` (`docs/design/16-fib-lookup.md`). The
packet still carries the VIP as destination, so the backend must hold the VIP on a loopback or
dummy interface with ARP/NDP suppression. Replies go directly to the client and never traverse
Marlin.

- No packet growth and the lowest latency of the four modes. MTU exposure is not quite nil:
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
  why GUE — and, sharing the same UDP outer header, VXLAN (§7.4, below) — exist as modes.

Backend side: `ipip` for IPv4 inner (protocol 4), `sit` for IPv6 inner (protocol 41). A
backend serving both inner families needs both devices.

## 7.3 GUE

Outer IPv4, then UDP, then a 4-byte GUE header carrying the inner IP protocol number.
Destination port is `backend.encap_dport` or 6080. Overhead 32 bytes.

**Outer UDP source port — the entropy field.** Once encapsulated, everything a router can see
is identical for every packet to a given backend: same source address, same destination
address, UDP. Routers hash those fields to choose among equal-cost paths, and the backend NIC
hashes them to choose a receive queue, so without variation all traffic to a backend follows
one path and lands on one CPU. This is not particular to GUE: every encapsulating mode whose
outer header includes UDP has the same exposure, which is VXLAN as well as GUE (§7.4, below).
Both share the fix — the UDP source port is 16 bits nothing else needs, so it carries a value
derived from the inner connection:

- **Different connections → different values**, spreading them across paths and queues.
- **Same connection → the same value every time**, so its packets keep one path and do not
  reorder.

Both modes use their own hash over the inner 5-tuple (`marlin_ctx.tuple`), distinct from the
selection hash, which deliberately uses the client address only. Reusing the selection hash
here would collapse all of one client's connections onto a single path and a single receive
queue, discarding the reason to choose a UDP-encapsulating mode over IPIP in the first place.

The entropy hash degrades to whatever fields are readable. Inner fragments have no ports, so
their fragments spread across paths and may reorder slightly before the backend reassembles —
same backend either way, so reordering rather than misrouting.

Backend side: one FOU/GUE listener on the configured port. GUE carries the inner protocol in
its own header, so a single listener covers both inner families — but the kernel demultiplexes
into the protocol-4 and protocol-41 receive paths, so the corresponding tunnel receive devices
(or the `tunl0`/`sit0` fallbacks) must still exist. GUE removes the second *listener*, not the
second device.

## 7.4 VXLAN

Outer IPv4, then UDP, then an 8-byte VXLAN header (RFC 7348): flags (1 byte, with the `I` bit —
0x08 — set to mark the VNI valid), reserved (3 bytes), VNI (3 bytes), reserved (1 byte).
Destination port is `backend.encap_dport` or 4789. Overhead is **50 bytes** — outer IPv4 (20) +
UDP (8) + VXLAN (8) + inner Ethernet (14) — the largest of the three encapsulating modes, and
materially more than IPIP's 20 or GUE's 32, because VXLAN encapsulates an Ethernet frame rather
than an IP packet.

That distinction is what the rest of this section is about. IPIP and GUE prepend headers in
front of the client's IP packet; VXLAN prepends headers in front of the client's IP packet
**and** a 14-byte Ethernet header ahead of that, because the backend's `vxlan` device expects to
receive a frame, not a bare IP packet.

**The VNI comes from `backend.vni`** (`docs/design/08-types.md`), a per-backend configuration
value rather than anything derived from the packet. It identifies the overlay network the
backend's `vxlan` device is bound to; Marlin does not interpret it beyond writing it into the
header.

`backend.vni` is a **host-order** `__u32` holding a plain 0…0xFFFFFF integer, unlike `addr` and
`encap_dport`, which the control plane stores already in wire order. `vxlan_encap.c` converts,
in one 4-byte store of `bpf_htonl(vni << 8)` covering the header's 3-byte VNI and the reserved
byte behind it, which the shift zeroes.

The asymmetry is deliberate. `types.h` is mirrored by hand (`docs/design/06-map-abi.md`), so a
wire-ready pre-shifted field would put the shift in the hand-written C# declaration, where
nothing checks it and a forgotten `<< 8` sends a zero VNI with the operator's value stranded in
the reserved byte. A plain integer keeps the only tricky step in compiled, tested datapath
code. "High byte" — in `docs/design/08-types.md`'s comment and in
`docs/design/20-configuration-validation.md`'s rule — accordingly means the value's high byte,
`vni & 0xFF000000`, not a byte position in the struct.

**The inner Ethernet header is the arriving frame's own header, relocated and partially
rewritten, not a new header constructed from nothing.** The frame Marlin received already
carries an Ethernet header — source the upstream router, destination Marlin's own MAC — sitting
directly in front of the IP packet that is being encapsulated. Prepending the outer headers
pushes that same 14 bytes deeper into the frame, where it becomes the inner Ethernet header,
rather than allocating a second one. Its two addresses are then corrected for their new
position: the destination is overwritten with **`backend.inner_mac`**, the overlay address
configured for that backend (`docs/design/08-types.md`) — the arriving frame's destination was
Marlin's own MAC, which means nothing inside the overlay — and the source is overwritten with
Marlin's own MAC — the same value the outer header takes as *its* source, below — so that the
frame's inner origin is Marlin's VTEP identity rather than the upstream router's, which likewise
means nothing inside the overlay. The inner EtherType is left as the arriving
frame set it, `ETH_P_IP` or `ETH_P_IPV6`, and that is what lets one `vxlan` device carry both
inner families: the receiving kernel demultiplexes on it, the way GUE demultiplexes on its own
header field rather than on which listener received the packet.

**The outer Ethernet header is written by `vxlan_encap.c`, not by the step-9 MAC swap.** This is
the one place VXLAN cannot share the encapsulating modes' next-hop default
(`docs/design/15-nexthop-l2dsr.md`), and the paragraph above is the reason: that default swaps
the arriving frame's source and destination, and under VXLAN the arriving frame's Ethernet
header is no longer there to swap. It has become the inner header and both its addresses have
been overwritten, so the upstream router's MAC — which the outer destination must be — exists
nowhere in the frame by the time step 9 runs (`docs/design/11-pipeline.md`, step 8 precedes step
9).

`vxlan_encap.c` therefore reads both arriving addresses **before** `bpf_xdp_adjust_head()`,
carries them across the call as values — copies, not pointers, so the rule against holding a
packet pointer across a header adjustment is not in play — and writes them into the outer header
at the new frame start: destination the arriving source, which is the router; source the
arriving destination, which is Marlin's own MAC and is the same value the inner header's source
takes. The outer header ends up carrying exactly what the swap would have produced, one step
earlier and out of saved values rather than out of bytes that no longer hold them.

Two consequences, stated rather than left to be rediscovered:

- **The ordering inside `vxlan_encap.c` is load-bearing.** Both arriving addresses must be read
  before either is overwritten. An implementation that rewrites the inner header first destroys
  the router's MAC and has nothing left to address the outer header with — a failure no other
  mode can produce, because no other mode consumes the arriving header.
- **The FIB path is unaffected.** Where `bpf_fib_lookup()` resolves the next hop it supplies
  `smac` and `dmac`, and those overwrite the outer header exactly as under IPIP and GUE
  (`docs/design/16-fib-lookup.md`). Only the zero-lookup MAC-swap default needed the exception;
  the paths converge again immediately after it.

**`encap_dport` defaults to 4789** (IANA-assigned), the same field GUE uses for its own default
of 6080 (`docs/design/08-types.md`) — one field, two per-mode defaults, rather than a second
field for the same purpose. The trap worth stating plainly: the Linux `vxlan`
netdev has historically defaulted to UDP port **8472**, not 4789, so a backend's `vxlan` device
and any host probe device (`docs/design/18-health.md`) must both be given `dstport 4789`
explicitly. A device left at its kernel default silently fails to match what Marlin sends,
indistinguishable at the datapath from a missing device.

**The outer UDP source port carries the same entropy hash as GUE, above** — derived from
`marlin_ctx.tuple`, never the selection hash, and for the identical reason: without it, every
packet to one VXLAN backend would present an identical outer tuple to routers and to the
backend's NIC, collapsing every connection onto one path and one receive queue.

**Backend side: one `vxlan` device**, matching the configured VNI and `dstport`. This is where
VXLAN costs less than what it replaces: IPIP needs `ipip` and `sit` as separate devices for its
two inner families (§7.2, above), and GUE needs its single listener paired with both the
`tunl0`/`sit0`-style receive devices GUE itself does not remove (§7.3, above). VXLAN needs
neither split, because the inner EtherType in the inner Ethernet header — not the outer
encapsulation, not a receiving device's type — is what tells the kernel which family the
decapsulated packet is. One device, one listener, both families.

## 7.5 Inner and outer address families

An encapsulated packet has two families:

- **Inner** — the client's original packet, addressed to the VIP. Either family.
- **Outer** — the tunnel from Marlin to the backend. **IPv4 only** (`docs/design/01-scope.md`).

They therefore differ whenever a VIP serves IPv6 clients, which is the normal case: IPv6
inner over IPv4 outer is a required combination, not an optional one.

Fixing the outer family at IPv4 removes the `ip6tnl` cases, halves the encapsulation code
paths, keeps the tunnel destination in `struct backend` at 4 bytes rather than 16, and
eliminates the zero-UDPv6-checksum problem entirely (see Checksums, below).

## 7.6 Checksums

`bpf_l3_csum_replace()` and `bpf_l4_csum_replace()` are tc-only and unavailable in XDP.
Checksum arithmetic is done by hand in `csum.h`; `bpf_csum_diff()` is available in XDP and is
used where a diff is cheaper than recomputation.

- **Outer IPv4 header checksum** is computed over known fields — cheap and exact.
- **Outer UDP checksum, GUE and VXLAN,** may be zero. With an IPv4 outer this is
  unconditionally permitted for both, so Marlin emits zero and the receiver requires no special
  configuration. This is a direct benefit of the IPv4-only outer decision; an IPv6 outer would
  have required RFC 6935/6936 handling and matching receiver configuration for both.
- **Inner headers are never modified under IPIP or GUE**, so no inner checksum is ever
  recomputed for either. VXLAN is the exception: its inner Ethernet header's destination and
  source addresses are written (§7.4, above), so "never modified" no longer holds for every
  mode. The checksum half of the claim survives regardless, for an unrelated reason — Ethernet
  carries no header checksum for a datapath to recompute; the frame check sequence is a
  hardware concern below the layer Marlin touches — so there is no inner checksum arithmetic to
  add even where the inner header's addresses change.
