# Marlin — Packet Pipeline


Single entry point. Because Marlin holds no per-flow state and backends reply directly to
clients, there is no reverse path and no classifier.

1. **Parse** L2 and L3. Determine L4 offset.
2. **Parse L4 far enough to obtain the destination port**, which `vip_key` requires. For
   ICMP, take the ICMP branch (`docs/design/13-icmp.md`).

   For IPv4 the L4 offset follows from `ihl`. **For IPv6 it does not:** hop-by-hop, routing,
   destination-options and fragment headers chain between the base header and L4, so the
   chain is walked to at most `MAX_EXT_HDRS` headers. Exceeding that bound drops with reason
   `ext_hdr_limit` rather than `parse_error`, so that an attacker padding a chain to force
   the loop to its bound is countable rather than indistinguishable from a malformed packet.
   **ESP or AH is `unsupported_proto` in both families, regardless of fragment state** —
   Marlin cannot reach the ports behind either, so a non-first fragment of an ESP or AH
   datagram carries the same verdict as the unfragmented packet; the check runs ahead of the
   fragment handling below rather than only at the head.

   `IPPROTO_FRAGMENT` in the chain marks the packet as a fragment, which is what makes the
   client-address-only hashing of `docs/design/12-selection.md` implementable for IPv6 — the
   equivalent of IPv4's `frag_off`. **The Fragment header's Next Header field is the first
   header of the Fragmentable Part (RFC 8200 §4.5), not necessarily the upper-layer protocol**
   — a head walks past a Destination Options header that follows it and resolves the real L4,
   while a tail stops at the Fragment header and takes its Next Header value as `tuple.proto`
   directly. Left alone, the two would key `vip_map` on different protocols for the same
   datagram, so any extension header found immediately behind a Fragment header is
   `unsupported_proto` for both halves — a second, broader case than the ESP/AH one above.
   The extension-header walk only records the shape; `marlin_parse()` is what refuses it,
   ahead of the fragment handling below, so it catches the head as well as the tail before
   either reaches `vip_map`. **This refuses only the packet Marlin forwards.** The same walk
   also parses the header an ICMP error quotes (`docs/design/13-icmp.md`), and there the
   refusal does not apply: a quote is a whole, unfragmented packet — the backend-to-client
   reply it reports on bypassed Marlin through DSR — so it has no head/tail to split.
   A non-first fragment carries no L4 header in either family, so `sport` and `dport` stay
   zero and the VIP lookup falls to the port-agnostic retry below. That retry resolves the
   packet only when a `port == 0` entry exists for its `(address, protocol)`; on a VIP
   configured with an explicit port and no such entry, both lookups carry the same zero
   port, so the fragment tail is `vip_miss` regardless of the VIP its first fragment
   reached (`docs/design/12-selection.md`, "Hash input").

   A UDP payload opening with a QUIC short header is flagged `MARLIN_CTX_F_QUIC` here, for
   step 6 to steer on — but only once the datagram's own declared UDP length, not merely
   `data_end`, leaves at least one payload byte; a header-only datagram's trailing frame padding
   must never be read as that byte. A long header is never flagged: RFC 9000 §9 forbids
   migrating before the handshake completes, so every long-header packet is safe on the hash path
   (`docs/design/30-quic.md`).
3. **ACL evaluate** — `marlin_acl_check()`. Produces allow, block or no-match on
   `marlin_ctx.acl_verdict`. Nothing is dropped here. `docs/design/27-source-filtering.md`.
4. **VIP lookup, then ACL enforcement** — `vip_map` → `vip_num`, `flags`, `hash_key`.
   - Miss: a block verdict drops `acl_blocked`; otherwise `XDP_PASS`, counted `vip_miss`.
     Enforcement is instance-scoped here, there being no VIP to read `VIP_ACL` from.
   - Hit with `VIP_ACL` set: a block verdict drops `acl_blocked`; an allow verdict suppresses
     step 5.
   - Hit with `VIP_ACL` clear: the verdict is discarded — neither the block nor the allow
     applies.
5. **Rate limit** — `marlin_ratelimit()`, if `VIP_RATELIMIT` is set and step 4 did not admit
   explicitly. Over budget → drop `ratelimited`. `docs/design/28-rate-limiting.md`.
6. **Resolve** — on a `VIP_QUIC` VIP, a `MARLIN_CTX_F_QUIC` packet decodes a `backend_id`
   from the connection ID and indexes `backends` directly, bypassing `fwd_table`
   (`docs/design/30-quic.md`); every other packet, and any decode failure, falls through to
   hash, `fwd_table`, `backends`, in `balancer.c` (`docs/design/12-selection.md`).
7. **Validity and state** — `backend_id == 0` → drop `no_backend`;
   `MARLIN_BE_F_STATE` clear in `backend.flags` → drop `backend_down`; a `pkt_len`/frame-length
   invariant violation → drop `encap_length` (`docs/design/23-mtu.md`).
8. **Dispatch** on `ENCAP_MODE(backend.flags)`:
   - `L2DSR` → rewrite destination MAC; `XDP_TX`, or `XDP_REDIRECT` where `docs/design/16-fib-lookup.md` resolves the
     backend out another interface
   - `IPIP` → `docs/design/14-forwarding-modes.md`
   - `GUE` → `docs/design/14-forwarding-modes.md`
   - `VXLAN` → `docs/design/14-forwarding-modes.md`; alone among the modes this step also
     writes the frame's **outer** Ethernet header, because it consumes the arriving one as the
     inner header (§7.4)
9. **Next hop** — `docs/design/15-nexthop-l2dsr.md`, `docs/design/16-fib-lookup.md`.

Steps 1–7 are identical for all four modes. Steps 8 and 9 both diverge on `ENCAP_MODE(backend.flags)`:
step 8 between the three encapsulation units and L2 DSR's empty case, step 9 between
`marlin_nexthop_l2dsr()` and `marlin_nexthop_encapsulate()` — and, inside the latter, once more on
whether the MAC-swap default applies, which it does for IPIP and GUE and does not for VXLAN
(`docs/design/15-nexthop-l2dsr.md`).

**Why evaluation precedes the VIP lookup and enforcement follows it.** The per-VIP gate is
`vip_meta.flags` bit 0, so nothing can be enforced per VIP ahead of the lookup that produces it.
Splitting the step is what keeps the host-firewall property with it: a VIP miss is `XDP_PASS` to
the local stack, and enforcing the block verdict on that path means a blocked source still cannot
reach the Marlin host itself. The consequence is that a blocklist entry can lock an operator out;
the unconditional allow precedence in `docs/design/27-source-filtering.md` is what makes an
allowlist entry for the management prefixes an escape hatch that no block can override.

**Clearing `VIP_ACL` does not restore host access.** The bit exempts one VIP's traffic; the
host-bound path of step 4 is enforced whatever any VIP's bit says, because that path has no VIP
to take a bit from. An operator locked out by their own blocklist cannot undo it by exempting
VIPs.

**Why the rate limiter follows it.** It needs `vip_meta.flags` to know whether it applies, and
metering ahead of the lookup would charge host-bound traffic — SSH, BGP, the control plane's own
probes — against a client's bucket and shed it under load. Host-bound traffic leaves at step 4
as a VIP miss and is never metered.

**The evaluation is still paid ahead of the lookup; no drop is, any longer.** Step 3 is evaluated
in `marlin_balance()` itself, before the stage function covering steps 4-8, so every packet pays
the entry point's single `config` lookup — which it pays regardless
(`docs/design/04-calling-convention.md`) — and at most two trie lookups, a packet bound for a
`VIP_ACL`-clear VIP included. What no blocked packet avoids any more is the VIP lookup itself:
host-bound traffic is only *identified* as host-bound by the step-4 miss, so even the drop that
protects the host is taken after the lookup. That cost is the price of the per-VIP gate, and it
falls on traffic an operator has chosen to block. The
verdict has to outlive step 4 for both of its consumers — the enforcement gate and step 5 — and
does so on `marlin_ctx.acl_verdict` (`docs/design/04-calling-convention.md`) rather than as an
argument threaded through a stage function that has no other use for it. An allow must remain
distinguishable from "no rule matched" for exactly this reason
(`docs/design/27-source-filtering.md`).

One consequence for `docs/design/22-observability.md`: `vip_stats` counts packets that matched a
VIP including those the rate limiter then drops, and now those the ACL blocks as well — the two
filters are treated alike because enforcement and metering are the same point in the pipeline.
`acl_blocked` is nonetheless still instance-scoped, because `drop_stats` carries no VIP dimension,
and no longer because no `vip_num` exists where the drop happens.

**Port-agnostic VIPs.** A VIP configured with `port == 0` matches any port. `vip_map` is
consulted twice: first with the parsed destination port, then with port 0 on a miss. Both
lookups use a fully zeroed key.

**A fragment tail's parsed destination port is always zero** (step 2 above), so for a tail
the two lookups are identical: there is no second, different key for the retry to try. An
explicit-port VIP with no `port == 0` companion therefore never admits a fragment tail, and
a `port == 0` VIP sharing the address admits it into a different `vip_num` than the head
reached — see `docs/design/12-selection.md`'s "Hash input" for why this is the same split
that section rejects as a hash input, arrived at instead through admission.

## Pointer invalidation

`bpf_xdp_adjust_head()` invalidates `data` and `data_end`. Both must be re-read after any
header adjustment and before further packet access. This is the most likely source of
verifier rejections in the encapsulation paths and is stated here rather than repeated per
mode.
