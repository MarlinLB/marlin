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
   A chain terminating in ESP or AH is `unsupported_proto`; Marlin cannot reach the ports.

   `IPPROTO_FRAGMENT` in the chain marks the packet as a fragment, which is what makes the
   client-address-only hashing of `docs/design/12-selection.md` implementable for IPv6 — the
   equivalent of IPv4's `frag_off`.
   A non-first fragment carries no L4 header in either family, so `sport` and `dport` stay
   zero and the VIP lookup falls to the port-agnostic retry below.
3. **ACL** — `marlin_acl()`. An allow match admits and suppresses step 5; a block match drops
   with reason `acl_blocked`. `docs/design/27-source-filtering.md`.
4. **VIP lookup** — `vip_map` → `vip_num`, `flags`, `hash_key`. Miss → `XDP_PASS`.
5. **Rate limit** — `marlin_ratelimit()`, if `VIP_RATELIMIT` is set and step 3 did not admit
   explicitly. Over budget → drop `ratelimited`. `docs/design/28-rate-limiting.md`.
6. **Resolve** — hash, `fwd_table`, `backends`, in `balancer.c`. `docs/design/12-selection.md`.
7. **Validity and state** — `backend_id == 0` → drop `no_backend`;
   `state != MARLIN_UP` → drop `backend_down`.
8. **Dispatch** on `backend.mode`:
   - `L2DSR` → rewrite destination MAC; `XDP_TX`, or `XDP_REDIRECT` where `docs/design/16-fib-lookup.md` resolves the
     backend out another interface
   - `IPIP` → `docs/design/14-forwarding-modes.md`
   - `GUE` → `docs/design/14-forwarding-modes.md`
   - `VXLAN` → `docs/design/14-forwarding-modes.md`; alone among the modes this step also
     writes the frame's **outer** Ethernet header, because it consumes the arriving one as the
     inner header (§7.4)
9. **Next hop** — `docs/design/15-nexthop-l2dsr.md`, `docs/design/16-fib-lookup.md`.

Steps 1–7 are identical for all four modes. Steps 8 and 9 both diverge on `backend.mode`:
step 8 between the three encapsulation units and L2 DSR's empty case, step 9 between
`marlin_nexthop_l2dsr()` and `marlin_nexthop_encap()` — and, inside the latter, once more on
whether the MAC-swap default applies, which it does for IPIP and GUE and does not for VXLAN
(`docs/design/15-nexthop-l2dsr.md`).

**Why the ACL precedes the VIP lookup.** A VIP miss is `XDP_PASS` to the local stack, so ahead
of the lookup the ACL is a host firewall as well as a VIP firewall — a blocked source cannot
reach the Marlin host itself. The consequence is that a blocklist entry can lock an operator
out; the unconditional allow precedence in `docs/design/27-source-filtering.md` is what makes an
allowlist entry for the management prefixes an escape hatch that no block can override.

**Why the rate limiter follows it.** It needs `vip_meta.flags` to know whether it applies, and
metering ahead of the lookup would charge host-bound traffic — SSH, BGP, the control plane's own
probes — against a client's bucket and shed it under load. Host-bound traffic leaves at step 4
as a VIP miss and is never metered.

**The two filtering steps are therefore split across the lookup between them.** Step 3 is
evaluated in `marlin_balance()` itself, before the stage function covering steps 4-8, so a
blocked source is dropped having cost the entry point's single `config` lookup — which every
packet pays regardless (`docs/design/04-calling-convention.md`) — and at most two trie lookups. No VIP lookup, no `vip_stats`
write. Because an allow verdict suppresses step 5, it has to outlive
step 4, and it does so on `marlin_ctx.acl_verdict` (`docs/design/04-calling-convention.md`) rather than as an argument threaded
through a stage function that has no other use for it. An allow must remain distinguishable
from "no rule matched" for exactly this reason (`docs/design/27-source-filtering.md`).

One consequence for `docs/design/22-observability.md`: `vip_stats` counts packets that matched a VIP including those the
rate limiter then drops, but not those the ACL blocked, since those never reach step 4. Per-VIP
attribution of blocked volume does not exist, which is consistent with `acl_blocked` being
instance-scoped.

**Port-agnostic VIPs.** A VIP configured with `port == 0` matches any port. `vip_map` is
consulted twice: first with the parsed destination port, then with port 0 on a miss. Both
lookups use a fully zeroed key.

## Pointer invalidation

`bpf_xdp_adjust_head()` invalidates `data` and `data_end`. Both must be re-read after any
header adjustment and before further packet access. This is the most likely source of
verifier rejections in the encapsulation paths and is stated here rather than repeated per
mode.
