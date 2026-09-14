# Marlin — MTU and Fragmentation


**Strategy:** jumbo frames on the Marlin→backend path, or TCP MSS. Marlin does not generate
ICMP "fragmentation needed" or "packet too big"; it forwards errors generated elsewhere
(`docs/design/13-icmp.md`).

Encapsulation only occurs Marlin→backend, and Marlin never receives encapsulated traffic —
there is no reverse path. Client-facing ingress is therefore always ≤ 1500 bytes and XDP
multi-buffer never applies.

**MSS clamping must happen on the backend, not on Marlin.** The encapsulated direction is
client→backend, so limiting those packets means reducing the MSS the *backend* advertises in
its SYN-ACK — and in DSR modes the SYN-ACK never traverses Marlin. This is a backend
provisioning requirement: `advmss` on the route, or setting the tunnel device MTU and letting
the kernel derive the advertised MSS.

**What remains uncovered.** MSS applies only to TCP. QUIC is unaffected in practice: 1200-byte
datagrams with DPLPMTUD sit below 1500 even with VXLAN's 50 bytes of overhead, now the worst
case among the three — 1250 is still comfortably under 1500. Large non-QUIC UDP
is covered only by jumbo frames.

`RET_FRAG_NEEDED` is counted rather than merely dropped, which is what makes the
misconfiguration diagnosable (`docs/design/22-observability.md`). `mtu_result` — the MTU value
`bpf_fib_lookup()` writes back over the same field on this return code — is not recorded:
`drop_stats` holds counts, not values, and the MTU is already visible in the route that
produced it.

**`RET_FRAG_NEEDED` does not cover the default path.** The zero-lookup next-hop default — MAC swap under IPIP
and GUE, `vxlan.c`'s own outer header under VXLAN (`docs/design/15-nexthop-l2dsr.md`) —
performs no FIB lookup, so `RET_FRAG_NEEDED` never fires there. The datapath
therefore checks the emitted frame against `config.max_frame` before transmitting, and drops
with reason `frame_too_big`. A 1500-byte inner packet leaves as 1532 under GUE and, as the new
worst case, 1550 under VXLAN; without this check the NIC or the first switch discards it and
Marlin's counters show a normal forward.

**The check lives in `include/marlin/mtu.h`'s `marlin_frame_fits(const struct marlin_ctx
*mctx, __u16 overhead)`**, returning `MARLIN_OK` or `MARLIN_DROP_FRAME_TOO_BIG`. It compares
`mctx->pkt_len + overhead > cfg.max_frame`, both sides already including `ETH_HLEN` —
`parser.c` sets `pkt_len` to the whole ingress frame length, and `max_frame` is "egress MTU +
ETH_HLEN" (`docs/design/08-types.md`) — so neither side needs adjusting before the comparison.
Each encapsulation unit calls it once, with its own `MARLIN_OVERHEAD_*` constant, **before**
`bpf_xdp_adjust_head()` and before anything updates `pkt_len`: the check is meaningless against
a `pkt_len` that already reflects the growth it exists to catch. `mtu.h` is a header rather
than a translation unit for the same reason `stats.h` and `entropy.h` are
(`docs/design/03-translation-units.md:50-55`) — it takes only `mctx`, a BTF struct pointer
already resolved by the caller, and reads no packet bytes.

The check is per-instance rather than per-next-hop, so it catches the ordinary single-egress
case; an asymmetric-MTU fabric remains covered only by the FIB path. `max_frame == 0` disables
it, so an instance whose control plane has not yet written `config` forwards rather than
dropping every encapsulated packet — which is why `docs/design/20-configuration-validation.md` validates that it is set.
