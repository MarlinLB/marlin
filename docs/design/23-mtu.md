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

`RET_FRAG_NEEDED` and `mtu_result` from `bpf_fib_lookup()` are counted rather than merely
dropped, which is what makes the misconfiguration diagnosable (`docs/design/22-observability.md`).

**They do not cover the default path.** The zero-lookup next-hop default — MAC swap under IPIP
and GUE, `vxlan.c`'s own outer header under VXLAN (`docs/design/15-nexthop-l2dsr.md`) —
performs no FIB lookup, so `RET_FRAG_NEEDED` never fires there. The datapath
therefore checks the emitted frame against `config.max_frame` before transmitting, and drops
with reason `frame_too_big`. A 1500-byte inner packet leaves as 1532 under GUE and, as the new
worst case, 1550 under VXLAN; without this check the NIC or the first switch discards it and
Marlin's counters show a normal forward.

The check is per-instance rather than per-next-hop, so it catches the ordinary single-egress
case; an asymmetric-MTU fabric remains covered only by the FIB path. `max_frame == 0` disables
it, so an instance whose control plane has not yet written `config` forwards rather than
dropping every encapsulated packet — which is why `docs/design/20-configuration-validation.md` validates that it is set.
