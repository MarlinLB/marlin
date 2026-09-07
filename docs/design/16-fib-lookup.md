# Marlin — Next-hop Resolution: bpf_fib_lookup()

## `bpf_fib_lookup()`

Also used where backends are reached via a different interface than ingress. The destination is
always `backend.addr`, in every mode — the outer tunnel destination for IPIP, GUE and VXLAN, the
backend's segment address for L2 DSR — so the lookup is `AF_INET` throughout. Set `ifindex` to
the ingress interface and call with flags `0`, or optionally `BPF_FIB_LOOKUP_DIRECT` to skip
policy rules. On success the helper returns egress `ifindex`, `smac`, `dmac` and `mtu_result`.
Then `XDP_TX` if egress equals ingress, otherwise `XDP_REDIRECT` via `tx_ports`.

**`RET_SUCCESS` includes gatewayed routes, and L2 DSR must reject them.** `dmac` is the next
hop's MAC either way — the backend's where the route is on-link, a router's where it is not.
The two are told apart by the helper's *conditional* write-back: on an IPv4 gateway it assigns
`ipv4_dst = nhc_gw.ipv4`; on an IPv6 gateway for an IPv4 route (RFC 5549) it sets
`family = AF_INET6` and writes the `ipv6_dst` arm of the union; on a directly connected route it
writes neither and `ipv4_dst` still holds the seeded value. So the datapath tests `family` and
then `ipv4_dst` against `backend.addr` — a check for "did the helper overwrite my seed", not a
read of a returned field. Stated precisely because the distinction does not show in the outcome
and the imprecise version invites a future reader to rely on an unconditional write that does not
exist. The behaviour is stable across the range in Appendix A. For IPIP, GUE and VXLAN a gateway is the point — the outer
header is addressed to `backend.addr` and the router forwards it onward. Under L2 DSR the frame
is not encapsulated and still carries the VIP, so a router receiving it routes on the VIP, which
is anycast to Marlin. The packet returns, is balanced again and leaves again: a loop bounded by
the outer TTL rather than a drop. L2 DSR therefore drops `fib_gatewayed` when the returned
next hop differs from `backend.addr`. This is what makes `docs/design/14-forwarding-modes.md`'s "directly attached" requirement
enforced rather than merely stated.

**`backend.egress_ifindex` validates, it does not steer.** On every path that emits a frame —
including the `NO_NEIGH` fallback below, and the L2 DSR stored-MAC and encapsulation
zero-lookup fast paths, which hold no FIB result at all — a recorded expectation is compared
against an actual egress: the `ifindex` the FIB returned where there was a lookup, the ingress
interface where there was not, since those paths commit to `XDP_TX` out of it. A difference
increments `egress_mismatch`. Not on the drop paths, which hold a valid `ifindex` too: a packet
dropped `fib_gatewayed` or `fib_no_neigh` already carries a reason naming its cause, and a
second counter would double-report one event. The FIB result is authoritative and the mismatch never changes the verdict:
a stale expectation must be visible without becoming an outage. Zero means no expectation was
recorded and the check is skipped. This counter is what makes `MARLIN_BE_F_FIB` safe to depend
on — the flag is control-plane belief about reachability, and this is how belief that is wrong
in the direction that still forwards becomes observable rather than silent.

The counter is bumped before the `tx_ports` resolution below, so it is not a guarantee that the
frame left: a mismatch on an interface missing from `tx_ports` increments `egress_mismatch` and
then drops `no_tx_port`. That ordering is deliberate — the mismatch is a fact about the lookup,
and suppressing it on a subsequent failure would hide the more diagnostic of the two signals.

**Not `BPF_FIB_LOOKUP_OUTPUT`.** That flag makes `ifindex` an *egress* constraint
(`flowi4_oif`) rather than lookup context, so the route is forced back out the ingress
interface: a backend reachable only elsewhere either fails or silently follows a less specific
route out the ingress device, and the returned `ifindex` can never differ from the one passed
in, which leaves `tx_ports` unreachable. The helper also rejects `ifindex` `0`, so the flag
cannot be used to discover an egress interface at all — only to resolve a next hop within one
already chosen. `samples/bpf/xdp_fwd_kern.c` and Cilium both take the ingress perspective for
this reason.

| Return code | Handling |
|---|---|
| `BPF_FIB_LKUP_RET_SUCCESS`, next hop == `backend.addr` | write MACs, transmit |
| `BPF_FIB_LKUP_RET_SUCCESS`, next hop != `backend.addr` | IPIP, GUE and VXLAN: write MACs, transmit. L2 DSR: drop `fib_gatewayed` |
| `RET_NO_NEIGH`, L2 DSR, next hop on-link, egress == ingress, `backend.mac` set | write the stored MAC, `XDP_TX`, count `neigh_fallback` |
| `RET_NO_NEIGH`, otherwise | drop `fib_no_neigh`; passing cannot resolve it in any mode (below) |
| `RET_FWD_DISABLED` | drop `fib_fwd_disabled`; integrator prerequisite |
| `RET_BLACKHOLE` | drop `fib_blackhole` |
| `RET_UNREACHABLE` | drop `fib_unreachable` |
| `RET_PROHIBIT` | drop `fib_prohibit` |
| `RET_FRAG_NEEDED` | drop `frag_needed`; see `docs/design/23-mtu.md` |

XDP cannot trigger ARP or NDP resolution, so `RET_NO_NEIGH` cannot be resolved in the
datapath. The next-hop set is small and stable, so the control plane keeps those neighbours
pinned (`nud permanent`) or probes them periodically, reducing `NO_NEIGH` to a startup
transient. This is why the control plane needs `CAP_NET_ADMIN` (`docs/design/02-architecture.md`).

**One case answers it without resolution: a flagged L2 DSR backend that turns out to be on the
ingress segment.** Such a backend reached the helper only because `docs/design/19-control-plane.md` sets `MARLIN_BE_F_FIB` on
everything it has not *confirmed* on that segment — so the flag expresses doubt, and a
`NO_NEIGH` whose next hop is on-link and whose egress interface is the ingress one resolves that
doubt in favour of the stored MAC. `backend.mac` is then exactly the answer the lookup was
trying to obtain, and the datapath uses it and counts `neigh_fallback` rather than dropping a
packet it can deliver. Reading `ifindex` here is sound because the *route* lookup succeeded and
only the neighbour lookup failed; the helper has returned the target ifindex in that case since
5.10, below the 6.0 floor in Appendix A. `smac` is not set, which costs nothing — egress equals
ingress, so the correct source is the frame's current destination, as on the fast path.

**The on-link test carries as much weight here as it does on `RET_SUCCESS`.** `NO_NEIGH` is
reachable for a gatewayed route, where the missing neighbour is the *router's* — and the gateway
has already been written into the lookup params by then, because that write precedes the
neighbour lookup that failed. Without the test, a gatewayed L2 DSR backend whose router's
neighbour entry happened to expire would take the fallback and emit to `backend.mac`, while the
same route with the entry present drops `fib_gatewayed`. An unrelated neighbour entry would
decide between a correct loud drop and a silent blackhole counted as a healthy fallback.

This narrows the control plane's neighbour obligation for L2 DSR rather than removing it. A
flagged backend that is genuinely off-segment, or one configured with no `backend.mac` at all,
still needs a resolvable neighbour or it drops.

**Passing does not resolve it in any mode.** Handing the frame to the stack works only where
the stack would look up the same neighbour — where the address this lookup asked about is also
the destination of the frame being passed. The lookup asks about `backend.addr`, and no mode's
frame is addressed to it. Under L2 DSR the frame carries the VIP, so the stack would
resolve the VIP's neighbour rather than the backend's — and the backend requirement in `docs/design/14-forwarding-modes.md`
suppresses ARP and NDP for the VIP, so that resolution has no answer either. Under IPIP, GUE and
VXLAN the frame reaching next-hop resolution is already the encapsulated one (`docs/design/11-pipeline.md` step 8 precedes step
9), sourced from `config.tunnel_src`; where that address is local to the Marlin host the
ingress path discards it as a martian source, because `bpf_fib_lookup()` applies no source
validation in either direction while `XDP_PASS` submits the frame to `ip_route_input()`, which
does. Reordering does not recover the pass for the encapsulation modes either, for the same
reason it fails under L2 DSR: the unencapsulated frame is addressed to the VIP. All modes
therefore drop and count, which makes an unpinned next hop visible instead of silently lossy.
