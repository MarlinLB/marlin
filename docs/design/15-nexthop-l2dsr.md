# Marlin — Next-hop Resolution: MAC Swap and L2 DSR


XDP emits a finished Ethernet frame, so the destination MAC must be supplied.

## MAC swap — default for IPIP and GUE

The packet arrived from the upstream router, so the frame already carries that router's MAC as
source and Marlin's as destination. Swap them and `XDP_TX`; the router routes the encapsulated
packet onward using its own table.

- No lookup, no state, backend reachable anywhere the router can reach.
- Requires Marlin and the router on the same segment — true in the standard BGP/ECMP anycast
  topology.
- The router must hairpin, routing back out the ingress interface. Normal for L3 interfaces;
  ICMP redirect generation should be suppressed. Some switch SVIs restrict same-interface
  forwarding and must be verified.
- Naturally symmetric with multiple uplinks: the encapsulated packet leaves via whichever
  router delivered it. There is no reply path — backends answer clients directly (`docs/design/01-scope.md`).

**VXLAN does not take this path.** Its encapsulation consumes the arriving Ethernet header as
the frame's *inner* header and overwrites both addresses, so by the time next-hop resolution
runs there is nothing left to swap and the router's MAC is gone. `vxlan.c` writes the
outer header itself, from addresses saved ahead of the header adjustment, reaching the same
result one step earlier (`docs/design/14-forwarding-modes.md` §7.4). `marlin_nexthop_encapsulate()`
therefore applies the swap above for IPIP and GUE and skips it for VXLAN.

The FIB path below is common to all three regardless: where `bpf_fib_lookup()` resolves the next
hop it supplies both MACs, and those overwrite whatever the encapsulation unit wrote.

## L2 DSR — stored MAC, with FIB fallback

L2 DSR cannot MAC-swap: the destination is the backend itself, not a router.

1. `MARLIN_BE_F_FIB` set → `bpf_fib_lookup()` on `backend.addr`. Checked *first*, ahead of the
   stored MAC, and `mac_fallback` is not incremented — nothing has fallen back.
2. `backend.mac` non-zero → use it. No lookup.
3. `backend.mac` all-zero → `bpf_fib_lookup()` on `backend.addr`, and increment `mac_fallback` —
   except when `backend.addr` is also zero, where rule 4 below drops `backend_unresolved` before
   the counter is reached. The suppression exists so the one misconfiguration is not
   double-reported under two reasons.
4. `backend.addr` zero on any path that reaches the lookup → drop `backend_unresolved`. Note
   this is `addr` alone, not "both zero": a flagged backend goes to the helper with its MAC
   resolved and unread, so a missing `addr` drops it even though a usable MAC exists. `docs/design/20-configuration-validation.md`
   rejects such a backend at configuration time, so the case should not arise; it is stated
   because the datapath does not assume that.

**Why the flag is checked before the stored MAC.** The stored MAC commits to `XDP_TX`. Nothing
in `backend.mac` records which interface it belongs on, and the source MAC written alongside it
is Marlin's on the *ingress* device — `bpf_redirect_map()` transmits the frame verbatim, so
that source address on another segment is a MAC move the adjacent switch sees and may drop on
port security. The egress device's own MAC is obtainable only from `bpf_fib_lookup()`, as
`smac`. A backend that may not be on the ingress segment therefore has to take the FIB path
*even when its MAC is resolved*, and the flag is how the control plane says so. Reading it
after the stored MAC would make the fast path unreachable for exactly the backends that need
the slow one.

Making the *stored-MAC path itself* redirect — by carrying an egress ifindex beside the MAC —
was considered and rejected: it would need the egress `smac` too, duplicating interface state
across every backend on that interface and creating an invalidation path on NIC MAC change, to
save one helper call on the minority of backends that are off-segment. The struct was widened
all the same, but for `egress_ifindex` as a *validation* field that never steers a packet
(below).

The control plane populates `backend.mac` from the kernel neighbour table via netlink and
refreshes it on neighbour change events. The fallback exists so that a control plane that has
not yet resolved a backend, or has lost track of one, degrades to working-but-slower rather
than failing. A persistently non-zero `mac_fallback` counter indicates the control plane is
not maintaining neighbours correctly.

**`backend.mac` is optional.** Nothing requires it: `docs/design/20-configuration-validation.md` rejects a backend with no `addr`, never
one with no `mac`, and an all-zero MAC is a defined state rather than an incomplete one. An
operator who is content to let the kernel resolve every next hop may configure backends with
addresses alone, and every L2 DSR packet then takes step 3 above. Two consequences to accept
deliberately rather than discover:

- **`mac_fallback` becomes the steady state and stops being a signal.** Its reading in `docs/design/22-observability.md` is
  "the control plane is not maintaining `backend.mac`", which is true of this deployment by
  choice. Monitoring should ignore it here, not alert on it.
- **`neigh_fallback` is unavailable**, because it answers from the stored MAC. A MAC-less
  backend has nothing to fall back to when the neighbour entry is missing, so `RET_NO_NEIGH` is
  an unconditional drop and the neighbour-freshness obligation of `docs/design/19-control-plane.md` applies in full.

The trade is fewer things for the control plane to keep correct against a hard dependency on
the kernel neighbour table. That is a reasonable choice where the backends are stable and the
segment is quiet; it is a poor one where `nud permanent` is not being maintained.

**The lookup is on `backend.addr`, never the VIP.** The VIP belongs to every backend in the
pool, so a neighbour resolved from it is unrelated to the backend the selection already chose —
and the backend requirement above puts the VIP on loopback with ARP/NDP suppression, so nothing
on the segment answers for it in any case. L2 DSR therefore requires `backend.addr` to carry
the backend's own address on the attached segment. That address is IPv4 (`__be32`), including
where the VIP is IPv6: the lookup exists to produce a neighbour on the segment, and an IPv4
neighbour forwards an IPv6 flow unchanged. Widening it to hold an IPv6 address would cost 12
bytes of the `docs/design/05-budgets.md` stack budget for no forwarding capability, which is a firmer reason than the
fixed struct size this argument used to rest on — `struct backend` is no longer fixed, but the
budget that constrains it is.
**An L2 DSR backend therefore needs an IPv4 address on the attached segment** — a deployment
prerequisite, see `DEPLOYMENT.md` §2.2.
