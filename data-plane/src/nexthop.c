/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Next-hop resolution. XDP emits a finished Ethernet frame, so the
 * destination MAC must be supplied here. Two global subprograms, one per
 * next-hop discipline: marlin_nexthop_l2dsr() uses the stored backend MAC
 * or falls back to bpf_fib_lookup(); marlin_nexthop_encapsulate() swaps the
 * arriving Ethernet addresses (IPIP and GUE only) or takes the same FIB
 * fallback. balancer.c dispatches between them on ENCAP_MODE(backend.flags).
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>

#include <bpf/bpf_helpers.h>

#include <marlin/marlin.h>
#include <marlin/maps.h>
#include <marlin/stats.h>
#include <marlin/nexthop.h>

/*
 * Which next-hop discipline is calling marlin_nexthop_fib(): a literal
 * argument at each of its two call sites, so the branch below folds at
 * compile time and neither entry point's independent verification walks
 * the other's path.
 */
enum marlin_nh_discipline {
    MARLIN_NH_ENCAP = 0,
    MARLIN_NH_L2DSR = 1,
};

/*
 * Re-derives eth: a caller may have called bpf_xdp_adjust_head()
 * beforehand, invalidating prior pointers.
 */
static __always_inline struct ethhdr *marlin_nexthop_eth(struct xdp_md *ctx)
{
    void *data = (void *)(unsigned long)ctx->data;         // NOLINT(performance-no-int-to-ptr)
    void *data_end = (void *)(unsigned long)ctx->data_end; // NOLINT(performance-no-int-to-ptr)
    struct ethhdr *eth = data;

    if((void *)(eth + 1) > data_end) {
        return NULL;
    }

    return eth;
}

/* All-zero backend.mac means "not resolved". */
static __always_inline int marlin_backend_mac_set(const struct backend *be)
{
    return (be->mac[0] | be->mac[1] | be->mac[2] | be->mac[3] | be->mac[4] | be->mac[5]) != 0;
}

/*
 * Writes the stored backend MAC and hands the frame back out the ingress
 * interface. Only correct when the frame leaves by the interface it
 * arrived on -- the caller's obligation to establish.
 */
static __always_inline void marlin_nexthop_store_mac(struct ethhdr *eth, const struct backend *be)
{
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, be->mac, ETH_ALEN);
}

/*
 * Was the next hop directly connected? bpf_fib_lookup() only overwrites the
 * seeded params on a gateway route (IPv4, or an RFC 5549 IPv6 gateway for
 * an IPv4 route); on an on-link route the seed survives, so this tests
 * whether it did.
 */
static __always_inline int marlin_fib_onlink(const struct bpf_fib_lookup *fib, __be32 backend_addr)
{
    return fib->family == AF_INET && fib->ipv4_dst == backend_addr;
}

/*
 * Diagnostic only: compares the FIB's chosen egress interface against the
 * control plane's expectation. Never changes the verdict -- the FIB result
 * is what actually gets used to forward the frame.
 */
static __always_inline void marlin_nexthop_check_egress(const struct backend *be, __u32 ifindex)
{
    if(be->egress_ifindex != 0 && be->egress_ifindex != ifindex) {
        marlin_count(MARLIN_COUNT_EGRESS_MISMATCH);
    }
}

/* plen below is sizeof(fib): the kernel rejects a plen smaller than its own
 * struct bpf_fib_lookup with -EINVAL, so this direction (a UAPI header
 * older than the running kernel) is the one to watch, not a newer one.
 */
_Static_assert(sizeof(struct bpf_fib_lookup) == 64,
               "struct bpf_fib_lookup no longer fits nexthop.c's share of the stack budget (docs/design/05-budgets.md)");

/*
 * bpf_fib_lookup() path: L2 DSR with an unresolved backend.mac, or an
 * encapsulation backend not reachable out the ingress interface.
 */
static __always_inline int marlin_nexthop_fib(struct xdp_md *ctx, struct marlin_ctx *mctx, struct ethhdr *eth,
                                              enum marlin_nh_discipline disc)
{
    struct bpf_fib_lookup fib;
    long rc;

    /* Always the backend's own address, never the VIP address -- the VIP
     * belongs to every backend behind it, so a neighbour resolved for it
     * would be unrelated to the backend already selected. Zero means
     * neither backend.mac nor backend.addr is resolved -- a control-plane
     * fault.
     */
    if(mctx->backend.addr == 0) {
        return MARLIN_DROP_BACKEND_UNRESOLVED;
    }

    __builtin_memset(&fib, 0, sizeof(fib));

    /* AF_INET in every mode, including an IPv6 VIP under L2 DSR: the outer
     * tunnel or attached-segment address is always IPv4. ipv4_src, tos,
     * l4_protocol, sport and dport are left zero -- inputs to policy
     * routing, which this lookup applies (flags 0, below). The correct
     * ipv4_src differs by mode -- the inner client address under L2 DSR,
     * cfg.tunnel_src under IPIP/GUE/VXLAN -- and nexthop.c is not among
     * cfg's readers (docs/design/04-calling-convention.md), so it is left
     * unset rather than seeded wrong. Same open decision as
     * BPF_FIB_LOOKUP_DIRECT below: which policy-routing inputs Marlin
     * supplies (docs/PHASES.md).
     */
    fib.family = AF_INET;
    fib.ipv4_dst = mctx->backend.addr;

    /* L3 length from the network header, which starts at ETH_HLEN
     * unconditionally: XDP emits an untagged frame (parser.c rejects
     * 0x8100 as not_forwarded), and VXLAN's outer Ethernet header is
     * written at offset 0 by vxlan.c, so this holds whether or not an
     * encapsulation unit ran first. mctx->l3_off is not usable here -- its
     * value after bpf_xdp_adjust_head() is unspecified by
     * docs/design/04-calling-convention.md. tot_len unions with
     * mtu_result, so this seed does not survive RET_FRAG_NEEDED.
     */
    fib.tot_len = (__u16)((ctx->data_end - ctx->data) - ETH_HLEN);
    fib.ifindex = ctx->ingress_ifindex;

    /* Ingress perspective (flags 0): the FIB picks the egress device from
     * the destination, which is what makes a backend reachable only out
     * another interface work. BPF_FIB_LOOKUP_DIRECT would instead skip
     * policy-routing rules (a direct table lookup) and is not used here --
     * an open decision, docs/PHASES.md.
     */
    rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);

    switch(rc) {
    case BPF_FIB_LKUP_RET_SUCCESS:
        break;
    case BPF_FIB_LKUP_RET_NO_NEIGH:
        /* XDP cannot trigger ARP/NDP, and XDP_PASS cannot resolve this
         * either -- the frame handed to the stack is never addressed to
         * the neighbour this lookup wanted. Fall back to the stored MAC
         * only when: the frame is L2 DSR, the route is on-link, the FIB's
         * ifindex is the ingress interface, and backend.mac is set. The
         * on-link test matters because NO_NEIGH is also reachable for a
         * gatewayed route, where the missing neighbour is the router's
         * and the stored MAC would be the wrong answer. fib.ifindex is
         * valid here since kernel commit d1c362e1dd68 (5.10, below
         * Marlin's 6.0 floor).
         */
        if(disc == MARLIN_NH_L2DSR && marlin_fib_onlink(&fib, mctx->backend.addr) && fib.ifindex == ctx->ingress_ifindex &&
           marlin_backend_mac_set(&mctx->backend) != 0) {
            marlin_nexthop_check_egress(&mctx->backend, fib.ifindex);
            marlin_nexthop_store_mac(eth, &mctx->backend);
            marlin_count(MARLIN_COUNT_NEIGH_FALLBACK);
            return MARLIN_OK_TX;
        }

        return MARLIN_DROP_FIB_NO_NEIGH;
    case BPF_FIB_LKUP_RET_FWD_DISABLED:
        return MARLIN_DROP_FIB_FWD_DISABLED;
    case BPF_FIB_LKUP_RET_BLACKHOLE:
        return MARLIN_DROP_FIB_BLACKHOLE;
    case BPF_FIB_LKUP_RET_UNREACHABLE:
        return MARLIN_DROP_FIB_UNREACHABLE;
    case BPF_FIB_LKUP_RET_PROHIBIT:
        return MARLIN_DROP_FIB_PROHIBIT;
    case BPF_FIB_LKUP_RET_FRAG_NEEDED:
        return MARLIN_DROP_FRAG_NEEDED;
    default:
        /* RET_NOT_FWDED, RET_UNSUPP_LWT, RET_NO_SRC_ADDR and negative
         * errnos (-ENODEV for a zero or stale ifindex, -EINVAL,
         * -EAFNOSUPPORT) -- the helper returns more codes than are
         * handled individually above.
         */
        return MARLIN_DROP_FIB_UNSPEC;
    }

    /* RET_SUCCESS covers both gatewayed and directly connected routes;
     * fib.dmac is the next hop's MAC either way. With an outer header a
     * gateway is fine -- it is addressed to backend.addr. Without one it
     * is fatal: the frame still carries the VIP, so a router would route
     * it back to Marlin, looping.
     */
    if(disc == MARLIN_NH_L2DSR && marlin_fib_onlink(&fib, mctx->backend.addr) == 0) {
        return MARLIN_DROP_FIB_GATEWAYED;
    }

    __builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);

    marlin_nexthop_check_egress(&mctx->backend, fib.ifindex);

    if(fib.ifindex == ctx->ingress_ifindex) {
        return MARLIN_OK_TX;
    }

    /* tx_ports is a DEVMAP_HASH keyed by ifindex, so the FIB result is the
     * key directly. Flags 0: bpf_redirect_map() returns the flags value
     * itself, XDP_ABORTED (0), on a missing key.
     */
    if(bpf_redirect_map(&tx_ports, fib.ifindex, 0) != XDP_REDIRECT) {
        return MARLIN_DROP_NO_TX_PORT;
    }

    return MARLIN_OK_REDIRECT;
}

/*
 * L2 DSR: MARLIN_BE_F_FIB first, then the stored MAC, then the FIB
 * fallback. L2 DSR cannot MAC-swap -- the destination is the backend
 * itself, not a router -- so Marlin's own MAC becomes the new source.
 */
int marlin_nexthop_l2dsr(struct xdp_md *ctx, struct marlin_ctx *mctx)
{
    struct ethhdr *eth = marlin_nexthop_eth(ctx);

    if(eth == NULL) {
        return MARLIN_DROP_PARSE_ERROR;
    }

    /* MARLIN_BE_F_FIB means the control plane has not confirmed this
     * backend on the ingress segment, so the FIB is asked even when a MAC
     * is stored.
     */
    if((mctx->backend.flags & MARLIN_BE_F_FIB) == 0) {
        if(marlin_backend_mac_set(&mctx->backend) != 0) {
            marlin_nexthop_check_egress(&mctx->backend, ctx->ingress_ifindex);
            marlin_nexthop_store_mac(eth, &mctx->backend);
            return MARLIN_OK_TX;
        }

        /* Degrade to the FIB rather than fail; a persistently non-zero
         * counter means the control plane isn't maintaining neighbours.
         * Only counted once addr is known resolvable -- otherwise this and
         * backend_unresolved (inside marlin_nexthop_fib, below) would
         * double-report one misconfiguration under two reasons.
         */
        if(mctx->backend.addr != 0) {
            marlin_count(MARLIN_COUNT_MAC_FALLBACK);
        }
    }

    return marlin_nexthop_fib(ctx, mctx, eth, MARLIN_NH_L2DSR);
}

/*
 * Encapsulation modes: MAC swap by default. The frame arrived from the
 * upstream router, so swapping source/destination and XDP_TX lets the
 * router forward the encapsulated packet using its own table. The router
 * must hairpin (normal for L3 interfaces; verify on switch SVIs).
 *
 * VXLAN is the exception and is tested on the MODE, not on the discipline
 * passed to marlin_nexthop_fib() -- the one place in the datapath where the
 * mode rather than the discipline is the right question, because what
 * differs is not whether an outer header exists but who wrote its Ethernet
 * part. vxlan.c consumed the arriving Ethernet header as the frame's
 * inner header and overwrote both of its addresses, so by the time this
 * runs the router's MAC exists nowhere in the frame and there is nothing
 * left to swap; the unit wrote the outer header itself, from addresses
 * saved before bpf_xdp_adjust_head(), reaching the same result one step
 * earlier (docs/design/14-forwarding-modes.md SS7.4,
 * docs/design/15-nexthop-l2dsr.md).
 *
 * Swapping anyway would not merely be redundant: it would exchange the
 * outer header's correct destination -- the router -- with Marlin's own
 * MAC, and transmit a frame addressed to nobody.
 *
 * The FIB path below is unaffected and common to all three modes: where
 * bpf_fib_lookup() resolves the next hop it supplies smac and dmac, and
 * those overwrite whatever this function wrote.
 */
int marlin_nexthop_encapsulate(struct xdp_md *ctx, struct marlin_ctx *mctx)
{
    struct ethhdr *eth = marlin_nexthop_eth(ctx);
    __u8 tmp[ETH_ALEN];

    if(eth == NULL) {
        return MARLIN_DROP_PARSE_ERROR;
    }

    /* Same flag, same meaning as under L2 DSR. Checked ahead of the VXLAN
     * test: the flag says the backend is not known reachable out the
     * ingress interface, which no encapsulation unit can answer.
     */
    if((mctx->backend.flags & MARLIN_BE_F_FIB) != 0) {
        return marlin_nexthop_fib(ctx, mctx, eth, MARLIN_NH_ENCAP);
    }

    /* Below this point the frame commits to XDP_TX out the ingress
     * interface without a lookup, so that is the expectation to validate
     * -- both the VXLAN no-swap return and the IPIP/GUE swap below share
     * this check (docs/design/16-fib-lookup.md).
     */
    marlin_nexthop_check_egress(&mctx->backend, ctx->ingress_ifindex);

    if(ENCAP_MODE(mctx->backend.flags) == MARLIN_MODE_VXLAN) {
        return MARLIN_OK_TX;
    }

    __builtin_memcpy(tmp, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, tmp, ETH_ALEN);

    return MARLIN_OK_TX;
}
