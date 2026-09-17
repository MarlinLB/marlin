/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Next-hop resolution and Ethernet MAC assignment. Provides two disciplines:
 * L2DSR uses stored backend MAC or falls back to bpf_fib_lookup(); encapsulation
 * swaps Ethernet addresses (IPIP/GUE) or takes the same FIB fallback.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>

#include <bpf/bpf_helpers.h>

#include <marlin/marlin.h>
#include <marlin/maps.h>
#include <marlin/stats.h>
#include <marlin/nexthop.h>

enum marlin_nh_discipline {
    MARLIN_NH_ENCAP = 0,
    MARLIN_NH_L2DSR = 1,
};

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

static __always_inline void marlin_nexthop_store_mac(struct ethhdr *eth, const struct backend *be)
{
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, be->mac, ETH_ALEN);
}

static __always_inline int marlin_fib_onlink(const struct bpf_fib_lookup *fib, __be32 backend_addr)
{
    return fib->family == AF_INET && fib->ipv4_dst == backend_addr;
}

static __always_inline void marlin_nexthop_check_egress(const struct backend *be, __u32 ifindex)
{
    if(be->egress_ifindex != 0 && be->egress_ifindex != ifindex) {
        marlin_stats_reason(MARLIN_COUNT_EGRESS_MISMATCH);
    }
}

_Static_assert(sizeof(struct bpf_fib_lookup) == 64, "bpf_fib_lookup must fit within the stack budget");

static __always_inline int marlin_nexthop_fib(struct xdp_md *ctx, struct marlin_ctx *mctx, struct ethhdr *eth,
                                              enum marlin_nh_discipline disc)
{
    struct bpf_fib_lookup fib;
    long rc;

    if(mctx->backend.addr == 0) {
        return MARLIN_DROP_BACKEND_UNRESOLVED;
    }

    __builtin_memset(&fib, 0, sizeof(fib));

    fib.family = AF_INET;
    fib.ipv4_dst = mctx->backend.addr;
    fib.tot_len = (__u16)((ctx->data_end - ctx->data) - ETH_HLEN);
    fib.ifindex = ctx->ingress_ifindex;
    /*
     * So a policy-routing rule matching dsfield resolves the next hop the
     * way the wire will actually see the frame. fib.tos is unioned with
     * rt_metric, which the kernel may write on return -- the same union
     * hazard the mtu_result comment below records for tot_len -- but
     * nothing reads fib.tos back.
     */
    fib.tos = marlin_outer_tos(mctx);

    rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);

    switch(rc) {
    case BPF_FIB_LKUP_RET_SUCCESS:
        break;
    case BPF_FIB_LKUP_RET_NO_NEIGH:
        if(disc == MARLIN_NH_L2DSR && marlin_fib_onlink(&fib, mctx->backend.addr) && fib.ifindex == ctx->ingress_ifindex &&
           marlin_backend_mac_set(&mctx->backend) != 0) {
            marlin_nexthop_check_egress(&mctx->backend, fib.ifindex);
            marlin_nexthop_store_mac(eth, &mctx->backend);
            marlin_stats_reason(MARLIN_COUNT_NEIGH_FALLBACK);
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
        /* fib.mtu_result (union'd with tot_len above) is deliberately not
         * recorded: drop_stats holds counts, not values, and the MTU is
         * already visible in the route that produced it (docs/design/23-mtu.md).
         */
        return MARLIN_DROP_FRAG_NEEDED;
    default:
        return MARLIN_DROP_FIB_UNSPEC;
    }

    if(disc == MARLIN_NH_L2DSR && marlin_fib_onlink(&fib, mctx->backend.addr) == 0) {
        return MARLIN_DROP_FIB_GATEWAYED;
    }

    __builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);

    marlin_nexthop_check_egress(&mctx->backend, fib.ifindex);

    if(fib.ifindex == ctx->ingress_ifindex) {
        return MARLIN_OK_TX;
    }

    if(bpf_redirect_map(&tx_ports, fib.ifindex, 0) != XDP_REDIRECT) {
        return MARLIN_DROP_NO_TX_PORT;
    }

    return MARLIN_OK_REDIRECT;
}

int marlin_nexthop_l2dsr(struct xdp_md *ctx, struct marlin_ctx *mctx)
{
    struct ethhdr *eth;

    if(ctx == NULL || mctx == NULL) {
        return MARLIN_ABORT_NULLREF;
    }

    eth = marlin_nexthop_eth(ctx);

    if(eth == NULL) {
        return MARLIN_DROP_PARSE_ERROR;
    }

    if((mctx->backend.flags & MARLIN_BE_F_FIB) == 0) {
        if(marlin_backend_mac_set(&mctx->backend) != 0) {
            marlin_nexthop_check_egress(&mctx->backend, ctx->ingress_ifindex);
            marlin_nexthop_store_mac(eth, &mctx->backend);
            return MARLIN_OK_TX;
        }

        if(mctx->backend.addr != 0) {
            marlin_stats_reason(MARLIN_COUNT_MAC_FALLBACK);
        }
    }

    return marlin_nexthop_fib(ctx, mctx, eth, MARLIN_NH_L2DSR);
}

int marlin_nexthop_encapsulate(struct xdp_md *ctx, struct marlin_ctx *mctx)
{
    struct ethhdr *eth;
    __u8 tmp[ETH_ALEN];

    if(ctx == NULL || mctx == NULL) {
        return MARLIN_ABORT_NULLREF;
    }

    eth = marlin_nexthop_eth(ctx);

    if(eth == NULL) {
        return MARLIN_DROP_PARSE_ERROR;
    }

    if((mctx->backend.flags & MARLIN_BE_F_FIB) != 0) {
        return marlin_nexthop_fib(ctx, mctx, eth, MARLIN_NH_ENCAP);
    }

    marlin_nexthop_check_egress(&mctx->backend, ctx->ingress_ifindex);

    if(ENCAP_MODE(mctx->backend.flags) == MARLIN_MODE_VXLAN) {
        return MARLIN_OK_TX;
    }

    __builtin_memcpy(tmp, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, tmp, ETH_ALEN);

    return MARLIN_OK_TX;
}
