/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * IPIP tunnel encapsulation: wraps inner packets in an outer IPv4 header for
 * backend delivery, with DF set to prevent outer-layer fragmentation.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <marlin/marlin.h>
#include <marlin/encap.h>
#include <marlin/csum.h>
#include <marlin/mtu.h>
#include <marlin/proto.h>

_Static_assert(MARLIN_OVERHEAD_IPIP == sizeof(struct iphdr), "MARLIN_OVERHEAD_IPIP must match the outer IPv4 header size");

/* Guard against pkt_len invariant violation to prevent garbage-length headers. */
static __always_inline int marlin_ipip_validate(const struct marlin_ctx *mctx)
{
    if(mctx->pkt_len < ETH_HLEN) {
        return MARLIN_DROP_ENCAP_LENGTH;
    }

    return marlin_frame_fits(mctx, MARLIN_OVERHEAD_IPIP);
}

/* Relocate the arriving Ethernet header to the new frame start for nexthop.c's MAC swap. */
static __always_inline void marlin_ipip_build_outer_eth(const void *data, __u16 overhead, struct ethhdr *eth)
{
    __builtin_memcpy(eth, (const char *)data + overhead, sizeof(*eth));
    eth->h_proto = bpf_htons(ETH_P_IP);
}

/*
 * id=0, frag_off=DF: frame_fits() prevents fragmentation. tos carries the
 * VIP's configured DSCP (docs/design/14-forwarding-modes.md SS7.2); never the
 * client's, and never its ECN bits.
 */
static __always_inline void marlin_ipip_build_outer_ipv4(const struct marlin_ctx *mctx, struct iphdr *iph, __u16 inner_len)
{
    __builtin_memset(iph, 0, sizeof(*iph));
    iph->version = 4;
    iph->ihl = MARLIN_IPV4_IHL_MIN;
    iph->tos = marlin_outer_tos(mctx);
    iph->frag_off = bpf_htons(IP_DF);
    iph->ttl = MARLIN_OUTER_TTL;
    iph->protocol = (mctx->tuple.family == AF_INET6) ? IPPROTO_IPV6 : IPPROTO_IPIP;
    iph->tot_len = bpf_htons((__u16)(MARLIN_OVERHEAD_IPIP + inner_len));
    iph->saddr = mctx->cfg.tunnel_src;
    iph->daddr = mctx->backend.addr;
    iph->check = marlin_ipv4_csum(iph);
}

/*
 * Both writes land inside the ETH_HLEN + MARLIN_OVERHEAD_IPIP bytes the
 * caller's bounds check already proved writable; store each header right
 * after building it; interleaving eth's store before iph's build keeps
 * their live ranges disjoint instead of both surviving to a batched end.
 */
static __always_inline void marlin_ipip_write_outer(const struct marlin_ctx *mctx, void *data, __u16 inner_len)
{
    struct ethhdr eth;
    struct iphdr iph;

    marlin_ipip_build_outer_eth(data, MARLIN_OVERHEAD_IPIP, &eth);
    __builtin_memcpy(data, &eth, sizeof(eth));

    marlin_ipip_build_outer_ipv4(mctx, &iph, inner_len);
    __builtin_memcpy((char *)data + ETH_HLEN, &iph, sizeof(iph));
}

int marlin_ipip_encap_packet(struct xdp_md *ctx, struct marlin_ctx *mctx)
{
    void *data;
    void *data_end;
    __u16 inner_len;
    int rc;

    if(ctx == NULL || mctx == NULL) {
        return MARLIN_ABORT_NULLREF;
    }

    rc = marlin_ipip_validate(mctx);

    if(rc != MARLIN_OK) {
        return rc;
    }

    inner_len = (__u16)(mctx->pkt_len - ETH_HLEN);

    if(bpf_xdp_adjust_head(ctx, -MARLIN_OVERHEAD_IPIP) != 0) {
        return MARLIN_DROP_ADJUST_HEAD;
    }

    data = (void *)(unsigned long)ctx->data;         // NOLINT(performance-no-int-to-ptr)
    data_end = (void *)(unsigned long)ctx->data_end; // NOLINT(performance-no-int-to-ptr)

    if((char *)data + ETH_HLEN + MARLIN_OVERHEAD_IPIP > (char *)data_end) {
        return MARLIN_DROP_ADJUST_HEAD;
    }

    marlin_ipip_write_outer(mctx, data, inner_len);

    mctx->l3_off = ETH_HLEN;
    mctx->pkt_len = (__u16)(ETH_HLEN + MARLIN_OVERHEAD_IPIP + inner_len);

    return MARLIN_OK;
}
