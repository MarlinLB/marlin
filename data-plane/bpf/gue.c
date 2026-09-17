/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * GUE tunnel encapsulation: outer IPv4 + UDP + a 4-byte GUE header carrying
 * the inner protocol, with the outer UDP source port carrying per-connection
 * entropy for ECMP and RSS spread.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <marlin/marlin.h>
#include <marlin/encap.h>
#include <marlin/csum.h>
#include <marlin/entropy.h>
#include <marlin/mtu.h>
#include <marlin/proto.h>

_Static_assert(MARLIN_OVERHEAD_GUE == sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct marlin_gue_hdr),
               "MARLIN_OVERHEAD_GUE must match the outer IPv4 + UDP + GUE header sizes");

static __always_inline int marlin_gue_validate(const struct marlin_ctx *mctx)
{
    /* Guard against pkt_len invariant violation to prevent garbage-length headers. */
    if(mctx->pkt_len < ETH_HLEN) {
        return MARLIN_DROP_ENCAP_LENGTH;
    }

    return marlin_frame_fits(mctx, MARLIN_OVERHEAD_GUE);
}

/* Relocate the arriving Ethernet header to the new frame start for nexthop.c's MAC swap. */
static __always_inline void marlin_gue_build_outer_eth(const void *data, __u16 overhead, struct ethhdr *eth)
{
    __builtin_memcpy(eth, (const char *)data + overhead, sizeof(*eth));
    eth->h_proto = bpf_htons(ETH_P_IP);
}

/* tos/id=0, frag_off=DF: frame_fits() prevents fragmentation. */
static __always_inline void marlin_gue_build_outer_ipv4(const struct marlin_ctx *mctx, struct iphdr *iph, __u16 inner_len)
{
    __builtin_memset(iph, 0, sizeof(*iph));
    iph->version = 4;
    iph->ihl = MARLIN_IPV4_IHL_MIN;
    iph->frag_off = bpf_htons(IP_DF);
    iph->ttl = MARLIN_OUTER_TTL;
    iph->protocol = IPPROTO_UDP;
    iph->tot_len = bpf_htons((__u16)(MARLIN_OVERHEAD_GUE + inner_len));
    iph->saddr = mctx->cfg.tunnel_src;
    iph->daddr = mctx->backend.addr;
    iph->check = marlin_ipv4_csum(iph);
}

static __always_inline void marlin_gue_build_outer_udp(const struct marlin_ctx *mctx, struct udphdr *udp, __be16 sport,
                                                       __u16 inner_len)
{
    __builtin_memset(udp, 0, sizeof(*udp));
    udp->source = sport;
    udp->dest = (mctx->backend.encap_dport != 0) ? mctx->backend.encap_dport : bpf_htons(MARLIN_GUE_DPORT_DEFAULT);
    udp->len = bpf_htons((__u16)(MARLIN_UDP_HLEN + sizeof(struct marlin_gue_hdr) + inner_len));
    udp->check = 0;
}

static __always_inline void marlin_gue_build_gue_hdr(struct marlin_gue_hdr *gue, __u8 family)
{
    __builtin_memset(gue, 0, sizeof(*gue));
    gue->proto = (family == AF_INET6) ? IPPROTO_IPV6 : IPPROTO_IPIP;
}

static __always_inline void marlin_gue_write_outer_l3(const struct marlin_ctx *mctx, void *data, __u16 inner_len)
{
    struct ethhdr eth;
    struct iphdr iph;

    marlin_gue_build_outer_eth(data, MARLIN_OVERHEAD_GUE, &eth);
    __builtin_memcpy(data, &eth, sizeof(eth));

    marlin_gue_build_outer_ipv4(mctx, &iph, inner_len);
    __builtin_memcpy((char *)data + ETH_HLEN, &iph, sizeof(iph));
}

static __always_inline void marlin_gue_write_outer_l4(const struct marlin_ctx *mctx, void *data, __be16 sport, __u16 inner_len)
{
    struct udphdr udp;
    struct marlin_gue_hdr gue;

    marlin_gue_build_outer_udp(mctx, &udp, sport, inner_len);
    __builtin_memcpy((char *)data + ETH_HLEN + sizeof(struct iphdr), &udp, sizeof(udp));

    marlin_gue_build_gue_hdr(&gue, mctx->tuple.family);
    __builtin_memcpy((char *)data + ETH_HLEN + sizeof(struct iphdr) + sizeof(udp), &gue, sizeof(gue));
}

int marlin_gue_encap_packet(struct xdp_md *ctx, struct marlin_ctx *mctx)
{
    void *data;
    void *data_end;
    __u16 inner_len;
    __be16 sport;
    int rc;

    if(ctx == NULL || mctx == NULL) {
        return MARLIN_ABORT_NULLREF;
    }

    rc = marlin_gue_validate(mctx);

    if(rc != MARLIN_OK) {
        return rc;
    }

    inner_len = (__u16)(mctx->pkt_len - ETH_HLEN);

    if(bpf_xdp_adjust_head(ctx, -MARLIN_OVERHEAD_GUE) != 0) {
        return MARLIN_DROP_ADJUST_HEAD;
    }

    data = (void *)(unsigned long)ctx->data;         // NOLINT(performance-no-int-to-ptr)
    data_end = (void *)(unsigned long)ctx->data_end; // NOLINT(performance-no-int-to-ptr)

    if((char *)data + ETH_HLEN + MARLIN_OVERHEAD_GUE > (char *)data_end) {
        return MARLIN_DROP_ADJUST_HEAD;
    }

    marlin_gue_write_outer_l3(mctx, data, inner_len);

    /* Pinned: left inline, clang spills mctx's tuple fields by scheduling this past the header stores below. */
    sport = marlin_entropy_sport(&mctx->tuple);
    barrier_var(sport);

    marlin_gue_write_outer_l4(mctx, data, sport, inner_len);

    mctx->l3_off = ETH_HLEN;
    mctx->pkt_len = (__u16)(ETH_HLEN + MARLIN_OVERHEAD_GUE + inner_len);

    return MARLIN_OK;
}
