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

int marlin_gue_encap_packet(struct xdp_md *ctx, struct marlin_ctx *mctx)
{
    void *data;
    void *data_end;
    struct ethhdr eth;
    struct iphdr iph;
    struct udphdr udp;
    struct marlin_gue_hdr gue;
    __u16 inner_len;
    int rc;

    if(ctx == NULL || mctx == NULL) {
        return MARLIN_ABORT_NULLREF;
    }

    /* Guard against pkt_len invariant violation to prevent garbage-length headers. */
    if(mctx->pkt_len < ETH_HLEN) {
        return MARLIN_DROP_ENCAP_LENGTH;
    }

    rc = marlin_frame_fits(mctx, MARLIN_OVERHEAD_GUE);

    if(rc != MARLIN_OK) {
        return rc;
    }

    inner_len = (__u16)(mctx->pkt_len - ETH_HLEN);

    if(bpf_xdp_adjust_head(ctx, -MARLIN_OVERHEAD_GUE) != 0) {
        return MARLIN_DROP_ADJUST_HEAD;
    }

    data = (void *)(unsigned long)ctx->data;
    data_end = (void *)(unsigned long)ctx->data_end;

    if((char *)data + ETH_HLEN + MARLIN_OVERHEAD_GUE > (char *)data_end) {
        return MARLIN_DROP_ADJUST_HEAD;
    }

    /* Relocate inner Ethernet header to frame start for nexthop.c's MAC swap. */
    __builtin_memcpy(&eth, (char *)data + MARLIN_OVERHEAD_GUE, sizeof(eth));

    /*
     * The outer network layer is always IPv4 (docs/design/14-forwarding-modes.md
     * SS7.5), regardless of tuple.family, so the arriving EtherType -- which
     * mirrors tuple.family exactly (parser.c) -- must not carry forward unchanged.
     */
    eth.h_proto = bpf_htons(ETH_P_IP);
    __builtin_memcpy(data, &eth, sizeof(eth));

    /* tos/id=0, frag_off=DF: frame_fits() prevents fragmentation. */
    __builtin_memset(&iph, 0, sizeof(iph));
    iph.version = 4;
    iph.ihl = MARLIN_IPV4_IHL_MIN;
    iph.frag_off = bpf_htons(IP_DF);
    iph.ttl = MARLIN_OUTER_TTL;
    iph.protocol = IPPROTO_UDP;
    iph.tot_len = bpf_htons((__u16)(MARLIN_OVERHEAD_GUE + inner_len));
    iph.saddr = mctx->cfg.tunnel_src;
    iph.daddr = mctx->backend.addr;
    iph.check = marlin_ipv4_csum(&iph);

    /* check=0: unconditionally permitted with an IPv4 outer (docs/design/14-forwarding-modes.md SS7.6). */
    __builtin_memset(&udp, 0, sizeof(udp));
    udp.source = marlin_entropy_sport(&mctx->tuple);
    udp.dest = (mctx->backend.encap_dport != 0) ? mctx->backend.encap_dport : bpf_htons(MARLIN_GUE_DPORT_DEFAULT);
    udp.len = bpf_htons((__u16)(MARLIN_UDP_HLEN + sizeof(gue) + inner_len));
    udp.check = 0;

    __builtin_memset(&gue, 0, sizeof(gue));
    gue.proto = (mctx->tuple.family == AF_INET6) ? IPPROTO_IPV6 : IPPROTO_IPIP;

    __builtin_memcpy((char *)data + ETH_HLEN, &iph, sizeof(iph));
    __builtin_memcpy((char *)data + ETH_HLEN + sizeof(iph), &udp, sizeof(udp));
    __builtin_memcpy((char *)data + ETH_HLEN + sizeof(iph) + sizeof(udp), &gue, sizeof(gue));

    mctx->l3_off = ETH_HLEN;
    mctx->pkt_len = (__u16)(ETH_HLEN + MARLIN_OVERHEAD_GUE + inner_len);

    return MARLIN_OK;
}
