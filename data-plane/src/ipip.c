/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * IPIP encapsulation implementation.
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

int marlin_ipip_encap_packet(struct xdp_md *ctx, struct marlin_ctx *mctx)
{
    void *data;
    void *data_end;
    struct ethhdr eth;
    struct iphdr iph;
    __u16 inner_len;
    int rc;

    if(ctx == NULL || mctx == NULL) {
        return MARLIN_ABORT_NULLREF;
    }

    /* Every successfully parsed packet has pkt_len >= ETH_HLEN; this guards
     * the subtraction below against wrapping if that invariant is ever
     * violated, rather than silently building a garbage-length header.
     */
    if(mctx->pkt_len < ETH_HLEN) {
        return MARLIN_DROP_ENCAP_LENGTH;
    }

    rc = marlin_frame_fits(mctx, MARLIN_OVERHEAD_IPIP);

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

    /* adjust_head shifted the arriving frame forward by MARLIN_OVERHEAD_IPIP;
     * the Ethernet header that was at the old frame start now sits at that
     * offset. Relocate it to the new frame start so nexthop.c's MAC swap
     * still finds it there, freeing its old slot for the outer header.
     */
    __builtin_memcpy(&eth, (char *)data + MARLIN_OVERHEAD_IPIP, sizeof(eth));
    __builtin_memcpy(data, &eth, sizeof(eth));

    /* tos and id stay 0: DSCP/ECN copy-through and outer fragmentation are
     * both out of scope (docs/design/14-forwarding-modes.md). frag_off
     * carries IP_DF because Marlin never fragments the outer packet --
     * frame_fits() above is the check that takes its place.
     */
    __builtin_memset(&iph, 0, sizeof(iph));
    iph.version = 4;
    iph.ihl = MARLIN_IPV4_IHL_MIN;
    iph.frag_off = bpf_htons(IP_DF);
    iph.ttl = MARLIN_OUTER_TTL;
    iph.protocol = (mctx->tuple.family == AF_INET6) ? IPPROTO_IPV6 : IPPROTO_IPIP;
    iph.tot_len = bpf_htons((__u16)(MARLIN_OVERHEAD_IPIP + inner_len));
    iph.saddr = mctx->cfg.tunnel_src;
    iph.daddr = mctx->backend.addr;
    iph.check = marlin_ipv4_csum(&iph);

    __builtin_memcpy((char *)data + ETH_HLEN, &iph, sizeof(iph));

    mctx->l3_off = ETH_HLEN;
    mctx->pkt_len = (__u16)(ETH_HLEN + MARLIN_OVERHEAD_IPIP + inner_len);

    return MARLIN_OK;
}
