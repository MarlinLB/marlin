/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * VXLAN tunnel encapsulation: wraps the arriving frame, Ethernet header
 * included, in outer IPv4 + UDP + an 8-byte VXLAN header, since the
 * backend's vxlan device expects a full Ethernet frame rather than a bare
 * IP packet (docs/design/14-forwarding-modes.md SS7.4). The arriving
 * Ethernet header becomes the inner header in place; both its addresses
 * must be read before bpf_xdp_adjust_head() invalidates the pointer that
 * holds them.
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

_Static_assert(MARLIN_OVERHEAD_VXLAN ==
                       sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct marlin_vxlan_hdr),
               "MARLIN_OVERHEAD_VXLAN must match the outer Ethernet + IPv4 + UDP + VXLAN header sizes");

int marlin_vxlan_encap_packet(struct xdp_md *ctx, struct marlin_ctx *mctx)
{
    void *data;
    void *data_end;
    struct ethhdr *eth;
    struct ethhdr *inner_eth;
    __u8 arriving_dst[ETH_ALEN];
    __u8 arriving_src[ETH_ALEN];
    struct ethhdr outer_eth;
    struct iphdr iph;
    struct udphdr udp;
    struct marlin_vxlan_hdr vxlan;
    __u16 inner_len;
    __be16 sport;
    int rc;

    if(ctx == NULL || mctx == NULL) {
        return MARLIN_ABORT_NULLREF;
    }

    /* Guard against pkt_len invariant violation to prevent garbage-length headers. */
    if(mctx->pkt_len < ETH_HLEN) {
        return MARLIN_DROP_ENCAP_LENGTH;
    }

    rc = marlin_frame_fits(mctx, MARLIN_OVERHEAD_VXLAN);

    if(rc != MARLIN_OK) {
        return rc;
    }

    inner_len = (__u16)(mctx->pkt_len - ETH_HLEN);

    data = (void *)(unsigned long)ctx->data;         // NOLINT(performance-no-int-to-ptr)
    data_end = (void *)(unsigned long)ctx->data_end; // NOLINT(performance-no-int-to-ptr)
    eth = data;

    if((void *)(eth + 1) > data_end) {
        return MARLIN_DROP_PARSE_ERROR;
    }

    /* Save both arriving addresses as values: adjust_head below invalidates eth. */
    __builtin_memcpy(arriving_dst, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(arriving_src, eth->h_source, ETH_ALEN);

    if(bpf_xdp_adjust_head(ctx, -MARLIN_OVERHEAD_VXLAN) != 0) {
        return MARLIN_DROP_ADJUST_HEAD;
    }

    data = (void *)(unsigned long)ctx->data;         // NOLINT(performance-no-int-to-ptr)
    data_end = (void *)(unsigned long)ctx->data_end; // NOLINT(performance-no-int-to-ptr)

    /*
     * Implied by the eth+1 check above once adjust_head succeeds, since
     * data_end does not move -- kept because the verifier needs a fresh
     * bounds proof against the pointers adjust_head just invalidated.
     */
    if((char *)data + MARLIN_OVERHEAD_VXLAN + ETH_HLEN > (char *)data_end) {
        return MARLIN_DROP_ADJUST_HEAD;
    }

    /*
     * adjust_head pushed the arriving frame forward by exactly the outer
     * headers' combined size, landing the arriving Ethernet header at the
     * inner-header offset already -- only its two addresses need correcting.
     */
    inner_eth = (struct ethhdr *)((char *)data + MARLIN_OVERHEAD_VXLAN);
    __builtin_memcpy(inner_eth->h_dest, mctx->backend.inner_mac, ETH_ALEN);
    __builtin_memcpy(inner_eth->h_source, arriving_dst, ETH_ALEN);

    __builtin_memset(&outer_eth, 0, sizeof(outer_eth));
    __builtin_memcpy(outer_eth.h_dest, arriving_src, ETH_ALEN);
    __builtin_memcpy(outer_eth.h_source, arriving_dst, ETH_ALEN);
    outer_eth.h_proto = bpf_htons(ETH_P_IP);

    /* tos/id=0, frag_off=DF: frame_fits() prevents fragmentation. */
    __builtin_memset(&iph, 0, sizeof(iph));
    iph.version = 4;
    iph.ihl = MARLIN_IPV4_IHL_MIN;
    iph.frag_off = bpf_htons(IP_DF);
    iph.ttl = MARLIN_OUTER_TTL;
    iph.protocol = IPPROTO_UDP;

    /*
     * tot_len excludes the outer Ethernet header but includes the inner one
     * VXLAN carries; both are ETH_HLEN bytes, so they cancel and the sum
     * takes the same MARLIN_OVERHEAD_VXLAN + inner_len shape as ipip.c/gue.c.
     */
    iph.tot_len = bpf_htons((__u16)(MARLIN_OVERHEAD_VXLAN + inner_len));
    iph.saddr = mctx->cfg.tunnel_src;
    iph.daddr = mctx->backend.addr;
    iph.check = marlin_ipv4_csum(&iph);

    /* Pinned: left inline, clang spills mctx's tuple fields by scheduling this past the header stores below. */
    sport = marlin_entropy_sport(&mctx->tuple);
    barrier_var(sport);

    /* check=0: unconditionally permitted with an IPv4 outer (docs/design/14-forwarding-modes.md SS7.6). */
    __builtin_memset(&udp, 0, sizeof(udp));
    udp.source = sport;
    udp.dest = (mctx->backend.encap_dport != 0) ? mctx->backend.encap_dport : bpf_htons(MARLIN_VXLAN_DPORT_DEFAULT);
    udp.len = bpf_htons((__u16)(MARLIN_UDP_HLEN + sizeof(vxlan) + ETH_HLEN + inner_len));
    udp.check = 0;

    /* flags: only the I bit is ever set (RFC 7348); vni_and_reserved's shift zeroes the trailing reserved byte. */
    __builtin_memset(&vxlan, 0, sizeof(vxlan));
    vxlan.flags = MARLIN_VXLAN_FLAG_VNI;
    vxlan.vni_and_reserved = bpf_htonl(mctx->backend.vni << 8);

    __builtin_memcpy(data, &outer_eth, sizeof(outer_eth));
    __builtin_memcpy((char *)data + ETH_HLEN, &iph, sizeof(iph));
    __builtin_memcpy((char *)data + ETH_HLEN + sizeof(iph), &udp, sizeof(udp));
    __builtin_memcpy((char *)data + ETH_HLEN + sizeof(iph) + sizeof(udp), &vxlan, sizeof(vxlan));

    mctx->l3_off = ETH_HLEN;
    mctx->pkt_len = (__u16)(ETH_HLEN + MARLIN_OVERHEAD_VXLAN + inner_len);

    return MARLIN_OK;
}
