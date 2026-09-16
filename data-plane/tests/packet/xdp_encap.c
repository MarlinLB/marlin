/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Definitions for xdp_encap.h's encap constants and frame checkers.
 */

#include <string.h>

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>

#include <marlin/marlin.h>
#include <marlin/proto.h>

#include "../harness.h"
#include "../packet.h"
#include "maps.h"
#include "xdp_encap.h"
#include "xdp_fixture.h"

void seed_encap_cfg(__be32 tunnel_src, __u16 max_frame)
{
    struct marlin_config cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.tunnel_src = tunnel_src;
    cfg.max_frame = max_frame;
    xdp_seed_config(&cfg);
}

__sum16 test_ipv4_csum(const struct iphdr *iph)
{
    struct iphdr tmp = *iph;
    const __u8 *p = (const __u8 *)&tmp;
    __u32 sum = 0;
    __u32 i;

    tmp.check = 0;

    for(i = 0; i + 1 < sizeof(tmp); i += 2) {
        sum += ((__u32)p[i] << 8) | p[i + 1];
    }

    sum = (sum & 0xffffU) + (sum >> 16);
    sum = (sum & 0xffffU) + (sum >> 16);

    return bpf_htons((__u16)~sum);
}

void ipip_check_frame(const unsigned char *expect_dst, const unsigned char *expect_src, __be32 tunnel_src,
                       __be32 backend_addr, __u8 inner_family, __u32 out_len)
{
    unsigned char expect_eth[ETH_HLEN];
    __be16 outer_proto = bpf_htons(ETH_P_IP);
    struct iphdr expect_iph;

    CHECK_EQ(pb_len + MARLIN_OVERHEAD_IPIP, out_len);

    /*
     * The outer network layer is always IPv4 regardless of inner_family
     * (docs/design/14-forwarding-modes.md SS7.5): the arriving frame's
     * EtherType is not what the outer header carries, even though it
     * mirrors inner_family exactly (parser.c).
     */
    memcpy(expect_eth, pb_arena, ETH_HLEN);
    memcpy(expect_eth, expect_dst, ETH_ALEN);
    memcpy(expect_eth + ETH_ALEN, expect_src, ETH_ALEN);
    memcpy(expect_eth + 2 * ETH_ALEN, &outer_proto, sizeof(outer_proto));
    CHECK_MEM(expect_eth, out_buf, sizeof(expect_eth));

    memset(&expect_iph, 0, sizeof(expect_iph));
    expect_iph.version = 4;
    expect_iph.ihl = MARLIN_IPV4_IHL_MIN;
    expect_iph.frag_off = bpf_htons(IP_DF);
    expect_iph.ttl = MARLIN_OUTER_TTL;
    expect_iph.protocol = (inner_family == AF_INET6) ? IPPROTO_IPV6 : IPPROTO_IPIP;
    expect_iph.tot_len = bpf_htons((__u16)(pb_len - ETH_HLEN + MARLIN_OVERHEAD_IPIP));
    expect_iph.saddr = tunnel_src;
    expect_iph.daddr = backend_addr;
    expect_iph.check = test_ipv4_csum(&expect_iph);
    CHECK_MEM(&expect_iph, out_buf + ETH_HLEN, sizeof(expect_iph));

    CHECK_MEM(pb_arena + ETH_HLEN, out_buf + ETH_HLEN + MARLIN_OVERHEAD_IPIP, pb_len - ETH_HLEN);
}

void gue_check_frame(const unsigned char *expect_dst, const unsigned char *expect_src, __be32 tunnel_src,
                      __be32 backend_addr, __be16 encap_dport, __u8 inner_family, __u32 out_len)
{
    unsigned char expect_eth[ETH_HLEN];
    __be16 outer_proto = bpf_htons(ETH_P_IP);
    struct iphdr expect_iph;
    struct udphdr udp;
    struct marlin_gue_hdr expect_gue;

    CHECK_EQ(pb_len + MARLIN_OVERHEAD_GUE, out_len);

    /*
     * The outer network layer is always IPv4 regardless of inner_family
     * (docs/design/14-forwarding-modes.md SS7.5): the arriving frame's
     * EtherType is not what the outer header carries, even though it
     * mirrors inner_family exactly (parser.c).
     */
    memcpy(expect_eth, pb_arena, ETH_HLEN);
    memcpy(expect_eth, expect_dst, ETH_ALEN);
    memcpy(expect_eth + ETH_ALEN, expect_src, ETH_ALEN);
    memcpy(expect_eth + 2 * ETH_ALEN, &outer_proto, sizeof(outer_proto));
    CHECK_MEM(expect_eth, out_buf, sizeof(expect_eth));

    memset(&expect_iph, 0, sizeof(expect_iph));
    expect_iph.version = 4;
    expect_iph.ihl = MARLIN_IPV4_IHL_MIN;
    expect_iph.frag_off = bpf_htons(IP_DF);
    expect_iph.ttl = MARLIN_OUTER_TTL;
    expect_iph.protocol = IPPROTO_UDP;
    expect_iph.tot_len = bpf_htons((__u16)(pb_len - ETH_HLEN + MARLIN_OVERHEAD_GUE));
    expect_iph.saddr = tunnel_src;
    expect_iph.daddr = backend_addr;
    expect_iph.check = test_ipv4_csum(&expect_iph);
    CHECK_MEM(&expect_iph, out_buf + ETH_HLEN, sizeof(expect_iph));

    memcpy(&udp, out_buf + ETH_HLEN + sizeof(expect_iph), sizeof(udp));
    CHECK_TRUE(bpf_ntohs(udp.source) >= GUE_ENTROPY_SPORT_MIN);
    CHECK_EQ((encap_dport != 0) ? encap_dport : bpf_htons(MARLIN_GUE_DPORT_DEFAULT), udp.dest);
    CHECK_EQ(bpf_htons((__u16)(MARLIN_UDP_HLEN + sizeof(expect_gue) + (pb_len - ETH_HLEN))), udp.len);
    CHECK_EQ(0, udp.check);

    memset(&expect_gue, 0, sizeof(expect_gue));
    expect_gue.proto = (inner_family == AF_INET6) ? IPPROTO_IPV6 : IPPROTO_IPIP;
    CHECK_MEM(&expect_gue, out_buf + ETH_HLEN + sizeof(expect_iph) + sizeof(udp), sizeof(expect_gue));

    CHECK_MEM(pb_arena + ETH_HLEN, out_buf + ETH_HLEN + MARLIN_OVERHEAD_GUE, pb_len - ETH_HLEN);
}

void vxlan_check_frame(const unsigned char *expect_dst, const unsigned char *expect_src, __be32 tunnel_src,
                        __be32 backend_addr, __be16 encap_dport, const unsigned char *inner_mac, __u32 vni,
                        __u32 out_len)
{
    unsigned char expect_eth[ETH_HLEN];
    __be16 outer_proto = bpf_htons(ETH_P_IP);
    struct ethhdr arriving_eth;
    struct ethhdr inner_eth;
    struct iphdr expect_iph;
    struct udphdr udp;
    struct marlin_vxlan_hdr expect_vxlan;

    CHECK_EQ(pb_len + MARLIN_OVERHEAD_VXLAN, out_len);

    memcpy(&arriving_eth, pb_arena, sizeof(arriving_eth));

    memset(expect_eth, 0, sizeof(expect_eth));
    memcpy(expect_eth, expect_dst, ETH_ALEN);
    memcpy(expect_eth + ETH_ALEN, expect_src, ETH_ALEN);
    memcpy(expect_eth + 2 * ETH_ALEN, &outer_proto, sizeof(outer_proto));
    CHECK_MEM(expect_eth, out_buf, sizeof(expect_eth));

    memset(&expect_iph, 0, sizeof(expect_iph));
    expect_iph.version = 4;
    expect_iph.ihl = MARLIN_IPV4_IHL_MIN;
    expect_iph.frag_off = bpf_htons(IP_DF);
    expect_iph.ttl = MARLIN_OUTER_TTL;
    expect_iph.protocol = IPPROTO_UDP;
    expect_iph.tot_len = bpf_htons((__u16)(pb_len - ETH_HLEN + MARLIN_OVERHEAD_VXLAN));
    expect_iph.saddr = tunnel_src;
    expect_iph.daddr = backend_addr;
    expect_iph.check = test_ipv4_csum(&expect_iph);
    CHECK_MEM(&expect_iph, out_buf + ETH_HLEN, sizeof(expect_iph));

    memcpy(&udp, out_buf + ETH_HLEN + sizeof(expect_iph), sizeof(udp));
    CHECK_TRUE(bpf_ntohs(udp.source) >= GUE_ENTROPY_SPORT_MIN);
    CHECK_EQ((encap_dport != 0) ? encap_dport : bpf_htons(MARLIN_VXLAN_DPORT_DEFAULT), udp.dest);
    CHECK_EQ(bpf_htons((__u16)(MARLIN_UDP_HLEN + sizeof(expect_vxlan) + pb_len)), udp.len);
    CHECK_EQ(0, udp.check);

    memset(&expect_vxlan, 0, sizeof(expect_vxlan));
    expect_vxlan.flags = MARLIN_VXLAN_FLAG_VNI;
    expect_vxlan.vni_and_reserved = bpf_htonl(vni << 8);
    CHECK_MEM(&expect_vxlan, out_buf + ETH_HLEN + sizeof(expect_iph) + sizeof(udp), sizeof(expect_vxlan));

    memcpy(&inner_eth, out_buf + MARLIN_OVERHEAD_VXLAN, sizeof(inner_eth));
    CHECK_MEM(inner_mac, inner_eth.h_dest, ETH_ALEN);
    CHECK_MEM(expect_src, inner_eth.h_source, ETH_ALEN);
    CHECK_EQ(arriving_eth.h_proto, inner_eth.h_proto);

    CHECK_MEM(pb_arena + ETH_HLEN, out_buf + MARLIN_OVERHEAD_VXLAN + ETH_HLEN, pb_len - ETH_HLEN);
}
