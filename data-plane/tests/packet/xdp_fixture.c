/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Definitions for xdp_fixture.h's shared addresses, run wrappers and
 * VIP/backend/forwarding-table helpers. See the header comment there for
 * which files use what.
 */

#include <string.h>

#include <linux/in.h>

#include <bpf/bpf_endian.h>

#include <marlin/marlin.h>

#include "../harness.h"
#include "../packet.h"
#include "maps.h"
#include "xdp_fixture.h"

const unsigned char SRC6[16] = {0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
                                0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80};
const unsigned char DST6[16] = {0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
                                0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90};

unsigned char out_buf[XDP_TEST_RUN_MAX_SIZE];

struct xdp_run_result run_current_packet(void)
{
    return xdp_run(pb_arena, pb_len, out_buf, sizeof(out_buf), 0);
}

struct xdp_run_result run_packet_on(__u32 ingress_ifindex)
{
    return xdp_run(pb_arena, pb_len, out_buf, sizeof(out_buf), ingress_ifindex);
}

const unsigned char NH_MARLIN_MAC[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
const unsigned char NH_ROUTER_MAC[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
const unsigned char NH_BACKEND_MAC[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x03};

const unsigned char NH_DECOY_MAC[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0b};

const unsigned char VXLAN_INNER_MAC[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x04};

const unsigned char ALT_BACKEND_MAC[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x05};

void vip_key4(struct vip_key *key, __be32 addr, __u16 port_host, __u8 proto)
{
    memset(key, 0, sizeof(*key));
    key->addr4 = addr;
    key->port = bpf_htons(port_host);
    key->proto = proto;
    key->family = AF_INET;
}

void vip_key6(struct vip_key *key, const unsigned char addr16[16], __u16 port_host, __u8 proto)
{
    memset(key, 0, sizeof(*key));
    memcpy(key->addr6, addr16, sizeof(key->addr6));
    key->port = bpf_htons(port_host);
    key->proto = proto;
    key->family = AF_INET6;
}

void vip_meta_init(struct vip_meta *meta, __u32 vip_num, __u32 flags)
{
    memset(meta, 0, sizeof(*meta));
    meta->vip_num = vip_num;
    meta->flags = flags;
    memset(meta->hash_key, VIP_FIXTURE_HASH_KEY_BYTE, sizeof(meta->hash_key));
}

void vip_seed4(__be32 addr, __u16 port_host, __u8 proto, __u32 vip_num, __u32 flags)
{
    struct vip_key key;
    struct vip_meta meta;

    vip_key4(&key, addr, port_host, proto);
    vip_meta_init(&meta, vip_num, flags);
    xdp_vip_add(&key, &meta);
}

void vip_seed6(const unsigned char addr16[16], __u16 port_host, __u8 proto, __u32 vip_num, __u32 flags)
{
    struct vip_key key;
    struct vip_meta meta;

    vip_key6(&key, addr16, port_host, proto);
    vip_meta_init(&meta, vip_num, flags);
    xdp_vip_add(&key, &meta);
}

void backend_seed_l2dsr(__u32 id, const unsigned char *mac)
{
    struct backend be;

    memset(&be, 0, sizeof(be));
    be.flags = (__u8)(MARLIN_MODE_L2DSR | MARLIN_BE_F_STATE);
    be.addr = NH_BACKEND_ADDR;
    be.id = (__u16)id;

    if(mac != NULL) {
        memcpy(be.mac, mac, ETH_ALEN);
    }

    xdp_backend_write(id, &be);
}

void udp_vip_seed(__u32 flags)
{
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    vip_seed4(V4_DST, 53, IPPROTO_UDP, UDP_VIP_NUM, flags);
    vip_seed6(DST6, 53, IPPROTO_UDP, UDP_VIP_NUM, flags);
    xdp_fwd_fill(UDP_VIP_NUM, NH_BACKEND_ID);
}

void udp_vip_clear(void)
{
    struct vip_key key;

    vip_key4(&key, V4_DST, 53, IPPROTO_UDP);
    xdp_vip_del(&key);
    vip_key6(&key, DST6, 53, IPPROTO_UDP);
    xdp_vip_del(&key);
    xdp_fwd_clear(UDP_VIP_NUM);
    xdp_backend_clear(NH_BACKEND_ID);
}

void seed_acl_cfg(__u32 flags, __u16 acl_lists)
{
    struct marlin_config cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.flags = flags;
    cfg.acl_lists = acl_lists;
    xdp_seed_config(&cfg);
}

void build_udp4(__be32 src, __be32 dst)
{
    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_UDP, MARLIN_IPV4_IHL_MIN, 0, src, dst);
    pb_ports(11111, 53);
}

void build_udp6(const unsigned char src[16], const unsigned char dst[16])
{
    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_UDP, src, dst);
    pb_ports(11111, 53);
}

void nh_vip_seed(__u32 flags)
{
    vip_seed4(V4_DST, 80, IPPROTO_TCP, NH_VIP_NUM, flags);
    vip_seed6(DST6, 80, IPPROTO_TCP, NH_VIP_NUM, flags);
    xdp_fwd_fill(NH_VIP_NUM, NH_BACKEND_ID);
}

void nh_vip_clear(void)
{
    struct vip_key key;

    vip_key4(&key, V4_DST, 80, IPPROTO_TCP);
    xdp_vip_del(&key);
    vip_key6(&key, DST6, 80, IPPROTO_TCP);
    xdp_vip_del(&key);
    xdp_fwd_clear(NH_VIP_NUM);
}

void nh_backend_write(const struct backend *be)
{
    xdp_backend_write(NH_BACKEND_ID, be);
}

void nh_backend_clear(void)
{
    struct backend be;

    memset(&be, 0, sizeof(be));
    nh_backend_write(&be);
    nh_vip_clear();
}

void nh_backend_seed(__u8 mode_and_flags, __be32 addr, const unsigned char *mac, __u32 egress_ifindex, __u32 vni,
                     const unsigned char *inner_mac)
{
    struct backend be;

    memset(&be, 0, sizeof(be));
    be.flags = (__u8)(mode_and_flags | MARLIN_BE_F_STATE);
    be.addr = addr;
    be.egress_ifindex = egress_ifindex;
    be.vni = vni;
    be.id = (__u16)NH_BACKEND_ID;

    if(mac != NULL) {
        memcpy(be.mac, mac, ETH_ALEN);
    }

    if(inner_mac != NULL) {
        memcpy(be.inner_mac, inner_mac, ETH_ALEN);
    }

    nh_backend_write(&be);
    nh_vip_seed(VIP_HASH_5TUPLE);
}

void nh_build_frame(void)
{
    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(11111, 80);
}

void nh_check_frame(const unsigned char *expect_dst, const unsigned char *expect_src, __u32 out_len)
{
    unsigned char expect[ETH_HLEN];

    CHECK_EQ(pb_len, out_len);
    memcpy(expect, pb_arena, ETH_HLEN);
    memcpy(expect, expect_dst, ETH_ALEN);
    memcpy(expect + ETH_ALEN, expect_src, ETH_ALEN);
    CHECK_MEM(expect, out_buf, sizeof(expect));
    CHECK_MEM(pb_arena + ETH_HLEN, out_buf + ETH_HLEN, pb_len - ETH_HLEN);
}

void nh_build_frame_v6(void)
{
    pb_reset();
    pb_eth(ETH_P_IPV6);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv6(IPPROTO_TCP, SRC6, DST6);
    pb_ports(11111, 80);
}

void bal_setup(void)
{
    struct marlin_config cfg;

    memset(&cfg, 0, sizeof(cfg));
    xdp_seed_config(&cfg);
    xdp_vip_clear();
}
