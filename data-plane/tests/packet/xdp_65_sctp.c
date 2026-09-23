/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * SCTP forwarding: baseline admission and encapsulation, VIP_HASH_PORTS
 * selection, and address groups (docs/design/32-sctp.md). Reuses
 * sctp_vip_seed/clear from xdp_fixture.h, which already seeds the two-key,
 * one-vip_num shape a group is.
 */

#include <string.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>

#include <marlin/marlin.h>

#include "../harness.h"
#include "../packet.h"
#include "maps.h"
#include "prog.h"
#include "xdp_encap.h"
#include "xdp_fixture.h"

static void sctp_build_frame4(__be32 src, __be32 dst, __u16 sport_host, __u16 dport_host)
{
    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_SCTP, MARLIN_IPV4_IHL_MIN, 0, src, dst);
    pb_sctp(sport_host, dport_host, 0xdeadbeef);
}

static void sctp_build_frame6(const unsigned char *src, const unsigned char *dst, __u16 sport_host, __u16 dport_host)
{
    pb_reset();
    pb_eth(ETH_P_IPV6);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv6(IPPROTO_SCTP, src, dst);
    pb_sctp(sport_host, dport_host, 0xdeadbeef);
}

/* ---- baseline: forwarding in every mode -------------------------------- */

MARLIN_TEST(sctp_l2dsr_ipv4_is_tx_on_backend_mac)
{
    struct xdp_run_result result;

    sctp_vip_seed(0);
    sctp_build_frame4(V4_SRC, V4_DST, 11111, SCTP_VIP_PORT);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    sctp_vip_clear();
}

MARLIN_TEST(sctp_l2dsr_ipv6_is_tx_on_backend_mac)
{
    struct xdp_run_result result;

    sctp_vip_seed(0);
    sctp_build_frame6(SRC6, DST6, 11111, SCTP_VIP_PORT);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    sctp_vip_clear();
}

MARLIN_TEST(sctp_ipip_inner_bytes_unchanged)
{
    struct xdp_run_result result;
    struct backend be;

    seed_encap_cfg(IPIP_TUNNEL_SRC, 1500);
    vip_seed4(V4_DST, SCTP_VIP_PORT, IPPROTO_SCTP, SCTP_VIP_NUM, 0);
    xdp_fwd_fill(SCTP_VIP_NUM, NH_BACKEND_ID);
    memset(&be, 0, sizeof(be));
    be.flags = (__u8)(MARLIN_MODE_IPIP | MARLIN_BE_F_STATE);
    be.addr = NH_BACKEND_ADDR;
    be.id = (__u16)NH_BACKEND_ID;
    xdp_backend_write(NH_BACKEND_ID, &be);
    sctp_build_frame4(V4_SRC, V4_DST, 11111, SCTP_VIP_PORT);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    ipip_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, IPIP_TUNNEL_SRC, NH_BACKEND_ADDR, AF_INET, result.out_len, 0);

    sctp_vip_clear();
}

MARLIN_TEST(sctp_gue_inner_bytes_unchanged)
{
    struct xdp_run_result result;
    struct backend be;

    seed_encap_cfg(GUE_TUNNEL_SRC, 1500);
    vip_seed4(V4_DST, SCTP_VIP_PORT, IPPROTO_SCTP, SCTP_VIP_NUM, 0);
    xdp_fwd_fill(SCTP_VIP_NUM, NH_BACKEND_ID);
    memset(&be, 0, sizeof(be));
    be.flags = (__u8)(MARLIN_MODE_GUE | MARLIN_BE_F_STATE);
    be.addr = NH_BACKEND_ADDR;
    be.id = (__u16)NH_BACKEND_ID;
    xdp_backend_write(NH_BACKEND_ID, &be);
    sctp_build_frame4(V4_SRC, V4_DST, 11111, SCTP_VIP_PORT);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    gue_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, GUE_TUNNEL_SRC, NH_BACKEND_ADDR, 0, AF_INET, result.out_len, 0);

    sctp_vip_clear();
}

MARLIN_TEST(sctp_vxlan_inner_bytes_unchanged)
{
    struct xdp_run_result result;
    struct backend be;

    seed_encap_cfg(VXLAN_TUNNEL_SRC, 1500);
    vip_seed4(V4_DST, SCTP_VIP_PORT, IPPROTO_SCTP, SCTP_VIP_NUM, 0);
    xdp_fwd_fill(SCTP_VIP_NUM, NH_BACKEND_ID);
    memset(&be, 0, sizeof(be));
    be.flags = (__u8)(MARLIN_MODE_VXLAN | MARLIN_BE_F_STATE);
    be.addr = NH_BACKEND_ADDR;
    be.vni = VXLAN_VNI;
    be.id = (__u16)NH_BACKEND_ID;
    memcpy(be.inner_mac, VXLAN_INNER_MAC, ETH_ALEN);
    xdp_backend_write(NH_BACKEND_ID, &be);
    sctp_build_frame4(V4_SRC, V4_DST, 11111, SCTP_VIP_PORT);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    vxlan_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, VXLAN_TUNNEL_SRC, NH_BACKEND_ADDR, 0, VXLAN_INNER_MAC, VXLAN_VNI,
                      result.out_len, 0);

    sctp_vip_clear();
}

MARLIN_TEST(sctp_to_tcp_vip_is_vip_miss)
{
    __u64 before;
    struct xdp_run_result result;

    vip_seed4(V4_DST, SCTP_VIP_PORT, IPPROTO_TCP, SCTP_VIP_NUM, 0);
    xdp_fwd_fill(SCTP_VIP_NUM, NH_BACKEND_ID);
    before = xdp_drop_stats_total(MARLIN_PASS_VIP_MISS);
    sctp_build_frame4(V4_SRC, V4_DST, 11111, SCTP_VIP_PORT);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_PASS_VIP_MISS));

    struct vip_key key;

    vip_key4(&key, V4_DST, SCTP_VIP_PORT, IPPROTO_TCP);
    xdp_vip_del(&key);
    xdp_fwd_clear(SCTP_VIP_NUM);
}

MARLIN_TEST(sctp_port_agnostic_vip_matches_any_dport)
{
    struct xdp_run_result result;

    vip_seed4(V4_DST, 0, IPPROTO_SCTP, SCTP_VIP_NUM, 0);
    xdp_fwd_fill(SCTP_VIP_NUM, NH_BACKEND_ID);
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    sctp_build_frame4(V4_SRC, V4_DST, 11111, SCTP_VIP_PORT); /* no vip_map key names this dport */

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    struct vip_key key;

    vip_key4(&key, V4_DST, 0, IPPROTO_SCTP);
    xdp_vip_del(&key);
    xdp_fwd_clear(SCTP_VIP_NUM);
    xdp_backend_clear(NH_BACKEND_ID);
}

MARLIN_TEST(sctp_to_non_vip_is_vip_miss_not_not_forwarded)
{
    __u64 miss_before = xdp_drop_stats_total(MARLIN_PASS_VIP_MISS);
    __u64 not_fwd_before = xdp_drop_stats_total(MARLIN_PASS_NOT_FORWARDED);
    struct xdp_run_result result;

    sctp_build_frame4(V4_SRC, ACL_ADDR4(203, 0, 113, 9), 11111, SCTP_VIP_PORT); /* no VIP configured */

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
    CHECK_EQ(miss_before + 1, xdp_drop_stats_total(MARLIN_PASS_VIP_MISS));
    CHECK_EQ(not_fwd_before, xdp_drop_stats_total(MARLIN_PASS_NOT_FORWARDED));
}

MARLIN_TEST(sctp_host_bound_blocked_source_is_acl_blocked)
{
    __u64 before;
    struct xdp_run_result result;

    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_block_v4", 32, ACL_ADDR4(10, 60, 60, 3), 1);
    seed_acl_cfg(CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));
    before = xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED);

    sctp_build_frame4(ACL_ADDR4(10, 60, 60, 3), ACL_ADDR4(203, 0, 113, 9), 11111, SCTP_VIP_PORT); /* not a VIP */

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED));

    struct marlin_config cfg;

    xdp_acl_clear("acl_block_v4");
    memset(&cfg, 0, sizeof(cfg));
    xdp_seed_config(&cfg);
}

/* ---- VIP_HASH_PORTS ------------------------------------------------------ */

MARLIN_TEST(sctp_hash_ports_ignores_client_address)
{
    unsigned char first[ETH_ALEN];
    struct xdp_run_result result;

    sctp_vip_seed(VIP_HASH_PORTS);
    sctp_build_frame4(V4_SRC, V4_DST, 11111, SCTP_VIP_PORT);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    memcpy(first, out_buf, ETH_ALEN);

    sctp_build_frame4(ACL_ADDR4(203, 0, 113, 200), V4_DST, 11111, SCTP_VIP_PORT);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    CHECK_MEM(first, out_buf, ETH_ALEN);

    sctp_vip_clear();
}

static int sctp_hash_ports_sport_moves_selection(__u16 count)
{
    unsigned char first[ETH_ALEN] = {0};
    struct xdp_run_result result;
    __u16 i;

    for(i = 0; i < count; i++) {
        sctp_build_frame4(V4_SRC, V4_DST, (__u16)(40000U + i), SCTP_VIP_PORT);
        result = run_current_packet();

        if(result.err != 0 || result.retval != XDP_TX) {
            return -1;
        }

        if(i == 0) {
            memcpy(first, out_buf, ETH_ALEN);
        } else if(memcmp(first, out_buf, ETH_ALEN) != 0) {
            return 1;
        }
    }

    return 0;
}

MARLIN_TEST(sctp_hash_ports_varies_with_source_port)
{
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    backend_seed_l2dsr(ALT_BACKEND_ID, ALT_BACKEND_MAC);
    vip_seed4(V4_DST, SCTP_VIP_PORT, IPPROTO_SCTP, SCTP_VIP_NUM, VIP_HASH_PORTS);
    xdp_fwd_fill_striped(SCTP_VIP_NUM, NH_BACKEND_ID, ALT_BACKEND_ID);

    CHECK_EQ(1, sctp_hash_ports_sport_moves_selection(32));

    struct vip_key key;

    vip_key4(&key, V4_DST, SCTP_VIP_PORT, IPPROTO_SCTP);
    xdp_vip_del(&key);
    xdp_fwd_clear(SCTP_VIP_NUM);
    xdp_backend_clear(NH_BACKEND_ID);
    xdp_backend_clear(ALT_BACKEND_ID);
}

MARLIN_TEST(sctp_address_hash_ignores_source_port)
{
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    backend_seed_l2dsr(ALT_BACKEND_ID, ALT_BACKEND_MAC);
    vip_seed4(V4_DST, SCTP_VIP_PORT, IPPROTO_SCTP, SCTP_VIP_NUM, 0);
    xdp_fwd_fill_striped(SCTP_VIP_NUM, NH_BACKEND_ID, ALT_BACKEND_ID);

    CHECK_EQ(0, sctp_hash_ports_sport_moves_selection(32));

    struct vip_key key;

    vip_key4(&key, V4_DST, SCTP_VIP_PORT, IPPROTO_SCTP);
    xdp_vip_del(&key);
    xdp_fwd_clear(SCTP_VIP_NUM);
    xdp_backend_clear(NH_BACKEND_ID);
    xdp_backend_clear(ALT_BACKEND_ID);
}

/* Same ports, both families: VIP_HASH_PORTS never reads family, so both select the same backend. */
MARLIN_TEST(sctp_hash_ports_same_row_across_families)
{
    struct xdp_run_result result;
    unsigned char v4_dst[ETH_ALEN], v6_dst[ETH_ALEN];

    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    backend_seed_l2dsr(ALT_BACKEND_ID, ALT_BACKEND_MAC);
    vip_seed4(V4_DST, SCTP_VIP_PORT, IPPROTO_SCTP, SCTP_VIP_NUM, VIP_HASH_PORTS);
    vip_seed6(DST6, SCTP_VIP_PORT, IPPROTO_SCTP, SCTP_VIP_NUM, VIP_HASH_PORTS);
    xdp_fwd_fill_striped(SCTP_VIP_NUM, NH_BACKEND_ID, ALT_BACKEND_ID);

    sctp_build_frame4(V4_SRC, V4_DST, 41000, SCTP_VIP_PORT);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    memcpy(v4_dst, out_buf, ETH_ALEN);

    sctp_build_frame6(SRC6, DST6, 41000, SCTP_VIP_PORT);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    memcpy(v6_dst, out_buf, ETH_ALEN);

    CHECK_MEM(v4_dst, v6_dst, ETH_ALEN);

    struct vip_key key;

    vip_key4(&key, V4_DST, SCTP_VIP_PORT, IPPROTO_SCTP);
    xdp_vip_del(&key);
    vip_key6(&key, DST6, SCTP_VIP_PORT, IPPROTO_SCTP);
    xdp_vip_del(&key);
    xdp_fwd_clear(SCTP_VIP_NUM);
    xdp_backend_clear(NH_BACKEND_ID);
    xdp_backend_clear(ALT_BACKEND_ID);
}

MARLIN_TEST(sctp_hash_ports_first_fragment_is_frag_unsupported)
{
    __u64 before;
    struct xdp_run_result result;

    before = xdp_drop_stats_total(MARLIN_DROP_FRAG_UNSUPPORTED);
    sctp_vip_seed(VIP_HASH_PORTS);
    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_SCTP, MARLIN_IPV4_IHL_MIN, IP_MF, V4_SRC, V4_DST);
    pb_sctp(11111, SCTP_VIP_PORT, 0xdeadbeef);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_FRAG_UNSUPPORTED));

    sctp_vip_clear();
}

MARLIN_TEST(sctp_hash_ports_non_first_fragment_is_frag_unsupported)
{
    /*
     * A non-first fragment carries no SCTP header, so its parsed dport is
     * always zero (data-plane/bpf/parser.c). The explicit-port VIP that
     * sctp_vip_seed() creates cannot match it, and it would otherwise pass
     * as vip_miss before marlin_lb_check_frag() ever runs
     * (docs/design/12-selection.md, "Hash input"; the TCP sibling of this
     * test is xdp_60_lb_core.c's fragment_non_first_on_five_tuple_vip_is_drop).
     * A port == 0 VIP is required to reach the frag check at all.
     */
    __u64 before;
    struct xdp_run_result result;
    struct vip_key key;

    before = xdp_drop_stats_total(MARLIN_DROP_FRAG_UNSUPPORTED);
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    vip_seed4(V4_DST, 0, IPPROTO_SCTP, SCTP_VIP_NUM, VIP_HASH_PORTS);
    xdp_fwd_fill(SCTP_VIP_NUM, NH_BACKEND_ID);

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_SCTP, MARLIN_IPV4_IHL_MIN, 0x0040 /* offset set, MF clear: non-first, last fragment */, V4_SRC, V4_DST);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_FRAG_UNSUPPORTED));

    vip_key4(&key, V4_DST, 0, IPPROTO_SCTP);
    xdp_vip_del(&key);
    xdp_fwd_clear(SCTP_VIP_NUM);
    xdp_backend_clear(NH_BACKEND_ID);
}

/* ---- address groups ------------------------------------------------------ */

MARLIN_TEST(sctp_group_both_addresses_select_the_same_backend)
{
    struct xdp_run_result result;
    struct stats before;

    sctp_vip_seed(0);
    before = xdp_vip_stats_total(SCTP_VIP_NUM);

    sctp_build_frame4(V4_SRC, V4_DST, 11111, SCTP_VIP_PORT);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    sctp_build_frame6(SRC6, DST6, 11111, SCTP_VIP_PORT);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    /* One vip_num, so both addresses' traffic lands in the same counter. */
    CHECK_EQ(before.packets + 2, xdp_vip_stats_total(SCTP_VIP_NUM).packets);

    sctp_vip_clear();
}
