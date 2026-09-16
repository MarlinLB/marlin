/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * FIB lookup and NO_NEIGH cases: bpf_fib_lookup() outcomes against the real
 * netns/veth topology fib.h builds (route types, neighbour states, MTU,
 * blackhole/unreachable/prohibit, forwarding-disabled). Frame construction
 * (nh_build_frame()/nh_check_frame()) and the VIP/backend fixture come from
 * xdp_fixture.h; xdp_45_encap.c is this section's other half and shares
 * xdp_encap.h with it.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>

#include <marlin/marlin.h>

#include "../harness.h"
#include "../packet.h"
#include "fib.h"
#include "maps.h"
#include "prog.h"
#include "xdp_encap.h"
#include "xdp_fixture.h"

MARLIN_TEST(fib_no_neigh_onlink_ingress_is_neigh_fallback)
{
    __u64 fallback_before = xdp_drop_stats_total(MARLIN_COUNT_NEIGH_FALLBACK);
    __u64 mismatch_before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    struct xdp_run_result result;

    fib_neigh_del(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS);
    fib_neigh_set(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS, FIB_MAC_BACKEND_A, "failed");

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_BACKEND_A, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(fallback_before + 1, xdp_drop_stats_total(MARLIN_COUNT_NEIGH_FALLBACK));
    CHECK_EQ(mismatch_before, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));

    nh_backend_clear();
    fib_neigh_del(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS);
}

MARLIN_TEST(fib_no_neigh_onlink_other_egress_is_drop)
{
    /*
     * docs/design/24-testing.md:63-64 -- on-link but FIB returns another
     * interface: drop fib_no_neigh, no frame emitted.
     */
    __u64 no_neigh_before = xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH);
    __u64 fallback_before = xdp_drop_stats_total(MARLIN_COUNT_NEIGH_FALLBACK);
    struct xdp_run_result result;

    fib_neigh_del(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS);
    fib_neigh_set(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS, FIB_MAC_BACKEND_B, "failed");

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_BACKEND_B, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(no_neigh_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH));
    CHECK_EQ(fallback_before, xdp_drop_stats_total(MARLIN_COUNT_NEIGH_FALLBACK));

    nh_backend_clear();
    fib_neigh_del(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS);
}

MARLIN_TEST(fib_no_neigh_gatewayed_ingress_is_drop)
{
    __u64 no_neigh_before = xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH);
    __u64 fallback_before = xdp_drop_stats_total(MARLIN_COUNT_NEIGH_FALLBACK);
    struct xdp_run_result result;

    fib_route_add_via(FIB_ADDR_GATEWAYED, FIB_ADDR_GATEWAY, FIB_DEV_INGRESS);
    fib_neigh_del(FIB_ADDR_GATEWAY, FIB_DEV_INGRESS);
    fib_neigh_set(FIB_ADDR_GATEWAY, FIB_DEV_INGRESS, FIB_MAC_GATEWAY, "failed");

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_GATEWAYED, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(no_neigh_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH));
    CHECK_EQ(fallback_before, xdp_drop_stats_total(MARLIN_COUNT_NEIGH_FALLBACK));

    nh_backend_clear();
    fib_neigh_del(FIB_ADDR_GATEWAY, FIB_DEV_INGRESS);
    fib_route_del(FIB_ADDR_GATEWAYED);
}

MARLIN_TEST(fib_no_neigh_onlink_ingress_zero_mac_is_drop)
{
    /*
     * docs/design/24-testing.md:66-67 -- the on-link ingress case again
     * with an all-zero backend.mac: drop, nothing left to fall back to.
     */
    __u64 no_neigh_before = xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH);
    __u64 fallback_before = xdp_drop_stats_total(MARLIN_COUNT_NEIGH_FALLBACK);
    struct xdp_run_result result;

    fib_neigh_del(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS);
    fib_neigh_set(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS, FIB_MAC_BACKEND_A, "failed");

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_BACKEND_A, NULL, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(no_neigh_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH));
    CHECK_EQ(fallback_before, xdp_drop_stats_total(MARLIN_COUNT_NEIGH_FALLBACK));

    nh_backend_clear();
    fib_neigh_del(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS);
}

MARLIN_TEST(fib_no_neigh_under_ipip_is_drop)
{
    __u64 no_neigh_before = xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH);
    struct xdp_run_result result;

    fib_neigh_del(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS);
    fib_neigh_set(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS, FIB_MAC_BACKEND_A, "failed");

    seed_encap_cfg(IPIP_TUNNEL_SRC, 1500);
    nh_backend_seed(MARLIN_MODE_IPIP | MARLIN_BE_F_FIB, FIB_ADDR_BACKEND_A, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    /*
     * Encapsulation precedes next-hop resolution: the frame already grew by
     * MARLIN_OVERHEAD_IPIP by the time the FIB lookup fails.
     */
    ipip_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, IPIP_TUNNEL_SRC, FIB_ADDR_BACKEND_A, AF_INET, result.out_len);
    CHECK_EQ(no_neigh_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH));

    nh_backend_clear();
    fib_neigh_del(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS);
}

MARLIN_TEST(fib_fallback_resolves_backend_not_vip)
{
    __u64 fallback_before = xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK);
    struct xdp_run_result result;

    fib_neigh_del(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS);
    fib_neigh_set(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS, FIB_MAC_BACKEND_A, "permanent");
    fib_route_add_onlink(V4_DST, FIB_DEV_INGRESS);
    fib_neigh_del(V4_DST, FIB_DEV_INGRESS);
    fib_neigh_set(V4_DST, FIB_DEV_INGRESS, NH_DECOY_MAC, "permanent");

    nh_backend_seed(MARLIN_MODE_L2DSR, FIB_ADDR_BACKEND_A, NULL, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(FIB_MAC_BACKEND_A, FIB_MAC_INGRESS, result.out_len);
    CHECK_EQ(fallback_before + 1, xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK));

    nh_backend_clear();
    fib_neigh_del(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS);
    fib_neigh_del(V4_DST, FIB_DEV_INGRESS);
    fib_route_del(V4_DST);
}

MARLIN_TEST(fib_flag_beats_resolved_mac)
{
    __u64 mismatch_before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    struct xdp_run_result result;

    fib_neigh_del(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS);
    fib_neigh_set(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS, FIB_MAC_BACKEND_B, "permanent");
    xdp_tx_ports_add((__u32)fib_ifindex(FIB_DEV_EGRESS));

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_BACKEND_B, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_REDIRECT, result.retval);
    nh_check_frame(FIB_MAC_BACKEND_B, FIB_MAC_EGRESS, result.out_len);
    CHECK_EQ(mismatch_before, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));

    nh_backend_seed(MARLIN_MODE_L2DSR, FIB_ADDR_BACKEND_B, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    nh_backend_clear();
    xdp_tx_ports_clear();
    fib_neigh_del(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS);
}

MARLIN_TEST(fib_l2dsr_refuses_gatewayed_ipip_forwards)
{
    __u64 gatewayed_before;
    struct xdp_run_result result;

    fib_route_add_via(FIB_ADDR_GATEWAYED, FIB_ADDR_GATEWAY, FIB_DEV_INGRESS);
    fib_neigh_del(FIB_ADDR_GATEWAY, FIB_DEV_INGRESS);
    fib_neigh_set(FIB_ADDR_GATEWAY, FIB_DEV_INGRESS, FIB_MAC_GATEWAY, "permanent");

    gatewayed_before = xdp_drop_stats_total(MARLIN_DROP_FIB_GATEWAYED);
    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_GATEWAYED, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(gatewayed_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_GATEWAYED));

    seed_encap_cfg(IPIP_TUNNEL_SRC, 1500);
    nh_backend_seed(MARLIN_MODE_IPIP | MARLIN_BE_F_FIB, FIB_ADDR_GATEWAYED, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    /*
     * The mode split is the whole point here: the same route that L2DSR
     * refused above forwards under IPIP, with the FIB's own smac/dmac
     * overwriting the outer Ethernet header ipip.c relocated.
     */
    ipip_check_frame(FIB_MAC_GATEWAY, FIB_MAC_INGRESS, IPIP_TUNNEL_SRC, FIB_ADDR_GATEWAYED, AF_INET, result.out_len);

    nh_backend_clear();
    fib_neigh_del(FIB_ADDR_GATEWAY, FIB_DEV_INGRESS);
    fib_route_del(FIB_ADDR_GATEWAYED);
}

MARLIN_TEST(fib_egress_mismatch_counts_verdict_unchanged)
{
    __u64 mismatch_before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    struct xdp_run_result result;
    int nofwd_ifindex = fib_ifindex(FIB_DEV_NOFWD);

    fib_neigh_del(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS);
    fib_neigh_set(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS, FIB_MAC_BACKEND_B, "permanent");
    xdp_tx_ports_add((__u32)fib_ifindex(FIB_DEV_EGRESS));
    xdp_tx_ports_add((__u32)nofwd_ifindex);

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_BACKEND_B, NH_BACKEND_MAC, (__u32)nofwd_ifindex, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_REDIRECT, result.retval);
    nh_check_frame(FIB_MAC_BACKEND_B, FIB_MAC_EGRESS, result.out_len);
    CHECK_EQ(mismatch_before + 1, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));

    nh_backend_clear();
    xdp_tx_ports_clear();
    fib_neigh_del(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS);
}

MARLIN_TEST(fib_egress_mismatch_plus_no_tx_port_is_drop)
{
    __u64 mismatch_before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    __u64 no_tx_port_before = xdp_drop_stats_total(MARLIN_DROP_NO_TX_PORT);
    struct xdp_run_result result;
    int nofwd_ifindex = fib_ifindex(FIB_DEV_NOFWD);

    fib_neigh_del(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS);
    fib_neigh_set(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS, FIB_MAC_BACKEND_B, "permanent");
    xdp_tx_ports_add((__u32)nofwd_ifindex); /* the FIB's own interface, mve1, is deliberately absent */

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_BACKEND_B, NH_BACKEND_MAC, (__u32)nofwd_ifindex, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_ABORTED, result.retval);
    nh_check_frame(FIB_MAC_BACKEND_B, FIB_MAC_EGRESS, result.out_len);
    CHECK_EQ(mismatch_before + 1, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));
    CHECK_EQ(no_tx_port_before + 1, xdp_drop_stats_total(MARLIN_DROP_NO_TX_PORT));

    nh_backend_clear();
    xdp_tx_ports_clear();
    fib_neigh_del(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS);
}

MARLIN_TEST(fib_blackhole_route_is_drop_and_counted)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_FIB_BLACKHOLE);
    struct xdp_run_result result;

    fib_route_add_special("blackhole", FIB_ADDR_BLACKHOLE);
    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_BLACKHOLE, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_BLACKHOLE));

    nh_backend_clear();
    fib_route_del(FIB_ADDR_BLACKHOLE);
}

MARLIN_TEST(fib_unreachable_route_is_drop_and_counted)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_FIB_UNREACHABLE);
    struct xdp_run_result result;

    fib_route_add_special("unreachable", FIB_ADDR_UNREACHABLE);
    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_UNREACHABLE, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_UNREACHABLE));

    nh_backend_clear();
    fib_route_del(FIB_ADDR_UNREACHABLE);
}

MARLIN_TEST(fib_prohibit_route_is_drop_and_counted)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_FIB_PROHIBIT);
    struct xdp_run_result result;

    fib_route_add_special("prohibit", FIB_ADDR_PROHIBIT);
    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_PROHIBIT, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_PROHIBIT));

    nh_backend_clear();
    fib_route_del(FIB_ADDR_PROHIBIT);
}

MARLIN_TEST(fib_small_mtu_route_is_frag_needed_drop)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_FRAG_NEEDED);
    struct xdp_run_result result;

    fib_route_add_mtu(FIB_ADDR_MTU_ROUTE, FIB_DEV_INGRESS, 576);
    fib_neigh_del(FIB_ADDR_MTU_ROUTE, FIB_DEV_INGRESS);
    fib_neigh_set(FIB_ADDR_MTU_ROUTE, FIB_DEV_INGRESS, FIB_MAC_BACKEND_A, "permanent");

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_MTU_ROUTE, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();
    pb_pad(700);

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_FRAG_NEEDED));

    nh_backend_clear();
    fib_neigh_del(FIB_ADDR_MTU_ROUTE, FIB_DEV_INGRESS);
    fib_route_del(FIB_ADDR_MTU_ROUTE);
}

MARLIN_TEST(fib_unrouted_destination_is_unspec_drop)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_FIB_UNSPEC);
    struct xdp_run_result result;

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_UNROUTED, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_UNSPEC));

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_INGRESS, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(before + 2, xdp_drop_stats_total(MARLIN_DROP_FIB_UNSPEC));

    nh_backend_clear();
}

MARLIN_TEST(fib_ingress_forwarding_disabled_is_drop)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_FIB_FWD_DISABLED);
    struct xdp_run_result result;

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_UNROUTED, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_NOFWD));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_FWD_DISABLED));

    nh_backend_clear();
}
