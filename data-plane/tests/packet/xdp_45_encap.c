/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * L2DSR and tunnel encapsulation cases (IPIP, GUE, VXLAN) plus two
 * cross-cutting invariants: no case in this file or xdp_40_fib.c leaks
 * route/neighbour/tx_ports state, and an unknown encap mode is a bounds
 * drop rather than undefined behaviour. Shares xdp_encap.h with
 * xdp_40_fib.c, this section's other half.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/udp.h>

#include <marlin/marlin.h>

#include "../harness.h"
#include "../packet.h"
#include "fib.h"
#include "maps.h"
#include "prog.h"
#include "xdp_encap.h"
#include "xdp_fixture.h"

/*
 * Arbitrary, in-range: EF (RFC 3246). Shared by the four DSCP cases at the
 * end of this file, each named for the mode/discipline it exercises.
 */
#define TEST_DSCP 46U

MARLIN_TEST(l2dsr_stored_mac_is_tx_on_backend_mac)
{
    __u64 fallback_before = xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK);
    __u64 mismatch_before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    struct stats backend_before, backend_after;
    struct xdp_run_result result;

    nh_backend_seed(MARLIN_MODE_L2DSR, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, 0, NULL);
    backend_before = xdp_backend_stats_total(NH_BACKEND_ID);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    CHECK_EQ(fallback_before, xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK));
    CHECK_EQ(mismatch_before, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));

    /* backend_stats is metered on every forward, not only the down-backend
     * path backend_stats_counts_a_down_backend_and_keys_on_its_abi_id above
     * already asserts.
     */
    backend_after = xdp_backend_stats_total(NH_BACKEND_ID);
    CHECK_EQ(backend_before.packets + 1, backend_after.packets);
    CHECK_EQ(backend_before.bytes + pb_len, backend_after.bytes);

    nh_backend_clear();
}

MARLIN_TEST(l2dsr_egress_mismatch_counts_verdict_unchanged)
{
    __u64 before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    struct xdp_run_result result;

    nh_backend_seed(MARLIN_MODE_L2DSR, NH_BACKEND_ADDR, NH_BACKEND_MAC, NH_INGRESS_IFINDEX + 1, 0, NULL);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));

    nh_backend_clear();
}

MARLIN_TEST(l2dsr_egress_match_does_not_count)
{
    __u64 before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    struct xdp_run_result result;

    nh_backend_seed(MARLIN_MODE_L2DSR, NH_BACKEND_ADDR, NH_BACKEND_MAC, NH_INGRESS_IFINDEX, 0, NULL);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(before, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));

    nh_backend_clear();
}

MARLIN_TEST(l2dsr_zero_mac_zero_addr_is_backend_unresolved)
{
    __u64 unresolved_before = xdp_drop_stats_total(MARLIN_DROP_BACKEND_UNRESOLVED);
    __u64 fallback_before = xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK);
    struct xdp_run_result result;

    nh_backend_seed(MARLIN_MODE_L2DSR, 0, NULL, 0, 0, NULL);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(unresolved_before + 1, xdp_drop_stats_total(MARLIN_DROP_BACKEND_UNRESOLVED));
    CHECK_EQ(fallback_before, xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK));

    nh_backend_clear();
}

MARLIN_TEST(l2dsr_zero_mac_resolvable_addr_counts_mac_fallback)
{
    __u64 fallback_before = xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK);
    __u64 fwd_disabled_before = xdp_drop_stats_total(MARLIN_DROP_FIB_FWD_DISABLED);
    struct xdp_run_result result;

    nh_backend_seed(MARLIN_MODE_L2DSR, NH_BACKEND_ADDR, NULL, 0, 0, NULL);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(fallback_before + 1, xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK));
    CHECK_EQ(fwd_disabled_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_FWD_DISABLED));

    nh_backend_clear();
}

MARLIN_TEST(l2dsr_fib_flag_does_not_use_stored_mac)
{
    __u64 fallback_before = xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK);
    __u64 fwd_disabled_before = xdp_drop_stats_total(MARLIN_DROP_FIB_FWD_DISABLED);
    struct xdp_run_result result;

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(fallback_before, xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK));
    CHECK_EQ(fwd_disabled_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_FWD_DISABLED));

    nh_backend_clear();
}

MARLIN_TEST(ipip_encap_zero_lookup_swaps_ethernet_and_builds_outer_header)
{
    __u64 mismatch_before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    struct xdp_run_result result;

    seed_encap_cfg(IPIP_TUNNEL_SRC, 1500);
    nh_backend_seed(MARLIN_MODE_IPIP, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    ipip_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, IPIP_TUNNEL_SRC, NH_BACKEND_ADDR, AF_INET, result.out_len, 0);
    CHECK_EQ(mismatch_before, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));

    nh_backend_clear();
}

MARLIN_TEST(ipip_encap_ipv6_inner_sets_protocol_41)
{
    struct xdp_run_result result;

    seed_encap_cfg(IPIP_TUNNEL_SRC, 1500);
    nh_backend_seed(MARLIN_MODE_IPIP, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame_v6();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    ipip_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, IPIP_TUNNEL_SRC, NH_BACKEND_ADDR, AF_INET6, result.out_len, 0);

    nh_backend_clear();
}

MARLIN_TEST(ipip_encap_frame_too_big_drops_before_adjust_head)
{
    __u64 too_big_before;
    struct xdp_run_result result;

    /*
     * Far smaller than any encapsulated test frame: this is a wiring proof
     * that ipip.c checks and drops before touching the packet, not the
     * boundary arithmetic itself, which tests/mtu_test.c already covers.
     */
    seed_encap_cfg(IPIP_TUNNEL_SRC, 10);
    too_big_before = xdp_drop_stats_total(MARLIN_DROP_FRAME_TOO_BIG);

    nh_backend_seed(MARLIN_MODE_IPIP, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(too_big_before + 1, xdp_drop_stats_total(MARLIN_DROP_FRAME_TOO_BIG));

    nh_backend_clear();
}

MARLIN_TEST(ipip_encap_max_frame_zero_disables_the_check)
{
    struct xdp_run_result result;

    seed_encap_cfg(IPIP_TUNNEL_SRC, 0);
    nh_backend_seed(MARLIN_MODE_IPIP, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();
    pb_pad(2000); /* well past any real MTU; only max_frame == 0 lets this through */

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    ipip_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, IPIP_TUNNEL_SRC, NH_BACKEND_ADDR, AF_INET, result.out_len, 0);

    nh_backend_clear();
}

MARLIN_TEST(gue_encap_zero_lookup_swaps_ethernet_and_builds_outer_header)
{
    __u64 mismatch_before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    struct xdp_run_result result;

    seed_encap_cfg(GUE_TUNNEL_SRC, 1500);
    nh_backend_seed(MARLIN_MODE_GUE, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    gue_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, GUE_TUNNEL_SRC, NH_BACKEND_ADDR, 0, AF_INET, result.out_len, 0);
    CHECK_EQ(mismatch_before, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));

    nh_backend_clear();
}

MARLIN_TEST(gue_encap_ipv6_inner_sets_gue_proto_41)
{
    struct xdp_run_result result;

    seed_encap_cfg(GUE_TUNNEL_SRC, 1500);
    nh_backend_seed(MARLIN_MODE_GUE, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame_v6();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    gue_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, GUE_TUNNEL_SRC, NH_BACKEND_ADDR, 0, AF_INET6, result.out_len, 0);

    nh_backend_clear();
}

MARLIN_TEST(gue_encap_frame_too_big_drops_before_adjust_head)
{
    __u64 too_big_before;
    struct xdp_run_result result;

    /* Far smaller than any encapsulated test frame: this is a wiring proof
     * that gue.c checks and drops before touching the packet, not the
     * boundary arithmetic itself, which tests/mtu_test.c already covers.
     */
    seed_encap_cfg(GUE_TUNNEL_SRC, 10);
    too_big_before = xdp_drop_stats_total(MARLIN_DROP_FRAME_TOO_BIG);

    nh_backend_seed(MARLIN_MODE_GUE, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(too_big_before + 1, xdp_drop_stats_total(MARLIN_DROP_FRAME_TOO_BIG));

    nh_backend_clear();
}

MARLIN_TEST(gue_encap_max_frame_zero_disables_the_check)
{
    struct xdp_run_result result;

    seed_encap_cfg(GUE_TUNNEL_SRC, 0);
    nh_backend_seed(MARLIN_MODE_GUE, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();
    pb_pad(2000); /* well past any real MTU; only max_frame == 0 lets this through */

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    gue_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, GUE_TUNNEL_SRC, NH_BACKEND_ADDR, 0, AF_INET, result.out_len, 0);

    nh_backend_clear();
}

MARLIN_TEST(gue_encap_entropy_source_port_differs_for_different_inner_ports)
{
    /* The real-kernel counterpart to entropy_test.c's algorithm-level
     * differentiation case: proves marlin_ctx.tuple, as populated by the
     * compiled parser.c and threaded through the compiled gue.c, actually
     * varies the emitted source port -- not just the algorithm in
     * isolation (docs/design/14-forwarding-modes.md SS7.3).
     */
    struct xdp_run_result result;
    struct udphdr udp_a, udp_b;

    seed_encap_cfg(GUE_TUNNEL_SRC, 1500);
    nh_backend_seed(MARLIN_MODE_GUE, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, 0, NULL);

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(11111, 80);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    memcpy(&udp_a, out_buf + ETH_HLEN + sizeof(struct iphdr), sizeof(udp_a));

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(22222, 80);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    memcpy(&udp_b, out_buf + ETH_HLEN + sizeof(struct iphdr), sizeof(udp_b));

    CHECK_TRUE(udp_a.source != udp_b.source);

    nh_backend_clear();
}

MARLIN_TEST(vxlan_encap_zero_lookup_writes_outer_and_inner_ethernet_headers)
{
    /*
     * nexthop.c:179-181 returns before the Ethernet swap for VXLAN, so the
     * outer addresses here are the ones vxlan.c wrote, not swapped ones. It
     * builds them from the same saved addresses the swap would have used
     * (docs/design/14-forwarding-modes.md SS7.4), which is why the expected
     * outer header below is still ingress-destination-then-ingress-source.
     */
    struct xdp_run_result result;

    seed_encap_cfg(VXLAN_TUNNEL_SRC, 1500);
    nh_backend_seed(MARLIN_MODE_VXLAN, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, VXLAN_VNI, VXLAN_INNER_MAC);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    vxlan_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, VXLAN_TUNNEL_SRC, NH_BACKEND_ADDR, 0, VXLAN_INNER_MAC, VXLAN_VNI,
                      result.out_len, 0);

    nh_backend_clear();
}

MARLIN_TEST(encap_fib_flag_beats_the_vxlan_no_swap)
{
    /*
     * The FIB path is unaffected by vxlan.c's exception
     * (docs/design/14-forwarding-modes.md SS7.4): bpf_fib_lookup() would
     * overwrite the outer addresses on success exactly as under IPIP/GUE,
     * but this route has no forwarding enabled, so the drop fires before
     * that ever happens -- the outer header at drop time is still whatever
     * vxlan.c itself wrote.
     */
    __u64 fwd_disabled_before = xdp_drop_stats_total(MARLIN_DROP_FIB_FWD_DISABLED);
    __u64 mismatch_before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    struct xdp_run_result result;

    seed_encap_cfg(VXLAN_TUNNEL_SRC, 1500);
    nh_backend_seed(MARLIN_MODE_VXLAN | MARLIN_BE_F_FIB, NH_BACKEND_ADDR, NH_BACKEND_MAC, NH_INGRESS_IFINDEX + 1, VXLAN_VNI,
                    VXLAN_INNER_MAC);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    vxlan_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, VXLAN_TUNNEL_SRC, NH_BACKEND_ADDR, 0, VXLAN_INNER_MAC, VXLAN_VNI,
                      result.out_len, 0);
    CHECK_EQ(fwd_disabled_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_FWD_DISABLED));
    CHECK_EQ(mismatch_before, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));

    nh_backend_clear();
}

MARLIN_TEST(vxlan_encap_ipv6_inner_preserves_ethertype)
{
    /*
     * Unlike IPIP/GUE, VXLAN carries no separate inner-protocol field --
     * the inner EtherType is the only family signal a receiving vxlan
     * device gets (docs/design/14-forwarding-modes.md SS7.4), so it must
     * survive relocation unchanged. vxlan_check_frame() derives its
     * expectation from the arriving frame itself, so this only needs to
     * arm a v6 frame and let the shared checker prove it.
     */
    struct xdp_run_result result;

    seed_encap_cfg(VXLAN_TUNNEL_SRC, 1500);
    nh_backend_seed(MARLIN_MODE_VXLAN, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, VXLAN_VNI, VXLAN_INNER_MAC);
    nh_build_frame_v6();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    vxlan_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, VXLAN_TUNNEL_SRC, NH_BACKEND_ADDR, 0, VXLAN_INNER_MAC, VXLAN_VNI,
                      result.out_len, 0);

    nh_backend_clear();
}

MARLIN_TEST(vxlan_encap_frame_too_big_drops_before_adjust_head)
{
    __u64 too_big_before;
    struct xdp_run_result result;

    /* Far smaller than any encapsulated test frame: this is a wiring proof
     * that vxlan.c checks and drops before touching the packet, not the
     * boundary arithmetic itself, which tests/mtu_test.c already covers.
     */
    seed_encap_cfg(VXLAN_TUNNEL_SRC, 10);
    too_big_before = xdp_drop_stats_total(MARLIN_DROP_FRAME_TOO_BIG);

    nh_backend_seed(MARLIN_MODE_VXLAN, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, VXLAN_VNI, VXLAN_INNER_MAC);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(too_big_before + 1, xdp_drop_stats_total(MARLIN_DROP_FRAME_TOO_BIG));

    nh_backend_clear();
}

MARLIN_TEST(vxlan_encap_max_frame_zero_disables_the_check)
{
    struct xdp_run_result result;

    seed_encap_cfg(VXLAN_TUNNEL_SRC, 0);
    nh_backend_seed(MARLIN_MODE_VXLAN, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, VXLAN_VNI, VXLAN_INNER_MAC);
    nh_build_frame();
    pb_pad(2000); /* well past any real MTU; only max_frame == 0 lets this through */

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    vxlan_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, VXLAN_TUNNEL_SRC, NH_BACKEND_ADDR, 0, VXLAN_INNER_MAC, VXLAN_VNI,
                      result.out_len, 0);

    nh_backend_clear();
}

MARLIN_TEST(vxlan_encap_entropy_source_port_differs_for_different_inner_ports)
{
    /* The real-kernel counterpart to entropy_test.c's algorithm-level
     * differentiation case: proves marlin_ctx.tuple, as populated by the
     * compiled parser.c and threaded through the compiled vxlan.c, actually
     * varies the emitted source port -- not just the algorithm in
     * isolation (docs/design/14-forwarding-modes.md SS7.3).
     */
    struct xdp_run_result result;
    struct udphdr udp_a, udp_b;

    seed_encap_cfg(VXLAN_TUNNEL_SRC, 1500);
    nh_backend_seed(MARLIN_MODE_VXLAN, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, VXLAN_VNI, VXLAN_INNER_MAC);

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(11111, 80);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    memcpy(&udp_a, out_buf + ETH_HLEN + sizeof(struct iphdr), sizeof(udp_a));

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(22222, 80);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    memcpy(&udp_b, out_buf + ETH_HLEN + sizeof(struct iphdr), sizeof(udp_b));

    CHECK_TRUE(udp_a.source != udp_b.source);

    nh_backend_clear();
}

MARLIN_TEST(fib_cases_leave_no_route_or_neigh_state)
{
    __u64 unspec_before = xdp_drop_stats_total(MARLIN_DROP_FIB_UNSPEC);
    __u64 no_neigh_before = xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH);
    struct xdp_run_result result;

    CHECK_TRUE(xdp_tx_ports_is_empty());

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_GATEWAYED, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();
    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(unspec_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_UNSPEC));
    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_BACKEND_A, NULL, 0, 0, NULL);
    nh_build_frame();
    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(no_neigh_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH));

    nh_backend_clear();
}

MARLIN_TEST(unknown_encap_mode_is_map_bounds_drop)
{
    /*
     * The mode field is 4 bits (ENCAP_MODE_MASK, defines.h) with only 0-3
     * assigned (MARLIN_MODE_L2DSR/IPIP/GUE/VXLAN); 4 names none of them.
     */
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_MAP_BOUNDS);
    struct xdp_run_result result;

    nh_backend_seed(4, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_MAP_BOUNDS));

    nh_backend_clear();
}

MARLIN_TEST(ipip_encap_dscp_marks_the_outer_header)
{
    /*
     * The real-kernel counterpart to ipip_test.c's mctx-level DSCP cases:
     * proves the VIP's configured DSCP survives the real vip_map lookup in
     * balancer.c and reaches ipip.c's outer header.
     */
    struct xdp_run_result result;

    seed_encap_cfg(IPIP_TUNNEL_SRC, 1500);
    nh_backend_seed(MARLIN_MODE_IPIP, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, 0, NULL);
    nh_vip_seed(VIP_HASH_5TUPLE | ((TEST_DSCP << VIP_DSCP_SHIFT) & VIP_DSCP_MASK));
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    ipip_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, IPIP_TUNNEL_SRC, NH_BACKEND_ADDR, AF_INET, result.out_len,
                      (__u8)TEST_DSCP);

    nh_backend_clear();
}

MARLIN_TEST(gue_encap_dscp_marks_the_outer_header)
{
    struct xdp_run_result result;

    seed_encap_cfg(GUE_TUNNEL_SRC, 1500);
    nh_backend_seed(MARLIN_MODE_GUE, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, 0, NULL);
    nh_vip_seed(VIP_HASH_5TUPLE | ((TEST_DSCP << VIP_DSCP_SHIFT) & VIP_DSCP_MASK));
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    gue_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, GUE_TUNNEL_SRC, NH_BACKEND_ADDR, 0, AF_INET, result.out_len,
                     (__u8)TEST_DSCP);

    nh_backend_clear();
}

MARLIN_TEST(vxlan_encap_dscp_marks_the_outer_header)
{
    struct xdp_run_result result;

    seed_encap_cfg(VXLAN_TUNNEL_SRC, 1500);
    nh_backend_seed(MARLIN_MODE_VXLAN, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, VXLAN_VNI, VXLAN_INNER_MAC);
    nh_vip_seed(VIP_HASH_5TUPLE | ((TEST_DSCP << VIP_DSCP_SHIFT) & VIP_DSCP_MASK));
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    vxlan_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, VXLAN_TUNNEL_SRC, NH_BACKEND_ADDR, 0, VXLAN_INNER_MAC, VXLAN_VNI,
                       result.out_len, (__u8)TEST_DSCP);

    nh_backend_clear();
}

MARLIN_TEST(l2dsr_configured_dscp_leaves_the_frame_unchanged)
{
    /*
     * Negative case for the L2 DSR boundary the feature promises
     * (docs/design/14-forwarding-modes.md SS7.2): a VIP's configured DSCP
     * only ever reaches an outer header balancer.c writes for the three
     * tunnel modes, never an L2 DSR frame, which has no outer header to
     * carry it in the first place.
     */
    struct xdp_run_result result;

    nh_backend_seed(MARLIN_MODE_L2DSR, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, 0, NULL);
    nh_vip_seed(VIP_HASH_5TUPLE | ((TEST_DSCP << VIP_DSCP_SHIFT) & VIP_DSCP_MASK));
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    nh_backend_clear();
}
