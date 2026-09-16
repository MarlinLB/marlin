/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Source filtering / ACL cases (docs/design/27-source-filtering.md): block
 * and allow lists, prefix-length precedence, list-bit gating, fragments and
 * ICMP-embedded tuples. Frame construction (build_udp4/build_udp6) and
 * config seeding (seed_acl_cfg) live in xdp_fixture.h -- xdp_30_ratelimit.c
 * and xdp_70_acl_placement.c reuse both.
 */

#include <linux/bpf.h>
#include <linux/in.h>

#include <marlin/abi/types.h>
#include <marlin/marlin.h>

#include "../harness.h"
#include "../packet.h"
#include "maps.h"
#include "prog.h"
#include "xdp_fixture.h"

MARLIN_TEST(acl_key_struct_sizes_match_lpm_prefixlen_widths)
{
    CHECK_EQ(8, sizeof(struct acl_key4));
    CHECK_EQ(20, sizeof(struct acl_key6));
}

MARLIN_TEST(acl_v4_block_matched_is_drop_and_counted)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED);
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_block_v4", 32, ACL_ADDR4(10, 20, 20, 20), 1);
    seed_acl_cfg(CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));

    build_udp4(ACL_ADDR4(10, 20, 20, 20), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED));
}

MARLIN_TEST(acl_v4_block_missed_is_pass)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED);
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_block_v4", 32, ACL_ADDR4(10, 20, 20, 20), 1);
    seed_acl_cfg(CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));

    build_udp4(ACL_ADDR4(10, 20, 20, 21), V4_DST); /* one host away from the blocked entry */
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
    CHECK_EQ(before, xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED));
}

MARLIN_TEST(acl_v6_block_matched_is_drop_and_counted)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED);
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v6");
    xdp_acl_clear("acl_block_v6");
    xdp_acl_add6("acl_block_v6", 128, SRC6, 1);
    seed_acl_cfg(CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V6));

    build_udp6(SRC6, DST6);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED));
}

MARLIN_TEST(acl_v6_block_missed_is_pass)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED);
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v6");
    xdp_acl_clear("acl_block_v6");
    xdp_acl_add6("acl_block_v6", 128, SRC6, 1);
    seed_acl_cfg(CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V6));

    build_udp6(DST6, SRC6); /* DST6 as the client address: not the blocked SRC6 entry */
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
    CHECK_EQ(before, xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED));
}

MARLIN_TEST(acl_v4_allow_beats_covering_block_is_pass)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED);
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_allow_v4", 32, ACL_ADDR4(10, 30, 30, 30), 1);
    xdp_acl_add4("acl_block_v4", 32, ACL_ADDR4(10, 30, 30, 30), 2); /* same host, both lists */
    seed_acl_cfg(CFG_ACL_ENABLE, (__u16)(ACL_LISTS_BIT(ACL_LIST_ALLOW, ACL_FAMILY_V4) | ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4)));

    build_udp4(ACL_ADDR4(10, 30, 30, 30), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
    CHECK_EQ(before, xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED));
}

MARLIN_TEST(acl_v6_allow_beats_covering_block_is_pass)
{
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v6");
    xdp_acl_clear("acl_block_v6");
    xdp_acl_add6("acl_allow_v6", 128, SRC6, 1);
    xdp_acl_add6("acl_block_v6", 128, SRC6, 2);
    seed_acl_cfg(CFG_ACL_ENABLE, (__u16)(ACL_LISTS_BIT(ACL_LIST_ALLOW, ACL_FAMILY_V6) | ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V6)));

    build_udp6(SRC6, DST6);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
}

MARLIN_TEST(acl_v4_slash24_block_covers_inside_not_outside)
{
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_block_v4", 24, ACL_ADDR4(10, 40, 50, 0), 1);
    seed_acl_cfg(CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));

    build_udp4(ACL_ADDR4(10, 40, 50, 7), V4_DST); /* inside 10.40.50.0/24 */
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);

    build_udp4(ACL_ADDR4(10, 40, 51, 7), V4_DST); /* outside it: third octet differs */
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
}

MARLIN_TEST(acl_v4_slash32_block_does_not_cover_neighbour)
{
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_block_v4", 32, ACL_ADDR4(10, 60, 60, 6), 1);
    seed_acl_cfg(CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));

    build_udp4(ACL_ADDR4(10, 60, 60, 6), V4_DST); /* the exact blocked host */
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);

    build_udp4(ACL_ADDR4(10, 60, 60, 7), V4_DST); /* its neighbour: last octet differs */
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
}

MARLIN_TEST(acl_v4_nested_block_prefixes_in_one_trie)
{
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_block_v4", 8, ACL_ADDR4(10, 0, 0, 0), 1);
    xdp_acl_add4("acl_block_v4", 24, ACL_ADDR4(10, 130, 40, 0), 2);
    xdp_acl_add4("acl_block_v4", 32, ACL_ADDR4(10, 130, 40, 5), 3);
    seed_acl_cfg(CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));

    build_udp4(ACL_ADDR4(10, 130, 40, 5), V4_DST); /* matches all three entries */
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);

    build_udp4(ACL_ADDR4(10, 130, 40, 9), V4_DST); /* in the /24 and /8, not the /32 */
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);

    build_udp4(ACL_ADDR4(10, 130, 99, 9), V4_DST); /* in the /8 only */
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);

    build_udp4(ACL_ADDR4(11, 130, 40, 5), V4_DST); /* outside the /8: first octet differs */
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
}

MARLIN_TEST(acl_v4_slash8_allow_beats_slash32_block)
{
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_allow_v4", 8, ACL_ADDR4(10, 0, 0, 0), 1);
    xdp_acl_add4("acl_block_v4", 32, ACL_ADDR4(10, 70, 70, 70), 2);
    seed_acl_cfg(CFG_ACL_ENABLE, (__u16)(ACL_LISTS_BIT(ACL_LIST_ALLOW, ACL_FAMILY_V4) | ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4)));

    build_udp4(ACL_ADDR4(10, 70, 70, 70), V4_DST); /* the more specific block entry, exactly */
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
}

MARLIN_TEST(acl_v4_equal_length_allow_beats_block)
{
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_allow_v4", 32, ACL_ADDR4(10, 80, 80, 80), 1);
    xdp_acl_add4("acl_block_v4", 32, ACL_ADDR4(10, 80, 80, 80), 2);
    seed_acl_cfg(CFG_ACL_ENABLE, (__u16)(ACL_LISTS_BIT(ACL_LIST_ALLOW, ACL_FAMILY_V4) | ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4)));

    build_udp4(ACL_ADDR4(10, 80, 80, 80), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
}

MARLIN_TEST(acl_v4_slash32_allow_beats_slash8_block_but_not_its_neighbour)
{
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_block_v4", 8, ACL_ADDR4(10, 0, 0, 0), 1);
    xdp_acl_add4("acl_allow_v4", 32, ACL_ADDR4(10, 90, 90, 90), 2);
    seed_acl_cfg(CFG_ACL_ENABLE, (__u16)(ACL_LISTS_BIT(ACL_LIST_ALLOW, ACL_FAMILY_V4) | ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4)));

    build_udp4(ACL_ADDR4(10, 90, 90, 90), V4_DST); /* the allowed host: escapes the /8 block */
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);

    build_udp4(ACL_ADDR4(10, 90, 90, 91), V4_DST); /* one host over: still just the /8 block */
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
}

MARLIN_TEST(acl_empty_list_bit_clear_skips_a_present_allow_rule)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED);
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_allow_v4", 32, ACL_ADDR4(10, 105, 105, 105), 1);
    xdp_acl_add4("acl_block_v4", 8, ACL_ADDR4(10, 0, 0, 0), 2);                 /* covers the allow entry */
    seed_acl_cfg(CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4)); /* the allow bit claims the list is empty */

    build_udp4(ACL_ADDR4(10, 105, 105, 105), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED));
}

MARLIN_TEST(acl_empty_list_bit_clear_skips_a_present_block_rule)
{
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_block_v4", 32, ACL_ADDR4(10, 100, 100, 100), 1);
    seed_acl_cfg(CFG_ACL_ENABLE, 0); /* the rule exists; acl_lists claims the list is empty */

    build_udp4(ACL_ADDR4(10, 100, 100, 100), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
}

MARLIN_TEST(acl_disabled_skips_a_present_block_rule)
{
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_block_v4", 32, ACL_ADDR4(10, 110, 110, 110), 1);
    seed_acl_cfg(0, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4)); /* CFG_ACL_ENABLE clear */

    build_udp4(ACL_ADDR4(10, 110, 110, 110), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
}

MARLIN_TEST(acl_v4_non_first_fragment_blocked_source_is_drop)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED);
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_block_v4", 32, ACL_ADDR4(10, 120, 120, 120), 1);
    seed_acl_cfg(CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0x0040 /* offset set, MF clear: non-first, last fragment */,
            ACL_ADDR4(10, 120, 120, 120), V4_DST);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED));
}

MARLIN_TEST(acl_v4_first_fragment_blocked_source_is_drop)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED);
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_block_v4", 32, ACL_ADDR4(10, 125, 125, 125), 1);
    seed_acl_cfg(CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, IP_MF /* offset zero, MF set: first fragment, more follow */,
            ACL_ADDR4(10, 125, 125, 125), V4_DST);
    pb_ports(443, 51000);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED));
}

MARLIN_TEST(acl_v6_non_first_fragment_blocked_source_is_drop)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED);
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v6");
    xdp_acl_clear("acl_block_v6");
    xdp_acl_add6("acl_block_v6", 128, SRC6, 1);
    seed_acl_cfg(CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V6));

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_FRAGMENT, SRC6, DST6);
    pb_frag6(IPPROTO_TCP, 0x0008 /* offset set, MF clear: non-first, last fragment */);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED));
}

MARLIN_TEST(acl_icmp_embedded_client_blocked_is_drop)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED);
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_block_v4", 32, ACL_ADDR4(10, 9, 9, 9), 1);
    seed_acl_cfg(CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ICMP, MARLIN_IPV4_IHL_MIN, 0, ACL_ADDR4(198, 51, 100, 1) /* router: irrelevant here */, V4_DST);
    pb_icmp(ICMP_DEST_UNREACH, 0);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, ACL_ADDR4(203, 0, 113, 5) /* embedded src: the VIP, unread */,
            ACL_ADDR4(10, 9, 9, 9) /* embedded dst: the client, becomes tuple.src */);
    pb_ports(443, 51000);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED));
}

MARLIN_TEST(acl_icmp_transit_router_blocked_is_pass)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED);
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_block_v4", 32, ACL_ADDR4(10, 9, 9, 9), 1); /* same rule as above */
    seed_acl_cfg(CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ICMP, MARLIN_IPV4_IHL_MIN, 0, ACL_ADDR4(10, 9, 9, 9) /* the blocked address, now the outer source */, V4_DST);
    pb_icmp(ICMP_DEST_UNREACH, 0);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, ACL_ADDR4(203, 0, 113, 5) /* embedded src: the VIP, unread */,
            ACL_ADDR4(10, 9, 9, 10) /* embedded dst: an unblocked client */);
    pb_ports(443, 51000);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
    CHECK_EQ(before, xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED));
}
