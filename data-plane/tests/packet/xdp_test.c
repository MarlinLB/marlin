#define _GNU_SOURCE

#include <sched.h>
#include <stdio.h>
#include <string.h>

#include <linux/bpf.h>

#include <marlin/abi/types.h>
#include <marlin/marlin.h>
#include <marlin/proto.h>

#include "../harness.h"
#include "../packet.h"
#include "fib.h"
#include "maps.h"
#include "prog.h"

#define V4_SRC 0x0a0a0a0aU /* 10.10.10.10 */
#define V4_DST 0x0b0b0b0bU /* 11.11.11.11 */

static const unsigned char SRC6[16] = {0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
                                       0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80};
static const unsigned char DST6[16] = {0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
                                       0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90};

static unsigned char out_buf[XDP_TEST_RUN_MAX_SIZE];

static struct xdp_run_result run_current_packet(void)
{
    return xdp_run(pb_arena, pb_len, out_buf, sizeof(out_buf), 0);
}

static struct xdp_run_result run_packet_on(__u32 ingress_ifindex)
{
    return xdp_run(pb_arena, pb_len, out_buf, sizeof(out_buf), ingress_ifindex);
}

MARLIN_TEST(ok_ipv4_tcp_is_pass_and_uncounted)
{
    __u64 before = xdp_drop_stats_total(MARLIN_PASS_NOT_FORWARDED);
    struct xdp_run_result result;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(11111, 80);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
    CHECK_MEM(pb_arena, out_buf, pb_len); /* marlin_parse is read-only */

    CHECK_EQ(before, xdp_drop_stats_total(MARLIN_PASS_NOT_FORWARDED));
}

MARLIN_TEST(ok_ipv6_udp_is_pass)
{
    struct xdp_run_result result;

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_UDP, SRC6, DST6);
    pb_ports(53, 33333);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
}

MARLIN_TEST(not_forwarded_arp_is_pass_and_counted)
{
    __u64 before = xdp_drop_stats_total(MARLIN_PASS_NOT_FORWARDED);
    struct xdp_run_result result;

    pb_reset();
    pb_eth(ETH_P_ARP); /* exactly ETH_HLEN bytes: the XDP_TEST_RUN_MIN_SIZE floor */

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_PASS_NOT_FORWARDED));
}

MARLIN_TEST(not_forwarded_sctp_is_pass_and_counted)
{
    __u64 before = xdp_drop_stats_total(MARLIN_PASS_NOT_FORWARDED);
    struct xdp_run_result result;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_SCTP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_PASS_NOT_FORWARDED));
}

MARLIN_TEST(icmp_echo_request_is_pass_and_counted)
{
    __u64 before = xdp_drop_stats_total(MARLIN_PASS_ICMP_ECHO);
    struct xdp_run_result result;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ICMP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_icmp(ICMP_ECHO, 0);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_PASS_ICMP_ECHO));
}

MARLIN_TEST(unsupported_proto_esp_is_drop_and_counted)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_UNSUPPORTED_PROTO);
    struct xdp_run_result result;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ESP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_UNSUPPORTED_PROTO));
}

MARLIN_TEST(parse_error_truncated_ipv4_is_drop_and_distinct_from_ext_hdr_limit)
{
    __u64 parse_error_before = xdp_drop_stats_total(MARLIN_DROP_PARSE_ERROR);
    __u64 ext_hdr_limit_before = xdp_drop_stats_total(MARLIN_DROP_EXT_HDR_LIMIT);
    struct xdp_run_result result;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_truncate(14 + 10); /* 10 of the IPv4 header's 20 bytes: iph+1 > data_end */

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(parse_error_before + 1, xdp_drop_stats_total(MARLIN_DROP_PARSE_ERROR));
    CHECK_EQ(ext_hdr_limit_before, xdp_drop_stats_total(MARLIN_DROP_EXT_HDR_LIMIT));
}

MARLIN_TEST(parse_error_minimal_frame_no_l3_bytes_is_drop)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_PARSE_ERROR);
    struct xdp_run_result result;

    pb_reset();
    pb_eth(ETH_P_IP); /* data_end right at ETH_HLEN: the min data_size_in itself, zero IPv4 bytes */

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_PARSE_ERROR));
}

MARLIN_TEST(ext_hdr_limit_nine_headers_is_drop_and_distinct_from_parse_error)
{
    __u64 ext_hdr_limit_before = xdp_drop_stats_total(MARLIN_DROP_EXT_HDR_LIMIT);
    __u64 parse_error_before = xdp_drop_stats_total(MARLIN_DROP_PARSE_ERROR);
    struct xdp_run_result result;
    int i;

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_HOPOPTS, SRC6, DST6);
    for(i = 0; i < 9; i++) {
        pb_ext6(IPPROTO_HOPOPTS, 0); /* 9 > MAX_EXT_HDRS(8): see parser_test.c's walk_ext6_nine_headers_is_limit */
    }

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(ext_hdr_limit_before + 1, xdp_drop_stats_total(MARLIN_DROP_EXT_HDR_LIMIT));
    CHECK_EQ(parse_error_before, xdp_drop_stats_total(MARLIN_DROP_PARSE_ERROR));
}

MARLIN_TEST(icmp_unparseable_no_embedded_header_is_drop_and_counted)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_ICMP_UNPARSEABLE);
    struct xdp_run_result result;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ICMP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_icmp(ICMP_DEST_UNREACH, 0); /* data_end ends here: zero bytes of embedded header */

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_ICMP_UNPARSEABLE));
}

#define ACL_ADDR4(a, b, c, d) bpf_htonl(((__u32)(a) << 24) | ((__u32)(b) << 16) | ((__u32)(c) << 8) | (__u32)(d))

static void seed_acl_cfg(__u32 flags, __u16 acl_lists)
{
    struct marlin_config cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.flags = flags;
    cfg.acl_lists = acl_lists;
    xdp_seed_config(&cfg);
}

static void build_udp4(__be32 src, __be32 dst)
{
    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_UDP, MARLIN_IPV4_IHL_MIN, 0, src, dst);
    pb_ports(11111, 53);
}

static void build_udp6(const unsigned char src[16], const unsigned char dst[16])
{
    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_UDP, src, dst);
    pb_ports(11111, 53);
}

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

MARLIN_TEST(pending_phase3_acl_placement_blocked_source_non_vip_dest)
{
    MARLIN_SKIP("docs/PHASES.md:329-332 -- needs the VIP lookup xdp_main does not have yet");
}

MARLIN_TEST(pending_phase4_acl_allow_survives_rate_limiter)
{
    MARLIN_SKIP("docs/design/24-testing.md:133 -- needs the rate limiter xdp_main does not have yet");
}

MARLIN_TEST(pending_phase2_ok_tx_returns_xdp_tx)
{
    MARLIN_SKIP("docs/PHASES.md:142-144 -- needs VIP forwarding xdp_main does not have yet");
}

MARLIN_TEST(pending_phase2_ok_redirect_returns_xdp_redirect)
{
    /* MARLIN_OK_REDIRECT is unreachable for the same reason. */
    MARLIN_SKIP("docs/PHASES.md:142-144 -- needs VIP forwarding xdp_main does not have yet");
}

MARLIN_TEST(pending_phase1_criterion2_vip_miss_is_pass_and_counted)
{
    /* docs/PHASES.md:143 -- "a miss returning XDP_PASS counting vip_miss". */
    MARLIN_SKIP("docs/PHASES.md:143 -- needs the VIP lookup xdp_main does not have yet");
}

MARLIN_TEST(pending_phase1_criterion2_no_backend_is_drop)
{
    /* docs/PHASES.md:143-144 -- "backend_id == 0 dropping no_backend". */
    MARLIN_SKIP("docs/PHASES.md:143-144 -- needs the VIP lookup xdp_main does not have yet");
}

MARLIN_TEST(pending_phase1_criterion2_backend_down_is_drop)
{
    /* docs/PHASES.md:144 -- "state != MARLIN_UP dropping backend_down". */
    MARLIN_SKIP("docs/PHASES.md:144 -- needs the VIP lookup xdp_main does not have yet");
}

#define NH_INGRESS_IFINDEX 1U

#define NH_BACKEND_ADDR 0x0c0c0c0cU /* 12.12.12.12 */

static const unsigned char NH_MARLIN_MAC[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
static const unsigned char NH_ROUTER_MAC[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
static const unsigned char NH_BACKEND_MAC[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x03};

static const unsigned char NH_DECOY_MAC[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0b};

static void nh_backend_write(const struct backend *be)
{
    __u32 key = 0;
    int fd = xdp_map_fd("backends");

    if(bpf_map_update_elem(fd, &key, be, BPF_ANY) != 0) {
        fprintf(stderr, "packet-tests: failed to seed backends[0]: %s\n", strerror(errno));
        exit(1);
    }
}

static void nh_backend_clear(void)
{
    struct backend be;

    memset(&be, 0, sizeof(be));
    nh_backend_write(&be);
}

static void nh_backend_seed(__u8 mode_and_flags, __be32 addr, const unsigned char *mac, __u32 egress_ifindex)
{
    struct backend be;

    memset(&be, 0, sizeof(be));
    be.flags = (__u8)(mode_and_flags | MARLIN_BE_F_STATE);
    be.addr = addr;
    be.egress_ifindex = egress_ifindex;

    if(mac != NULL) {
        memcpy(be.mac, mac, ETH_ALEN);
    }

    nh_backend_write(&be);
}

static void nh_build_frame(void)
{
    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(11111, 80);
}

static void nh_check_frame(const unsigned char *expect_dst, const unsigned char *expect_src, __u32 out_len)
{
    unsigned char expect[ETH_HLEN];

    CHECK_EQ(pb_len, out_len);
    memcpy(expect, pb_arena, ETH_HLEN);
    memcpy(expect, expect_dst, ETH_ALEN);
    memcpy(expect + ETH_ALEN, expect_src, ETH_ALEN);
    CHECK_MEM(expect, out_buf, sizeof(expect));
    CHECK_MEM(pb_arena + ETH_HLEN, out_buf + ETH_HLEN, pb_len - ETH_HLEN);
}

#define IPIP_TUNNEL_SRC 0x0d0d0d0dU /* 13.13.13.13 */

/* config is process-global and outlives a case: every ipip_* case seeds its
 * own tunnel_src/max_frame rather than relying on what an earlier case left,
 * mirroring seed_acl_cfg's discipline above.
 */
static void seed_encap_cfg(__be32 tunnel_src, __u16 max_frame)
{
    struct marlin_config cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.tunnel_src = tunnel_src;
    cfg.max_frame = max_frame;
    xdp_seed_config(&cfg);
}

static void nh_build_frame_v6(void)
{
    pb_reset();
    pb_eth(ETH_P_IPV6);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv6(IPPROTO_TCP, SRC6, DST6);
    pb_ports(11111, 80);
}

/* A from-scratch reimplementation, not a call into csum.h: including
 * <marlin/csum.h> here would drag in the real <bpf/bpf_helpers.h> for
 * __always_inline, which conflicts with the userspace <bpf/bpf.h>/
 * <bpf/libbpf.h> this tier's own fib.h needs (both declare
 * bpf_map_update_elem et al. with incompatible signatures). An independent
 * implementation also means this assertion does not share a bug with the
 * one it is checking; tests/csum_test.c verifies csum.h's own algorithm.
 */
static __sum16 test_ipv4_csum(const struct iphdr *iph)
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

/* IPIP-specific sibling of nh_check_frame(): the frame grew by
 * MARLIN_OVERHEAD_IPIP, so neither "same length" nor "everything past
 * ETH_HLEN is unchanged" applies. Asserts the outer Ethernet addresses, the
 * whole outer IPv4 header byte-for-byte, and that the inner packet moved
 * without otherwise changing.
 */
static void ipip_check_frame(const unsigned char *expect_dst, const unsigned char *expect_src, __be32 tunnel_src,
                             __be32 backend_addr, __u8 inner_family, __u32 out_len)
{
    unsigned char expect_eth[ETH_HLEN];
    struct iphdr expect_iph;

    CHECK_EQ(pb_len + MARLIN_OVERHEAD_IPIP, out_len);

    memcpy(expect_eth, pb_arena, ETH_HLEN);
    memcpy(expect_eth, expect_dst, ETH_ALEN);
    memcpy(expect_eth + ETH_ALEN, expect_src, ETH_ALEN);
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

MARLIN_TEST(pending_phase2b_no_neigh_onlink_ingress_is_neigh_fallback)
{
    __u64 fallback_before = xdp_drop_stats_total(MARLIN_COUNT_NEIGH_FALLBACK);
    __u64 mismatch_before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    struct xdp_run_result result;

    fib_neigh_del(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS);
    fib_neigh_set(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS, FIB_MAC_BACKEND_A, "failed");

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_BACKEND_A, NH_BACKEND_MAC, 0);
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

MARLIN_TEST(pending_phase2b_no_neigh_onlink_other_egress_is_drop)
{
    /* docs/design/24-testing.md:63-64 -- on-link but FIB returns another
     * interface: drop fib_no_neigh, no frame emitted.
     */
    __u64 no_neigh_before = xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH);
    __u64 fallback_before = xdp_drop_stats_total(MARLIN_COUNT_NEIGH_FALLBACK);
    struct xdp_run_result result;

    fib_neigh_del(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS);
    fib_neigh_set(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS, FIB_MAC_BACKEND_B, "failed");

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_BACKEND_B, NH_BACKEND_MAC, 0);
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

MARLIN_TEST(pending_phase2b_no_neigh_gatewayed_ingress_is_drop)
{
    __u64 no_neigh_before = xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH);
    __u64 fallback_before = xdp_drop_stats_total(MARLIN_COUNT_NEIGH_FALLBACK);
    struct xdp_run_result result;

    fib_route_add_via(FIB_ADDR_GATEWAYED, FIB_ADDR_GATEWAY, FIB_DEV_INGRESS);
    fib_neigh_del(FIB_ADDR_GATEWAY, FIB_DEV_INGRESS);
    fib_neigh_set(FIB_ADDR_GATEWAY, FIB_DEV_INGRESS, FIB_MAC_GATEWAY, "failed");

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_GATEWAYED, NH_BACKEND_MAC, 0);
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

MARLIN_TEST(pending_phase2b_no_neigh_onlink_ingress_zero_mac_is_drop)
{
    /* docs/design/24-testing.md:66-67 -- the on-link ingress case again
     * with an all-zero backend.mac: drop, nothing left to fall back to.
     */
    __u64 no_neigh_before = xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH);
    __u64 fallback_before = xdp_drop_stats_total(MARLIN_COUNT_NEIGH_FALLBACK);
    struct xdp_run_result result;

    fib_neigh_del(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS);
    fib_neigh_set(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS, FIB_MAC_BACKEND_A, "failed");

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_BACKEND_A, NULL, 0);
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

MARLIN_TEST(pending_phase2b_no_neigh_under_ipip_is_drop)
{
    __u64 no_neigh_before = xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH);
    struct xdp_run_result result;

    fib_neigh_del(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS);
    fib_neigh_set(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS, FIB_MAC_BACKEND_A, "failed");

    seed_encap_cfg(IPIP_TUNNEL_SRC, 1500);
    nh_backend_seed(MARLIN_MODE_IPIP | MARLIN_BE_F_FIB, FIB_ADDR_BACKEND_A, NH_BACKEND_MAC, 0);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    /* Encapsulation precedes next-hop resolution: the frame already grew by
     * MARLIN_OVERHEAD_IPIP by the time the FIB lookup fails.
     */
    ipip_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, IPIP_TUNNEL_SRC, FIB_ADDR_BACKEND_A, AF_INET, result.out_len);
    CHECK_EQ(no_neigh_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH));

    nh_backend_clear();
    fib_neigh_del(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS);
}

MARLIN_TEST(pending_phase2b_fib_fallback_resolves_backend_not_vip)
{
    __u64 fallback_before = xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK);
    struct xdp_run_result result;

    fib_neigh_del(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS);
    fib_neigh_set(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS, FIB_MAC_BACKEND_A, "permanent");
    fib_route_add_onlink(V4_DST, FIB_DEV_INGRESS);
    fib_neigh_del(V4_DST, FIB_DEV_INGRESS);
    fib_neigh_set(V4_DST, FIB_DEV_INGRESS, NH_DECOY_MAC, "permanent");

    nh_backend_seed(MARLIN_MODE_L2DSR, FIB_ADDR_BACKEND_A, NULL, 0);
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

MARLIN_TEST(pending_phase2b_fib_flag_beats_resolved_mac)
{
    __u64 mismatch_before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    struct xdp_run_result result;

    fib_neigh_del(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS);
    fib_neigh_set(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS, FIB_MAC_BACKEND_B, "permanent");
    xdp_tx_ports_add((__u32)fib_ifindex(FIB_DEV_EGRESS));

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_BACKEND_B, NH_BACKEND_MAC, 0);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_REDIRECT, result.retval);
    nh_check_frame(FIB_MAC_BACKEND_B, FIB_MAC_EGRESS, result.out_len);
    CHECK_EQ(mismatch_before, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));

    nh_backend_seed(MARLIN_MODE_L2DSR, FIB_ADDR_BACKEND_B, NH_BACKEND_MAC, 0);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    nh_backend_clear();
    xdp_tx_ports_clear();
    fib_neigh_del(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS);
}

MARLIN_TEST(pending_phase2b_l2dsr_refuses_gatewayed_ipip_forwards)
{
    __u64 gatewayed_before;
    struct xdp_run_result result;

    fib_route_add_via(FIB_ADDR_GATEWAYED, FIB_ADDR_GATEWAY, FIB_DEV_INGRESS);
    fib_neigh_del(FIB_ADDR_GATEWAY, FIB_DEV_INGRESS);
    fib_neigh_set(FIB_ADDR_GATEWAY, FIB_DEV_INGRESS, FIB_MAC_GATEWAY, "permanent");

    gatewayed_before = xdp_drop_stats_total(MARLIN_DROP_FIB_GATEWAYED);
    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_GATEWAYED, NH_BACKEND_MAC, 0);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(gatewayed_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_GATEWAYED));

    seed_encap_cfg(IPIP_TUNNEL_SRC, 1500);
    nh_backend_seed(MARLIN_MODE_IPIP | MARLIN_BE_F_FIB, FIB_ADDR_GATEWAYED, NH_BACKEND_MAC, 0);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    /* The mode split is the whole point here: the same route that L2DSR
     * refused above forwards under IPIP, with the FIB's own smac/dmac
     * overwriting the outer Ethernet header ipip.c relocated.
     */
    ipip_check_frame(FIB_MAC_GATEWAY, FIB_MAC_INGRESS, IPIP_TUNNEL_SRC, FIB_ADDR_GATEWAYED, AF_INET, result.out_len);

    nh_backend_clear();
    fib_neigh_del(FIB_ADDR_GATEWAY, FIB_DEV_INGRESS);
    fib_route_del(FIB_ADDR_GATEWAYED);
}

MARLIN_TEST(pending_phase2b_egress_mismatch_counts_verdict_unchanged)
{
    __u64 mismatch_before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    struct xdp_run_result result;
    int nofwd_ifindex = fib_ifindex(FIB_DEV_NOFWD);

    fib_neigh_del(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS);
    fib_neigh_set(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS, FIB_MAC_BACKEND_B, "permanent");
    xdp_tx_ports_add((__u32)fib_ifindex(FIB_DEV_EGRESS));
    xdp_tx_ports_add((__u32)nofwd_ifindex);

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_BACKEND_B, NH_BACKEND_MAC, (__u32)nofwd_ifindex);
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

MARLIN_TEST(pending_phase2b_egress_mismatch_plus_no_tx_port_is_drop)
{
    __u64 mismatch_before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    __u64 no_tx_port_before = xdp_drop_stats_total(MARLIN_DROP_NO_TX_PORT);
    struct xdp_run_result result;
    int nofwd_ifindex = fib_ifindex(FIB_DEV_NOFWD);

    fib_neigh_del(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS);
    fib_neigh_set(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS, FIB_MAC_BACKEND_B, "permanent");
    xdp_tx_ports_add((__u32)nofwd_ifindex); /* the FIB's own interface, mve1, is deliberately absent */

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_BACKEND_B, NH_BACKEND_MAC, (__u32)nofwd_ifindex);
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
    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_BLACKHOLE, NH_BACKEND_MAC, 0);
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
    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_UNREACHABLE, NH_BACKEND_MAC, 0);
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
    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_PROHIBIT, NH_BACKEND_MAC, 0);
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

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_MTU_ROUTE, NH_BACKEND_MAC, 0);
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

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_UNROUTED, NH_BACKEND_MAC, 0);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_UNSPEC));

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_INGRESS, NH_BACKEND_MAC, 0);
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

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_UNROUTED, NH_BACKEND_MAC, 0);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_NOFWD));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_FWD_DISABLED));

    nh_backend_clear();
}

MARLIN_TEST(nexthop_interim_l2dsr_stored_mac_is_tx_on_backend_mac)
{
    __u64 fallback_before = xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK);
    __u64 mismatch_before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    struct xdp_run_result result;

    nh_backend_seed(MARLIN_MODE_L2DSR, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    CHECK_EQ(fallback_before, xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK));
    CHECK_EQ(mismatch_before, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));

    nh_backend_clear();
}

MARLIN_TEST(nexthop_interim_l2dsr_egress_mismatch_counts_verdict_unchanged)
{
    __u64 before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    struct xdp_run_result result;

    nh_backend_seed(MARLIN_MODE_L2DSR, NH_BACKEND_ADDR, NH_BACKEND_MAC, NH_INGRESS_IFINDEX + 1);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));

    nh_backend_clear();
}

MARLIN_TEST(nexthop_interim_l2dsr_egress_match_does_not_count)
{
    __u64 before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    struct xdp_run_result result;

    nh_backend_seed(MARLIN_MODE_L2DSR, NH_BACKEND_ADDR, NH_BACKEND_MAC, NH_INGRESS_IFINDEX);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(before, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));

    nh_backend_clear();
}

MARLIN_TEST(nexthop_interim_l2dsr_zero_mac_zero_addr_is_backend_unresolved)
{
    __u64 unresolved_before = xdp_drop_stats_total(MARLIN_DROP_BACKEND_UNRESOLVED);
    __u64 fallback_before = xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK);
    struct xdp_run_result result;

    nh_backend_seed(MARLIN_MODE_L2DSR, 0, NULL, 0);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(unresolved_before + 1, xdp_drop_stats_total(MARLIN_DROP_BACKEND_UNRESOLVED));
    CHECK_EQ(fallback_before, xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK));

    nh_backend_clear();
}

MARLIN_TEST(nexthop_interim_l2dsr_zero_mac_resolvable_addr_counts_mac_fallback)
{
    __u64 fallback_before = xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK);
    __u64 fwd_disabled_before = xdp_drop_stats_total(MARLIN_DROP_FIB_FWD_DISABLED);
    struct xdp_run_result result;

    nh_backend_seed(MARLIN_MODE_L2DSR, NH_BACKEND_ADDR, NULL, 0);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(fallback_before + 1, xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK));
    CHECK_EQ(fwd_disabled_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_FWD_DISABLED));

    nh_backend_clear();
}

MARLIN_TEST(nexthop_interim_l2dsr_fib_flag_does_not_use_stored_mac)
{
    __u64 fallback_before = xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK);
    __u64 fwd_disabled_before = xdp_drop_stats_total(MARLIN_DROP_FIB_FWD_DISABLED);
    struct xdp_run_result result;

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0);
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
    nh_backend_seed(MARLIN_MODE_IPIP, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    ipip_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, IPIP_TUNNEL_SRC, NH_BACKEND_ADDR, AF_INET, result.out_len);
    CHECK_EQ(mismatch_before, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));

    nh_backend_clear();
}

MARLIN_TEST(ipip_encap_ipv6_inner_sets_protocol_41)
{
    struct xdp_run_result result;

    seed_encap_cfg(IPIP_TUNNEL_SRC, 1500);
    nh_backend_seed(MARLIN_MODE_IPIP, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0);
    nh_build_frame_v6();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    ipip_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, IPIP_TUNNEL_SRC, NH_BACKEND_ADDR, AF_INET6, result.out_len);

    nh_backend_clear();
}

MARLIN_TEST(ipip_encap_frame_too_big_drops_before_adjust_head)
{
    __u64 too_big_before;
    struct xdp_run_result result;

    /* Far smaller than any encapsulated test frame: this is a wiring proof
     * that ipip.c checks and drops before touching the packet, not the
     * boundary arithmetic itself, which tests/mtu_test.c already covers.
     */
    seed_encap_cfg(IPIP_TUNNEL_SRC, 10);
    too_big_before = xdp_drop_stats_total(MARLIN_DROP_FRAME_TOO_BIG);

    nh_backend_seed(MARLIN_MODE_IPIP, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0);
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
    nh_backend_seed(MARLIN_MODE_IPIP, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0);
    nh_build_frame();
    pb_pad(2000); /* well past any real MTU; only max_frame == 0 lets this through */

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    ipip_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, IPIP_TUNNEL_SRC, NH_BACKEND_ADDR, AF_INET, result.out_len);

    nh_backend_clear();
}

MARLIN_TEST(nexthop_interim_encap_vxlan_leaves_ethernet_addresses_alone)
{
    struct xdp_run_result result;

    nh_backend_seed(MARLIN_MODE_VXLAN, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);

    nh_backend_clear();
}

MARLIN_TEST(nexthop_interim_encap_fib_flag_beats_the_vxlan_no_swap_test)
{
    __u64 fwd_disabled_before = xdp_drop_stats_total(MARLIN_DROP_FIB_FWD_DISABLED);
    __u64 mismatch_before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    struct xdp_run_result result;

    nh_backend_seed(MARLIN_MODE_VXLAN | MARLIN_BE_F_FIB, NH_BACKEND_ADDR, NH_BACKEND_MAC, NH_INGRESS_IFINDEX + 1);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(fwd_disabled_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_FWD_DISABLED));
    CHECK_EQ(mismatch_before, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));

    nh_backend_clear();
}

MARLIN_TEST(nexthop_interim_gate_closed_leaves_every_other_case_alone)
{
    struct xdp_run_result result;

    nh_backend_seed(MARLIN_MODE_L2DSR, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0);
    nh_backend_clear();
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
}

/* ---- end interim nexthop.c coverage ------------------------------------- */

MARLIN_TEST(fib_cases_leave_no_route_or_neigh_state)
{
    __u64 unspec_before = xdp_drop_stats_total(MARLIN_DROP_FIB_UNSPEC);
    __u64 no_neigh_before = xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH);
    struct xdp_run_result result;

    CHECK_TRUE(xdp_tx_ports_is_empty());

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_GATEWAYED, NH_BACKEND_MAC, 0);
    nh_build_frame();
    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(unspec_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_UNSPEC));
    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_BACKEND_A, NULL, 0);
    nh_build_frame();
    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(no_neigh_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH));

    nh_backend_clear();
}

int main(int argc, char **argv)
{
    const char *obj_path = (argc > 1) ? argv[1] : "build/marlin.bpf.o";
    struct marlin_config cfg;
    int rc;

    if(unshare(CLONE_NEWNET) != 0) {
        fprintf(stderr, "packet-tests: unshare(CLONE_NEWNET) failed: %s\n", strerror(errno));
        exit(1);
    }

    fib_topology_up();

    xdp_prog_load(obj_path);

    memset(&cfg, 0, sizeof(cfg));
    xdp_seed_config(&cfg);

    rc = marlin_tests_main();

    xdp_prog_unload();
    return rc;
}
