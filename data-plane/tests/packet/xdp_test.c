/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * bpf_prog_test_run tests for xdp_main -- the tier that runs the code as
 * compiled for the datapath (docs/design/24-testing.md, "Native unit
 * tests"). Coverage here is bounded by what xdp_main can distinguish today:
 * it parses, applies the ACL, counts, and returns XDP_PASS on every other
 * non-error path (main.c), since no VIP lookup or forwarding exists yet.
 * The four VIP assertions in docs/PHASES.md's Phase 1 exit criterion 2, and
 * MARLIN_OK_TX/MARLIN_OK_REDIRECT, are registered below via MARLIN_SKIP, so
 * the gap reports as a named `skip` line rather than as a pass or only in
 * docs/PHASES.md.
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>

#include <linux/bpf.h>

#include <marlin/abi/types.h>
#include <marlin/marlin.h>
#include <marlin/proto.h>

#include "../harness.h"
#include "../packet.h"
#include "maps.h"
#include "prog.h"

/* Symmetric bytes (all four octets equal), the same trick parser_test.c's
 * V4_SRC/V4_DST use, so no bpf_htonl is needed to hand a host-order literal
 * to pb_ipv4's __be32 parameters -- these values read the same either way.
 */
#define V4_SRC 0x0a0a0a0aU /* 10.10.10.10 */
#define V4_DST 0x0b0b0b0bU /* 11.11.11.11 */

static const unsigned char SRC6[16] = {0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
                                       0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80};
static const unsigned char DST6[16] = {0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
                                       0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90};

static unsigned char out_buf[XDP_TEST_RUN_MAX_SIZE];

static struct xdp_run_result run_current_packet(void)
{
    /* 0, load-bearing: the kernel sends any non-zero ingress_ifindex through
     * dev_get_by_index() and then xdp_rxq_info_is_reg() (xdp_convert_md_to_buff
     * in net/bpf/test_run.c), which no interface here satisfies -- not even
     * loopback registers XDP rxq info. A real ifindex needs the netns/veth
     * integration tier, not this one.
     */
    return xdp_run(pb_arena, pb_len, out_buf, sizeof(out_buf), 0);
}

/* ---- MARLIN_OK: bypasses marlin_action entirely (main.c:78 returns
 * XDP_PASS unconditionally on success), unlike every other case below which
 * goes through marlin_action's switch. Asserted separately for that reason.
 */

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

    /* marlin_count skips rc < MARLIN_PASS_VIP_MISS, and MARLIN_OK is 0 --
     * no drop_stats slot moves for a successful parse. MARLIN_PASS_NOT_FORWARDED
     * stands in for "any counted slot" here.
     */
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

/* ---- MARLIN_PASS_NOT_FORWARDED: three distinct triggers in parser.c, one
 * verdict. Each is counted (rc sits between MARLIN_PASS_VIP_MISS and
 * MARLIN_RET_MAX in enum order).
 */

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

/* ---- The pair below is docs/PHASES.md:250-251's requirement made concrete:
 * ext_hdr_limit and parse_error both return XDP_DROP through marlin_action
 * (main.c:30-47 has no case for either), so opts.retval alone cannot tell
 * them apart -- only their distinct drop_stats index can. Each case asserts
 * its own index moves and the other one does not.
 */

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

/* ---- ACL (docs/design/27-source-filtering.md, docs/design/24-testing.md:104-124).
 * Reachable today: main.c calls marlin_acl_check() right after a successful
 * parse. Every case seeds its own marlin_config (flags, acl_lists) and clears
 * both tries it touches first -- xdp_seed_config's one all-zero call in
 * main() below is not enough once a case needs CFG_ACL_ENABLE or a non-empty
 * acl_lists, and BPF_F_NO_PREALLOC tries carry no zeroed baseline to reset to.
 */

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
    /* docs/PHASES.md Phase 3 exit criterion 5: a layout change alters what
     * the trie compares. abi/types.h asserts this at compile time already;
     * this is the runtime case that criterion asks for in addition.
     */
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

/* An allow hit is observationally identical to "no rule matched" until the
 * rate limiter exists to distinguish them (docs/design/24-testing.md:121-124),
 * so what these two cases assert is the one thing that IS observable now:
 * the allow trie's unconditional precedence over a covering block entry.
 */
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

/* "Longest-prefix selection" is unobservable from outside a single trie --
 * every hit in acl_block_v4 returns the same verdict regardless of which
 * entry matched. What full-width presentation (32, not the rule's own
 * prefixlen) actually buys is asserted here instead: a /24 blocks exactly its
 * 256 addresses, not its containing /8, and a /32 blocks exactly its one
 * host, not its containing /24 -- either bug would show up as one of the two
 * checks in each case below flipping.
 */
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

/* Every case above seeds exactly one entry per trie, so the verdict is
 * identical whichever entry matched -- a flat trie with a single leaf, no
 * intermediate node, no partial-match descent. docs/design/24-testing.md:109
 * asks for a /32 inside a /8 and a /24 inside a /8, which only a trie
 * holding more than one entry can exercise: the kernel builds an
 * intermediate node at the shared prefix and walks it on every lookup
 * below, a code path a single-leaf trie never reaches.
 */
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

    build_udp4(ACL_ADDR4(10, 131, 0, 1), V4_DST); /* outside the /8: second octet differs */
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
}

/* Allow wins unconditionally, not by specificity -- so all three relative
 * orderings must pass, and the third pairs a hit against a miss on the same
 * two rules to show the outcome really does turn on the allow trie, not on
 * the block trie happening not to match.
 */
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

/* The block-side gate above is the only acl_lists bit any case exercises.
 * This is the allow-side counterpart, and unlike the block-only case it is
 * observable through more than just the lookup being skipped: the allow
 * bit clear must let the covering block entry decide, so a broken gate
 * (one that always checks the allow trie regardless of the bit) would pass
 * here instead of dropping.
 */
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
    /* No ports on a fragment tail (docs/design/13-icmp.md's sibling case in
     * parser.c), but tuple.src is still populated from the IP header, which
     * is all the ACL reads -- the fragment hole a port-granular design would
     * have had does not exist here.
     */
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

/* The companion to the non-first case above: "identically" in
 * docs/design/24-testing.md:111-112 is a claim about both halves of a
 * fragmented datagram, not just the tail this file already covers.
 */
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

/* ICMP: parser.c reconstructs the tuple from the embedded header, source into
 * tuple.dst and destination into tuple.src (docs/design/13-icmp.md), so the
 * client the ACL must filter is the embedded DESTINATION, never the outer IP
 * source -- that outer source is the transit router (docs/design/27-source-filtering.md,
 * "What is matched"). One rule, reused both ways, makes the contrast direct:
 * as the embedded destination it must block; as the outer source it must not.
 */
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
    /* docs/PHASES.md:329-332, docs/design/24-testing.md:117-124 -- a blocked
     * source addressed to a destination that is not a VIP must drop
     * acl_blocked, not pass vip_miss. Every case above uses a destination no
     * VIP lookup ever runs against yet (main.c has none), so this is not
     * merely uncovered -- it is unfalsifiable until the VIP lookup exists:
     * every packet here would take this path regardless of whether step 3
     * ran before or after it.
     */
    MARLIN_SKIP("docs/PHASES.md:329-332 -- needs the VIP lookup xdp_main does not have yet");
}

MARLIN_TEST(pending_phase4_acl_allow_survives_rate_limiter)
{
    /* docs/PHASES.md:380-382, docs/design/24-testing.md:133 -- the other
     * half of the placement property: an allow verdict must suppress the
     * rate limiter rather than merely reach it unmetered. Needs
     * marlin_ratelimit() and CFG_RL_ENABLE, neither of which exists yet.
     */
    MARLIN_SKIP("docs/design/24-testing.md:133 -- needs the rate limiter xdp_main does not have yet");
}

/* ---- Placeholders: registered so the gap is visible in `make packet-tests`
 * output as a named `skip` line, not only in docs/PHASES.md's exit-criteria
 * table, and does not read as a passing assertion. When the code path a
 * case names lands, delete its MARLIN_SKIP line and replace it with the
 * real assertions -- the case name and doc reference do not change, so the
 * diff shows exactly which criterion closed.
 */

MARLIN_TEST(pending_phase2_ok_tx_returns_xdp_tx)
{
    /* MARLIN_OK_TX is unreachable: xdp_main has no VIP lookup or forwarding
     * path yet (main.c). docs/PHASES.md Phase 1 exit criterion 2's first
     * assertion -- a VIP hit rewriting the destination MAC and returning
     * XDP_TX -- lands with that code.
     */
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

/* ---- nexthop.c's Phase 2b assertion matrix (docs/design/24-testing.md:61-103,
 * docs/PHASES.md's Phase 2b exit criterion 1). Three blockers, all real, apply
 * to every case below: balancer.c does not exist, so xdp_main never calls
 * marlin_nexthop_l2dsr() or marlin_nexthop_encapsulate() (main.c returns
 * XDP_PASS after parsing); libbpf submits only subprograms reachable from a
 * SEC() program, so neither entry point is verified at all yet -- this tier
 * does not cover that gap either, since it loads the same marlin.bpf.o; and
 * even once balancer.c calls them, prog.h pins ingress_ifindex to 0 because no
 * interface here satisfies xdp_rxq_info_is_reg(), while bpf_fib_lookup()
 * rejects ifindex 0 -- so the FIB path needs the netns/veth integration tier
 * docs/design/24-testing.md assigns it, which does not exist yet (the only
 * scaffolding is scripts/netns-topo.sh). When that tier lands, delete each
 * MARLIN_SKIP line and replace it with the real assertion -- the case name and
 * doc reference do not change, so the diff shows exactly which criterion
 * closed.
 */

MARLIN_TEST(pending_phase2b_no_neigh_onlink_ingress_is_neigh_fallback)
{
    /* docs/design/16-fib-lookup.md:57, docs/design/24-testing.md:62-63 --
     * flagged L2 DSR backend, stored MAC, no neighbour, on-link route, FIB
     * returns the ingress interface: emit on the stored MAC, count
     * neigh_fallback, and assert the emitted source MAC is Marlin's
     * ingress MAC, not fib.smac (docs/design/24-testing.md:69-72).
     */
    MARLIN_SKIP("docs/design/16-fib-lookup.md:57 -- needs balancer.c and the netns/veth FIB tier");
}

MARLIN_TEST(pending_phase2b_no_neigh_onlink_other_egress_is_drop)
{
    /* docs/design/24-testing.md:63-64 -- on-link but FIB returns another
     * interface: drop fib_no_neigh, no frame emitted.
     */
    MARLIN_SKIP("docs/design/16-fib-lookup.md:58 -- needs balancer.c and the netns/veth FIB tier");
}

MARLIN_TEST(pending_phase2b_no_neigh_gatewayed_ingress_is_drop)
{
    /* docs/design/24-testing.md:64-66 -- gatewayed route, FIB returns the
     * ingress interface: drop, no frame -- the case that separates a
     * correct implementation from one that blackholes whenever a router's
     * neighbour entry expires.
     */
    MARLIN_SKIP("docs/design/16-fib-lookup.md:81-87 -- needs balancer.c and the netns/veth FIB tier");
}

MARLIN_TEST(pending_phase2b_no_neigh_onlink_ingress_zero_mac_is_drop)
{
    /* docs/design/24-testing.md:66-67 -- the on-link ingress case again
     * with an all-zero backend.mac: drop, nothing left to fall back to.
     */
    MARLIN_SKIP("docs/design/15-nexthop-l2dsr.md:77-79 -- needs balancer.c and the netns/veth FIB tier");
}

MARLIN_TEST(pending_phase2b_no_neigh_under_ipip_is_drop)
{
    /* docs/design/24-testing.md:67-68,74-78 -- the same missing neighbour
     * under IPIP must drop: the stored-MAC fallback is L2 DSR only.
     * docs/design/16-fib-lookup.md's FIB handling does not vary by mode, so
     * this one case stands for GUE and VXLAN too.
     */
    MARLIN_SKIP("docs/design/16-fib-lookup.md:67 -- needs balancer.c and the netns/veth FIB tier");
}

MARLIN_TEST(pending_phase2b_fib_fallback_resolves_backend_not_vip)
{
    /* docs/design/24-testing.md:80-84 -- L2 DSR, all-zero backend.mac, a
     * populated backend.addr with a neighbour entry: the emitted frame
     * carries that neighbour's MAC, not one resolved from the VIP. A
     * separate assertion in this case: both fields zero drops
     * backend_unresolved without reaching the helper at all -- that half
     * needs no FIB tier and is covered by unit reasoning, not a packet
     * test, since nothing about it depends on kernel routing state.
     */
    MARLIN_SKIP("docs/design/15-nexthop-l2dsr.md:85-88 -- needs balancer.c and the netns/veth FIB tier");
}

MARLIN_TEST(pending_phase2b_fib_flag_beats_resolved_mac)
{
    /* docs/design/24-testing.md:86-90 -- an L2 DSR backend carrying
     * MARLIN_BE_F_FIB and a non-zero backend.mac must take the FIB path;
     * assert the emitted source MAC is the egress interface's. Pair with
     * the unflagged case on the same backend, which must XDP_TX on the
     * stored MAC without touching the helper.
     */
    MARLIN_SKIP("docs/design/15-nexthop-l2dsr.md:35-53 -- needs balancer.c and the netns/veth FIB tier");
}

MARLIN_TEST(pending_phase2b_l2dsr_refuses_gatewayed_ipip_forwards)
{
    /* docs/design/24-testing.md:92-96 -- a backend whose addr is reachable
     * only via a router: L2 DSR drops fib_gatewayed with no frame emitted;
     * the same route under IPIP forwards normally. The mode split is the
     * whole content of the check, so both halves must be asserted against
     * the same route.
     */
    MARLIN_SKIP("docs/design/16-fib-lookup.md:12-27 -- needs balancer.c and the netns/veth FIB tier");
}

MARLIN_TEST(pending_phase2b_egress_mismatch_counts_verdict_unchanged)
{
    /* docs/design/24-testing.md:98-101 -- backend.egress_ifindex names an
     * interface the FIB does not choose, and that interface is in
     * tx_ports: the frame still emits on the FIB's interface, with
     * egress_mismatch incremented. Assert both halves.
     */
    MARLIN_SKIP("docs/design/16-fib-lookup.md:29-38 -- needs balancer.c and the netns/veth FIB tier");
}

MARLIN_TEST(pending_phase2b_egress_mismatch_plus_no_tx_port_is_drop)
{
    /* docs/design/24-testing.md:101-103 -- as above, but the FIB's
     * interface is absent from tx_ports: egress_mismatch increments AND
     * the packet drops no_tx_port -- the counter is not a claim the frame
     * left. The redirect keys on the FIB's ifindex, never on
     * backend.egress_ifindex (docs/PHASES.md's Phase 2b exit criterion 1).
     */
    MARLIN_SKIP("docs/design/16-fib-lookup.md:39-42 -- needs balancer.c and the netns/veth FIB tier");
}

int main(int argc, char **argv)
{
    const char *obj_path = (argc > 1) ? argv[1] : "build/marlin.bpf.o";
    struct marlin_config cfg;
    int rc;

    xdp_prog_load(obj_path);

    memset(&cfg, 0, sizeof(cfg));
    xdp_seed_config(&cfg);

    rc = marlin_tests_main();

    xdp_prog_unload();
    return rc;
}
