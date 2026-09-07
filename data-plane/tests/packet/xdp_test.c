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
    /* 0: every case above this file's nexthop.c sections has no ingress
     * device of its own and does not need one -- it binds to this process's
     * network namespace's loopback device (see nexthop_interim_*'s header
     * below), which is fine for anything that does not depend on FIB state.
     * The FIB cases (fib.h) pass a real ifindex through run_packet_on()
     * instead: dev_get_by_index() and xdp_rxq_info_is_reg()
     * (xdp_convert_md_to_buff, net/bpf/test_run.c) require rxq info
     * registered on the named device, which fib.h's XDP_PASS anchor is what
     * provides -- lo never does.
     */
    return xdp_run(pb_arena, pb_len, out_buf, sizeof(out_buf), 0);
}

/* Sibling of run_current_packet() for the fib.h cases: a real device's
 * ifindex, so bpf_fib_lookup() (nexthop.c) resolves against this process's
 * namespace instead of deterministically reporting FWD_DISABLED off lo.
 */
static struct xdp_run_result run_packet_on(__u32 ingress_ifindex)
{
    return xdp_run(pb_arena, pb_len, out_buf, sizeof(out_buf), ingress_ifindex);
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

    build_udp4(ACL_ADDR4(11, 130, 40, 5), V4_DST); /* outside the /8: first octet differs */
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

/* ---- shared by every nexthop.c case below: both the Phase 2b matrix
 * (real FIB state, via fib.h) and the interim-coverage section further
 * down (backends[0] through main.c's xdp_interim_nexthop()). One frame
 * builder and one backend seeder for both, so a divergence between what
 * the two tiers hand nexthop.c is not itself a source of false coverage.
 */

/* bpf_prog_test_run_xdp() binds the run to this process's network
 * namespace's loopback device when ctx_in.ingress_ifindex is 0, and
 * ctx->ingress_ifindex reads that device's ifindex -- 1, always, inside
 * the unshare(CLONE_NEWNET) namespace main() creates. Only the
 * interim-coverage section below runs with ingress_ifindex 0; the Phase 2b
 * matrix above it passes a real device through run_packet_on() instead.
 */
#define NH_INGRESS_IFINDEX 1U

#define NH_BACKEND_ADDR 0x0c0c0c0cU /* 12.12.12.12 */

static const unsigned char NH_MARLIN_MAC[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
static const unsigned char NH_ROUTER_MAC[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
static const unsigned char NH_BACKEND_MAC[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x03};

/* The decoy neighbour for pending_phase2b_fib_fallback_resolves_backend_not_vip:
 * a MAC distinct from every FIB_MAC_* in fib.h and from NH_BACKEND_MAC, so a
 * lookup that used the wrong address is visible as a wrong MAC, not merely a
 * different verdict class.
 */
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

/* mac may be NULL for the unresolved-MAC cases; addr and egress_ifindex are
 * passed explicitly because both change the branch taken.
 */
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

/* pb_eth() zeroes both addresses, and a MAC swap over two zeroed fields is
 * indistinguishable from no swap at all -- the whole point of these cases.
 */
static void nh_build_frame(void)
{
    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(11111, 80);
}

/* Compares the whole emitted frame against the arena with the two Ethernet
 * addresses replaced -- so a case asserting a rewrite also asserts that
 * nothing past ETH_ALEN * 2 moved, which a field-by-field check would miss.
 *
 * The drop cases below call this too: bpf_test_finish() copies data_out from
 * the run's xdp_buff whatever the program returned, so "the frame was not
 * rewritten" is assertable on a drop. No case above this section asserts
 * bytes on a drop, so if the out_len check is what fails here, that
 * assumption -- not the branch the case is about -- is what to revisit.
 */
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

/* ---- nexthop.c's Phase 2b assertion matrix (docs/design/24-testing.md:61-103,
 * docs/PHASES.md's Phase 2b exit criterion 1). Both entry points are already
 * reachable through main.c's interim xdp_interim_nexthop() (see the
 * "interim nexthop.c coverage" section below); what the cases below add is
 * real FIB state to drive them against, from fib.h's veth topology inside
 * the network namespace this binary's main() already unshares. Case names
 * and doc citations are unchanged from when these were MARLIN_SKIP
 * placeholders, so the history of this file shows exactly which criterion
 * closed and when.
 */

MARLIN_TEST(pending_phase2b_no_neigh_onlink_ingress_is_neigh_fallback)
{
    /* docs/design/16-fib-lookup.md:57, docs/design/24-testing.md:62-63 --
     * flagged L2 DSR backend, stored MAC, no neighbour, on-link route, FIB
     * returns the ingress interface: emit on the stored MAC, count
     * neigh_fallback, and assert the emitted source MAC is the frame's own
     * arriving destination, not fib.smac (docs/design/24-testing.md:69-72).
     */
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
    /* marlin_nexthop_store_mac() (nexthop.c:46-50) takes the new source from
     * the frame's own arriving destination, NH_MARLIN_MAC here -- not
     * fib.smac, which this branch never sets (docs/design/16-fib-lookup.md:85-86).
     * NH_MARLIN_MAC != FIB_MAC_INGRESS is what makes "not fib.smac" a fact a
     * regression could actually fail.
     */
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
    /* docs/design/24-testing.md:64-66 -- gatewayed route, FIB returns the
     * ingress interface: drop, no frame -- the case that separates a
     * correct implementation from one that blackholes whenever a router's
     * neighbour entry expires.
     */
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
    /* The assertion this case exists for: an unrelated neighbour entry must
     * not decide between a correct loud drop and a silent blackhole counted
     * as a healthy fallback (docs/design/16-fib-lookup.md:88-90).
     */
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
    /* docs/design/24-testing.md:67-68,74-78 -- the same missing neighbour
     * under IPIP must drop: the stored-MAC fallback is L2 DSR only.
     * docs/design/16-fib-lookup.md's FIB handling does not vary by mode, so
     * this one case stands for GUE and VXLAN too.
     */
    __u64 no_neigh_before = xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH);
    struct xdp_run_result result;

    fib_neigh_del(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS);
    fib_neigh_set(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS, FIB_MAC_BACKEND_A, "failed");

    nh_backend_seed(MARLIN_MODE_IPIP | MARLIN_BE_F_FIB, FIB_ADDR_BACKEND_A, NH_BACKEND_MAC, 0);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    /* nexthop.c:177-179 returns before the swap at :187-189: no frame
     * emitted, not merely one that failed to swap.
     */
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(no_neigh_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH));

    nh_backend_clear();
    fib_neigh_del(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS);
}

MARLIN_TEST(pending_phase2b_fib_fallback_resolves_backend_not_vip)
{
    /* docs/design/24-testing.md:80-84 -- L2 DSR, all-zero backend.mac, a
     * populated backend.addr with a neighbour entry: the emitted frame
     * carries that neighbour's MAC, not one resolved from the VIP. A
     * separate assertion in this case: both fields zero drops
     * backend_unresolved without reaching the helper at all -- that half
     * needs no FIB tier and is already covered at
     * nexthop_interim_l2dsr_zero_mac_zero_addr_is_backend_unresolved below.
     *
     * The decoy route/neighbour on V4_DST (the frame's IP destination, not
     * backend.addr) is what makes "resolves the backend, not the VIP"
     * falsifiable: a lookup that used V4_DST instead would still emit
     * XDP_TX (same ingress device) but on NH_DECOY_MAC, not
     * FIB_MAC_BACKEND_A.
     */
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
    /* docs/design/24-testing.md:86-90 -- an L2 DSR backend carrying
     * MARLIN_BE_F_FIB and a non-zero backend.mac must take the FIB path;
     * assert the emitted source MAC is the egress interface's. Pair with
     * the unflagged case on the same backend, which must XDP_TX on the
     * stored MAC without touching the helper.
     */
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
    /* "The egress interface's, not the ingress one" -- literally, since
     * FIB_MAC_EGRESS != FIB_MAC_INGRESS: this is the half that would still
     * pass with the two branches reversed if only the destination MAC were
     * checked.
     */
    nh_check_frame(FIB_MAC_BACKEND_B, FIB_MAC_EGRESS, result.out_len);
    CHECK_EQ(mismatch_before, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));

    nh_backend_seed(MARLIN_MODE_L2DSR, FIB_ADDR_BACKEND_B, NH_BACKEND_MAC, 0);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    /* The unflagged pair: the stored MAC path never touches fib.smac, so the
     * source comes back as the frame's own arriving destination, same as
     * pending_phase2b_no_neigh_onlink_ingress_is_neigh_fallback above.
     */
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    nh_backend_clear();
    xdp_tx_ports_clear();
    fib_neigh_del(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS);
}

MARLIN_TEST(pending_phase2b_l2dsr_refuses_gatewayed_ipip_forwards)
{
    /* docs/design/24-testing.md:92-96 -- a backend whose addr is reachable
     * only via a router: L2 DSR drops fib_gatewayed with no frame emitted;
     * the same route under IPIP forwards normally. The mode split is the
     * whole content of the check, so both halves are asserted against the
     * same route.
     */
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

    nh_backend_seed(MARLIN_MODE_IPIP | MARLIN_BE_F_FIB, FIB_ADDR_GATEWAYED, NH_BACKEND_MAC, 0);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(FIB_MAC_GATEWAY, FIB_MAC_INGRESS, result.out_len);

    nh_backend_clear();
    fib_neigh_del(FIB_ADDR_GATEWAY, FIB_DEV_INGRESS);
    fib_route_del(FIB_ADDR_GATEWAYED);
}

MARLIN_TEST(pending_phase2b_egress_mismatch_counts_verdict_unchanged)
{
    /* docs/design/24-testing.md:98-101 -- backend.egress_ifindex names an
     * interface the FIB does not choose, and that interface is in
     * tx_ports: the frame still emits on the FIB's interface, with
     * egress_mismatch incremented. Assert both halves.
     */
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
    /* docs/design/24-testing.md:101-103 -- as above, but the FIB's
     * interface is absent from tx_ports: egress_mismatch increments AND
     * the packet drops no_tx_port -- the counter is not a claim the frame
     * left. The redirect keys on the FIB's ifindex, never on
     * backend.egress_ifindex (docs/PHASES.md's Phase 2b exit criterion 1).
     */
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
    /* Rewritten, not arriving: nexthop.c:117-118's MAC writes precede the
     * redirect attempt at :126, so a frame was built before the drop.
     */
    nh_check_frame(FIB_MAC_BACKEND_B, FIB_MAC_EGRESS, result.out_len);
    CHECK_EQ(mismatch_before + 1, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));
    CHECK_EQ(no_tx_port_before + 1, xdp_drop_stats_total(MARLIN_DROP_NO_TX_PORT));

    nh_backend_clear();
    xdp_tx_ports_clear();
    fib_neigh_del(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS);
}

/* ---- Remaining bpf_fib_lookup() return codes: no existing case name
 * covers these (docs/design/16-fib-lookup.md:56-66, docs/PHASES.md:244
 * "seven return codes"). BLACKHOLE/UNREACHABLE/PROHIBIT need no neighbour --
 * the kernel returns before any neighbour lookup for a non-forwardable
 * route. FRAG_NEEDED's MTU check also precedes the neighbour lookup, so the
 * permanent neighbour seeded there is redundant insurance, not a
 * requirement this case depends on.
 */

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
    /* nexthop.c seeds fib.tot_len from the frame's own length less
     * ETH_HLEN (nexthop.c:81), so the frame must exceed the route's MTU --
     * nh_build_frame() alone (a TCP header and 4 bytes of ports) does not,
     * hence the padding.
     */
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
    /* nexthop.c's FRAG_NEEDED arm (:107-108) returns ahead of every MAC
     * write, same as every other drop code in the switch.
     */
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_FRAG_NEEDED));

    nh_backend_clear();
    fib_neigh_del(FIB_ADDR_MTU_ROUTE, FIB_DEV_INGRESS);
    fib_route_del(FIB_ADDR_MTU_ROUTE);
}

MARLIN_TEST(fib_unrouted_destination_is_unspec_drop)
{
    /* nexthop.c:86-111 has no case for BPF_FIB_LKUP_RET_NOT_FWDED --
     * "no matching route", what -ENETUNREACH maps to, and what a
     * non-RTN_UNICAST result (RTN_LOCAL here) also maps to -- so both
     * land on the default: arm, MARLIN_DROP_FIB_UNSPEC. Two runs: no route
     * at all, then the ingress device's own address.
     */
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
    /* fib.h's FIB_DEV_NOFWD is left with forwarding off, so this is the
     * one case in this section that runs on a different ingress device --
     * BPF_FIB_LKUP_RET_FWD_DISABLED is checked against the ingress device,
     * not the destination, so no route needs to exist at all.
     */
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

/* ---- interim nexthop.c coverage: remove with balancer.c ------------------
 *
 * These reach nexthop.c through main.c's xdp_interim_nexthop() -- backends[0]
 * seeded MARLIN_BE_F_STATE, with ENCAP_MODE(flags) choosing the entry point.
 * They cover only what does not need a routing table -- everything that
 * does now has real FIB state above, from fib.h. prog.h pins
 * ctx_in.ingress_ifindex to 0 for every case below, and that is not what
 * the program observes: bpf_prog_test_run_xdp() (net/bpf/test_run.c) binds
 * the run to the calling process's network namespace's loopback device when
 * ingress_ifindex is 0, and ctx->ingress_ifindex is verifier-rewritten to
 * that device's ifindex -- 1, always, for a namespace's own lo.
 *
 * lo stays unrouted and forwarding-disabled on purpose: fib.h enables
 * forwarding per device (FIB_DEV_INGRESS, FIB_DEV_EGRESS), never via
 * conf.all/conf.default or net.ipv4.ip_forward, precisely so this section's
 * BPF_FIB_LKUP_RET_FWD_DISABLED assertions keep holding once real FIB state
 * exists elsewhere in the same namespace. So the assertions below still take
 * that as "the FIB was consulted and could not answer", which is enough to
 * pin *which branch was taken* but not what a real FIB would have replied --
 * that is what the fib.h-backed cases above assert instead.
 *
 * Each case seeds and clears backends[0] itself: nothing else in this file
 * touches that map, and clearing on the way out keeps
 * docs/design/24-testing.md:9's order-independence intact for every other
 * case, all of which depend on the gate being closed.
 */

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

    /* docs/design/15-nexthop-l2dsr.md: the backend is the destination, so
     * Marlin's own MAC -- the arriving frame's destination -- becomes the new
     * source. No MAC swap: the router's address does not survive.
     */
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    CHECK_EQ(fallback_before, xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK));
    CHECK_EQ(mismatch_before, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));

    nh_backend_clear();
}

MARLIN_TEST(nexthop_interim_l2dsr_egress_mismatch_counts_verdict_unchanged)
{
    __u64 before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    struct xdp_run_result result;

    /* egress_ifindex one past NH_INGRESS_IFINDEX, so it disagrees with the
     * ifindex this tier's ingress actually resolves to. The zero-lookup half
     * of docs/design/24-testing.md:98-101 -- the tx_ports/FIB half stays with
     * pending_phase2b_egress_mismatch_*.
     */
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

    /* The negative half of the case above: an egress_ifindex equal to the
     * ifindex this tier's ingress actually resolves to must not count.
     * Pins NH_INGRESS_IFINDEX -- if the value the program observes ever
     * changes, this fails rather than quietly turning the mismatch case
     * above into a no-op.
     */
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

    /* docs/design/24-testing.md:82-84's second half, which that document
     * already marks as needing no FIB tier: both fields zero drops
     * backend_unresolved, and mac_fallback must not also count -- one
     * misconfiguration, one reason (nexthop.c:73-75).
     */
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

    /* The counter is the assertion; the verdict only says the FIB was
     * reached (see this section's header on the unshared netns).
     */
    CHECK_EQ(fallback_before + 1, xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK));
    CHECK_EQ(fwd_disabled_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_FWD_DISABLED));

    nh_backend_clear();
}

MARLIN_TEST(nexthop_interim_l2dsr_fib_flag_does_not_use_stored_mac)
{
    __u64 fallback_before = xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK);
    __u64 fwd_disabled_before = xdp_drop_stats_total(MARLIN_DROP_FIB_FWD_DISABLED);
    struct xdp_run_result result;

    /* The negative half of docs/design/24-testing.md:86-90: MARLIN_BE_F_FIB
     * with a resolved backend.mac must reach the helper, so the frame must
     * not come back carrying that MAC. Asserting the emitted *source* MAC is
     * the egress interface's -- the half that fails with the branches
     * reversed -- needs a FIB that answers, and stays with
     * pending_phase2b_fib_flag_beats_resolved_mac.
     *
     * mac_fallback must not count either: nexthop.c:147-157 only degrades to
     * the FIB when the flag is clear, and a flagged backend taking the
     * lookup is the configured behaviour, not a control-plane fault.
     */
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

MARLIN_TEST(nexthop_interim_encap_ipip_swaps_ethernet_addresses)
{
    __u64 mismatch_before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    struct xdp_run_result result;

    /* No ipip.c yet, so nothing has written an outer header -- irrelevant to
     * the assertion, which is that the arriving addresses come back swapped
     * so the upstream router forwards on its own table
     * (docs/design/14-forwarding-modes.md). GUE takes this same branch and
     * is deliberately not a second case.
     */
    nh_backend_seed(MARLIN_MODE_IPIP, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(mismatch_before, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));

    nh_backend_clear();
}

MARLIN_TEST(nexthop_interim_encap_vxlan_leaves_ethernet_addresses_alone)
{
    struct xdp_run_result result;

    /* docs/design/14-forwarding-modes.md SS7.4: vxlan.c writes the outer
     * Ethernet header itself, so swapping here would replace its correct
     * destination -- the router -- with Marlin's own MAC and transmit a
     * frame addressed to nobody. The mode is tested, not the discipline, so
     * this case is reachable before vxlan.c exists and is the only one that
     * distinguishes the two.
     */
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

    /* nexthop.c:177-179 checks MARLIN_BE_F_FIB ahead of both the VXLAN test
     * and the swap, and ahead of the egress check the two share -- so a
     * flagged VXLAN backend must reach the helper and must not count
     * egress_mismatch despite the mismatching egress_ifindex below: the FIB
     * drop returns before marlin_nexthop_check_egress() ever runs.
     */
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

    /* A DOWN backends[0] -- which is also what an untouched map holds -- must
     * leave xdp_main on its XDP_PASS path, or every case above this section
     * would depend on which order the cases ran in.
     */
    nh_backend_seed(MARLIN_MODE_L2DSR, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0);
    nh_backend_clear();
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
}

/* ---- end interim nexthop.c coverage ------------------------------------- */

/* ---- fib.h order-independence canary ------------------------------------
 *
 * Every fib.h-backed case above adds its own routes/neighbours/tx_ports
 * entries and removes them on the way out (docs/design/24-testing.md's
 * order-independence property, the same reasoning as
 * xdp_acl_clear/nh_backend_clear). This is the direct proof, run last:
 * tx_ports is empty, the gatewayed destination -- its route deleted along
 * with every other per-case route -- now falls through to fib_unspec, and
 * the on-link backend -- its permanent/failed neighbour deleted along with
 * every other per-case neighbour -- now falls through to fib_no_neigh. Named
 * "last" only by intent: MARLIN_TEST registration order is file order
 * (harness.h), and nothing enforces it against a reordering; what makes this
 * check meaningful is that every case above already tore its own state down,
 * not the position of this one.
 */
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

    /* No stored MAC here: a non-zero backend.mac on an on-link, egress ==
     * ingress route is exactly pending_phase2b_no_neigh_onlink_ingress_is_neigh_fallback's
     * fallback (nexthop.c:89-96) and would XDP_TX instead of proving the
     * neighbour is gone.
     */
    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_BACKEND_A, NULL, 0);
    nh_build_frame();
    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(no_neigh_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH));

    nh_backend_clear();
}

/* ---- end fib.h order-independence canary --------------------------------- */

int main(int argc, char **argv)
{
    const char *obj_path = (argc > 1) ? argv[1] : "build/marlin.bpf.o";
    struct marlin_config cfg;
    int rc;

    /* Puts this process's only interface, lo, on a namespace with no routes
     * and forwarding disabled, so the nexthop_interim_* section's
     * bpf_fib_lookup() outcomes are the same on every host regardless of its
     * own routing table or net.ipv4.ip_forward. BPF objects and maps are not
     * netns-scoped, so this must run before the load below only for hygiene,
     * not correctness.
     */
    if(unshare(CLONE_NEWNET) != 0) {
        fprintf(stderr, "packet-tests: unshare(CLONE_NEWNET) failed: %s\n", strerror(errno));
        exit(1);
    }

    /* Before the load below, deliberately: a topology failure then reports
     * before the slower program load, and DEVMAP_HASH resolves an inserted
     * ifindex against the calling process's network namespace at the time
     * of the update, which makes this ordering correctness, not (as the
     * comment above once had it) mere hygiene.
     */
    fib_topology_up();

    xdp_prog_load(obj_path);

    memset(&cfg, 0, sizeof(cfg));
    xdp_seed_config(&cfg);

    rc = marlin_tests_main();

    xdp_prog_unload();
    return rc;
}
