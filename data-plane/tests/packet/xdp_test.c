/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * bpf_prog_test_run tests for xdp_main -- the tier that runs the code as
 * compiled for the datapath (docs/design/24-testing.md, "Native unit
 * tests"). Coverage here is bounded by what xdp_main can distinguish today:
 * it parses, counts, and returns XDP_PASS on every non-error path (main.c),
 * since no VIP lookup or forwarding exists yet. The four VIP assertions in
 * docs/PHASES.md's Phase 1 exit criterion 2, and MARLIN_OK_TX/
 * MARLIN_OK_REDIRECT, are registered below via MARLIN_SKIP, so the gap
 * reports as a named `skip` line rather than as a pass or only in
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

/* No case depends on a config field yet -- nothing reads a VIP, ACL or rate
 * limiter today (docs/PHASES.md) -- so a zeroed struct exercises the seeding
 * mechanism without asserting behaviour the datapath does not have.
 */
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
