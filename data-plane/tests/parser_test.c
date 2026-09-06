/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Native unit tests for parser.c. This translation unit #includes the
 * source file directly to reach its `static __always_inline` helpers with
 * real host pointers -- see data-plane/tests/packet.h for why marlin_parse
 * itself still needs an arena below 4 GiB.
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>

#include "packet.h"
#include "harness.h"

#include "../src/parser.c"

/* ---- fixed addresses, reused across cases -------------------------------
 * Outer v4/v6 endpoints for ordinary (non-ICMP) traffic.
 */
#define V4_SRC 0x01010101U /* 1.1.1.1 */
#define V4_DST 0x02020202U /* 2.2.2.2 */

static const unsigned char SRC6[16] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                                       0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
static const unsigned char DST6[16] = {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
                                       0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30};

/* Embedded (quoted) client/VIP for the ICMP error path -- distinct from the
 * outer addresses so a test that mixes them up is caught by CHECK_MEM.
 */
#define EMB4_SRC 0x0a000005U /* 10.0.0.5 -- original client */
#define EMB4_DST 0x0a000006U /* 10.0.0.6 -- original VIP */

static const unsigned char EMB6_SRC[16] = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
                                           0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50};
static const unsigned char EMB6_DST[16] = {0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
                                           0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60};

/* Non-error, non-echo type used to prove marlin_icmp_is_error/echo return
 * false for it; not in proto.h because parser.c never needs it by name. */
#define TEST_ICMP_REDIRECT 5
#define TEST_ICMP_TIMESTAMP 13

static void mctx_init(struct marlin_ctx *mctx)
{
    /* Poisoned rather than zeroed (unlike src/main.c:57) so a field the
     * parser is not supposed to touch on some path reads back as garbage,
     * not as a coincidentally-correct zero.
     */
    memset(mctx, 0xAA, sizeof(*mctx));
    mctx->flags = 0;
}

/* ======================================================================
 * Tier A -- helpers, called directly with real host pointers
 * ====================================================================== */

MARLIN_TEST(eth_truncated_13_bytes_is_null)
{
    pb_reset();
    pb_pad(13);
    CHECK_TRUE(marlin_parse_eth(pb_arena, pb_arena + pb_len) == NULL);
}

MARLIN_TEST(eth_exactly_14_bytes_is_non_null)
{
    pb_reset();
    pb_pad(14);
    CHECK_TRUE(marlin_parse_eth(pb_arena, pb_arena + pb_len) != NULL);
}

MARLIN_TEST(frag4_zero_is_no_flags)
{
    CHECK_EQ(0, marlin_parse_frag4(bpf_htons(0)));
}

MARLIN_TEST(frag4_df_is_no_flags)
{
    CHECK_EQ(0, marlin_parse_frag4(bpf_htons(IP_DF)));
}

MARLIN_TEST(frag4_reserved_bit_alone_is_no_flags)
{
    CHECK_EQ(0, marlin_parse_frag4(bpf_htons(0x8000)));
}

MARLIN_TEST(frag4_min_offset_is_frag)
{
    CHECK_EQ(MARLIN_CTX_F_FRAG, marlin_parse_frag4(bpf_htons(0x0001)));
}

MARLIN_TEST(frag4_max_offset_is_frag)
{
    CHECK_EQ(MARLIN_CTX_F_FRAG, marlin_parse_frag4(bpf_htons(IP_OFFSET)));
}

MARLIN_TEST(frag4_mf_alone_is_frag_first)
{
    CHECK_EQ(MARLIN_CTX_F_FRAG_FIRST, marlin_parse_frag4(bpf_htons(IP_MF)));
}

/* The ordinary middle fragment: MF set AND a non-zero offset. Proves the
 * offset check (parser.c:57) is tested before the MF check (parser.c:61).
 */
MARLIN_TEST(frag4_mf_and_offset_is_frag_only)
{
    CHECK_EQ(MARLIN_CTX_F_FRAG, marlin_parse_frag4(bpf_htons(IP_MF | 0x0001)));
}

MARLIN_TEST(frag6_zero_is_no_flags)
{
    CHECK_EQ(0, marlin_parse_frag6(bpf_htons(0)));
}

MARLIN_TEST(frag6_offset_is_frag)
{
    CHECK_EQ(MARLIN_CTX_F_FRAG, marlin_parse_frag6(bpf_htons(IP6_OFFSET)));
}

MARLIN_TEST(frag6_mf_alone_is_frag_first)
{
    CHECK_EQ(MARLIN_CTX_F_FRAG_FIRST, marlin_parse_frag6(bpf_htons(IP6_MF)));
}

MARLIN_TEST(frag6_mf_and_offset_is_frag_only)
{
    CHECK_EQ(MARLIN_CTX_F_FRAG, marlin_parse_frag6(bpf_htons(IP6_MF | 0x0008)));
}

MARLIN_TEST(is_ext6_true_for_all_four)
{
    CHECK_TRUE(marlin_is_ext6(IPPROTO_HOPOPTS));
    CHECK_TRUE(marlin_is_ext6(IPPROTO_ROUTING));
    CHECK_TRUE(marlin_is_ext6(IPPROTO_DSTOPTS));
    CHECK_TRUE(marlin_is_ext6(IPPROTO_FRAGMENT));
}

MARLIN_TEST(is_ext6_false_for_upper_layer_and_none)
{
    CHECK_TRUE(!marlin_is_ext6(IPPROTO_TCP));
    CHECK_TRUE(!marlin_is_ext6(IPPROTO_UDP));
    CHECK_TRUE(!marlin_is_ext6(IPPROTO_NONE));
    CHECK_TRUE(!marlin_is_ext6(IPPROTO_MH));
}

/* max_ext == 0: the limit must fire at i == 0, before any header is read --
 * data_end == data proves nothing was dereferenced.
 */
MARLIN_TEST(walk_ext6_max_zero_is_limit_without_dereference)
{
    struct marlin_l3 out;
    int rc = marlin_walk_ext6(pb_arena, pb_arena, 0, IPPROTO_HOPOPTS, 0, &out);
    CHECK_RET(MARLIN_DROP_EXT_HDR_LIMIT, rc);
}

MARLIN_TEST(walk_ext6_max_one_with_two_headers_is_limit)
{
    __u32 off;
    struct marlin_l3 out;
    int rc;

    pb_reset();
    pb_ext6(IPPROTO_HOPOPTS, 0);
    pb_ext6(IPPROTO_TCP, 0);
    off = 0;
    rc = marlin_walk_ext6(pb_arena, pb_arena + pb_len, off, IPPROTO_HOPOPTS, 1, &out);
    CHECK_RET(MARLIN_DROP_EXT_HDR_LIMIT, rc);
}

MARLIN_TEST(walk_ext6_eight_headers_is_ok)
{
    struct marlin_l3 out;
    int rc;
    int i;

    pb_reset();
    for(i = 0; i < 7; i++) {
        pb_ext6(IPPROTO_HOPOPTS, 0); /* chains to the next header, also HOPOPTS */
    }
    pb_ext6(IPPROTO_TCP, 0); /* the 8th header terminates the chain */
    pb_ports(1, 2);
    rc = marlin_walk_ext6(pb_arena, pb_arena + pb_len, 0, IPPROTO_HOPOPTS, MAX_EXT_HDRS, &out);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(IPPROTO_TCP, out.proto);
    CHECK_EQ(64, out.l4_off); /* 8 headers * 8 bytes */
}

MARLIN_TEST(walk_ext6_nine_headers_is_limit)
{
    struct marlin_l3 out;
    int rc;
    int i;

    pb_reset();
    for(i = 0; i < 9; i++) {
        pb_ext6(IPPROTO_HOPOPTS, 0);
    }
    rc = marlin_walk_ext6(pb_arena, pb_arena + pb_len, 0, IPPROTO_HOPOPTS, MAX_EXT_HDRS, &out);
    CHECK_RET(MARLIN_DROP_EXT_HDR_LIMIT, rc);
}

/* ESP as the 9th header: the unsupported-proto check (parser.c:97) runs
 * before the limit check (parser.c:107), so this must NOT be EXT_HDR_LIMIT.
 */
MARLIN_TEST(walk_ext6_esp_after_eight_is_unsupported_not_limit)
{
    struct marlin_l3 out;
    int rc;
    int i;

    pb_reset();
    for(i = 0; i < 7; i++) {
        pb_ext6(IPPROTO_HOPOPTS, 0); /* chains to the next header, also HOPOPTS */
    }
    pb_ext6(IPPROTO_ESP, 0); /* the 8th header terminates the chain into ESP */
    rc = marlin_walk_ext6(pb_arena, pb_arena + pb_len, 0, IPPROTO_HOPOPTS, MAX_EXT_HDRS, &out);
    CHECK_RET(MARLIN_DROP_UNSUPPORTED_PROTO, rc);
}

MARLIN_TEST(walk_ext6_esp_first_is_unsupported)
{
    struct marlin_l3 out;
    int rc = marlin_walk_ext6(pb_arena, pb_arena, 0, IPPROTO_ESP, MAX_EXT_HDRS, &out);
    CHECK_RET(MARLIN_DROP_UNSUPPORTED_PROTO, rc);
}

MARLIN_TEST(walk_ext6_ah_first_is_unsupported)
{
    struct marlin_l3 out;
    int rc = marlin_walk_ext6(pb_arena, pb_arena, 0, IPPROTO_AH, MAX_EXT_HDRS, &out);
    CHECK_RET(MARLIN_DROP_UNSUPPORTED_PROTO, rc);
}

/* sizeof(struct ipv6_opt_hdr) == 2, so 0 or 1 available bytes is what
 * actually reaches parser.c:113 -- 7 bytes, as an earlier draft of this
 * matrix proposed, passes that check and depends on whatever nexthdr byte
 * happens to be there instead.
 */
MARLIN_TEST(walk_ext6_zero_bytes_of_opt_hdr_is_parse_error)
{
    struct marlin_l3 out;
    int rc;

    pb_reset();
    rc = marlin_walk_ext6(pb_arena, pb_arena + pb_len, 0, IPPROTO_HOPOPTS, MAX_EXT_HDRS, &out);
    CHECK_RET(MARLIN_DROP_PARSE_ERROR, rc);
}

MARLIN_TEST(walk_ext6_one_byte_of_opt_hdr_is_parse_error)
{
    struct marlin_l3 out;
    int rc;

    pb_reset();
    pb_pad(1);
    rc = marlin_walk_ext6(pb_arena, pb_arena + pb_len, 0, IPPROTO_HOPOPTS, MAX_EXT_HDRS, &out);
    CHECK_RET(MARLIN_DROP_PARSE_ERROR, rc);
}

/* struct marlin_frag_hdr is 8 bytes; 2-7 available bytes passes the 2-byte
 * ipv6_opt_hdr check but fails parser.c:120's fragment-header-specific one.
 */
MARLIN_TEST(walk_ext6_truncated_frag_hdr_is_parse_error)
{
    struct marlin_l3 out;
    int rc;

    pb_reset();
    pb_pad(4);
    rc = marlin_walk_ext6(pb_arena, pb_arena + pb_len, 0, IPPROTO_FRAGMENT, MAX_EXT_HDRS, &out);
    CHECK_RET(MARLIN_DROP_PARSE_ERROR, rc);
}

/* hdrlen==255 is the largest single ext header (2048 bytes); pins the width
 * the _Static_assert at parser.c:86 and the (__u16) cast at parser.c:329
 * depend on.
 */
MARLIN_TEST(walk_ext6_max_hdrlen_advances_by_2048)
{
    struct marlin_l3 out;
    int rc;

    pb_reset();
    pb_ext6(IPPROTO_TCP, 255);
    rc = marlin_walk_ext6(pb_arena, pb_arena + pb_len, 0, IPPROTO_HOPOPTS, MAX_EXT_HDRS, &out);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(2048, out.l4_off);
}

MARLIN_TEST(walk_ext6_eight_max_hdrlen_headers_advances_by_16384)
{
    struct marlin_l3 out;
    int rc;
    int i;

    pb_reset();
    for(i = 0; i < 8; i++) {
        pb_ext6(IPPROTO_HOPOPTS, 255);
    }
    rc = marlin_walk_ext6(pb_arena, pb_arena + pb_len, 0, IPPROTO_HOPOPTS, MAX_EXT_HDRS, &out);
    CHECK_RET(MARLIN_DROP_EXT_HDR_LIMIT, rc); /* 8 ext headers exhausts max_ext before a 9th, non-ext one is seen */
}

/* Two chained FRAGMENT headers: the first (MF only) accumulates F_FRAG_FIRST,
 * the second (offset set) accumulates F_FRAG -- parser.c:124 uses |=, so both
 * end up set at once. include/marlin/marlin.h:26-27 documents them as if
 * mutually exclusive; this is Observation 2, pinned rather than fixed.
 */
MARLIN_TEST(walk_ext6_two_fragment_headers_sets_both_frag_flags)
{
    struct marlin_l3 out;
    int rc;

    /* Unlike marlin_parse_l3, marlin_walk_ext6 does not zero *out itself
     * (parser.c:153 is the caller's job); called directly, this test must
     * do it, or out.flags's |= accumulates onto stack garbage.
     */
    memset(&out, 0, sizeof(out));
    pb_reset();
    pb_frag6(IPPROTO_FRAGMENT, IP6_MF);
    pb_frag6(IPPROTO_TCP, 0x0008);
    rc = marlin_walk_ext6(pb_arena, pb_arena + pb_len, 0, IPPROTO_FRAGMENT, MAX_EXT_HDRS, &out);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(MARLIN_CTX_F_FRAG | MARLIN_CTX_F_FRAG_FIRST, out.flags);
    CHECK_EQ(IPPROTO_TCP, out.proto);
    CHECK_EQ(16, out.l4_off);
}

/* max_ext=9 exceeds MAX_EXT_HDRS(8), so the loop (bounded at i<=MAX_EXT_HDRS)
 * runs out before parser.c:107's `i >= max_ext` ever fires -- the only way
 * to reach the dead-looking return at parser.c:147 (Observation 5).
 */
MARLIN_TEST(walk_ext6_max_ext_above_loop_bound_reaches_trailing_return)
{
    struct marlin_l3 out;
    int rc;
    int i;

    pb_reset();
    for(i = 0; i < 9; i++) {
        pb_ext6(IPPROTO_HOPOPTS, 0);
    }
    rc = marlin_walk_ext6(pb_arena, pb_arena + pb_len, 0, IPPROTO_HOPOPTS, 9, &out);
    CHECK_RET(MARLIN_DROP_EXT_HDR_LIMIT, rc);
}

MARLIN_TEST(parse_l3_v4_truncated_iphdr_is_parse_error)
{
    struct marlin_l3 out;
    int rc;

    pb_reset();
    pb_pad(19);
    rc = marlin_parse_l3(pb_arena, pb_arena + pb_len, 0, AF_INET, MAX_EXT_HDRS, &out);
    CHECK_RET(MARLIN_DROP_PARSE_ERROR, rc);
}

MARLIN_TEST(parse_l3_v4_ihl_below_minimum_is_parse_error)
{
    struct marlin_l3 out;
    int rc;

    pb_reset();
    pb_ipv4(IPPROTO_TCP, 4, 0, V4_SRC, V4_DST);
    rc = marlin_parse_l3(pb_arena, pb_arena + pb_len, 0, AF_INET, MAX_EXT_HDRS, &out);
    CHECK_RET(MARLIN_DROP_PARSE_ERROR, rc);
}

MARLIN_TEST(parse_l3_v4_ihl_max_truncated_options_is_parse_error)
{
    struct marlin_l3 out;
    int rc;

    pb_reset();
    pb_pad(20); /* ihl=15 needs 60 bytes; a bare 20-byte iphdr has none of the options */
    ((struct iphdr *)pb_arena)->ihl = 15;
    rc = marlin_parse_l3(pb_arena, pb_arena + pb_len, 0, AF_INET, MAX_EXT_HDRS, &out);
    CHECK_RET(MARLIN_DROP_PARSE_ERROR, rc);
}

MARLIN_TEST(parse_l3_v4_ihl_min_exact_length_is_ok)
{
    struct marlin_l3 out;
    int rc;

    pb_reset();
    pb_ipv4(IPPROTO_TCP, 5, 0, V4_SRC, V4_DST);
    rc = marlin_parse_l3(pb_arena, pb_arena + pb_len, 0, AF_INET, MAX_EXT_HDRS, &out);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(20, out.l4_off);
}

MARLIN_TEST(parse_l3_v4_ihl_max_exact_length_is_ok)
{
    struct marlin_l3 out;
    int rc;

    pb_reset();
    pb_ipv4(IPPROTO_TCP, 15, 0, V4_SRC, V4_DST);
    rc = marlin_parse_l3(pb_arena, pb_arena + pb_len, 0, AF_INET, MAX_EXT_HDRS, &out);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(60, out.l4_off);
}

MARLIN_TEST(parse_l3_v4_ihl_with_options_advances_l4_off)
{
    struct marlin_l3 out;
    int rc;

    pb_reset();
    pb_ipv4(IPPROTO_TCP, 6, 0, V4_SRC, V4_DST);
    rc = marlin_parse_l3(pb_arena, pb_arena + pb_len, 0, AF_INET, MAX_EXT_HDRS, &out);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(24, out.l4_off);
}

MARLIN_TEST(parse_l3_v6_truncated_hdr_is_parse_error)
{
    struct marlin_l3 out;
    int rc;

    pb_reset();
    pb_pad(39);
    rc = marlin_parse_l3(pb_arena, pb_arena + pb_len, 0, AF_INET6, MAX_EXT_HDRS, &out);
    CHECK_RET(MARLIN_DROP_PARSE_ERROR, rc);
}

MARLIN_TEST(parse_l3_v6_copies_addresses_verbatim)
{
    struct marlin_l3 out;
    int rc;

    pb_reset();
    pb_ipv6(IPPROTO_TCP, SRC6, DST6);
    rc = marlin_parse_l3(pb_arena, pb_arena + pb_len, 0, AF_INET6, MAX_EXT_HDRS, &out);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_MEM(SRC6, out.src, 16);
    CHECK_MEM(DST6, out.dst, 16);
}

/* parser.c:155 has no explicit AF_INET6 guard: any family that isn't
 * AF_INET falls into the IPv6 branch. Observation 8, pinned as-is.
 */
MARLIN_TEST(parse_l3_unknown_family_is_parsed_as_v6)
{
    struct marlin_l3 out;
    int rc;

    pb_reset();
    pb_ipv6(IPPROTO_TCP, SRC6, DST6);
    rc = marlin_parse_l3(pb_arena, pb_arena + pb_len, 0, 0, MAX_EXT_HDRS, &out);
    CHECK_RET(MARLIN_OK, rc);
}

static void check_ports_untouched_after(int rc_expect, __u8 proto, __u32 avail)
{
    __be16 sport = 0xdead;
    __be16 dport = 0xbeef;
    int rc;

    pb_reset();
    pb_pad(avail);
    rc = marlin_parse_ports(pb_arena, pb_arena + pb_len, 0, proto, &sport, &dport);
    CHECK_RET(rc_expect, rc);
    CHECK_EQ(0xdead, sport);
    CHECK_EQ(0xbeef, dport);
}

MARLIN_TEST(parse_ports_tcp_exact_four_bytes_is_ok)
{
    __be16 sport;
    __be16 dport;
    int rc;

    pb_reset();
    pb_ports(1234, 80);
    rc = marlin_parse_ports(pb_arena, pb_arena + pb_len, 0, IPPROTO_TCP, &sport, &dport);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(bpf_htons(1234), sport);
    CHECK_EQ(bpf_htons(80), dport);
}

MARLIN_TEST(parse_ports_udp_exact_four_bytes_is_ok)
{
    __be16 sport;
    __be16 dport;
    int rc;

    pb_reset();
    pb_ports(53, 5353);
    rc = marlin_parse_ports(pb_arena, pb_arena + pb_len, 0, IPPROTO_UDP, &sport, &dport);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(bpf_htons(53), sport);
    CHECK_EQ(bpf_htons(5353), dport);
}

MARLIN_TEST(parse_ports_tcp_truncated_three_bytes_is_parse_error)
{
    check_ports_untouched_after(MARLIN_DROP_PARSE_ERROR, IPPROTO_TCP, 3);
}

MARLIN_TEST(parse_ports_udp_truncated_three_bytes_is_parse_error)
{
    check_ports_untouched_after(MARLIN_DROP_PARSE_ERROR, IPPROTO_UDP, 3);
}

MARLIN_TEST(parse_ports_esp_is_unsupported_proto)
{
    check_ports_untouched_after(MARLIN_DROP_UNSUPPORTED_PROTO, IPPROTO_ESP, 4);
}

MARLIN_TEST(parse_ports_ah_is_unsupported_proto)
{
    check_ports_untouched_after(MARLIN_DROP_UNSUPPORTED_PROTO, IPPROTO_AH, 4);
}

MARLIN_TEST(parse_ports_sctp_is_not_forwarded)
{
    check_ports_untouched_after(MARLIN_PASS_NOT_FORWARDED, IPPROTO_SCTP, 4);
}

MARLIN_TEST(parse_ports_gre_is_not_forwarded)
{
    check_ports_untouched_after(MARLIN_PASS_NOT_FORWARDED, IPPROTO_GRE, 4);
}

MARLIN_TEST(proto_is_icmp_all_four_combinations)
{
    CHECK_TRUE(marlin_proto_is_icmp(AF_INET, IPPROTO_ICMP));
    CHECK_TRUE(marlin_proto_is_icmp(AF_INET6, IPPROTO_ICMPV6));
    CHECK_TRUE(!marlin_proto_is_icmp(AF_INET, IPPROTO_ICMPV6));
    CHECK_TRUE(!marlin_proto_is_icmp(AF_INET6, IPPROTO_ICMP));
}

MARLIN_TEST(icmp_is_error_v4_types)
{
    CHECK_TRUE(marlin_icmp_is_error(AF_INET, ICMP_DEST_UNREACH));
    CHECK_TRUE(marlin_icmp_is_error(AF_INET, ICMP_TIME_EXCEEDED));
    CHECK_TRUE(marlin_icmp_is_error(AF_INET, ICMP_PARAMETERPROB));
    CHECK_TRUE(!marlin_icmp_is_error(AF_INET, TEST_ICMP_REDIRECT));
}

MARLIN_TEST(icmp_is_error_v6_types)
{
    CHECK_TRUE(marlin_icmp_is_error(AF_INET6, ICMPV6_DEST_UNREACH));
    CHECK_TRUE(marlin_icmp_is_error(AF_INET6, ICMPV6_PKT_TOOBIG));
    CHECK_TRUE(marlin_icmp_is_error(AF_INET6, ICMPV6_TIME_EXCEED));
    CHECK_TRUE(marlin_icmp_is_error(AF_INET6, ICMPV6_PARAMPROB));
    CHECK_TRUE(!marlin_icmp_is_error(AF_INET6, ICMPV6_MGM_QUERY));
}

MARLIN_TEST(icmp_is_echo_v4_types)
{
    CHECK_TRUE(marlin_icmp_is_echo(AF_INET, ICMP_ECHO));
    CHECK_TRUE(marlin_icmp_is_echo(AF_INET, ICMP_ECHOREPLY));
    CHECK_TRUE(!marlin_icmp_is_echo(AF_INET, TEST_ICMP_TIMESTAMP));
}

MARLIN_TEST(icmp_is_echo_v6_types)
{
    CHECK_TRUE(marlin_icmp_is_echo(AF_INET6, ICMPV6_ECHO_REQUEST));
    CHECK_TRUE(marlin_icmp_is_echo(AF_INET6, ICMPV6_ECHO_REPLY));
    CHECK_TRUE(!marlin_icmp_is_echo(AF_INET6, ICMPV6_MGM_QUERY));
}

/* ======================================================================
 * Tier B -- marlin_parse end-to-end through struct xdp_md
 * ====================================================================== */

MARLIN_TEST(parse_null_mctx_is_parse_error)
{
    struct xdp_md md;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_TCP, 5, 0, V4_SRC, V4_DST);
    pb_ports(1, 2);
    pb_xdp(&md);
    rc = marlin_parse(&md, NULL);
    CHECK_RET(MARLIN_DROP_PARSE_ERROR, rc);
}

/* pkt_len is written before the eth bounds check (parser.c:302 precedes
 * :306), so a too-short frame still gets a correct pkt_len.
 */
MARLIN_TEST(parse_pkt_len_set_before_validation_on_truncated_frame)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_pad(13);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_DROP_PARSE_ERROR, rc);
    CHECK_EQ(13, mctx.pkt_len);
}

MARLIN_TEST(parse_pkt_len_zero_on_empty_frame)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_DROP_PARSE_ERROR, rc);
    CHECK_EQ(0, mctx.pkt_len);
}

static __u32 build_valid_ipv4_tcp(void)
{
    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_TCP, 5, 0, V4_SRC, V4_DST);
    pb_ports(1234, 80);
    return pb_len;
}

/* mctx->pkt_len is (__u16)(data_end - data) -- parser.c:302 -- so it wraps
 * once the frame is 64 KiB or larger. The well-formed header at the front
 * still parses, independent of how far past it data_end sits.
 */
MARLIN_TEST(parse_pkt_len_65535_no_wrap)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    __u32 built;
    int rc;

    built = build_valid_ipv4_tcp();
    pb_pad(65535 - built);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(65535, mctx.pkt_len);
}

MARLIN_TEST(parse_pkt_len_65536_wraps_to_zero)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    __u32 built;
    int rc;

    built = build_valid_ipv4_tcp();
    pb_pad(65536 - built);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(0, mctx.pkt_len);
}

MARLIN_TEST(parse_pkt_len_70000_wraps_to_4464)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    __u32 built;
    int rc;

    built = build_valid_ipv4_tcp();
    pb_pad(70000 - built);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(4464, mctx.pkt_len);
}

static void check_ethertype_not_forwarded(__u16 ethertype_host)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ethertype_host);
    pb_pad(46); /* pad to a plausible minimum frame; parser never reads past eth here */
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_PASS_NOT_FORWARDED, rc);
}

MARLIN_TEST(parse_arp_ethertype_not_forwarded)
{
    check_ethertype_not_forwarded(0x0806);
}

MARLIN_TEST(parse_vlan_ethertype_not_forwarded)
{
    check_ethertype_not_forwarded(0x8100);
}

MARLIN_TEST(parse_zero_ethertype_not_forwarded)
{
    check_ethertype_not_forwarded(0x0000);
}

MARLIN_TEST(parse_8023_length_field_not_forwarded)
{
    check_ethertype_not_forwarded(0x0006);
}

/* If parser.c's own bpf_htons(ETH_P_IP) at parser.c:310 were ever dropped,
 * this host-order-stored h_proto would start matching. Today it does not.
 */
MARLIN_TEST(parse_host_order_ethertype_not_forwarded)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    struct ethhdr eth;
    int rc;

    pb_reset();
    memset(&eth, 0, sizeof(eth));
    eth.h_proto = ETH_P_IP; /* deliberately NOT bpf_htons()-converted */
    pb_raw(&eth, sizeof(eth));
    pb_pad(46);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_PASS_NOT_FORWARDED, rc);
}

MARLIN_TEST(parse_ipv4_tcp_ok_with_l3_off_and_family)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    build_valid_ipv4_tcp();
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(14, mctx.l3_off);
    CHECK_EQ(AF_INET, mctx.tuple.family);
    CHECK_EQ(bpf_htons(1234), mctx.tuple.sport);
    CHECK_EQ(bpf_htons(80), mctx.tuple.dport);
    CHECK_EQ(V4_SRC, mctx.tuple.src[0]);
    CHECK_EQ(V4_DST, mctx.tuple.dst[0]);
    CHECK_EQ(0, mctx.tuple.src[1]);
    CHECK_EQ(0, mctx.tuple.src[2]);
    CHECK_EQ(0, mctx.tuple.src[3]);
    CHECK_EQ(0, mctx.tuple.dst[1]);
    CHECK_EQ(0, mctx.tuple.dst[2]);
    CHECK_EQ(0, mctx.tuple.dst[3]);
}

MARLIN_TEST(parse_ipv4_udp_ok)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_UDP, 5, 0, V4_SRC, V4_DST);
    pb_ports(53, 5353);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
}

MARLIN_TEST(parse_ipv4_esp_is_unsupported_proto)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ESP, 5, 0, V4_SRC, V4_DST);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_DROP_UNSUPPORTED_PROTO, rc);
}

MARLIN_TEST(parse_ipv4_ah_is_unsupported_proto)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_AH, 5, 0, V4_SRC, V4_DST);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_DROP_UNSUPPORTED_PROTO, rc);
}

MARLIN_TEST(parse_ipv4_sctp_is_not_forwarded)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_SCTP, 5, 0, V4_SRC, V4_DST);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_PASS_NOT_FORWARDED, rc);
}

MARLIN_TEST(parse_ipv4_gre_is_not_forwarded)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_GRE, 5, 0, V4_SRC, V4_DST);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_PASS_NOT_FORWARDED, rc);
}

MARLIN_TEST(parse_ipv4_tcp_truncated_l4_is_parse_error)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_TCP, 5, 0, V4_SRC, V4_DST);
    pb_pad(3);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_DROP_PARSE_ERROR, rc);
}

MARLIN_TEST(parse_ipv4_tcp_zero_l4_bytes_is_parse_error)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_TCP, 5, 0, V4_SRC, V4_DST);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_DROP_PARSE_ERROR, rc);
}

/* --- fragments, IPv4 ---------------------------------------------------- */

/* A non-first fragment: no L4 header is present on the wire, so ports must
 * stay untouched even though the outer proto is TCP.
 */
MARLIN_TEST(parse_ipv4_non_first_fragment_tcp_is_ok_no_ports)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_TCP, 5, 0x0040 /* offset, MF clear: not-first, last fragment */, V4_SRC, V4_DST);
    pb_xdp(&md);
    mctx_init(&mctx);
    mctx.tuple.sport = 0xdead;
    mctx.tuple.dport = 0xbeef;
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(MARLIN_CTX_F_FRAG, mctx.flags);
    CHECK_EQ(0xdead, mctx.tuple.sport);
    CHECK_EQ(0xbeef, mctx.tuple.dport);
}

/* The first fragment: ports ARE present and must be parsed, and the flag is
 * F_FRAG_FIRST, not F_FRAG. docs/design/24-testing.md:27-30 -- this is the
 * one assertion nothing else catches.
 */
MARLIN_TEST(parse_ipv4_first_fragment_tcp_is_ok_with_ports)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_TCP, 5, IP_MF, V4_SRC, V4_DST);
    pb_ports(1234, 80);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(MARLIN_CTX_F_FRAG_FIRST, mctx.flags);
    CHECK_EQ(bpf_htons(1234), mctx.tuple.sport);
    CHECK_EQ(bpf_htons(80), mctx.tuple.dport);
}

/* A fragment tail carries no ICMP header, so the ICMP branch must never be
 * taken for it -- parser.c:332-338.
 */
MARLIN_TEST(parse_ipv4_non_first_fragment_icmp_is_not_forwarded)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ICMP, 5, 0x0040, V4_SRC, V4_DST);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_PASS_NOT_FORWARDED, rc);
}

/* The fragment early-return bypasses the ESP/AH rejection entirely: an
 * unfragmented ESP packet is DROP_UNSUPPORTED_PROTO, but a fragment of one
 * is not. Two policies for one protocol -- Observation 3, pinned as-is.
 */
MARLIN_TEST(parse_ipv4_non_first_fragment_esp_is_ok_not_unsupported)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ESP, 5, 0x0040, V4_SRC, V4_DST);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(IPPROTO_ESP, mctx.tuple.proto);
}

/* parser.c:332 branches on mctx->flags, not the l3.flags this call computed
 * -- a caller-supplied stale F_FRAG bit makes an ordinary packet take the
 * fragment early-return and skip port parsing entirely. Safe today only
 * because src/main.c:57 memsets the whole struct first. Observation 1.
 */
MARLIN_TEST(parse_stale_frag_flag_skips_port_parsing)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    build_valid_ipv4_tcp();
    pb_xdp(&md);
    mctx_init(&mctx);
    mctx.flags = MARLIN_CTX_F_FRAG; /* stale, caller-supplied -- not computed by this call */
    mctx.tuple.sport = 0xdead;
    mctx.tuple.dport = 0xbeef;
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(0xdead, mctx.tuple.sport);
    CHECK_EQ(0xbeef, mctx.tuple.dport);
}

MARLIN_TEST(parse_stale_frag_flag_skips_icmp_echo)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ICMP, 5, 0, V4_SRC, V4_DST);
    pb_icmp(ICMP_ECHO, 0);
    pb_xdp(&md);
    mctx_init(&mctx);
    mctx.flags = MARLIN_CTX_F_FRAG;
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_PASS_NOT_FORWARDED, rc); /* would be MARLIN_PASS_ICMP_ECHO without the stale flag */
}

/* parser.c:330 uses |=: a caller-supplied flag bit unrelated to fragmentation
 * must survive the call. */
MARLIN_TEST(parse_preserves_unrelated_preset_flag_bit)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    build_valid_ipv4_tcp();
    pb_xdp(&md);
    mctx_init(&mctx);
    mctx.flags = MARLIN_CTX_F_ICMP; /* arbitrary bit this call has no reason to touch */
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_TRUE((mctx.flags & MARLIN_CTX_F_ICMP) != 0U);
}

/* --- fragments, IPv6 ------------------------------------------------------ */

MARLIN_TEST(parse_ipv6_non_first_fragment_tcp_is_ok_no_ports)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_FRAGMENT, SRC6, DST6);
    pb_frag6(IPPROTO_TCP, 0x0008 /* offset set, MF clear */);
    pb_xdp(&md);
    mctx_init(&mctx);
    mctx.tuple.sport = 0xdead;
    mctx.tuple.dport = 0xbeef;
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(MARLIN_CTX_F_FRAG, mctx.flags);
    CHECK_EQ(0xdead, mctx.tuple.sport);
    CHECK_EQ(0xbeef, mctx.tuple.dport);
}

MARLIN_TEST(parse_ipv6_non_first_fragment_icmpv6_is_not_forwarded)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_FRAGMENT, SRC6, DST6);
    pb_frag6(IPPROTO_ICMPV6, 0x0008);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_PASS_NOT_FORWARDED, rc);
}

MARLIN_TEST(parse_ipv6_non_first_fragment_esp_is_ok_not_unsupported)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_FRAGMENT, SRC6, DST6);
    pb_frag6(IPPROTO_ESP, 0x0008);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(IPPROTO_ESP, mctx.tuple.proto);
}

/* --- IPv6 body ------------------------------------------------------------ */

MARLIN_TEST(parse_ipv6_tcp_no_ext_hdrs_l4_off)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_TCP, SRC6, DST6);
    pb_ports(1234, 80);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(54, mctx.l4_off);
    CHECK_EQ(AF_INET6, mctx.tuple.family);
    CHECK_MEM(SRC6, mctx.tuple.src, 16);
    CHECK_MEM(DST6, mctx.tuple.dst, 16);
}

MARLIN_TEST(parse_ipv6_one_hopopts_hdrlen_zero_l4_off)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_HOPOPTS, SRC6, DST6);
    pb_ext6(IPPROTO_TCP, 0);
    pb_ports(1234, 80);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(62, mctx.l4_off);
}

MARLIN_TEST(parse_ipv6_one_hopopts_hdrlen_one_l4_off)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_HOPOPTS, SRC6, DST6);
    pb_ext6(IPPROTO_TCP, 1);
    pb_ports(1234, 80);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(70, mctx.l4_off);
}

MARLIN_TEST(parse_ipv6_routing_header_is_ok)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_ROUTING, SRC6, DST6);
    pb_ext6(IPPROTO_TCP, 0);
    pb_ports(1, 2);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
}

MARLIN_TEST(parse_ipv6_dstopts_header_is_ok)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_DSTOPTS, SRC6, DST6);
    pb_ext6(IPPROTO_TCP, 0);
    pb_ports(1, 2);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
}

/* An atomic fragment header (offset zero, MF clear) sets neither flag and
 * walk_ext6's "return 0" path (parser.c:78) is otherwise unreachable from a
 * full parse.
 */
MARLIN_TEST(parse_ipv6_atomic_fragment_sets_no_flags)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_FRAGMENT, SRC6, DST6);
    pb_frag6(IPPROTO_TCP, 0);
    pb_ports(1234, 80);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(0, mctx.flags);
    CHECK_EQ(62, mctx.l4_off);
}

MARLIN_TEST(parse_ipv6_sctp_is_not_forwarded)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_SCTP, SRC6, DST6);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_PASS_NOT_FORWARDED, rc);
}

MARLIN_TEST(parse_ipv6_tcp_truncated_l4_is_parse_error)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_TCP, SRC6, DST6);
    pb_pad(3);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_DROP_PARSE_ERROR, rc);
}

/* --- ICMP ------------------------------------------------------------------ */

MARLIN_TEST(parse_icmpv4_echo_request_is_pass_icmp_echo)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ICMP, 5, 0, V4_SRC, V4_DST);
    pb_icmp(ICMP_ECHO, 0);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_PASS_ICMP_ECHO, rc);
    CHECK_TRUE((mctx.flags & MARLIN_CTX_F_ICMP) == 0U);
}

MARLIN_TEST(parse_icmpv4_echo_reply_is_pass_icmp_echo)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ICMP, 5, 0, V4_SRC, V4_DST);
    pb_icmp(ICMP_ECHOREPLY, 0);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_PASS_ICMP_ECHO, rc);
}

/* Exactly 2 ICMP bytes with an echo type: parser.c:250's 2-byte check passes
 * and parser.c:258 returns before parser.c:261's 8-byte check is ever
 * reached -- proving the type check runs first.
 */
MARLIN_TEST(parse_icmpv4_exactly_two_bytes_echo_is_pass_icmp_echo)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    __u32 before_icmp;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ICMP, 5, 0, V4_SRC, V4_DST);
    before_icmp = pb_len;
    pb_icmp(ICMP_ECHO, 0);
    pb_truncate(before_icmp + 2);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_PASS_ICMP_ECHO, rc);
}

MARLIN_TEST(parse_icmpv4_zero_bytes_is_parse_error)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ICMP, 5, 0, V4_SRC, V4_DST);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_DROP_PARSE_ERROR, rc);
}

/* 2-7 bytes with an ERROR type: the type byte is readable but the embedded
 * header never is -- parser.c:262.
 */
MARLIN_TEST(parse_icmpv4_error_truncated_to_two_bytes_is_unparseable)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    __u32 before_icmp;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ICMP, 5, 0, V4_SRC, V4_DST);
    before_icmp = pb_len;
    pb_icmp(ICMP_DEST_UNREACH, 0);
    pb_truncate(before_icmp + 2);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_DROP_ICMP_UNPARSEABLE, rc);
}

/* Exactly 8 ICMP bytes, nothing after: passes parser.c:261 but the embedded
 * iphdr check at parser.c:159 then fails -- distinguishes :268 from :262.
 */
MARLIN_TEST(parse_icmpv4_error_exactly_eight_bytes_is_unparseable)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ICMP, 5, 0, V4_SRC, V4_DST);
    pb_icmp(ICMP_DEST_UNREACH, 0);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_DROP_ICMP_UNPARSEABLE, rc);
}

MARLIN_TEST(parse_icmpv4_redirect_is_not_forwarded)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ICMP, 5, 0, V4_SRC, V4_DST);
    pb_icmp(TEST_ICMP_REDIRECT, 0);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_PASS_NOT_FORWARDED, rc);
}

MARLIN_TEST(parse_icmpv6_neighbor_solicitation_is_not_forwarded)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_ICMPV6, SRC6, DST6);
    pb_icmp(135 /* ICMPV6 neighbour solicitation */, 0);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_PASS_NOT_FORWARDED, rc);
}

MARLIN_TEST(parse_icmpv6_neighbor_advertisement_is_not_forwarded)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_ICMPV6, SRC6, DST6);
    pb_icmp(136 /* ICMPV6 neighbour advertisement */, 0);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_PASS_NOT_FORWARDED, rc);
}

MARLIN_TEST(parse_icmpv6_echo_request_is_pass_icmp_echo)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_ICMPV6, SRC6, DST6);
    pb_icmp(ICMPV6_ECHO_REQUEST, 0);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_PASS_ICMP_ECHO, rc);
}

MARLIN_TEST(parse_icmpv6_echo_reply_is_pass_icmp_echo)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_ICMPV6, SRC6, DST6);
    pb_icmp(ICMPV6_ECHO_REPLY, 0);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_PASS_ICMP_ECHO, rc);
}

/* --- ICMP embedded-header path: the second assertion nothing else catches -- ★ */

static void build_icmpv4_error_embedding_tcp(__u8 icmp_type)
{
    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ICMP, 5, 0, V4_DST /* router's own src, irrelevant */, V4_SRC);
    pb_icmp(icmp_type, 0);
    pb_ipv4(IPPROTO_TCP, 5, 0, EMB4_SRC, EMB4_DST);
    pb_ports(51000, 443); /* client ephemeral port -> server port */
}

static void check_icmpv4_embedded_ok(__u8 icmp_type)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    build_icmpv4_error_embedding_tcp(icmp_type);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(EMB4_SRC, mctx.tuple.dst[0]);   /* swapped: quoted client becomes tuple.dst */
    CHECK_EQ(EMB4_DST, mctx.tuple.src[0]);   /* swapped: quoted VIP becomes tuple.src */
    CHECK_EQ(bpf_htons(51000), mctx.tuple.dport); /* the embedded SOURCE port recovered into dport */
    CHECK_EQ(bpf_htons(443), mctx.tuple.sport); /* the embedded DEST port recovered into sport -- the starred assertion */
    CHECK_EQ(IPPROTO_TCP, mctx.tuple.proto);
    CHECK_TRUE((mctx.flags & MARLIN_CTX_F_ICMP) != 0U);
    /* Outer fields must survive the embedded parse -- Observation 6. */
    CHECK_EQ(AF_INET, mctx.tuple.family);
    CHECK_EQ(14, mctx.l3_off);
    CHECK_EQ(34, mctx.l4_off); /* the outer ICMP offset, not the embedded L4 offset */
    CHECK_EQ(pb_len, mctx.pkt_len);
}

MARLIN_TEST(parse_icmpv4_dest_unreach_embedding_tcp_recovers_tuple)
{
    check_icmpv4_embedded_ok(ICMP_DEST_UNREACH);
}

MARLIN_TEST(parse_icmpv4_time_exceeded_embedding_tcp_recovers_tuple)
{
    check_icmpv4_embedded_ok(ICMP_TIME_EXCEEDED);
}

MARLIN_TEST(parse_icmpv4_paramprob_embedding_tcp_recovers_tuple)
{
    check_icmpv4_embedded_ok(ICMP_PARAMETERPROB);
}

MARLIN_TEST(parse_icmpv4_dest_unreach_embedding_udp_recovers_tuple)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ICMP, 5, 0, V4_DST, V4_SRC);
    pb_icmp(ICMP_DEST_UNREACH, 0);
    pb_ipv4(IPPROTO_UDP, 5, 0, EMB4_SRC, EMB4_DST);
    pb_ports(51000, 53);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(bpf_htons(51000), mctx.tuple.dport);
    CHECK_EQ(bpf_htons(53), mctx.tuple.sport);
    CHECK_EQ(IPPROTO_UDP, mctx.tuple.proto);
}

MARLIN_TEST(parse_icmpv4_embedded_truncated_iphdr_is_unparseable)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ICMP, 5, 0, V4_DST, V4_SRC);
    pb_icmp(ICMP_DEST_UNREACH, 0);
    pb_pad(19); /* embedded iphdr truncated */
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_DROP_ICMP_UNPARSEABLE, rc);
}

MARLIN_TEST(parse_icmpv4_embedded_esp_is_unparseable)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ICMP, 5, 0, V4_DST, V4_SRC);
    pb_icmp(ICMP_DEST_UNREACH, 0);
    pb_ipv4(IPPROTO_ESP, 5, 0, EMB4_SRC, EMB4_DST);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_DROP_ICMP_UNPARSEABLE, rc);
}

MARLIN_TEST(parse_icmpv4_embedded_ah_is_unparseable)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ICMP, 5, 0, V4_DST, V4_SRC);
    pb_icmp(ICMP_DEST_UNREACH, 0);
    pb_ipv4(IPPROTO_AH, 5, 0, EMB4_SRC, EMB4_DST);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_DROP_ICMP_UNPARSEABLE, rc);
}

MARLIN_TEST(parse_icmpv4_embedded_sctp_is_unparseable)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ICMP, 5, 0, V4_DST, V4_SRC);
    pb_icmp(ICMP_DEST_UNREACH, 0);
    pb_ipv4(IPPROTO_SCTP, 5, 0, EMB4_SRC, EMB4_DST);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_DROP_ICMP_UNPARSEABLE, rc);
}

/* Embedded TCP truncated to 2 bytes: a third, distinct route into
 * parser.c:276, via marlin_parse_ports's own truncation check rather than
 * an unsupported/non-TCP-UDP proto. */
MARLIN_TEST(parse_icmpv4_embedded_tcp_truncated_is_unparseable)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ICMP, 5, 0, V4_DST, V4_SRC);
    pb_icmp(ICMP_DEST_UNREACH, 0);
    pb_ipv4(IPPROTO_TCP, 5, 0, EMB4_SRC, EMB4_DST);
    pb_pad(2);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_DROP_ICMP_UNPARSEABLE, rc);
}

/* A quoted non-first fragment: emb->flags & F_FRAG at parser.c:271. */
MARLIN_TEST(parse_icmpv4_embedded_non_first_fragment_is_unparseable)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ICMP, 5, 0, V4_DST, V4_SRC);
    pb_icmp(ICMP_DEST_UNREACH, 0);
    pb_ipv4(IPPROTO_TCP, 5, 0x0040 /* not-first fragment */, EMB4_SRC, EMB4_DST);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_DROP_ICMP_UNPARSEABLE, rc);
}

/* A quoted FIRST fragment carries F_FRAG_FIRST, not F_FRAG -- parser.c:271
 * tests F_FRAG alone, so this one is NOT dropped, and the ports it carries
 * are recovered normally. An earlier draft of this matrix conflated the two
 * (see the plan's ERRORS list, item 4). */
MARLIN_TEST(parse_icmpv4_embedded_first_fragment_is_ok_not_dropped)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ICMP, 5, 0, V4_DST, V4_SRC);
    pb_icmp(ICMP_DEST_UNREACH, 0);
    pb_ipv4(IPPROTO_TCP, 5, IP_MF, EMB4_SRC, EMB4_DST);
    pb_ports(51000, 443);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(bpf_htons(51000), mctx.tuple.dport);
    CHECK_EQ(bpf_htons(443), mctx.tuple.sport);
}

/* --- ICMPv6 embedded-header path -------------------------------------- */

static void check_icmpv6_embedded_ok(__u8 icmp_type)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_ICMPV6, DST6, SRC6); /* router's own addresses, irrelevant to the assertion */
    pb_icmp(icmp_type, 0);
    pb_ipv6(IPPROTO_TCP, EMB6_SRC, EMB6_DST);
    pb_ports(51000, 443);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_MEM(EMB6_SRC, mctx.tuple.dst, 16);
    CHECK_MEM(EMB6_DST, mctx.tuple.src, 16);
    CHECK_EQ(bpf_htons(51000), mctx.tuple.dport);
    CHECK_EQ(bpf_htons(443), mctx.tuple.sport);
    CHECK_TRUE((mctx.flags & MARLIN_CTX_F_ICMP) != 0U);
}

MARLIN_TEST(parse_icmpv6_dest_unreach_embedding_tcp_recovers_tuple)
{
    check_icmpv6_embedded_ok(ICMPV6_DEST_UNREACH);
}

MARLIN_TEST(parse_icmpv6_pkt_toobig_embedding_tcp_recovers_tuple)
{
    check_icmpv6_embedded_ok(ICMPV6_PKT_TOOBIG);
}

MARLIN_TEST(parse_icmpv6_time_exceed_embedding_tcp_recovers_tuple)
{
    check_icmpv6_embedded_ok(ICMPV6_TIME_EXCEED);
}

MARLIN_TEST(parse_icmpv6_paramprob_embedding_tcp_recovers_tuple)
{
    check_icmpv6_embedded_ok(ICMPV6_PARAMPROB);
}

MARLIN_TEST(parse_icmpv6_embedded_udp_recovers_tuple)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_ICMPV6, DST6, SRC6);
    pb_icmp(ICMPV6_DEST_UNREACH, 0);
    pb_ipv6(IPPROTO_UDP, EMB6_SRC, EMB6_DST);
    pb_ports(51000, 53);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(bpf_htons(51000), mctx.tuple.dport);
}

MARLIN_TEST(parse_icmpv6_embedded_truncated_hdr_is_unparseable)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_ICMPV6, DST6, SRC6);
    pb_icmp(ICMPV6_DEST_UNREACH, 0);
    pb_pad(39);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_DROP_ICMP_UNPARSEABLE, rc);
}

/* MARLIN_ICMP_EMB_EXT_HDRS == 2 (parser.c:29): a 3-header embedded chain
 * exceeds the embedded-parse budget even though the outer walk allows 8. */
MARLIN_TEST(parse_icmpv6_embedded_three_ext_hdrs_is_unparseable)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_ICMPV6, DST6, SRC6);
    pb_icmp(ICMPV6_DEST_UNREACH, 0);
    pb_ipv6(IPPROTO_HOPOPTS, EMB6_SRC, EMB6_DST);
    pb_ext6(IPPROTO_HOPOPTS, 0);
    pb_ext6(IPPROTO_HOPOPTS, 0);
    pb_ext6(IPPROTO_TCP, 0);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_DROP_ICMP_UNPARSEABLE, rc);
}

MARLIN_TEST(parse_icmpv6_embedded_two_ext_hdrs_is_ok)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_ICMPV6, DST6, SRC6);
    pb_icmp(ICMPV6_DEST_UNREACH, 0);
    pb_ipv6(IPPROTO_HOPOPTS, EMB6_SRC, EMB6_DST);
    pb_ext6(IPPROTO_HOPOPTS, 0);
    pb_ext6(IPPROTO_TCP, 0);
    pb_ports(1234, 80);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
}

/* ======================================================================
 * QUIC classification -- marlin_parse_quic(), the parser half of
 * docs/design/30-quic.md. balancer.c does not exist yet, so nothing reads
 * MARLIN_CTX_F_QUIC downstream; these cases assert the classification
 * itself and that it changes nothing else.
 * ====================================================================== */

MARLIN_TEST(parse_quic_short_header_sets_flag)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_UDP, 5, 0, V4_SRC, V4_DST);
    pb_udp(51820, 443, 9);
    pb_quic_form(0x40); /* bit 7 clear: short header */
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(MARLIN_CTX_F_QUIC, mctx.flags & MARLIN_CTX_F_QUIC);
}

static void check_quic_long_header_no_flag(__u8 first_byte)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_UDP, 5, 0, V4_SRC, V4_DST);
    pb_udp(51820, 443, 9);
    pb_quic_form(first_byte);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(0, mctx.flags & MARLIN_CTX_F_QUIC);
}

/* Every long-header packet type -- Initial, Handshake and Retry alike --
 * must leave the flag clear: RFC 9000 SS9 forbids migrating before the
 * handshake completes, so none of them can arrive off a migrated path, and
 * an Initial's client-invented DCID must never be steered (docs/design/30-quic.md).
 */
MARLIN_TEST(parse_quic_long_header_initial_v1_no_flag)
{
    check_quic_long_header_no_flag(0xc3); /* long, fixed bit, type=Initial */
}

MARLIN_TEST(parse_quic_long_header_handshake_v1_no_flag)
{
    check_quic_long_header_no_flag(0xe3); /* long, fixed bit, type=Handshake */
}

MARLIN_TEST(parse_quic_long_header_retry_v1_no_flag)
{
    check_quic_long_header_no_flag(0xf0); /* long, fixed bit, type=Retry */
}

MARLIN_TEST(parse_quic_zero_length_udp_payload_no_flag)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_UDP, 5, 0, V4_SRC, V4_DST);
    pb_udp(51820, 443, 8); /* header only, no payload byte */
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(0, mctx.flags & MARLIN_CTX_F_QUIC);
}

/* Every truncation from the start of the UDP header through one byte short
 * of a complete form byte must leave the flag clear without reading past
 * data_end -- ASan (-fsanitize=address, data-plane/Makefile) is what
 * actually catches an out-of-bounds read here; CHECK_EQ only catches the
 * flag. Some of these truncations fall inside the ports word itself, so rc
 * varies between MARLIN_OK and MARLIN_DROP_PARSE_ERROR; only the flag is
 * asserted.
 */
MARLIN_TEST(parse_quic_truncated_udp_header_no_flag)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    __u32 udp_off;
    __u32 n;

    for(n = 0; n < 9; n++) {
        pb_reset();
        pb_eth(ETH_P_IP);
        pb_ipv4(IPPROTO_UDP, 5, 0, V4_SRC, V4_DST);
        udp_off = pb_len;
        pb_udp(51820, 443, 9);
        pb_quic_form(0x40);
        pb_truncate(udp_off + n);
        pb_xdp(&md);
        mctx_init(&mctx);
        marlin_parse(&md, &mctx);
        CHECK_EQ(0, mctx.flags & MARLIN_CTX_F_QUIC);
    }
}

/* proto is TCP, so marlin_parse() must never call marlin_parse_quic() at
 * all -- the same byte that would set the flag on UDP must not on TCP.
 */
MARLIN_TEST(parse_quic_short_header_byte_on_tcp_no_flag)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_TCP, 5, 0, V4_SRC, V4_DST);
    pb_ports(51820, 443);
    pb_pad(4); /* the len/checksum a real tcphdr carries here; parser.c never reads them */
    pb_quic_form(0x40); /* would set MARLIN_CTX_F_QUIC on UDP; proto is TCP */
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(0, mctx.flags & MARLIN_CTX_F_QUIC);
}

/* A non-first fragment carries no L4 header on the wire, so the QUIC
 * classifier must not run -- mctx.flags must equal MARLIN_CTX_F_FRAG
 * exactly, not MARLIN_CTX_F_FRAG with the QUIC bit also set.
 */
MARLIN_TEST(parse_quic_non_first_fragment_udp_no_flag)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_UDP, 5, 0x0040 /* offset, MF clear: not-first, last fragment */, V4_SRC, V4_DST);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(MARLIN_CTX_F_FRAG, mctx.flags);
}

/* An ICMP error's embedded header carries at most 8 bytes of L4
 * (marlin_l4_ports) and never a CID -- marlin_parse_icmp() has no call site
 * for marlin_parse_quic() at all, so the flag must stay clear even when a
 * QUIC-shaped byte follows the embedded ports word.
 */
MARLIN_TEST(parse_quic_icmpv4_embedded_udp_no_flag)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ICMP, 5, 0, V4_DST, V4_SRC);
    pb_icmp(ICMP_DEST_UNREACH, 0);
    pb_ipv4(IPPROTO_UDP, 5, 0, EMB4_SRC, EMB4_DST);
    pb_ports(51000, 53);
    pb_quic_form(0x40); /* one byte past the embedded ports word */
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(0, mctx.flags & MARLIN_CTX_F_QUIC);
}

/* The form byte is read off l4_off after the IPv6 extension-header walk,
 * not a fixed ethernet+ipv4 offset -- l4_off=62 matches the sibling TCP
 * case at parse_ipv6_one_hopopts_hdrlen_zero_l4_off.
 */
MARLIN_TEST(parse_quic_ipv6_hopopts_flag_set_off_walked_l4_off)
{
    struct xdp_md md;
    struct marlin_ctx mctx;
    int rc;

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_HOPOPTS, SRC6, DST6);
    pb_ext6(IPPROTO_UDP, 0);
    pb_udp(51820, 443, 9);
    pb_quic_form(0x40);
    pb_xdp(&md);
    mctx_init(&mctx);
    rc = marlin_parse(&md, &mctx);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(62, mctx.l4_off);
    CHECK_EQ(MARLIN_CTX_F_QUIC, mctx.flags & MARLIN_CTX_F_QUIC);
}

/* The parser's outward behaviour is unchanged by this payload: rc and the
 * tuple are identical whether or not a QUIC-shaped byte follows the UDP
 * header, and mctx.flags differs from the no-payload case by exactly
 * MARLIN_CTX_F_QUIC. Nothing downstream reads the new bit yet
 * (docs/design/30-quic.md); this is what "inert" means for this commit.
 */
MARLIN_TEST(parse_quic_payload_does_not_change_tuple_or_rc)
{
    struct xdp_md md;
    struct marlin_ctx plain;
    struct marlin_ctx quic;
    int rc_plain;
    int rc_quic;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_UDP, 5, 0, V4_SRC, V4_DST);
    pb_udp(51820, 443, 8);
    pb_xdp(&md);
    mctx_init(&plain);
    rc_plain = marlin_parse(&md, &plain);

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_UDP, 5, 0, V4_SRC, V4_DST);
    pb_udp(51820, 443, 9);
    pb_quic_form(0x40);
    pb_xdp(&md);
    mctx_init(&quic);
    rc_quic = marlin_parse(&md, &quic);

    CHECK_RET(rc_plain, rc_quic);
    CHECK_MEM(&plain.tuple, &quic.tuple, sizeof(plain.tuple));
    CHECK_EQ(MARLIN_CTX_F_QUIC, quic.flags ^ plain.flags);
}

int main(void)
{
    return marlin_tests_main();
}
