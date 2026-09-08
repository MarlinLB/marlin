/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Native unit tests for gue.c. This translation unit #includes the source
 * directly, the same as ipip_test.c; its only helper, bpf_xdp_adjust_head(),
 * is answered by tests/stubs/xdp_stub.h through tests/stubs/bpf/bpf_helpers.h.
 */

#include <stdio.h>
#include <string.h>

#include "packet.h"
#include "harness.h"

#include "../src/gue.c"

/*
 * Grant the same headroom BPF_PROG_TEST_RUN would (tests/packet/prog.h),
 * except where the boundary itself is under test.
 */
#define GUE_HEADROOM XDP_PACKET_HEADROOM

/*
 * Palindromic under bpf_htonl(), like ipip_test.c's IPIP_TUNNEL_SRC and
 * IPIP_BACKEND, so the __be32 fields below can be set with the literal
 * directly.
 */
#define GUE_TUNNEL_SRC 0x0d0d0d0dU /* 13.13.13.13 */
#define GUE_BACKEND    0x0c0c0c0cU /* 12.12.12.12 */

#define V4_SRC 0x01010101U /* 1.1.1.1 -- inner client, arbitrary */
#define V4_DST 0x02020202U /* 2.2.2.2 -- inner VIP, arbitrary */

static const unsigned char SRC6[16] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                                       0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
static const unsigned char DST6[16] = {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
                                       0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30};

/*
 * Zeroed like ipip_test.c's mctx_init: every field gue.c reads is set
 * explicitly, so a wrongly-read field shows up as a wrong assertion rather
 * than a coincidental zero. encap_dport stays 0 (the "use default" sentinel)
 * unless a case overrides it directly.
 */
static void mctx_init(struct marlin_ctx *mctx, __u16 pkt_len, __u16 max_frame, __u8 family)
{
    memset(mctx, 0, sizeof(*mctx));
    mctx->pkt_len = pkt_len;
    mctx->cfg.max_frame = max_frame;
    mctx->cfg.tunnel_src = GUE_TUNNEL_SRC;
    mctx->backend.addr = GUE_BACKEND;
    mctx->tuple.family = family;
}

/*
 * Places the xdp_md over the frame packet.h just built inside pb_arena, with
 * `headroom` bytes of room in front for bpf_xdp_adjust_head() to grow into,
 * and arms the stub over exactly that layout. Every case pb_pad()s the
 * headroom before building the frame, so pb_len already accounts for it by
 * the time this runs.
 */
static void gue_arm(struct xdp_md *ctx, __u32 headroom)
{
    unsigned char *data = pb_arena + headroom;

    memset(ctx, 0, sizeof(*ctx));
    ctx->data = (__u32)(unsigned long)data;
    ctx->data_end = (__u32)(unsigned long)(pb_arena + pb_len);
    xdp_stub_attach(pb_arena, data, pb_len - headroom);
}

/*
 * Reads the relocated Ethernet header and the outer IPv4/UDP/GUE headers
 * back out of ctx->data after a successful call. eth_out may be NULL when a
 * case only needs the encapsulation headers.
 */
static void gue_read_outer(const struct xdp_md *ctx, struct ethhdr *eth_out, struct iphdr *iph_out, struct udphdr *udp_out,
                           struct marlin_gue_hdr *gue_out)
{
    unsigned char *data = (unsigned char *)(unsigned long)ctx->data;

    if(eth_out != NULL) {
        memcpy(eth_out, data, sizeof(*eth_out));
    }

    memcpy(iph_out, data + ETH_HLEN, sizeof(*iph_out));
    memcpy(udp_out, data + ETH_HLEN + sizeof(*iph_out), sizeof(*udp_out));
    memcpy(gue_out, data + ETH_HLEN + sizeof(*iph_out) + sizeof(*udp_out), sizeof(*gue_out));
}

/*
 * Shared by gue_encap_failure_paths_leave_mctx_untouched: every failure
 * return must leave l3_off/pkt_len exactly as the case set them, since
 * gue.c writes either field only on the MARLIN_OK path.
 */
static void gue_check_failure_leaves_mctx(struct marlin_ctx *mctx, struct xdp_md *ctx, int expect_ret)
{
    __u16 l3_before = mctx->l3_off;
    __u16 pkt_before = mctx->pkt_len;

    CHECK_RET(expect_ret, marlin_gue_encap_packet(ctx, mctx));
    CHECK_EQ(l3_before, mctx->l3_off);
    CHECK_EQ(pkt_before, mctx->pkt_len);
}

typedef void (*gue_inner_builder)(void);

static void gue_inner_ports(void)
{
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(11111, 80);
}

static void gue_inner_ext6_ports(void)
{
    pb_ipv6(IPPROTO_HOPOPTS, SRC6, DST6);
    pb_ext6(IPPROTO_TCP, 0);
    pb_ports(11111, 80);
}

static void gue_inner_icmp(void)
{
    pb_ipv4(IPPROTO_ICMP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_icmp(8, 0);
}

/*
 * Runs one inner shape through marlin_gue_encap_packet() and checks the
 * bytes past the outer headers are bit-for-bit what was built: gue.c copies
 * only the Ethernet header and writes only the 32-byte outer IPv4+UDP+GUE
 * block, so nothing past that should change regardless of what the payload
 * looks like.
 */
static void gue_check_inner_relocated_unchanged(gue_inner_builder build, __u8 family)
{
    unsigned char snapshot[64];
    struct marlin_ctx mctx;
    struct xdp_md ctx;
    struct iphdr iph;
    struct udphdr udp;
    struct marlin_gue_hdr gue;
    unsigned char *payload;
    __u16 inner_len;

    pb_reset();
    pb_pad(GUE_HEADROOM);
    pb_eth((family == AF_INET6) ? ETH_P_IPV6 : ETH_P_IP);
    build();

    inner_len = (__u16)(pb_len - GUE_HEADROOM - ETH_HLEN);
    CHECK_TRUE(inner_len <= sizeof(snapshot));
    payload = pb_arena + GUE_HEADROOM + ETH_HLEN;
    memcpy(snapshot, payload, inner_len);

    mctx_init(&mctx, (__u16)(pb_len - GUE_HEADROOM), 0, family);
    gue_arm(&ctx, GUE_HEADROOM);

    CHECK_RET(MARLIN_OK, marlin_gue_encap_packet(&ctx, &mctx));

    gue_read_outer(&ctx, NULL, &iph, &udp, &gue);
    CHECK_EQ(bpf_htons((__u16)(MARLIN_OVERHEAD_GUE + inner_len)), iph.tot_len);
    CHECK_EQ(bpf_htons((__u16)(MARLIN_UDP_HLEN + sizeof(gue) + inner_len)), udp.len);
    CHECK_MEM(snapshot, payload, inner_len);
}

/* ---- no packet-tier counterpart: mctx write-back, NULL guards, the
 * length/headroom boundaries, and bookkeeping the emitted frame alone
 * cannot show (docs/design/24-testing.md) --------------------------------
 */

MARLIN_TEST(gue_encap_null_ctx_is_nullref)
{
    struct marlin_ctx mctx;

    memset(&mctx, 0, sizeof(mctx));
    xdp_stub_reset();

    CHECK_RET(MARLIN_ABORT_NULLREF, marlin_gue_encap_packet(NULL, &mctx));
    CHECK_EQ(0, xdp_stub_calls());
}

MARLIN_TEST(gue_encap_null_mctx_is_nullref)
{
    struct xdp_md ctx;
    __u32 data_before;

    pb_reset();
    pb_pad(GUE_HEADROOM);
    pb_eth(ETH_P_IP);
    gue_arm(&ctx, GUE_HEADROOM);
    data_before = ctx.data;

    CHECK_RET(MARLIN_ABORT_NULLREF, marlin_gue_encap_packet(&ctx, NULL));
    CHECK_EQ(data_before, ctx.data);
    CHECK_EQ(0, xdp_stub_calls());
}

MARLIN_TEST(gue_encap_pkt_len_below_eth_hlen_is_encap_length)
{
    /*
     * Native-only by construction, the same reason parser_test.c's 13-byte
     * Ethernet truncation case is (docs/design/24-testing.md): the kernel
     * rejects a bpf_prog_test_run data_size_in below ETH_HLEN before
     * xdp_main ever runs.
     */
    struct marlin_ctx mctx;
    struct xdp_md ctx;

    pb_reset();
    pb_pad(GUE_HEADROOM);
    pb_pad(ETH_HLEN - 1);

    mctx_init(&mctx, ETH_HLEN - 1, 0, AF_INET);
    gue_arm(&ctx, GUE_HEADROOM);

    CHECK_RET(MARLIN_DROP_ENCAP_LENGTH, marlin_gue_encap_packet(&ctx, &mctx));
    CHECK_EQ(0, xdp_stub_calls());
    CHECK_EQ(-1, xdp_stub_diff_first());
}

MARLIN_TEST(gue_encap_pkt_len_exactly_eth_hlen_encapsulates_an_empty_payload)
{
    struct marlin_ctx mctx;
    struct xdp_md ctx;
    struct iphdr iph;
    struct udphdr udp;
    struct marlin_gue_hdr gue;

    pb_reset();
    pb_pad(GUE_HEADROOM);
    pb_eth(ETH_P_IP);

    mctx_init(&mctx, ETH_HLEN, 0, AF_INET);
    gue_arm(&ctx, GUE_HEADROOM);

    CHECK_RET(MARLIN_OK, marlin_gue_encap_packet(&ctx, &mctx));
    CHECK_EQ(ETH_HLEN, mctx.l3_off);
    CHECK_EQ(ETH_HLEN + MARLIN_OVERHEAD_GUE, mctx.pkt_len);

    gue_read_outer(&ctx, NULL, &iph, &udp, &gue);
    CHECK_EQ(bpf_htons(MARLIN_OVERHEAD_GUE), iph.tot_len);
    CHECK_EQ(bpf_htons((__u16)(MARLIN_UDP_HLEN + sizeof(gue))), udp.len);
}

MARLIN_TEST(gue_encap_headroom_exactly_the_overhead_passes_and_one_byte_short_drops)
{
    struct marlin_ctx mctx;
    struct xdp_md ctx;

    pb_reset();
    pb_pad(MARLIN_OVERHEAD_GUE);
    pb_eth(ETH_P_IP);
    mctx_init(&mctx, ETH_HLEN, 0, AF_INET);
    gue_arm(&ctx, MARLIN_OVERHEAD_GUE);

    CHECK_RET(MARLIN_OK, marlin_gue_encap_packet(&ctx, &mctx));
    CHECK_EQ(1, xdp_stub_calls());

    pb_reset();
    pb_pad(MARLIN_OVERHEAD_GUE - 1);
    pb_eth(ETH_P_IP);
    mctx_init(&mctx, ETH_HLEN, 0, AF_INET);
    gue_arm(&ctx, MARLIN_OVERHEAD_GUE - 1);

    CHECK_RET(MARLIN_DROP_ADJUST_HEAD, marlin_gue_encap_packet(&ctx, &mctx));
    CHECK_EQ(1, xdp_stub_calls());
    CHECK_EQ(-MARLIN_OVERHEAD_GUE, xdp_stub_last_delta());
    CHECK_EQ(-1, xdp_stub_diff_first());
    CHECK_EQ(0, mctx.l3_off);
    CHECK_EQ(ETH_HLEN, mctx.pkt_len);
}

MARLIN_TEST(gue_encap_data_end_shorter_than_pkt_len_fails_the_post_adjust_recheck)
{
    /*
     * Unreachable from the datapath -- bpf_prog_test_run_opts requires
     * ctx->data_end to equal data_size_in exactly (tests/packet/prog.h:
     * 89-90), so pkt_len and the real frame length can never disagree
     * there. Defence-in-depth against a future producer of pkt_len that is
     * not the frame length (docs/design/24-testing.md).
     */
    struct marlin_ctx mctx;
    struct xdp_md ctx;

    pb_reset();
    pb_pad(GUE_HEADROOM);
    pb_eth(ETH_P_IP);
    pb_truncate(GUE_HEADROOM + 10); /* real frame far shorter than the pkt_len claimed below */

    mctx_init(&mctx, ETH_HLEN, 0, AF_INET); /* claims 14 bytes; only 10 are real */
    gue_arm(&ctx, GUE_HEADROOM);

    CHECK_RET(MARLIN_DROP_ADJUST_HEAD, marlin_gue_encap_packet(&ctx, &mctx));
    CHECK_EQ(1, xdp_stub_calls());
    CHECK_EQ(-1, xdp_stub_diff_first());
    CHECK_EQ(0, mctx.l3_off);
    CHECK_EQ(ETH_HLEN, mctx.pkt_len);
}

MARLIN_TEST(gue_encap_writes_back_l3_off_and_pkt_len_and_touches_no_other_field)
{
    struct marlin_ctx before, after;
    struct xdp_md ctx;
    __u16 inner_len;

    pb_reset();
    pb_pad(GUE_HEADROOM);
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(1234, 80);

    mctx_init(&before, (__u16)(pb_len - GUE_HEADROOM), 0, AF_INET);
    gue_arm(&ctx, GUE_HEADROOM);

    after = before;
    inner_len = (__u16)(before.pkt_len - ETH_HLEN);

    CHECK_RET(MARLIN_OK, marlin_gue_encap_packet(&ctx, &after));

    before.l3_off = ETH_HLEN;
    before.pkt_len = (__u16)(ETH_HLEN + MARLIN_OVERHEAD_GUE + inner_len);

    CHECK_MEM(&before, &after, sizeof(before));
}

MARLIN_TEST(gue_encap_failure_paths_leave_mctx_untouched)
{
    struct marlin_ctx mctx;
    struct xdp_md ctx;

    /* MARLIN_ABORT_NULLREF; a NULL mctx has nothing left to check untouched. */
    pb_reset();
    pb_pad(GUE_HEADROOM);
    pb_eth(ETH_P_IP);
    mctx_init(&mctx, ETH_HLEN, 0, AF_INET);
    mctx.l3_off = 0xBEEF;
    gue_check_failure_leaves_mctx(&mctx, NULL, MARLIN_ABORT_NULLREF);

    /* MARLIN_DROP_ENCAP_LENGTH */
    pb_reset();
    pb_pad(GUE_HEADROOM);
    pb_pad(ETH_HLEN - 1);
    mctx_init(&mctx, ETH_HLEN - 1, 0, AF_INET);
    mctx.l3_off = 0xBEEF;
    gue_arm(&ctx, GUE_HEADROOM);
    gue_check_failure_leaves_mctx(&mctx, &ctx, MARLIN_DROP_ENCAP_LENGTH);

    /* MARLIN_DROP_FRAME_TOO_BIG */
    pb_reset();
    pb_pad(GUE_HEADROOM);
    pb_eth(ETH_P_IP);
    mctx_init(&mctx, ETH_HLEN, 10, AF_INET);
    mctx.l3_off = 0xBEEF;
    gue_arm(&ctx, GUE_HEADROOM);
    gue_check_failure_leaves_mctx(&mctx, &ctx, MARLIN_DROP_FRAME_TOO_BIG);

    /* MARLIN_DROP_ADJUST_HEAD */
    pb_reset();
    pb_pad(MARLIN_OVERHEAD_GUE - 1);
    pb_eth(ETH_P_IP);
    mctx_init(&mctx, ETH_HLEN, 0, AF_INET);
    mctx.l3_off = 0xBEEF;
    gue_arm(&ctx, MARLIN_OVERHEAD_GUE - 1);
    gue_check_failure_leaves_mctx(&mctx, &ctx, MARLIN_DROP_ADJUST_HEAD);
}

MARLIN_TEST(gue_encap_writes_exactly_eth_hlen_plus_overhead_bytes_at_the_new_frame_start)
{
    struct marlin_ctx mctx;
    struct xdp_md ctx;

    pb_reset();
    pb_pad(GUE_HEADROOM);
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(1234, 80);

    mctx_init(&mctx, (__u16)(pb_len - GUE_HEADROOM), 0, AF_INET);
    gue_arm(&ctx, GUE_HEADROOM);

    CHECK_RET(MARLIN_OK, marlin_gue_encap_packet(&ctx, &mctx));

    /*
     * diff_last() cannot be asserted == here the way ipip_test.c's
     * counterpart can: the GUE header's flags field is always zero (no
     * optional fields, docs/design/14-forwarding-modes.md SS7.3), and its
     * low byte lands on this frame's ETH_P_IP h_proto low byte, which is
     * also zero -- a same-value overwrite a byte-diff cannot see. <= still
     * catches a write that overruns the expected span; diff_first() below
     * is exact because the relocated Ethernet header's first byte is not
     * coincidentally zero.
     */
    CHECK_EQ((int)GUE_HEADROOM - MARLIN_OVERHEAD_GUE, xdp_stub_diff_first());
    CHECK_TRUE(xdp_stub_diff_last() <= (int)GUE_HEADROOM + ETH_HLEN - 1);
}

MARLIN_TEST(gue_encap_calls_adjust_head_once_and_leaves_data_end_alone)
{
    struct marlin_ctx mctx;
    struct xdp_md ctx;
    __u32 data_before, data_end_before;

    pb_reset();
    pb_pad(GUE_HEADROOM);
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(1234, 80);

    mctx_init(&mctx, (__u16)(pb_len - GUE_HEADROOM), 0, AF_INET);
    gue_arm(&ctx, GUE_HEADROOM);
    data_before = ctx.data;
    data_end_before = ctx.data_end;

    CHECK_RET(MARLIN_OK, marlin_gue_encap_packet(&ctx, &mctx));

    CHECK_EQ(1, xdp_stub_calls());
    CHECK_EQ(-MARLIN_OVERHEAD_GUE, xdp_stub_last_delta());
    CHECK_EQ(data_before - MARLIN_OVERHEAD_GUE, ctx.data);
    CHECK_EQ(data_end_before, ctx.data_end);
}

MARLIN_TEST(gue_encap_unknown_family_falls_back_to_gue_proto_4)
{
    /*
     * No parseable frame carries a tuple.family other than AF_INET/AF_INET6
     * (parser.c only ever sets one of the two), so this exercises what
     * gue.c's ternary does with a value that is neither -- a state no other
     * tier can produce.
     */
    static const __u8 families[] = {0, 17}; /* 17 == AF_PACKET */
    struct marlin_ctx mctx;
    struct xdp_md ctx;
    struct iphdr iph;
    struct udphdr udp;
    struct marlin_gue_hdr gue;
    unsigned int i;

    for(i = 0; i < sizeof(families) / sizeof(families[0]); i++) {
        pb_reset();
        pb_pad(GUE_HEADROOM);
        pb_eth(ETH_P_IP);
        mctx_init(&mctx, ETH_HLEN, 0, families[i]);
        gue_arm(&ctx, GUE_HEADROOM);

        CHECK_RET(MARLIN_OK, marlin_gue_encap_packet(&ctx, &mctx));
        gue_read_outer(&ctx, NULL, &iph, &udp, &gue);
        CHECK_EQ(IPPROTO_IPIP, gue.proto);
    }
}

MARLIN_TEST(gue_encap_pkt_len_at_the_u16_ceiling_does_not_wrap)
{
    /*
     * pkt_len is decoupled from the real frame on purpose here -- the
     * arithmetic in question depends only on the __u16 value, not on how
     * many bytes actually exist, mirroring
     * ipip_test.c's ipip_encap_pkt_len_at_the_u16_ceiling_does_not_wrap.
     */
    __u16 huge_pkt_len = (__u16)(0xffffU - MARLIN_OVERHEAD_GUE); /* 65503 */
    struct marlin_ctx mctx;
    struct xdp_md ctx;
    struct iphdr iph;
    struct udphdr udp;
    struct marlin_gue_hdr gue;

    pb_reset();
    pb_pad(GUE_HEADROOM);
    pb_eth(ETH_P_IP);

    mctx_init(&mctx, huge_pkt_len, 0, AF_INET);
    gue_arm(&ctx, GUE_HEADROOM);

    CHECK_RET(MARLIN_OK, marlin_gue_encap_packet(&ctx, &mctx));
    gue_read_outer(&ctx, NULL, &iph, &udp, &gue);
    CHECK_EQ(bpf_htons((__u16)(0xffffU - ETH_HLEN)), iph.tot_len);
    CHECK_EQ(0xffffU, mctx.pkt_len);
}

MARLIN_TEST(gue_encap_relocates_any_inner_payload_unchanged)
{
    gue_check_inner_relocated_unchanged(gue_inner_ports, AF_INET);
    gue_check_inner_relocated_unchanged(gue_inner_ext6_ports, AF_INET6);
    gue_check_inner_relocated_unchanged(gue_inner_icmp, AF_INET);
}

MARLIN_TEST(gue_encap_dest_port_defaults_and_honours_configured_encap_dport)
{
    struct marlin_ctx mctx;
    struct xdp_md ctx;
    struct iphdr iph;
    struct udphdr udp;
    struct marlin_gue_hdr gue;

    pb_reset();
    pb_pad(GUE_HEADROOM);
    pb_eth(ETH_P_IP);
    mctx_init(&mctx, ETH_HLEN, 0, AF_INET);
    gue_arm(&ctx, GUE_HEADROOM);

    CHECK_RET(MARLIN_OK, marlin_gue_encap_packet(&ctx, &mctx));
    gue_read_outer(&ctx, NULL, &iph, &udp, &gue);
    CHECK_EQ(bpf_htons(MARLIN_GUE_DPORT_DEFAULT), udp.dest);

    pb_reset();
    pb_pad(GUE_HEADROOM);
    pb_eth(ETH_P_IP);
    mctx_init(&mctx, ETH_HLEN, 0, AF_INET);
    mctx.backend.encap_dport = bpf_htons(7777);
    gue_arm(&ctx, GUE_HEADROOM);

    CHECK_RET(MARLIN_OK, marlin_gue_encap_packet(&ctx, &mctx));
    gue_read_outer(&ctx, NULL, &iph, &udp, &gue);
    CHECK_EQ(bpf_htons(7777), udp.dest);
}

/* ---- mirrors a packet-tier assertion, each naming its counterpart
 * (docs/design/24-testing.md's discipline rule) -------------------------
 */

MARLIN_TEST(gue_encap_builds_the_outer_headers_byte_for_byte)
{
    /*
     * Mirrors gue_encap_zero_lookup_swaps_ethernet_and_builds_outer_header
     * (tests/packet/xdp_test.c). The swapped MACs asserted there are
     * nexthop.c's contribution, not gue.c's, so this checks only the
     * headers gue.c itself writes and that the arriving Ethernet header
     * relocated unchanged. The entropy source port is checked by calling
     * marlin_entropy_sport() directly -- entropy_test.c independently
     * verifies that function's algorithm; this test verifies only that
     * gue.c wires its result into udp.source.
     */
    static const unsigned char SMAC[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    static const unsigned char DMAC[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    struct marlin_ctx mctx;
    struct xdp_md ctx;
    struct ethhdr eth_before, eth_after;
    struct iphdr iph, expect_iph;
    struct udphdr udp, expect_udp;
    struct marlin_gue_hdr gue, expect_gue;
    __u16 inner_len;

    pb_reset();
    pb_pad(GUE_HEADROOM);
    pb_eth(ETH_P_IP);
    memcpy(pb_arena + GUE_HEADROOM, DMAC, ETH_ALEN);
    memcpy(pb_arena + GUE_HEADROOM + ETH_ALEN, SMAC, ETH_ALEN);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(1234, 80);

    memcpy(&eth_before, pb_arena + GUE_HEADROOM, sizeof(eth_before));
    inner_len = (__u16)(pb_len - GUE_HEADROOM - ETH_HLEN);

    mctx_init(&mctx, (__u16)(pb_len - GUE_HEADROOM), 0, AF_INET);
    gue_arm(&ctx, GUE_HEADROOM);

    CHECK_RET(MARLIN_OK, marlin_gue_encap_packet(&ctx, &mctx));

    gue_read_outer(&ctx, &eth_after, &iph, &udp, &gue);
    CHECK_MEM(&eth_before, &eth_after, sizeof(eth_before));

    memset(&expect_iph, 0, sizeof(expect_iph));
    expect_iph.version = 4;
    expect_iph.ihl = MARLIN_IPV4_IHL_MIN;
    expect_iph.frag_off = bpf_htons(IP_DF);
    expect_iph.ttl = MARLIN_OUTER_TTL;
    expect_iph.protocol = IPPROTO_UDP;
    expect_iph.tot_len = bpf_htons((__u16)(MARLIN_OVERHEAD_GUE + inner_len));
    expect_iph.saddr = GUE_TUNNEL_SRC;
    expect_iph.daddr = GUE_BACKEND;
    expect_iph.check = marlin_ipv4_csum(&expect_iph);
    CHECK_MEM(&expect_iph, &iph, sizeof(expect_iph));

    memset(&expect_udp, 0, sizeof(expect_udp));
    expect_udp.source = marlin_entropy_sport(&mctx.tuple);
    expect_udp.dest = bpf_htons(MARLIN_GUE_DPORT_DEFAULT);
    expect_udp.len = bpf_htons((__u16)(MARLIN_UDP_HLEN + sizeof(expect_gue) + inner_len));
    expect_udp.check = 0;
    CHECK_MEM(&expect_udp, &udp, sizeof(expect_udp));

    memset(&expect_gue, 0, sizeof(expect_gue));
    expect_gue.proto = IPPROTO_IPIP;
    CHECK_MEM(&expect_gue, &gue, sizeof(expect_gue));
}

MARLIN_TEST(gue_encap_ipv6_inner_sets_gue_proto_41)
{
    /* Mirrors gue_encap_ipv6_inner_sets_gue_proto_41 (tests/packet/xdp_test.c). */
    struct marlin_ctx mctx;
    struct xdp_md ctx;
    struct iphdr iph;
    struct udphdr udp;
    struct marlin_gue_hdr gue;

    pb_reset();
    pb_pad(GUE_HEADROOM);
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_TCP, SRC6, DST6);
    pb_ports(1234, 80);

    mctx_init(&mctx, (__u16)(pb_len - GUE_HEADROOM), 0, AF_INET6);
    gue_arm(&ctx, GUE_HEADROOM);

    CHECK_RET(MARLIN_OK, marlin_gue_encap_packet(&ctx, &mctx));
    gue_read_outer(&ctx, NULL, &iph, &udp, &gue);
    CHECK_EQ(IPPROTO_UDP, iph.protocol);
    CHECK_EQ(IPPROTO_IPV6, gue.proto);
}

MARLIN_TEST(gue_encap_frame_too_big_returns_before_the_helper)
{
    /*
     * Mirrors gue_encap_frame_too_big_drops_before_adjust_head
     * (tests/packet/xdp_test.c); the native-only half is that the helper is
     * never reached at all, asserted directly rather than inferred from an
     * unmodified frame.
     */
    struct marlin_ctx mctx;
    struct xdp_md ctx;

    pb_reset();
    pb_pad(GUE_HEADROOM);
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(1234, 80);

    mctx_init(&mctx, (__u16)(pb_len - GUE_HEADROOM), 10, AF_INET);
    gue_arm(&ctx, GUE_HEADROOM);

    CHECK_RET(MARLIN_DROP_FRAME_TOO_BIG, marlin_gue_encap_packet(&ctx, &mctx));
    CHECK_EQ(0, xdp_stub_calls());
    CHECK_EQ(-1, xdp_stub_diff_first());
}

MARLIN_TEST(gue_encap_max_frame_zero_disables_the_check)
{
    /* Mirrors gue_encap_max_frame_zero_disables_the_check (tests/packet/xdp_test.c). */
    struct marlin_ctx mctx;
    struct xdp_md ctx;

    pb_reset();
    pb_pad(GUE_HEADROOM);
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_pad(2000); /* well past any real MTU; only max_frame == 0 lets this through */

    mctx_init(&mctx, (__u16)(pb_len - GUE_HEADROOM), 0, AF_INET);
    gue_arm(&ctx, GUE_HEADROOM);

    CHECK_RET(MARLIN_OK, marlin_gue_encap_packet(&ctx, &mctx));
}

int main(void)
{
    return marlin_tests_main();
}
