/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Native unit tests for ipip.c. This translation unit #includes the source
 * directly, the same as acl_test.c; its only helper, bpf_xdp_adjust_head(),
 * is answered by tests/stubs/xdp_stub.h through tests/stubs/bpf/bpf_helpers.h.
 */

#include <stdio.h>
#include <string.h>

#include "packet.h"
#include "harness.h"

#include "../bpf/ipip.c"

/*
 * Grant the same headroom BPF_PROG_TEST_RUN would (tests/packet/prog.h),
 * except where the boundary itself is under test.
 */
#define IPIP_HEADROOM XDP_PACKET_HEADROOM

/*
 * Palindromic under bpf_htonl(), like xdp_test.c's IPIP_TUNNEL_SRC and
 * NH_BACKEND_ADDR, so the __be32 fields below can be set with the literal
 * directly. IPIP_BACKEND's last octet is deliberately non-zero: it lands on
 * the last byte diff_last() below checks, and a zero octet there would be
 * indistinguishable from the untouched canary at that position.
 */
#define IPIP_TUNNEL_SRC 0x0d0d0d0dU /* 13.13.13.13 */
#define IPIP_BACKEND    0x0c0c0c0cU /* 12.12.12.12 */

#define V4_SRC 0x01010101U /* 1.1.1.1 -- inner client, arbitrary */
#define V4_DST 0x02020202U /* 2.2.2.2 -- inner VIP, arbitrary */

static const unsigned char SRC6[16] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                                       0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
static const unsigned char DST6[16] = {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
                                       0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30};

/*
 * Zeroed like mtu_test.c's mctx_init: every field ipip.c reads is set
 * explicitly, so a wrongly-read field shows up as a wrong assertion rather
 * than a coincidental zero.
 */
static void mctx_init(struct marlin_ctx *mctx, __u16 pkt_len, __u16 max_frame, __u8 family)
{
    memset(mctx, 0, sizeof(*mctx));
    mctx->pkt_len = pkt_len;
    mctx->cfg.max_frame = max_frame;
    mctx->cfg.tunnel_src = IPIP_TUNNEL_SRC;
    mctx->backend.addr = IPIP_BACKEND;
    mctx->tuple.family = family;
}

/*
 * Places the xdp_md over the frame packet.h just built inside pb_arena,
 * with `headroom` bytes of room in front for bpf_xdp_adjust_head() to grow
 * into, and arms the stub over exactly that layout. Every case pb_pad()s
 * the headroom before building the frame, so pb_len already accounts for
 * it by the time this runs -- unlike pb_xdp() (packet.h), which assumes the
 * frame starts at pb_arena itself.
 */
static void ipip_arm(struct xdp_md *ctx, __u32 headroom)
{
    unsigned char *data = pb_arena + headroom;

    memset(ctx, 0, sizeof(*ctx));
    ctx->data = (__u32)(unsigned long)data;
    ctx->data_end = (__u32)(unsigned long)(pb_arena + pb_len);
    xdp_stub_attach(pb_arena, data, pb_len - headroom);
}

/*
 * Reads the relocated Ethernet header and the outer IPv4 header back out of
 * ctx->data after a successful call. eth_out may be NULL when a case only
 * needs the IPv4 header.
 */
static void ipip_read_outer(const struct xdp_md *ctx, struct ethhdr *eth_out, struct iphdr *iph_out)
{
    unsigned char *data = (unsigned char *)(unsigned long)ctx->data;

    if(eth_out != NULL) {
        memcpy(eth_out, data, sizeof(*eth_out));
    }

    memcpy(iph_out, data + ETH_HLEN, sizeof(*iph_out));
}

/*
 * Shared by ipip_encap_failure_paths_leave_mctx_untouched: every failure
 * return must leave l3_off/pkt_len exactly as the case set them, since
 * marlin_ipip_encap_packet() writes either field only on the MARLIN_OK path.
 */
static void ipip_check_failure_leaves_mctx(struct marlin_ctx *mctx, struct xdp_md *ctx, int expect_ret)
{
    __u16 l3_before = mctx->l3_off;
    __u16 pkt_before = mctx->pkt_len;

    CHECK_RET(expect_ret, marlin_ipip_encap_packet(ctx, mctx));
    CHECK_EQ(l3_before, mctx->l3_off);
    CHECK_EQ(pkt_before, mctx->pkt_len);
}

typedef void (*ipip_inner_builder)(void);

static void ipip_inner_ports(void)
{
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(11111, 80);
}

static void ipip_inner_ext6_ports(void)
{
    pb_ipv6(IPPROTO_HOPOPTS, SRC6, DST6);
    pb_ext6(IPPROTO_TCP, 0);
    pb_ports(11111, 80);
}

static void ipip_inner_icmp(void)
{
    pb_ipv4(IPPROTO_ICMP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_icmp(8, 0);
}

/*
 * Runs one inner shape through marlin_ipip_encap_packet() and checks the
 * bytes past the outer header are bit-for-bit what was built: the function
 * copies only the Ethernet header and writes only the 20-byte outer iphdr,
 * so nothing past that should change regardless of what the payload looks
 * like.
 */
static void ipip_check_inner_relocated_unchanged(ipip_inner_builder build, __u8 family)
{
    unsigned char snapshot[64];
    struct marlin_ctx mctx;
    struct xdp_md ctx;
    struct iphdr iph;
    unsigned char *payload;
    __u16 inner_len;

    pb_reset();
    pb_pad(IPIP_HEADROOM);
    pb_eth((family == AF_INET6) ? ETH_P_IPV6 : ETH_P_IP);
    build();

    inner_len = (__u16)(pb_len - IPIP_HEADROOM - ETH_HLEN);
    CHECK_TRUE(inner_len <= sizeof(snapshot));
    payload = pb_arena + IPIP_HEADROOM + ETH_HLEN;
    memcpy(snapshot, payload, inner_len);

    mctx_init(&mctx, (__u16)(pb_len - IPIP_HEADROOM), 0, family);
    ipip_arm(&ctx, IPIP_HEADROOM);

    CHECK_RET(MARLIN_OK, marlin_ipip_encap_packet(&ctx, &mctx));

    ipip_read_outer(&ctx, NULL, &iph);
    CHECK_EQ(bpf_htons((__u16)(MARLIN_OVERHEAD_IPIP + inner_len)), iph.tot_len);
    CHECK_MEM(snapshot, payload, inner_len);
}

/* ---- no packet-tier counterpart: mctx write-back, NULL guards, the
 * length/headroom boundaries, and bookkeeping the emitted frame alone
 * cannot show (docs/design/24-testing.md) --------------------------------
 */

MARLIN_TEST(ipip_encap_null_ctx_is_nullref)
{
    struct marlin_ctx mctx;

    memset(&mctx, 0, sizeof(mctx));
    xdp_stub_reset();

    CHECK_RET(MARLIN_ABORT_NULLREF, marlin_ipip_encap_packet(NULL, &mctx));
    CHECK_EQ(0, xdp_stub_calls());
}

MARLIN_TEST(ipip_encap_null_mctx_is_nullref)
{
    struct xdp_md ctx;
    __u32 data_before;

    pb_reset();
    pb_pad(IPIP_HEADROOM);
    pb_eth(ETH_P_IP);
    ipip_arm(&ctx, IPIP_HEADROOM);
    data_before = ctx.data;

    CHECK_RET(MARLIN_ABORT_NULLREF, marlin_ipip_encap_packet(&ctx, NULL));
    CHECK_EQ(data_before, ctx.data);
    CHECK_EQ(0, xdp_stub_calls());
}

MARLIN_TEST(ipip_encap_pkt_len_below_eth_hlen_is_encap_length)
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
    pb_pad(IPIP_HEADROOM);
    pb_pad(ETH_HLEN - 1);

    mctx_init(&mctx, ETH_HLEN - 1, 0, AF_INET);
    ipip_arm(&ctx, IPIP_HEADROOM);

    CHECK_RET(MARLIN_DROP_ENCAP_LENGTH, marlin_ipip_encap_packet(&ctx, &mctx));
    CHECK_EQ(0, xdp_stub_calls());
    CHECK_EQ(-1, xdp_stub_diff_first());
}

MARLIN_TEST(ipip_encap_pkt_len_exactly_eth_hlen_encapsulates_an_empty_payload)
{
    struct marlin_ctx mctx;
    struct xdp_md ctx;
    struct iphdr iph;

    pb_reset();
    pb_pad(IPIP_HEADROOM);
    pb_eth(ETH_P_IP);

    mctx_init(&mctx, ETH_HLEN, 0, AF_INET);
    ipip_arm(&ctx, IPIP_HEADROOM);

    CHECK_RET(MARLIN_OK, marlin_ipip_encap_packet(&ctx, &mctx));
    CHECK_EQ(ETH_HLEN, mctx.l3_off);
    CHECK_EQ(ETH_HLEN + MARLIN_OVERHEAD_IPIP, mctx.pkt_len);

    ipip_read_outer(&ctx, NULL, &iph);
    CHECK_EQ(bpf_htons(MARLIN_OVERHEAD_IPIP), iph.tot_len);
}

MARLIN_TEST(ipip_encap_headroom_exactly_the_overhead_passes_and_one_byte_short_drops)
{
    struct marlin_ctx mctx;
    struct xdp_md ctx;

    pb_reset();
    pb_pad(MARLIN_OVERHEAD_IPIP);
    pb_eth(ETH_P_IP);
    mctx_init(&mctx, ETH_HLEN, 0, AF_INET);
    ipip_arm(&ctx, MARLIN_OVERHEAD_IPIP);

    CHECK_RET(MARLIN_OK, marlin_ipip_encap_packet(&ctx, &mctx));
    CHECK_EQ(1, xdp_stub_calls());

    pb_reset();
    pb_pad(MARLIN_OVERHEAD_IPIP - 1);
    pb_eth(ETH_P_IP);
    mctx_init(&mctx, ETH_HLEN, 0, AF_INET);
    ipip_arm(&ctx, MARLIN_OVERHEAD_IPIP - 1);

    CHECK_RET(MARLIN_DROP_ADJUST_HEAD, marlin_ipip_encap_packet(&ctx, &mctx));
    CHECK_EQ(1, xdp_stub_calls());
    CHECK_EQ(-MARLIN_OVERHEAD_IPIP, xdp_stub_last_delta());
    CHECK_EQ(-1, xdp_stub_diff_first());
    CHECK_EQ(0, mctx.l3_off);
    CHECK_EQ(ETH_HLEN, mctx.pkt_len);
}

MARLIN_TEST(ipip_encap_data_end_shorter_than_pkt_len_fails_the_post_adjust_recheck)
{
    /*
     * Unreachable from the datapath -- bpf_prog_test_run_opts requires
     * ctx->data_end to equal data_size_in exactly (tests/packet/prog.h:
     * 89-90), so pkt_len and the real frame length can never disagree
     * there. Constructed here the same way acl.c's NULL-mctx case exercises
     * a branch the verifier proves unreachable (docs/design/24-testing.md):
     * defence-in-depth against a future producer of pkt_len that is not
     * the frame length.
     */
    struct marlin_ctx mctx;
    struct xdp_md ctx;

    pb_reset();
    pb_pad(IPIP_HEADROOM);
    pb_eth(ETH_P_IP);
    pb_truncate(IPIP_HEADROOM + 10); /* real frame far shorter than the pkt_len claimed below */

    mctx_init(&mctx, ETH_HLEN, 0, AF_INET); /* claims 14 bytes; only 10 are real */
    ipip_arm(&ctx, IPIP_HEADROOM);

    CHECK_RET(MARLIN_DROP_ADJUST_HEAD, marlin_ipip_encap_packet(&ctx, &mctx));
    CHECK_EQ(1, xdp_stub_calls());
    CHECK_EQ(-1, xdp_stub_diff_first());
    CHECK_EQ(0, mctx.l3_off);
    CHECK_EQ(ETH_HLEN, mctx.pkt_len);
}

MARLIN_TEST(ipip_encap_writes_back_l3_off_and_pkt_len_and_touches_no_other_field)
{
    struct marlin_ctx before, after;
    struct xdp_md ctx;
    __u16 inner_len;

    pb_reset();
    pb_pad(IPIP_HEADROOM);
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(1234, 80);

    mctx_init(&before, (__u16)(pb_len - IPIP_HEADROOM), 0, AF_INET);
    ipip_arm(&ctx, IPIP_HEADROOM);

    after = before;
    inner_len = (__u16)(before.pkt_len - ETH_HLEN);

    CHECK_RET(MARLIN_OK, marlin_ipip_encap_packet(&ctx, &after));

    before.l3_off = ETH_HLEN;
    before.pkt_len = (__u16)(ETH_HLEN + MARLIN_OVERHEAD_IPIP + inner_len);

    CHECK_MEM(&before, &after, sizeof(before));
}

MARLIN_TEST(ipip_encap_failure_paths_leave_mctx_untouched)
{
    struct marlin_ctx mctx;
    struct xdp_md ctx;

    /* MARLIN_ABORT_NULLREF; a NULL mctx has nothing left to check untouched. */
    pb_reset();
    pb_pad(IPIP_HEADROOM);
    pb_eth(ETH_P_IP);
    mctx_init(&mctx, ETH_HLEN, 0, AF_INET);
    mctx.l3_off = 0xBEEF;
    ipip_check_failure_leaves_mctx(&mctx, NULL, MARLIN_ABORT_NULLREF);

    /* MARLIN_DROP_ENCAP_LENGTH */
    pb_reset();
    pb_pad(IPIP_HEADROOM);
    pb_pad(ETH_HLEN - 1);
    mctx_init(&mctx, ETH_HLEN - 1, 0, AF_INET);
    mctx.l3_off = 0xBEEF;
    ipip_arm(&ctx, IPIP_HEADROOM);
    ipip_check_failure_leaves_mctx(&mctx, &ctx, MARLIN_DROP_ENCAP_LENGTH);

    /* MARLIN_DROP_FRAME_TOO_BIG */
    pb_reset();
    pb_pad(IPIP_HEADROOM);
    pb_eth(ETH_P_IP);
    mctx_init(&mctx, ETH_HLEN, 10, AF_INET);
    mctx.l3_off = 0xBEEF;
    ipip_arm(&ctx, IPIP_HEADROOM);
    ipip_check_failure_leaves_mctx(&mctx, &ctx, MARLIN_DROP_FRAME_TOO_BIG);

    /* MARLIN_DROP_ADJUST_HEAD */
    pb_reset();
    pb_pad(MARLIN_OVERHEAD_IPIP - 1);
    pb_eth(ETH_P_IP);
    mctx_init(&mctx, ETH_HLEN, 0, AF_INET);
    mctx.l3_off = 0xBEEF;
    ipip_arm(&ctx, MARLIN_OVERHEAD_IPIP - 1);
    ipip_check_failure_leaves_mctx(&mctx, &ctx, MARLIN_DROP_ADJUST_HEAD);
}

MARLIN_TEST(ipip_encap_writes_exactly_eth_hlen_plus_overhead_bytes_at_the_new_frame_start)
{
    struct marlin_ctx mctx;
    struct xdp_md ctx;

    pb_reset();
    pb_pad(IPIP_HEADROOM);
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(1234, 80);

    mctx_init(&mctx, (__u16)(pb_len - IPIP_HEADROOM), 0, AF_INET);
    ipip_arm(&ctx, IPIP_HEADROOM);

    CHECK_RET(MARLIN_OK, marlin_ipip_encap_packet(&ctx, &mctx));

    CHECK_EQ((int)IPIP_HEADROOM - MARLIN_OVERHEAD_IPIP, xdp_stub_diff_first());
    CHECK_EQ((int)IPIP_HEADROOM + ETH_HLEN - 1, xdp_stub_diff_last());
}

MARLIN_TEST(ipip_encap_calls_adjust_head_once_and_leaves_data_end_alone)
{
    struct marlin_ctx mctx;
    struct xdp_md ctx;
    __u32 data_before, data_end_before;

    pb_reset();
    pb_pad(IPIP_HEADROOM);
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(1234, 80);

    mctx_init(&mctx, (__u16)(pb_len - IPIP_HEADROOM), 0, AF_INET);
    ipip_arm(&ctx, IPIP_HEADROOM);
    data_before = ctx.data;
    data_end_before = ctx.data_end;

    CHECK_RET(MARLIN_OK, marlin_ipip_encap_packet(&ctx, &mctx));

    CHECK_EQ(1, xdp_stub_calls());
    CHECK_EQ(-MARLIN_OVERHEAD_IPIP, xdp_stub_last_delta());
    CHECK_EQ(data_before - MARLIN_OVERHEAD_IPIP, ctx.data);
    CHECK_EQ(data_end_before, ctx.data_end);
}

MARLIN_TEST(ipip_encap_unknown_family_falls_back_to_protocol_4)
{
    /*
     * No parseable frame carries a tuple.family other than AF_INET/AF_INET6
     * (parser.c only ever sets one of the two), so this exercises what
     * ipip.c's ternary does with a value that is neither -- a state no
     * other tier can produce.
     */
    static const __u8 families[] = {0, 17}; /* 17 == AF_PACKET */
    struct marlin_ctx mctx;
    struct xdp_md ctx;
    struct iphdr iph;
    unsigned int i;

    for(i = 0; i < sizeof(families) / sizeof(families[0]); i++) {
        pb_reset();
        pb_pad(IPIP_HEADROOM);
        pb_eth(ETH_P_IP);
        mctx_init(&mctx, ETH_HLEN, 0, families[i]);
        ipip_arm(&ctx, IPIP_HEADROOM);

        CHECK_RET(MARLIN_OK, marlin_ipip_encap_packet(&ctx, &mctx));
        ipip_read_outer(&ctx, NULL, &iph);
        CHECK_EQ(IPPROTO_IPIP, iph.protocol);
    }
}

MARLIN_TEST(ipip_encap_pkt_len_at_the_u16_ceiling_does_not_wrap)
{
    /*
     * pkt_len is decoupled from the real frame on purpose here -- the
     * tot_len/pkt_len arithmetic depends only on the __u16 value, not on
     * how many bytes actually exist, mirroring mtu_test.c's
     * frame_fits_pkt_len_near_u16_max_does_not_wrap.
     */
    __u16 huge_pkt_len = (__u16)(0xffffU - MARLIN_OVERHEAD_IPIP); /* 65515 */
    struct marlin_ctx mctx;
    struct xdp_md ctx;
    struct iphdr iph;

    pb_reset();
    pb_pad(IPIP_HEADROOM);
    pb_eth(ETH_P_IP);

    mctx_init(&mctx, huge_pkt_len, 0, AF_INET);
    ipip_arm(&ctx, IPIP_HEADROOM);

    CHECK_RET(MARLIN_OK, marlin_ipip_encap_packet(&ctx, &mctx));
    ipip_read_outer(&ctx, NULL, &iph);
    CHECK_EQ(bpf_htons((__u16)(0xffffU - ETH_HLEN)), iph.tot_len);
    CHECK_EQ(0xffffU, mctx.pkt_len);
}

MARLIN_TEST(ipip_encap_relocates_any_inner_payload_unchanged)
{
    ipip_check_inner_relocated_unchanged(ipip_inner_ports, AF_INET);
    ipip_check_inner_relocated_unchanged(ipip_inner_ext6_ports, AF_INET6);
    ipip_check_inner_relocated_unchanged(ipip_inner_icmp, AF_INET);
}

/* ---- mirrors a packet-tier assertion, each naming its counterpart
 * (docs/design/24-testing.md's discipline rule) -------------------------
 */

MARLIN_TEST(ipip_encap_builds_the_outer_ipv4_header_byte_for_byte)
{
    /*
     * Mirrors ipip_encap_zero_lookup_swaps_ethernet_and_builds_outer_header
     * (tests/packet/xdp_test.c:1319). The swapped MACs asserted there are
     * nexthop.c's contribution, not ipip.c's, so this checks only the
     * header ipip.c itself writes and that the arriving Ethernet header
     * relocated unchanged.
     */
    static const unsigned char SMAC[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    static const unsigned char DMAC[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    struct marlin_ctx mctx;
    struct xdp_md ctx;
    struct ethhdr eth_before, eth_after;
    struct iphdr iph, expect;
    __u16 inner_len;

    pb_reset();
    pb_pad(IPIP_HEADROOM);
    pb_eth(ETH_P_IP);
    memcpy(pb_arena + IPIP_HEADROOM, DMAC, ETH_ALEN);
    memcpy(pb_arena + IPIP_HEADROOM + ETH_ALEN, SMAC, ETH_ALEN);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(1234, 80);

    memcpy(&eth_before, pb_arena + IPIP_HEADROOM, sizeof(eth_before));
    inner_len = (__u16)(pb_len - IPIP_HEADROOM - ETH_HLEN);

    mctx_init(&mctx, (__u16)(pb_len - IPIP_HEADROOM), 0, AF_INET);
    ipip_arm(&ctx, IPIP_HEADROOM);

    CHECK_RET(MARLIN_OK, marlin_ipip_encap_packet(&ctx, &mctx));

    ipip_read_outer(&ctx, &eth_after, &iph);
    CHECK_MEM(&eth_before, &eth_after, sizeof(eth_before));

    memset(&expect, 0, sizeof(expect));
    expect.version = 4;
    expect.ihl = MARLIN_IPV4_IHL_MIN;
    expect.frag_off = bpf_htons(IP_DF);
    expect.ttl = MARLIN_OUTER_TTL;
    expect.protocol = IPPROTO_IPIP;
    expect.tot_len = bpf_htons((__u16)(MARLIN_OVERHEAD_IPIP + inner_len));
    expect.saddr = IPIP_TUNNEL_SRC;
    expect.daddr = IPIP_BACKEND;
    expect.check = marlin_ipv4_csum(&expect);

    CHECK_MEM(&expect, &iph, sizeof(expect));
}

MARLIN_TEST(ipip_encap_ipv6_inner_sets_protocol_41)
{
    /*
     * Mirrors ipip_encap_ipv6_inner_sets_protocol_41 (tests/packet/xdp_test.c:1337).
     * Also a regression test for the bug where the outer Ethernet header's
     * EtherType carried the arriving frame's ETH_P_IPV6 forward unchanged:
     * the arriving EtherType mirrors tuple.family exactly (parser.c), but
     * the outer network layer is always IPv4
     * (docs/design/14-forwarding-modes.md SS7.5).
     */
    struct marlin_ctx mctx;
    struct xdp_md ctx;
    struct ethhdr eth;
    struct iphdr iph;

    pb_reset();
    pb_pad(IPIP_HEADROOM);
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_TCP, SRC6, DST6);
    pb_ports(1234, 80);

    mctx_init(&mctx, (__u16)(pb_len - IPIP_HEADROOM), 0, AF_INET6);
    ipip_arm(&ctx, IPIP_HEADROOM);

    CHECK_RET(MARLIN_OK, marlin_ipip_encap_packet(&ctx, &mctx));
    ipip_read_outer(&ctx, &eth, &iph);
    CHECK_EQ(IPPROTO_IPV6, iph.protocol);
    CHECK_EQ(bpf_htons(ETH_P_IP), eth.h_proto);
}

MARLIN_TEST(ipip_encap_frame_too_big_returns_before_the_helper)
{
    /*
     * Mirrors ipip_encap_frame_too_big_drops_before_adjust_head
     * (tests/packet/xdp_test.c:1353); the native-only half is that the
     * helper is never reached at all, asserted directly rather than
     * inferred from an unmodified frame.
     */
    struct marlin_ctx mctx;
    struct xdp_md ctx;

    pb_reset();
    pb_pad(IPIP_HEADROOM);
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(1234, 80);

    mctx_init(&mctx, (__u16)(pb_len - IPIP_HEADROOM), 10, AF_INET);
    ipip_arm(&ctx, IPIP_HEADROOM);

    CHECK_RET(MARLIN_DROP_FRAME_TOO_BIG, marlin_ipip_encap_packet(&ctx, &mctx));
    CHECK_EQ(0, xdp_stub_calls());
    CHECK_EQ(-1, xdp_stub_diff_first());
}

MARLIN_TEST(ipip_encap_max_frame_zero_disables_the_check)
{
    /* Mirrors ipip_encap_max_frame_zero_disables_the_check (tests/packet/xdp_test.c:1377). */
    struct marlin_ctx mctx;
    struct xdp_md ctx;

    pb_reset();
    pb_pad(IPIP_HEADROOM);
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_pad(2000); /* well past any real MTU; only max_frame == 0 lets this through */

    mctx_init(&mctx, (__u16)(pb_len - IPIP_HEADROOM), 0, AF_INET);
    ipip_arm(&ctx, IPIP_HEADROOM);

    CHECK_RET(MARLIN_OK, marlin_ipip_encap_packet(&ctx, &mctx));
}

int main(void)
{
    return marlin_tests_main();
}
