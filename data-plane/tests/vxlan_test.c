/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Native unit tests for vxlan.c. This translation unit #includes the source
 * directly, the same as ipip_test.c/gue_test.c; its only helper,
 * bpf_xdp_adjust_head(), is answered by tests/stubs/xdp_stub.h through
 * tests/stubs/bpf/bpf_helpers.h.
 */

#include <stdio.h>
#include <string.h>

#include "packet.h"
#include "harness.h"

#include "../bpf/vxlan.c"

/*
 * Grant the same headroom BPF_PROG_TEST_RUN would (tests/packet/prog.h),
 * except where the boundary itself is under test.
 */
#define VXLAN_HEADROOM XDP_PACKET_HEADROOM

/*
 * Palindromic under bpf_htonl(), like ipip_test.c's IPIP_TUNNEL_SRC and
 * IPIP_BACKEND, so the __be32 fields below can be set with the literal
 * directly.
 */
#define VXLAN_TUNNEL_SRC 0x0d0d0d0dU /* 13.13.13.13 */
#define VXLAN_BACKEND    0x0c0c0c0cU /* 12.12.12.12 */
#define VXLAN_VNI        0x00abcdefU /* arbitrary, within the 24-bit field */

#define V4_SRC 0x01010101U /* 1.1.1.1 -- inner client, arbitrary */
#define V4_DST 0x02020202U /* 2.2.2.2 -- inner VIP, arbitrary */

static const unsigned char SRC6[16] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                                       0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
static const unsigned char DST6[16] = {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
                                       0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30};

/*
 * Distinguishable from each other and from an all-zero MAC, the same
 * reasoning as ipip_test.c's IPIP_BACKEND comment: a zero byte at a
 * checked position would be indistinguishable from an untouched canary.
 */
static const unsigned char ARRIVING_DST[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01}; /* Marlin's own MAC */
static const unsigned char ARRIVING_SRC[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02}; /* the upstream router */
static const unsigned char VXLAN_INNER_MAC[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x04};

/*
 * Zeroed like ipip_test.c's mctx_init: every field vxlan.c reads is set
 * explicitly, so a wrongly-read field shows up as a wrong assertion rather
 * than a coincidental zero. encap_dport stays 0 (the "use default" sentinel)
 * unless a case overrides it directly.
 */
static void mctx_init(struct marlin_ctx *mctx, __u16 pkt_len, __u16 max_frame, __u8 family)
{
    memset(mctx, 0, sizeof(*mctx));
    mctx->pkt_len = pkt_len;
    mctx->cfg.max_frame = max_frame;
    mctx->cfg.tunnel_src = VXLAN_TUNNEL_SRC;
    mctx->backend.addr = VXLAN_BACKEND;
    mctx->backend.vni = VXLAN_VNI;
    memcpy(mctx->backend.inner_mac, VXLAN_INNER_MAC, ETH_ALEN);
    mctx->tuple.family = family;
}

/*
 * Places the xdp_md over the frame packet.h just built inside pb_arena, with
 * `headroom` bytes of room in front for bpf_xdp_adjust_head() to grow into,
 * and arms the stub over exactly that layout. Every case pb_pad()s the
 * headroom before building the frame, so pb_len already accounts for it by
 * the time this runs.
 */
static void vxlan_arm(struct xdp_md *ctx, __u32 headroom)
{
    unsigned char *data = pb_arena + headroom;

    memset(ctx, 0, sizeof(*ctx));
    ctx->data = (__u32)(unsigned long)data;
    ctx->data_end = (__u32)(unsigned long)(pb_arena + pb_len);
    xdp_stub_attach(pb_arena, data, pb_len - headroom);
}

/*
 * pb_eth() writes zero MACs; most cases below don't care about the specific
 * arriving addresses, but vxlan.c reads them, so every case that runs the
 * function past the length/frame_fits guards needs a real Ethernet header.
 * Writes ARRIVING_DST/ARRIVING_SRC over whatever pb_eth() just zeroed.
 */
static void vxlan_set_arriving_addrs(__u32 headroom)
{
    memcpy(pb_arena + headroom, ARRIVING_DST, ETH_ALEN);
    memcpy(pb_arena + headroom + ETH_ALEN, ARRIVING_SRC, ETH_ALEN);
}

/*
 * Reads the outer Ethernet/IPv4/UDP/VXLAN headers and the relocated inner
 * Ethernet header back out of ctx->data after a successful call. Any _out
 * pointer may be NULL when a case does not need that header.
 */
static void vxlan_read_outer(const struct xdp_md *ctx, struct ethhdr *outer_eth_out, struct iphdr *iph_out,
                             struct udphdr *udp_out, struct marlin_vxlan_hdr *vxlan_out, struct ethhdr *inner_eth_out)
{
    unsigned char *data = (unsigned char *)(unsigned long)ctx->data;

    if(outer_eth_out != NULL) {
        memcpy(outer_eth_out, data, sizeof(*outer_eth_out));
    }

    if(iph_out != NULL) {
        memcpy(iph_out, data + ETH_HLEN, sizeof(*iph_out));
    }

    if(udp_out != NULL) {
        memcpy(udp_out, data + ETH_HLEN + sizeof(struct iphdr), sizeof(*udp_out));
    }

    if(vxlan_out != NULL) {
        memcpy(vxlan_out, data + ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr), sizeof(*vxlan_out));
    }

    if(inner_eth_out != NULL) {
        memcpy(inner_eth_out, data + MARLIN_OVERHEAD_VXLAN, sizeof(*inner_eth_out));
    }
}

/*
 * Shared by vxlan_encap_failure_paths_leave_mctx_untouched: every failure
 * return must leave l3_off/pkt_len exactly as the case set them, since
 * vxlan.c writes either field only on the MARLIN_OK path.
 */
static void vxlan_check_failure_leaves_mctx(struct marlin_ctx *mctx, struct xdp_md *ctx, int expect_ret)
{
    __u16 l3_before = mctx->l3_off;
    __u16 pkt_before = mctx->pkt_len;

    CHECK_RET(expect_ret, marlin_vxlan_encap_packet(ctx, mctx));
    CHECK_EQ(l3_before, mctx->l3_off);
    CHECK_EQ(pkt_before, mctx->pkt_len);
}

typedef void (*vxlan_inner_builder)(void);

static void vxlan_inner_ports(void)
{
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(11111, 80);
}

static void vxlan_inner_ext6_ports(void)
{
    pb_ipv6(IPPROTO_HOPOPTS, SRC6, DST6);
    pb_ext6(IPPROTO_TCP, 0);
    pb_ports(11111, 80);
}

static void vxlan_inner_icmp(void)
{
    pb_ipv4(IPPROTO_ICMP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_icmp(8, 0);
}

/*
 * Runs one inner shape through marlin_vxlan_encap_packet() and checks the
 * bytes past the relocated inner Ethernet header are bit-for-bit what was
 * built: vxlan.c writes only the 50-byte outer block plus the inner header's
 * two addresses (vxlan.c), so nothing past that should change regardless of
 * what the payload looks like.
 */
static void vxlan_check_inner_relocated_unchanged(vxlan_inner_builder build, __u8 family)
{
    unsigned char snapshot[64];
    struct marlin_ctx mctx;
    struct xdp_md ctx;
    struct ethhdr inner_eth;
    __be16 proto_before;
    unsigned char *payload;
    __u16 inner_len;

    pb_reset();
    pb_pad(VXLAN_HEADROOM);
    proto_before = (family == AF_INET6) ? bpf_htons(ETH_P_IPV6) : bpf_htons(ETH_P_IP);
    pb_eth((family == AF_INET6) ? ETH_P_IPV6 : ETH_P_IP);
    vxlan_set_arriving_addrs(VXLAN_HEADROOM);
    build();

    inner_len = (__u16)(pb_len - VXLAN_HEADROOM - ETH_HLEN);
    CHECK_TRUE(inner_len <= sizeof(snapshot));
    payload = pb_arena + VXLAN_HEADROOM + ETH_HLEN;
    memcpy(snapshot, payload, inner_len);

    mctx_init(&mctx, (__u16)(pb_len - VXLAN_HEADROOM), 0, family);
    vxlan_arm(&ctx, VXLAN_HEADROOM);

    CHECK_RET(MARLIN_OK, marlin_vxlan_encap_packet(&ctx, &mctx));

    vxlan_read_outer(&ctx, NULL, NULL, NULL, NULL, &inner_eth);
    CHECK_EQ(proto_before, inner_eth.h_proto);

    payload = (unsigned char *)(unsigned long)ctx.data + MARLIN_OVERHEAD_VXLAN + ETH_HLEN;
    CHECK_MEM(snapshot, payload, inner_len);
}

/* ---- no packet-tier counterpart: mctx write-back, NULL guards, the
 * length/headroom boundaries, and bookkeeping the emitted frame alone
 * cannot show (docs/design/24-testing.md) --------------------------------
 */

MARLIN_TEST(vxlan_encap_null_ctx_is_nullref)
{
    struct marlin_ctx mctx;

    memset(&mctx, 0, sizeof(mctx));
    xdp_stub_reset();

    CHECK_RET(MARLIN_ABORT_NULLREF, marlin_vxlan_encap_packet(NULL, &mctx));
    CHECK_EQ(0, xdp_stub_calls());
}

MARLIN_TEST(vxlan_encap_null_mctx_is_nullref)
{
    struct xdp_md ctx;
    __u32 data_before;

    pb_reset();
    pb_pad(VXLAN_HEADROOM);
    pb_eth(ETH_P_IP);
    vxlan_arm(&ctx, VXLAN_HEADROOM);
    data_before = ctx.data;

    CHECK_RET(MARLIN_ABORT_NULLREF, marlin_vxlan_encap_packet(&ctx, NULL));
    CHECK_EQ(data_before, ctx.data);
    CHECK_EQ(0, xdp_stub_calls());
}

MARLIN_TEST(vxlan_encap_pkt_len_below_eth_hlen_is_encap_length)
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
    pb_pad(VXLAN_HEADROOM);
    pb_pad(ETH_HLEN - 1);

    mctx_init(&mctx, ETH_HLEN - 1, 0, AF_INET);
    vxlan_arm(&ctx, VXLAN_HEADROOM);

    CHECK_RET(MARLIN_DROP_ENCAP_LENGTH, marlin_vxlan_encap_packet(&ctx, &mctx));
    CHECK_EQ(0, xdp_stub_calls());
    CHECK_EQ(-1, xdp_stub_diff_first());
}

MARLIN_TEST(vxlan_encap_data_end_shorter_than_eth_hlen_before_adjust_head_is_parse_error)
{
    /*
     * Unlike ipip.c/gue.c, vxlan.c must dereference the arriving Ethernet
     * header *before* calling bpf_xdp_adjust_head() (docs/design/
     * 14-forwarding-modes.md SS7.4), so a pkt_len/data_end mismatch here is
     * caught before the helper ever runs, not after -- there is no reachable
     * "post-adjust recheck fires but the pre-check didn't" scenario for this
     * mode: adjust_head never moves data_end, so once the pre-check
     * guarantees data_end - data >= ETH_HLEN, a successful call always
     * leaves at least MARLIN_OVERHEAD_VXLAN + ETH_HLEN bytes behind it.
     * Unreachable from the real datapath for the same reason ipip_test.c's
     * counterpart is (bpf_prog_test_run_opts requires ctx->data_end to equal
     * data_size_in exactly); defence-in-depth against a future producer of
     * pkt_len that is not the frame length.
     */
    struct marlin_ctx mctx;
    struct xdp_md ctx;

    pb_reset();
    pb_pad(VXLAN_HEADROOM);
    pb_eth(ETH_P_IP);
    pb_truncate(VXLAN_HEADROOM + 10); /* real frame far shorter than the pkt_len claimed below */

    mctx_init(&mctx, ETH_HLEN, 0, AF_INET); /* claims 14 bytes; only 10 are real */
    vxlan_arm(&ctx, VXLAN_HEADROOM);

    CHECK_RET(MARLIN_DROP_PARSE_ERROR, marlin_vxlan_encap_packet(&ctx, &mctx));
    CHECK_EQ(0, xdp_stub_calls());
    CHECK_EQ(-1, xdp_stub_diff_first());
    CHECK_EQ(0, mctx.l3_off);
    CHECK_EQ(ETH_HLEN, mctx.pkt_len);
}

MARLIN_TEST(vxlan_encap_pkt_len_exactly_eth_hlen_encapsulates_an_empty_payload)
{
    struct marlin_ctx mctx;
    struct xdp_md ctx;
    struct iphdr iph;
    struct udphdr udp;
    struct marlin_vxlan_hdr vxlan;

    pb_reset();
    pb_pad(VXLAN_HEADROOM);
    pb_eth(ETH_P_IP);
    vxlan_set_arriving_addrs(VXLAN_HEADROOM);

    mctx_init(&mctx, ETH_HLEN, 0, AF_INET);
    vxlan_arm(&ctx, VXLAN_HEADROOM);

    CHECK_RET(MARLIN_OK, marlin_vxlan_encap_packet(&ctx, &mctx));
    CHECK_EQ(ETH_HLEN, mctx.l3_off);
    CHECK_EQ(ETH_HLEN + MARLIN_OVERHEAD_VXLAN, mctx.pkt_len);

    vxlan_read_outer(&ctx, NULL, &iph, &udp, &vxlan, NULL);
    CHECK_EQ(bpf_htons(MARLIN_OVERHEAD_VXLAN), iph.tot_len);
    CHECK_EQ(bpf_htons((__u16)(MARLIN_UDP_HLEN + sizeof(vxlan) + ETH_HLEN)), udp.len);
}

MARLIN_TEST(vxlan_encap_headroom_exactly_the_overhead_passes_and_one_byte_short_drops)
{
    struct marlin_ctx mctx;
    struct xdp_md ctx;

    pb_reset();
    pb_pad(MARLIN_OVERHEAD_VXLAN);
    pb_eth(ETH_P_IP);
    vxlan_set_arriving_addrs(MARLIN_OVERHEAD_VXLAN);
    mctx_init(&mctx, ETH_HLEN, 0, AF_INET);
    vxlan_arm(&ctx, MARLIN_OVERHEAD_VXLAN);

    CHECK_RET(MARLIN_OK, marlin_vxlan_encap_packet(&ctx, &mctx));
    CHECK_EQ(1, xdp_stub_calls());

    pb_reset();
    pb_pad(MARLIN_OVERHEAD_VXLAN - 1);
    pb_eth(ETH_P_IP);
    vxlan_set_arriving_addrs(MARLIN_OVERHEAD_VXLAN - 1);
    mctx_init(&mctx, ETH_HLEN, 0, AF_INET);
    vxlan_arm(&ctx, MARLIN_OVERHEAD_VXLAN - 1);

    CHECK_RET(MARLIN_DROP_ADJUST_HEAD, marlin_vxlan_encap_packet(&ctx, &mctx));
    CHECK_EQ(1, xdp_stub_calls());
    CHECK_EQ(-MARLIN_OVERHEAD_VXLAN, xdp_stub_last_delta());
    CHECK_EQ(-1, xdp_stub_diff_first());
    CHECK_EQ(0, mctx.l3_off);
    CHECK_EQ(ETH_HLEN, mctx.pkt_len);
}

MARLIN_TEST(vxlan_encap_writes_back_l3_off_and_pkt_len_and_touches_no_other_field)
{
    struct marlin_ctx before, after;
    struct xdp_md ctx;
    __u16 inner_len;

    pb_reset();
    pb_pad(VXLAN_HEADROOM);
    pb_eth(ETH_P_IP);
    vxlan_set_arriving_addrs(VXLAN_HEADROOM);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(1234, 80);

    mctx_init(&before, (__u16)(pb_len - VXLAN_HEADROOM), 0, AF_INET);
    vxlan_arm(&ctx, VXLAN_HEADROOM);

    after = before;
    inner_len = (__u16)(before.pkt_len - ETH_HLEN);

    CHECK_RET(MARLIN_OK, marlin_vxlan_encap_packet(&ctx, &after));

    before.l3_off = ETH_HLEN;
    before.pkt_len = (__u16)(ETH_HLEN + MARLIN_OVERHEAD_VXLAN + inner_len);

    CHECK_MEM(&before, &after, sizeof(before));
}

MARLIN_TEST(vxlan_encap_failure_paths_leave_mctx_untouched)
{
    struct marlin_ctx mctx;
    struct xdp_md ctx;

    /* MARLIN_ABORT_NULLREF; a NULL mctx has nothing left to check untouched. */
    pb_reset();
    pb_pad(VXLAN_HEADROOM);
    pb_eth(ETH_P_IP);
    mctx_init(&mctx, ETH_HLEN, 0, AF_INET);
    mctx.l3_off = 0xBEEF;
    vxlan_check_failure_leaves_mctx(&mctx, NULL, MARLIN_ABORT_NULLREF);

    /* MARLIN_DROP_ENCAP_LENGTH */
    pb_reset();
    pb_pad(VXLAN_HEADROOM);
    pb_pad(ETH_HLEN - 1);
    mctx_init(&mctx, ETH_HLEN - 1, 0, AF_INET);
    mctx.l3_off = 0xBEEF;
    vxlan_arm(&ctx, VXLAN_HEADROOM);
    vxlan_check_failure_leaves_mctx(&mctx, &ctx, MARLIN_DROP_ENCAP_LENGTH);

    /* MARLIN_DROP_FRAME_TOO_BIG */
    pb_reset();
    pb_pad(VXLAN_HEADROOM);
    pb_eth(ETH_P_IP);
    mctx_init(&mctx, ETH_HLEN, 10, AF_INET);
    mctx.l3_off = 0xBEEF;
    vxlan_arm(&ctx, VXLAN_HEADROOM);
    vxlan_check_failure_leaves_mctx(&mctx, &ctx, MARLIN_DROP_FRAME_TOO_BIG);

    /* MARLIN_DROP_PARSE_ERROR: real bytes shorter than ETH_HLEN before adjust_head */
    pb_reset();
    pb_pad(VXLAN_HEADROOM);
    pb_truncate(VXLAN_HEADROOM + 10);
    mctx_init(&mctx, ETH_HLEN, 0, AF_INET);
    mctx.l3_off = 0xBEEF;
    vxlan_arm(&ctx, VXLAN_HEADROOM);
    vxlan_check_failure_leaves_mctx(&mctx, &ctx, MARLIN_DROP_PARSE_ERROR);

    /* MARLIN_DROP_ADJUST_HEAD */
    pb_reset();
    pb_pad(MARLIN_OVERHEAD_VXLAN - 1);
    pb_eth(ETH_P_IP);
    vxlan_set_arriving_addrs(MARLIN_OVERHEAD_VXLAN - 1);
    mctx_init(&mctx, ETH_HLEN, 0, AF_INET);
    mctx.l3_off = 0xBEEF;
    vxlan_arm(&ctx, MARLIN_OVERHEAD_VXLAN - 1);
    vxlan_check_failure_leaves_mctx(&mctx, &ctx, MARLIN_DROP_ADJUST_HEAD);
}

MARLIN_TEST(vxlan_encap_writes_exactly_the_outer_block_plus_two_inner_mac_fields)
{
    /*
     * Unlike ipip.c/gue.c, the write does not extend across the whole
     * relocated inner header: only h_dest/h_source (2*ETH_ALEN bytes) are
     * corrected, and h_proto -- already in place, untouched -- is the last
     * ETH_HLEN - 2*ETH_ALEN bytes of it.
     */
    struct marlin_ctx mctx;
    struct xdp_md ctx;

    pb_reset();
    pb_pad(VXLAN_HEADROOM);
    pb_eth(ETH_P_IP);
    vxlan_set_arriving_addrs(VXLAN_HEADROOM);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(1234, 80);

    mctx_init(&mctx, (__u16)(pb_len - VXLAN_HEADROOM), 0, AF_INET);
    vxlan_arm(&ctx, VXLAN_HEADROOM);

    CHECK_RET(MARLIN_OK, marlin_vxlan_encap_packet(&ctx, &mctx));

    CHECK_EQ((int)VXLAN_HEADROOM - MARLIN_OVERHEAD_VXLAN, xdp_stub_diff_first());
    CHECK_EQ((int)VXLAN_HEADROOM + 2 * ETH_ALEN - 1, xdp_stub_diff_last());
}

MARLIN_TEST(vxlan_encap_calls_adjust_head_once_and_leaves_data_end_alone)
{
    struct marlin_ctx mctx;
    struct xdp_md ctx;
    __u32 data_before, data_end_before;

    pb_reset();
    pb_pad(VXLAN_HEADROOM);
    pb_eth(ETH_P_IP);
    vxlan_set_arriving_addrs(VXLAN_HEADROOM);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(1234, 80);

    mctx_init(&mctx, (__u16)(pb_len - VXLAN_HEADROOM), 0, AF_INET);
    vxlan_arm(&ctx, VXLAN_HEADROOM);
    data_before = ctx.data;
    data_end_before = ctx.data_end;

    CHECK_RET(MARLIN_OK, marlin_vxlan_encap_packet(&ctx, &mctx));

    CHECK_EQ(1, xdp_stub_calls());
    CHECK_EQ(-MARLIN_OVERHEAD_VXLAN, xdp_stub_last_delta());
    CHECK_EQ(data_before - MARLIN_OVERHEAD_VXLAN, ctx.data);
    CHECK_EQ(data_end_before, ctx.data_end);
}

MARLIN_TEST(vxlan_encap_pkt_len_at_the_u16_ceiling_does_not_wrap)
{
    /*
     * pkt_len is decoupled from the real frame on purpose here -- the
     * arithmetic in question depends only on the __u16 value, not on how
     * many bytes actually exist, mirroring
     * ipip_test.c's ipip_encap_pkt_len_at_the_u16_ceiling_does_not_wrap.
     */
    __u16 huge_pkt_len = (__u16)(0xffffU - MARLIN_OVERHEAD_VXLAN); /* 65485 */
    struct marlin_ctx mctx;
    struct xdp_md ctx;
    struct iphdr iph;

    pb_reset();
    pb_pad(VXLAN_HEADROOM);
    pb_eth(ETH_P_IP);
    vxlan_set_arriving_addrs(VXLAN_HEADROOM);

    mctx_init(&mctx, huge_pkt_len, 0, AF_INET);
    vxlan_arm(&ctx, VXLAN_HEADROOM);

    CHECK_RET(MARLIN_OK, marlin_vxlan_encap_packet(&ctx, &mctx));
    vxlan_read_outer(&ctx, NULL, &iph, NULL, NULL, NULL);
    CHECK_EQ(bpf_htons((__u16)(0xffffU - ETH_HLEN)), iph.tot_len);
    CHECK_EQ(0xffffU, mctx.pkt_len);
}

MARLIN_TEST(vxlan_encap_relocates_any_inner_payload_unchanged)
{
    vxlan_check_inner_relocated_unchanged(vxlan_inner_ports, AF_INET);
    vxlan_check_inner_relocated_unchanged(vxlan_inner_ext6_ports, AF_INET6);
    vxlan_check_inner_relocated_unchanged(vxlan_inner_icmp, AF_INET);
}

MARLIN_TEST(vxlan_encap_dest_port_defaults_and_honours_configured_encap_dport)
{
    struct marlin_ctx mctx;
    struct xdp_md ctx;
    struct udphdr udp;

    pb_reset();
    pb_pad(VXLAN_HEADROOM);
    pb_eth(ETH_P_IP);
    vxlan_set_arriving_addrs(VXLAN_HEADROOM);
    mctx_init(&mctx, ETH_HLEN, 0, AF_INET);
    vxlan_arm(&ctx, VXLAN_HEADROOM);

    CHECK_RET(MARLIN_OK, marlin_vxlan_encap_packet(&ctx, &mctx));
    vxlan_read_outer(&ctx, NULL, NULL, &udp, NULL, NULL);
    CHECK_EQ(bpf_htons(MARLIN_VXLAN_DPORT_DEFAULT), udp.dest);

    pb_reset();
    pb_pad(VXLAN_HEADROOM);
    pb_eth(ETH_P_IP);
    vxlan_set_arriving_addrs(VXLAN_HEADROOM);
    mctx_init(&mctx, ETH_HLEN, 0, AF_INET);
    mctx.backend.encap_dport = bpf_htons(7777);
    vxlan_arm(&ctx, VXLAN_HEADROOM);

    CHECK_RET(MARLIN_OK, marlin_vxlan_encap_packet(&ctx, &mctx));
    vxlan_read_outer(&ctx, NULL, NULL, &udp, NULL, NULL);
    CHECK_EQ(bpf_htons(7777), udp.dest);
}

/* ---- mirrors a packet-tier assertion, each naming its counterpart
 * (docs/design/24-testing.md's discipline rule) -------------------------
 */

MARLIN_TEST(vxlan_encap_builds_the_outer_and_inner_headers_byte_for_byte)
{
    /*
     * Mirrors vxlan_encap_zero_lookup_writes_outer_and_inner_ethernet_headers
     * (tests/packet/xdp_test.c). This is vxlan.c's central hazard
     * (docs/design/14-forwarding-modes.md SS7.4): the outer Ethernet header
     * is built from the *saved* arriving addresses, not by relocating and
     * swapping the arriving header the way nexthop.c's default does for
     * IPIP/GUE. The entropy source port is checked by calling
     * marlin_entropy_sport() directly -- entropy_test.c independently
     * verifies that function's algorithm; this test verifies only that
     * vxlan.c wires its result into udp.source.
     */
    struct marlin_ctx mctx;
    struct xdp_md ctx;
    struct ethhdr outer_eth, inner_eth;
    struct iphdr iph, expect_iph;
    struct udphdr udp, expect_udp;
    struct marlin_vxlan_hdr vxlan, expect_vxlan;
    __u16 inner_len;

    pb_reset();
    pb_pad(VXLAN_HEADROOM);
    pb_eth(ETH_P_IP);
    vxlan_set_arriving_addrs(VXLAN_HEADROOM);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(1234, 80);

    inner_len = (__u16)(pb_len - VXLAN_HEADROOM - ETH_HLEN);

    mctx_init(&mctx, (__u16)(pb_len - VXLAN_HEADROOM), 0, AF_INET);
    vxlan_arm(&ctx, VXLAN_HEADROOM);

    CHECK_RET(MARLIN_OK, marlin_vxlan_encap_packet(&ctx, &mctx));

    vxlan_read_outer(&ctx, &outer_eth, &iph, &udp, &vxlan, &inner_eth);

    /* outer: dst the arriving source (router), src the arriving destination (Marlin) */
    CHECK_MEM(ARRIVING_SRC, outer_eth.h_dest, ETH_ALEN);
    CHECK_MEM(ARRIVING_DST, outer_eth.h_source, ETH_ALEN);
    CHECK_EQ(bpf_htons(ETH_P_IP), outer_eth.h_proto);

    memset(&expect_iph, 0, sizeof(expect_iph));
    expect_iph.version = 4;
    expect_iph.ihl = MARLIN_IPV4_IHL_MIN;
    expect_iph.frag_off = bpf_htons(IP_DF);
    expect_iph.ttl = MARLIN_OUTER_TTL;
    expect_iph.protocol = IPPROTO_UDP;
    expect_iph.tot_len = bpf_htons((__u16)(MARLIN_OVERHEAD_VXLAN + inner_len));
    expect_iph.saddr = VXLAN_TUNNEL_SRC;
    expect_iph.daddr = VXLAN_BACKEND;
    expect_iph.check = marlin_ipv4_csum(&expect_iph);
    CHECK_MEM(&expect_iph, &iph, sizeof(expect_iph));

    memset(&expect_udp, 0, sizeof(expect_udp));
    expect_udp.source = marlin_entropy_sport(&mctx.tuple);
    expect_udp.dest = bpf_htons(MARLIN_VXLAN_DPORT_DEFAULT);
    expect_udp.len = bpf_htons((__u16)(MARLIN_UDP_HLEN + sizeof(expect_vxlan) + ETH_HLEN + inner_len));
    expect_udp.check = 0;
    CHECK_MEM(&expect_udp, &udp, sizeof(expect_udp));

    memset(&expect_vxlan, 0, sizeof(expect_vxlan));
    expect_vxlan.flags = MARLIN_VXLAN_FLAG_VNI;
    expect_vxlan.vni_and_reserved = bpf_htonl(VXLAN_VNI << 8);
    CHECK_MEM(&expect_vxlan, &vxlan, sizeof(expect_vxlan));

    /* inner: dst backend.inner_mac (the overlay address), src Marlin's own MAC, proto untouched */
    CHECK_MEM(VXLAN_INNER_MAC, inner_eth.h_dest, ETH_ALEN);
    CHECK_MEM(ARRIVING_DST, inner_eth.h_source, ETH_ALEN);
    CHECK_EQ(bpf_htons(ETH_P_IP), inner_eth.h_proto);
}

MARLIN_TEST(vxlan_encap_vni_occupies_the_high_three_bytes_and_reserved_byte_stays_zero)
{
    static const __u32 vnis[] = {0x00000000U, 0x00000001U, 0x00abcdefU, 0x00ffffffU};
    struct marlin_ctx mctx;
    struct xdp_md ctx;
    struct marlin_vxlan_hdr vxlan;
    unsigned int i;

    for(i = 0; i < sizeof(vnis) / sizeof(vnis[0]); i++) {
        pb_reset();
        pb_pad(VXLAN_HEADROOM);
        pb_eth(ETH_P_IP);
        vxlan_set_arriving_addrs(VXLAN_HEADROOM);
        mctx_init(&mctx, ETH_HLEN, 0, AF_INET);
        mctx.backend.vni = vnis[i];
        vxlan_arm(&ctx, VXLAN_HEADROOM);

        CHECK_RET(MARLIN_OK, marlin_vxlan_encap_packet(&ctx, &mctx));
        vxlan_read_outer(&ctx, NULL, NULL, NULL, &vxlan, NULL);
        CHECK_EQ(MARLIN_VXLAN_FLAG_VNI, vxlan.flags);
        CHECK_EQ(0, vxlan.reserved0[0] | vxlan.reserved0[1] | vxlan.reserved0[2]);
        CHECK_EQ(bpf_htonl(vnis[i] << 8), vxlan.vni_and_reserved);
    }
}

MARLIN_TEST(vxlan_encap_frame_too_big_returns_before_the_helper)
{
    /*
     * Mirrors vxlan_encap_frame_too_big_drops_before_adjust_head
     * (tests/packet/xdp_test.c); the native-only half is that the helper is
     * never reached at all, asserted directly rather than inferred from an
     * unmodified frame.
     */
    struct marlin_ctx mctx;
    struct xdp_md ctx;

    pb_reset();
    pb_pad(VXLAN_HEADROOM);
    pb_eth(ETH_P_IP);
    vxlan_set_arriving_addrs(VXLAN_HEADROOM);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(1234, 80);

    mctx_init(&mctx, (__u16)(pb_len - VXLAN_HEADROOM), 10, AF_INET);
    vxlan_arm(&ctx, VXLAN_HEADROOM);

    CHECK_RET(MARLIN_DROP_FRAME_TOO_BIG, marlin_vxlan_encap_packet(&ctx, &mctx));
    CHECK_EQ(0, xdp_stub_calls());
    CHECK_EQ(-1, xdp_stub_diff_first());
}

MARLIN_TEST(vxlan_encap_max_frame_zero_disables_the_check)
{
    /* Mirrors vxlan_encap_max_frame_zero_disables_the_check (tests/packet/xdp_test.c). */
    struct marlin_ctx mctx;
    struct xdp_md ctx;

    pb_reset();
    pb_pad(VXLAN_HEADROOM);
    pb_eth(ETH_P_IP);
    vxlan_set_arriving_addrs(VXLAN_HEADROOM);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_pad(2000); /* well past any real MTU; only max_frame == 0 lets this through */

    mctx_init(&mctx, (__u16)(pb_len - VXLAN_HEADROOM), 0, AF_INET);
    vxlan_arm(&ctx, VXLAN_HEADROOM);

    CHECK_RET(MARLIN_OK, marlin_vxlan_encap_packet(&ctx, &mctx));
}

int main(void)
{
    return marlin_tests_main();
}
