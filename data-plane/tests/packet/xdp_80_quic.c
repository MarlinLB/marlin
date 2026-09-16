/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * QUIC connection-ID steering (docs/design/30-quic.md): valid/forged CIDs,
 * every fallback-to-hash path (bad check, generation bits, long header,
 * missing flag, length bounds, truncation, decoded backend
 * zero/out-of-range/down), fragments, ICMP errors, migration, and IPv6.
 * Reuses bal_setup()/the VIP fixture from xdp_fixture.h and sip_hash64()
 * from xdp_siphash.h to forge connection IDs the same way balancer.c
 * decodes them.
 */

#include <string.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>

#include <marlin/abi/types.h>
#include <marlin/marlin.h>
#include <marlin/proto.h>

#include "../harness.h"
#include "../packet.h"
#include "maps.h"
#include "prog.h"
#include "xdp_fixture.h"
#include "xdp_siphash.h"

#define QUIC_VIP_NUM  3U
#define QUIC_VIP_PORT 443U
#define QUIC_CID_LEN  8U

/* Short header: MARLIN_QUIC_LONG_HEADER clear, fixed bit set (RFC 9000 SS17.3). */
#define QUIC_SHORT_FORM ((__u8)0x40)

/*
 * hash_5tuple and striped give the QUIC cases control over the fallback hash
 * path's own behaviour: a fragment case needs VIP_HASH_5TUPLE clear so
 * marlin_balancer_frag() does not drop before backend selection ever runs,
 * and a migration case needs the fwd_table block striped so a fallback to
 * hash is observable at all. Every other case keeps the original uniform,
 * 5-tuple-flagged fixture, where the hash path answers with NH_BACKEND_ID for
 * every row, so a packet that comes out on ALT_BACKEND_MAC can only have been
 * steered.
 */
static void quic_vip_seed(__u32 cid_len, __u32 extra_flags, int hash_5tuple, int striped)
{
    bal_setup();
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    backend_seed_l2dsr(ALT_BACKEND_ID, ALT_BACKEND_MAC);
    vip_seed4(V4_DST, QUIC_VIP_PORT, IPPROTO_UDP, QUIC_VIP_NUM,
              (hash_5tuple ? VIP_HASH_5TUPLE : 0U) | extra_flags | ((cid_len << VIP_QUIC_CID_LEN_SHIFT) & VIP_QUIC_CID_LEN_MASK));

    if(striped) {
        xdp_fwd_fill_striped(QUIC_VIP_NUM, NH_BACKEND_ID, ALT_BACKEND_ID);
    } else {
        xdp_fwd_fill(QUIC_VIP_NUM, NH_BACKEND_ID);
    }
}

static void quic_vip_clear(void)
{
    struct vip_key key;

    vip_key4(&key, V4_DST, QUIC_VIP_PORT, IPPROTO_UDP);
    xdp_vip_del(&key);
    xdp_fwd_clear(QUIC_VIP_NUM);
    xdp_backend_clear(NH_BACKEND_ID);
    xdp_backend_clear(ALT_BACKEND_ID);
}

/*
 * Reproduces the decoder's arithmetic, not its struct layout: the hash input is
 * struct marlin_quic_input straight from proto.h, so a field moving there
 * breaks this as loudly as it breaks balancer.c.
 */
static void quic_forge_cid(__u8 *cid, __u32 cid_len, __u32 backend_id)
{
    struct marlin_quic_input in;
    struct vip_meta meta;
    __u32 i, ent_len, obfuscated;
    __u64 mask;

    ent_len = cid_len - MARLIN_QUIC_CID_ENTROPY_OFF;

    for(i = 0; i < ent_len; i++) {
        cid[MARLIN_QUIC_CID_ENTROPY_OFF + i] = (__u8)(0xa0U + i);
    }

    memset(&in, 0, sizeof(in));
    in.domain = MARLIN_QUIC_SIPHASH_DOMAIN;
    memcpy(in.entropy, cid + MARLIN_QUIC_CID_ENTROPY_OFF, ent_len);

    vip_meta_init(&meta, QUIC_VIP_NUM, 0);
    mask = sip_hash64(&in, sizeof(in), meta.hash_key);

    obfuscated = backend_id ^ (__u32)(mask & 0xffffU);

    cid[0] = (__u8)((mask >> 16) & MARLIN_QUIC_CID_CHECK_MASK);
    cid[1] = (__u8)((obfuscated >> 8) & 0xffU);
    cid[2] = (__u8)(obfuscated & 0xffU);
}

/*
 * pb_udp rather than pb_ports: the decoder reads the connection ID at
 * l4_off + MARLIN_UDP_HLEN + 1, so the full eight-byte UDP header has to be on
 * the wire for those offsets to line up. src is a parameter, not always
 * V4_SRC, so a migration case can vary it while the destination and
 * connection ID stay fixed. declared_len is independent of cid_len -- every
 * other case wants them consistent (what quic_build_frame() below gives),
 * but the declared-length bound needs to put more, or fewer, bytes on the
 * wire than the datagram claims to hold.
 */
static void quic_build_frame_declared_len(__be32 src, __u8 form_byte, const __u8 *cid, __u32 cid_len, __u16 declared_len)
{
    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_UDP, MARLIN_IPV4_IHL_MIN, 0, src, V4_DST);
    pb_udp(33333, (__u16)QUIC_VIP_PORT, declared_len);
    pb_quic_cid(form_byte, cid, cid_len);
}

static void quic_build_frame(__be32 src, __u8 form_byte, const __u8 *cid, __u32 cid_len)
{
    quic_build_frame_declared_len(src, form_byte, cid, cid_len, (__u16)(MARLIN_UDP_HLEN + 1 + cid_len));
}

/*
 * Sweeps source address against a forged CID's fallback hash selection,
 * mirroring bal_sport_moves_selection()'s "does it ever differ" construction
 * above: 1 if the emitted destination MAC ever changed, 0 if it never did, -1
 * if a packet did not forward at all.
 */
static int quic_src_sweep_dmac_changes(const __u8 *cid, __u32 cid_len, __u16 count)
{
    unsigned char first[ETH_ALEN] = {0};
    struct xdp_run_result result;
    __u16 i;

    for(i = 0; i < count; i++) {
        quic_build_frame(ACL_ADDR4(10, 70, 80, (__u8)i), QUIC_SHORT_FORM, cid, cid_len);
        result = run_current_packet();

        if(result.err != 0 || result.retval != XDP_TX) {
            return -1;
        }

        if(i == 0) {
            memcpy(first, out_buf, ETH_ALEN);
        } else if(memcmp(first, out_buf, ETH_ALEN) != 0) {
            return 1;
        }
    }

    return 0;
}

MARLIN_TEST(quic_valid_cid_routes_to_encoded_backend)
{
    __u64 routed_before;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;

    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 1, 0);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    quic_forge_cid(cid, QUIC_CID_LEN, ALT_BACKEND_ID);
    quic_build_frame(V4_SRC, QUIC_SHORT_FORM, cid, QUIC_CID_LEN);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(ALT_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(routed_before + 1, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(quic_bad_check_falls_back_to_hash)
{
    __u64 failed_before, routed_before;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;

    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    quic_forge_cid(cid, QUIC_CID_LEN, ALT_BACKEND_ID);
    cid[0] ^= 0x01; /* one check bit; the generation bits stay clear */
    quic_build_frame(V4_SRC, QUIC_SHORT_FORM, cid, QUIC_CID_LEN);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(failed_before + 1, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(quic_nonzero_generation_bits_fall_back_to_hash)
{
    __u64 failed_before, routed_before;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;

    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    quic_forge_cid(cid, QUIC_CID_LEN, ALT_BACKEND_ID);
    cid[0] |= MARLIN_QUIC_CID_GEN_MASK; /* an ID this instance did not issue */
    quic_build_frame(V4_SRC, QUIC_SHORT_FORM, cid, QUIC_CID_LEN);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(failed_before + 1, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(quic_long_header_is_not_steered)
{
    __u64 failed_before, routed_before;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;

    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    quic_forge_cid(cid, QUIC_CID_LEN, ALT_BACKEND_ID);
    quic_build_frame(V4_SRC, (__u8)(QUIC_SHORT_FORM | MARLIN_QUIC_LONG_HEADER), cid, QUIC_CID_LEN);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    /* The decoder never ran, so neither of its counters moved. */
    CHECK_EQ(failed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(quic_without_vip_quic_flag_is_not_steered)
{
    __u64 failed_before, routed_before;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;

    quic_vip_seed(QUIC_CID_LEN, 0, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    quic_forge_cid(cid, QUIC_CID_LEN, ALT_BACKEND_ID);
    quic_build_frame(V4_SRC, QUIC_SHORT_FORM, cid, QUIC_CID_LEN);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(failed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(quic_cid_len_out_of_range_falls_back_to_hash)
{
    __u64 failed_before, routed_before;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;

    quic_vip_seed(MARLIN_QUIC_CID_MIN - 1, VIP_QUIC, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    quic_forge_cid(cid, QUIC_CID_LEN, ALT_BACKEND_ID);
    quic_build_frame(V4_SRC, QUIC_SHORT_FORM, cid, QUIC_CID_LEN);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    /* Refused before the format byte is read, so nothing is counted. */
    CHECK_EQ(failed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(quic_cid_len_above_max_falls_back_to_hash)
{
    /*
     * 21..31 fit VIP_QUIC_CID_LEN's 5-bit field but exceed MARLIN_QUIC_CID_MAX
     * (20, RFC 9000 SS17.2) -- the upper-bound sibling of the MIN-1 case above.
     */
    __u64 failed_before, routed_before;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;

    quic_vip_seed(MARLIN_QUIC_CID_MAX + 1, VIP_QUIC, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    quic_forge_cid(cid, QUIC_CID_LEN, ALT_BACKEND_ID);
    quic_build_frame(V4_SRC, QUIC_SHORT_FORM, cid, QUIC_CID_LEN);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    /* Refused before the format byte is read, so nothing is counted. */
    CHECK_EQ(failed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(quic_truncated_format_byte_falls_back_to_hash)
{
    __u64 failed_before, routed_before;
    struct xdp_run_result result;

    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_UDP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_udp(33333, (__u16)QUIC_VIP_PORT, (__u16)(MARLIN_UDP_HLEN + 1));
    /* The form byte only: nothing follows it for the decoder's 3-byte load at off. */
    pb_quic_form(QUIC_SHORT_FORM);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(failed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(quic_truncated_entropy_falls_back_to_hash)
{
    __u64 failed_before, routed_before;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;

    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    /*
     * The check/id header only; on the wire below, just 2 of the 5 entropy
     * bytes an 8-byte CID's decode expects actually follow.
     */
    quic_forge_cid(cid, QUIC_CID_LEN, ALT_BACKEND_ID);

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_UDP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_udp(33333, (__u16)QUIC_VIP_PORT, (__u16)(MARLIN_UDP_HLEN + 1 + MARLIN_QUIC_CID_ENTROPY_OFF + 2));
    pb_quic_cid(QUIC_SHORT_FORM, cid, MARLIN_QUIC_CID_ENTROPY_OFF + 2);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(failed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

/*
 * A fully valid forged connection ID sits on the wire, but the UDP header
 * declares only the form byte -- the decoder must bound itself against
 * mctx->udp_payload_len (parser.c), not against bpf_xdp_load_bytes()'s
 * frame-extent check, or these physically-present bytes steer the packet.
 */
MARLIN_TEST(quic_cid_past_declared_udp_len_falls_back_to_hash)
{
    __u64 failed_before, routed_before;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;

    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    quic_forge_cid(cid, QUIC_CID_LEN, ALT_BACKEND_ID);
    quic_build_frame_declared_len(V4_SRC, QUIC_SHORT_FORM, cid, QUIC_CID_LEN, (__u16)(MARLIN_UDP_HLEN + 1));

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(failed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

/*
 * The declared length covers the form byte and part of the connection ID,
 * not all of it -- the sibling of the truncated-entropy case above, but
 * where the missing bytes are physically present on the wire rather than
 * absent from the frame. Same bound, different reason it needs proving.
 */
MARLIN_TEST(quic_partial_cid_in_declared_udp_len_falls_back_to_hash)
{
    __u64 failed_before, routed_before;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;

    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    quic_forge_cid(cid, QUIC_CID_LEN, ALT_BACKEND_ID);
    quic_build_frame_declared_len(V4_SRC, QUIC_SHORT_FORM, cid, QUIC_CID_LEN, (__u16)(MARLIN_UDP_HLEN + QUIC_CID_LEN));

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(failed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

/*
 * A valid forged CID physically follows a UDP header declaring zero
 * payload bytes -- the end-to-end proof that the parser's flag (never set,
 * docs/design/30-quic.md) and the decoder's own length gate compose: either
 * bound alone would already stop this packet, but this is what proves
 * neither is silently relying on the other.
 */
MARLIN_TEST(quic_header_only_declared_udp_len_falls_back_to_hash)
{
    __u64 failed_before, routed_before;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;

    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    quic_forge_cid(cid, QUIC_CID_LEN, ALT_BACKEND_ID);
    quic_build_frame_declared_len(V4_SRC, QUIC_SHORT_FORM, cid, QUIC_CID_LEN, (__u16)MARLIN_UDP_HLEN);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(failed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

/*
 * The Ethernet-minimum-padding shape: a header-only UDP datagram whose
 * trailing zero bytes read as an all-zero connection ID if either bound is
 * missing. Zero bytes clear MARLIN_QUIC_CID_GEN_MASK, so a decoder reached
 * by mistake runs all the way to the check field instead of bailing out
 * early -- this is the case that would inflate quic_cid_check_failed on
 * ordinary padded traffic rather than merely mis-steering it.
 */
MARLIN_TEST(quic_padded_non_quic_udp_does_not_count_check_failed)
{
    __u64 failed_before, routed_before;
    struct xdp_run_result result;

    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_UDP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_udp(33333, (__u16)QUIC_VIP_PORT, MARLIN_UDP_HLEN); /* declares no payload */
    pb_pad(QUIC_CID_LEN + 1);                             /* Ethernet-minimum-padding shape: zero bytes */

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(failed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(quic_backend_id_zero_falls_back_to_hash)
{
    __u64 failed_before, routed_before;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;

    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    quic_forge_cid(cid, QUIC_CID_LEN, 0); /* backend_id 0: fwd_table's own empty-slot sentinel */
    quic_build_frame(V4_SRC, QUIC_SHORT_FORM, cid, QUIC_CID_LEN);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    /* A valid check byte naming an id the decoder itself refuses: never
     * counted, never a backends[0] read.
     */
    CHECK_EQ(failed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(quic_backend_id_out_of_range_falls_back_to_hash)
{
    __u64 failed_before, routed_before;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;

    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    quic_forge_cid(cid, QUIC_CID_LEN, MAX_BACKENDS); /* one past backends[]'s last valid index */
    quic_build_frame(V4_SRC, QUIC_SHORT_FORM, cid, QUIC_CID_LEN);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    CHECK_EQ(failed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(quic_decoded_backend_down_falls_back_to_hash)
{
    __u64 failed_before, routed_before;
    struct stats alt_before, alt_after;
    struct backend be;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;

    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);
    alt_before = xdp_backend_stats_total(ALT_BACKEND_ID);

    /* backends is an ARRAY, so the slot resolves; MARLIN_BE_F_STATE is what is missing. */
    memset(&be, 0, sizeof(be));
    be.flags = MARLIN_MODE_L2DSR;
    be.id = (__u16)ALT_BACKEND_ID;
    memcpy(be.mac, ALT_BACKEND_MAC, ETH_ALEN);
    xdp_backend_write(ALT_BACKEND_ID, &be);

    quic_forge_cid(cid, QUIC_CID_LEN, ALT_BACKEND_ID);
    quic_build_frame(V4_SRC, QUIC_SHORT_FORM, cid, QUIC_CID_LEN);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    CHECK_EQ(failed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    /*
     * The rejection is marlin_balancer_select_backend_quic()'s own
     * MARLIN_BE_F_STATE check, which returns NULL before
     * marlin_balancer_load_backend() -- the only call that meters -- ever
     * sees this backend.
     */
    alt_after = xdp_backend_stats_total(ALT_BACKEND_ID);
    CHECK_EQ(alt_before.packets, alt_after.packets);

    quic_vip_clear();
}

MARLIN_TEST(quic_non_quic_udp_on_vip_quic_routes_by_hash)
{
    __u64 failed_before, routed_before;
    struct xdp_run_result result;

    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_UDP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_udp(33333, (__u16)QUIC_VIP_PORT, MARLIN_UDP_HLEN); /* no payload: parser.c never reads a form byte */

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(failed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(icmp_error_on_vip_quic_routes_by_hash)
{
    __u64 failed_before, routed_before;
    struct xdp_run_result result;

    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_ICMP, MARLIN_IPV4_IHL_MIN, 0, ACL_ADDR4(198, 51, 100, 1) /* router: irrelevant */, V4_DST);
    pb_icmp(ICMP_DEST_UNREACH, 0);
    /*
     * An embedded header carries at most 8 bytes of L4 (proto.h) -- ports
     * only, never a connection ID -- so this can only ever reach hash
     * selection; parser.c's marlin_parse_icmp() never calls the QUIC parser.
     */
    pb_ipv4(IPPROTO_UDP, MARLIN_IPV4_IHL_MIN, 0, V4_DST /* embedded src: the VIP, becomes tuple.dst */,
            V4_SRC /* embedded dst: the client, becomes tuple.src */);
    pb_ports((__u16)QUIC_VIP_PORT, 33333);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(failed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(fragmented_udp_on_vip_quic_routes_by_hash)
{
    __u64 failed_before, routed_before;
    struct xdp_run_result result;

    /*
     * VIP_HASH_5TUPLE clear: with it set, marlin_balancer_frag() would drop
     * frag_unsupported before backend selection ever runs, testing the wrong
     * guard. VIP_QUIC alone still reaches marlin_balancer_quic_decode(),
     * whose own MARLIN_CTX_F_FRAG_ANY check (balancer.c) is what this proves.
     */
    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 0, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    /* First fragment: ports are present, so admission reaches the VIP_QUIC VIP. */
    pb_ipv4(IPPROTO_UDP, MARLIN_IPV4_IHL_MIN, IP_MF, V4_SRC, V4_DST);
    pb_udp(33333, (__u16)QUIC_VIP_PORT, (__u16)(MARLIN_UDP_HLEN + 1));
    pb_quic_form(QUIC_SHORT_FORM);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(failed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(quic_migration_same_cid_different_sources_same_backend)
{
    __u64 routed_before;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;
    __u16 i;

    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 1, 1);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);
    quic_forge_cid(cid, QUIC_CID_LEN, ALT_BACKEND_ID);

    for(i = 0; i < 8; i++) {
        quic_build_frame(ACL_ADDR4(10, 71, 71, (__u8)i), QUIC_SHORT_FORM, cid, QUIC_CID_LEN);
        result = run_current_packet();
        CHECK_EQ(0, result.err);
        CHECK_XDP(XDP_TX, result.retval);
        nh_check_frame(ALT_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    }
    CHECK_EQ(routed_before + 8, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(quic_migration_needs_the_vip_quic_flag)
{
    __u8 cid[QUIC_CID_LEN];

    /*
     * Same forged CID and striped table as the migration case above, but
     * VIP_QUIC clear: selection now depends on the hash, which does depend
     * on source address, so the sweep must observe a change.
     */
    quic_vip_seed(QUIC_CID_LEN, 0, 1, 1);
    quic_forge_cid(cid, QUIC_CID_LEN, ALT_BACKEND_ID);

    CHECK_EQ(1, quic_src_sweep_dmac_changes(cid, QUIC_CID_LEN, 32));

    quic_vip_clear();
}

MARLIN_TEST(quic_cid_routes_over_ipv6)
{
    __u64 routed_before;
    struct vip_key key;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;

    bal_setup();
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    backend_seed_l2dsr(ALT_BACKEND_ID, ALT_BACKEND_MAC);
    vip_seed6(DST6, QUIC_VIP_PORT, IPPROTO_UDP, QUIC_VIP_NUM,
              VIP_HASH_5TUPLE | VIP_QUIC | ((QUIC_CID_LEN << VIP_QUIC_CID_LEN_SHIFT) & VIP_QUIC_CID_LEN_MASK));
    xdp_fwd_fill(QUIC_VIP_NUM, NH_BACKEND_ID);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    quic_forge_cid(cid, QUIC_CID_LEN, ALT_BACKEND_ID);

    pb_reset();
    pb_eth(ETH_P_IPV6);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv6(IPPROTO_UDP, SRC6, DST6);
    pb_udp(33333, (__u16)QUIC_VIP_PORT, (__u16)(MARLIN_UDP_HLEN + 1 + QUIC_CID_LEN));
    pb_quic_cid(QUIC_SHORT_FORM, cid, QUIC_CID_LEN);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    /*
     * Proves balancer.c reads mctx->l4_off rather than a v4-shaped constant:
     * a wrong offset would decode garbage and fall back to NH_BACKEND_MAC.
     */
    nh_check_frame(ALT_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(routed_before + 1, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    vip_key6(&key, DST6, QUIC_VIP_PORT, IPPROTO_UDP);
    xdp_vip_del(&key);
    xdp_fwd_clear(QUIC_VIP_NUM);
    xdp_backend_clear(NH_BACKEND_ID);
    xdp_backend_clear(ALT_BACKEND_ID);
}
