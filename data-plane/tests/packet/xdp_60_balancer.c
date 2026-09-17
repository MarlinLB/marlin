/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * VIP admission and backend selection: VIP miss/hit, out-of-range and
 * empty/down forwarding slots, the 5-tuple vs. source-only hash regime, and
 * fragment handling under each. bal_setup() and the VIP/frame fixture come
 * from xdp_fixture.h -- xdp_80_quic.c reuses bal_setup() for its own setup.
 */

#include <string.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>

#include <marlin/abi/types.h>
#include <marlin/marlin.h>

#include "../harness.h"
#include "../packet.h"
#include "maps.h"
#include "prog.h"
#include "xdp_fixture.h"

/*
 * Distinct from every fixture backends[] index, so a counter keyed on the map
 * index cannot pass for one keyed on backend.id.
 */
#define BAL_ABI_BACKEND_ID 7U

/*
 * The VIP nh_build_frame()'s frame lands on, seeded one element at a time
 * rather than through nh_backend_seed(): each case below varies exactly one of
 * the VIP flags, the forwarding-table contents or the backend entry, and needs
 * the rest held fixed.
 */
static void bal_vip_seed(__u32 vip_num, __u16 port_host, __u32 flags, __u32 fwd_id)
{
    vip_seed4(V4_DST, port_host, IPPROTO_TCP, vip_num, flags);
    xdp_fwd_fill(vip_num, fwd_id);
}

static void bal_vip_clear(__u32 vip_num, __u16 port_host)
{
    struct vip_key key;

    vip_key4(&key, V4_DST, port_host, IPPROTO_TCP);
    xdp_vip_del(&key);
    xdp_fwd_clear(vip_num);
}

static void bal_build_frame_sport(__u16 sport_host)
{
    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(sport_host, 80);
}

/*
 * Sweeps the source port against a forwarding block striped between two
 * backends and reports whether the emitted destination MAC ever changed: 1 if
 * the source port can move the selection, 0 if it never did, -1 if a packet
 * did not forward at all. Which row any one packet lands on stays unknown,
 * which is the point -- no hash is recomputed here.
 */
static int bal_sport_moves_selection(__u16 count)
{
    unsigned char first[ETH_ALEN] = {0};
    struct xdp_run_result result;
    __u16 i;

    for(i = 0; i < count; i++) {
        bal_build_frame_sport((__u16)(40000U + i));
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

MARLIN_TEST(vip_miss_is_pass_and_counted)
{
    __u64 before;
    struct xdp_run_result result;

    bal_setup();
    before = xdp_drop_stats_total(MARLIN_PASS_VIP_MISS);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_PASS_VIP_MISS));
}

MARLIN_TEST(port_agnostic_vip_matches_any_dport)
{
    struct xdp_run_result result;

    bal_setup();
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    bal_vip_seed(NH_VIP_NUM, 0, VIP_HASH_5TUPLE, NH_BACKEND_ID);
    nh_build_frame(); /* dport 80, which no vip_map key names */

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    bal_vip_clear(NH_VIP_NUM, 0);
    xdp_backend_clear(NH_BACKEND_ID);
}

MARLIN_TEST(exact_port_vip_wins_over_port_agnostic)
{
    struct stats exact_before, any_before;
    struct xdp_run_result result;

    bal_setup();
    exact_before = xdp_vip_stats_total(NH_VIP_NUM);
    any_before = xdp_vip_stats_total(ALT_VIP_NUM);

    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    bal_vip_seed(NH_VIP_NUM, 80, VIP_HASH_5TUPLE, NH_BACKEND_ID);
    bal_vip_seed(ALT_VIP_NUM, 0, VIP_HASH_5TUPLE, NH_BACKEND_ID);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    CHECK_EQ(exact_before.packets + 1, xdp_vip_stats_total(NH_VIP_NUM).packets);
    CHECK_EQ(any_before.packets, xdp_vip_stats_total(ALT_VIP_NUM).packets);

    bal_vip_clear(NH_VIP_NUM, 80);
    bal_vip_clear(ALT_VIP_NUM, 0);
    xdp_backend_clear(NH_BACKEND_ID);
}

MARLIN_TEST(vip_stats_counts_the_ingress_frame_at_admission)
{
    struct stats before, after;
    struct xdp_run_result result;

    bal_setup();
    before = xdp_vip_stats_total(NH_VIP_NUM);

    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    bal_vip_seed(NH_VIP_NUM, 80, VIP_HASH_5TUPLE, NH_BACKEND_ID);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);

    after = xdp_vip_stats_total(NH_VIP_NUM);
    CHECK_EQ(before.packets + 1, after.packets);
    CHECK_EQ(before.bytes + pb_len, after.bytes);

    bal_vip_clear(NH_VIP_NUM, 80);
    xdp_backend_clear(NH_BACKEND_ID);
}

MARLIN_TEST(vip_num_out_of_range_is_drop)
{
    __u64 before;
    struct xdp_run_result result;

    bal_setup();
    before = xdp_drop_stats_total(MARLIN_DROP_MAP_BOUNDS);
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);

    /*
     * No forwarding block is seeded for it: MAX_VIPS owns none, which is the
     * reason admission refuses the entry in the first place.
     */
    vip_seed4(V4_DST, 80, IPPROTO_TCP, MAX_VIPS, VIP_HASH_5TUPLE);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_MAP_BOUNDS));

    bal_vip_clear(NH_VIP_NUM, 80);
    xdp_backend_clear(NH_BACKEND_ID);
}

MARLIN_TEST(empty_fwd_slot_is_no_backend)
{
    __u64 before;
    struct xdp_run_result result;

    bal_setup();
    before = xdp_drop_stats_total(MARLIN_DROP_NO_BACKEND);
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    bal_vip_seed(NH_VIP_NUM, 80, VIP_HASH_5TUPLE, 0);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_NO_BACKEND));

    bal_vip_clear(NH_VIP_NUM, 80);
    xdp_backend_clear(NH_BACKEND_ID);
}

MARLIN_TEST(out_of_range_fwd_slot_is_no_backend)
{
    __u64 before;
    struct xdp_run_result result;

    bal_setup();
    before = xdp_drop_stats_total(MARLIN_DROP_NO_BACKEND);
    bal_vip_seed(NH_VIP_NUM, 80, VIP_HASH_5TUPLE, MAX_BACKENDS);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_NO_BACKEND));

    bal_vip_clear(NH_VIP_NUM, 80);
}

MARLIN_TEST(unseeded_backend_is_backend_down)
{
    __u64 before;
    struct xdp_run_result result;

    bal_setup();
    before = xdp_drop_stats_total(MARLIN_DROP_BACKEND_DOWN);

    /* backends is an ARRAY, so the slot resolves; MARLIN_BE_F_STATE is what is missing. */
    xdp_backend_clear(NH_BACKEND_ID);
    bal_vip_seed(NH_VIP_NUM, 80, VIP_HASH_5TUPLE, NH_BACKEND_ID);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_BACKEND_DOWN));

    bal_vip_clear(NH_VIP_NUM, 80);
}

MARLIN_TEST(backend_stats_counts_a_down_backend_and_keys_on_its_abi_id)
{
    struct stats abi_before, index_before;
    struct backend be;
    struct xdp_run_result result;

    bal_setup();
    abi_before = xdp_backend_stats_total(BAL_ABI_BACKEND_ID);
    index_before = xdp_backend_stats_total(NH_BACKEND_ID);

    memset(&be, 0, sizeof(be));
    be.flags = MARLIN_MODE_L2DSR; /* no MARLIN_BE_F_STATE */
    be.addr = NH_BACKEND_ADDR;
    be.id = (__u16)BAL_ABI_BACKEND_ID;
    memcpy(be.mac, NH_BACKEND_MAC, ETH_ALEN);
    xdp_backend_write(NH_BACKEND_ID, &be);

    bal_vip_seed(NH_VIP_NUM, 80, VIP_HASH_5TUPLE, NH_BACKEND_ID);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);

    /* Metered on the way in, before the state check rejects the backend. */
    CHECK_EQ(abi_before.packets + 1, xdp_backend_stats_total(BAL_ABI_BACKEND_ID).packets);
    CHECK_EQ(index_before.packets, xdp_backend_stats_total(NH_BACKEND_ID).packets);

    bal_vip_clear(NH_VIP_NUM, 80);
    xdp_backend_clear(NH_BACKEND_ID);
}

MARLIN_TEST(five_tuple_hash_varies_with_source_port)
{
    bal_setup();
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    backend_seed_l2dsr(ALT_BACKEND_ID, ALT_BACKEND_MAC);
    vip_seed4(V4_DST, 80, IPPROTO_TCP, NH_VIP_NUM, VIP_HASH_5TUPLE);
    xdp_fwd_fill_striped(NH_VIP_NUM, NH_BACKEND_ID, ALT_BACKEND_ID);

    CHECK_EQ(1, bal_sport_moves_selection(32));

    bal_vip_clear(NH_VIP_NUM, 80);
    xdp_backend_clear(NH_BACKEND_ID);
    xdp_backend_clear(ALT_BACKEND_ID);
}

MARLIN_TEST(src_only_hash_ignores_source_port)
{
    bal_setup();
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    backend_seed_l2dsr(ALT_BACKEND_ID, ALT_BACKEND_MAC);
    vip_seed4(V4_DST, 80, IPPROTO_TCP, NH_VIP_NUM, 0);
    xdp_fwd_fill_striped(NH_VIP_NUM, NH_BACKEND_ID, ALT_BACKEND_ID);

    CHECK_EQ(0, bal_sport_moves_selection(32));

    bal_vip_clear(NH_VIP_NUM, 80);
    xdp_backend_clear(NH_BACKEND_ID);
    xdp_backend_clear(ALT_BACKEND_ID);
}

/*
 * A first fragment, not a later one: the ports a later fragment lacks are what
 * the exact-port VIP key is built from, so only a first fragment reaches
 * admission carrying dport 80.
 */
static void bal_build_first_fragment(void)
{
    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, IP_MF, V4_SRC, V4_DST);
    pb_ports(11111, 80);
}

MARLIN_TEST(fragment_on_five_tuple_vip_is_drop)
{
    __u64 before;
    struct xdp_run_result result;

    bal_setup();
    before = xdp_drop_stats_total(MARLIN_DROP_FRAG_UNSUPPORTED);
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    bal_vip_seed(NH_VIP_NUM, 80, VIP_HASH_5TUPLE, NH_BACKEND_ID);
    bal_build_first_fragment();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_FRAG_UNSUPPORTED));

    bal_vip_clear(NH_VIP_NUM, 80);
    xdp_backend_clear(NH_BACKEND_ID);
}

MARLIN_TEST(fragment_non_first_on_five_tuple_vip_is_drop)
{
    /*
     * The first-fragment sibling above proves MARLIN_CTX_F_FRAG_FIRST is
     * produced; this proves the plain MARLIN_CTX_F_FRAG tail is caught too
     * (docs/design/24-testing.md). A tail fragment carries no ports, so the
     * VIP must be port-agnostic for the exact-port lookup to still land here.
     */
    __u64 before;
    struct xdp_run_result result;

    bal_setup();
    before = xdp_drop_stats_total(MARLIN_DROP_FRAG_UNSUPPORTED);
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    bal_vip_seed(NH_VIP_NUM, 0, VIP_HASH_5TUPLE, NH_BACKEND_ID);

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0x0040 /* offset set, MF clear: non-first, last fragment */, V4_SRC, V4_DST);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_FRAG_UNSUPPORTED));

    bal_vip_clear(NH_VIP_NUM, 0);
    xdp_backend_clear(NH_BACKEND_ID);
}

MARLIN_TEST(fragment_on_src_hash_vip_forwards)
{
    __u64 before;
    struct xdp_run_result result;

    bal_setup();
    before = xdp_drop_stats_total(MARLIN_DROP_FRAG_UNSUPPORTED);
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    bal_vip_seed(NH_VIP_NUM, 80, 0, NH_BACKEND_ID);
    bal_build_first_fragment();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(before, xdp_drop_stats_total(MARLIN_DROP_FRAG_UNSUPPORTED));

    bal_vip_clear(NH_VIP_NUM, 80);
    xdp_backend_clear(NH_BACKEND_ID);
}

MARLIN_TEST(unflagged_vip_fragments_and_unfragmented_share_a_row)
{
    /*
     * docs/design/24-testing.md: with VIP_HASH_5TUPLE clear, both fragments
     * must still forward, and to the same backend as an unfragmented packet
     * of the same flow -- the existing guarantee the flag must not disturb.
     * Seeded at port 0: a fragment tail's parsed dport is always zero, so
     * this guarantee holds only because the VIP itself is port-agnostic --
     * see explicit_port_vip_fragment_tail_is_vip_miss and
     * explicit_and_agnostic_vip_split_a_fragmented_datagram below for what
     * happens on an explicit port instead.
     */
    unsigned char dmac_full[ETH_ALEN];
    unsigned char dmac_first_frag[ETH_ALEN];
    unsigned char dmac_tail_frag[ETH_ALEN];
    struct xdp_run_result result;

    bal_setup();
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    backend_seed_l2dsr(ALT_BACKEND_ID, ALT_BACKEND_MAC);
    vip_seed4(V4_DST, 0, IPPROTO_TCP, NH_VIP_NUM, 0);
    xdp_fwd_fill_striped(NH_VIP_NUM, NH_BACKEND_ID, ALT_BACKEND_ID);

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(11111, 80);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    memcpy(dmac_full, out_buf, ETH_ALEN);

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, IP_MF, V4_SRC, V4_DST);
    pb_ports(11111, 80);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    memcpy(dmac_first_frag, out_buf, ETH_ALEN);

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0x0040 /* offset set, MF clear: non-first, last fragment */, V4_SRC, V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    memcpy(dmac_tail_frag, out_buf, ETH_ALEN);

    CHECK_MEM(dmac_full, dmac_first_frag, ETH_ALEN);
    CHECK_MEM(dmac_full, dmac_tail_frag, ETH_ALEN);

    bal_vip_clear(NH_VIP_NUM, 0);
    xdp_backend_clear(NH_BACKEND_ID);
    xdp_backend_clear(ALT_BACKEND_ID);
}

/*
 * A fragment tail's parsed dport is always zero (parser.c), so on a VIP
 * configured with an explicit port and no port == 0 companion, the tail's
 * vip_map lookup is the same miss twice over -- not a second chance, since
 * both lookups in marlin_balancer_vip() carry the identical zeroed key. The
 * head still resolves and forwards; only the tail is stranded. This is the
 * documented consequence of docs/design/11-pipeline.md and
 * docs/design/12-selection.md's "Hash input", not a bug this test enshrines.
 */
MARLIN_TEST(explicit_port_vip_fragment_tail_is_vip_miss)
{
    __u64 miss_before;
    struct xdp_run_result result;

    bal_setup();
    miss_before = xdp_drop_stats_total(MARLIN_PASS_VIP_MISS);
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    bal_vip_seed(NH_VIP_NUM, 80, 0, NH_BACKEND_ID);

    bal_build_first_fragment();
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0x0040 /* offset set, MF clear: non-first, last fragment */, V4_SRC, V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(miss_before + 1, xdp_drop_stats_total(MARLIN_PASS_VIP_MISS));

    bal_vip_clear(NH_VIP_NUM, 80);
    xdp_backend_clear(NH_BACKEND_ID);
}

/*
 * If a port == 0 companion does exist on the same address, the tail is not
 * stranded -- it resolves through the companion's vip_num instead of the
 * head's, splitting one datagram across two independently configured pools.
 * docs/design/12-selection.md rejects exactly this split as a hash input
 * ("Hashing ports with fragments falling back to the address"); here it is
 * reached through VIP admission rather than through the hash, which is why
 * fixing the hash input alone does not close it.
 */
MARLIN_TEST(explicit_and_agnostic_vip_split_a_fragmented_datagram)
{
    struct xdp_run_result result;

    bal_setup();
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    backend_seed_l2dsr(ALT_BACKEND_ID, ALT_BACKEND_MAC);
    bal_vip_seed(NH_VIP_NUM, 80, 0, NH_BACKEND_ID);
    bal_vip_seed(ALT_VIP_NUM, 0, 0, ALT_BACKEND_ID);

    bal_build_first_fragment();
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0x0040 /* offset set, MF clear: non-first, last fragment */, V4_SRC, V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(ALT_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    bal_vip_clear(NH_VIP_NUM, 80);
    bal_vip_clear(ALT_VIP_NUM, 0);
    xdp_backend_clear(NH_BACKEND_ID);
    xdp_backend_clear(ALT_BACKEND_ID);
}

/*
 * RFC 8200 SS4.5: the Fragment header's Next Header is the first header of
 * the Fragmentable Part, not necessarily the upper-layer protocol. Before
 * parser.c's frag/ext-header gate, a Destination Options header behind the
 * fragment header made the head resolve UDP (forwarding here, to
 * NH_BACKEND_MAC) while the tail resolved proto 60 and missed this VIP
 * outright -- a different failure from the port-agnostic-VIP case above,
 * since no port == 0 companion can save a lookup keyed on the wrong
 * protocol. The gate now refuses both halves in the parser, before either
 * ever reaches vip_map.
 */
MARLIN_TEST(ipv6_frag_behind_ext_hdr_refuses_both_halves)
{
    struct vip_key key;
    __u64 unsupported_before;
    struct xdp_run_result result;

    bal_setup();
    unsupported_before = xdp_drop_stats_total(MARLIN_DROP_UNSUPPORTED_PROTO);
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    vip_seed6(DST6, 0, IPPROTO_UDP, NH_VIP_NUM, 0);
    xdp_fwd_fill(NH_VIP_NUM, NH_BACKEND_ID);

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_FRAGMENT, SRC6, DST6);
    pb_frag6(IPPROTO_DSTOPTS, IP6_MF);
    pb_ext6(IPPROTO_UDP, 0);
    pb_ports(11111, 80);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(unsupported_before + 1, xdp_drop_stats_total(MARLIN_DROP_UNSUPPORTED_PROTO));

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_FRAGMENT, SRC6, DST6);
    pb_frag6(IPPROTO_DSTOPTS, 0x0008 /* offset set, MF clear: non-first, last fragment */);
    pb_ext6(IPPROTO_UDP, 0);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(unsupported_before + 2, xdp_drop_stats_total(MARLIN_DROP_UNSUPPORTED_PROTO));

    vip_key6(&key, DST6, 0, IPPROTO_UDP);
    xdp_vip_del(&key);
    xdp_fwd_clear(NH_VIP_NUM);
    xdp_backend_clear(NH_BACKEND_ID);
}

static void bal_build_icmp_embedding_flow(__u16 flow_sport)
{
    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_ICMP, MARLIN_IPV4_IHL_MIN, 0, ACL_ADDR4(198, 51, 100, 1) /* router: irrelevant */, V4_DST);
    pb_icmp(ICMP_DEST_UNREACH, 0);
    /*
     * The embedded packet is the VIP's own response leg (docs/design/13-icmp.md):
     * src is the VIP, dst is the client, and parser.c normalizes both the
     * address and port fields back into the forward-direction tuple this
     * error reports on.
     */
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_DST, V4_SRC);
    pb_ports(80, flow_sport);
}

MARLIN_TEST(icmp_error_on_five_tuple_vip_picks_the_flows_row)
{
    /*
     * docs/design/24-testing.md: fails unless parser.c recovers the embedded
     * destination port into tuple.sport, and it is the only test that
     * catches that omission.
     */
    unsigned char dmac_flow[ETH_ALEN];
    unsigned char dmac_icmp[ETH_ALEN];
    struct xdp_run_result result;
    __u16 i;

    bal_setup();
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    backend_seed_l2dsr(ALT_BACKEND_ID, ALT_BACKEND_MAC);
    vip_seed4(V4_DST, 80, IPPROTO_TCP, NH_VIP_NUM, VIP_HASH_5TUPLE);
    xdp_fwd_fill_striped(NH_VIP_NUM, NH_BACKEND_ID, ALT_BACKEND_ID);

    for(i = 0; i < 8; i++) {
        __u16 sport = (__u16)(50000U + i);

        bal_build_frame_sport(sport);
        result = run_current_packet();
        CHECK_EQ(0, result.err);
        CHECK_XDP(XDP_TX, result.retval);
        memcpy(dmac_flow, out_buf, ETH_ALEN);

        bal_build_icmp_embedding_flow(sport);
        result = run_current_packet();
        CHECK_EQ(0, result.err);
        CHECK_XDP(XDP_TX, result.retval);
        memcpy(dmac_icmp, out_buf, ETH_ALEN);

        CHECK_MEM(dmac_flow, dmac_icmp, ETH_ALEN);
    }

    bal_vip_clear(NH_VIP_NUM, 80);
    xdp_backend_clear(NH_BACKEND_ID);
    xdp_backend_clear(ALT_BACKEND_ID);
}
