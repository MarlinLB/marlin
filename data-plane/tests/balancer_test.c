/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Native unit tests for balancer.c. This translation unit #includes the
 * source directly, the same as nexthop_test.c, to call its `static` helpers
 * with real pointers. Three groups of coverage:
 *
 * - The NULL-argument abort convention on marlin_balancer_process()'s two
 *   parameters: the abort branch a verifier-proven-unreachable BTF argument
 *   can never drive through bpf_prog_test_run.
 * - tuple.pad's effect on the 5-tuple hash, which takes no packet bytes and
 *   so leaves no wire-level knob for the packet tier to turn.
 * - The helpers that call neither a map lookup nor a packet-adjusting or
 *   -reading helper -- marlin_balancer_vip_key(), marlin_balancer_validate(),
 *   marlin_balancer_acl_enforce(), marlin_balancer_frag(),
 *   marlin_balancer_load_backend(), and marlin_balancer_filter()'s three
 *   early-return paths -- and so need nothing this tier lacks.
 *
 * Everything else -- the VIP lookup, QUIC connection-ID steering, backend
 * selection, and the pipeline entry point that ties them together -- needs a
 * populated vip_map/fwd_table/backends lookup or bpf_xdp_load_bytes()/
 * bpf_xdp_get_buff_len(), none of which this tier stubs
 * (docs/design/24-testing.md, docs/PHASES.md); that coverage stays
 * packet-tier-only.
 */

#include <string.h>

#include <linux/in.h>

#include <bpf/bpf_endian.h>

#include "harness.h"

#include "../bpf/balancer.c"

/*
 * Die-loudly stubs for the five translation units balancer.c calls into. No
 * case below reaches any of them: the NULL checks are balancer.c's first
 * lines, the pad cases call marlin_siphash() directly without going through
 * marlin_balancer_process() at all, and the helper-level cases further down
 * call only balancer.c's own map-free, helper-free static functions -- so
 * these exist only so the object links, the same convention
 * tests/stubs/bpf/bpf_helpers.h uses for bpf_fib_lookup()/bpf_redirect_map().
 */
int marlin_acl_check(const struct marlin_ctx *mctx)
{
    (void)mctx;
    fprintf(stderr, "tests: marlin_acl_check() stub reached; no case should call this far\n");
    exit(1);
}

int marlin_ratelimit(const struct marlin_ctx *mctx)
{
    (void)mctx;
    fprintf(stderr, "tests: marlin_ratelimit() stub reached; no case should call this far\n");
    exit(1);
}

int marlin_ipip_encap_packet(struct xdp_md *ctx, struct marlin_ctx *mctx)
{
    (void)ctx;
    (void)mctx;
    fprintf(stderr, "tests: marlin_ipip_encap_packet() stub reached; no case should call this far\n");
    exit(1);
}

int marlin_gue_encap_packet(struct xdp_md *ctx, struct marlin_ctx *mctx)
{
    (void)ctx;
    (void)mctx;
    fprintf(stderr, "tests: marlin_gue_encap_packet() stub reached; no case should call this far\n");
    exit(1);
}

int marlin_vxlan_encap_packet(struct xdp_md *ctx, struct marlin_ctx *mctx)
{
    (void)ctx;
    (void)mctx;
    fprintf(stderr, "tests: marlin_vxlan_encap_packet() stub reached; no case should call this far\n");
    exit(1);
}

int marlin_nexthop_encapsulate(struct xdp_md *ctx, struct marlin_ctx *mctx)
{
    (void)ctx;
    (void)mctx;
    fprintf(stderr, "tests: marlin_nexthop_encapsulate() stub reached; no case should call this far\n");
    exit(1);
}

int marlin_nexthop_l2dsr(struct xdp_md *ctx, struct marlin_ctx *mctx)
{
    (void)ctx;
    (void)mctx;
    fprintf(stderr, "tests: marlin_nexthop_l2dsr() stub reached; no case should call this far\n");
    exit(1);
}

MARLIN_TEST(balancer_null_ctx_aborts)
{
    struct marlin_ctx mctx;

    memset(&mctx, 0xAA, sizeof(mctx));
    CHECK_RET(MARLIN_ABORT_NULLREF, marlin_balancer_process(NULL, &mctx));
}

MARLIN_TEST(balancer_null_mctx_aborts)
{
    struct xdp_md ctx;

    memset(&ctx, 0, sizeof(ctx));
    CHECK_RET(MARLIN_ABORT_NULLREF, marlin_balancer_process(&ctx, NULL));
}

/*
 * VIP_HASH_5TUPLE hashes struct packet_tuple whole (docs/design/10-map-invariants.md),
 * so a non-zero pad changes the digest; the src-only path hashes tuple.src
 * alone and cannot see pad at all. This pins the premise
 * docs/design/24-testing.md's row-consistency assertions depend on -- the
 * zeroing itself is main.c's memset of the whole mctx, not something either
 * tier exercises here.
 */
MARLIN_TEST(tuple_pad_changes_the_five_tuple_hash)
{
    static const __u8 key[16] = {0};
    struct packet_tuple zero_pad;
    struct packet_tuple nonzero_pad;
    __u64 hash_zero, hash_nonzero;

    memset(&zero_pad, 0, sizeof(zero_pad));
    zero_pad.dport = bpf_htons(80);
    zero_pad.sport = bpf_htons(11111);
    zero_pad.proto = IPPROTO_TCP;
    zero_pad.family = AF_INET;

    nonzero_pad = zero_pad;
    nonzero_pad.pad[0] = 0x01;

    hash_zero = marlin_siphash(&zero_pad, sizeof(zero_pad), key);
    hash_nonzero = marlin_siphash(&nonzero_pad, sizeof(nonzero_pad), key);

    CHECK_TRUE(hash_zero != hash_nonzero);
}

MARLIN_TEST(tuple_pad_does_not_change_the_src_hash)
{
    static const __u8 key[16] = {0};
    struct packet_tuple zero_pad;
    struct packet_tuple nonzero_pad;
    __u64 hash_zero, hash_nonzero;

    memset(&zero_pad, 0, sizeof(zero_pad));
    zero_pad.dport = bpf_htons(80);
    zero_pad.sport = bpf_htons(11111);
    zero_pad.proto = IPPROTO_TCP;
    zero_pad.family = AF_INET;

    nonzero_pad = zero_pad;
    nonzero_pad.pad[0] = 0x01;

    hash_zero = marlin_siphash(zero_pad.src, sizeof(zero_pad.src), key);
    hash_nonzero = marlin_siphash(nonzero_pad.src, sizeof(nonzero_pad.src), key);

    CHECK_EQ(hash_zero, hash_nonzero);
}

/*
 * marlin_balancer_vip_key() reads nothing but mctx->tuple and calls no
 * helper, so it is native-tier testable outright. addr4/addr6 share a
 * union (abi/types.h), so the v4 case also pins that the family check does
 * not spill past the 4 bytes it means to write into the rest of the union.
 */
MARLIN_TEST(vip_key_v4_fills_only_addr4)
{
    struct marlin_ctx mctx;
    struct vip_key vkey;

    memset(&mctx, 0, sizeof(mctx));
    mctx.tuple.family = AF_INET;
    mctx.tuple.proto = IPPROTO_TCP;
    mctx.tuple.dport = bpf_htons(443);
    mctx.tuple.dst[0] = bpf_htonl(0x0a000001);

    marlin_balancer_vip_key(&mctx, &vkey);

    CHECK_EQ(AF_INET, vkey.family);
    CHECK_EQ(IPPROTO_TCP, vkey.proto);
    CHECK_EQ(bpf_htons(443), vkey.port);
    CHECK_EQ(bpf_htonl(0x0a000001), vkey.addr4);
    CHECK_EQ(0, vkey.addr6[1]);
    CHECK_EQ(0, vkey.addr6[2]);
    CHECK_EQ(0, vkey.addr6[3]);
}

MARLIN_TEST(vip_key_v6_copies_the_full_address)
{
    struct marlin_ctx mctx;
    struct vip_key vkey;

    memset(&mctx, 0, sizeof(mctx));
    mctx.tuple.family = AF_INET6;
    mctx.tuple.proto = IPPROTO_UDP;
    mctx.tuple.dport = bpf_htons(53);
    mctx.tuple.dst[0] = bpf_htonl(0x20010db8);
    mctx.tuple.dst[1] = bpf_htonl(0x00000000);
    mctx.tuple.dst[2] = bpf_htonl(0x00000000);
    mctx.tuple.dst[3] = bpf_htonl(0x00000001);

    marlin_balancer_vip_key(&mctx, &vkey);

    CHECK_EQ(AF_INET6, vkey.family);
    CHECK_MEM(mctx.tuple.dst, vkey.addr6, sizeof(vkey.addr6));
}

/*
 * marlin_balancer_validate() takes frame_len as a plain argument and reads
 * only mctx->pkt_len -- it calls bpf_xdp_get_buff_len() nowhere itself, only
 * its caller (marlin_balancer_process_packet()) does -- so both
 * MARLIN_DROP_ENCAP_LENGTH branches are native-tier testable directly.
 */
MARLIN_TEST(validate_rejects_a_sub_eth_hlen_pkt_len)
{
    struct marlin_ctx mctx;

    memset(&mctx, 0, sizeof(mctx));
    mctx.pkt_len = ETH_HLEN - 1;

    CHECK_RET(MARLIN_DROP_ENCAP_LENGTH, marlin_balancer_validate(&mctx, mctx.pkt_len));
}

MARLIN_TEST(validate_rejects_a_frame_len_mismatch)
{
    struct marlin_ctx mctx;

    memset(&mctx, 0, sizeof(mctx));
    mctx.pkt_len = ETH_HLEN + 20;

    CHECK_RET(MARLIN_DROP_ENCAP_LENGTH, marlin_balancer_validate(&mctx, (__u32)mctx.pkt_len + 1));
}

MARLIN_TEST(validate_admits_a_matching_frame_len)
{
    struct marlin_ctx mctx;

    memset(&mctx, 0, sizeof(mctx));
    mctx.pkt_len = ETH_HLEN + 20;

    CHECK_RET(MARLIN_OK, marlin_balancer_validate(&mctx, (__u32)mctx.pkt_len));
}

/*
 * marlin_balancer_acl_enforce() is a pure function of mctx->acl_verdict and
 * vip->flags -- no map or packet helper reachable -- so it is native-tier
 * testable outright. This pins the boolean logic directly; which drop
 * reason a live packet actually gets is the placement property
 * docs/design/24-testing.md's ACL assertions cover at the packet tier.
 */
MARLIN_TEST(acl_enforce_admits_when_verdict_not_blocked)
{
    struct marlin_ctx mctx;
    struct vip_meta vip;

    memset(&mctx, 0, sizeof(mctx));
    memset(&vip, 0, sizeof(vip));
    vip.flags = VIP_ACL;

    mctx.acl_verdict = MARLIN_ACL_ALLOW;
    CHECK_RET(MARLIN_OK, marlin_balancer_acl_enforce(&mctx, NULL));

    mctx.acl_verdict = MARLIN_ACL_NONE;
    CHECK_RET(MARLIN_OK, marlin_balancer_acl_enforce(&mctx, &vip));
}

MARLIN_TEST(acl_enforce_blocks_a_non_vip_destination)
{
    struct marlin_ctx mctx;

    memset(&mctx, 0, sizeof(mctx));
    mctx.acl_verdict = MARLIN_ACL_BLOCK;

    CHECK_RET(MARLIN_DROP_ACL_BLOCKED, marlin_balancer_acl_enforce(&mctx, NULL));
}

MARLIN_TEST(acl_enforce_needs_vip_acl_bit_to_block)
{
    struct marlin_ctx mctx;
    struct vip_meta vip;

    memset(&mctx, 0, sizeof(mctx));
    memset(&vip, 0, sizeof(vip));
    mctx.acl_verdict = MARLIN_ACL_BLOCK;

    vip.flags = 0;
    CHECK_RET(MARLIN_OK, marlin_balancer_acl_enforce(&mctx, &vip));

    vip.flags = VIP_ACL;
    CHECK_RET(MARLIN_DROP_ACL_BLOCKED, marlin_balancer_acl_enforce(&mctx, &vip));
}

/*
 * marlin_balancer_frag() reads only mctx->flags and vip->flags and calls no
 * helper, so it is native-tier testable outright.
 */
MARLIN_TEST(frag_only_matters_with_hash_5tuple)
{
    struct marlin_ctx mctx;
    struct vip_meta vip;

    memset(&mctx, 0, sizeof(mctx));
    memset(&vip, 0, sizeof(vip));
    mctx.flags = MARLIN_CTX_F_FRAG_ANY;

    vip.flags = 0;
    CHECK_RET(MARLIN_OK, marlin_balancer_frag(&mctx, &vip));

    vip.flags = VIP_HASH_5TUPLE;
    CHECK_RET(MARLIN_DROP_FRAG_UNSUPPORTED, marlin_balancer_frag(&mctx, &vip));

    mctx.flags = 0;
    CHECK_RET(MARLIN_OK, marlin_balancer_frag(&mctx, &vip));
}

/*
 * marlin_balancer_outer_dscp() reads only vip->flags and writes only
 * mctx->flags, same shape as marlin_balancer_frag() above.
 */
MARLIN_TEST(outer_dscp_copies_only_the_dscp_field)
{
    struct marlin_ctx mctx;
    struct vip_meta vip;

    memset(&mctx, 0, sizeof(mctx));
    memset(&vip, 0, sizeof(vip));

    vip.flags = 0;
    marlin_balancer_outer_dscp(&mctx, &vip);
    CHECK_EQ(0, mctx.flags);

    vip.flags = VIP_ACL | ((0x3fU << VIP_DSCP_SHIFT) & VIP_DSCP_MASK);
    marlin_balancer_outer_dscp(&mctx, &vip);
    CHECK_EQ(0x3fU << MARLIN_CTX_DSCP_SHIFT, mctx.flags);
}

MARLIN_TEST(outer_dscp_preserves_preexisting_mctx_flags)
{
    struct marlin_ctx mctx;
    struct vip_meta vip;

    memset(&mctx, 0, sizeof(mctx));
    memset(&vip, 0, sizeof(vip));
    mctx.flags = MARLIN_CTX_F_QUIC | MARLIN_CTX_F_FRAG;
    vip.flags = (0x2aU << VIP_DSCP_SHIFT) & VIP_DSCP_MASK;

    marlin_balancer_outer_dscp(&mctx, &vip);

    CHECK_EQ((__u32)(MARLIN_CTX_F_QUIC | MARLIN_CTX_F_FRAG) | (0x2aU << MARLIN_CTX_DSCP_SHIFT), mctx.flags);
}

/*
 * marlin_balancer_load_backend() calls marlin_stats_backend(), which reads
 * `backend_stats` (a PERCPU_ARRAY) through bpf_map_lookup_elem(). No ARRAY
 * stub exists (docs/PHASES.md), so the call falls through to the ACL stub's
 * trie lookup, which adopts the unseeded map address as an empty trie and
 * returns NULL (tests/stubs/map_stub.h) -- a safe no-op here, not a modelled
 * counter. Nothing below asserts backend_stats' contents.
 */
MARLIN_TEST(load_backend_null_is_no_backend)
{
    struct marlin_ctx mctx;

    memset(&mctx, 0xAA, sizeof(mctx));
    CHECK_RET(MARLIN_DROP_NO_BACKEND, marlin_balancer_load_backend(&mctx, NULL));
}

MARLIN_TEST(load_backend_copies_even_when_down)
{
    struct marlin_ctx mctx;
    struct backend backend;

    memset(&mctx, 0, sizeof(mctx));
    memset(&backend, 0, sizeof(backend));
    backend.id = 7;

    CHECK_RET(MARLIN_DROP_BACKEND_DOWN, marlin_balancer_load_backend(&mctx, &backend));
    CHECK_MEM(&backend, &mctx.backend, sizeof(backend));
}

MARLIN_TEST(load_backend_up_admits_with_byte_exact_copy)
{
    struct marlin_ctx mctx;
    struct backend backend;

    memset(&mctx, 0, sizeof(mctx));
    memset(&backend, 0, sizeof(backend));
    backend.id = 3;
    backend.flags = MARLIN_BE_F_STATE;

    CHECK_RET(MARLIN_OK, marlin_balancer_load_backend(&mctx, &backend));
    CHECK_MEM(&backend, &mctx.backend, sizeof(backend));
}

/*
 * Only marlin_balancer_filter()'s three early-return paths are native-tier
 * reachable: the fourth calls marlin_ratelimit(), stubbed to die loudly
 * above like every other collaborator this file cannot model.
 */
MARLIN_TEST(filter_admits_without_reaching_ratelimit)
{
    struct marlin_ctx mctx;

    memset(&mctx, 0, sizeof(mctx));

    mctx.cfg.flags = 0; /* CFG_RL_ENABLE clear */
    CHECK_RET(MARLIN_OK, marlin_balancer_filter(&mctx, VIP_RATELIMIT));

    mctx.cfg.flags = CFG_RL_ENABLE;
    CHECK_RET(MARLIN_OK, marlin_balancer_filter(&mctx, 0)); /* VIP_RATELIMIT clear */

    mctx.acl_verdict = MARLIN_ACL_ALLOW;
    CHECK_RET(MARLIN_OK, marlin_balancer_filter(&mctx, VIP_RATELIMIT));
}

int main(void)
{
    return marlin_tests_main();
}
