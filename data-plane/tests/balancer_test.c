/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Native unit tests for balancer.c's NULL-argument abort convention and for
 * tuple.pad's effect on the 5-tuple hash. This translation unit #includes the
 * source directly, the same as nexthop_test.c. Every other branch needs a
 * populated vip_map/fwd_table/backends lookup or a packet-adjusting helper
 * this tier has no stub for (docs/design/24-testing.md, docs/PHASES.md) --
 * native coverage here stops at the two things neither tier could otherwise
 * reach: the abort branch a verifier-proven-unreachable BTF argument can
 * never drive through bpf_prog_test_run, and tuple.pad, which takes no
 * packet bytes and so leaves no wire-level knob for the packet tier to turn.
 */

#include <string.h>

#include <linux/in.h>

#include <bpf/bpf_endian.h>

#include "harness.h"

#include "../bpf/balancer.c"

/*
 * Die-loudly stubs for the five translation units balancer.c calls into.
 * Every case below returns before any of them is reached -- the NULL checks
 * are balancer.c's first lines, and the pad cases call marlin_siphash()
 * directly without going through marlin_balancer_process() at all -- so
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

int main(void)
{
    return marlin_tests_main();
}
