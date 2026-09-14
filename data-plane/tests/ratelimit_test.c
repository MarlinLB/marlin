/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Native unit tests for ratelimit.c. This translation unit #includes the
 * source directly and reaches its map lookup/update and its clock read
 * through tests/stubs/, which shadows libbpf's <bpf/bpf_helpers.h>.
 *
 * Split across two regimes, matching docs/design/24-testing.md: rl_spend()
 * is a pure function of its arguments, so the arithmetic cases call it
 * directly with no stub at all; marlin_ratelimit() itself needs the map and
 * clock stubs and covers what rl_spend() cannot -- the gates, the key
 * construction, and the miss path's insert. Eviction and capacity under
 * MAX_RL_ENTRIES stay packet-tier-only: the LRU_HASH's eviction is not a
 * function of the arguments, which is exactly what disqualifies it from
 * this tier under that document's three-part test.
 */

#include <stdio.h>
#include <string.h>

#include <bpf/bpf_endian.h>

#include "harness.h"

#include "../bpf/ratelimit.c"

#define RL_ADDR4(a, b, c, d) bpf_htonl(((__u32)(a) << 24) | ((__u32)(b) << 16) | ((__u32)(c) << 8) | (__u32)(d))

/*
 * Poisoned rather than zeroed, like acl_test.c's mctx_init: every field the
 * rate limiter is not supposed to read holds a value a wrongly-scoped read
 * would notice. tuple.src is the exception -- mctx_src4()/mctx_src6() below
 * set it exactly, because unlike acl.c's v4 path (which reads only
 * tuple.src[0] and so is tested *with* poisoned upper words) ratelimit.c's
 * key always copies the full 16 bytes, so a v4 case needs the real
 * zero-extension invariant parser.c would have produced, not a poisoned one.
 */
static void mctx_init(struct marlin_ctx *mctx, __u8 family, __u32 flags, __u8 acl_verdict)
{
    memset(mctx, 0xAA, sizeof(*mctx));
    mctx->cfg.flags = flags;
    mctx->tuple.family = family;
    mctx->acl_verdict = acl_verdict;
    hash_stub_reset(&ratelimit);
    time_stub_set_ns(0);
}

static void mctx_src4(struct marlin_ctx *mctx, __be32 addr)
{
    memset(mctx->tuple.src, 0, sizeof(mctx->tuple.src));
    mctx->tuple.src[0] = addr;
}

/* ---- rl_spend(): pure arithmetic, no stub ------------------------------ */

MARLIN_TEST(rl_spend_refill_credited)
{
    __u64 next;
    int rc;

    /* old: timestamp 0, drained; now: 10 ticks later; rate: 1 token/tick. */
    rc = rl_spend(0, 10, MARLIN_RL_ONE_TOKEN, 100 * MARLIN_RL_ONE_TOKEN, &next);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(9 * MARLIN_RL_ONE_TOKEN, next & MARLIN_RL_STATE_MASK); /* 10 refilled, 1 spent */
    CHECK_EQ(10, next >> 32);
}

MARLIN_TEST(rl_spend_product_overflowing_32_bits_clamps)
{
    __u64 next;
    int rc;
    __u64 burst = 5 * MARLIN_RL_ONE_TOKEN;

    /* elapsed=16 at rate=1<<30: the raw product is far past what a 32-bit
     * sum could represent -- the clamp before the add is what keeps this
     * exact instead of wrapping.
     */
    rc = rl_spend(0, 16, (__u64)1 << 30, burst, &next);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(burst - MARLIN_RL_ONE_TOKEN, next & MARLIN_RL_STATE_MASK);
}

MARLIN_TEST(rl_spend_clamps_to_burst)
{
    __u64 next;
    int rc;
    __u64 burst = 5 * MARLIN_RL_ONE_TOKEN;
    __u64 old = (__u64)4 * MARLIN_RL_ONE_TOKEN; /* timestamp 0, near-full already */

    /* elapsed=1 tick at a high rate: refill alone would exceed burst even
     * before adding to the 4 tokens already held.
     */
    rc = rl_spend(old, 1, 10 * MARLIN_RL_ONE_TOKEN, burst, &next);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(burst - MARLIN_RL_ONE_TOKEN, next & MARLIN_RL_STATE_MASK);
}

MARLIN_TEST(rl_spend_exactly_one_token_spent)
{
    __u64 next;
    int rc;
    __u64 old = ((__u64)5 << 32) | (3 * MARLIN_RL_ONE_TOKEN);

    /* elapsed=0: no refill, so the only change is the one token spent. */
    rc = rl_spend(old, 5, MARLIN_RL_ONE_TOKEN, 100 * MARLIN_RL_ONE_TOKEN, &next);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(2 * MARLIN_RL_ONE_TOKEN, next & MARLIN_RL_STATE_MASK);
    CHECK_EQ(5, next >> 32);
}

MARLIN_TEST(rl_spend_sub_one_token_drops)
{
    __u64 next = 0xdeadbeefdeadbeefULL; /* poisoned: a drop must not write it */
    int rc;
    __u64 old = MARLIN_RL_ONE_TOKEN / 2; /* timestamp 0, half a token; refill 0 */

    rc = rl_spend(old, 0, 0, 100 * MARLIN_RL_ONE_TOKEN, &next);
    CHECK_RET(MARLIN_DROP_RATELIMITED, rc);
    CHECK_EQ(0xdeadbeefdeadbeefULL, next);
}

MARLIN_TEST(rl_spend_negative_elapsed_resyncs)
{
    __u64 next;
    int rc;
    __u64 burst = 5 * MARLIN_RL_ONE_TOKEN;
    __u64 old = (__u64)100 << 32; /* stamped ahead of "now": drained */

    /* now(10) is behind old's timestamp(100) -- the wrap or a clock step
     * backwards. Without this resync a drained bucket would stay dropped
     * until "now" caught back up to the stale value.
     */
    rc = rl_spend(old, 10, MARLIN_RL_ONE_TOKEN, burst, &next);
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(burst - MARLIN_RL_ONE_TOKEN, next & MARLIN_RL_STATE_MASK);
    CHECK_EQ(10, next >> 32); /* resyncs to now, not to the stale timestamp */
}

MARLIN_TEST(rl_spend_tokens_above_lowered_burst_converge_down)
{
    __u64 next;
    int rc;
    __u64 old = 10 * MARLIN_RL_ONE_TOKEN; /* timestamp 0, above a burst since lowered */
    __u64 burst = 3 * MARLIN_RL_ONE_TOKEN;

    rc = rl_spend(old, 0, 0, burst, &next); /* elapsed 0: only the clamp acts */
    CHECK_RET(MARLIN_OK, rc);
    CHECK_EQ(burst - MARLIN_RL_ONE_TOKEN, next & MARLIN_RL_STATE_MASK);
}

/* ---- marlin_ratelimit(): the gates, the key, and the miss path --------- */

MARLIN_TEST(rl_null_ctx_aborts)
{
    hash_stub_reset(&ratelimit);
    CHECK_RET(MARLIN_ABORT_NULLREF, marlin_ratelimit(NULL));
    CHECK_EQ(0, hash_stub_lookup_count());
}

MARLIN_TEST(rl_disabled_admits_with_zero_lookups)
{
    struct marlin_ctx m;

    mctx_init(&m, AF_INET, 0, MARLIN_ACL_NONE); /* CFG_RL_ENABLE clear */
    mctx_src4(&m, RL_ADDR4(10, 50, 50, 1));

    CHECK_RET(MARLIN_OK, marlin_ratelimit(&m));
    CHECK_EQ(0, hash_stub_lookup_count());
}

MARLIN_TEST(rl_allow_verdict_admits_with_zero_lookups)
{
    struct marlin_ctx m;

    mctx_init(&m, AF_INET, CFG_RL_ENABLE, MARLIN_ACL_ALLOW);
    mctx_src4(&m, RL_ADDR4(10, 50, 50, 2));

    CHECK_RET(MARLIN_OK, marlin_ratelimit(&m));
    CHECK_EQ(0, hash_stub_lookup_count());
}

MARLIN_TEST(rl_key_is_byte_exact_with_pad_zeroed)
{
    struct marlin_ctx m;
    const struct rl_key *key;
    unsigned char expect[sizeof(struct rl_key)];

    mctx_init(&m, AF_INET, CFG_RL_ENABLE, MARLIN_ACL_NONE);
    mctx_src4(&m, RL_ADDR4(10, 50, 50, 3));

    marlin_ratelimit(&m); /* a miss, the only path that reaches a lookup */

    key = hash_stub_last_key();
    memset(expect, 0, sizeof(expect));
    memcpy(expect, &m.tuple.src[0], sizeof(m.tuple.src[0]));
    expect[16] = AF_INET;
    CHECK_MEM(expect, key, sizeof(expect));
}

MARLIN_TEST(rl_miss_inserts_bucket_charged_one_token)
{
    struct marlin_ctx m;
    const struct rl_key *key;
    struct rl_bucket *bucket;

    mctx_init(&m, AF_INET, CFG_RL_ENABLE, MARLIN_ACL_NONE);
    mctx_src4(&m, RL_ADDR4(10, 50, 50, 4));
    m.cfg.rl_burst = 3 * MARLIN_RL_ONE_TOKEN;

    CHECK_RET(MARLIN_OK, marlin_ratelimit(&m));
    CHECK_EQ(1, hash_stub_update_count());

    key = hash_stub_last_key();
    bucket = hash_stub_lookup(&ratelimit, key);
    CHECK_TRUE(bucket != NULL);
    CHECK_EQ(2 * MARLIN_RL_ONE_TOKEN, bucket->state & MARLIN_RL_STATE_MASK);
}

MARLIN_TEST(rl_insert_failure_still_admits)
{
    struct marlin_ctx m;

    mctx_init(&m, AF_INET, CFG_RL_ENABLE, MARLIN_ACL_NONE);
    mctx_src4(&m, RL_ADDR4(10, 50, 50, 5));
    m.cfg.rl_burst = 3 * MARLIN_RL_ONE_TOKEN;

    hash_stub_force_update_failure_once();

    /*
     * The fail-open half of the tradeoff docs/design/28-rate-limiting.md
     * names: fail-closed here would let a control plane starving the map
     * of memory become a denial of service in its own right. No bucket is
     * left behind for the next packet to find either.
     */
    CHECK_RET(MARLIN_OK, marlin_ratelimit(&m));
    CHECK_EQ(1, hash_stub_update_count());
    CHECK_TRUE(hash_stub_lookup(&ratelimit, hash_stub_last_key()) == NULL);
}

int main(void)
{
    return marlin_tests_main();
}
