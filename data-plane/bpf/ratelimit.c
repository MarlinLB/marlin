/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Rate limit implementation.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <marlin/marlin.h>
#include <marlin/ratelimit.h>
#include <marlin/abi/defines.h>
#include <marlin/acl.h>
#include <marlin/maps.h>
#include <marlin/stats.h>

#define MARLIN_RL_ONE_TOKEN  ((__u64)1 << RL_TOKEN_SHIFT)

#define MARLIN_RL_STATE_MASK 0xffffffffULL /* shared by state[31:0] tokens and state[63:32] timestamp */

#define MARLIN_READ_ONCE(x)  (*(const volatile __typeof__(x) *)&(x))

static __always_inline int rl_spend(__u64 old, __u64 now, __u64 rate, __u64 burst, __u64 *next)
{
    __u64 tokens;
    __u64 refill;
    __s64 elapsed;

    elapsed = (__s64)now - (__s64)(old >> 32);

    if(elapsed < 0) {
        refill = burst;
    } else {
        refill = (__u64)elapsed * rate;
        if(refill > burst) {
            refill = burst;
        }
    }

    tokens = (old & MARLIN_RL_STATE_MASK) + refill;
    if(tokens > burst) {
        tokens = burst;
    }

    if(tokens < MARLIN_RL_ONE_TOKEN) {
        return MARLIN_DROP_RATELIMITED;
    }

    tokens -= MARLIN_RL_ONE_TOKEN;
    *next = (now << 32) | (tokens & MARLIN_RL_STATE_MASK);
    return MARLIN_OK;
}

int marlin_ratelimit(const struct marlin_ctx *mctx)
{
    struct rl_bucket *bucket;
    struct rl_bucket fresh;
    struct rl_key key;
    __u64 now;
    __u64 burst;
    __u64 rate;
    __u64 old;
    int retry;
    int rc;

    if(mctx == NULL) {
        return MARLIN_ABORT_NULLREF;
    }

    if((mctx->cfg.flags & CFG_RL_ENABLE) == 0U) {
        return MARLIN_OK;
    }

    if(mctx->acl_verdict == MARLIN_ACL_ALLOW) {
        return MARLIN_OK;
    }

    rate = mctx->cfg.rl_refill;
    burst = mctx->cfg.rl_burst;

    /* Byte-exact hash key: all 20 bytes zeroed first, pad included. */
    __builtin_memset(&key, 0, sizeof(key));
    key.family = mctx->tuple.family;
    __builtin_memcpy(key.addr, mctx->tuple.src, sizeof(key.addr));

    bucket = bpf_map_lookup_elem(&ratelimit, &key);
    if(bucket == NULL) {
        /* Coarse timestamp, masked to the 32 bits the state word carries. */
        now = (bpf_ktime_get_ns() >> RL_TICK_SHIFT) & MARLIN_RL_STATE_MASK;

        rc = rl_spend((now << 32) | burst, now, rate, burst, &fresh.state);
        if(rc != MARLIN_OK) {
            return rc;
        }

        if(bpf_map_update_elem(&ratelimit, &key, &fresh, BPF_ANY) != 0) {
            marlin_stats_reason(MARLIN_COUNT_RL_INSERT_FAILED);
        }

        return MARLIN_OK;
    }

    old = MARLIN_READ_ONCE(bucket->state);
    now = (bpf_ktime_get_ns() >> RL_TICK_SHIFT) & MARLIN_RL_STATE_MASK;

#pragma clang loop unroll(full)
    for(retry = 0; retry < RL_CAS_RETRIES; retry++) {
        __u64 next;
        __u64 prev;

        rc = rl_spend(old, now, rate, burst, &next);
        if(rc != MARLIN_OK) {
            return rc;
        }

        prev = __sync_val_compare_and_swap(&bucket->state, old, next);
        if(prev == old) {
            return MARLIN_OK;
        }

        old = prev;

        /* The winning CPU may have advanced the bucket past this attempt. */
        now = (bpf_ktime_get_ns() >> RL_TICK_SHIFT) & MARLIN_RL_STATE_MASK;
    }

    marlin_stats_reason(MARLIN_COUNT_RL_CAS_EXHAUSTED);
    return MARLIN_OK;
}
