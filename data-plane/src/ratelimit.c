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

/*
 * A failed compare-and-swap already returns the current value, so only the
 * first read of a bucket needs this; re-reading inside the retry loop would
 * be redundant.
 */
#define MARLIN_READ_ONCE(x)  (*(const volatile __typeof__(x) *)&(x))

/*
 * Pure token-bucket step: refills `old` to `now` and spends one token,
 * reporting the result through `*next` rather than writing the map. Shared
 * by the miss path below, against a synthetic full bucket, and by the
 * compare-and-swap loop -- and callable from a native unit test with no map
 * or clock stub, since it reads no map and no packet byte.
 */
static __always_inline int rl_spend(__u64 old, __u64 now, __u64 rate, __u64 burst, __u64 *next)
{
    __u64 tokens;
    __u64 refill;
    __s64 elapsed;

    elapsed = (__s64)now - (__s64)(old >> 32);

    if(elapsed < 0) {
        /*
         * The 32-bit tick counter wrapped (roughly every 52 days of
         * uptime), or the clock moved backwards. Resyncing to a full
         * bucket costs the source nothing further than the resync itself:
         * clamping elapsed to zero instead would credit no refill, and
         * because a drained bucket never reaches the compare-and-swap
         * below, the stale future timestamp would never be overwritten --
         * the source would stay dropped until `now` caught back up to it.
         */
        refill = burst;
    } else {
        /* Clamped before the add: elapsed * rate can overflow 32 bits long
         * before the sum does.
         */
        refill = (__u64)elapsed * rate;
        if(refill > burst) {
            refill = burst;
        }
    }

    tokens = (old & MARLIN_RL_STATE_MASK) + refill;
    if(tokens > burst) {
        tokens = burst;
    }

    /*
     * Ahead of the exchange, deliberately: a drained bucket drops without
     * attempting a compare-and-swap, which is what makes retry exhaustion
     * unreachable for a source that is over budget.
     */
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

    /* An allow verdict is a metering exemption, not merely an ACL outcome
     * (docs/design/27-source-filtering.md).
     */
    if(mctx->acl_verdict == MARLIN_ACL_ALLOW) {
        return MARLIN_OK;
    }

    /* Pre-scaled by RL_TOKEN_SHIFT; the datapath performs no unit
     * conversion.
     */
    rate = mctx->cfg.rl_refill;
    burst = mctx->cfg.rl_burst;

    /* Coarse timestamp, masked to the 32 bits the state word carries. */
    now = (bpf_ktime_get_ns() >> RL_TICK_SHIFT) & MARLIN_RL_STATE_MASK;

    /* Byte-exact hash key: all 20 bytes zeroed first, pad included. */
    __builtin_memset(&key, 0, sizeof(key));
    key.family = mctx->tuple.family;
    __builtin_memcpy(key.addr, mctx->tuple.src, sizeof(key.addr));

    bucket = bpf_map_lookup_elem(&ratelimit, &key);
    if(bucket == NULL) {
        /*
         * First packet from this source, or its bucket was evicted. Charged
         * here (a full bucket less this packet) rather than left
         * uncharged, so every admitted packet spends a token without
         * exception -- bounded by one token per insertion.
         */
        rc = rl_spend((now << 32) | burst, now, rate, burst, &fresh.state);
        if(rc != MARLIN_OK) {
            return rc;
        }

        /*
         * BPF_ANY: two CPUs missing on the same key concurrently both
         * write a full bucket, so one loses its spent token; both
         * outcomes are bounded by the burst. An update failure admits
         * this packet anyway -- fail-closed here would let a control
         * plane starving the map of memory become a denial of service in
         * its own right -- but is counted, since it is otherwise invisible
         * and is exactly the signal the insert-cost measurement of
         * docs/design/28-rate-limiting.md wants.
         */
        if(bpf_map_update_elem(&ratelimit, &key, &fresh, BPF_ANY) != 0) {
            marlin_count(MARLIN_COUNT_RL_INSERT_FAILED);
        }

        return MARLIN_OK;
    }

    /*
     * Unrolled over a compile-time constant, bounded independently of the
     * verifier's bounded-loop support. A compare-and-swap loop suits the
     * contention pattern here better than bpf_spin_lock: a failed exchange
     * retries locally rather than serialising the CPUs contending an
     * attacker's bucket.
     *
     * `bucket` is held across every iteration; safe even if the LRU evicts
     * this element mid-loop, since map elements are RCU-freed and this
     * program runs inside the RCU read section.
     */
    old = MARLIN_READ_ONCE(bucket->state);

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
    }

    marlin_count(MARLIN_COUNT_RL_CAS_EXHAUSTED);
    return MARLIN_OK;
}
