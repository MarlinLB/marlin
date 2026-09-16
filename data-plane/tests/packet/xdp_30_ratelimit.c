/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Rate-limiting cases (docs/design/28-rate-limiting.md): token bucket
 * admission, refill and burst clamping, resync on a future timestamp, and
 * the v4/v6 bucket keying split. udp_vip_seed()/build_udp4()/build_udp6()
 * come from xdp_fixture.h -- xdp_20_acl.c and xdp_70_acl_placement.c reuse
 * them too.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <linux/bpf.h>
#include <linux/in.h>

#include <marlin/marlin.h>

#include "../harness.h"
#include "../packet.h"
#include "maps.h"
#include "prog.h"
#include "xdp_fixture.h"

/* ---- Rate limit (docs/design/28-rate-limiting.md) --------------------- */

/*
 * ratelimit.c's own scaling constant, re-derived from the same RL_TOKEN_SHIFT
 * rather than exposed by any header -- it is a fixed unit conversion, not
 * the algorithm under test, the same reasoning that lets nh_check_frame()
 * below reimplement the IPv4 checksum independently.
 */
#define RL_ONE_TOKEN ((__u32)1U << RL_TOKEN_SHIFT)

static void seed_rl_cfg(__u32 flags, __u32 refill, __u32 burst)
{
    struct marlin_config cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.flags = flags;
    cfg.rl_refill = refill;
    cfg.rl_burst = burst;
    xdp_seed_config(&cfg);
}

static void rl_addr4(unsigned char out[16], __be32 addr)
{
    memset(out, 0, 16);
    memcpy(out, &addr, sizeof(addr));
}

/*
 * The same clock bpf_ktime_get_ns() reports, so a timestamp built from this
 * and fed to xdp_rl_seed() lands in the same tick unit ratelimit.c computes
 * `now` in -- bpf_prog_test_run has no way to fake the kernel's clock, so a
 * case that needs a *relative* offset from "now" reads this instead.
 */
static __u64 rl_now_ticks(void)
{
    struct timespec ts;

    if(clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        fprintf(stderr, "packet-tests: clock_gettime(CLOCK_MONOTONIC) failed: %s\n", strerror(errno));
        exit(1);
    }

    return (((__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec) >> RL_TICK_SHIFT) & 0xffffffffULL;
}

MARLIN_TEST(rl_disabled_does_not_meter)
{
    unsigned char addr16[16];
    __u64 after;
    struct xdp_run_result result;

    rl_addr4(addr16, ACL_ADDR4(10, 40, 40, 1));
    xdp_rl_clear();
    udp_vip_seed(VIP_RATELIMIT);
    seed_rl_cfg(0, 0, 0); /* CFG_RL_ENABLE clear */
    xdp_rl_seed(AF_INET, addr16, 0); /* drained, were it read at all */

    build_udp4(ACL_ADDR4(10, 40, 40, 1), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);

    CHECK_TRUE(xdp_rl_get(AF_INET, addr16, &after));
    CHECK_EQ(0, after); /* untouched: the gate returns before any map access */

    udp_vip_clear();
}

MARLIN_TEST(rl_vip_without_ratelimit_flag_is_not_metered)
{
    unsigned char addr16[16];
    __u64 after;
    struct xdp_run_result result;

    rl_addr4(addr16, ACL_ADDR4(10, 40, 40, 7));
    xdp_rl_clear();
    udp_vip_seed(0); /* VIP_RATELIMIT clear, config enabled */
    seed_rl_cfg(CFG_RL_ENABLE, 0, 3 * RL_ONE_TOKEN);
    xdp_rl_seed(AF_INET, addr16, 0);

    build_udp4(ACL_ADDR4(10, 40, 40, 7), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval); /* a drained bucket would have dropped it */

    CHECK_TRUE(xdp_rl_get(AF_INET, addr16, &after));
    CHECK_EQ(0, after);

    udp_vip_clear();
}

MARLIN_TEST(rl_first_packet_inserts_charged_bucket)
{
    unsigned char addr16[16];
    __u64 state;
    struct xdp_run_result result;

    rl_addr4(addr16, ACL_ADDR4(10, 40, 40, 2));
    xdp_rl_clear();
    udp_vip_seed(VIP_RATELIMIT);
    seed_rl_cfg(CFG_RL_ENABLE, 0, 3 * RL_ONE_TOKEN);

    build_udp4(ACL_ADDR4(10, 40, 40, 2), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);

    CHECK_TRUE(xdp_rl_get(AF_INET, addr16, &state));
    CHECK_EQ(2 * RL_ONE_TOKEN, state & 0xffffffffULL); /* burst less the one token this packet spent */

    udp_vip_clear();
}

MARLIN_TEST(rl_fixed_budget_admits_n_then_drops)
{
    unsigned char addr16[16];
    __u64 before;
    struct xdp_run_result result;
    int i;

    rl_addr4(addr16, ACL_ADDR4(10, 40, 40, 3));
    xdp_rl_clear();
    udp_vip_seed(VIP_RATELIMIT);
    /* refill 0: a fixed budget with no time dependence, so the Nth packet
     * always admits and the N+1th always drops regardless of how long the
     * case takes to run.
     */
    seed_rl_cfg(CFG_RL_ENABLE, 0, 3 * RL_ONE_TOKEN);
    before = xdp_drop_stats_total(MARLIN_DROP_RATELIMITED);

    build_udp4(ACL_ADDR4(10, 40, 40, 3), V4_DST);

    for(i = 0; i < 3; i++) {
        result = run_current_packet();
        CHECK_EQ(0, result.err);
        CHECK_XDP(XDP_TX, result.retval);
    }

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_RATELIMITED));

    udp_vip_clear();
}

MARLIN_TEST(rl_refill_clamps_to_burst)
{
    unsigned char addr16[16];
    __u64 state;
    struct xdp_run_result result;

    rl_addr4(addr16, ACL_ADDR4(10, 40, 40, 4));
    xdp_rl_clear();
    udp_vip_seed(VIP_RATELIMIT);
    /* A rate high enough that elapsed * rate overflows 32 bits after even a
     * handful of ticks; rl_spend()'s clamp before the add is what keeps
     * this exact rather than wrapping. Robust to the two ways a stale
     * timestamp of 0 can be read: as an ordinary (very large) elapsed, or,
     * on a long-uptime test host, as a 32-bit-wrapped "future" timestamp --
     * both paths in rl_spend() converge on a full bucket.
     */
    seed_rl_cfg(CFG_RL_ENABLE, 1U << 30, 5 * RL_ONE_TOKEN);
    xdp_rl_seed(AF_INET, addr16, 0);

    build_udp4(ACL_ADDR4(10, 40, 40, 4), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);

    CHECK_TRUE(xdp_rl_get(AF_INET, addr16, &state));
    CHECK_EQ(4 * RL_ONE_TOKEN, state & 0xffffffffULL); /* clamped to burst, less the one token spent */

    udp_vip_clear();
}

MARLIN_TEST(rl_future_timestamp_resyncs)
{
    unsigned char addr16[16];
    __u64 state;
    __u64 future_state;
    struct xdp_run_result result;

    rl_addr4(addr16, ACL_ADDR4(10, 40, 40, 5));
    xdp_rl_clear();
    udp_vip_seed(VIP_RATELIMIT);
    seed_rl_cfg(CFG_RL_ENABLE, 0, 5 * RL_ONE_TOKEN);

    /*
     * A drained bucket stamped ahead of "now" -- what the 32-bit tick
     * counter's wrap produces roughly every 52 days of uptime, or a clock
     * stepped backwards. Without rl_spend()'s resync this source would stay
     * dropped until "now" caught back up to the stale timestamp; 1,000,000
     * ticks (~17.5 minutes) puts it far enough ahead that no plausible test
     * run duration closes the gap on its own.
     */
    future_state = (rl_now_ticks() + 1000000ULL) << 32; /* tokens: 0 */
    xdp_rl_seed(AF_INET, addr16, future_state);

    build_udp4(ACL_ADDR4(10, 40, 40, 5), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);

    CHECK_TRUE(xdp_rl_get(AF_INET, addr16, &state));
    CHECK_EQ(4 * RL_ONE_TOKEN, state & 0xffffffffULL);

    udp_vip_clear();
}

MARLIN_TEST(rl_v4_and_v6_same_bytes_are_distinct_buckets)
{
    static const unsigned char addr16[16] = {0x0a, 0x01, 0x02, 0x03};
    struct xdp_run_result result;

    xdp_rl_clear();
    udp_vip_seed(VIP_RATELIMIT);
    seed_rl_cfg(CFG_RL_ENABLE, 0, 3 * RL_ONE_TOKEN);

    /* 10.1.2.3 and the IPv6 address 0a01:0203:: share these exact 16 bytes
     * (docs/design/28-rate-limiting.md); family is what keeps them in
     * separate buckets.
     */
    xdp_rl_seed(AF_INET, addr16, 0); /* v4 bucket: drained */
    xdp_rl_seed(AF_INET6, addr16, 3 * RL_ONE_TOKEN); /* v6 bucket, same bytes: full */

    build_udp4(ACL_ADDR4(10, 1, 2, 3), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval); /* the v4 bucket is drained */

    build_udp6(addr16, DST6);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval); /* the v6 bucket, same bytes, is full */

    udp_vip_clear();
}

MARLIN_TEST(rl_allow_verdict_survives_rate_limiter)
{
    unsigned char addr16[16];
    __u64 after;
    struct marlin_config cfg;
    struct xdp_run_result result;

    rl_addr4(addr16, ACL_ADDR4(10, 40, 40, 6));
    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_allow_v4", 32, ACL_ADDR4(10, 40, 40, 6), 1);
    xdp_rl_clear();
    xdp_rl_seed(AF_INET, addr16, 0); /* drained: any further packet would ratelimit if metered at all */
    udp_vip_seed(VIP_ACL | VIP_RATELIMIT);

    memset(&cfg, 0, sizeof(cfg));
    cfg.flags = CFG_ACL_ENABLE | CFG_RL_ENABLE;
    cfg.acl_lists = ACL_LISTS_BIT(ACL_LIST_ALLOW, ACL_FAMILY_V4);
    cfg.rl_refill = 0;
    cfg.rl_burst = 3 * RL_ONE_TOKEN;
    xdp_seed_config(&cfg);

    build_udp4(ACL_ADDR4(10, 40, 40, 6), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval); /* the allow verdict, not an empty bucket, is why */

    CHECK_TRUE(xdp_rl_get(AF_INET, addr16, &after));
    CHECK_EQ(0, after); /* untouched: an allow verdict returns before any map access */

    udp_vip_clear();

    /*
     * config is process-global and outlives a case (seed_encap_cfg's
     * comment above). Unlike a leftover ACL rule, CFG_RL_ENABLE affects
     * every source, not just ones a rule names: left set here, every test
     * after this one that never reseeds config -- the nexthop/FIB cases
     * below, which all send from the same V4_SRC -- drains that source's
     * bucket a token at a time until one drops for ratelimited instead of
     * the reason it meant to test. Reset to the all-off state every test
     * before this section assumed.
     */
    memset(&cfg, 0, sizeof(cfg));
    xdp_seed_config(&cfg);
}
