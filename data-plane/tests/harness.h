/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Minimal test runner shared by the native (parser_test.c) and
 * bpf_prog_test_run (tests/packet/xdp_test.c) tiers. Each includes this
 * header into its own translation unit, so the storage below is file-static
 * rather than extern -- there is no sharing across TUs, only duplication.
 */

#pragma once

#include <stdio.h>
#include <string.h>

#include <linux/bpf.h>

#include <marlin/marlin.h>

#ifndef MARLIN_TEST_MAX
#define MARLIN_TEST_MAX 512
#endif

typedef void (*marlin_test_fn)(void);

struct marlin_test_case {
    const char *name;
    marlin_test_fn fn;
};

static struct marlin_test_case marlin_tests[MARLIN_TEST_MAX];
static int marlin_test_count;
static int marlin_case_failures;
static const char *marlin_case_skip_reason;

/* enum marlin_ret -> name, so a failure reads "expected MARLIN_DROP_..., got
 * MARLIN_OK" instead of "expected 9, got 0". Only the values parser.c can
 * return need a case; everything else falls through to the numeric default.
 * Unused in the bpf_prog_test_run tier, which never sees marlin_parse's raw
 * rc -- only the xdp_action it maps to and the drop_stats it increments.
 */
static __attribute__((unused)) const char *marlin_ret_name(int ret)
{
    switch(ret) {
        case MARLIN_OK:
            return "MARLIN_OK";
        case MARLIN_OK_TX:
            return "MARLIN_OK_TX";
        case MARLIN_OK_REDIRECT:
            return "MARLIN_OK_REDIRECT";
        case MARLIN_PASS_VIP_MISS:
            return "MARLIN_PASS_VIP_MISS";
        case MARLIN_PASS_ICMP_ECHO:
            return "MARLIN_PASS_ICMP_ECHO";
        case MARLIN_DROP_PARSE_ERROR:
            return "MARLIN_DROP_PARSE_ERROR";
        case MARLIN_DROP_UNSUPPORTED_PROTO:
            return "MARLIN_DROP_UNSUPPORTED_PROTO";
        case MARLIN_DROP_EXT_HDR_LIMIT:
            return "MARLIN_DROP_EXT_HDR_LIMIT";
        case MARLIN_DROP_ICMP_UNPARSEABLE:
            return "MARLIN_DROP_ICMP_UNPARSEABLE";
        case MARLIN_DROP_FRAG_UNSUPPORTED:
            return "MARLIN_DROP_FRAG_UNSUPPORTED";
        case MARLIN_PASS_NOT_FORWARDED:
            return "MARLIN_PASS_NOT_FORWARDED";
        default:
            return "<unknown enum marlin_ret>";
    }
}

/* enum xdp_action -> name, for the bpf_prog_test_run tier's verdict
 * assertions (tests/packet/xdp_test.c). linux/bpf.h defines the enum;
 * nothing here depends on marlin.h. Unused in the native tier, which asserts
 * enum marlin_ret directly and never runs a program through the kernel.
 */
static __attribute__((unused)) const char *xdp_action_name(int action)
{
    switch(action) {
        case XDP_ABORTED:
            return "XDP_ABORTED";
        case XDP_DROP:
            return "XDP_DROP";
        case XDP_PASS:
            return "XDP_PASS";
        case XDP_TX:
            return "XDP_TX";
        case XDP_REDIRECT:
            return "XDP_REDIRECT";
        default:
            return "<unknown xdp_action>";
    }
}

static void marlin_test_register(const char *name, marlin_test_fn fn)
{
    if(marlin_test_count < MARLIN_TEST_MAX) {
        marlin_tests[marlin_test_count].name = name;
        marlin_tests[marlin_test_count].fn = fn;
        marlin_test_count++;
    }
}

/* Registers `test_name` via a constructor, so listing every case in a table
 * by hand -- and forgetting to add one to it -- is not a way to lose coverage.
 */
#define MARLIN_TEST(test_name)                                                                                       \
    static void test_name(void);                                                                                    \
    __attribute__((constructor)) static void test_name##_register(void)                                             \
    {                                                                                                                \
        marlin_test_register(#test_name, test_name);                                                                 \
    }                                                                                                                \
    static void test_name(void)

#define MARLIN_FAIL(fmt, ...)                                                                                         \
    do {                                                                                                             \
        fprintf(stderr, "  FAIL %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__);                               \
        marlin_case_failures++;                                                                                      \
    } while(0)

/* Marks a case not yet implemented and returns from its body immediately --
 * placed first (and alone) in the body, so a skipped case never also runs
 * CHECK_* assertions against code that does not exist yet. `reason` should
 * name the doc line the missing behaviour is tracked against, so `make
 * packet-tests` output says exactly what is pending and where.
 */
#define MARLIN_SKIP(reason)                                                                                           \
    do {                                                                                                             \
        marlin_case_skip_reason = (reason);                                                                          \
        return;                                                                                                      \
    } while(0)

/* Casts both sides to a common signed width rather than comparing the raw
 * argument types: the fields under test span __u8 to __be32, and mismatched
 * signedness between "expected" (usually a literal int) and "actual" (usually
 * an unsigned struct field) would otherwise fail -Wsign-compare.
 */
#define CHECK_EQ(expected, actual)                                                                                    \
    do {                                                                                                             \
        long long marlin_check_actual_ = (long long)(actual);                                                        \
        long long marlin_check_expected_ = (long long)(expected);                                                    \
        if(marlin_check_actual_ != marlin_check_expected_) {                                                         \
            MARLIN_FAIL("expected %s == %lld, got %lld", #actual, marlin_check_expected_, marlin_check_actual_);     \
        }                                                                                                            \
    } while(0)

#define CHECK_RET(expected, actual)                                                                                   \
    do {                                                                                                             \
        int marlin_check_actual_ = (actual);                                                                         \
        int marlin_check_expected_ = (expected);                                                                     \
        if(marlin_check_actual_ != marlin_check_expected_) {                                                         \
            MARLIN_FAIL("expected %s, got %s", marlin_ret_name(marlin_check_expected_),                              \
                        marlin_ret_name(marlin_check_actual_));                                                      \
        }                                                                                                            \
    } while(0)

#define CHECK_XDP(expected, actual)                                                                                   \
    do {                                                                                                             \
        int marlin_check_actual_ = (actual);                                                                         \
        int marlin_check_expected_ = (expected);                                                                     \
        if(marlin_check_actual_ != marlin_check_expected_) {                                                         \
            MARLIN_FAIL("expected %s, got %s", xdp_action_name(marlin_check_expected_),                              \
                        xdp_action_name(marlin_check_actual_));                                                      \
        }                                                                                                            \
    } while(0)

#define CHECK_MEM(expected_ptr, actual_ptr, len)                                                                      \
    do {                                                                                                             \
        if(memcmp((expected_ptr), (actual_ptr), (len)) != 0) {                                                       \
            MARLIN_FAIL("memory mismatch: %s != %s", #expected_ptr, #actual_ptr);                                    \
        }                                                                                                            \
    } while(0)

#define CHECK_TRUE(cond)                                                                                              \
    do {                                                                                                             \
        if(!(cond)) {                                                                                                \
            MARLIN_FAIL("expected true: %s", #cond);                                                                  \
        }                                                                                                            \
    } while(0)

static int marlin_tests_main(void)
{
    int failed = 0;
    int skipped = 0;
    int i;

    for(i = 0; i < marlin_test_count; i++) {
        marlin_case_failures = 0;
        marlin_case_skip_reason = NULL;
        marlin_tests[i].fn();

        if(marlin_case_skip_reason != NULL) {
            /* Checked ahead of failures: MARLIN_SKIP returns before any
             * CHECK_* in the case body can run, so a skip is never also a
             * failure -- reporting both would double-count the same case.
             */
            printf("skip %s (%s)\n", marlin_tests[i].name, marlin_case_skip_reason);
            skipped++;
        } else if(marlin_case_failures == 0) {
            printf("ok   %s\n", marlin_tests[i].name);
        } else {
            printf("FAIL %s (%d check%s failed)\n", marlin_tests[i].name, marlin_case_failures,
                   marlin_case_failures == 1 ? "" : "s");
            failed++;
        }
    }

    if(skipped == 0) {
        printf("%d passed, %d failed, %d total\n", marlin_test_count - failed, failed, marlin_test_count);
    } else {
        printf("%d passed, %d failed, %d skipped, %d total\n", marlin_test_count - failed - skipped, failed, skipped,
               marlin_test_count);
    }

    return failed == 0 ? 0 : 1;
}
