/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Minimal test runner shared by the native (parser_test.c) and
 * bpf_prog_test_run (tests/packet/xdp_*.c) tiers. Declarations only -- the
 * registry and the runner are defined once, in tests/support/harness.c, and
 * linked into both tiers' binaries (data-plane/Makefile), so a case
 * registered from any translation unit is one every tier's runner sees.
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

extern struct marlin_test_case marlin_tests[MARLIN_TEST_MAX];
extern int marlin_test_count;
extern int marlin_case_failures;
extern const char *marlin_case_skip_reason;

/*
 * enum marlin_ret -> name, so a failure reads "expected MARLIN_DROP_..., got
 * MARLIN_OK" instead of "expected 9, got 0". Only the values a translation
 * unit under native-tier test can return need a case; everything else falls
 * through to the numeric default. Unused in the bpf_prog_test_run tier,
 * which never sees marlin_parse's raw rc -- only the xdp_action it maps to
 * and the drop_stats it increments.
 */
const char *marlin_ret_name(int ret);

/*
 * enum xdp_action -> name, for the bpf_prog_test_run tier's verdict
 * assertions (tests/packet/xdp_*.c). linux/bpf.h defines the enum; nothing
 * here depends on marlin.h. Unused in the native tier, which asserts enum
 * marlin_ret directly and never runs a program through the kernel.
 */
const char *xdp_action_name(int action);

void marlin_test_register(const char *name, marlin_test_fn fn);

/*
 * Registers `test_name` via a constructor, so listing every case in a table
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

/*
 * Marks a case not yet implemented and returns from its body immediately --
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

/*
 * Casts both sides to a common signed width rather than comparing the raw
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

int marlin_tests_main(void);
