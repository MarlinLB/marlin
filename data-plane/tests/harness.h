/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Minimal native test runner for the data-plane unit tests. Included once
 * from parser_test.c, so the storage below is file-static rather than
 * extern -- there is no second translation unit to share it with.
 */

#pragma once

#include <stdio.h>
#include <string.h>

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

/* enum marlin_ret -> name, so a failure reads "expected MARLIN_DROP_..., got
 * MARLIN_OK" instead of "expected 9, got 0". Only the values parser.c can
 * return need a case; everything else falls through to the numeric default.
 */
static const char *marlin_ret_name(int ret)
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
    int i;

    for(i = 0; i < marlin_test_count; i++) {
        marlin_case_failures = 0;
        marlin_tests[i].fn();

        if(marlin_case_failures == 0) {
            printf("ok   %s\n", marlin_tests[i].name);
        } else {
            printf("FAIL %s (%d check%s failed)\n", marlin_tests[i].name, marlin_case_failures,
                   marlin_case_failures == 1 ? "" : "s");
            failed++;
        }
    }

    printf("%d passed, %d failed, %d total\n", marlin_test_count - failed, failed, marlin_test_count);
    return failed == 0 ? 0 : 1;
}
