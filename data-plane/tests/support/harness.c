/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Definitions for tests/harness.h's registry and runner. Built once per tier
 * (data-plane/Makefile) rather than included inline: the packet tier splits
 * its cases across several translation units, and a per-TU registry (the
 * previous header-only, file-static design) would silently run only whichever
 * TU happened to define main().
 */

#include <stdlib.h>

#include "../harness.h"

struct marlin_test_case marlin_tests[MARLIN_TEST_MAX];
int marlin_test_count;
int marlin_case_failures;
const char *marlin_case_skip_reason;

const char *marlin_ret_name(int ret)
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
        case MARLIN_DROP_ACL_BLOCKED:
            return "MARLIN_DROP_ACL_BLOCKED";
        case MARLIN_DROP_ADJUST_HEAD:
            return "MARLIN_DROP_ADJUST_HEAD";
        case MARLIN_DROP_ENCAP_LENGTH:
            return "MARLIN_DROP_ENCAP_LENGTH";
        case MARLIN_DROP_FRAME_TOO_BIG:
            return "MARLIN_DROP_FRAME_TOO_BIG";
        case MARLIN_ABORT_NULLREF:
            return "MARLIN_ABORT_NULLREF";
        default:
            return "<unknown enum marlin_ret>";
    }
}

const char *xdp_action_name(int action)
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

/*
 * Fatal rather than silently dropping the case: with the registry shared
 * across translation units (the header comment above), overflow here would
 * otherwise mean a real test file compiled and linked cleanly but never ran,
 * exactly the silent-loss mode this split is meant to make unreachable.
 */
void marlin_test_register(const char *name, marlin_test_fn fn)
{
    if(marlin_test_count >= MARLIN_TEST_MAX) {
        fprintf(stderr, "harness.c: MARLIN_TEST_MAX (%d) exceeded registering \"%s\"\n", MARLIN_TEST_MAX, name);
        abort();
    }

    marlin_tests[marlin_test_count].name = name;
    marlin_tests[marlin_test_count].fn = fn;
    marlin_test_count++;
}

int marlin_tests_main(void)
{
    int failed = 0;
    int skipped = 0;
    int i;

    for(i = 0; i < marlin_test_count; i++) {
        marlin_case_failures = 0;
        marlin_case_skip_reason = NULL;
        marlin_tests[i].fn();

        if(marlin_case_skip_reason != NULL) {
            /*
             * Checked ahead of failures: MARLIN_SKIP returns before any
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
