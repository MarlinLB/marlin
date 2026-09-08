/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Native unit tests for nexthop.c's NULL-argument abort convention. This
 * translation unit #includes the source directly, the same as acl_test.c.
 * Every other branch of marlin_nexthop_l2dsr()/marlin_nexthop_encapsulate()
 * needs a real FIB lookup or redirect, which is the packet tier's job
 * (tests/packet/xdp_test.c's nexthop_interim_* section) -- native coverage
 * here stops at the two branches neither tier could otherwise reach.
 */

#include <string.h>

#include "harness.h"

#include "../src/nexthop.c"

MARLIN_TEST(nexthop_l2dsr_null_ctx_aborts)
{
    struct marlin_ctx mctx;

    memset(&mctx, 0xAA, sizeof(mctx));
    CHECK_RET(MARLIN_ABORT_NULLREF, marlin_nexthop_l2dsr(NULL, &mctx));
}

MARLIN_TEST(nexthop_l2dsr_null_mctx_aborts)
{
    struct xdp_md md;

    memset(&md, 0, sizeof(md));
    CHECK_RET(MARLIN_ABORT_NULLREF, marlin_nexthop_l2dsr(&md, NULL));
}

MARLIN_TEST(nexthop_encapsulate_null_ctx_aborts)
{
    struct marlin_ctx mctx;

    memset(&mctx, 0xAA, sizeof(mctx));
    CHECK_RET(MARLIN_ABORT_NULLREF, marlin_nexthop_encapsulate(NULL, &mctx));
}

MARLIN_TEST(nexthop_encapsulate_null_mctx_aborts)
{
    struct xdp_md md;

    memset(&md, 0, sizeof(md));
    CHECK_RET(MARLIN_ABORT_NULLREF, marlin_nexthop_encapsulate(&md, NULL));
}

int main(void)
{
    return marlin_tests_main();
}
