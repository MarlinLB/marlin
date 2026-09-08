/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Native unit tests for mtu.h. marlin_frame_fits() takes only marlin_ctx,
 * so every case here is a struct literal: no kernel, no root, no frame to
 * build.
 */

#include <string.h>

#include <marlin/mtu.h>

#include "harness.h"

static void mctx_init(struct marlin_ctx *mctx, __u16 pkt_len, __u16 max_frame)
{
    memset(mctx, 0, sizeof(*mctx));
    mctx->pkt_len = pkt_len;
    mctx->cfg.max_frame = max_frame;
}

MARLIN_TEST(frame_fits_max_frame_zero_disables_the_check)
{
    struct marlin_ctx m;

    /*
     * An unconfigured max_frame must forward rather than drop every
     * encapsulated packet (docs/design/23-mtu.md), regardless of overhead
     * or how large pkt_len already is.
     */
    mctx_init(&m, 65000, 0);
    CHECK_RET(MARLIN_OK, marlin_frame_fits(&m, MARLIN_OVERHEAD_VXLAN));
}

MARLIN_TEST(frame_fits_ipip_boundary_passes_and_boundary_plus_one_drops)
{
    struct marlin_ctx m;

    mctx_init(&m, 1500 - MARLIN_OVERHEAD_IPIP, 1500);
    CHECK_RET(MARLIN_OK, marlin_frame_fits(&m, MARLIN_OVERHEAD_IPIP));

    mctx_init(&m, 1500 - MARLIN_OVERHEAD_IPIP + 1, 1500);
    CHECK_RET(MARLIN_DROP_FRAME_TOO_BIG, marlin_frame_fits(&m, MARLIN_OVERHEAD_IPIP));
}

MARLIN_TEST(frame_fits_gue_boundary_passes_and_boundary_plus_one_drops)
{
    struct marlin_ctx m;

    mctx_init(&m, 1500 - MARLIN_OVERHEAD_GUE, 1500);
    CHECK_RET(MARLIN_OK, marlin_frame_fits(&m, MARLIN_OVERHEAD_GUE));

    mctx_init(&m, 1500 - MARLIN_OVERHEAD_GUE + 1, 1500);
    CHECK_RET(MARLIN_DROP_FRAME_TOO_BIG, marlin_frame_fits(&m, MARLIN_OVERHEAD_GUE));
}

MARLIN_TEST(frame_fits_vxlan_boundary_passes_and_boundary_plus_one_drops)
{
    struct marlin_ctx m;

    mctx_init(&m, 1500 - MARLIN_OVERHEAD_VXLAN, 1500);
    CHECK_RET(MARLIN_OK, marlin_frame_fits(&m, MARLIN_OVERHEAD_VXLAN));

    mctx_init(&m, 1500 - MARLIN_OVERHEAD_VXLAN + 1, 1500);
    CHECK_RET(MARLIN_DROP_FRAME_TOO_BIG, marlin_frame_fits(&m, MARLIN_OVERHEAD_VXLAN));
}

MARLIN_TEST(frame_fits_pkt_len_near_u16_max_does_not_wrap)
{
    struct marlin_ctx m;

    /*
     * pkt_len + overhead is done in __u32 specifically so this does not
     * wrap back under max_frame and produce a false pass.
     */
    mctx_init(&m, 65530, 1500);
    CHECK_RET(MARLIN_DROP_FRAME_TOO_BIG, marlin_frame_fits(&m, MARLIN_OVERHEAD_VXLAN));
}

int main(void)
{
    return marlin_tests_main();
}
