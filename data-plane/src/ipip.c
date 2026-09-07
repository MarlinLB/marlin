/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * IPIP encapsulation implementation.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <marlin/marlin.h>
#include <marlin/encap.h>

int marlin_ipip_encap_packet(struct xdp_md *ctx, struct marlin_ctx *mctx)
{
    if(ctx == NULL || mctx == NULL) {
        return MARLIN_ABORT_NULLREF;
    }

    return MARLIN_OK;
}
