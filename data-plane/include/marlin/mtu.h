/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * The frame_too_big check of docs/design/23-mtu.md: the zero-lookup encap
 * default performs no bpf_fib_lookup(), so RET_FRAG_NEEDED never fires for
 * it, and something has to catch an emitted frame that will not fit the
 * egress MTU. A header, not a translation unit: it takes only mctx -- a BTF
 * struct pointer already resolved by the caller -- and reads no packet
 * bytes (docs/design/03-translation-units.md).
 */

#pragma once

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

#include <marlin/marlin.h>

static __always_inline int marlin_frame_fits(const struct marlin_ctx *mctx, __u16 overhead)
{
    if(mctx->cfg.max_frame == 0) {
        return MARLIN_OK;
    }

    if((__u32)mctx->pkt_len + overhead > mctx->cfg.max_frame) {
        return MARLIN_DROP_FRAME_TOO_BIG;
    }

    return MARLIN_OK;
}
