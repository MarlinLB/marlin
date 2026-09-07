/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Frame size checking for encapsulated packets. Validates that the final
 * frame size does not exceed the egress MTU. Header only: takes a resolved
 * BTF struct pointer and reads no packet bytes.
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
