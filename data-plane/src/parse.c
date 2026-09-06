/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Parsing implementation for the Marlin data plane application.
 */

#include <linux/bpf.h>

#include <marlin/abi/types.h>
#include <marlin/compiler.h>
#include <marlin/parse.h>


int marlin_parse(struct xdp_md *ctx, struct marlin_ctx *mctx)
{
    return MARLIN_OK;
}
