/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 */

#pragma once

#include <linux/bpf.h>

#include <marlin/marlin.h>

int marlin_nexthop_encapsulate(struct xdp_md *ctx, struct marlin_ctx *mctx);
int marlin_nexthop_l2dsr(struct xdp_md *ctx, struct marlin_ctx *mctx);
