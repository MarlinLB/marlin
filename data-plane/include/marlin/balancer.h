/**
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * The Marlin balancer header file.
 */

#pragma once

#include <linux/bpf.h>
#include <marlin/marlin.h>

int marlin_balancer_process(struct xdp_md *ctx, struct marlin_ctx *mctx);
