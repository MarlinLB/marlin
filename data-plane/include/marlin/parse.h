/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Parsing utilities for the Marlin data plane application.
 */

#pragma once

#include <linux/bpf.h>

#include <marlin/marlin.h>

int marlin_parse(struct xdp_md *ctx, struct marlin_ctx *mctx);
