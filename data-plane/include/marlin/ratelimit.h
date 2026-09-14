/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Rate limit definitions.
 */

#pragma once

#include <marlin/marlin.h>

int marlin_ratelimit(const struct marlin_ctx *mctx);
