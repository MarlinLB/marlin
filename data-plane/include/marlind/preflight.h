/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Preflight -- asserts host state, never configures it. Mirrors the checks
 * formerly in deploy/marlin-load.sh's load(), minus the already-attached
 * check: bpf_link_create() reports that itself, atomically.
 */

#pragma once

#include <marlind/marlind.h>

void preflight(const struct config *cfg);
