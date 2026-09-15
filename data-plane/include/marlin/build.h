/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Build identity embedded in marlin.bpf.o, read by marlind and verifier_stats
 * from the object file -- see docs/design/02-architecture.md on why this is
 * a .rodata global rather than a config-map field.
 */

#pragma once

#include <linux/types.h>

#define MARLIN_BUILD_MAGIC 0x4d524c4eU /* "MRLN" */
#define MARLIN_VERSION_MAX 64

struct marlin_build {
    __u32 magic;
    char version[MARLIN_VERSION_MAX];
};

_Static_assert(sizeof(struct marlin_build) == 68, "marlin_build must stay 68 bytes");
