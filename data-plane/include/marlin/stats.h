/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Counter and action-mapping helpers shared by every marlin_* call site.
 * A header rather than a translation unit: neither helper reads packet
 * bytes and an extra call frame for a map lookup and a switch does not earn
 * one (docs/design/03-translation-units.md).
 */

#pragma once

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <marlin/marlin.h>
#include <marlin/maps.h>

static __always_inline void marlin_count(int rc)
{
    __u32 key;
    __u64 *slot;

    if(rc < MARLIN_PASS_VIP_MISS || rc >= MARLIN_RET_MAX) {
        return;
    }

    key = (__u32)rc;
    slot = bpf_map_lookup_elem(&drop_stats, &key);

    if(slot != NULL) {
        *slot += 1; /* PERCPU_ARRAY: no other CPU touches this slot */
    }
}
