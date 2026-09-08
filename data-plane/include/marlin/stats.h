/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Counter and action-mapping helpers. Header only: no packet I/O,
 * and avoiding an extra call frame for map lookup and switch.
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
