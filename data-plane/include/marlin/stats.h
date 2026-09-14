/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Statistics helpers. Header only: no packet I/O, and avoiding an extra
 * call frame for map lookup and update.
 */

#pragma once

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <marlin/marlin.h>
#include <marlin/abi/defines.h>
#include <marlin/maps.h>

static __always_inline void marlin_stats_reason(int rc)
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

/*
 * Shared by marlin_stats_vip() and marlin_stats_backend(): both are a
 * packets+bytes update against a PERCPU_ARRAY, differing only in which map
 * and which bound. `map` resolves to a constant after inlining, so the
 * verifier sees a direct reference rather than an indirect one.
 */
static __always_inline void marlin_stats_add(void *map, __u32 key, __u32 len)
{
    struct stats *slot = bpf_map_lookup_elem(map, &key);

    if(slot != NULL) {
        slot->packets += 1; /* PERCPU_ARRAY: no other CPU touches this slot */
        slot->bytes += len;
    }
}

/* `len` is the ingress frame length, so all four modes stay comparable. */
static __always_inline void marlin_stats_vip(__u32 vip_num, __u32 len)
{
    if(vip_num >= MAX_VIPS) {
        return;
    }

    marlin_stats_add(&vip_stats, vip_num, len);
}

/* Bumped at selection, not on successful forward: docs/design/22-observability.md. */
static __always_inline void marlin_stats_backend(__u32 backend_id, __u32 len)
{
    if(backend_id >= MAX_BACKENDS) {
        return;
    }

    marlin_stats_add(&backend_stats, backend_id, len);
}
