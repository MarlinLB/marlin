/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Pure allocation and write ordering for VIP address groups, independent of map I/O.
 */

#pragma once

#if defined(__bpf__)
#error "include/marlind/ is host-only; do not include it from BPF sources"
#endif

#include <stdbool.h>

#include <linux/types.h>

#include <marlin/abi/defines.h>
#include <marlin/abi/types.h>

#define VIP_ALLOC_NUM_UNSET 0xffffffffU

/* One [[vip]] entry's identity: every address it holds, sharing one block. */
struct vip_alloc_entry {
    const struct vip_key *keys;
    __u32 key_count;
    __u32 vip_num; /* VIP_ALLOC_NUM_UNSET on input; filled on return */
};

/* One vip_map row read back at reconcile start. */
struct vip_alloc_baseline {
    struct vip_key key;
    __u32 vip_num;
};

struct vip_alloc_plan {
    __u32 write_order[MAX_VIPS]; /* indices into entries[] */
    __u32 write_count;
    __u32 release[MAX_VIPS];
    __u32 release_count;
};

/*
 * Entries must have unique keys, as enforced by configuration validation.
 * Prefers the first unclaimed baseline block matching an entry's keys, then
 * the lowest free number. A dependency cycle can move an entry to an
 * unreferenced final block instead of retaining its preferred number.
 *
 * Delete unwanted baseline keys first, then follow write_order: write each
 * entry's whole block before publishing all its keys. Only then zero release[].
 * This order moves foreign aliases away before their old block is overwritten.
 *
 * On failure all assignments are unset and the plan is empty; the caller
 * must report the failure before making any map writes.
 */
bool vip_alloc(struct vip_alloc_entry *entries, __u32 entry_count, const struct vip_alloc_baseline *baseline, __u32 baseline_count,
               struct vip_alloc_plan *plan);
