/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * vip_num allocation over MAX_VIPS blocks (docs/design/31-file-configuration.md
 * SS5, extended to address groups by docs/design/32-sctp.md): a pure function
 * over plain arrays, deliberately independent of marlind/conf.h so it links
 * and tests without libbpf, the same reasoning fwd_gen.h gives for staying
 * independent of it.
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

/*
 * Assigns entries[].vip_num in place: an entry takes the first baseline
 * vip_num any of its own keys still matches, in key order, skipping a value
 * already taken by an earlier entry -- which is what makes a merge keep one
 * of its two old blocks and a split hand the second half a fresh one.
 * Entries with no such match take the lowest block neither matched nor
 * already assigned.
 *
 * release/release_count receive every baseline vip_num no surviving entry
 * ended up using -- reconcile.c must write every entry's block and vip_map
 * keys before zeroing these, so a block a key still references is never
 * observed zeroed.
 *
 * Returns false, leaving every entry's vip_num VIP_ALLOC_NUM_UNSET, if
 * MAX_VIPS blocks cannot cover every entry -- the caller's diagnostic to
 * raise, not this function's.
 */
bool vip_alloc(struct vip_alloc_entry *entries, __u32 entry_count, const struct vip_alloc_baseline *baseline, __u32 baseline_count,
               __u32 release[MAX_VIPS], __u32 *release_count);
