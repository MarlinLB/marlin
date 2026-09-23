/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Definitions for vip_alloc.h.
 */

#include <string.h>

#include <marlind/vip_alloc.h>

static bool vip_alloc_key_eq(const struct vip_key *lhs, const struct vip_key *rhs)
{
    if(lhs->family != rhs->family || lhs->port != rhs->port || lhs->proto != rhs->proto) {
        return false;
    }
    if(lhs->family == AF_INET) {
        return lhs->addr4 == rhs->addr4;
    }
    return memcmp(lhs->addr6, rhs->addr6, sizeof(lhs->addr6)) == 0;
}

bool vip_alloc(struct vip_alloc_entry *entries, __u32 entry_count, const struct vip_alloc_baseline *baseline, __u32 baseline_count,
               __u32 release[MAX_VIPS], __u32 *release_count)
{
    bool used[MAX_VIPS] = { false };
    bool baseline_nums[MAX_VIPS] = { false };

    for(__u32 i = 0; i < entry_count; i++) {
        entries[i].vip_num = VIP_ALLOC_NUM_UNSET;
    }

    for(__u32 i = 0; i < entry_count; i++) {
        struct vip_alloc_entry *e = &entries[i];

        for(__u32 k = 0; k < e->key_count && e->vip_num == VIP_ALLOC_NUM_UNSET; k++) {
            for(__u32 b = 0; b < baseline_count; b++) {
                if(baseline[b].vip_num >= MAX_VIPS || used[baseline[b].vip_num]) {
                    continue;
                }
                if(vip_alloc_key_eq(&e->keys[k], &baseline[b].key)) {
                    e->vip_num = baseline[b].vip_num;
                    break;
                }
            }
        }

        if(e->vip_num != VIP_ALLOC_NUM_UNSET) {
            used[e->vip_num] = true;
        }
    }

    for(__u32 i = 0; i < entry_count; i++) {
        struct vip_alloc_entry *e = &entries[i];

        if(e->vip_num != VIP_ALLOC_NUM_UNSET) {
            continue;
        }

        __u32 num;

        for(num = 0; num < MAX_VIPS; num++) {
            if(!used[num]) {
                break;
            }
        }
        if(num == MAX_VIPS) {
            for(__u32 j = 0; j < entry_count; j++) {
                entries[j].vip_num = VIP_ALLOC_NUM_UNSET;
            }
            return false;
        }

        e->vip_num = num;
        used[num] = true;
    }

    for(__u32 b = 0; b < baseline_count; b++) {
        if(baseline[b].vip_num < MAX_VIPS) {
            baseline_nums[baseline[b].vip_num] = true;
        }
    }

    *release_count = 0;
    for(__u32 num = 0; num < MAX_VIPS; num++) {
        if(baseline_nums[num] && !used[num]) {
            release[(*release_count)++] = num;
        }
    }

    return true;
}
