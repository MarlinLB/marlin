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

struct vip_alloc_reference {
    __u32 entry;
    __u32 num;
};

static __u32 vip_alloc_owner(const struct vip_alloc_entry *entries, __u32 entry_count, const struct vip_key *key)
{
    for(__u32 i = 0; i < entry_count; i++) {
        for(__u32 k = 0; k < entries[i].key_count; k++) {
            if(vip_alloc_key_eq(&entries[i].keys[k], key)) {
                return i;
            }
        }
    }
    return VIP_ALLOC_NUM_UNSET;
}

static bool vip_alloc_block_ready(const struct vip_alloc_reference *refs, __u32 count, __u32 num, __u32 entry)
{
    for(__u32 i = 0; i < count; i++) {
        if(refs[i].num == num && refs[i].entry != entry) {
            return false;
        }
    }
    return true;
}

static __u32 vip_alloc_match(const struct vip_alloc_entry *entry, const struct vip_alloc_baseline *baseline, __u32 baseline_count,
                             const bool used[MAX_VIPS])
{
    for(__u32 k = 0; k < entry->key_count; k++) {
        for(__u32 b = 0; b < baseline_count; b++) {
            if(!used[baseline[b].vip_num] && vip_alloc_key_eq(&entry->keys[k], &baseline[b].key)) {
                return baseline[b].vip_num;
            }
        }
    }
    return VIP_ALLOC_NUM_UNSET;
}

static bool vip_alloc_claim(struct vip_alloc_entry *entries, __u32 entry_count, const struct vip_alloc_baseline *baseline,
                            __u32 baseline_count, bool used[MAX_VIPS])
{
    for(__u32 i = 0; i < entry_count; i++) {
        struct vip_alloc_entry *entry = &entries[i];

        entry->vip_num = vip_alloc_match(entry, baseline, baseline_count, used);
        if(entry->vip_num != VIP_ALLOC_NUM_UNSET) {
            used[entry->vip_num] = true;
        }
    }

    for(__u32 i = 0; i < entry_count; i++) {
        struct vip_alloc_entry *entry = &entries[i];

        if(entry->vip_num != VIP_ALLOC_NUM_UNSET) {
            continue;
        }

        __u32 num;

        for(num = 0; num < MAX_VIPS; num++) {
            if(!used[num]) {
                break;
            }
        }
        if(num == MAX_VIPS) {
            return false;
        }

        entry->vip_num = num;
        used[num] = true;
    }
    return true;
}

static bool vip_alloc_relocate(struct vip_alloc_entry *entry, const struct vip_alloc_reference *refs, __u32 ref_count,
                               bool used[MAX_VIPS])
{
    for(__u32 num = 0; num < MAX_VIPS; num++) {
        if(!used[num] && vip_alloc_block_ready(refs, ref_count, num, VIP_ALLOC_NUM_UNSET)) {
            used[entry->vip_num] = false;
            entry->vip_num = num;
            used[num] = true;
            return true;
        }
    }
    return false;
}

static bool vip_alloc_order(struct vip_alloc_entry *entries, __u32 entry_count, struct vip_alloc_reference *refs, __u32 ref_count,
                            bool used[MAX_VIPS], struct vip_alloc_plan *plan)
{
    bool written[MAX_VIPS] = { false };

    while(plan->write_count < entry_count) {
        __u32 entry;

        for(entry = 0; entry < entry_count; entry++) {
            if(!written[entry] && vip_alloc_block_ready(refs, ref_count, entries[entry].vip_num, entry)) {
                break;
            }
        }
        if(entry == entry_count) {
            /*
             * Cyclic regrouping has no safe in-place first write. Publish
             * one entry in an unreferenced final block to break the cycle.
             */
            for(entry = 0; entry < entry_count && written[entry]; entry++) {
            }
            if(entry == entry_count || !vip_alloc_relocate(&entries[entry], refs, ref_count, used)) {
                return false;
            }
        }

        plan->write_order[plan->write_count++] = entry;
        written[entry] = true;
        for(__u32 r = 0; r < ref_count; r++) {
            if(refs[r].entry == entry) {
                refs[r].num = entries[entry].vip_num;
            }
        }
    }
    return true;
}

bool vip_alloc(struct vip_alloc_entry *entries, __u32 entry_count, const struct vip_alloc_baseline *baseline, __u32 baseline_count,
               struct vip_alloc_plan *plan)
{
    bool used[MAX_VIPS] = { false };
    bool baseline_nums[MAX_VIPS] = { false };
    struct vip_alloc_reference refs[MAX_VIPS];
    __u32 ref_count = 0;
    __u32 key_count = 0;

    memset(plan, 0, sizeof(*plan));
    for(__u32 i = 0; i < entry_count; i++) {
        entries[i].vip_num = VIP_ALLOC_NUM_UNSET;
    }
    if(entry_count > MAX_VIPS || baseline_count > MAX_VIPS) {
        return false;
    }
    for(__u32 i = 0; i < entry_count; i++) {
        if(entries[i].keys == NULL || entries[i].key_count == 0 || entries[i].key_count > MAX_VIPS - key_count) {
            return false;
        }
        key_count += entries[i].key_count;
    }
    for(__u32 b = 0; b < baseline_count; b++) {
        __u32 owner;

        if(baseline[b].vip_num >= MAX_VIPS) {
            return false;
        }
        baseline_nums[baseline[b].vip_num] = true;
        owner = vip_alloc_owner(entries, entry_count, &baseline[b].key);
        if(owner != VIP_ALLOC_NUM_UNSET) {
            refs[ref_count].entry = owner;
            refs[ref_count++].num = baseline[b].vip_num;
        }
    }
    if(!vip_alloc_claim(entries, entry_count, baseline, baseline_count, used) ||
       !vip_alloc_order(entries, entry_count, refs, ref_count, used, plan)) {
        for(__u32 i = 0; i < entry_count; i++) {
            entries[i].vip_num = VIP_ALLOC_NUM_UNSET;
        }
        memset(plan, 0, sizeof(*plan));
        return false;
    }
    for(__u32 num = 0; num < MAX_VIPS; num++) {
        if(baseline_nums[num] && !used[num]) {
            plan->release[plan->release_count++] = num;
        }
    }

    return true;
}
