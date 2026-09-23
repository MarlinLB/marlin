/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Native tests for VIP allocation and alias-safe write ordering.
 */

#include <string.h>

#include <linux/in.h>

#include "../marlind/vip_alloc.c"

#include "harness.h"

static void key4(struct vip_key *key, __be32 addr, __u16 port, __u8 proto)
{
    memset(key, 0, sizeof(*key));
    key->addr4 = addr;
    key->port = port;
    key->proto = proto;
    key->family = AF_INET;
}

#define ADDR_A 0x01010101U
#define ADDR_B 0x02020202U
#define ADDR_C 0x03030303U

MARLIN_TEST(surviving_key_keeps_its_block)
{
    struct vip_key k;
    struct vip_alloc_entry entries[1];
    struct vip_alloc_baseline baseline[1];
    struct vip_alloc_plan plan;

    key4(&k, ADDR_A, 0, IPPROTO_TCP);
    baseline[0].key = k;
    baseline[0].vip_num = 5;

    entries[0].keys = &k;
    entries[0].key_count = 1;

    CHECK_TRUE(vip_alloc(entries, 1, baseline, 1, &plan));
    CHECK_EQ(5, entries[0].vip_num);
    CHECK_EQ(0, plan.release_count);
}

MARLIN_TEST(adding_an_address_inherits_the_groups_block)
{
    struct vip_key keys[2];
    struct vip_alloc_entry entries[1];
    struct vip_alloc_baseline baseline[1];
    struct vip_alloc_plan plan;

    key4(&keys[0], ADDR_A, 0, IPPROTO_SCTP);
    key4(&keys[1], ADDR_B, 0, IPPROTO_SCTP); /* new; no baseline row */

    baseline[0].key = keys[0];
    baseline[0].vip_num = 7;

    entries[0].keys = keys;
    entries[0].key_count = 2;

    CHECK_TRUE(vip_alloc(entries, 1, baseline, 1, &plan));
    CHECK_EQ(7, entries[0].vip_num);
    CHECK_EQ(0, plan.release_count);
}

MARLIN_TEST(removing_an_address_keeps_the_shared_block_out_of_release)
{
    struct vip_key keys[2];
    struct vip_alloc_entry entries[1];
    struct vip_alloc_baseline baseline[2];
    struct vip_alloc_plan plan;

    key4(&keys[0], ADDR_A, 0, IPPROTO_SCTP);
    key4(&keys[1], ADDR_B, 0, IPPROTO_SCTP);

    baseline[0].key = keys[0];
    baseline[0].vip_num = 3;
    baseline[1].key = keys[1];
    baseline[1].vip_num = 3; /* both addresses shared one block */

    entries[0].keys = keys; /* ADDR_B dropped from the group */
    entries[0].key_count = 1;

    CHECK_TRUE(vip_alloc(entries, 1, baseline, 2, &plan));
    CHECK_EQ(3, entries[0].vip_num);
    CHECK_EQ(0, plan.release_count);
}

MARLIN_TEST(merging_two_vips_releases_the_absorbed_block)
{
    struct vip_key keys[2];
    struct vip_alloc_entry entries[1];
    struct vip_alloc_baseline baseline[2];
    struct vip_alloc_plan plan;

    key4(&keys[0], ADDR_A, 0, IPPROTO_SCTP);
    key4(&keys[1], ADDR_B, 0, IPPROTO_SCTP);

    baseline[0].key = keys[0];
    baseline[0].vip_num = 1; /* was VIP1 */
    baseline[1].key = keys[1];
    baseline[1].vip_num = 2; /* was VIP2 */

    entries[0].keys = keys; /* now one group */
    entries[0].key_count = 2;

    CHECK_TRUE(vip_alloc(entries, 1, baseline, 2, &plan));
    CHECK_EQ(1, entries[0].vip_num); /* first key's block, in key order */
    CHECK_EQ(1, plan.release_count);
    CHECK_EQ(2, plan.release[0]);
}

MARLIN_TEST(splitting_a_group_gives_the_split_off_entry_a_new_block)
{
    struct vip_key keys[2];
    struct vip_alloc_entry entries[2];
    struct vip_alloc_baseline baseline[2];
    struct vip_alloc_plan plan;

    key4(&keys[0], ADDR_A, 0, IPPROTO_SCTP);
    key4(&keys[1], ADDR_B, 0, IPPROTO_SCTP);

    baseline[0].key = keys[0];
    baseline[0].vip_num = 4; /* the group's one block, before the split */
    baseline[1].key = keys[1];
    baseline[1].vip_num = 4;

    entries[0].keys = &keys[0];
    entries[0].key_count = 1;
    entries[1].keys = &keys[1];
    entries[1].key_count = 1;

    CHECK_TRUE(vip_alloc(entries, 2, baseline, 2, &plan));
    CHECK_EQ(4, entries[0].vip_num);
    CHECK_TRUE(entries[1].vip_num != 4);
    CHECK_TRUE(entries[1].vip_num < MAX_VIPS);
    CHECK_EQ(0, plan.release_count);
    CHECK_EQ(1, plan.write_order[0]);
    CHECK_EQ(0, plan.write_order[1]);
}

MARLIN_TEST(a_new_vip_never_takes_a_reserved_block)
{
    struct vip_key keys[2];
    struct vip_alloc_entry entries[2];
    struct vip_alloc_baseline baseline[1];
    struct vip_alloc_plan plan;

    key4(&keys[0], ADDR_A, 0, IPPROTO_TCP);
    key4(&keys[1], ADDR_C, 0, IPPROTO_TCP); /* brand new, no baseline row */

    baseline[0].key = keys[0];
    baseline[0].vip_num = 0;

    entries[0].keys = &keys[0];
    entries[0].key_count = 1;
    entries[1].keys = &keys[1];
    entries[1].key_count = 1;

    CHECK_TRUE(vip_alloc(entries, 2, baseline, 1, &plan));
    CHECK_EQ(0, entries[0].vip_num);
    CHECK_TRUE(entries[1].vip_num != 0);
}

MARLIN_TEST(exhaustion_fails_and_leaves_every_vip_num_unset)
{
    struct vip_key keys[MAX_VIPS + 1];
    struct vip_alloc_entry entries[MAX_VIPS + 1];
    struct vip_alloc_plan plan;

    for(__u32 i = 0; i < MAX_VIPS + 1; i++) {
        key4(&keys[i], ADDR_A + i, 0, IPPROTO_TCP);
        entries[i].keys = &keys[i];
        entries[i].key_count = 1;
    }

    memset(&plan, 0xff, sizeof(plan));
    CHECK_TRUE(!vip_alloc(entries, MAX_VIPS + 1, NULL, 0, &plan));
    CHECK_EQ(0, plan.write_count);
    CHECK_EQ(0, plan.release_count);
    for(__u32 i = 0; i < MAX_VIPS + 1; i++) {
        CHECK_EQ(VIP_ALLOC_NUM_UNSET, entries[i].vip_num);
    }
}

static void check_write_order(const struct vip_alloc_entry *entries, __u32 count, const struct vip_alloc_baseline *baseline,
                              __u32 baseline_count, const struct vip_alloc_plan *plan)
{
    __u32 owner[MAX_VIPS];
    __u32 current[MAX_VIPS];
    bool written[MAX_VIPS] = { false };
    bool assigned[MAX_VIPS] = { false };

    CHECK_EQ(count, plan->write_count);
    for(__u32 i = 0; i < count; i++) {
        CHECK_TRUE(entries[i].vip_num < MAX_VIPS);
        if(entries[i].vip_num >= MAX_VIPS) {
            return;
        }
        CHECK_TRUE(!assigned[entries[i].vip_num]);
        assigned[entries[i].vip_num] = true;
    }
    for(__u32 b = 0; b < baseline_count; b++) {
        owner[b] = VIP_ALLOC_NUM_UNSET;
        current[b] = baseline[b].vip_num;
        for(__u32 i = 0; i < count; i++) {
            for(__u32 k = 0; k < entries[i].key_count; k++) {
                if(vip_alloc_key_eq(&entries[i].keys[k], &baseline[b].key)) {
                    owner[b] = i;
                }
            }
        }
    }
    for(__u32 step = 0; step < plan->write_count; step++) {
        __u32 entry = plan->write_order[step];

        CHECK_TRUE(entry < count);
        if(entry >= count) {
            return;
        }
        CHECK_TRUE(!written[entry]);
        written[entry] = true;
        for(__u32 b = 0; b < baseline_count; b++) {
            CHECK_TRUE(owner[b] == VIP_ALLOC_NUM_UNSET || owner[b] == entry || current[b] != entries[entry].vip_num);
        }
        for(__u32 b = 0; b < baseline_count; b++) {
            if(owner[b] == entry) {
                current[b] = entries[entry].vip_num;
            }
        }
    }
    for(__u32 r = 0; r < plan->release_count; r++) {
        CHECK_TRUE(!assigned[plan->release[r]]);
    }
}

MARLIN_TEST(merge_moves_aliases_before_an_addition_reuses_their_block)
{
    struct vip_key keys[3];
    struct vip_alloc_entry entries[2];
    struct vip_alloc_baseline baseline[2];
    struct vip_alloc_plan plan;

    for(__u32 i = 0; i < 3; i++) {
        key4(&keys[i], i + 1, 0, IPPROTO_SCTP);
    }
    baseline[0] = (struct vip_alloc_baseline){ .key = keys[0], .vip_num = 0 };
    baseline[1] = (struct vip_alloc_baseline){ .key = keys[1], .vip_num = 1 };
    entries[0] = (struct vip_alloc_entry){ .keys = &keys[2], .key_count = 1 };
    entries[1] = (struct vip_alloc_entry){ .keys = keys, .key_count = 2 };

    CHECK_TRUE(vip_alloc(entries, 2, baseline, 2, &plan));
    CHECK_EQ(1, entries[0].vip_num);
    CHECK_EQ(1, plan.write_order[0]);
    CHECK_EQ(0, plan.write_order[1]);
    check_write_order(entries, 2, baseline, 2, &plan);
}

MARLIN_TEST(all_four_key_partitions_have_a_safe_write_order)
{
    for(__u32 old_partition = 0; old_partition < 256; old_partition++) {
        for(__u32 new_partition = 0; new_partition < 256; new_partition++) {
            struct vip_key keys[4][4];
            __u32 counts[4] = { 0 };
            struct vip_alloc_baseline baseline[4];
            struct vip_alloc_entry entries[4];
            struct vip_alloc_plan plan;
            __u32 count = 0;

            for(__u32 k = 0; k < 4; k++) {
                __u32 group = (new_partition >> (k * 2)) & 3U;
                struct vip_key key;

                key4(&key, k + 1, 0, IPPROTO_SCTP);
                baseline[k] = (struct vip_alloc_baseline){ .key = key, .vip_num = (old_partition >> (k * 2)) & 3U };
                keys[group][counts[group]++] = key;
            }
            for(__u32 group = 0; group < 4; group++) {
                if(counts[group] != 0) {
                    entries[count++] = (struct vip_alloc_entry){ .keys = keys[group], .key_count = counts[group] };
                }
            }
            CHECK_TRUE(vip_alloc(entries, count, baseline, 4, &plan));
            check_write_order(entries, count, baseline, 4, &plan);
        }
    }
}

MARLIN_TEST(full_capacity_splits_do_not_require_a_reserved_spare)
{
    struct vip_key keys[MAX_VIPS];
    struct vip_alloc_baseline baseline[MAX_VIPS];
    struct vip_alloc_entry entries[MAX_VIPS];
    struct vip_alloc_plan plan;

    for(__u32 i = 0; i < MAX_VIPS; i++) {
        key4(&keys[i], i + 1, 0, IPPROTO_SCTP);
        baseline[i] = (struct vip_alloc_baseline){ .key = keys[i], .vip_num = i == 0 ? 0 : i - 1 };
        entries[i] = (struct vip_alloc_entry){ .keys = &keys[i], .key_count = 1 };
    }
    CHECK_TRUE(vip_alloc(entries, MAX_VIPS, baseline, MAX_VIPS, &plan));
    CHECK_EQ(MAX_VIPS - 1, entries[1].vip_num);
    CHECK_EQ(0, plan.release_count);
    check_write_order(entries, MAX_VIPS, baseline, MAX_VIPS, &plan);

    for(__u32 i = 0; i < MAX_VIPS; i++) {
        baseline[i].vip_num = entries[i].vip_num;
    }
    CHECK_TRUE(vip_alloc(entries, MAX_VIPS, baseline, MAX_VIPS, &plan));
    for(__u32 i = 0; i < MAX_VIPS; i++) {
        CHECK_EQ(baseline[i].vip_num, entries[i].vip_num);
    }
    check_write_order(entries, MAX_VIPS, baseline, MAX_VIPS, &plan);
}

MARLIN_TEST(cyclic_regrouping_at_full_key_capacity_uses_a_free_final_block)
{
    struct vip_key keys[MAX_VIPS];
    struct vip_key groups[2][2];
    struct vip_alloc_baseline baseline[MAX_VIPS];
    struct vip_alloc_entry entries[MAX_VIPS - 2];
    struct vip_alloc_plan plan;

    for(__u32 i = 0; i < MAX_VIPS; i++) {
        key4(&keys[i], i + 1, 0, IPPROTO_SCTP);
        baseline[i] = (struct vip_alloc_baseline){ .key = keys[i], .vip_num = i < 4 ? i / 2 : i - 2 };
        if(i >= 4) {
            entries[i - 2] = (struct vip_alloc_entry){ .keys = &keys[i], .key_count = 1 };
        }
    }
    groups[0][0] = keys[0];
    groups[0][1] = keys[2];
    groups[1][0] = keys[1];
    groups[1][1] = keys[3];
    entries[0] = (struct vip_alloc_entry){ .keys = groups[0], .key_count = 2 };
    entries[1] = (struct vip_alloc_entry){ .keys = groups[1], .key_count = 2 };
    CHECK_TRUE(vip_alloc(entries, MAX_VIPS - 2, baseline, MAX_VIPS, &plan));
    CHECK_EQ(MAX_VIPS - 2, entries[0].vip_num);
    CHECK_EQ(1, plan.release_count);
    CHECK_EQ(0, plan.release[0]);
    check_write_order(entries, MAX_VIPS - 2, baseline, MAX_VIPS, &plan);
}

MARLIN_TEST(cycle_break_relocates_only_the_entry_actually_stuck)
{
    struct vip_key keys[6];
    struct vip_alloc_baseline baseline[6];
    struct vip_key b_keys[3];
    struct vip_key c_keys[2];
    struct vip_alloc_entry entries[3];
    struct vip_alloc_plan plan;

    for(__u32 i = 0; i < 6; i++) {
        key4(&keys[i], i + 1, 0, IPPROTO_SCTP);
        baseline[i] = (struct vip_alloc_baseline){ .key = keys[i], .vip_num = i / 2 };
    }
    b_keys[0] = keys[0]; /* k1, was A's block 0 */
    b_keys[1] = keys[2]; /* k3, was B's block 1 */
    b_keys[2] = keys[5]; /* k6, was C's block 2 */
    c_keys[0] = keys[1]; /* k2, was A's block 0 */
    c_keys[1] = keys[3]; /* k4, was B's block 1 */
    entries[0] = (struct vip_alloc_entry){ .keys = &keys[4], .key_count = 1 }; /* [k5] keeps C's block 2 */
    entries[1] = (struct vip_alloc_entry){ .keys = b_keys, .key_count = 3 };
    entries[2] = (struct vip_alloc_entry){ .keys = c_keys, .key_count = 2 };

    /*
     * entries[1] and entries[2] block each other (each holds a key from
     * the other's preferred block), a genuine cycle. entries[0] merely
     * has to wait behind entries[1] -- it is not part of that cycle, so
     * relocating the first unwritten entry rather than a real cycle
     * member would move it for no reason.
     */
    CHECK_TRUE(vip_alloc(entries, 3, baseline, 6, &plan));
    CHECK_EQ(2, entries[0].vip_num);
    CHECK_EQ(1, entries[2].vip_num);
    CHECK_TRUE(entries[1].vip_num != 0 && entries[1].vip_num != 1 && entries[1].vip_num != 2);
    check_write_order(entries, 3, baseline, 6, &plan);
}

MARLIN_TEST(deleting_a_group_releases_its_block_once)
{
    struct vip_alloc_baseline baseline[2];
    struct vip_alloc_plan plan;

    for(__u32 i = 0; i < 2; i++) {
        key4(&baseline[i].key, i + 1, 0, IPPROTO_SCTP);
        baseline[i].vip_num = 7;
    }
    CHECK_TRUE(vip_alloc(NULL, 0, baseline, 2, &plan));
    CHECK_EQ(0, plan.write_count);
    CHECK_EQ(1, plan.release_count);
    CHECK_EQ(7, plan.release[0]);
}

MARLIN_TEST(invalid_baseline_fails_with_an_empty_plan)
{
    struct vip_key key;
    struct vip_alloc_plan plan;

    key4(&key, ADDR_A, 0, IPPROTO_SCTP);
    struct vip_alloc_entry entry = { .keys = &key, .key_count = 1 };
    struct vip_alloc_baseline baseline = { .key = key, .vip_num = MAX_VIPS };

    CHECK_TRUE(!vip_alloc(&entry, 1, &baseline, 1, &plan));
    CHECK_EQ(VIP_ALLOC_NUM_UNSET, entry.vip_num);
    CHECK_EQ(0, plan.write_count);
    CHECK_EQ(0, plan.release_count);
}

int main(void)
{
    return marlin_tests_main();
}
