/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Native unit tests for marlind's vip_num allocation (vip_alloc.c),
 * including address groups (docs/design/32-sctp.md).
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
    __u32 release[MAX_VIPS];
    __u32 release_count;

    key4(&k, ADDR_A, 0, IPPROTO_TCP);
    baseline[0].key = k;
    baseline[0].vip_num = 5;

    entries[0].keys = &k;
    entries[0].key_count = 1;

    CHECK_TRUE(vip_alloc(entries, 1, baseline, 1, release, &release_count));
    CHECK_EQ(5, entries[0].vip_num);
    CHECK_EQ(0, release_count);
}

MARLIN_TEST(adding_an_address_inherits_the_groups_block)
{
    struct vip_key keys[2];
    struct vip_alloc_entry entries[1];
    struct vip_alloc_baseline baseline[1];
    __u32 release[MAX_VIPS];
    __u32 release_count;

    key4(&keys[0], ADDR_A, 0, IPPROTO_SCTP);
    key4(&keys[1], ADDR_B, 0, IPPROTO_SCTP); /* new; no baseline row */

    baseline[0].key = keys[0];
    baseline[0].vip_num = 7;

    entries[0].keys = keys;
    entries[0].key_count = 2;

    CHECK_TRUE(vip_alloc(entries, 1, baseline, 1, release, &release_count));
    CHECK_EQ(7, entries[0].vip_num);
    CHECK_EQ(0, release_count);
}

MARLIN_TEST(removing_an_address_keeps_the_shared_block_out_of_release)
{
    struct vip_key keys[2];
    struct vip_alloc_entry entries[1];
    struct vip_alloc_baseline baseline[2];
    __u32 release[MAX_VIPS];
    __u32 release_count;

    key4(&keys[0], ADDR_A, 0, IPPROTO_SCTP);
    key4(&keys[1], ADDR_B, 0, IPPROTO_SCTP);

    baseline[0].key = keys[0];
    baseline[0].vip_num = 3;
    baseline[1].key = keys[1];
    baseline[1].vip_num = 3; /* both addresses shared one block */

    entries[0].keys = keys; /* ADDR_B dropped from the group */
    entries[0].key_count = 1;

    CHECK_TRUE(vip_alloc(entries, 1, baseline, 2, release, &release_count));
    CHECK_EQ(3, entries[0].vip_num);
    CHECK_EQ(0, release_count); /* still referenced by the surviving key */
}

MARLIN_TEST(merging_two_vips_releases_the_absorbed_block)
{
    struct vip_key keys[2];
    struct vip_alloc_entry entries[1];
    struct vip_alloc_baseline baseline[2];
    __u32 release[MAX_VIPS];
    __u32 release_count;

    key4(&keys[0], ADDR_A, 0, IPPROTO_SCTP);
    key4(&keys[1], ADDR_B, 0, IPPROTO_SCTP);

    baseline[0].key = keys[0];
    baseline[0].vip_num = 1; /* was VIP1 */
    baseline[1].key = keys[1];
    baseline[1].vip_num = 2; /* was VIP2 */

    entries[0].keys = keys; /* now one group */
    entries[0].key_count = 2;

    CHECK_TRUE(vip_alloc(entries, 1, baseline, 2, release, &release_count));
    CHECK_EQ(1, entries[0].vip_num); /* first key's block, in key order */
    CHECK_EQ(1, release_count);
    CHECK_EQ(2, release[0]);
}

MARLIN_TEST(splitting_a_group_gives_the_split_off_entry_a_new_block)
{
    struct vip_key keys[2];
    struct vip_alloc_entry entries[2];
    struct vip_alloc_baseline baseline[2];
    __u32 release[MAX_VIPS];
    __u32 release_count;

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

    CHECK_TRUE(vip_alloc(entries, 2, baseline, 2, release, &release_count));
    CHECK_EQ(4, entries[0].vip_num);
    CHECK_TRUE(entries[1].vip_num != 4);
    CHECK_TRUE(entries[1].vip_num < MAX_VIPS);
    CHECK_EQ(0, release_count); /* block 4 is still used, by entries[0] */
}

MARLIN_TEST(a_new_vip_never_takes_a_reserved_block)
{
    struct vip_key keys[2];
    struct vip_alloc_entry entries[2];
    struct vip_alloc_baseline baseline[1];
    __u32 release[MAX_VIPS];
    __u32 release_count;

    key4(&keys[0], ADDR_A, 0, IPPROTO_TCP);
    key4(&keys[1], ADDR_C, 0, IPPROTO_TCP); /* brand new, no baseline row */

    baseline[0].key = keys[0];
    baseline[0].vip_num = 0;

    entries[0].keys = &keys[0];
    entries[0].key_count = 1;
    entries[1].keys = &keys[1];
    entries[1].key_count = 1;

    CHECK_TRUE(vip_alloc(entries, 2, baseline, 1, release, &release_count));
    CHECK_EQ(0, entries[0].vip_num);
    CHECK_TRUE(entries[1].vip_num != 0);
}

MARLIN_TEST(exhaustion_fails_and_leaves_every_vip_num_unset)
{
    struct vip_key keys[MAX_VIPS + 1];
    struct vip_alloc_entry entries[MAX_VIPS + 1];
    __u32 release[MAX_VIPS];
    __u32 release_count;

    for(__u32 i = 0; i < MAX_VIPS + 1; i++) {
        key4(&keys[i], ADDR_A + i, 0, IPPROTO_TCP);
        entries[i].keys = &keys[i];
        entries[i].key_count = 1;
    }

    CHECK_TRUE(!vip_alloc(entries, MAX_VIPS + 1, NULL, 0, release, &release_count));
    for(__u32 i = 0; i < MAX_VIPS + 1; i++) {
        CHECK_EQ(VIP_ALLOC_NUM_UNSET, entries[i].vip_num);
    }
}

int main(void)
{
    return marlin_tests_main();
}
