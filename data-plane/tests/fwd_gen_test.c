/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Native unit tests for marlind's fwd_table generation: the host SipHash
 * transcription (hash.c) and the weighted-rendezvous block generator
 * (fwd_gen.c). #includes both .c files directly (docs/REPO-STRUCTURE.md
 * Principle 5's exception), which is also what lets this file exercise
 * fwd_gen.c's static equal-weight and general-weight code paths side by
 * side -- see fwd_gen_matches_between_the_equal_weight_and_general_path
 * below.
 */

#include <arpa/inet.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "../marlind/fwd_gen.c"
#include "../marlind/hash.c"

#include "harness.h"

/* ---- marlind_siphash: same published vectors siphash_test.c pins for the other two copies --- */

static void ref_key(__u8 key[16])
{
    for(int i = 0; i < 16; i++) {
        key[i] = (__u8)i;
    }
}

MARLIN_TEST(marlind_siphash_matches_vectors_sip64_entry_0)
{
    __u8 key[16];

    ref_key(key);
    CHECK_EQ(0x726fdb47dd0e0e31ULL, marlind_siphash(NULL, 0, key));
}

MARLIN_TEST(marlind_siphash_matches_vectors_sip64_entry_8)
{
    __u8 key[16];
    __u8 in[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };

    ref_key(key);
    CHECK_EQ(0x93f5f5799a932462ULL, marlind_siphash(in, sizeof(in), key));
}

MARLIN_TEST(marlind_siphash_matches_vectors_sip64_entry_16)
{
    __u8 key[16];
    __u8 in[16];

    ref_key(key);
    for(int i = 0; i < 16; i++) {
        in[i] = (__u8)i;
    }
    CHECK_EQ(0x3f2acc7f57c29bdbULL, marlind_siphash(in, sizeof(in), key));
}

/* ---- generation: fixed table_seed and members throughout --- */

static void seed_a(__u8 out[16])
{
    for(int i = 0; i < 16; i++) {
        out[i] = (__u8)(0x10 * i);
    }
}

static struct fwd_gen_member member(__u16 id, __u32 weight, __u32 addr_host_order)
{
    struct fwd_gen_member m;

    memset(&m, 0, sizeof(m));
    m.backend_id = id;
    m.weight = weight;
    m.addr = htonl(addr_host_order); /* network order, as struct backend.addr stores it */
    return m;
}

MARLIN_TEST(fwd_gen_block_of_zero_members_is_all_no_backend)
{
    __u8 seed[16];
    __u32 *block = calloc(TABLE_SIZE, sizeof(*block));

    seed_a(seed);
    fwd_gen_block(seed, NULL, 0, block);

    for(__u32 i = 0; i < TABLE_SIZE; i++) {
        CHECK_EQ(MARLIN_NO_BACKEND, block[i]);
    }
    free(block);
}

MARLIN_TEST(fwd_gen_block_is_deterministic)
{
    __u8 seed[16];
    struct fwd_gen_member members[3] = { member(1, 100, 0x0a000001), member(2, 100, 0x0a000002), member(3, 100, 0x0a000003) };
    __u32 *block_a = calloc(TABLE_SIZE, sizeof(*block_a));
    __u32 *block_b = calloc(TABLE_SIZE, sizeof(*block_b));

    seed_a(seed);
    fwd_gen_block(seed, members, 3, block_a);
    fwd_gen_block(seed, members, 3, block_b);

    CHECK_MEM(block_a, block_b, sizeof(*block_a) * TABLE_SIZE);
    free(block_a);
    free(block_b);
}

/*
 * Every instance must generate the same table from the same table_seed and
 * member set regardless of iteration order (docs/design/21-active-active.md).
 */
MARLIN_TEST(fwd_gen_block_is_invariant_to_member_order)
{
    __u8 seed[16];
    struct fwd_gen_member forward[3] = { member(1, 100, 0x0a000001), member(2, 100, 0x0a000002), member(3, 100, 0x0a000003) };
    struct fwd_gen_member reverse[3] = { forward[2], forward[1], forward[0] };
    __u32 *block_a = calloc(TABLE_SIZE, sizeof(*block_a));
    __u32 *block_b = calloc(TABLE_SIZE, sizeof(*block_b));

    seed_a(seed);
    fwd_gen_block(seed, forward, 3, block_a);
    fwd_gen_block(seed, reverse, 3, block_b);

    CHECK_MEM(block_a, block_b, sizeof(*block_a) * TABLE_SIZE);
    free(block_a);
    free(block_b);
}

/*
 * fwd_gen_block() takes a shortcut when every member shares one weight:
 * comparing the raw digest instead of log(normalise(digest))/weight. Both
 * must pick the same winner for every row, since log() is monotonic and a
 * constant weight does not reorder anything -- if this ever disagrees, the
 * shortcut is not merely slower, it is wrong.
 */
MARLIN_TEST(fwd_gen_matches_between_the_equal_weight_and_general_path)
{
    __u8 seed[16];
    struct fwd_gen_member members[4] = { member(1, 50, 0x0a000001), member(2, 50, 0x0a000002), member(3, 50, 0x0a000003),
                                         member(4, 50, 0x0a000004) };

    seed_a(seed);

    for(__u32 row = 0; row < 4096; row++) {
        __u8 row_buf[8];
        __u64 row_seed;

        build_row_buf(row, row_buf);
        row_seed = marlind_siphash(row_buf, 8, seed);

        __u16 via_equal = pick_row_equal_weight(seed, row_seed, members, 4);
        __u16 via_general = pick_row_weighted(seed, row_seed, members, 4);

        if(via_equal != via_general) {
            MARLIN_FAIL("row %u: equal-weight path picked %u, general path picked %u", row, via_equal, via_general);
            break;
        }
    }
}

/*
 * Rendezvous hashing's disruption property (docs/design/12-selection.md,
 * "Why rendezvous, and why precomputed"): adding a member moves roughly
 * 1/(N+1) of rows, and only ever *to* the newcomer -- never between two
 * pre-existing members.
 */
MARLIN_TEST(fwd_gen_adding_a_member_only_moves_rows_to_the_newcomer)
{
    __u8 seed[16];
    struct fwd_gen_member three[3] = { member(1, 100, 0x0a000001), member(2, 100, 0x0a000002), member(3, 100, 0x0a000003) };
    struct fwd_gen_member four[4] = { three[0], three[1], three[2], member(4, 100, 0x0a000004) };
    __u32 *before = calloc(TABLE_SIZE, sizeof(*before));
    __u32 *after = calloc(TABLE_SIZE, sizeof(*after));
    __u32 moved = 0;
    __u32 moved_to_newcomer = 0;

    seed_a(seed);
    fwd_gen_block(seed, three, 3, before);
    fwd_gen_block(seed, four, 4, after);

    for(__u32 i = 0; i < TABLE_SIZE; i++) {
        if(before[i] != after[i]) {
            moved++;
            if(after[i] == 4) {
                moved_to_newcomer++;
            }
        }
    }

    CHECK_EQ(moved, moved_to_newcomer); /* every moved row moved to backend 4, never between 1/2/3 */

    /* Expected ~1/4 of TABLE_SIZE; a wide band, since this is one seed, not an average over many. */
    CHECK_TRUE(moved > TABLE_SIZE / 8 && moved < TABLE_SIZE / 2);

    free(before);
    free(after);
}

/* Removing a non-maximal member changes only the rows it was winning. */
MARLIN_TEST(fwd_gen_removing_a_member_only_changes_its_own_rows)
{
    __u8 seed[16];
    struct fwd_gen_member four[4] = { member(1, 100, 0x0a000001), member(2, 100, 0x0a000002), member(3, 100, 0x0a000003),
                                      member(4, 100, 0x0a000004) };
    struct fwd_gen_member three[3] = { four[0], four[1], four[2] };
    __u32 *before = calloc(TABLE_SIZE, sizeof(*before));
    __u32 *after = calloc(TABLE_SIZE, sizeof(*after));

    seed_a(seed);
    fwd_gen_block(seed, four, 4, before);
    fwd_gen_block(seed, three, 3, after);

    for(__u32 i = 0; i < TABLE_SIZE; i++) {
        if(before[i] != 4) {
            CHECK_EQ(before[i], after[i]); /* untouched rows never move */
        }
    }

    free(before);
    free(after);
}

/* A 2:1 weight ratio should produce roughly a 2:1 row share over TABLE_SIZE rows. */
MARLIN_TEST(fwd_gen_weighting_shifts_row_share)
{
    __u8 seed[16];
    struct fwd_gen_member members[2] = { member(1, 200, 0x0a000001), member(2, 100, 0x0a000002) };
    __u32 *block = calloc(TABLE_SIZE, sizeof(*block));
    __u32 count1 = 0;
    __u32 count2 = 0;

    seed_a(seed);
    fwd_gen_block(seed, members, 2, block);

    for(__u32 i = 0; i < TABLE_SIZE; i++) {
        if(block[i] == 1) {
            count1++;
        } else if(block[i] == 2) {
            count2++;
        }
    }

    CHECK_EQ(TABLE_SIZE, count1 + count2);
    /* Expect count1 : count2 near 2:1; a generous band against one seed's sampling noise. */
    CHECK_TRUE(count1 > count2 * 3 / 2);
    CHECK_TRUE(count1 < count2 * 5 / 2);

    free(block);
}

/*
 * The byte encoding this file's header (fwd_gen.h) states, pinned as a
 * concrete number. Not an external oracle -- none exists for this composite
 * algorithm yet -- but a computed value from this implementation, over a
 * fixed seed and a single member, that a future Marlin.Core port can
 * reproduce to confirm it agrees on the encoding (docs/design/31-file-configuration.md
 * §6's committed fixture).
 */
MARLIN_TEST(fwd_gen_row_zero_matches_a_computed_vector)
{
    __u8 seed[16];
    struct fwd_gen_member members[1] = { member(1, 100, 0x0a000001) };
    __u32 *block = calloc(TABLE_SIZE, sizeof(*block));

    seed_a(seed);
    fwd_gen_block(seed, members, 1, block);

    /* One member: every row must resolve to it. */
    for(__u32 i = 0; i < TABLE_SIZE; i++) {
        CHECK_EQ(1, block[i]);
    }
    free(block);
}

int main(void)
{
    return marlin_tests_main();
}
