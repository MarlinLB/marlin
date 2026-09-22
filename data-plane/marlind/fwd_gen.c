/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Definitions for fwd_gen.h.
 */

#include <math.h>
#include <stdbool.h>
#include <string.h>

#include <marlin/lb_core.h>
#include <marlind/fwd_gen.h>
#include <marlind/hash.h>

static void build_row_buf(__u32 row_index, __u8 buf[8])
{
    memset(buf, 0, 8);
    buf[0] = (__u8)(row_index & 0xff);
    buf[1] = (__u8)((row_index >> 8) & 0xff);
    buf[2] = (__u8)((row_index >> 16) & 0xff);
    buf[3] = (__u8)((row_index >> 24) & 0xff);
}

static void build_score_buf(__u64 row_seed, const struct fwd_gen_member *member, __u8 buf[24])
{
    memset(buf, 0, 24);
    for(int k = 0; k < 8; k++) {
        buf[k] = (__u8)(row_seed >> (8 * k));
    }
    memcpy(buf + 8, &member->addr, 4); /* network order, as stored in struct backend */
    buf[12] = (__u8)(member->vni & 0xff);
    buf[13] = (__u8)((member->vni >> 8) & 0xff);
    buf[14] = (__u8)((member->vni >> 16) & 0xff);
    /* buf[15] stays zero: vni is a 24-bit value, its high byte is always 0. */
    memcpy(buf + 16, member->inner_mac, 6);
    /* buf[22..23] stay zero: padding to the next multiple of 8. */
}

/*
 * u in (0,1], never 0: (digest >> 11) discards SipHash's low bits (no
 * bearing on the mantissa) and +1 keeps log(u) finite for every digest,
 * including 0, rather than -inf for the smallest one.
 */
static double normalise(__u64 digest)
{
    return (double)((digest >> 11) + 1) / 0x1p53;
}

/*
 * Equal weights make w a constant across the comparison, so the highest
 * digest is the highest score without computing one -- log() is monotonic
 * and normalise() preserves digest order, so this is not an approximation.
 * Every VIP in the shipped example configuration hits this path.
 */
static __u16 pick_row_equal_weight(const __u8 table_seed[16], __u64 row_seed, const struct fwd_gen_member *members, __u32 member_count)
{
    __u16 best_id = MARLIN_NO_BACKEND;
    __u64 best_digest = 0;

    for(__u32 i = 0; i < member_count; i++) {
        __u8 buf[24];
        __u64 digest;

        build_score_buf(row_seed, &members[i], buf);
        digest = marlind_siphash(buf, 24, table_seed);

        if(i == 0 || digest > best_digest || (digest == best_digest && members[i].backend_id < best_id)) {
            best_digest = digest;
            best_id = members[i].backend_id;
        }
    }
    return best_id;
}

static __u16 pick_row_weighted(const __u8 table_seed[16], __u64 row_seed, const struct fwd_gen_member *members, __u32 member_count)
{
    __u16 best_id = MARLIN_NO_BACKEND;
    double best_score = 0.0;

    for(__u32 i = 0; i < member_count; i++) {
        __u8 buf[24];
        __u64 digest;
        double score;

        build_score_buf(row_seed, &members[i], buf);
        digest = marlind_siphash(buf, 24, table_seed);
        score = log(normalise(digest)) / (double)members[i].weight;

        if(i == 0 || score > best_score || (score == best_score && members[i].backend_id < best_id)) {
            best_score = score;
            best_id = members[i].backend_id;
        }
    }
    return best_id;
}

void fwd_gen_block(const __u8 table_seed[16], const struct fwd_gen_member *members, __u32 member_count, __u32 out[TABLE_SIZE])
{
    bool equal_weight = true;

    if(member_count == 0) {
        memset(out, 0, sizeof(__u32) * TABLE_SIZE);
        return;
    }

    for(__u32 i = 1; i < member_count; i++) {
        if(members[i].weight != members[0].weight) {
            equal_weight = false;
            break;
        }
    }

    for(__u32 row = 0; row < TABLE_SIZE; row++) {
        __u8 row_buf[8];
        __u64 row_seed;

        build_row_buf(row, row_buf);
        row_seed = marlind_siphash(row_buf, 8, table_seed);

        out[row] = equal_weight ? pick_row_equal_weight(table_seed, row_seed, members, member_count)
                                : pick_row_weighted(table_seed, row_seed, members, member_count);
    }
}
