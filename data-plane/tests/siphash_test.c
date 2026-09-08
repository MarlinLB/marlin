/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Native unit tests for siphash.h. Pure arithmetic over stack-local buffers:
 * no bpf_* helper, no map, so nothing here needs tests/stubs.
 */

#include <string.h>

#include <marlin/siphash.h>

#include "harness.h"

/*
 * SipHash-2-4 reference test key from the published vectors_sip64 table:
 * bytes 0x00..0x0f in order.
 */
static void ref_key(__u8 key[16])
{
    int i;

    for(i = 0; i < 16; i++) {
        key[i] = (__u8)i;
    }
}

/* vectors_sip64 input for length n: bytes 0x00..(n-1) in order. */
static void ref_input(__u8 *buf, __u32 n)
{
    __u32 i;

    for(i = 0; i < n; i++) {
        buf[i] = (__u8)i;
    }
}

MARLIN_TEST(siphash_matches_vectors_sip64_entry_0)
{
    __u8 key[16];

    ref_key(key);

    CHECK_EQ(0x726fdb47dd0e0e31ULL, marlin_siphash(NULL, 0, key));
}

MARLIN_TEST(siphash_matches_vectors_sip64_entry_8)
{
    __u8 key[16];
    __u8 in[8];

    ref_key(key);
    ref_input(in, sizeof(in));

    CHECK_EQ(0x93f5f5799a932462ULL, marlin_siphash(in, sizeof(in), key));
}

MARLIN_TEST(siphash_matches_vectors_sip64_entry_16)
{
    __u8 key[16];
    __u8 in[16];

    ref_key(key);
    ref_input(in, sizeof(in));

    CHECK_EQ(0x3f2acc7f57c29bdbULL, marlin_siphash(in, sizeof(in), key));
}

/*
 * Entries 24, 32 and 40 are not in the published vectors_sip64 excerpt this
 * header cites, but were derived from a full reference SipHash-2-4
 * implementation (partial-tail path included) whose 0/8/16-byte outputs
 * reproduce the published ones above. 40 bytes is struct packet_tuple's
 * size (marlin.h) -- the input marlin_siphash() actually hashes for row
 * selection (docs/design/12-selection.md).
 */
MARLIN_TEST(siphash_matches_derived_vector_24)
{
    __u8 key[16];
    __u8 in[24];

    ref_key(key);
    ref_input(in, sizeof(in));

    CHECK_EQ(0xb8ad50c6f649af94ULL, marlin_siphash(in, sizeof(in), key));
}

MARLIN_TEST(siphash_matches_derived_vector_32)
{
    __u8 key[16];
    __u8 in[32];

    ref_key(key);
    ref_input(in, sizeof(in));

    CHECK_EQ(0x7127512f72f27cceULL, marlin_siphash(in, sizeof(in), key));
}

MARLIN_TEST(siphash_matches_derived_vector_40)
{
    __u8 key[16];
    __u8 in[40];

    ref_key(key);
    ref_input(in, sizeof(in));

    CHECK_EQ(0x0e3ea96b5304a7d0ULL, marlin_siphash(in, sizeof(in), key));
}

MARLIN_TEST(siphash_is_invariant_to_input_alignment)
{
    static const __u8 pattern[16] = { 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
                                       0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    __u8 key[16];
    __u8 aligned[16];
    __u8 unaligned[17];

    ref_key(key);
    memcpy(aligned, pattern, sizeof(pattern));

    /*
     * unaligned+1 carries the identical 16 bytes starting one byte into the
     * buffer. marlin_siphash_le64() must read byte-wise regardless of the
     * pointer's alignment -- the invariant a single wide load would break --
     * so both calls must produce the same digest.
     */
    unaligned[0] = 0xAA;
    memcpy(unaligned + 1, pattern, sizeof(pattern));

    CHECK_EQ(marlin_siphash(aligned, sizeof(aligned), key), marlin_siphash(unaligned + 1, sizeof(pattern), key));
}

MARLIN_TEST(siphash_output_depends_on_every_key_bit)
{
    __u8 key_a[16];
    __u8 key_b[16];
    __u8 in[16];

    ref_key(key_a);
    ref_key(key_b);
    key_b[0] ^= 0x01; /* single bit flip */
    ref_input(in, sizeof(in));

    CHECK_TRUE(marlin_siphash(in, sizeof(in), key_a) != marlin_siphash(in, sizeof(in), key_b));
}

MARLIN_TEST(siphash_of_a_zero_padded_ragged_input_is_not_the_all_zero_digest)
{
    /*
     * The documented pattern for a ragged input (siphash.h): a 20-byte
     * payload -- struct rl_key's size (abi/types.h) -- packed into a
     * zero-filled 24-byte buffer. Confirms the payload actually changes the
     * digest rather than being lost in the padding.
     */
    __u8 key[16];
    __u8 payload[20];
    __u8 padded[24];
    __u8 zero[24];

    ref_key(key);
    ref_input(payload, sizeof(payload));

    memset(padded, 0, sizeof(padded));
    memcpy(padded, payload, sizeof(payload));

    memset(zero, 0, sizeof(zero));

    CHECK_TRUE(marlin_siphash(padded, sizeof(padded), key) != marlin_siphash(zero, sizeof(zero), key));
}

int main(void)
{
    return marlin_tests_main();
}
