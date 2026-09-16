/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Self-check for xdp_siphash.h's transcription against SipHash-2-4's
 * published test vectors. Without this, xdp_80_quic.c's connection-ID
 * forging would be asserting against itself.
 */

#include "../harness.h"
#include "xdp_siphash.h"

MARLIN_TEST(siphash_matches_published_vectors)
{
    __u8 key[16];
    __u8 in[24];
    int i;

    for(i = 0; i < 16; i++) {
        key[i] = (__u8)i;
    }

    for(i = 0; i < 24; i++) {
        in[i] = (__u8)i;
    }

    CHECK_EQ(0x726fdb47dd0e0e31ULL, sip_hash64(NULL, 0, key));
    CHECK_EQ(0x93f5f5799a932462ULL, sip_hash64(in, 8, key));
    CHECK_EQ(0x3f2acc7f57c29bdbULL, sip_hash64(in, 16, key));

    /* 24 bytes is sizeof(struct marlin_quic_input), the length forged below. */
    CHECK_EQ(0xb8ad50c6f649af94ULL, sip_hash64(in, 24, key));
}
