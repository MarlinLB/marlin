/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Definitions for xdp_siphash.h's SipHash-2-4 transcription. See the header
 * comment there for why this is not marlin_siphash() itself.
 */

#include "xdp_siphash.h"

static __u64 sip_le64(const __u8 *buf)
{
    return (__u64)buf[0] | ((__u64)buf[1] << 8) | ((__u64)buf[2] << 16) | ((__u64)buf[3] << 24) | ((__u64)buf[4] << 32) |
           ((__u64)buf[5] << 40) | ((__u64)buf[6] << 48) | ((__u64)buf[7] << 56);
}

#define SIP_ROTL(x, b) (((x) << (b)) | ((x) >> (64 - (b))))

#define SIP_ROUND(v0, v1, v2, v3)  \
    do {                           \
        (v0) += (v1);              \
        (v1) = SIP_ROTL((v1), 13); \
        (v1) ^= (v0);              \
        (v0) = SIP_ROTL((v0), 32); \
        (v2) += (v3);              \
        (v3) = SIP_ROTL((v3), 16); \
        (v3) ^= (v2);              \
        (v0) += (v3);              \
        (v3) = SIP_ROTL((v3), 21); \
        (v3) ^= (v0);              \
        (v2) += (v1);              \
        (v1) = SIP_ROTL((v1), 17); \
        (v1) ^= (v2);              \
        (v2) = SIP_ROTL((v2), 32); \
    } while(0)

/* Whole 8-byte blocks only, matching marlin_siphash()'s length contract. */
__u64 sip_hash64(const void *data, __u32 len, const __u8 key[16])
{
    const __u8 *msg = (const __u8 *)data;
    __u64 v0, v1, v2, v3;
    __u64 k0, k1, word, tail;
    __u32 i;

    k0 = sip_le64(key);
    k1 = sip_le64(key + 8);

    v0 = k0 ^ 0x736f6d6570736575ULL;
    v1 = k1 ^ 0x646f72616e646f6dULL;
    v2 = k0 ^ 0x6c7967656e657261ULL;
    v3 = k1 ^ 0x7465646279746573ULL;

    for(i = 0; i < len / 8; i++) {
        word = sip_le64(msg + i * 8);

        v3 ^= word;
        SIP_ROUND(v0, v1, v2, v3);
        SIP_ROUND(v0, v1, v2, v3);
        v0 ^= word;
    }

    tail = (__u64)len << 56;

    v3 ^= tail;
    SIP_ROUND(v0, v1, v2, v3);
    SIP_ROUND(v0, v1, v2, v3);
    v0 ^= tail;

    v2 ^= 0xff;
    SIP_ROUND(v0, v1, v2, v3);
    SIP_ROUND(v0, v1, v2, v3);
    SIP_ROUND(v0, v1, v2, v3);
    SIP_ROUND(v0, v1, v2, v3);

    return v0 ^ v1 ^ v2 ^ v3;
}
