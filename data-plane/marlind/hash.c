/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Definitions for hash.h. Transcribed from the same reference algorithm as
 * include/marlin/siphash.h and data-plane/tests/packet/xdp_siphash.c;
 * data-plane/tests/fwd_gen_test.c's published-vector case is what makes this
 * copy trustworthy, exactly as it is for the other two.
 */

#include <stddef.h>

#include <marlind/hash.h>

static __u64 le64(const __u8 *buf)
{
    return (__u64)buf[0] | ((__u64)buf[1] << 8) | ((__u64)buf[2] << 16) | ((__u64)buf[3] << 24) | ((__u64)buf[4] << 32) |
           ((__u64)buf[5] << 40) | ((__u64)buf[6] << 48) | ((__u64)buf[7] << 56);
}

#define ROTL(x, b) (((x) << (b)) | ((x) >> (64 - (b))))

/*
 * A function rather than the reference algorithm's inline macro: each
 * SIPROUND expansion added ~13 statements to marlind_siphash, which is what
 * tripped readability-function-size (149 statements, threshold 80). Called
 * 8 times per digest, so it stays a plain function rather than
 * __always_inline -- this file is host-only, with no BPF instruction budget
 * to protect.
 */
static void siphash_round(__u64 *v0, __u64 *v1, __u64 *v2, __u64 *v3)
{
    *v0 += *v1;
    *v1 = ROTL(*v1, 13);
    *v1 ^= *v0;
    *v0 = ROTL(*v0, 32);
    *v2 += *v3;
    *v3 = ROTL(*v3, 16);
    *v3 ^= *v2;
    *v0 += *v3;
    *v3 = ROTL(*v3, 21);
    *v3 ^= *v0;
    *v2 += *v1;
    *v1 = ROTL(*v1, 17);
    *v1 ^= *v2;
    *v2 = ROTL(*v2, 32);
}

__u64 marlind_siphash(const void *data, __u32 len, const __u8 key[16])
{
    const __u8 *msg = (const __u8 *)data;
    __u64 v0, v1, v2, v3;
    __u64 k0, k1, word, tail;

    k0 = le64(key);
    k1 = le64(key + 8);

    v0 = k0 ^ 0x736f6d6570736575ULL;
    v1 = k1 ^ 0x646f72616e646f6dULL;
    v2 = k0 ^ 0x6c7967656e657261ULL;
    v3 = k1 ^ 0x7465646279746573ULL;

    for(__u32 i = 0; i < len / 8; i++) {
        word = le64(msg + (size_t)i * 8);

        v3 ^= word;
        siphash_round(&v0, &v1, &v2, &v3);
        siphash_round(&v0, &v1, &v2, &v3);
        v0 ^= word;
    }

    /* len is always a multiple of 8 (see hash.h), so the tail block carries the length alone. */
    tail = (__u64)len << 56;

    v3 ^= tail;
    siphash_round(&v0, &v1, &v2, &v3);
    siphash_round(&v0, &v1, &v2, &v3);
    v0 ^= tail;

    v2 ^= 0xff;
    siphash_round(&v0, &v1, &v2, &v3);
    siphash_round(&v0, &v1, &v2, &v3);
    siphash_round(&v0, &v1, &v2, &v3);
    siphash_round(&v0, &v1, &v2, &v3);

    return v0 ^ v1 ^ v2 ^ v3;
}
