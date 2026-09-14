/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * siphash.h — SipHash-2-4, 64-bit output, keyed. Conformant to the reference
 * algorithm for input lengths that are a multiple of 8; see marlin_siphash()
 * below for why that is the only length it accepts.
 * Verified against published vectors_sip64 entries 0, 8 and 16.
 */

#pragma once

#include <linux/types.h>

#include <bpf/bpf_helpers.h>

#define MARLIN_SIP_ROTL(x, b) (((x) << (b)) | ((x) >> (64 - (b))))

#define MARLIN_SIPROUND(v0, v1, v2, v3)   \
    do {                                  \
        (v0) += (v1);                     \
        (v1) = MARLIN_SIP_ROTL((v1), 13); \
        (v1) ^= (v0);                     \
        (v0) = MARLIN_SIP_ROTL((v0), 32); \
        (v2) += (v3);                     \
        (v3) = MARLIN_SIP_ROTL((v3), 16); \
        (v3) ^= (v2);                     \
        (v0) += (v3);                     \
        (v3) = MARLIN_SIP_ROTL((v3), 21); \
        (v3) ^= (v0);                     \
        (v2) += (v1);                     \
        (v1) = MARLIN_SIP_ROTL((v1), 17); \
        (v1) ^= (v2);                     \
        (v2) = MARLIN_SIP_ROTL((v2), 32); \
    } while(0)

/*
 * Byte-wise little-endian load, so the digest is identical on every
 * architecture — every instance serving a VIP must compute the same row.
 */
static __always_inline __u64 marlin_siphash_le64(const __u8 *p)
{
    return (__u64)p[0] | ((__u64)p[1] << 8) | ((__u64)p[2] << 16) | ((__u64)p[3] << 24) | ((__u64)p[4] << 32) | ((__u64)p[5] << 40) |
           ((__u64)p[6] << 48) | ((__u64)p[7] << 56);
}

/*
 * `len` must be a compile-time constant multiple of 8: a variable trip
 * count would leave the block loop unable to unroll, and a length that is
 * not a multiple of 8 needs the reference implementation's partial-tail
 * switch, deliberately absent here. Callers with a ragged input pack it
 * into a zero-filled buffer of a constant multiple-of-8 size first.
 */
static __always_inline __u64 marlin_siphash_blocks(const void *data, __u32 len, const __u8 key[16])
{
    const __u8 *m = (const __u8 *)data;
    __u64 v0, v1, v2, v3;
    __u64 k0, k1, w, b;
    __u32 i;

    k0 = marlin_siphash_le64(key);
    k1 = marlin_siphash_le64(key + 8);

    v0 = k0 ^ 0x736f6d6570736575ULL;
    v1 = k1 ^ 0x646f72616e646f6dULL;
    v2 = k0 ^ 0x6c7967656e657261ULL;
    v3 = k1 ^ 0x7465646279746573ULL;

#pragma clang loop unroll(full)
    for(i = 0; i < len / 8; i++) {
        w = marlin_siphash_le64(m + i * 8);

        v3 ^= w;
        MARLIN_SIPROUND(v0, v1, v2, v3);
        MARLIN_SIPROUND(v0, v1, v2, v3);
        v0 ^= w;
    }

    /*
     * Tail block: with len a multiple of 8 there are no leftover bytes,
     * so it carries the length alone.
     */
    b = (__u64)len << 56;

    v3 ^= b;
    MARLIN_SIPROUND(v0, v1, v2, v3);
    MARLIN_SIPROUND(v0, v1, v2, v3);
    v0 ^= b;

    v2 ^= 0xff;
    MARLIN_SIPROUND(v0, v1, v2, v3);
    MARLIN_SIPROUND(v0, v1, v2, v3);
    MARLIN_SIPROUND(v0, v1, v2, v3);
    MARLIN_SIPROUND(v0, v1, v2, v3);

    return v0 ^ v1 ^ v2 ^ v3;
}

/* Largest input any caller hashes: struct packet_tuple, at 40 bytes. */
#define MARLIN_SIPHASH_MAX_LEN 48U

/*
 * Asserts marlin_siphash_blocks()'s length contract at the call site instead
 * of leaving it to a comment: a bad constant silently drops trailing bytes
 * from the digest, and a non-constant length silently defeats the unroll
 * above, and the BPF build carries no -Werror to turn either into a build
 * failure on its own.
 */
#define marlin_siphash(data, len, key)                                                                      \
    ({                                                                                                      \
        _Static_assert(__builtin_constant_p(len), "marlin_siphash() needs a constant len to unroll");       \
        _Static_assert((len) % 8U == 0U, "marlin_siphash() hashes whole 8-byte blocks");                    \
        _Static_assert((len) <= MARLIN_SIPHASH_MAX_LEN, "marlin_siphash() input exceeds its unroll bound"); \
        marlin_siphash_blocks((data), (len), (key));                                                        \
    }) // NOLINT(readability-identifier-naming) -- wraps a function, keeps its name
