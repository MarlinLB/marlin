/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Checksum arithmetic for encapsulation. Header only: uses stack-local
 * structs and no packet pointers. Hand-folded IPv4 checksums (unavailable in XDP).
 */

#pragma once

#include <linux/bpf.h>
#include <linux/ip.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

_Static_assert(sizeof(struct iphdr) == 20, "marlin_ipv4_csum assumes a 20-byte IPv4 header with no options");

/*
 * RFC 1071 one's-complement sum over 16-bit words. Treats memory as
 * big-endian to match network byte order. Trailing byte handled per RFC.
 */
static __always_inline __u32 marlin_csum_words(const void *buf, __u32 len, __u32 sum)
{
    const __u8 *ptr = (const __u8 *)buf;

    for(__u32 idx = 0; idx + 1 < len; idx += 2) {
        sum += ((__u32)ptr[idx] << 8) | ptr[idx + 1];
    }

    if((len & 1) != 0) {
        sum += (__u32)ptr[len - 1] << 8;
    }

    return sum;
}

/*
 * Fold accumulated sum to 16-bit one's-complement and byte-swap to wire order.
 * Two folds absorb any carry.
 */
static __always_inline __sum16 marlin_csum_fold(__u32 sum)
{
    sum = (sum & 0xffffU) + (sum >> 16);
    sum = (sum & 0xffffU) + (sum >> 16);
    return bpf_htons((__u16)~sum);
}

/*
 * Sums the header as raw 16-bit words, skipping the check field. One's
 * complement addition is byte-order invariant, so the folded result is
 * already in network order and needs no swap.
 */
static __always_inline __sum16 marlin_ipv4_csum(const struct iphdr *iph)
{
    union {
        struct iphdr iph;
        __u16 word[10];
    } hdr = { .iph = *iph };
    __u32 sum;

    sum = (__u32)hdr.word[0] + hdr.word[1] + hdr.word[2] + hdr.word[3] + hdr.word[4] + hdr.word[6] + hdr.word[7] + hdr.word[8] +
          hdr.word[9];
    sum = (sum & 0xffffU) + (sum >> 16);
    sum = (sum & 0xffffU) + (sum >> 16);

    return (__sum16)~sum;
}
