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

/* RFC 1071 one's-complement sum over 16-bit words. Treats memory as
 * big-endian to match network byte order. Trailing byte handled per RFC.
 */
static __always_inline __u32 marlin_csum_words(const void *buf, __u32 len, __u32 sum)
{
    const __u8 *p = (const __u8 *)buf;
    __u32 i;

    for(i = 0; i + 1 < len; i += 2) {
        sum += ((__u32)p[i] << 8) | p[i + 1];
    }

    if((len & 1) != 0) {
        sum += (__u32)p[len - 1] << 8;
    }

    return sum;
}

/* Fold accumulated sum to 16-bit one's-complement and byte-swap to wire order.
 * Two folds absorb any carry.
 */
static __always_inline __sum16 marlin_csum_fold(__u32 sum)
{
    sum = (sum & 0xffffU) + (sum >> 16);
    sum = (sum & 0xffffU) + (sum >> 16);
    return bpf_htons((__u16)~sum);
}

/* Zero iph->check on local copy; checksum field is meaningless until computed. */
static __always_inline __sum16 marlin_ipv4_csum(const struct iphdr *iph)
{
    struct iphdr tmp = *iph;

    tmp.check = 0;
    return marlin_csum_fold(marlin_csum_words(&tmp, sizeof(tmp), 0));
}
