/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Checksum arithmetic for the encapsulation units. bpf_l3_csum_replace() and
 * bpf_l4_csum_replace() are tc-only and unavailable in XDP, so the outer
 * IPv4 header's checksum is folded by hand (docs/design/14-forwarding-modes.md
 * SS7.6). A header, not a translation unit: a global subprogram cannot take
 * a packet pointer, and every caller here hands one a stack-local struct
 * (docs/design/03-translation-units.md).
 */

#pragma once

#include <linux/bpf.h>
#include <linux/ip.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

_Static_assert(sizeof(struct iphdr) == 20, "marlin_ipv4_csum assumes a 20-byte IPv4 header with no options");

/* RFC 1071's one's-complement sum: accumulates buf's 16-bit words into sum,
 * treating memory as big-endian regardless of the host's own byte order --
 * network-order multi-byte fields already store their most-significant byte
 * first, so reading two adjacent bytes as (high << 8) | low reproduces the
 * wire value without any swap. len need not be even: a trailing byte is
 * summed as the high half of its own word, per the RFC, though every caller
 * here passes sizeof() of a fixed struct and never exercises that path.
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

/* Folds an accumulated sum to the 16-bit one's-complement result and
 * byte-swaps it into wire order, so the return value is ready to store
 * directly into a __be16 header field with no further conversion at the
 * call site. Two folds always suffice regardless of how large sum grew:
 * the first can leave at most a 1-bit carry above bit 15, and the second
 * absorbs exactly that.
 */
static __always_inline __sum16 marlin_csum_fold(__u32 sum)
{
    sum = (sum & 0xffffU) + (sum >> 16);
    sum = (sum & 0xffffU) + (sum >> 16);
    return bpf_htons((__u16)~sum);
}

/* iph->check is never read: a freshly built header's checksum field is
 * meaningless until this returns, so it is zeroed on a local copy rather
 * than requiring every caller to remember to zero it first.
 */
static __always_inline __sum16 marlin_ipv4_csum(const struct iphdr *iph)
{
    struct iphdr tmp = *iph;

    tmp.check = 0;
    return marlin_csum_fold(marlin_csum_words(&tmp, sizeof(tmp), 0));
}
