/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Native unit tests for csum.h. Pure arithmetic over stack-local buffers:
 * no bpf_* helper, no map, so nothing here needs tests/stubs.
 */

#include <string.h>

#include <linux/in.h>

#include <bpf/bpf_endian.h>

#include <marlin/csum.h>
#include <marlin/proto.h>

#include "harness.h"

MARLIN_TEST(csum_words_sums_a_small_even_length_buffer)
{
    static const __u8 buf[4] = { 0x12, 0x34, 0x56, 0x78 };

    CHECK_EQ(0x1234 + 0x5678, marlin_csum_words(buf, sizeof(buf), 0));
}

MARLIN_TEST(csum_words_pads_a_trailing_odd_byte_as_its_high_half)
{
    static const __u8 buf[3] = { 0x12, 0x34, 0x56 };

    /* RFC 1071: an odd-length region's last byte is summed as the high
     * byte of its own word, the low byte implicitly zero.
     */
    CHECK_EQ(0x1234 + 0x5600, marlin_csum_words(buf, sizeof(buf), 0));
}

MARLIN_TEST(csum_words_continues_an_existing_running_sum)
{
    static const __u8 buf[2] = { 0x00, 0x01 };

    CHECK_EQ(100 + 0x0001, marlin_csum_words(buf, sizeof(buf), 100));
}

MARLIN_TEST(csum_fold_all_ones_input_becomes_zero)
{
    /* An accumulated sum of exactly 0xFFFF has no carry to fold, and
     * ~0xFFFF is zero -- the edge every checksum fold must get right.
     */
    CHECK_EQ(0, bpf_ntohs(marlin_csum_fold(0xFFFFU)));
}

MARLIN_TEST(csum_fold_carry_out_of_first_fold_is_absorbed)
{
    /* sum = 0x1FFFF: the first fold produces 0xFFFF + 0x1 = 0x10000, itself
     * carrying out of 16 bits. A single-fold implementation stops here and
     * returns an incorrect 17-bit intermediate; the second fold absorbs
     * that carry, reaching 0x0001, whose complement is 0xFFFE.
     */
    CHECK_EQ(0xFFFE, bpf_ntohs(marlin_csum_fold(0x1FFFFU)));
}

MARLIN_TEST(ipv4_csum_known_vector_matches_hand_computed_value)
{
    struct iphdr iph;

    /* The textbook worked example for the IPv4 header checksum: this exact
     * 20-byte header's independently verified checksum is 0xb1e6.
     */
    memset(&iph, 0, sizeof(iph));
    iph.version = 4;
    iph.ihl = 5;
    iph.tot_len = bpf_htons(0x003c);
    iph.id = bpf_htons(0x1c46);
    iph.frag_off = bpf_htons(0x4000);
    iph.ttl = 0x40;
    iph.protocol = IPPROTO_TCP;
    iph.saddr = bpf_htonl(0xac100a63U);
    iph.daddr = bpf_htonl(0xac100a0cU);

    CHECK_EQ(0xb1e6, bpf_ntohs(marlin_ipv4_csum(&iph)));
}

MARLIN_TEST(ipv4_csum_ignores_whatever_check_already_holds)
{
    struct iphdr a;
    struct iphdr b;

    memset(&a, 0, sizeof(a));
    a.version = 4;
    a.ihl = 5;
    a.protocol = IPPROTO_UDP;
    a.saddr = bpf_htonl(0x0a0a0a0aU);
    a.daddr = bpf_htonl(0x0b0b0b0bU);
    a.check = 0;

    b = a;
    b.check = 0xAAAA; /* garbage, as if reused from a prior packet */

    CHECK_EQ(marlin_ipv4_csum(&a), marlin_ipv4_csum(&b));
}

MARLIN_TEST(ipv4_csum_self_check_zeros)
{
    struct iphdr iph;
    __u32 sum;

    /* A header carrying its own correct checksum re-sums, unfolded, to
     * all-ones -- the one's-complement identity every correct checksum
     * satisfies, independent of any hand-computed vector.
     */
    memset(&iph, 0, sizeof(iph));
    iph.version = 4;
    iph.ihl = 5;
    iph.tot_len = bpf_htons(60);
    iph.id = bpf_htons(0x1c46);
    iph.frag_off = bpf_htons(IP_DF);
    iph.ttl = 64;
    iph.protocol = IPPROTO_TCP;
    iph.saddr = bpf_htonl(0xac100a63U);
    iph.daddr = bpf_htonl(0xac100a0cU);

    iph.check = marlin_ipv4_csum(&iph);

    sum = marlin_csum_words(&iph, sizeof(iph), 0);
    CHECK_EQ(0, bpf_ntohs(marlin_csum_fold(sum)));
}

int main(void)
{
    return marlin_tests_main();
}
