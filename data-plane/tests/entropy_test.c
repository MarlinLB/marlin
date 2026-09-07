/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Native unit tests for entropy.h. Pure arithmetic over marlin_ctx.tuple:
 * no bpf_* helper, no map, so nothing here needs tests/stubs.
 */

#include <string.h>

#include <linux/in.h>

#include <bpf/bpf_endian.h>

#include <marlin/entropy.h>

#include "harness.h"

static void tuple_init(struct packet_tuple *t, __be32 src0, __be32 dst0, __u16 sport_host, __u16 dport_host, __u8 proto)
{
    memset(t, 0, sizeof(*t));
    t->src[0] = src0;
    t->dst[0] = dst0;
    t->sport = bpf_htons(sport_host);
    t->dport = bpf_htons(dport_host);
    t->proto = proto;
    t->family = AF_INET;
}

MARLIN_TEST(entropy_sport_is_deterministic_for_a_repeated_tuple)
{
    struct packet_tuple t;
    __be16 first;
    __be16 second;

    tuple_init(&t, 0x0a0a0a0aU, 0x0b0b0b0bU, 11111, 80, IPPROTO_TCP);

    first = marlin_entropy_sport(&t);
    second = marlin_entropy_sport(&t);

    CHECK_EQ(first, second);
}

MARLIN_TEST(entropy_sport_differs_when_only_the_inner_source_port_differs)
{
    struct packet_tuple a;
    struct packet_tuple b;

    /* The assertion that separates this from the selection hash
     * (docs/design/12-selection.md:10), which reads tuple.src only and
     * would return the same row for both of these.
     */
    tuple_init(&a, 0x0a0a0a0aU, 0x0b0b0b0bU, 11111, 80, IPPROTO_TCP);
    tuple_init(&b, 0x0a0a0a0aU, 0x0b0b0b0bU, 22222, 80, IPPROTO_TCP);

    CHECK_TRUE(marlin_entropy_sport(&a) != marlin_entropy_sport(&b));
}

MARLIN_TEST(entropy_sport_stays_in_the_ephemeral_range)
{
    struct packet_tuple t;
    __u16 sport_host;
    __be32 src;
    __be32 dst;
    __u16 sport;
    __u16 dport;
    int i;

    /* Sweep a spread of tuples rather than asserting one: containment in
     * range is a property of the whole function, not one input.
     */
    for(i = 0; i < 4096; i++) {
        src = bpf_htonl((__u32)(0x0a000000U + (__u32)i));
        dst = bpf_htonl((__u32)(0x0b000000U + (__u32)(i * 7)));
        sport = (__u16)(1024 + i);
        dport = (__u16)(80 + (i % 5));

        tuple_init(&t, src, dst, sport, dport, (__u8)((i % 2) ? IPPROTO_UDP : IPPROTO_TCP));

        sport_host = bpf_ntohs(marlin_entropy_sport(&t));

        if(sport_host < MARLIN_ENTROPY_SPORT_MIN || sport_host > 65535) {
            MARLIN_FAIL("entropy sport %u outside [%u, 65535] for tuple %d", sport_host, MARLIN_ENTROPY_SPORT_MIN, i);
            return;
        }
    }
}

MARLIN_TEST(entropy_sport_is_stable_for_a_fragment_with_zero_ports)
{
    struct packet_tuple a;
    struct packet_tuple b;

    /* A non-first fragment carries no L4 header: sport and dport stay zero
     * in both directions, and the hash must still produce one stable value
     * per connection rather than failing or colliding on the missing ports
     * alone (docs/design/14-forwarding-modes.md:66-68).
     */
    tuple_init(&a, 0x0a0a0a0aU, 0x0b0b0b0bU, 0, 0, IPPROTO_UDP);
    a.sport = 0;
    a.dport = 0;

    b = a;

    CHECK_EQ(marlin_entropy_sport(&a), marlin_entropy_sport(&b));
}

int main(void)
{
    return marlin_tests_main();
}
