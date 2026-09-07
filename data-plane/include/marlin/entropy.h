/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * The outer UDP source port entropy hash shared by gue.c and vxlan.c
 * (docs/design/14-forwarding-modes.md SS7.3). Deliberately not the
 * selection hash (docs/design/12-selection.md), which reads the client
 * address only and would collapse every connection from one client onto a
 * single path and receive queue if reused here. A header, not a translation
 * unit: it takes only a BTF struct pointer already resolved by the caller
 * and reads no packet bytes (docs/design/03-translation-units.md).
 */

#pragma once

#include <linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <marlin/marlin.h>

#define MARLIN_ENTROPY_SPORT_MIN   49152U /* IANA ephemeral range floor */
#define MARLIN_ENTROPY_SPORT_RANGE 16384U /* MIN + RANGE - 1 == 65535 */

/* MurmurHash3's 32-bit finalizer, applied as a running mix per field rather
 * than only once at the end: each call both folds v into h and re-avalanches
 * h, so the single unavoidable final pass below still de-correlates the
 * output from whichever field happens to be mixed in last.
 */
static __always_inline __u32 marlin_entropy_mix(__u32 h, __u32 v)
{
    h ^= v;
    h *= 0x85ebca6bU;
    h ^= h >> 13;
    return h;
}

/* Hashes the five named 5-tuple fields explicitly -- never
 * sizeof(struct packet_tuple) whole. tuple.pad's zeroing invariant belongs
 * to the selection hash (docs/design/10-map-invariants.md), and hashing it
 * here too would make this a second consumer of that invariant for no
 * reason; family is already implied by which of src/dst's trailing words
 * are zero, so leaving it out with pad costs nothing.
 */
static __always_inline __be16 marlin_entropy_sport(const struct packet_tuple *tuple)
{
    __u32 h = 0;
    int i;

    for(i = 0; i < 4; i++) {
        h = marlin_entropy_mix(h, tuple->src[i]);
    }

    for(i = 0; i < 4; i++) {
        h = marlin_entropy_mix(h, tuple->dst[i]);
    }

    h = marlin_entropy_mix(h, ((__u32)tuple->sport << 16) | tuple->dport);
    h = marlin_entropy_mix(h, tuple->proto);

    /* The rest of MurmurHash3's finalizer: without this final avalanche the
     * low bits fed to the modulo below would be a near-linear function of
     * whichever field was mixed in last.
     */
    h ^= h >> 16;
    h *= 0x85ebca6bU;
    h ^= h >> 13;
    h *= 0xc2b2ae35U;
    h ^= h >> 16;

    return bpf_htons((__u16)(MARLIN_ENTROPY_SPORT_MIN + (h % MARLIN_ENTROPY_SPORT_RANGE)));
}
