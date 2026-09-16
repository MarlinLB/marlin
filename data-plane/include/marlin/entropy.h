/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Outer UDP source port entropy hash for GUE and VXLAN encapsulation.
 * Header only: takes a resolved BTF struct pointer and reads no packet bytes.
 */

#pragma once

#include <linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <marlin/marlin.h>

#define MARLIN_ENTROPY_SPORT_MIN   49152U /* IANA ephemeral range floor */
#define MARLIN_ENTROPY_SPORT_RANGE 16384U /* MIN + RANGE - 1 == 65535 */

/* MurmurHash3 running mix: fold and re-avalanche per field. */
static __always_inline __u32 marlin_entropy_mix(__u32 hash, __u32 val)
{
    hash ^= val;
    hash *= 0x85ebca6bU;
    hash ^= hash >> 13;
    return hash;
}

/*
 * Hash the five 5-tuple fields individually, not the whole struct. Skip
 * tuple.pad and family: family is implied by src/dst trailing zeros.
 */
static __always_inline __be16 marlin_entropy_sport(const struct packet_tuple *tuple)
{
    __u32 hash = 0;

    for(int i = 0; i < 4; i++) {
        hash = marlin_entropy_mix(hash, tuple->src[i]);
    }

    for(int i = 0; i < 4; i++) {
        hash = marlin_entropy_mix(hash, tuple->dst[i]);
    }

    hash = marlin_entropy_mix(hash, ((__u32)tuple->sport << 16) | tuple->dport);
    hash = marlin_entropy_mix(hash, tuple->proto);

    /* MurmurHash3 final avalanche to decorrelate output from last input. */
    hash ^= hash >> 16;
    hash *= 0x85ebca6bU;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35U;
    hash ^= hash >> 16;

    return bpf_htons((__u16)(MARLIN_ENTROPY_SPORT_MIN + (hash % MARLIN_ENTROPY_SPORT_RANGE)));
}
