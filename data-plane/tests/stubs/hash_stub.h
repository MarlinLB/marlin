/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Host stand-in for the one LRU_HASH the native tier looks up: `ratelimit`,
 * keyed by struct rl_key. Named generically like map_stub.h -- which is
 * itself hardcoded to the ACL tries despite its name -- but this stub is
 * ratelimit-specific: exact-key match, no eviction, and no dispatch of its
 * own. bpf_map_lookup_elem() in tests/stubs/bpf/bpf_helpers.h checks
 * hash_stub_owns() first and only falls through to the ACL trie stub on a
 * miss; reversing that order would let acl_stub_open() silently adopt
 * `ratelimit`'s address as an empty trie, and every case would then pass
 * vacuously.
 *
 * Lookup returns a pointer into the slot's own storage, never a copy:
 * ratelimit.c compare-and-swaps directly on the returned struct rl_bucket,
 * the same contract a real LRU_HASH lookup carries.
 */

#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <marlin/abi/types.h>

#define HASH_STUB_MAX_ENTRIES 32

struct hash_stub_slot {
    struct rl_key key;
    struct rl_bucket value;
    int used;
};

static const void *hash_stub_map_ptr;
static struct hash_stub_slot hash_stub_slots[HASH_STUB_MAX_ENTRIES];
static unsigned int hash_stub_lookups;
static unsigned int hash_stub_updates;
static struct rl_key hash_stub_last_key_;
static int hash_stub_force_update_failure;

static void hash_stub_die(const char *what)
{
    fprintf(stderr, "tests: hash stub: %s\n", what);
    exit(1);
}

/*
 * Cases share this file-static storage the way the packet tier shares a
 * loaded map, so each starts from a known-empty state rather than from
 * whatever the last one left. Takes the map object's address so
 * hash_stub_owns() below can tell "the ratelimit map" apart from every
 * other bpf_map_lookup_elem() caller in the same test binary.
 */
static __attribute__((unused)) void hash_stub_reset(const void *map)
{
    hash_stub_map_ptr = map;
    memset(hash_stub_slots, 0, sizeof(hash_stub_slots));
    memset(&hash_stub_last_key_, 0, sizeof(hash_stub_last_key_));
    hash_stub_lookups = 0;
    hash_stub_updates = 0;
    hash_stub_force_update_failure = 0;
}

static int hash_stub_owns(const void *map)
{
    return map == hash_stub_map_ptr;
}

static __attribute__((unused)) unsigned int hash_stub_lookup_count(void)
{
    return hash_stub_lookups;
}

static __attribute__((unused)) unsigned int hash_stub_update_count(void)
{
    return hash_stub_updates;
}

static __attribute__((unused)) const struct rl_key *hash_stub_last_key(void)
{
    return &hash_stub_last_key_;
}

/*
 * Makes the next bpf_map_update_elem() against this map fail, the way a
 * real LRU_HASH can under insert pressure. ratelimit.c's insert-failure
 * count has no other way to be driven from a native case.
 */
static __attribute__((unused)) void hash_stub_force_update_failure_once(void)
{
    hash_stub_force_update_failure = 1;
}

static struct hash_stub_slot *hash_stub_find(const struct rl_key *key)
{
    unsigned int i;

    for(i = 0; i < HASH_STUB_MAX_ENTRIES; i++) {
        if(hash_stub_slots[i].used && memcmp(&hash_stub_slots[i].key, key, sizeof(*key)) == 0) {
            return &hash_stub_slots[i];
        }
    }

    return NULL;
}

static void *hash_stub_lookup(void *map, const void *key)
{
    struct hash_stub_slot *slot;

    (void)map; /* dispatch already resolved this is the ratelimit map */
    hash_stub_lookups++;
    hash_stub_last_key_ = *(const struct rl_key *)key;

    slot = hash_stub_find((const struct rl_key *)key);
    return slot == NULL ? NULL : &slot->value;
}

static long hash_stub_update(void *map, const void *key, const void *value, __u64 flags)
{
    struct hash_stub_slot *slot;

    (void)map;
    (void)flags; /* BPF_ANY is the only flag ratelimit.c ever passes */

    hash_stub_updates++;
    hash_stub_last_key_ = *(const struct rl_key *)key;

    if(hash_stub_force_update_failure) {
        hash_stub_force_update_failure = 0;
        return -1;
    }

    slot = hash_stub_find((const struct rl_key *)key);
    if(slot == NULL) {
        unsigned int i;

        for(i = 0; i < HASH_STUB_MAX_ENTRIES; i++) {
            if(!hash_stub_slots[i].used) {
                slot = &hash_stub_slots[i];
                break;
            }
        }

        if(slot == NULL) {
            hash_stub_die("out of slots");
        }

        slot->key = *(const struct rl_key *)key;
        slot->used = 1;
    }

    slot->value = *(const struct rl_bucket *)value;
    return 0;
}
