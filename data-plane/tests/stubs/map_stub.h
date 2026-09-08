/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Host stand-in for the LPM tries the native tier's translation units look
 * up, reached through tests/stubs/bpf/bpf_helpers.h's bpf_map_lookup_elem.
 * A trie is identified by the address of the map object itself, the only
 * thing a caller hands the helper, and its rules live in a flat array
 * scanned longest-match-first: what a test asserts is the result the
 * kernel's trie produces, so building a trie here would reproduce its
 * structure rather than check the code that queries it.
 */

#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/types.h>

#include <marlin/abi/types.h>

#define ACL_STUB_MAX_TRIES 8
#define ACL_STUB_MAX_RULES 16

struct acl_stub_rule {
    __u32 prefixlen;
    unsigned char addr[16];
    __u32 value;
};

struct acl_stub_trie {
    const void *map;
    __u32 addr_bits; /* 32 or 128; 0 until an add fixes it */
    unsigned int rules;
    struct acl_stub_rule rule[ACL_STUB_MAX_RULES];

    /*
     * What the code under test last asked this map for, so a case can
     * assert a lookup was skipped rather than only that its verdict was
     * unchanged -- the two are indistinguishable from the return value.
     */
    unsigned int lookups;
    __u32 last_prefixlen;
    unsigned int last_addr_len;
    unsigned char last_addr[16];
};

static struct acl_stub_trie acl_stub_tries[ACL_STUB_MAX_TRIES];
static unsigned int acl_stub_trie_count;

static void acl_stub_die(const char *what)
{
    fprintf(stderr, "tests: map stub: %s\n", what);
    exit(1);
}

static struct acl_stub_trie *acl_stub_find(const void *map)
{
    unsigned int i;

    for(i = 0; i < acl_stub_trie_count; i++) {
        if(acl_stub_tries[i].map == map) {
            return &acl_stub_tries[i];
        }
    }

    return NULL;
}

static struct acl_stub_trie *acl_stub_open(const void *map, __u32 addr_bits)
{
    struct acl_stub_trie *trie = acl_stub_find(map);

    if(trie == NULL) {
        if(acl_stub_trie_count == ACL_STUB_MAX_TRIES) {
            acl_stub_die("out of trie slots");
        }

        trie = &acl_stub_tries[acl_stub_trie_count++];
        trie->map = map;
    }

    if(trie->addr_bits == 0U) {
        trie->addr_bits = addr_bits;
    } else if(addr_bits != 0U && trie->addr_bits != addr_bits) {
        acl_stub_die("one map seeded for both address families");
    }

    return trie;
}

/*
 * Cases share this file-static storage the way the packet tier shares a
 * loaded map, so each starts from a known-empty state rather than from
 * whatever the last one left (tests/packet/maps.h's xdp_acl_clear).
 */
static __attribute__((unused)) void acl_stub_reset(void)
{
    memset(acl_stub_tries, 0, sizeof(acl_stub_tries));
    acl_stub_trie_count = 0;
}

/*
 * Builds the key through struct acl_key4/acl_key6 rather than a local
 * re-declaration, same as tests/packet/maps.h -- a types.h layout change
 * must fail a test, not quietly seed a rule no lookup can match.
 */
static __attribute__((unused)) void acl_stub_add4(const void *map, __u32 prefixlen, __be32 addr, __u32 rule_id)
{
    struct acl_stub_trie *trie = acl_stub_open(map, 32);
    struct acl_key4 key;

    if(prefixlen > 32U) {
        acl_stub_die("v4 prefixlen above 32; the kernel rejects the update with EINVAL");
    }

    if(trie->rules == ACL_STUB_MAX_RULES) {
        acl_stub_die("out of rule slots");
    }

    key.prefixlen = prefixlen;
    key.addr = addr;

    trie->rule[trie->rules].prefixlen = key.prefixlen;
    memcpy(trie->rule[trie->rules].addr, &key.addr, sizeof(key.addr));
    trie->rule[trie->rules].value = rule_id;
    trie->rules++;
}

static __attribute__((unused)) void acl_stub_add6(const void *map, __u32 prefixlen, const unsigned char addr16[16],
                                                  __u32 rule_id)
{
    struct acl_stub_trie *trie = acl_stub_open(map, 128);
    struct acl_key6 key;

    if(prefixlen > 128U) {
        acl_stub_die("v6 prefixlen above 128; the kernel rejects the update with EINVAL");
    }

    if(trie->rules == ACL_STUB_MAX_RULES) {
        acl_stub_die("out of rule slots");
    }

    key.prefixlen = prefixlen;
    memcpy(key.addr, addr16, sizeof(key.addr));

    trie->rule[trie->rules].prefixlen = key.prefixlen;
    memcpy(trie->rule[trie->rules].addr, key.addr, sizeof(key.addr));
    trie->rule[trie->rules].value = rule_id;
    trie->rules++;
}

static __attribute__((unused)) unsigned int acl_stub_lookups(const void *map)
{
    const struct acl_stub_trie *trie = acl_stub_find(map);

    return trie == NULL ? 0U : trie->lookups;
}

static __attribute__((unused)) __u32 acl_stub_last_prefixlen(const void *map)
{
    const struct acl_stub_trie *trie = acl_stub_find(map);

    return trie == NULL ? 0U : trie->last_prefixlen;
}

static __attribute__((unused)) unsigned int acl_stub_last_addr_len(const void *map)
{
    const struct acl_stub_trie *trie = acl_stub_find(map);

    return trie == NULL ? 0U : trie->last_addr_len;
}

static __attribute__((unused)) const unsigned char *acl_stub_last_addr(const void *map)
{
    static const unsigned char none[16];
    const struct acl_stub_trie *trie = acl_stub_find(map);

    return trie == NULL ? none : trie->last_addr;
}

/*
 * Byte-order-free by construction: both key structs hold the address in
 * network order, so byte 0 carries the leading octet and the prefix is the
 * first `prefixlen` bits of memory -- the same bit string the kernel's trie
 * descends.
 */
static int acl_stub_prefix_match(const unsigned char *rule, const unsigned char *key, __u32 prefixlen)
{
    __u32 whole = prefixlen / 8U;
    __u32 bits = prefixlen % 8U;

    if(whole != 0U && memcmp(rule, key, whole) != 0) {
        return 0;
    }

    if(bits != 0U) {
        unsigned char mask = (unsigned char)(0xffU << (8U - bits));

        if(((rule[whole] ^ key[whole]) & mask) != 0U) {
            return 0;
        }
    }

    return 1;
}

static void *acl_stub_lookup(void *map, const void *key)
{
    /*
     * prefixlen is at offset 0 in both key structs (abi/types.h asserts it),
     * so it is readable before the key's width is known.
     */
    const struct acl_key4 *hdr = key;
    struct acl_stub_trie *trie = acl_stub_open(map, 0);
    struct acl_stub_rule *best = NULL;
    unsigned char query[16];
    unsigned int i;

    trie->lookups++;
    trie->last_prefixlen = hdr->prefixlen;
    trie->last_addr_len = 0;
    memset(trie->last_addr, 0, sizeof(trie->last_addr));

    /*
     * The helper signature carries no key size, so the width comes from the
     * trie the rules were seeded at, and a key not presenting exactly that
     * is refused: reading an 8-byte acl_key4 as an acl_key6 is an
     * out-of-bounds read of the caller's stack frame, and both a
     * partial-width key and a cross-family lookup are bugs in the code
     * under test that a recorded miss reports rather than an ASan abort.
     */
    if(trie->addr_bits == 0U || hdr->prefixlen != trie->addr_bits) {
        return NULL;
    }

    memset(query, 0, sizeof(query));

    if(trie->addr_bits == 32U) {
        memcpy(query, &hdr->addr, sizeof(hdr->addr));
    } else {
        const struct acl_key6 *key6 = key;

        memcpy(query, key6->addr, sizeof(key6->addr));
    }

    trie->last_addr_len = trie->addr_bits / 8U;
    memcpy(trie->last_addr, query, trie->last_addr_len);

    for(i = 0; i < trie->rules; i++) {
        struct acl_stub_rule *rule = &trie->rule[i];

        if(rule->prefixlen > hdr->prefixlen) {
            continue;
        }

        if(!acl_stub_prefix_match(rule->addr, query, rule->prefixlen)) {
            continue;
        }

        if(best == NULL || rule->prefixlen > best->prefixlen) {
            best = rule;
        }
    }

    return best == NULL ? NULL : &best->value;
}
