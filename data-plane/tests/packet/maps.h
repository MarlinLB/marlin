/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Map access for the bpf_prog_test_run tier: fd lookup by name, config
 * seeding, and drop_stats reads. Uses the real ABI structs from
 * include/marlin/abi/types.h -- never a local re-declaration, so a
 * types.h layout change fails a test instead of corrupting a map write
 * silently.
 */

#pragma once

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/bpf.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <marlin/abi/types.h>
#include <marlin/marlin.h>

#include "prog.h"

static int xdp_map_fd(const char *name)
{
    struct bpf_map *map = bpf_object__find_map_by_name(xdp_obj, name);
    int fd;

    if(map == NULL) {
        fprintf(stderr, "packet-tests: map \"%s\" not found\n", name);
        exit(1);
    }

    fd = bpf_map__fd(map);
    if(fd < 0) {
        fprintf(stderr, "packet-tests: no fd for map \"%s\": %s\n", name, strerror(errno));
        exit(1);
    }

    return fd;
}

/* config is BPF_MAP_TYPE_ARRAY with max_entries=1, so it is pre-allocated
 * and zero-filled at load -- bpf_map_lookup_elem never returns NULL for
 * index 0 (main.c:20-24's !cfgp branch is dynamically unreachable, see the
 * plan). Seeding it exercises the write path rather than something a test
 * can observe fail; every case still seeds it so the mechanism is in place
 * before the first config-dependent behaviour lands.
 */
static void xdp_seed_config(const struct marlin_config *cfg)
{
    __u32 key = 0;
    int fd = xdp_map_fd("config");

    if(bpf_map_update_elem(fd, &key, cfg, BPF_ANY) != 0) {
        fprintf(stderr, "packet-tests: failed to seed config: %s\n", strerror(errno));
        exit(1);
    }
}

/* drop_stats is BPF_MAP_TYPE_PERCPU_ARRAY: one __u64 slot per possible CPU
 * per index (stride is value_size rounded up to 8 bytes -- already 8 here,
 * so no padding between slots). Summed across CPUs since a test packet can
 * land on any of them and a prior case's traffic may have run on others.
 */
static __u64 xdp_drop_stats_total(int rc)
{
    int fd = xdp_map_fd("drop_stats");
    int ncpus = libbpf_num_possible_cpus();
    __u32 key = (__u32)rc;
    __u64 *percpu;
    __u64 total = 0;
    int i;

    if(ncpus <= 0) {
        fprintf(stderr, "packet-tests: libbpf_num_possible_cpus failed: %s\n", strerror(errno));
        exit(1);
    }

    percpu = calloc((size_t)ncpus, sizeof(*percpu));
    if(percpu == NULL) {
        fprintf(stderr, "packet-tests: out of memory reading drop_stats\n");
        exit(1);
    }

    if(bpf_map_lookup_elem(fd, &key, percpu) != 0) {
        fprintf(stderr, "packet-tests: drop_stats lookup for index %d failed: %s\n", rc, strerror(errno));
        exit(1);
    }

    for(i = 0; i < ncpus; i++) {
        total += percpu[i];
    }

    free(percpu);
    return total;
}

/* Builds the key from struct acl_key4/acl_key6 rather than a local
 * re-declaration, same as every other helper here -- a types.h layout change
 * must fail a test, not corrupt a map write silently.
 */
static __attribute__((unused)) void xdp_acl_add4(const char *map, __u32 prefixlen, __be32 addr, __u32 rule_id)
{
    struct acl_key4 key;
    int fd = xdp_map_fd(map);

    key.prefixlen = prefixlen;
    key.addr = addr;

    if(bpf_map_update_elem(fd, &key, &rule_id, BPF_ANY) != 0) {
        fprintf(stderr, "packet-tests: failed to seed %s: %s\n", map, strerror(errno));
        exit(1);
    }
}

static __attribute__((unused)) void xdp_acl_add6(const char *map, __u32 prefixlen, const unsigned char addr16[16], __u32 rule_id)
{
    struct acl_key6 key;
    int fd = xdp_map_fd(map);

    key.prefixlen = prefixlen;
    memcpy(key.addr, addr16, sizeof(key.addr));

    if(bpf_map_update_elem(fd, &key, &rule_id, BPF_ANY) != 0) {
        fprintf(stderr, "packet-tests: failed to seed %s: %s\n", map, strerror(errno));
        exit(1);
    }
}

/* BPF_F_NO_PREALLOC tries have no fixed slot set to zero between cases --
 * bpf_map_get_next_key() walks whatever the previous case left, so each ACL
 * case must clear its own trie rather than relying on a zeroed baseline.
 * The largest key in this file (acl_key6) sized the buffer; a smaller key
 * (acl_key4) leaves it partially unused, which get_next_key ignores since it
 * takes key_size from the map itself, not from this buffer's size.
 */
static __attribute__((unused)) void xdp_acl_clear(const char *map)
{
    int fd = xdp_map_fd(map);
    unsigned char next[sizeof(struct acl_key6)];

    /* Re-querying with prev_key == NULL each pass rather than advancing
     * from `next`: this map has no fixed key we could re-seed as a
     * sentinel, and re-querying "the first key still present" drains the
     * trie in max_entries iterations without needing one.
     */
    while(bpf_map_get_next_key(fd, NULL, next) == 0) {
        if(bpf_map_delete_elem(fd, next) != 0) {
            fprintf(stderr, "packet-tests: failed to clear an entry from %s: %s\n", map, strerror(errno));
            exit(1);
        }
    }
}
