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
