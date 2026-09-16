/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Map access for the bpf_prog_test_run tier: fd lookup by name, config
 * seeding, and drop_stats/vip_stats/backend_stats reads. Uses the real ABI structs from
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

/*
 * config is BPF_MAP_TYPE_ARRAY with max_entries=1, so it is pre-allocated
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

/*
 * drop_stats is BPF_MAP_TYPE_PERCPU_ARRAY: one __u64 slot per possible CPU
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

/*
 * vip_stats/backend_stats are BPF_MAP_TYPE_PERCPU_ARRAY of struct stats --
 * same per-CPU summing as xdp_drop_stats_total above, but the value is
 * packets+bytes rather than one __u64, so the sum is taken per field.
 */
static struct stats xdp_vip_stats_total(__u32 vip_num)
{
    int fd = xdp_map_fd("vip_stats");
    int ncpus = libbpf_num_possible_cpus();
    struct stats *percpu;
    struct stats total = {0};
    int i;

    if(ncpus <= 0) {
        fprintf(stderr, "packet-tests: libbpf_num_possible_cpus failed: %s\n", strerror(errno));
        exit(1);
    }

    percpu = calloc((size_t)ncpus, sizeof(*percpu));
    if(percpu == NULL) {
        fprintf(stderr, "packet-tests: out of memory reading vip_stats\n");
        exit(1);
    }

    if(bpf_map_lookup_elem(fd, &vip_num, percpu) != 0) {
        fprintf(stderr, "packet-tests: vip_stats lookup for index %u failed: %s\n", vip_num, strerror(errno));
        exit(1);
    }

    for(i = 0; i < ncpus; i++) {
        total.packets += percpu[i].packets;
        total.bytes += percpu[i].bytes;
    }

    free(percpu);
    return total;
}

static struct stats xdp_backend_stats_total(__u32 backend_id)
{
    int fd = xdp_map_fd("backend_stats");
    int ncpus = libbpf_num_possible_cpus();
    struct stats *percpu;
    struct stats total = {0};
    int i;

    if(ncpus <= 0) {
        fprintf(stderr, "packet-tests: libbpf_num_possible_cpus failed: %s\n", strerror(errno));
        exit(1);
    }

    percpu = calloc((size_t)ncpus, sizeof(*percpu));
    if(percpu == NULL) {
        fprintf(stderr, "packet-tests: out of memory reading backend_stats\n");
        exit(1);
    }

    if(bpf_map_lookup_elem(fd, &backend_id, percpu) != 0) {
        fprintf(stderr, "packet-tests: backend_stats lookup for index %u failed: %s\n", backend_id, strerror(errno));
        exit(1);
    }

    for(i = 0; i < ncpus; i++) {
        total.packets += percpu[i].packets;
        total.bytes += percpu[i].bytes;
    }

    free(percpu);
    return total;
}

/*
 * Builds the key from struct acl_key4/acl_key6 rather than a local
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

/*
 * BPF_F_NO_PREALLOC tries have no fixed slot set to zero between cases --
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

    /*
     * Re-querying with prev_key == NULL each pass rather than advancing
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

/*
 * tx_ports (DEVMAP_HASH, ifindex -> ifindex): the redirect target set for
 * data-plane/tests/packet/fib.h's FIB cases. Per-case like the ACL helpers
 * above, for the same order-independence reason.
 */
static __attribute__((unused)) void xdp_tx_ports_add(__u32 ifindex)
{
    int fd = xdp_map_fd("tx_ports");

    if(bpf_map_update_elem(fd, &ifindex, &ifindex, BPF_ANY) != 0) {
        fprintf(stderr, "packet-tests: failed to seed tx_ports[%u]: %s\n", ifindex, strerror(errno));
        exit(1);
    }
}

/*
 * Non-fatal on ENOENT: teardown at the start of a case must tolerate an
 * entry a failed earlier case never inserted.
 */
static __attribute__((unused)) void xdp_tx_ports_del(__u32 ifindex)
{
    int fd = xdp_map_fd("tx_ports");

    if(bpf_map_delete_elem(fd, &ifindex) != 0 && errno != ENOENT) {
        fprintf(stderr, "packet-tests: failed to clear tx_ports[%u]: %s\n", ifindex, strerror(errno));
        exit(1);
    }
}

static __attribute__((unused)) int xdp_tx_ports_is_empty(void)
{
    int fd = xdp_map_fd("tx_ports");
    __u32 next;

    return bpf_map_get_next_key(fd, NULL, &next) != 0;
}

/*
 * Drains every entry, not just the one(s) a case knows it added -- the same
 * drain-first-key loop as xdp_acl_clear, for a DEVMAP_HASH with no fixed
 * baseline to reset to.
 */
static __attribute__((unused)) void xdp_tx_ports_clear(void)
{
    int fd = xdp_map_fd("tx_ports");
    __u32 next;

    while(bpf_map_get_next_key(fd, NULL, &next) == 0) {
        if(bpf_map_delete_elem(fd, &next) != 0) {
            fprintf(stderr, "packet-tests: failed to clear an entry from tx_ports: %s\n", strerror(errno));
            exit(1);
        }
    }
}

/*
 * ratelimit (LRU_HASH, struct rl_key -> struct rl_bucket): built from the
 * real ABI structs, same discipline as the ACL helpers above. `addr16` is
 * the full 16-byte rl_key.addr -- a caller keying an IPv4 case zero-extends
 * it, mirroring the zeroed key ratelimit.c itself builds.
 */
static __attribute__((unused)) void xdp_rl_seed(__u8 family, const unsigned char addr16[16], __u64 state)
{
    struct rl_key key;
    struct rl_bucket bucket;
    int fd = xdp_map_fd("ratelimit");

    memset(&key, 0, sizeof(key));
    key.family = family;
    memcpy(key.addr, addr16, sizeof(key.addr));

    bucket.state = state;

    if(bpf_map_update_elem(fd, &key, &bucket, BPF_ANY) != 0) {
        fprintf(stderr, "packet-tests: failed to seed ratelimit: %s\n", strerror(errno));
        exit(1);
    }
}

/* Returns 0 on a miss rather than exiting: a case asserting the miss path
 * inserted a bucket needs to distinguish "not present" from "present".
 */
static __attribute__((unused)) int xdp_rl_get(__u8 family, const unsigned char addr16[16], __u64 *state)
{
    struct rl_key key;
    struct rl_bucket bucket;
    int fd = xdp_map_fd("ratelimit");

    memset(&key, 0, sizeof(key));
    key.family = family;
    memcpy(key.addr, addr16, sizeof(key.addr));

    if(bpf_map_lookup_elem(fd, &key, &bucket) != 0) {
        return 0;
    }

    *state = bucket.state;
    return 1;
}

/*
 * Drains every entry -- the same drain-first-key loop as xdp_acl_clear and
 * xdp_tx_ports_clear, for an LRU_HASH with no fixed baseline to reset to.
 */
static __attribute__((unused)) void xdp_rl_clear(void)
{
    int fd = xdp_map_fd("ratelimit");
    struct rl_key next;

    while(bpf_map_get_next_key(fd, NULL, &next) == 0) {
        if(bpf_map_delete_elem(fd, &next) != 0) {
            fprintf(stderr, "packet-tests: failed to clear an entry from ratelimit: %s\n", strerror(errno));
            exit(1);
        }
    }
}

/*
 * vip_map (HASH, struct vip_key -> struct vip_meta): built from the real ABI
 * structs, same discipline as the ACL helpers above. The key must be zeroed
 * before its fields are set -- balancer.c builds its lookup key with a
 * memset and an IPv4 packet leaves addr6[1..3] zero, so a userspace key with
 * anything else there silently fails to match.
 */
static __attribute__((unused)) void xdp_vip_add(const struct vip_key *key, const struct vip_meta *meta)
{
    int fd = xdp_map_fd("vip_map");

    if(bpf_map_update_elem(fd, key, meta, BPF_ANY) != 0) {
        fprintf(stderr, "packet-tests: failed to seed vip_map: %s\n", strerror(errno));
        exit(1);
    }
}

/* Non-fatal on ENOENT, for the same teardown reason as xdp_tx_ports_del. */
static __attribute__((unused)) void xdp_vip_del(const struct vip_key *key)
{
    int fd = xdp_map_fd("vip_map");

    if(bpf_map_delete_elem(fd, key) != 0 && errno != ENOENT) {
        fprintf(stderr, "packet-tests: failed to clear a vip_map entry: %s\n", strerror(errno));
        exit(1);
    }
}

static __attribute__((unused)) void xdp_vip_clear(void)
{
    int fd = xdp_map_fd("vip_map");
    struct vip_key next;

    while(bpf_map_get_next_key(fd, NULL, &next) == 0) {
        if(bpf_map_delete_elem(fd, &next) != 0) {
            fprintf(stderr, "packet-tests: failed to clear an entry from vip_map: %s\n", strerror(errno));
            exit(1);
        }
    }
}

/*
 * fwd_table is one flat ARRAY of MAX_VIPS * TABLE_SIZE slots; VIP `vip_num`
 * owns the block at vip_num * TABLE_SIZE and balancer.c picks a row inside it
 * with a keyed SipHash over the packet tuple. Userspace cannot recompute that
 * row without duplicating both the hash and struct packet_tuple's exact
 * layout, so every slot in the block is written instead: the row a packet
 * lands on stops mattering and a forwarding case asserts selection without
 * depending on a reimplementation staying in step.
 */
static void xdp_fwd_write_block(__u32 vip_num, __u32 id_even, __u32 id_odd)
{
    LIBBPF_OPTS(bpf_map_batch_opts, opts);
    int fd = xdp_map_fd("fwd_table");
    __u32 base = vip_num * TABLE_SIZE;
    __u32 count = TABLE_SIZE;
    __u32 *keys, *values;
    __u32 i;

    keys = calloc(TABLE_SIZE, sizeof(*keys));
    values = calloc(TABLE_SIZE, sizeof(*values));

    if(keys == NULL || values == NULL) {
        fprintf(stderr, "packet-tests: out of memory writing fwd_table\n");
        exit(1);
    }

    for(i = 0; i < TABLE_SIZE; i++) {
        keys[i] = base + i;
        values[i] = (i & 1U) ? id_odd : id_even;
    }

    /* ARRAY batch update needs 5.6; the element loop is the fallback. */
    if(bpf_map_update_batch(fd, keys, values, &count, &opts) != 0 || count != TABLE_SIZE) {
        for(i = 0; i < TABLE_SIZE; i++) {
            if(bpf_map_update_elem(fd, &keys[i], &values[i], BPF_ANY) != 0) {
                fprintf(stderr, "packet-tests: failed to write fwd_table[%u]: %s\n", keys[i], strerror(errno));
                exit(1);
            }
        }
    }

    free(values);
    free(keys);
}

static __attribute__((unused)) void xdp_fwd_fill(__u32 vip_num, __u32 id)
{
    xdp_fwd_write_block(vip_num, id, id);
}

/*
 * Splits a VIP's block between two backends on the low bit of the row index.
 * Which backend a packet reaches then reports one bit of its hash, which is
 * what lets a case observe that a tuple field does or does not feed the hash
 * without ever computing it.
 */
static __attribute__((unused)) void xdp_fwd_fill_striped(__u32 vip_num, __u32 id_even, __u32 id_odd)
{
    xdp_fwd_write_block(vip_num, id_even, id_odd);
}

static __attribute__((unused)) void xdp_fwd_clear(__u32 vip_num)
{
    xdp_fwd_write_block(vip_num, 0, 0);
}

/*
 * backends is an ARRAY, so index 0 exists but balancer.c treats a zero
 * forwarding-table slot as "empty" and refuses to resolve it. Callers must
 * pass a non-zero id for a backend they expect to be reachable.
 */
static __attribute__((unused)) void xdp_backend_write(__u32 id, const struct backend *be)
{
    int fd = xdp_map_fd("backends");

    if(bpf_map_update_elem(fd, &id, be, BPF_ANY) != 0) {
        fprintf(stderr, "packet-tests: failed to seed backends[%u]: %s\n", id, strerror(errno));
        exit(1);
    }
}

static __attribute__((unused)) void xdp_backend_clear(__u32 id)
{
    struct backend be;

    memset(&be, 0, sizeof(be));
    xdp_backend_write(id, &be);
}
