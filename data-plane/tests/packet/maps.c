/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Definitions for maps.h's map-access helpers. See the header comment on
 * tests/support/harness.c for why this is a separate translation unit rather
 * than included inline.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "maps.h"
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
void xdp_seed_config(const struct marlin_config *cfg)
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
__u64 xdp_drop_stats_total(int rc)
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
struct stats xdp_vip_stats_total(__u32 vip_num)
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

struct stats xdp_backend_stats_total(__u32 backend_id)
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

void xdp_acl_add4(const char *map, __u32 prefixlen, __be32 addr, __u32 rule_id)
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

void xdp_acl_add6(const char *map, __u32 prefixlen, const unsigned char addr16[16], __u32 rule_id)
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
 * Re-querying with prev_key == NULL each pass rather than advancing from
 * `next`: this map has no fixed key we could re-seed as a sentinel, and
 * re-querying "the first key still present" drains the trie in max_entries
 * iterations without needing one. The largest key in this file (acl_key6)
 * sizes the buffer; a smaller key (acl_key4) leaves it partially unused,
 * which get_next_key ignores since it takes key_size from the map itself,
 * not from this buffer's size.
 */
void xdp_acl_clear(const char *map)
{
    int fd = xdp_map_fd(map);
    unsigned char next[sizeof(struct acl_key6)];

    while(bpf_map_get_next_key(fd, NULL, next) == 0) {
        if(bpf_map_delete_elem(fd, next) != 0) {
            fprintf(stderr, "packet-tests: failed to clear an entry from %s: %s\n", map, strerror(errno));
            exit(1);
        }
    }
}

void xdp_tx_ports_add(__u32 ifindex)
{
    int fd = xdp_map_fd("tx_ports");

    if(bpf_map_update_elem(fd, &ifindex, &ifindex, BPF_ANY) != 0) {
        fprintf(stderr, "packet-tests: failed to seed tx_ports[%u]: %s\n", ifindex, strerror(errno));
        exit(1);
    }
}

void xdp_tx_ports_del(__u32 ifindex)
{
    int fd = xdp_map_fd("tx_ports");

    if(bpf_map_delete_elem(fd, &ifindex) != 0 && errno != ENOENT) {
        fprintf(stderr, "packet-tests: failed to clear tx_ports[%u]: %s\n", ifindex, strerror(errno));
        exit(1);
    }
}

int xdp_tx_ports_is_empty(void)
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
void xdp_tx_ports_clear(void)
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

void xdp_rl_seed(__u8 family, const unsigned char addr16[16], __u64 state)
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

int xdp_rl_get(__u8 family, const unsigned char addr16[16], __u64 *state)
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
void xdp_rl_clear(void)
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

void xdp_vip_add(const struct vip_key *key, const struct vip_meta *meta)
{
    int fd = xdp_map_fd("vip_map");

    if(bpf_map_update_elem(fd, key, meta, BPF_ANY) != 0) {
        fprintf(stderr, "packet-tests: failed to seed vip_map: %s\n", strerror(errno));
        exit(1);
    }
}

void xdp_vip_del(const struct vip_key *key)
{
    int fd = xdp_map_fd("vip_map");

    if(bpf_map_delete_elem(fd, key) != 0 && errno != ENOENT) {
        fprintf(stderr, "packet-tests: failed to clear a vip_map entry: %s\n", strerror(errno));
        exit(1);
    }
}

void xdp_vip_clear(void)
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

void xdp_fwd_fill(__u32 vip_num, __u32 id)
{
    xdp_fwd_write_block(vip_num, id, id);
}

void xdp_fwd_fill_striped(__u32 vip_num, __u32 id_even, __u32 id_odd)
{
    xdp_fwd_write_block(vip_num, id_even, id_odd);
}

void xdp_fwd_clear(__u32 vip_num)
{
    xdp_fwd_write_block(vip_num, 0, 0);
}

void xdp_backend_write(__u32 id, const struct backend *be)
{
    int fd = xdp_map_fd("backends");

    if(bpf_map_update_elem(fd, &id, be, BPF_ANY) != 0) {
        fprintf(stderr, "packet-tests: failed to seed backends[%u]: %s\n", id, strerror(errno));
        exit(1);
    }
}

void xdp_backend_clear(__u32 id)
{
    struct backend be;

    memset(&be, 0, sizeof(be));
    xdp_backend_write(id, &be);
}
