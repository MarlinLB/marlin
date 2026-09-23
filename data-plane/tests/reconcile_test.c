/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Native reconciliation tests with in-memory maps that observe routing between writes.
 */

#include <stdarg.h>

#include <linux/in.h>

#include "../marlind/hash.c"
#include "../marlind/fwd_gen.c"
#include "../marlind/vip_alloc.c"
#include "../marlind/reconcile.c"

#include "harness.h"

enum test_map_fd {
    TEST_CONFIG = 1,
    TEST_BACKENDS,
    TEST_FWD,
    TEST_VIPS,
    TEST_TX,
    TEST_ALLOW4,
    TEST_BLOCK4,
    TEST_ALLOW6,
    TEST_BLOCK6,
};

struct bpf_object {
    int unused;
};

struct bpf_map {
    const char *name;
    int fd;
};

static struct bpf_map test_maps[] = {
    { "config", TEST_CONFIG },       { "backends", TEST_BACKENDS },   { "fwd_table", TEST_FWD },
    { "vip_map", TEST_VIPS },        { "tx_ports", TEST_TX },         { "acl_allow_v4", TEST_ALLOW4 },
    { "acl_block_v4", TEST_BLOCK4 }, { "acl_allow_v6", TEST_ALLOW6 }, { "acl_block_v6", TEST_BLOCK6 },
};

#define TEST_KEY_COUNT 8U

static struct {
    struct vip_key key;
    struct vip_meta meta;
    bool live;
} live_vips[TEST_KEY_COUNT];
static __u32 live_count;
static __u32 fwd_values[MAX_VIPS * TABLE_SIZE];
static struct backend backend_values[MAX_BACKENDS];
static struct marlin_config config_value;
static __u32 old_backend[TEST_KEY_COUNT + 1];
static __u32 desired_backend[TEST_KEY_COUNT + 1];
static __u32 wrong_routes;
static __u32 mutations;
static int fail_key;
static int fail_row;
static bool partial_batch;
static bool fail_next;
static bool fail_lookup;
static __u32 batch_failures;
static struct bpf_object test_object;
static struct marlin_conf desired;
static struct conf_vip desired_vips[TEST_KEY_COUNT];
static struct vip_key desired_keys[TEST_KEY_COUNT][TEST_KEY_COUNT];
static struct conf_member desired_members[TEST_KEY_COUNT];
static struct conf_backend desired_backends[2];
static struct conf_diag diagnostics;

static void unexpected_map_call(void)
{
    fprintf(stderr, "reconcile_test: unexpected map operation\n");
    abort();
}

void conf_diag_add(struct conf_diag *diag, const char *fmt, ...)
{
    va_list ap;

    if(diag->count == MARLIN_CONF_DIAG_MAX) {
        diag->dropped++;
        return;
    }
    va_start(ap, fmt);
    (void)vsnprintf(diag->msg[diag->count++], MARLIN_CONF_DIAG_LEN, fmt, ap);
    va_end(ap);
}

struct bpf_map *bpf_object__find_map_by_name(const struct bpf_object *obj, const char *name)
{
    (void)obj;
    for(size_t i = 0; i < sizeof(test_maps) / sizeof(test_maps[0]); i++) {
        if(strcmp(name, test_maps[i].name) == 0) {
            return &test_maps[i];
        }
    }
    unexpected_map_call();
    return NULL;
}

int bpf_map__fd(const struct bpf_map *map)
{
    return map->fd;
}

static int live_key_index(const struct vip_key *key)
{
    for(__u32 i = 0; i < live_count; i++) {
        if(live_vips[i].live && vip_key_eq(key, &live_vips[i].key)) {
            return (int)i;
        }
    }
    return -1;
}

static void check_route(__u32 key_id, __u32 backend_id)
{
    if(desired_backend[key_id] != 0 && backend_id != desired_backend[key_id] &&
       (old_backend[key_id] == 0 || backend_id != old_backend[key_id])) {
        wrong_routes++;
    }
}

int bpf_map_get_next_key(int fd, const void *key, void *next_key)
{
    if(fd == TEST_VIPS) {
        int previous = key == NULL ? -1 : live_key_index(key);

        if(fail_next && previous >= 0) {
            errno = EIO;
            return -1;
        }
        for(__u32 i = (__u32)(previous + 1); i < live_count; i++) {
            if(live_vips[i].live) {
                memcpy(next_key, &live_vips[i].key, sizeof(struct vip_key));
                return 0;
            }
        }
    } else if(fd != TEST_TX && fd != TEST_ALLOW4 && fd != TEST_BLOCK4 && fd != TEST_ALLOW6 && fd != TEST_BLOCK6) {
        unexpected_map_call();
    }
    errno = ENOENT;
    return -1;
}

int bpf_map_lookup_elem(int fd, const void *key, void *value)
{
    if(fd == TEST_VIPS) {
        int index = live_key_index(key);

        if(fail_lookup) {
            errno = EIO;
            return -1;
        }
        if(index < 0) {
            errno = ENOENT;
            return -1;
        }
        memcpy(value, &live_vips[index].meta, sizeof(struct vip_meta));
    } else if(fd == TEST_CONFIG) {
        memcpy(value, &config_value, sizeof(config_value));
    } else if(fd == TEST_BACKENDS) {
        memcpy(value, &backend_values[*(const __u16 *)key], sizeof(struct backend));
    } else {
        unexpected_map_call();
    }
    return 0;
}

int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags)
{
    (void)flags;
    if(fd == TEST_FWD) {
        __u32 row = *(const __u32 *)key;

        if(row >= MAX_VIPS * TABLE_SIZE) {
            unexpected_map_call();
        }
        if((int)row == fail_row) {
            errno = EIO;
            return -1;
        }
        fwd_values[row] = *(const __u32 *)value;
        for(__u32 i = 0; i < live_count; i++) {
            if(live_vips[i].live && live_vips[i].meta.vip_num == row / TABLE_SIZE) {
                check_route(live_vips[i].key.addr4, fwd_values[row]);
            }
        }
    } else if(fd == TEST_VIPS) {
        const struct vip_key *vip_key = key;
        const struct vip_meta *meta = value;
        int index = live_key_index(key);

        if((int)vip_key->addr4 == fail_key) {
            errno = EIO;
            return -1;
        }
        if(index < 0) {
            if(live_count == TEST_KEY_COUNT) {
                unexpected_map_call();
            }
            index = (int)live_count++;
        }
        live_vips[index].key = *vip_key;
        live_vips[index].meta = *meta;
        live_vips[index].live = true;
        for(__u32 row = 0; row < TABLE_SIZE; row++) {
            check_route(vip_key->addr4, fwd_values[meta->vip_num * TABLE_SIZE + row]);
        }
    } else if(fd == TEST_CONFIG) {
        memcpy(&config_value, value, sizeof(config_value));
    } else if(fd == TEST_BACKENDS) {
        memcpy(&backend_values[*(const __u16 *)key], value, sizeof(struct backend));
    } else {
        unexpected_map_call();
    }
    mutations++;
    return 0;
}

int bpf_map_update_batch(int fd, const void *keys, const void *values, __u32 *count, const struct bpf_map_batch_opts *opts)
{
    __u32 requested = *count;
    (void)opts;

    if(fd != TEST_FWD) {
        unexpected_map_call();
    }
    for(__u32 i = 0; i < requested; i++) {
        if((partial_batch && i == requested / 2) ||
           bpf_map_update_elem(fd, &((const __u32 *)keys)[i], &((const __u32 *)values)[i], BPF_ANY) != 0) {
            *count = i;
            batch_failures++;
            errno = EIO;
            return -1;
        }
    }
    return 0;
}

int bpf_map_delete_elem(int fd, const void *key)
{
    int index;

    if(fd != TEST_VIPS) {
        unexpected_map_call();
    }
    index = live_key_index(key);
    if(index < 0) {
        errno = ENOENT;
        return -1;
    }
    live_vips[index].live = false;
    mutations++;
    return 0;
}

static struct vip_key test_key(__u32 id)
{
    struct vip_key key = { 0 };

    key.addr4 = id;
    key.family = AF_INET;
    key.proto = IPPROTO_SCTP;
    return key;
}

static void reset_fixture(void)
{
    memset(live_vips, 0, sizeof(live_vips));
    memset(fwd_values, 0, sizeof(fwd_values));
    memset(backend_values, 0, sizeof(backend_values));
    memset(&config_value, 0, sizeof(config_value));
    memset(old_backend, 0, sizeof(old_backend));
    memset(desired_backend, 0, sizeof(desired_backend));
    memset(&desired, 0, sizeof(desired));
    memset(desired_vips, 0, sizeof(desired_vips));
    memset(desired_members, 0, sizeof(desired_members));
    memset(desired_backends, 0, sizeof(desired_backends));
    memset(&diagnostics, 0, sizeof(diagnostics));
    live_count = 0;
    wrong_routes = 0;
    mutations = 0;
    batch_failures = 0;
    fail_key = -1;
    fail_row = -1;
    partial_batch = false;
    fail_next = false;
    fail_lookup = false;
    desired.instance.max_frame_set = true;
    desired.instance.max_frame = 1500;
    desired.vips = desired_vips;
    desired.backends = desired_backends;
    desired.backend_count = 2;
    for(__u16 i = 0; i < 2; i++) {
        desired_backends[i].id = i + 1;
        desired_backends[i].abi.addr = i + 1;
        desired_backends[i].abi.flags = MARLIN_BE_F_STATE;
    }
}

static void seed_key(__u32 id, __u32 num, __u32 backend_id)
{
    live_vips[live_count].key = test_key(id);
    live_vips[live_count].meta.vip_num = num;
    live_vips[live_count++].live = true;
    old_backend[id] = backend_id;
    for(__u32 row = 0; row < TABLE_SIZE; row++) {
        fwd_values[num * TABLE_SIZE + row] = backend_id;
    }
}

static void want_vip(__u32 first, __u32 second, __u16 backend_id)
{
    __u32 i = desired.vip_count++;
    struct conf_vip *vip = &desired_vips[i];

    desired_keys[i][0] = test_key(first);
    vip->keys = desired_keys[i];
    vip->key_count = 1;
    desired_backend[first] = backend_id;
    if(second != 0) {
        desired_keys[i][1] = test_key(second);
        vip->key_count++;
        desired_backend[second] = backend_id;
    }
    desired_members[i].backend_id = backend_id;
    desired_members[i].weight = 1;
    vip->members = &desired_members[i];
    vip->member_count = 1;
}

static void check_final_routes(void)
{
    CHECK_EQ(0, wrong_routes);
    for(__u32 i = 0; i < desired.vip_count; i++) {
        const struct conf_vip *vip = &desired.vips[i];

        for(__u32 k = 0; k < vip->key_count; k++) {
            int index = live_key_index(&vip->keys[k]);

            CHECK_TRUE(index >= 0);
            if(index >= 0) {
                CHECK_EQ(vip->meta.vip_num, live_vips[index].meta.vip_num);
                for(__u32 row = 0; row < TABLE_SIZE; row++) {
                    __u32 value = fwd_values[vip->meta.vip_num * TABLE_SIZE + row];

                    if(value != desired_backend[vip->keys[k].addr4]) {
                        CHECK_EQ(desired_backend[vip->keys[k].addr4], value);
                        break;
                    }
                }
            }
        }
    }
}

MARLIN_TEST(merge_plus_addition_never_overwrites_a_surviving_alias)
{
    for(int reverse = 0; reverse < 2; reverse++) {
        reset_fixture();
        seed_key(1, 0, 1);
        seed_key(2, 1, 1);
        want_vip(3, 0, 2);
        want_vip(1, 2, 1);
        if(reverse) {
            struct conf_vip tmp = desired_vips[0];
            desired_vips[0] = desired_vips[1];
            desired_vips[1] = tmp;
        }
        CHECK_TRUE(reconcile_apply(&test_object, &desired, &diagnostics));
        check_final_routes();
    }
}

MARLIN_TEST(split_moves_the_unchanged_alias_before_rewriting_its_old_block)
{
    for(int reverse = 0; reverse < 2; reverse++) {
        reset_fixture();
        seed_key(1, 0, 1);
        seed_key(2, 0, 1);
        want_vip(1, 0, 2);
        want_vip(2, 0, 1);
        if(reverse) {
            struct conf_vip tmp = desired_vips[0];
            desired_vips[0] = desired_vips[1];
            desired_vips[1] = tmp;
        }
        CHECK_TRUE(reconcile_apply(&test_object, &desired, &diagnostics));
        check_final_routes();
    }
}

MARLIN_TEST(cyclic_regrouping_is_safe_in_either_entry_and_address_order)
{
    for(int reverse = 0; reverse < 4; reverse++) {
        reset_fixture();
        seed_key(1, 0, 1);
        seed_key(2, 0, 1);
        seed_key(3, 1, 2);
        seed_key(4, 1, 2);
        want_vip(1, 3, 2);
        want_vip(2, 4, 1);
        if(reverse & 1) {
            struct conf_vip tmp = desired_vips[0];
            desired_vips[0] = desired_vips[1];
            desired_vips[1] = tmp;
        }
        if(reverse & 2) {
            for(__u32 i = 0; i < desired.vip_count; i++) {
                struct vip_key tmp = desired_vips[i].keys[0];
                desired_vips[i].keys[0] = desired_vips[i].keys[1];
                desired_vips[i].keys[1] = tmp;
            }
        }
        partial_batch = true;
        CHECK_TRUE(reconcile_apply(&test_object, &desired, &diagnostics));
        CHECK_TRUE(batch_failures > 0);
        check_final_routes();

        __u32 first_num = desired_vips[0].meta.vip_num;
        __u32 second_num = desired_vips[1].meta.vip_num;

        CHECK_TRUE(reconcile_apply(&test_object, &desired, &diagnostics));
        CHECK_EQ(first_num, desired_vips[0].meta.vip_num);
        CHECK_EQ(second_num, desired_vips[1].meta.vip_num);
        check_final_routes();
    }
}

MARLIN_TEST(failed_alias_publication_stops_before_reuse_and_can_be_retried)
{
    for(int key = 1; key <= 2; key++) {
        reset_fixture();
        seed_key(1, 0, 1);
        seed_key(2, 1, 1);
        want_vip(3, 0, 2);
        want_vip(1, 2, 1);
        fail_key = key;

        CHECK_TRUE(!reconcile_apply(&test_object, &desired, &diagnostics));
        CHECK_TRUE(diagnostics.count > 0);
        CHECK_EQ(0, wrong_routes);
        CHECK_EQ(1, live_vips[1].meta.vip_num);
        CHECK_EQ(1, fwd_values[TABLE_SIZE]);
        struct vip_key new_key = test_key(3);
        CHECK_EQ(-1, live_key_index(&new_key));

        fail_key = -1;
        memset(&diagnostics, 0, sizeof(diagnostics));
        CHECK_TRUE(reconcile_apply(&test_object, &desired, &diagnostics));
        check_final_routes();
    }
}

MARLIN_TEST(partial_table_failure_does_not_publish_keys_or_rewrite_the_shared_block)
{
    reset_fixture();
    seed_key(1, 0, 1);
    seed_key(2, 0, 1);
    want_vip(1, 0, 2);
    want_vip(2, 0, 1);
    fail_row = TABLE_SIZE + 16;

    CHECK_TRUE(!reconcile_apply(&test_object, &desired, &diagnostics));
    CHECK_TRUE(diagnostics.count > 0);
    CHECK_TRUE(batch_failures > 0);
    CHECK_EQ(0, wrong_routes);
    CHECK_EQ(0, live_vips[0].meta.vip_num);
    CHECK_EQ(0, live_vips[1].meta.vip_num);
    CHECK_EQ(1, fwd_values[0]);

    fail_row = -1;
    memset(&diagnostics, 0, sizeof(diagnostics));
    CHECK_TRUE(reconcile_apply(&test_object, &desired, &diagnostics));
    check_final_routes();
}

MARLIN_TEST(incomplete_baseline_reads_fail_before_any_map_write)
{
    for(int lookup = 0; lookup < 2; lookup++) {
        reset_fixture();
        seed_key(1, 0, 1);
        seed_key(2, 1, 1);
        want_vip(3, 0, 2);
        want_vip(1, 2, 1);
        fail_lookup = lookup != 0;
        fail_next = lookup == 0;

        CHECK_TRUE(!reconcile_apply(&test_object, &desired, &diagnostics));
        CHECK_TRUE(diagnostics.count > 0);
        CHECK_EQ(0, mutations);
    }
}

MARLIN_TEST(out_of_range_baseline_block_fails_before_any_map_write)
{
    reset_fixture();
    seed_key(1, 0, 1);
    live_vips[0].meta.vip_num = MAX_VIPS;
    want_vip(1, 0, 1);
    CHECK_TRUE(!reconcile_apply(&test_object, &desired, &diagnostics));
    CHECK_TRUE(diagnostics.count > 0);
    CHECK_EQ(0, mutations);
}

MARLIN_TEST(removing_group_addresses_releases_only_unreferenced_blocks)
{
    reset_fixture();
    seed_key(1, 0, 1);
    seed_key(2, 0, 1);
    seed_key(3, 2, 2);
    want_vip(1, 0, 1);
    want_vip(4, 0, 2);
    CHECK_TRUE(reconcile_apply(&test_object, &desired, &diagnostics));
    check_final_routes();
    CHECK_TRUE(!live_vips[1].live);
    CHECK_TRUE(!live_vips[2].live);
    for(__u32 row = 0; row < TABLE_SIZE; row++) {
        CHECK_EQ(0, fwd_values[2 * TABLE_SIZE + row]);
    }
}

int main(void)
{
    return marlin_tests_main();
}
