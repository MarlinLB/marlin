/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Definitions for reconcile.h.
 *
 * Simplifications against the fullest version of this design: every
 * backend the file names is rewritten in full on every reconcile, and every
 * VIP's fwd_table block is regenerated on every reconcile, rather than
 * diffing against the previous generation first. Both are unconditional
 * writes of the desired state -- correct, per
 * docs/design/19-control-plane.md's "the maps are not authoritative" --
 * they just cost CPU proportional to the whole configuration rather than to
 * the size of a reload's change, which docs/design/17-reconfiguration.md's
 * "regeneration is per VIP" language is written against. Narrowing this to
 * only the VIPs/backends that actually changed is future work.
 */

#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/sockios.h>

#include <bpf/bpf.h>

#include <marlin/abi/defines.h>
#include <marlin/abi/types.h>
#include <marlin/lb_core.h>
#include <marlind/fwd_gen.h>
#include <marlind/reconcile.h>
#include <marlind/rl_scale.h>

struct maps {
    int config;
    int backends;
    int fwd_table;
    int vip_map;
    int tx_ports;
    int acl_allow_v4;
    int acl_block_v4;
    int acl_allow_v6;
    int acl_block_v6;
};

static int find_map_fd(struct bpf_object *obj, const char *name, struct conf_diag *diag)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, name);
    int fd;

    if(map == NULL) {
        conf_diag_add(diag, "no such map: %s (was marlin.bpf.o built from the same ABI as this marlind?)", name);
        return -1;
    }
    fd = bpf_map__fd(map);
    if(fd < 0) {
        conf_diag_add(diag, "map %s has no open file descriptor", name);
    }
    return fd;
}

static bool open_maps(struct bpf_object *obj, struct maps *mp, struct conf_diag *diag)
{
    mp->config = find_map_fd(obj, "config", diag);
    mp->backends = find_map_fd(obj, "backends", diag);
    mp->fwd_table = find_map_fd(obj, "fwd_table", diag);
    mp->vip_map = find_map_fd(obj, "vip_map", diag);
    mp->tx_ports = find_map_fd(obj, "tx_ports", diag);
    mp->acl_allow_v4 = find_map_fd(obj, "acl_allow_v4", diag);
    mp->acl_block_v4 = find_map_fd(obj, "acl_block_v4", diag);
    mp->acl_allow_v6 = find_map_fd(obj, "acl_allow_v6", diag);
    mp->acl_block_v6 = find_map_fd(obj, "acl_block_v6", diag);

    return mp->config >= 0 && mp->backends >= 0 && mp->fwd_table >= 0 && mp->vip_map >= 0 && mp->tx_ports >= 0 &&
           mp->acl_allow_v4 >= 0 && mp->acl_block_v4 >= 0 && mp->acl_allow_v6 >= 0 && mp->acl_block_v6 >= 0;
}

/* ---- fwd_table block writes --------------------------------------------- */

/*
 * bpf_map_update_batch needs kernel 5.6 for ARRAY maps; the element loop is
 * the fallback data-plane/tools/marlin_seed.c:112-127 already carries for
 * kernels without it.
 */
static bool write_fwd_block(int fd, __u32 vip_num, const __u32 *values, struct conf_diag *diag)
{
    LIBBPF_OPTS(bpf_map_batch_opts, opts);
    __u32 *keys = calloc(TABLE_SIZE, sizeof(*keys));
    __u32 base = vip_num * TABLE_SIZE;
    __u32 count = TABLE_SIZE;
    bool ok = true;

    if(keys == NULL) {
        conf_diag_add(diag, "out of memory writing fwd_table[%u]", vip_num);
        return false;
    }
    for(__u32 i = 0; i < TABLE_SIZE; i++) {
        keys[i] = base + i;
    }

    if(bpf_map_update_batch(fd, keys, values, &count, &opts) == 0 && count == TABLE_SIZE) {
        free(keys);
        return true;
    }

    for(__u32 i = 0; i < TABLE_SIZE; i++) {
        if(bpf_map_update_elem(fd, &keys[i], &values[i], BPF_ANY) != 0) {
            conf_diag_add(diag, "fwd_table[%u]: %s", keys[i], strerror(errno));
            ok = false;
            break;
        }
    }
    free(keys);
    return ok;
}

static bool zero_fwd_block(int fd, __u32 vip_num, struct conf_diag *diag)
{
    __u32 *zeros = calloc(TABLE_SIZE, sizeof(*zeros)); /* MARLIN_NO_BACKEND is 0 */
    bool ok;

    if(zeros == NULL) {
        conf_diag_add(diag, "out of memory zeroing fwd_table[%u]", vip_num);
        return false;
    }
    ok = write_fwd_block(fd, vip_num, zeros, diag);
    free(zeros);
    return ok;
}

/* ---- vip_num allocation (docs/design/31-file-configuration.md §5) ------- */

struct vip_baseline {
    struct vip_key key;
    __u32 vip_num;
    bool claimed;
};

static __u32 read_vip_baseline(int fd, struct vip_baseline *out)
{
    struct vip_key key;
    struct vip_key next_key;
    struct vip_meta meta;
    bool have_key = false;
    __u32 count = 0;

    while(count < MAX_VIPS) {
        if(bpf_map_get_next_key(fd, have_key ? &key : NULL, &next_key) != 0) {
            break;
        }
        key = next_key;
        have_key = true;
        if(bpf_map_lookup_elem(fd, &key, &meta) != 0) {
            continue;
        }
        out[count].key = key;
        out[count].vip_num = meta.vip_num;
        out[count].claimed = false;
        count++;
    }
    return count;
}

static bool vip_num_in_use(const bool used[MAX_VIPS], __u32 num)
{
    return num < MAX_VIPS && used[num];
}

/*
 * Surviving VIPs keep the block they already hold; new VIPs take the lowest
 * free block. Minimises rewritten rows and makes a reload's churn
 * proportional to the change (docs/design/31-file-configuration.md §5).
 */
static void allocate_vip_nums(struct marlin_conf *conf, struct vip_baseline *baseline, __u32 baseline_count)
{
    bool used[MAX_VIPS] = { false };

    for(__u32 i = 0; i < conf->vip_count; i++) {
        for(__u32 j = 0; j < baseline_count; j++) {
            if(!baseline[j].claimed && vip_key_eq(&conf->vips[i].key, &baseline[j].key)) {
                conf->vips[i].meta.vip_num = baseline[j].vip_num;
                baseline[j].claimed = true;
                used[baseline[j].vip_num % MAX_VIPS] = true;
                break;
            }
        }
    }

    for(__u32 i = 0; i < conf->vip_count; i++) {
        if(conf->vips[i].meta.vip_num != MARLIN_CONF_VIP_NUM_UNSET) {
            continue;
        }
        for(__u32 num = 0; num < MAX_VIPS; num++) {
            if(!vip_num_in_use(used, num)) {
                conf->vips[i].meta.vip_num = num;
                used[num] = true;
                break;
            }
        }
    }
}

/* ---- ACL trie reconciliation (set difference over get_next_key) -------- */

static bool acl_v4_key_eq(const struct acl_key4 *lhs, const struct acl_key4 *rhs)
{
    return lhs->prefixlen == rhs->prefixlen && lhs->addr == rhs->addr;
}

static bool reconcile_acl_v4(int fd, const struct conf_acl_entry *entries, __u32 count, struct conf_diag *diag)
{
    struct acl_key4 *existing = calloc(MAX_ACL_ENTRIES, sizeof(*existing));
    struct acl_key4 key;
    struct acl_key4 next_key;
    bool have_key = false;
    __u32 existing_count = 0;
    bool ok = true;

    if(existing == NULL) {
        conf_diag_add(diag, "out of memory reconciling an ACL trie");
        return false;
    }

    while(existing_count < MAX_ACL_ENTRIES) {
        if(bpf_map_get_next_key(fd, have_key ? &key : NULL, &next_key) != 0) {
            break;
        }
        key = next_key;
        have_key = true;
        existing[existing_count++] = key;
    }

    for(__u32 i = 0; i < count && ok; i++) {
        struct acl_key4 want = { .prefixlen = entries[i].prefixlen };
        __u32 value = i; /* rule ordinal within its list: a diagnostic label, D-F9 */

        memcpy(&want.addr, entries[i].addr, sizeof(want.addr));
        if(bpf_map_update_elem(fd, &want, &value, BPF_ANY) != 0) {
            conf_diag_add(diag, "acl trie (v4) update failed: %s", strerror(errno));
            ok = false;
        }
    }

    for(__u32 i = 0; i < existing_count && ok; i++) {
        bool wanted = false;

        for(__u32 j = 0; j < count; j++) {
            struct acl_key4 want = { .prefixlen = entries[j].prefixlen };

            memcpy(&want.addr, entries[j].addr, sizeof(want.addr));
            if(acl_v4_key_eq(&want, &existing[i])) {
                wanted = true;
                break;
            }
        }
        if(!wanted && bpf_map_delete_elem(fd, &existing[i]) != 0 && errno != ENOENT) {
            conf_diag_add(diag, "acl trie (v4) delete failed: %s", strerror(errno));
            ok = false;
        }
    }

    free(existing);
    return ok;
}

static bool acl_v6_key_eq(const struct acl_key6 *lhs, const struct acl_key6 *rhs)
{
    return lhs->prefixlen == rhs->prefixlen && memcmp(lhs->addr, rhs->addr, sizeof(lhs->addr)) == 0;
}

static bool reconcile_acl_v6(int fd, const struct conf_acl_entry *entries, __u32 count, struct conf_diag *diag)
{
    struct acl_key6 *existing = calloc(MAX_ACL_ENTRIES, sizeof(*existing));
    struct acl_key6 key;
    struct acl_key6 next_key;
    bool have_key = false;
    __u32 existing_count = 0;
    bool ok = true;

    if(existing == NULL) {
        conf_diag_add(diag, "out of memory reconciling an ACL trie");
        return false;
    }

    while(existing_count < MAX_ACL_ENTRIES) {
        if(bpf_map_get_next_key(fd, have_key ? &key : NULL, &next_key) != 0) {
            break;
        }
        key = next_key;
        have_key = true;
        existing[existing_count++] = key;
    }

    for(__u32 i = 0; i < count && ok; i++) {
        struct acl_key6 want = { .prefixlen = entries[i].prefixlen };
        __u32 value = i;

        memcpy(want.addr, entries[i].addr, sizeof(want.addr));
        if(bpf_map_update_elem(fd, &want, &value, BPF_ANY) != 0) {
            conf_diag_add(diag, "acl trie (v6) update failed: %s", strerror(errno));
            ok = false;
        }
    }

    for(__u32 i = 0; i < existing_count && ok; i++) {
        bool wanted = false;

        for(__u32 j = 0; j < count; j++) {
            struct acl_key6 want = { .prefixlen = entries[j].prefixlen };

            memcpy(want.addr, entries[j].addr, sizeof(want.addr));
            if(acl_v6_key_eq(&want, &existing[i])) {
                wanted = true;
                break;
            }
        }
        if(!wanted && bpf_map_delete_elem(fd, &existing[i]) != 0 && errno != ENOENT) {
            conf_diag_add(diag, "acl trie (v6) delete failed: %s", strerror(errno));
            ok = false;
        }
    }

    free(existing);
    return ok;
}

static __u16 acl_lists_bits(const struct marlin_conf *conf)
{
    __u16 bits = 0;

    if(conf->acl.allow_v4_count > 0) {
        bits |= ACL_LISTS_BIT(ACL_LIST_ALLOW, ACL_FAMILY_V4);
    }
    if(conf->acl.block_v4_count > 0) {
        bits |= ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4);
    }
    if(conf->acl.allow_v6_count > 0) {
        bits |= ACL_LISTS_BIT(ACL_LIST_ALLOW, ACL_FAMILY_V6);
    }
    if(conf->acl.block_v6_count > 0) {
        bits |= ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V6);
    }
    return bits;
}

/* ---- config -------------------------------------------------------------- */

static bool derive_max_frame(const char *iface, __u16 *out, struct conf_diag *diag)
{
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if(fd < 0) {
        conf_diag_add(diag, "socket() failed deriving max_frame: %s", strerror(errno));
        return false;
    }
    memset(&ifr, 0, sizeof(ifr));
    (void)snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface);

    if(ioctl(fd, SIOCGIFMTU, &ifr) != 0) {
        conf_diag_add(diag, "could not read the MTU of %s to derive max_frame: %s", iface, strerror(errno));
        close(fd);
        return false;
    }
    close(fd);

    if(ifr.ifr_mtu < 0 || ifr.ifr_mtu + ETH_HLEN > 0xffff) {
        conf_diag_add(diag, "%s's MTU (%d) does not fit max_frame", iface, ifr.ifr_mtu);
        return false;
    }
    *out = (__u16)(ifr.ifr_mtu + ETH_HLEN);
    return true;
}

static bool any_backend_encapsulates(const struct marlin_conf *conf)
{
    for(__u32 i = 0; i < conf->backend_count; i++) {
        if((conf->backends[i].abi.flags & MARLIN_BE_F_ENCAP_REQUIRED) != 0) {
            return true;
        }
    }
    return false;
}

/*
 * Writes config with acl_lists = old_bits | final_bits: any trie about to
 * gain rows already has its bit set before the ACL reconcile below inserts
 * anything, and any trie the ACL reconcile is about to empty keeps its bit
 * set until it is actually empty. Without the union, the moment between
 * "a first row lands in a previously-empty trie" and "the bit finally says
 * so" is a window where that rule is silently unenforced -- the datapath
 * treats a clear acl_lists bit as license to skip the lookup entirely
 * (docs/design/27-source-filtering.md). §12 in this file's caller narrows
 * the bits back down to exactly the final population once the trie work is
 * done.
 */
static bool write_config(int fd, const struct marlin_conf *conf, __u16 acl_lists_override, struct conf_diag *diag)
{
    struct marlin_config value;
    __u32 zero = 0;
    __u16 max_frame = conf->instance.max_frame;

    memset(&value, 0, sizeof(value));

    if(!conf->instance.max_frame_set) {
        if(!derive_max_frame(conf->instance.iface, &max_frame, diag)) {
            if(any_backend_encapsulates(conf)) {
                conf_diag_add(diag, "max_frame could not be derived and at least one backend encapsulates; "
                                    "the egress-MTU check would be silently disabled");
                return false;
            }
            max_frame = 0;
        }
    }

    value.tunnel_src = conf->instance.tunnel_src;
    value.max_frame = max_frame;
    value.acl_lists = acl_lists_override;
    if(conf->acl.enabled) {
        value.flags |= CFG_ACL_ENABLE;
    }
    if(conf->ratelimit.enabled) {
        value.flags |= CFG_RL_ENABLE;
        value.rl_refill = marlind_scale_refill(conf->ratelimit.tokens_per_sec);
        value.rl_burst = marlind_scale_burst(conf->ratelimit.burst_packets);
    }

    if(bpf_map_update_elem(fd, &zero, &value, BPF_ANY) != 0) {
        conf_diag_add(diag, "config: %s", strerror(errno));
        return false;
    }
    return true;
}

static __u16 read_old_acl_lists(int config_fd)
{
    struct marlin_config old;
    __u32 zero = 0;

    memset(&old, 0, sizeof(old));
    (void)bpf_map_lookup_elem(config_fd, &zero, &old); /* ARRAY[0] always exists, zeroed if never written */
    return old.acl_lists;
}

/* ---- tx_ports ------------------------------------------------------------ */

static bool resolve_tx_ports(const struct marlin_conf *conf, __u32 out[MAX_TX_PORTS], struct conf_diag *diag)
{
    for(__u32 i = 0; i < conf->instance.tx_port_count; i++) {
        out[i] = if_nametoindex(conf->instance.tx_ports[i]);
        if(out[i] == 0) {
            conf_diag_add(diag, "instance.tx_ports[%u] (%s) does not resolve to an interface", i, conf->instance.tx_ports[i]);
            return false;
        }
    }
    return true;
}

static bool ifindex_in(const __u32 *arr, __u32 count, __u32 ifindex)
{
    for(__u32 i = 0; i < count; i++) {
        if(arr[i] == ifindex) {
            return true;
        }
    }
    return false;
}

static bool add_tx_ports(int fd, const __u32 *want, __u32 count, struct conf_diag *diag)
{
    for(__u32 i = 0; i < count; i++) {
        if(bpf_map_update_elem(fd, &want[i], &want[i], BPF_ANY) != 0) {
            conf_diag_add(diag, "tx_ports[%u]: %s", want[i], strerror(errno));
            return false;
        }
    }
    return true;
}

static bool remove_stale_tx_ports(int fd, const __u32 *want, __u32 want_count, struct conf_diag *diag)
{
    __u32 existing[MAX_TX_PORTS];
    __u32 key;
    __u32 next_key;
    bool have_key = false;
    __u32 existing_count = 0;

    while(existing_count < MAX_TX_PORTS) {
        if(bpf_map_get_next_key(fd, have_key ? &key : NULL, &next_key) != 0) {
            break;
        }
        key = next_key;
        have_key = true;
        existing[existing_count++] = key;
    }

    for(__u32 i = 0; i < existing_count; i++) {
        if(!ifindex_in(want, want_count, existing[i]) && bpf_map_delete_elem(fd, &existing[i]) != 0 && errno != ENOENT) {
            conf_diag_add(diag, "tx_ports delete failed for ifindex %u: %s", existing[i], strerror(errno));
            return false;
        }
    }
    return true;
}

/* ---- backends ------------------------------------------------------------ */

static bool write_backends(int fd, const struct marlin_conf *conf, struct conf_diag *diag)
{
    for(__u32 i = 0; i < conf->backend_count; i++) {
        const struct conf_backend *backend = &conf->backends[i];
        struct backend value = backend->abi;

        value.id = backend->id;
        if(backend->has_egress) {
            value.egress_ifindex = if_nametoindex(backend->egress);
        }
        if(bpf_map_update_elem(fd, &backend->id, &value, BPF_ANY) != 0) {
            conf_diag_add(diag, "backends[%u] (%s): %s", backend->id, backend->name, strerror(errno));
            return false;
        }
    }
    return true;
}

static bool backend_id_wanted(const struct marlin_conf *conf, __u16 id)
{
    for(__u32 i = 0; i < conf->backend_count; i++) {
        if(conf->backends[i].id == id) {
            return true;
        }
    }
    return false;
}

/* ARRAY has no delete; removal is a zero-write (docs/design/10-map-invariants.md). */
static bool retire_stale_backends(int fd, const struct marlin_conf *conf, struct conf_diag *diag)
{
    static const struct backend zeroed;

    for(__u16 id = 1; id < MAX_BACKENDS; id++) {
        struct backend cur;

        if(bpf_map_lookup_elem(fd, &id, &cur) != 0 || cur.id != id) {
            continue; /* slot never allocated */
        }
        if(backend_id_wanted(conf, id)) {
            continue;
        }
        if(bpf_map_update_elem(fd, &id, &zeroed, BPF_ANY) != 0) {
            conf_diag_add(diag, "retiring backends[%u]: %s", id, strerror(errno));
            return false;
        }
    }
    return true;
}

/* ---- vip_map / fwd_table -------------------------------------------------- */

static bool remove_stale_vips(const struct maps *mp, const struct vip_baseline *baseline, __u32 baseline_count, struct conf_diag *diag)
{
    for(__u32 i = 0; i < baseline_count; i++) {
        if(baseline[i].claimed) {
            continue;
        }
        if(bpf_map_delete_elem(mp->vip_map, &baseline[i].key) != 0 && errno != ENOENT) {
            conf_diag_add(diag, "vip_map delete failed: %s", strerror(errno));
            return false;
        }
        if(!zero_fwd_block(mp->fwd_table, baseline[i].vip_num, diag)) {
            return false;
        }
    }
    return true;
}

static bool write_vip(const struct maps *mp, const struct marlin_conf *conf, const struct conf_vip *vip, struct conf_diag *diag)
{
    struct fwd_gen_member *members = calloc(vip->member_count, sizeof(*members));
    __u32 *block = calloc(TABLE_SIZE, sizeof(*block));
    bool ok = true;

    if((vip->member_count > 0 && members == NULL) || block == NULL) {
        conf_diag_add(diag, "out of memory generating vip[%u]", vip->meta.vip_num);
        free(members);
        free(block);
        return false;
    }

    for(__u32 i = 0; i < vip->member_count; i++) {
        const struct conf_backend *backend = NULL;

        for(__u32 j = 0; j < conf->backend_count; j++) {
            if(conf->backends[j].id == vip->members[i].backend_id) {
                backend = &conf->backends[j];
                break;
            }
        }
        if(backend == NULL) {
            continue; /* rejected by conf_check() already; defensive only */
        }
        members[i].backend_id = backend->id;
        members[i].weight = vip->members[i].weight;
        members[i].addr = backend->abi.addr;
        members[i].vni = backend->abi.vni;
        memcpy(members[i].inner_mac, backend->abi.inner_mac, sizeof(members[i].inner_mac));
    }

    fwd_gen_block(vip->table_seed, members, vip->member_count, block);
    free(members);

    /* fwd_table block before the vip_map entry that points into it (docs/design/31-file-configuration.md §8). */
    if(!write_fwd_block(mp->fwd_table, vip->meta.vip_num, block, diag)) {
        ok = false;
    }
    free(block);
    if(!ok) {
        return false;
    }

    if(bpf_map_update_elem(mp->vip_map, &vip->key, &vip->meta, BPF_ANY) != 0) {
        conf_diag_add(diag, "vip_map: %s", strerror(errno));
        return false;
    }
    return true;
}

/* ---- entry point ---------------------------------------------------------- */

bool reconcile_apply(struct bpf_object *obj, struct marlin_conf *conf, struct conf_diag *diag)
{
    struct maps mp;
    struct vip_baseline baseline[MAX_VIPS];
    __u32 baseline_count;
    __u32 tx_want[MAX_TX_PORTS];
    __u16 old_acl_lists;
    __u16 final_acl_lists = acl_lists_bits(conf);

    if(!open_maps(obj, &mp, diag)) {
        return false;
    }

    baseline_count = read_vip_baseline(mp.vip_map, baseline);
    allocate_vip_nums(conf, baseline, baseline_count);

    if(!remove_stale_vips(&mp, baseline, baseline_count, diag)) {
        return false;
    }

    /* Union first: see write_config()'s comment for why this must precede the ACL trie work below. */
    old_acl_lists = read_old_acl_lists(mp.config);
    if(!write_config(mp.config, conf, old_acl_lists | final_acl_lists, diag)) {
        return false;
    }

    if(!reconcile_acl_v4(mp.acl_allow_v4, conf->acl.allow_v4, conf->acl.allow_v4_count, diag) ||
       !reconcile_acl_v4(mp.acl_block_v4, conf->acl.block_v4, conf->acl.block_v4_count, diag) ||
       !reconcile_acl_v6(mp.acl_allow_v6, conf->acl.allow_v6, conf->acl.allow_v6_count, diag) ||
       !reconcile_acl_v6(mp.acl_block_v6, conf->acl.block_v6, conf->acl.block_v6_count, diag)) {
        return false;
    }

    if(!resolve_tx_ports(conf, tx_want, diag)) {
        return false;
    }
    if(!add_tx_ports(mp.tx_ports, tx_want, conf->instance.tx_port_count, diag)) {
        return false;
    }

    if(!write_backends(mp.backends, conf, diag)) {
        return false;
    }

    for(__u32 i = 0; i < conf->vip_count; i++) {
        if(!write_vip(&mp, conf, &conf->vips[i], diag)) {
            return false;
        }
    }

    if(!retire_stale_backends(mp.backends, conf, diag)) {
        return false;
    }

    if(!remove_stale_tx_ports(mp.tx_ports, tx_want, conf->instance.tx_port_count, diag)) {
        return false;
    }

    /* Narrow acl_lists down to exactly the final population, now that the trie work above is complete. */
    return write_config(mp.config, conf, final_acl_lists, diag);
}
