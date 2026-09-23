/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Seeds and clears vip_map and fwd_table on a pinned marlin.bpf.o instance,
 * for the *_wsl.sh development rigs (data-plane/scripts/). Writes go through
 * marlin/abi/types.h directly instead of a third hand-written mirror of it
 * (docs/design/06-map-abi.md), and fwd_table's TABLE_SIZE rows are written
 * with one bpf_map_update_batch() call -- the same approach
 * tests/packet/maps.c's xdp_fwd_write_block() already uses against an
 * in-process object, applied here against a pinned one.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <marlin/abi/defines.h>
#include <marlin/abi/types.h>
#include <marlin/lb_core.h>

#define MARLIN_SEED_VERSION "1.0"

/*
 * Rigs run one backend per VIP, so which row of the block a packet's hash
 * lands on never changes the outcome -- every row names the same id. The key
 * only has to be non-zero so it reads as deliberate rather than forgotten.
 */
static const __u8 SEED_HASH_KEY[16] = {
    0x6d, 0x61, 0x72, 0x6c, 0x69, 0x6e, 0x2d, 0x73, 0x65, 0x65, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static int map_fd(const char *pindir, const char *name)
{
    char path[512];
    int fd;

    snprintf(path, sizeof(path), "%s/%s", pindir, name);
    fd = bpf_obj_get(path);
    if(fd < 0) {
        fprintf(stderr, "marlin-seed: %s: %s\n", path, strerror(errno));
    }

    return fd;
}

static int parse_u32(const char *s, const char *what, unsigned long max, __u32 *out)
{
    char *end;
    unsigned long v;

    errno = 0;
    v = strtoul(s, &end, 0);
    if(*s == '\0' || *end != '\0' || errno != 0 || v > max) {
        fprintf(stderr, "marlin-seed: %s out of range or not a number: %s\n", what, s);
        return -1;
    }

    *out = (__u32)v;
    return 0;
}

static int build_key(const char *vip, const char *port, const char *proto, struct vip_key *key)
{
    __u32 port_v, proto_v;

    memset(key, 0, sizeof(*key));

    if(inet_pton(AF_INET, vip, &key->addr4) != 1) {
        fprintf(stderr, "marlin-seed: not an IPv4 address: %s\n", vip);
        return -1;
    }

    if(parse_u32(port, "port", 0xffff, &port_v) != 0 || parse_u32(proto, "proto", 0xff, &proto_v) != 0) {
        return -1;
    }

    key->port = htons((__u16)port_v);
    key->proto = (__u8)proto_v;
    key->family = AF_INET;
    return 0;
}

/*
 * Fills fwd_table[vip_num * TABLE_SIZE .. +TABLE_SIZE) with backend_id --
 * every row of the block, since a single-backend VIP has no other value to
 * put there. Batch update needs kernel 5.6 for ARRAY maps; the element loop
 * below is the fallback (tests/packet/maps.c:372-380 carries the same one).
 */
static int fill_fwd_table(int fd, __u32 vip_num, __u32 backend_id)
{
    LIBBPF_OPTS(bpf_map_batch_opts, opts);
    __u32 base = vip_num * TABLE_SIZE;
    __u32 count = TABLE_SIZE;
    __u32 *keys, *values;
    __u32 i;
    int ret = -1;

    keys = calloc(TABLE_SIZE, sizeof(*keys));
    values = calloc(TABLE_SIZE, sizeof(*values));
    if(keys == NULL || values == NULL) {
        fprintf(stderr, "marlin-seed: out of memory writing fwd_table\n");
        goto out;
    }

    for(i = 0; i < TABLE_SIZE; i++) {
        keys[i] = base + i;
        values[i] = backend_id;
    }

    if(bpf_map_update_batch(fd, keys, values, &count, &opts) == 0 && count == TABLE_SIZE) {
        ret = 0;
        goto out;
    }

    for(i = 0; i < TABLE_SIZE; i++) {
        if(bpf_map_update_elem(fd, &keys[i], &values[i], BPF_ANY) != 0) {
            fprintf(stderr, "marlin-seed: fwd_table[%u]: %s\n", keys[i], strerror(errno));
            goto out;
        }
    }

    ret = 0;

out:
    free(values);
    free(keys);
    return ret;
}

static bool vip_num_still_referenced(int vip_fd, __u32 vip_num)
{
    struct vip_key key;
    struct vip_key next_key;
    struct vip_meta meta;
    bool have_key = false;

    while(bpf_map_get_next_key(vip_fd, have_key ? &key : NULL, &next_key) == 0) {
        key = next_key;
        have_key = true;
        if(bpf_map_lookup_elem(vip_fd, &key, &meta) == 0 && meta.vip_num == vip_num) {
            return true;
        }
    }
    return false;
}

static int cmd_add(int argc, char **argv)
{
    const char *pindir, *vip, *port, *proto;
    __u32 vip_num, flags, backend_id;
    struct vip_key key;
    struct vip_meta meta;
    int vip_fd, fwd_fd, ret = 1;

    if(argc != 7) {
        fprintf(stderr, "usage: marlin_seed add <pindir> <vip> <port> <proto> <vip_num> <flags> <backend_id>\n");
        return 1;
    }

    pindir = argv[0];
    vip = argv[1];
    port = argv[2];
    proto = argv[3];

    if(build_key(vip, port, proto, &key) != 0 || parse_u32(argv[4], "vip_num", MAX_VIPS - 1, &vip_num) != 0 ||
       parse_u32(argv[5], "flags", 0xffffffff, &flags) != 0 || parse_u32(argv[6], "backend_id", MAX_BACKENDS - 1, &backend_id) != 0) {
        return 1;
    }

    if(backend_id == MARLIN_NO_BACKEND) {
        fprintf(stderr, "marlin-seed: backend_id 0 is the sentinel for \"no backend\" "
                        "(docs/design/10-map-invariants.md) -- real IDs start at 1\n");
        return 1;
    }

    memset(&meta, 0, sizeof(meta));
    meta.vip_num = vip_num;
    meta.flags = flags;
    memcpy(meta.hash_key, SEED_HASH_KEY, sizeof(meta.hash_key));

    vip_fd = map_fd(pindir, "vip_map");
    if(vip_fd < 0) {
        return 1;
    }

    fwd_fd = map_fd(pindir, "fwd_table");
    if(fwd_fd < 0) {
        close(vip_fd);
        return 1;
    }

    /*
     * fwd_table first: inserting the vip_map key while the block still
     * carries an earlier tenant (or its post-attach zero fill) would let a
     * packet match the VIP and resolve a stale or absent backend for that
     * window (lb_core.c's fwd_table lookup, MARLIN_DROP_NO_BACKEND).
     */
    if(fill_fwd_table(fwd_fd, vip_num, backend_id) != 0) {
        goto out;
    }

    if(bpf_map_update_elem(vip_fd, &key, &meta, BPF_ANY) != 0) {
        fprintf(stderr, "marlin-seed: vip_map: %s\n", strerror(errno));
        goto out;
    }

    printf("vip_map   %s:%u proto %u -> vip_num %u flags 0x%x\n", vip, ntohs(key.port), key.proto, vip_num, flags);
    printf("fwd_table [%u..%u] -> backend %u\n", vip_num * TABLE_SIZE, vip_num * TABLE_SIZE + TABLE_SIZE - 1, backend_id);
    ret = 0;

out:
    close(fwd_fd);
    close(vip_fd);
    return ret;
}

static int cmd_del(int argc, char **argv)
{
    const char *pindir, *vip, *port, *proto;
    __u32 vip_num;
    struct vip_key key;
    int vip_fd, fwd_fd, ret = 1;

    if(argc != 5) {
        fprintf(stderr, "usage: marlin_seed del <pindir> <vip> <port> <proto> <vip_num>\n");
        return 1;
    }

    pindir = argv[0];
    vip = argv[1];
    port = argv[2];
    proto = argv[3];

    if(build_key(vip, port, proto, &key) != 0 || parse_u32(argv[4], "vip_num", MAX_VIPS - 1, &vip_num) != 0) {
        return 1;
    }

    vip_fd = map_fd(pindir, "vip_map");
    if(vip_fd < 0) {
        return 1;
    }

    fwd_fd = map_fd(pindir, "fwd_table");
    if(fwd_fd < 0) {
        close(vip_fd);
        return 1;
    }

    /*
     * vip_map first, in the opposite order from cmd_add: deleting the key
     * stops any packet from reaching this VIP's fwd_table block at all, so
     * zeroing the block afterwards can never be observed mid-write. Doing it
     * the other way round would route live traffic to MARLIN_NO_BACKEND
     * while the vip_map entry still matches.
     */
    if(bpf_map_delete_elem(vip_fd, &key) != 0 && errno != ENOENT) {
        fprintf(stderr, "marlin-seed: vip_map: %s\n", strerror(errno));
        goto out;
    }

    printf("vip_map   %s:%u proto %u removed\n", vip, ntohs(key.port), key.proto);

    /*
     * An address group (docs/design/32-sctp.md) shares vip_num across
     * several vip_map keys; zeroing the block here would strand the
     * addresses that key deletion above did not touch.
     */
    if(vip_num_still_referenced(vip_fd, vip_num)) {
        printf("fwd_table [%u..%u] left alone: another vip_map key still references vip_num %u\n", vip_num * TABLE_SIZE,
               vip_num * TABLE_SIZE + TABLE_SIZE - 1, vip_num);
        ret = 0;
        goto out;
    }

    if(fill_fwd_table(fwd_fd, vip_num, MARLIN_NO_BACKEND) != 0) {
        goto out;
    }

    printf("fwd_table [%u..%u] zeroed\n", vip_num * TABLE_SIZE, vip_num * TABLE_SIZE + TABLE_SIZE - 1);
    ret = 0;

out:
    close(fwd_fd);
    close(vip_fd);
    return ret;
}

int main(int argc, char **argv)
{
    if(argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("marlin_seed %s\n", MARLIN_SEED_VERSION);
        return 0;
    }

    if(argc >= 2 && strcmp(argv[1], "add") == 0) {
        return cmd_add(argc - 2, argv + 2);
    }

    if(argc >= 2 && strcmp(argv[1], "del") == 0) {
        return cmd_del(argc - 2, argv + 2);
    }

    fprintf(stderr, "usage: %s add <pindir> <vip> <port> <proto> <vip_num> <flags> <backend_id>\n", argv[0]);
    fprintf(stderr, "       %s del <pindir> <vip> <port> <proto> <vip_num>\n", argv[0]);
    fprintf(stderr, "       %s --version\n", argv[0]);
    fprintf(stderr, "\n"
                    "flags (vip_meta.flags, docs/design/08-types.md):\n"
                    "  bit 0       VIP_ACL\n"
                    "  bit 1       VIP_RATELIMIT\n"
                    "  bit 2       VIP_HASH_5TUPLE\n"
                    "  bit 3       VIP_QUIC\n"
                    "  bits 8-12   VIP_QUIC_CID_LEN (0 = unset, 7-20 valid)\n"
                    "  bits 16-21  VIP_DSCP: outer DSCP for IPIP/GUE/VXLAN, 0-63, 0 = unmarked\n"
                    "              e.g. flags=$((46 << 16)) marks EF (RFC 3246)\n");
    return 1;
}
