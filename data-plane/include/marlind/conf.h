/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * The in-memory model for marlind's file-managed configuration
 * (docs/design/31-file-configuration.md), and the diagnostic collector every
 * parse/check function reports through. Host-only, like every include/marlind/
 * header: nothing here is reachable from a -target bpf translation unit.
 *
 * conf_load() owns every string and array it produces -- nothing in a
 * struct marlin_conf points into the parser's own buffers, so the model
 * outlives the parse and a reload can hold two generations side by side
 * while the reconciler diffs them.
 */

#pragma once

#if defined(__bpf__)
#error "include/marlind/ is host-only; do not include it from BPF sources"
#endif

#include <limits.h>
#include <net/if.h>
#include <stdbool.h>
#include <string.h>

#include <linux/types.h>

#include <marlin/abi/defines.h>
#include <marlin/abi/types.h>

/* File-local identity strings; never written to a map. */
#define MARLIN_CONF_NAME_MAX      64

/* Bounded so one rejected file reports many mistakes, not just the first. */
#define MARLIN_CONF_DIAG_MAX      64
#define MARLIN_CONF_DIAG_LEN      256

/* vip_num has not yet been allocated by the reconciler (docs/design/31-file-configuration.md §5). */
#define MARLIN_CONF_VIP_NUM_UNSET 0xffffffffU

/*
 * Collected rejections and warnings. Every check function appends here
 * instead of calling die(): a startup failure and a rejected SIGHUP reload
 * both need every mistake in one report, and only the caller knows whether
 * that report is fatal (docs/design/31-file-configuration.md §7).
 */
struct conf_diag {
    char msg[MARLIN_CONF_DIAG_MAX][MARLIN_CONF_DIAG_LEN];
    __u32 count;
    __u32 dropped;

    char warn[MARLIN_CONF_DIAG_MAX][MARLIN_CONF_DIAG_LEN];
    __u32 warn_count;
    __u32 warn_dropped;
};

void conf_diag_reset(struct conf_diag *diag);
void conf_diag_add(struct conf_diag *diag, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void conf_diag_warn(struct conf_diag *diag, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

/*
 * [instance]. tunnel_src/max_frame carry an explicit "was it stated" flag
 * because their unset value (0) is also a legal derived value
 * (docs/design/31-file-configuration.md §4's "max_frame is omitted rather
 * than zeroed" rule) -- coercion must not confuse "absent" with "zero".
 */
struct conf_instance {
    char iface[IF_NAMESIZE];
    int ifindex; /* resolved by conf_check(); 0 until then */

    char object[PATH_MAX];
    char pin_dir[PATH_MAX];

    bool tunnel_src_set;
    __be32 tunnel_src;

    char tx_ports[MAX_TX_PORTS][IF_NAMESIZE];
    __u32 tx_port_count;

    bool max_frame_set;
    __u16 max_frame;
};

/*
 * abi holds every field that goes into struct backend verbatim except id,
 * which the array slot IS (docs/design/07-maps.md) and is therefore kept
 * alongside rather than inside, to make the file-local vs. ABI split visible
 * at every call site that reads one.
 */
struct conf_backend {
    char name[MARLIN_CONF_NAME_MAX];
    __u16 id;

    char egress[IF_NAMESIZE];
    bool has_egress;

    bool mac_stated;
    bool fib_stated;
    bool fib_value;
    bool vni_stated;
    bool inner_mac_stated;

    struct backend abi; /* addr, mac, encap_dport, flags, egress_ifindex, vni, inner_mac */
};

/* One [[vip]].members entry; weight is per-membership (docs/design/12-selection.md). */
struct conf_member {
    char backend_name[MARLIN_CONF_NAME_MAX];
    __u16 backend_id; /* resolved by conf_check() from backend_name */
    __u32 weight;
};

struct conf_vip {
    struct vip_key key;
    struct vip_meta meta; /* vip_num filled by the reconciler; MARLIN_CONF_VIP_NUM_UNSET until then */
    __u8 table_seed[16];

    struct conf_member *members;
    __u32 member_count;
};

/* One entry per allowed/blocked prefix; addr is stored network-order, full width, host bits included for the check. */
struct conf_acl_entry {
    __u32 prefixlen;
    __u8 addr[16]; /* v4 uses addr[0..3]; the rest stays zero */
};

struct conf_acl {
    bool enabled;

    struct conf_acl_entry *allow_v4;
    __u32 allow_v4_count;
    struct conf_acl_entry *block_v4;
    __u32 block_v4_count;
    struct conf_acl_entry *allow_v6;
    __u32 allow_v6_count;
    struct conf_acl_entry *block_v6;
    __u32 block_v6_count;
};

struct conf_ratelimit {
    bool enabled;
    __u32 tokens_per_sec;
    __u32 burst_packets;
};

struct marlin_conf {
    struct conf_instance instance;
    struct conf_acl acl;
    struct conf_ratelimit ratelimit;

    struct conf_backend *backends;
    __u32 backend_count;

    struct conf_vip *vips;
    __u32 vip_count;
};

/*
 * struct vip_key holds a union (abi/types.h), so memcmp()-ing the whole
 * struct is flagged as unsafe regardless of the ABI's own no-implicit-padding
 * guarantee (clang-tidy's bugprone-suspicious-memory-comparison) -- this is
 * the field-by-field comparison it asks for, shared by conf_check.c
 * (duplicate-VIP detection) and reconcile.c (matching a file VIP to its
 * previous generation's vip_num).
 */
static inline bool vip_key_eq(const struct vip_key *lhs, const struct vip_key *rhs)
{
    if(lhs->family != rhs->family || lhs->port != rhs->port || lhs->proto != rhs->proto) {
        return false;
    }
    if(lhs->family == AF_INET) {
        return lhs->addr4 == rhs->addr4;
    }
    return memcmp(lhs->addr6, rhs->addr6, sizeof(lhs->addr6)) == 0;
}

/*
 * INSTANCE_ONLY parses and validates [instance] alone, skipping every
 * backend/VIP/ACL rule -- what --status and --unpin need (they only read
 * iface/pin_dir) without failing on a file whose backends are momentarily
 * wrong (docs/design/31-file-configuration.md).
 */
enum conf_load_mode {
    CONF_LOAD_FULL = 0,
    CONF_LOAD_INSTANCE_ONLY,
};

/*
 * Parses and, for CONF_LOAD_FULL, validates path. Returns NULL and appends
 * to diag on any rejection; the caller decides whether that is fatal.
 * conf_check() has already run when this returns non-NULL for CONF_LOAD_FULL.
 *
 * enforce_perms controls what happens when the file is group/world-writable:
 * true makes it a rejection (the --attach and SIGHUP-reload paths, which
 * trust this file with real map writes), false a warning only (marlind
 * --check, deliberately unprivileged and runnable against a file laid out
 * however the caller's tree has it -- docs/design/31-file-configuration.md §7).
 */
struct marlin_conf *conf_load(const char *path, enum conf_load_mode mode, bool enforce_perms, struct conf_diag *diag);
void conf_free(struct marlin_conf *conf);
