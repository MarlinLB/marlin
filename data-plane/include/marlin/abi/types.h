/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * ABI types for the Marlin data plane application.
 */

#pragma once

#include <linux/types.h>
#include <marlin/abi/defines.h>

struct vip_key { /* 20 bytes, no implicit padding */

    union {
        __be32 addr4;
        __be32 addr6[4];
    };

    __be16 port; /* 0 matches any port */
    __u8 proto;
    __u8 family;
};

struct vip_meta {  /* 24 bytes */
    __u32 vip_num; /* block index into fwd_table */
    __u32 flags;
    __u8 hash_key[16];
};

struct backend { /* 32 bytes */
    __be32 addr;
    __u8 mac[6];
    __be16 encap_dport;
    __u8 flags;
    __u8 pad[3];
    __u32 egress_ifindex;
    __u32 vni;
    __u8 inner_mac[6];
    __u8 pad[2];
};

struct stats {
    __u64 packets;
    __u64 bytes;
};

struct marlin_config { /* 20 bytes, no implicit padding */
    __be32 tunnel_src; /*  0-3  IPv4 outer source address */
    __u32 flags;       /*  4-7  CFG_* */
    __u16 max_frame;   /*  8-9  egress MTU + ETH_HLEN; 0 = unset */
    __u16 acl_lists;   /* 10-11 which ACL tries are non-empty */
    __u32 rl_refill;   /* 12-15 scaled tokens per tick */
    __u32 rl_burst;    /* 16-19 bucket capacity, scaled tokens */
};

struct acl_key4 { /* 8 bytes, no implicit padding */
    __u32 prefixlen;
    __be32 addr;
};

struct acl_key6 { /* 20 bytes, no implicit padding */
    __u32 prefixlen;
    __be32 addr[4];
};

struct rl_key { /* 20 bytes, no implicit padding */
    __be32 addr[4];
    __u8 family;
    __u8 pad[3];
};

struct rl_bucket { /* 8 bytes */
    __u64 state;
};

_Static_assert(sizeof(struct vip_key) == 20, "vip_key must stay 20 bytes");
_Static_assert(sizeof(struct vip_meta) == 24, "vip_meta must stay 24 bytes");
_Static_assert(sizeof(struct backend) == 32, "backend must stay 32 bytes");
_Static_assert(__builtin_offsetof(struct backend, encap_dport) == 10, "backend.encap_dport must follow mac with no hole");
_Static_assert(__builtin_offsetof(struct backend, egress_ifindex) == 16, "backend.egress_ifindex must follow pad with no hole");
_Static_assert(__builtin_offsetof(struct backend, flags) == 12, "backend.flags must stay where the C# side reads the mode byte");
_Static_assert(__builtin_offsetof(struct backend, vni) == 20, "backend.vni must follow egress_ifindex with no hole");
_Static_assert(__builtin_offsetof(struct backend, inner_mac) == 24, "backend.inner_mac must follow vni with no hole");

_Static_assert(sizeof(struct stats) == 16, "stats must stay 16 bytes");
_Static_assert(sizeof(struct marlin_config) == 20, "marlin_config must stay 20 bytes");
_Static_assert(sizeof(struct rl_bucket) == 8, "rl_bucket must stay one word: the CAS depends on it");

/* An alignment hole here would land inside the bit string the trie compares. */
_Static_assert(sizeof(struct acl_key4) == 8, "acl_key4 must stay 8 bytes");
_Static_assert(sizeof(struct acl_key6) == 20, "acl_key6 must stay 20 bytes");
_Static_assert(__builtin_offsetof(struct acl_key4, addr) == 4, "acl_key4.addr must follow prefixlen with no hole");
_Static_assert(__builtin_offsetof(struct acl_key6, addr) == 4, "acl_key6.addr must follow prefixlen with no hole");

/* rl_key is a byte-exact hash key: pad must be addressable and zeroable. */
_Static_assert(sizeof(struct rl_key) == 20, "rl_key must stay 20 bytes");
_Static_assert(__builtin_offsetof(struct rl_key, family) == 16, "rl_key.family must follow the address words with no hole");

/* Each runtime-mutable config field must sit within one aligned unit,
 * which is what makes a torn read yield old-or-new per field (see above).
 */
_Static_assert(__builtin_offsetof(struct marlin_config, max_frame) == 8, "max_frame must stay 2-byte aligned at a known offset");
_Static_assert(__builtin_offsetof(struct marlin_config, acl_lists) == 10, "acl_lists must stay 2-byte aligned at a known offset");
_Static_assert(__builtin_offsetof(struct marlin_config, rl_refill) == 12, "rl_refill must stay 4-byte aligned at a known offset");
_Static_assert(__builtin_offsetof(struct marlin_config, rl_burst) == 16, "rl_burst must stay 4-byte aligned at a known offset");

/* LPM_TRIE requires a max_prefixlen that is a multiple of 8 between 8 and
 * 2048. The address width of each key supplies it.
 */
_Static_assert(sizeof(((struct acl_key4 *)0)->addr) * 8 == 32, "acl_key4 must present a 32-bit max_prefixlen");
_Static_assert(sizeof(((struct acl_key6 *)0)->addr) * 8 == 128, "acl_key6 must present a 128-bit max_prefixlen");
