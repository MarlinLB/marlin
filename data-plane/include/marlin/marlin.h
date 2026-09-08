/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Inner Marlin header file.
 */

#pragma once

#include <linux/types.h>

#include <marlin/abi/types.h>

struct packet_tuple { /* 40 bytes */
    __be32 src[4];    /* client; IPv4 in src[0], src[1..3] zero */
    __be32 dst[4];    /* VIP;    IPv4 in dst[0], dst[1..3] zero */
    __be16 sport;
    __be16 dport;
    __u8 proto;
    __u8 family; /* AF_INET | AF_INET6 */
    __u8 pad[2];
};

_Static_assert(sizeof(struct packet_tuple) == 40, "packet_tuple must stay 40 bytes");

#define MARLIN_CTX_F_ICMP       (1U << 0) /* tuple came from an embedded header */
#define MARLIN_CTX_F_FRAG       (1U << 1) /* non-first fragment: no L4 ports */
#define MARLIN_CTX_F_FRAG_FIRST (1U << 2) /* first fragment: ports present, more follow */
#define MARLIN_CTX_F_QUIC       (1U << 3) /* UDP payload opens with a QUIC short header (RFC 8999) */
#define MARLIN_CTX_F_FRAG_ANY   (MARLIN_CTX_F_FRAG | MARLIN_CTX_F_FRAG_FIRST)

struct marlin_ctx {            /* 104 bytes */
    struct packet_tuple tuple; /* 40 */
    struct backend backend;    /* 32 */
    struct marlin_config cfg;  /* 20 — one snapshot, taken in marlin.c */
    __u32 flags;               /*  4 */
    __u16 l3_off;              /*  2 — outer L3 offset once an encap unit has run */
    __u16 l4_off;              /*  2 */
    __u16 pkt_len;             /*  2 — emitted length once an encap unit has run */
    __u8 acl_verdict;          /*  1 — enum marlin_acl_verdict (acl.h) */
    __u8 pad;                  /*  1 */
};

_Static_assert(sizeof(struct marlin_ctx) <= 108, "marlin_ctx exceeds its share of MAX_BPF_STACK");

enum marlin_ret {
    /* terminal outcomes, not counted here */
    MARLIN_OK = 0,
    MARLIN_OK_TX,
    MARLIN_OK_REDIRECT,

    /* counted reasons; the enumerator value is the drop_stats index */
    MARLIN_PASS_VIP_MISS,
    MARLIN_PASS_ICMP_ECHO,
    MARLIN_DROP_NO_BACKEND,
    MARLIN_DROP_BACKEND_DOWN,
    MARLIN_DROP_BACKEND_UNRESOLVED,
    MARLIN_DROP_PARSE_ERROR,
    MARLIN_DROP_UNSUPPORTED_PROTO,
    MARLIN_DROP_EXT_HDR_LIMIT,
    MARLIN_DROP_ICMP_UNPARSEABLE,
    MARLIN_DROP_FIB_NO_NEIGH,
    MARLIN_DROP_FIB_FWD_DISABLED,
    MARLIN_DROP_FIB_BLACKHOLE,
    MARLIN_DROP_FIB_UNREACHABLE,
    MARLIN_DROP_FIB_PROHIBIT,
    MARLIN_DROP_FIB_GATEWAYED,
    MARLIN_DROP_FIB_UNSPEC,
    MARLIN_DROP_FRAG_NEEDED,
    MARLIN_DROP_ADJUST_HEAD,
    MARLIN_DROP_ENCAP_LENGTH,
    MARLIN_DROP_FRAME_TOO_BIG,
    MARLIN_DROP_MAP_BOUNDS,
    MARLIN_DROP_NO_TX_PORT,
    MARLIN_DROP_ACL_BLOCKED,
    MARLIN_DROP_RATELIMITED,

    /* counted in place, never returned */
    MARLIN_COUNT_MAC_FALLBACK,
    MARLIN_COUNT_NEIGH_FALLBACK,
    MARLIN_COUNT_EGRESS_MISMATCH,
    MARLIN_COUNT_RL_CAS_EXHAUSTED,

    MARLIN_DROP_FRAG_UNSUPPORTED,
    MARLIN_PASS_NOT_FORWARDED,
    MARLIN_ABORT_NULLREF,
    MARLIN_COUNT_RL_INSERT_FAILED, /* counted in place, never returned */

    /*
     * Reserved for VIP_QUIC's steering step (docs/design/30-quic.md);
     * balancer.c is the producer. None of the four is a drop -- a decode
     * failure falls through to the existing hash path uncounted as one.
     */
    MARLIN_COUNT_QUIC_CID_ROUTED,
    MARLIN_COUNT_QUIC_CID_CHECK_FAILED,
    MARLIN_COUNT_QUIC_CID_UNKNOWN_BACKEND,
    MARLIN_COUNT_QUIC_CID_BACKEND_DOWN,

    MARLIN_RET_MAX
};

_Static_assert(MARLIN_RET_MAX <= DROP_REASON_MAX, "enum marlin_ret no longer fits drop_stats");
