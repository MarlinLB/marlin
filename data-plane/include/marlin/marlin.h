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

/*
 * The VIP's outer DSCP, copied from vip_meta.flags by balancer.c. Same shift
 * as VIP_DSCP_SHIFT so the copy is a plain mask-and-or (see the equality
 * assert below); an encapsulation unit reads it back through
 * marlin_outer_tos().
 */
#define MARLIN_CTX_DSCP_SHIFT   16
#define MARLIN_CTX_DSCP_MASK    ((__u32)0x3f << MARLIN_CTX_DSCP_SHIFT)
#define MARLIN_CTX_DSCP(f)      (((f) & MARLIN_CTX_DSCP_MASK) >> MARLIN_CTX_DSCP_SHIFT)

struct marlin_ctx {            /* 104 bytes */
    struct packet_tuple tuple; /* 40 */
    struct backend backend;    /* 32 */
    struct marlin_config cfg;  /* 20 — one snapshot, taken in marlin.c */
    __u32 flags;               /*  4 */
    __u16 l3_off;              /*  2 — outer L3 offset once an encap unit has run */
    __u16 l4_off;              /*  2 */
    __u16 pkt_len;             /*  2 — emitted length once an encap unit has run */
    __u8 acl_verdict;          /*  1 — enum marlin_acl_verdict (acl.h) */
    __u8 udp_payload_len;      /*  1 */
};

_Static_assert(sizeof(struct marlin_ctx) <= 108, "marlin_ctx exceeds its mctx_scratch per-CPU map-value budget");

_Static_assert((MARLIN_CTX_DSCP_MASK & (MARLIN_CTX_F_ICMP | MARLIN_CTX_F_FRAG | MARLIN_CTX_F_FRAG_FIRST | MARLIN_CTX_F_QUIC)) == 0,
               "the mctx DSCP field overlaps an assigned MARLIN_CTX_F_* bit");
// NOLINTNEXTLINE(misc-redundant-expression) -- deliberately tautological: catches either side moving
_Static_assert(VIP_DSCP_MASK == MARLIN_CTX_DSCP_MASK,
               "the mctx DSCP field must sit where balancer.c copies vip_meta's without a shift");

/*
 * The outer ToS byte for the three encapsulating modes: the VIP's configured
 * DSCP shifted into place, ECN always clear (VIP_DSCP_MASK is six bits).
 * Shared by ipip.c/gue.c/vxlan.c and by nexthop.c's FIB lookup, so it lives
 * here rather than in encap.h.
 */
static __always_inline __u8 marlin_outer_tos(const struct marlin_ctx *mctx)
{
    return (__u8)(MARLIN_CTX_DSCP(mctx->flags) << 2);
}

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
     * VIP_QUIC's steering step (docs/design/30-quic.md), produced by
     * balancer.c. Neither is a drop: a connection ID that does not verify
     * falls through to the hash path, as do the fall-throughs that carry no
     * counter at all (docs/design/22-observability.md).
     */
    MARLIN_COUNT_QUIC_CID_ROUTED,
    MARLIN_COUNT_QUIC_CID_CHECK_FAILED,

    MARLIN_RET_MAX
};

_Static_assert(MARLIN_RET_MAX <= DROP_REASON_MAX, "enum marlin_ret no longer fits drop_stats");
