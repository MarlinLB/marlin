/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * ABI defines for the Marlin data plane application.
 */

#pragma once

#include <linux/types.h>

/* linux/bpf.h does not provide these and vmlinux.h is not in use. */
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

/*
 * ---- compile-time sizing ---------------------------------------------
 * All maps are sized here rather than at load time.
 */
#define MAX_EXT_HDRS                   8 /* IPv6 extension headers walked */
#define TABLE_SIZE                     65536
#define MAX_VIPS                       100
#define MAX_BACKENDS                   4096
#define MAX_TX_PORTS                   64
#define MAX_ACL_ENTRIES                65536  /* per ACL trie */
#define MAX_RL_ENTRIES                 262144 /* token buckets; LRU evicts at capacity */
#define DROP_REASON_MAX                48     /* drop_stats entries; enum marlin_ret must fit */

/*
 * backend.flag definitions
 */
#define MARLIN_BE_F_ENCAP_MODE_MASK    ((__u8)0x0f)
#define MARLIN_BE_F_ENCAP_REQUIRED_BIT 4
#define MARLIN_BE_F_FIB_BIT            5
#define MARLIN_BE_F_STATE_BIT          6
#define MARLIN_BE_F_ENCAP_REQUIRED     (1U << MARLIN_BE_F_ENCAP_REQUIRED_BIT)
#define MARLIN_BE_F_FIB                (1U << MARLIN_BE_F_FIB_BIT)
#define MARLIN_BE_F_STATE              (1U << MARLIN_BE_F_STATE_BIT)
#define MARLIN_BE_F_RESERVED \
    ((__u8) ~(MARLIN_BE_F_ENCAP_MODE_MASK | (MARLIN_BE_F_ENCAP_REQUIRED) | MARLIN_BE_F_FIB | MARLIN_BE_F_STATE))
#define ENCAP_MODE(f)          ((__u8)((f) & MARLIN_BE_F_ENCAP_MODE_MASK))

/* The mode field of backend flags */
#define MARLIN_MODE_L2DSR      0
#define MARLIN_MODE_IPIP       1
#define MARLIN_MODE_GUE        2
#define MARLIN_MODE_VXLAN      3

/* backend.state */
#define MARLIN_DOWN            0
#define MARLIN_UP              1

/*
 * marlin_config.flags
 */
#define CFG_ACL_ENABLE         (1U << 0)
#define CFG_RL_ENABLE          (1U << 1)
#define CFG_FLAGS_RESERVED     (~(__u32)(CFG_ACL_ENABLE | CFG_RL_ENABLE))

/* vip_meta.flags */
#define VIP_ACL                (1U << 0)
#define VIP_RATELIMIT          (1U << 1)
#define VIP_HASH_5TUPLE        (1U << 2)
#define VIP_QUIC               (1U << 3)
#define VIP_HASH_PORTS         (1U << 4)

#define VIP_HASH_5TUPLE_BIT    2
#define VIP_QUIC_BIT           3
#define VIP_ACL_BIT            0
#define VIP_HASH_PORTS_BIT     4

/*
 * QUIC connection-ID length for short-header decode: 7-20 inclusive, 0 = unset.
 * RFC 8999 SS4.2: DCID length not on wire, must come from configuration.
 */
#define VIP_QUIC_CID_LEN_SHIFT 8
#define VIP_QUIC_CID_LEN_MASK  ((__u32)0x1f << VIP_QUIC_CID_LEN_SHIFT)
#define VIP_QUIC_CID_LEN(f)    (((f) & VIP_QUIC_CID_LEN_MASK) >> VIP_QUIC_CID_LEN_SHIFT)

/*
 * Operator-assigned outer DSCP for this VIP's tunnel modes, RFC 2474's six
 * bits rather than the full ToS byte: the ECN pair stays unreachable from
 * configuration by construction, not by convention (docs/design/14-forwarding-modes.md
 * SS7.2). 0 = CS0, the class every VIP got before this field existed.
 */
#define VIP_DSCP_SHIFT         16
#define VIP_DSCP_MASK          ((__u32)0x3f << VIP_DSCP_SHIFT)
#define VIP_DSCP(f)            (((f) & VIP_DSCP_MASK) >> VIP_DSCP_SHIFT)

#define VIP_FLAGS_RESERVED \
    (~(__u32)(VIP_ACL | VIP_RATELIMIT | VIP_HASH_5TUPLE | VIP_QUIC | VIP_HASH_PORTS | VIP_QUIC_CID_LEN_MASK | VIP_DSCP_MASK))

/*
 * Rate limiting
 * RL_TOKEN_SHIFT: fractional width of the token field; both rl_refill and
 * rl_burst arrive pre-scaled by it. RL_TICK_SHIFT converts
 * bpf_ktime_get_ns() into bucket timestamp units, avoiding a division.
 */
#define RL_TOKEN_SHIFT             8
#define RL_TICK_SHIFT              20
#define RL_CAS_RETRIES             4

/* outer UDP destination port defaults */
#define MARLIN_GUE_DPORT_DEFAULT   6080
#define MARLIN_VXLAN_DPORT_DEFAULT 4789

#define MARLIN_VNI_MASK            ((__u32)0x00ffffff)
#define MARLIN_VNI_RESERVED        (~MARLIN_VNI_MASK)

#define MARLIN_OVERHEAD_NONE       0
#define MARLIN_OVERHEAD_IPIP       20
#define MARLIN_OVERHEAD_GUE        32
#define MARLIN_OVERHEAD_VXLAN      50

#define ACL_LIST_ALLOW             0
#define ACL_LIST_BLOCK             1
#define ACL_FAMILY_V4              0
#define ACL_FAMILY_V6              1
#define ACL_LISTS_BIT(list, fam)   ((__u16)(1U << (((list) << 1) | (fam))))
#define ACL_LISTS_RESERVED         ((__u16)0xfff0)

_Static_assert((MARLIN_VNI_MASK << 8) == 0xffffff00U, "MARLIN_VNI_MASK << 8 must fill the VXLAN header's VNI field exactly");
_Static_assert((MARLIN_VNI_MASK & MARLIN_VNI_RESERVED) == 0, "MARLIN_VNI_RESERVED overlaps the VNI value");

_Static_assert(((1U << MARLIN_BE_F_ENCAP_REQUIRED_BIT) & MARLIN_BE_F_ENCAP_MODE_MASK) == 0,
               "ENCAP_REQUIRED_BIT overlaps the flags mode field");
_Static_assert((MARLIN_BE_F_FIB & (MARLIN_BE_F_ENCAP_MODE_MASK | (1U << MARLIN_BE_F_ENCAP_REQUIRED_BIT))) == 0,
               "MARLIN_BE_F_FIB overlaps the flags mode field or ENCAP_REQUIRED_BIT");
_Static_assert((MARLIN_MODE_L2DSR | MARLIN_MODE_IPIP | MARLIN_MODE_GUE | MARLIN_MODE_VXLAN) <= MARLIN_BE_F_ENCAP_MODE_MASK,
               "a MARLIN_MODE_* value no longer fits ENCAP_MODE_MASK");
_Static_assert((MARLIN_BE_F_RESERVED &
                (MARLIN_BE_F_ENCAP_MODE_MASK | MARLIN_BE_F_STATE | MARLIN_BE_F_ENCAP_REQUIRED | MARLIN_BE_F_FIB)) == 0,
               "flags reserved bits overlap an assigned bit");

_Static_assert((VIP_FLAGS_RESERVED &
                (VIP_ACL | VIP_RATELIMIT | VIP_HASH_5TUPLE | VIP_QUIC | VIP_HASH_PORTS | VIP_QUIC_CID_LEN_MASK | VIP_DSCP_MASK)) == 0,
               "vip_meta.flags reserved mask overlaps an assigned bit");
_Static_assert((20U << VIP_QUIC_CID_LEN_SHIFT) <= VIP_QUIC_CID_LEN_MASK,
               "the QUIC CID length field must hold values up to 20 (RFC 9000 SS17.2)");
_Static_assert((VIP_DSCP_MASK & (VIP_ACL | VIP_RATELIMIT | VIP_HASH_5TUPLE | VIP_QUIC | VIP_HASH_PORTS | VIP_QUIC_CID_LEN_MASK)) == 0,
               "the DSCP field overlaps an assigned vip_meta.flags bit");
_Static_assert((VIP_DSCP_MASK >> VIP_DSCP_SHIFT) == 0x3f, "the DSCP field must hold every 6-bit codepoint (RFC 2474)");
// NOLINTNEXTLINE(misc-redundant-expression) -- constant-folds, that's the point of the assert
_Static_assert((((VIP_DSCP_MASK >> VIP_DSCP_SHIFT) << 2) & 0x03) == 0,
               "a configured DSCP must not reach the outer ToS byte's ECN bits (RFC 3168)");
/* The four acl_lists bits must fit below the reserved range. */
_Static_assert((ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V6) & ACL_LISTS_RESERVED) == 0,
               "acl_lists bit encoding overflows into the reserved bits");
_Static_assert((TABLE_SIZE & (TABLE_SIZE - 1)) == 0, "TABLE_SIZE must be a power of two: the row index is masked");
_Static_assert((__u64)MAX_VIPS *TABLE_SIZE <= 0xffffffffULL, "MAX_VIPS * TABLE_SIZE overflows the __u32 fwd_table index");

/* The scaled burst must fit the 32-bit token field, whole packets included. */
_Static_assert(((__u64)1 << (32 - RL_TOKEN_SHIFT)) - 1 == 0xffffff, "RL_TOKEN_SHIFT no longer bounds the burst at 2^24 - 1 packets");
