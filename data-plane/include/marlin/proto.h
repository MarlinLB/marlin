/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Wire-protocol constants not supplied by UAPI headers under -target bpf.
 * NOT ABI: not mirrored by control plane.
 */

#pragma once

#include <linux/types.h>

#ifndef IP_OFFSET
#define IP_OFFSET 0x1fff
#endif
#ifndef IP_MF
#define IP_MF 0x2000
#endif
#ifndef IP_DF
#define IP_DF 0x4000
#endif

#define MARLIN_IPV4_IHL_MIN 5

#ifndef IP6_MF
#define IP6_MF 0x0001
#endif
#ifndef IP6_OFFSET
#define IP6_OFFSET 0xfff8
#endif

struct marlin_frag_hdr {
    __u8 nexthdr;
    __u8 reserved;
    __be16 frag_off;
    __be32 identification;
};

_Static_assert(sizeof(struct marlin_frag_hdr) == 8, "the IPv6 fragment header must stay 8 bytes: the walk advances by sizeof");

#define ICMP_ECHOREPLY     0
#define ICMP_DEST_UNREACH  3
#define ICMP_ECHO          8
#define ICMP_TIME_EXCEEDED 11
#define ICMP_PARAMETERPROB 12

/*
 * Both families' error and echo messages share this layout to the end of the
 * per-type word; the offending header (errors) or identifier/sequence (echo)
 * follows.
 */
struct marlin_icmphdr {
    __u8 type;
    __u8 code;
    __be16 checksum;
    __be32 rest;
};

_Static_assert(sizeof(struct marlin_icmphdr) == 8, "the offending header follows the first 8 bytes of an ICMP error");

struct marlin_l4_ports {
    __be16 sport;
    __be16 dport;
};

_Static_assert(sizeof(struct marlin_l4_ports) == 4, "marlin_l4_ports must overlay the first word of a TCP or UDP header");

#define MARLIN_UDP_HLEN  8 /* source, dest, len, check -- fixed width, no options */

/*
 * Zero-lookup encap default has no bpf_fib_lookup() result for TTL, so
 * encap units fix one. 64 matches Linux and Katran defaults.
 */
#define MARLIN_OUTER_TTL 64

/*
 * GUE (RFC 8086), version 0. No control message or optional fields.
 * Only proto field varies; vcf and flags always zero.
 */
struct marlin_gue_hdr {
    __u8 vcf; /* version(2) | C-bit(1) | Hlen(5) */
    __u8 proto;
    __be16 flags;
};

_Static_assert(sizeof(struct marlin_gue_hdr) == 4, "GUE header must be 4 bytes");

#define MARLIN_VXLAN_FLAG_VNI 0x08 /* the "I" bit: marks the VNI field valid */

/*
 * VXLAN (RFC 7348). vni_and_reserved holds bpf_htonl(vni << 8):
 * VNI in high 3 bytes, trailing reserved byte zeroed by shift.
 */
struct marlin_vxlan_hdr {
    __u8 flags; /* MARLIN_VXLAN_FLAG_VNI, rest reserved */
    __u8 reserved0[3];
    __be32 vni_and_reserved;
};

_Static_assert(sizeof(struct marlin_vxlan_hdr) == 8, "VXLAN header must be 8 bytes");

/*
 * RFC 8999 SS4.1: header-form bit at fixed offset. Short header (bit clear)
 * is 1-RTT, steerable by connection ID. Long header spans handshake, no steering.
 */
#define MARLIN_QUIC_LONG_HEADER 0x80

#define MARLIN_QUIC_CID_MIN     7  /* 1 format byte + 2 backend_id bytes + >=4 entropy bytes */
#define MARLIN_QUIC_CID_MAX     20 /* QUIC v1 limit, RFC 9000 SS17.2 */
