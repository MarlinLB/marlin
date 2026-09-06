/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Wire-protocol constants the UAPI headers do not supply under -target bpf.
 * NOT ABI: nothing here is mirrored by the control plane (docs/REPO-STRUCTURE.md,
 * "every file under abi/ has a C# counterpart -- nothing else does").
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
#define IP_DF 0x4000 /* unused in Phase 1; the encap units set it in 2b */
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

/* Both families' error and echo messages share this layout to the end of the
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
