/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Packet builder shared by the native (parser_test.c) and bpf_prog_test_run
 * (tests/packet/xdp_*.c) tiers (docs/REPO-STRUCTURE.md Sec7.2). Declarations
 * only -- the arena and every pb_* function are defined once, in
 * tests/support/packet.c, and linked into both tiers' binaries
 * (data-plane/Makefile).
 */

#pragma once

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include <bpf/bpf_endian.h>

#include <marlin/proto.h>

/*
 * parser.c:140 admits hdrlen == 255 (2048 bytes/header), so
 * marlin_walk_ext6 can compute an l4_off far past data_end (parser.c:103,
 * never dereferenced -- see the plan's Observation 4). The arena is padded
 * well past the largest built frame so every pointer parser.c *computes*
 * stays inside one object; only what it *dereferences* is bounds-checked
 * by data_end.
 */
#define PB_ARENA_SIZE (256u * 1024u)

extern unsigned char *pb_arena;
extern __u32 pb_len;

__u32 pb_reset(void);
__u32 pb_raw(const void *bytes, __u32 len);
__u32 pb_pad(__u32 n);
__u32 pb_eth(__u16 ethertype_host);

/*
 * frag_off_host carries both the 3 flag bits and the 13-bit offset, already
 * combined by the caller (e.g. IP_MF | 0x0001) -- marlin_parse_frag4 masks
 * the wire (big-endian) value, so the combination is what is under test.
 */
__u32 pb_ipv4(__u8 proto, __u8 ihl, __u16 frag_off_host, __be32 saddr, __be32 daddr);
__u32 pb_ipv6(__u8 nexthdr, const unsigned char src[16], const unsigned char dst[16]);

/*
 * hdrlen follows RFC 8200 sizing: (hdrlen + 1) * 8 total bytes. Pads the TLV
 * area with zero option data -- marlin_walk_ext6 never inspects it.
 */
__u32 pb_ext6(__u8 nexthdr, __u8 hdrlen);
__u32 pb_frag6(__u8 nexthdr, __u16 frag_off_host);
__u32 pb_ports(__u16 sport_host, __u16 dport_host);

/*
 * Full 8-byte UDP header -- source and dest overlay marlin_l4_ports exactly
 * as pb_ports() writes them. len_host is marlin_parse_quic()'s declared-
 * payload bound (docs/design/30-quic.md); check is filled in so a captured
 * packet's fixed header matches the wire but is never read by parser.c.
 */
__u32 pb_udp(__u16 sport_host, __u16 dport_host, __u16 len_host);

/*
 * One byte carrying only the QUIC header-form bit (RFC 8999 SS4.1;
 * MARLIN_QUIC_LONG_HEADER in proto.h): 0x80 set selects a long header, clear
 * selects short. For a case that stops at the form bit -- a long header, or a
 * payload too short to hold a connection ID.
 */
__u32 pb_quic_form(__u8 first_byte);

/*
 * Short header plus the destination connection ID that follows it, which is
 * what balancer.c steers on (docs/design/30-quic.md). The ID's own layout is
 * the caller's business: this only guarantees it lands immediately after the
 * form byte, where the decoder reads it.
 */
__u32 pb_quic_cid(__u8 first_byte, const __u8 *cid, __u32 cid_len);
__u32 pb_icmp(__u8 type, __u8 code);

/*
 * Sets data_end to exactly n bytes from the start of the packet -- the one
 * primitive every truncation/boundary case needs; n may be less than pb_len
 * so far (truncating what was already built) or, for the pkt_len-only cases,
 * larger (padding with zeroed arena bytes that are never dereferenced).
 */
__u32 pb_truncate(__u32 n);
void pb_xdp(struct xdp_md *ctx);
