/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Encapsulation constants and frame-shape checkers shared by xdp_40_fib.c
 * and xdp_45_encap.c: seed_encap_cfg() and ipip_check_frame() are used by
 * both -- the FIB half exercises IPIP under a resolved next hop, the encap
 * half exercises it directly -- everything else here is encap-only but
 * lands in one header for symmetry with the FIB/encap split itself.
 */

#pragma once

#include <linux/if_ether.h>
#include <linux/ip.h>

#define IPIP_TUNNEL_SRC 0x0d0d0d0dU /* 13.13.13.13 */

/*
 * config is process-global and outlives a case: every case here seeds its
 * own tunnel_src/max_frame rather than relying on what an earlier case left,
 * mirroring seed_acl_cfg's discipline (xdp_fixture.h).
 */
void seed_encap_cfg(__be32 tunnel_src, __u16 max_frame);

/*
 * A from-scratch reimplementation, not a call into csum.h: including
 * <marlin/csum.h> here would drag in the real <bpf/bpf_helpers.h> for
 * __always_inline, which conflicts with the userspace <bpf/bpf.h>/
 * <bpf/libbpf.h> this tier's own fib.h needs (both declare
 * bpf_map_update_elem et al. with incompatible signatures). An independent
 * implementation also means this assertion does not share a bug with the
 * one it is checking; tests/csum_test.c verifies csum.h's own algorithm.
 */
__sum16 test_ipv4_csum(const struct iphdr *iph);

/*
 * IPIP-specific sibling of xdp_fixture.h's nh_check_frame(): the frame grew
 * by MARLIN_OVERHEAD_IPIP, so neither "same length" nor "everything past
 * ETH_HLEN is unchanged" applies. Asserts the outer Ethernet addresses, the
 * whole outer IPv4 header byte-for-byte, and that the inner packet moved
 * without otherwise changing.
 */
void ipip_check_frame(const unsigned char *expect_dst, const unsigned char *expect_src, __be32 tunnel_src,
                       __be32 backend_addr, __u8 inner_family, __u32 out_len, __u8 outer_dscp);

#define GUE_TUNNEL_SRC 0x0e0e0e0eU /* 14.14.14.14 */

#define VXLAN_TUNNEL_SRC 0x0f0f0f0fU /* 15.15.15.15 */
#define VXLAN_VNI        0x00abcdefU /* arbitrary, within the 24-bit field */

/* Mirrors entropy.h's MARLIN_ENTROPY_SPORT_MIN; entropy.h cannot be included
 * here for the same reason csum.h cannot (test_ipv4_csum above).
 */
#define GUE_ENTROPY_SPORT_MIN 49152U

/* GUE-specific sibling of ipip_check_frame(): the frame grew by
 * MARLIN_OVERHEAD_GUE and gained a UDP+GUE header past the outer IPv4 one.
 * udp.source (the entropy port) is range-checked rather than matched
 * exactly -- entropy.h's algorithm is independently verified by
 * tests/entropy_test.c and tests/gue_test.c wires it against the real
 * function; this tier only needs to know a real value landed there.
 */
void gue_check_frame(const unsigned char *expect_dst, const unsigned char *expect_src, __be32 tunnel_src,
                      __be32 backend_addr, __be16 encap_dport, __u8 inner_family, __u32 out_len, __u8 outer_dscp);

/*
 * VXLAN-specific sibling of gue_check_frame(): the frame grew by
 * MARLIN_OVERHEAD_VXLAN, and unlike IPIP/GUE the arriving Ethernet header
 * does not become the *outer* header -- it becomes the *inner* one, with its
 * own two addresses rewritten (docs/design/14-forwarding-modes.md SS7.4).
 * expect_dst/expect_src still name the *outer* header's addresses, the same
 * convention as ipip_check_frame()/gue_check_frame(): what a next-hop MAC
 * swap would have produced. udp.source reuses GUE_ENTROPY_SPORT_MIN --
 * entropy.h's port floor is shared by GUE and VXLAN.
 */
void vxlan_check_frame(const unsigned char *expect_dst, const unsigned char *expect_src, __be32 tunnel_src,
                        __be32 backend_addr, __be16 encap_dport, const unsigned char *inner_mac, __u32 vni,
                        __u32 out_len, __u8 outer_dscp);
