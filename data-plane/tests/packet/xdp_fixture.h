/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Fixture shared across the bpf_prog_test_run case files in this directory:
 * the addresses and MACs every theme sends packets between, the run
 * wrappers, and the VIP/backend/forwarding-table helpers more than one
 * theme needs to seed. A helper only one file uses stays local to it
 * instead of landing here (docs/REPO-STRUCTURE.md's split of xdp_test.c
 * into xdp_00_main.c..xdp_80_quic.c).
 */

#pragma once

#include <linux/if_ether.h>

#include <bpf/bpf_endian.h>

#include <marlin/abi/types.h>

#include "prog.h"

#define V4_SRC 0x0a0a0a0aU /* 10.10.10.10 */
#define V4_DST 0x0b0b0b0bU /* 11.11.11.11 */

extern const unsigned char SRC6[16];
extern const unsigned char DST6[16];

/* The frame after xdp_main runs, sized for the largest case in any file. */
extern unsigned char out_buf[XDP_TEST_RUN_MAX_SIZE];

struct xdp_run_result run_current_packet(void);
struct xdp_run_result run_packet_on(__u32 ingress_ifindex);

#define NH_INGRESS_IFINDEX 1U

#define NH_BACKEND_ADDR 0x0c0c0c0cU /* 12.12.12.12 */

extern const unsigned char NH_MARLIN_MAC[ETH_ALEN];
extern const unsigned char NH_ROUTER_MAC[ETH_ALEN];
extern const unsigned char NH_BACKEND_MAC[ETH_ALEN];
extern const unsigned char NH_DECOY_MAC[ETH_ALEN];
extern const unsigned char VXLAN_INNER_MAC[ETH_ALEN];
extern const unsigned char ALT_BACKEND_MAC[ETH_ALEN];

/* ---- VIP and backend fixture ------------------------------------------ */

/*
 * lb_core.c refuses a forwarding-table slot of 0, so no fixture backend may
 * live at index 0 of the backends array.
 */
#define NH_BACKEND_ID  1U
#define ALT_BACKEND_ID 2U

#define NH_VIP_NUM  0U
#define UDP_VIP_NUM 1U
#define ALT_VIP_NUM 2U
#define SCTP_VIP_NUM 3U
#define SCTP_VIP_PORT 38412U

/*
 * Every fixture VIP shares one hash key. Its value is arbitrary to the
 * forwarding cases, which fill a VIP's whole block so the row SipHash picks
 * cannot matter, but the QUIC cases forge a connection ID against it and so
 * need it to be a value userspace knows.
 */
#define VIP_FIXTURE_HASH_KEY_BYTE 0x5aU

void vip_key4(struct vip_key *key, __be32 addr, __u16 port_host, __u8 proto);
void vip_key6(struct vip_key *key, const unsigned char addr16[16], __u16 port_host, __u8 proto);
void vip_meta_init(struct vip_meta *meta, __u32 vip_num, __u32 flags);
void vip_seed4(__be32 addr, __u16 port_host, __u8 proto, __u32 vip_num, __u32 flags);
void vip_seed6(const unsigned char addr16[16], __u16 port_host, __u8 proto, __u32 vip_num, __u32 flags);

/*
 * L2DSR with a stored MAC and MARLIN_BE_F_FIB clear returns MARLIN_OK_TX
 * straight out of nexthop.c, without a FIB lookup. A case about something
 * upstream of next-hop resolution uses this to observe "was forwarded" as a
 * plain XDP_TX, with no route or neighbour to set up.
 */
void backend_seed_l2dsr(__u32 id, const unsigned char *mac);

/*
 * The VIP the build_udp4()/build_udp6() frames land on, with a reachable
 * backend behind it. Cases that would otherwise assert only "not dropped"
 * need it: without a VIP every outcome collapses onto the XDP_PASS of a VIP
 * miss, and an admitted packet becomes indistinguishable from one the step
 * under test never ran for.
 */
void udp_vip_seed(__u32 flags);
void udp_vip_clear(void);

/*
 * Two vip_map keys, one family each, sharing SCTP_VIP_NUM -- a VIP address
 * group (docs/design/32-sctp.md): both keys point at the one fwd_table
 * block udp_vip_seed's two keys already share, so a case addressed to
 * either family selects the same backend and the same vip_stats counter.
 */
void sctp_vip_seed(__u32 flags);
void sctp_vip_clear(void);

#define ACL_ADDR4(a, b, c, d) bpf_htonl(((__u32)(a) << 24) | ((__u32)(b) << 16) | ((__u32)(c) << 8) | (__u32)(d))

void seed_acl_cfg(__u32 flags, __u16 acl_lists);
void build_udp4(__be32 src, __be32 dst);
void build_udp6(const unsigned char src[16], const unsigned char dst[16]);

/*
 * Every case that sends a next-hop-fixture frame uses nh_build_frame() or
 * nh_build_frame_v6(), so the VIP and forwarding-table entries those
 * frames need are seeded and torn down by nh_backend_seed()/nh_backend_clear()
 * rather than repeated in every case body. The whole forwarding block is
 * filled with the one backend id, which is what lets these cases assert
 * selection without knowing which row SipHash picked.
 */
void nh_vip_seed(__u32 flags);
void nh_vip_clear(void);
void nh_backend_write(const struct backend *be);
void nh_backend_clear(void);
void nh_backend_seed(__u8 mode_and_flags, __be32 addr, const unsigned char *mac, __u32 egress_ifindex, __u32 vni,
                      const unsigned char *inner_mac);
void nh_build_frame(void);
void nh_check_frame(const unsigned char *expect_dst, const unsigned char *expect_src, __u32 out_len);
void nh_build_frame_v6(void);

/*
 * config is process-global and outlives a case (seed_acl_cfg, seed_encap_cfg
 * above). None of the lb_core/QUIC cases turn on the ACL or the rate
 * limiter, so they must clear what an earlier case enabled rather than
 * inherit it.
 */
void bal_setup(void);
