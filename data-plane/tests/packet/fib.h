/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Real bpf_fib_lookup() state for the bpf_prog_test_run tier, built inside
 * the network namespace xdp_00_main.c's main() already unshares. Three veth
 * pairs, driven through fork()+execvp("ip", ...) rather than netlink --
 * this fixture's only failure mode is a non-zero exit, which the kernel's
 * own tools/testing/selftests/bpf/prog_tests/fib_lookup.c settles the same
 * way. Addressing mirrors scripts/netns-topo.sh (TEST-NET ranges, pinned
 * 02:00:00:00:xx:xx MACs) so a failure is diagnosable across both tiers;
 * device names are deliberately different so neither reads as if the two
 * tiers share state.
 *
 * Devices are process-wide, brought up once by fib_topology_up(); routes,
 * neighbours and tx_ports entries are per-case (docs/design/24-testing.md's
 * order-independence), added and removed by the caller through the
 * fib_route_add_* / fib_neigh_* helpers below. Declarations only --
 * defined once in fib.c and linked into every xdp_*.c in this directory
 * (data-plane/Makefile).
 */

#pragma once

#include <linux/if_ether.h>

#include <bpf/bpf_endian.h>

/*
 * mve0: the ingress device every FIB case not naming another one uses.
 * Forwarding on; carries the connected /24 that makes 192.0.2.0/24 on-link.
 */
#define FIB_DEV_INGRESS      "mve0"
#define FIB_DEV_INGRESS_PEER "mve0p"

/*
 * mve1: the off-segment egress device -- on-link for 198.51.100.0/24, never
 * an ingress in any case below. Forwarding on.
 */
#define FIB_DEV_EGRESS      "mve1"
#define FIB_DEV_EGRESS_PEER "mve1p"

/*
 * mve2: forwarding deliberately left off, so ingress here reproduces
 * BPF_FIB_LKUP_RET_FWD_DISABLED the same way lo does today for the
 * xdp_40_fib.c's fib_no_neigh_* cases, but from a real, addressable device.
 */
#define FIB_DEV_NOFWD      "mve2"
#define FIB_DEV_NOFWD_PEER "mve2p"

static const unsigned char FIB_MAC_INGRESS[ETH_ALEN]   = {0x02, 0x00, 0x00, 0x00, 0x01, 0x10}; /* mve0 */
static const unsigned char FIB_MAC_EGRESS[ETH_ALEN]    = {0x02, 0x00, 0x00, 0x00, 0x01, 0x20}; /* mve1 */
static const unsigned char FIB_MAC_NOFWD[ETH_ALEN]     = {0x02, 0x00, 0x00, 0x00, 0x01, 0x30}; /* mve2 */
static const unsigned char FIB_MAC_BACKEND_A[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x01, 0x21}; /* neigh for 192.0.2.21 */
static const unsigned char FIB_MAC_BACKEND_B[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x01, 0x22}; /* neigh for 198.51.100.21 */
static const unsigned char FIB_MAC_GATEWAY[ETH_ALEN]   = {0x02, 0x00, 0x00, 0x00, 0x01, 0x11}; /* neigh for 192.0.2.1 */

#define FIB_ADDR4(a, b, c, d) bpf_htonl(((__u32)(a) << 24) | ((__u32)(b) << 16) | ((__u32)(c) << 8) | (__u32)(d))

#define FIB_ADDR_INGRESS     FIB_ADDR4(192, 0, 2, 10)   /* mve0's own address */
#define FIB_ADDR_BACKEND_A   FIB_ADDR4(192, 0, 2, 21)   /* on-link via mve0 */
#define FIB_ADDR_GATEWAY     FIB_ADDR4(192, 0, 2, 1)    /* on-link via mve0; used as a "via" next hop */
#define FIB_ADDR_EGRESS      FIB_ADDR4(198, 51, 100, 10) /* mve1's own address */
#define FIB_ADDR_BACKEND_B   FIB_ADDR4(198, 51, 100, 21) /* on-link via mve1 */
#define FIB_ADDR_GATEWAYED   FIB_ADDR4(203, 0, 113, 5)  /* reachable only via FIB_ADDR_GATEWAY */
#define FIB_ADDR_MTU_ROUTE   FIB_ADDR4(203, 0, 113, 6)  /* on-link via mve0, route MTU forced low */
#define FIB_ADDR_BLACKHOLE   FIB_ADDR4(203, 0, 113, 7)
#define FIB_ADDR_UNREACHABLE FIB_ADDR4(203, 0, 113, 8)
#define FIB_ADDR_PROHIBIT    FIB_ADDR4(203, 0, 113, 9)
#define FIB_ADDR_UNROUTED    FIB_ADDR4(203, 0, 113, 10) /* deliberately never routed */

int fib_ifindex(const char *dev);

/* ---- routes and neighbours: per-case, added and removed by the caller -- */

void fib_route_add_onlink(__be32 addr, const char *dev);
void fib_route_add_via(__be32 addr, __be32 gw, const char *dev);

/* type is "blackhole", "unreachable" or "prohibit". */
void fib_route_add_special(const char *type, __be32 addr);

/*
 * "mtu lock", not bare "mtu": bpf_fib_lookup()'s RET_FRAG_NEEDED check reads
 * fi->fib_mtu, which only takes the route metric over the device MTU when
 * either net.ipv4.ip_forward_use_pmtu is set or the metric is locked -- an
 * unlocked mtu here is invisible to the helper and the route falls back to
 * the veth's 1500.
 */
void fib_route_add_mtu(__be32 addr, const char *dev, int mtu);

/*
 * Idempotent and non-fatal: called at both ends of a case body, so a case
 * that failed an earlier assertion cannot leave state the next one
 * inherits. Matches whatever route type currently occupies the prefix,
 * special or ordinary, without the caller naming it.
 */
void fib_route_del(__be32 addr);

/*
 * nud is "permanent" (resolved) or "failed" (RET_NO_NEIGH) --
 * docs/design/16-fib-lookup.md:60,68-70 -- "replace" rather than "add" so a
 * case flipping an existing entry's state (permanent <-> failed) need not
 * delete first.
 */
void fib_neigh_set(__be32 addr, const char *dev, const unsigned char mac[ETH_ALEN], const char *nud);
void fib_neigh_del(__be32 addr, const char *dev);

/*
 * Called once from main(), between unshare(CLONE_NEWNET) and
 * xdp_prog_load() -- a topology failure then reports before the slower
 * program load. No matching teardown: the namespace and everything in it
 * is freed when the process exits.
 */
void fib_topology_up(void);
