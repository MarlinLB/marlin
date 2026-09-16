/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Map access for the bpf_prog_test_run tier: fd lookup by name, config
 * seeding, and drop_stats/vip_stats/backend_stats reads. Uses the real ABI structs from
 * include/marlin/abi/types.h -- never a local re-declaration, so a
 * types.h layout change fails a test instead of corrupting a map write
 * silently. Declarations only -- defined once in maps.c and linked into
 * every xdp_*.c in this directory (data-plane/Makefile).
 */

#pragma once

#include <linux/bpf.h>

#include <marlin/abi/types.h>
#include <marlin/marlin.h>

void xdp_seed_config(const struct marlin_config *cfg);
__u64 xdp_drop_stats_total(int rc);
struct stats xdp_vip_stats_total(__u32 vip_num);
struct stats xdp_backend_stats_total(__u32 backend_id);

/*
 * Builds the key from struct acl_key4/acl_key6 rather than a local
 * re-declaration, same as every other helper here -- a types.h layout change
 * must fail a test, not corrupt a map write silently.
 */
void xdp_acl_add4(const char *map, __u32 prefixlen, __be32 addr, __u32 rule_id);
void xdp_acl_add6(const char *map, __u32 prefixlen, const unsigned char addr16[16], __u32 rule_id);

/*
 * BPF_F_NO_PREALLOC tries have no fixed slot set to zero between cases --
 * bpf_map_get_next_key() walks whatever the previous case left, so each ACL
 * case must clear its own trie rather than relying on a zeroed baseline.
 */
void xdp_acl_clear(const char *map);

/*
 * tx_ports (DEVMAP_HASH, ifindex -> ifindex): the redirect target set for
 * data-plane/tests/packet/fib.h's FIB cases. Per-case like the ACL helpers
 * above, for the same order-independence reason.
 */
void xdp_tx_ports_add(__u32 ifindex);

/*
 * Non-fatal on ENOENT: teardown at the start of a case must tolerate an
 * entry a failed earlier case never inserted.
 */
void xdp_tx_ports_del(__u32 ifindex);
int xdp_tx_ports_is_empty(void);
void xdp_tx_ports_clear(void);

/*
 * ratelimit (LRU_HASH, struct rl_key -> struct rl_bucket): built from the
 * real ABI structs, same discipline as the ACL helpers above. `addr16` is
 * the full 16-byte rl_key.addr -- a caller keying an IPv4 case zero-extends
 * it, mirroring the zeroed key ratelimit.c itself builds.
 */
void xdp_rl_seed(__u8 family, const unsigned char addr16[16], __u64 state);

/* Returns 0 on a miss rather than exiting: a case asserting the miss path
 * inserted a bucket needs to distinguish "not present" from "present".
 */
int xdp_rl_get(__u8 family, const unsigned char addr16[16], __u64 *state);
void xdp_rl_clear(void);

/*
 * vip_map (HASH, struct vip_key -> struct vip_meta): built from the real ABI
 * structs, same discipline as the ACL helpers above. The key must be zeroed
 * before its fields are set -- balancer.c builds its lookup key with a
 * memset and an IPv4 packet leaves addr6[1..3] zero, so a userspace key with
 * anything else there silently fails to match.
 */
void xdp_vip_add(const struct vip_key *key, const struct vip_meta *meta);

/* Non-fatal on ENOENT, for the same teardown reason as xdp_tx_ports_del. */
void xdp_vip_del(const struct vip_key *key);
void xdp_vip_clear(void);

/*
 * fwd_table is one flat ARRAY of MAX_VIPS * TABLE_SIZE slots; VIP `vip_num`
 * owns the block at vip_num * TABLE_SIZE and balancer.c picks a row inside it
 * with a keyed SipHash over the packet tuple. Userspace cannot recompute that
 * row without duplicating both the hash and struct packet_tuple's exact
 * layout, so every slot in the block is written instead: the row a packet
 * lands on stops mattering and a forwarding case asserts selection without
 * depending on a reimplementation staying in step.
 */
void xdp_fwd_fill(__u32 vip_num, __u32 id);

/*
 * Splits a VIP's block between two backends on the low bit of the row index.
 * Which backend a packet reaches then reports one bit of its hash, which is
 * what lets a case observe that a tuple field does or does not feed the hash
 * without ever computing it.
 */
void xdp_fwd_fill_striped(__u32 vip_num, __u32 id_even, __u32 id_odd);
void xdp_fwd_clear(__u32 vip_num);

/*
 * backends is an ARRAY, so index 0 exists but balancer.c treats a zero
 * forwarding-table slot as "empty" and refuses to resolve it. Callers must
 * pass a non-zero id for a backend they expect to be reachable.
 */
void xdp_backend_write(__u32 id, const struct backend *be);
void xdp_backend_clear(__u32 id);
