/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Map definitions for the Marlin data plane application. Every map is
 * declared weak: more than one translation unit includes this header, and
 * without it `bpftool gen object` refuses the link with "conflicting
 * non-weak symbol" the moment a second .c file references a map, rather
 * than merging the identical definitions as docs/design/03-translation-units.md's
 * "Linking" section assumes.
 */

#pragma once

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <marlin/abi/types.h>

__attribute__((weak)) struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct marlin_config);
    __uint(max_entries, 1);
} config SEC(".maps");

__attribute__((weak)) struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct backend);
    __uint(max_entries, MAX_BACKENDS);
} backends SEC(".maps");

__attribute__((weak)) struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_VIPS * TABLE_SIZE);
} fwd_table SEC(".maps");

__attribute__((weak)) struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct vip_key);
    __type(value, struct vip_meta);
    __uint(max_entries, MAX_VIPS);
} vip_map SEC(".maps");

/* Keyed by kernel ifindex: bpf_fib_lookup()'s egress ifindex is the
 * redirect key directly. DEVMAP_HASH rather than DEVMAP because a host
 * ifindex may exceed MAX_TX_PORTS -- it is a capacity bound, not an index
 * space (docs/design/09-sizing.md). The ingress interface is deliberately
 * absent: transmitting back out it needs no devmap.
 */
__attribute__((weak)) struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
    __type(key, __u32);   /* ifindex */
    __type(value, __u32); /* ifindex */
    __uint(max_entries, MAX_TX_PORTS);
} tx_ports SEC(".maps");

/* ACL maps for IPv4 and IPv6 allow/block rules */

__attribute__((weak)) struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct acl_key4);
    __type(value, __u32); /* control-plane rule id */
    __uint(max_entries, MAX_ACL_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} acl_allow_v4 SEC(".maps");

__attribute__((weak)) struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct acl_key4);
    __type(value, __u32);
    __uint(max_entries, MAX_ACL_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} acl_block_v4 SEC(".maps");

__attribute__((weak)) struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct acl_key6);
    __type(value, __u32);
    __uint(max_entries, MAX_ACL_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} acl_allow_v6 SEC(".maps");

__attribute__((weak)) struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct acl_key6);
    __type(value, __u32);
    __uint(max_entries, MAX_ACL_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} acl_block_v6 SEC(".maps");

__attribute__((weak)) struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct rl_key);
    __type(value, struct rl_bucket);
    __uint(max_entries, MAX_RL_ENTRIES);
} ratelimit SEC(".maps");

/* Statistics maps for VIPs and backends */

__attribute__((weak)) struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct stats);
    __uint(max_entries, MAX_VIPS);
} vip_stats SEC(".maps");

__attribute__((weak)) struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct stats);
    __uint(max_entries, MAX_BACKENDS);
} backend_stats SEC(".maps");

__attribute__((weak)) struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, DROP_REASON_MAX);
} drop_stats SEC(".maps");
