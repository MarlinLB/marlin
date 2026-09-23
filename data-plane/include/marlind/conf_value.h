/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Scalar coercion for marlin.conf values: address families, MACs, hex keys,
 * CIDR prefixes and the enumerated string fields. Each function reports its
 * own failure by return value alone -- the caller has the key path, this
 * layer does not, so conf.c is what turns a false return into a conf_diag
 * entry naming the offending key.
 */

#pragma once

#if defined(__bpf__)
#error "include/marlind/ is host-only; do not include it from BPF sources"
#endif

#include <stdbool.h>

#include <linux/types.h>

/* AF_INET / AF_INET6, matching marlin/abi/types.h's vip_key.family. */
bool conf_parse_ipv4(const char *str, __be32 *out);
bool conf_parse_ipv6(const char *str, __u8 out[16]);

bool conf_parse_mac(const char *str, __u8 out[6]);

/* Exactly 32 hex digits -> 16 bytes; hash_key and table_seed both use this. */
bool conf_parse_hexkey16(const char *str, __u8 out[16]);

/* "tcp" | "udp" | "sctp" -> IPPROTO_*. */
bool conf_parse_proto(const char *str, __u8 *out);

/* "l2dsr" | "ipip" | "gue" | "vxlan" -> MARLIN_MODE_*. */
bool conf_parse_mode(const char *str, __u8 *out);

/* "up" | "down". */
bool conf_parse_state(const char *str, bool *up);

/*
 * "<addr>/<prefixlen>". Family is detected from the address, not stated
 * separately: v4 fills addr[0..3] and leaves addr[4..15] zero. Returns the
 * bits as given -- callers wanting the host-bits-clear rule
 * (docs/design/20-configuration-validation.md) check it themselves, since
 * accepting or rejecting is a conf_check() decision, not a parse one.
 */
bool conf_parse_cidr(const char *str, bool *is_v6, __u32 *prefixlen, __u8 addr[16]);

/* True if conf_parse_cidr()'s addr carries any bit at or beyond prefixlen. */
bool conf_cidr_host_bits_set(const __u8 addr[16], __u32 prefixlen, bool is_v6);
