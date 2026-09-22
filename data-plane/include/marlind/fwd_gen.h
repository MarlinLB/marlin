/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Weighted-rendezvous fwd_table block generation (docs/design/12-selection.md),
 * with the byte encoding docs/design/31-file-configuration.md D-F10 leaves
 * unstated: both hashes are keyed by the VIP's table_seed.
 *
 *   row_seed     = siphash(row_index_le32 || 0x00000000, table_seed)      (8 bytes)
 *   score_input  = siphash(row_seed_le64 || addr_be32 || vni_le32
 *                          || inner_mac[6] || 0x0000,   table_seed)       (24 bytes)
 *
 * addr is copied exactly as it sits in struct backend (network order); vni
 * and row_index are little-endian, matching every other host-order scalar
 * the datapath hashes (include/marlin/siphash.h's byte-wise little-endian
 * load). The trailing zero bytes exist only to keep both inputs a multiple
 * of 8 for marlind_siphash()'s length contract.
 *
 * This must eventually move into docs/design/12-selection.md itself and be
 * asserted by a fixture both marlind and Marlin.Core's test suites hold
 * (data-plane/tests/fwd_gen_test.c carries the C-side half).
 */

#pragma once

#if defined(__bpf__)
#error "include/marlind/ is host-only; do not include it from BPF sources"
#endif

#include <linux/types.h>

#include <marlin/abi/defines.h>

/* One [[vip]].members entry, resolved to what the score actually hashes. */
struct fwd_gen_member {
    __u16 backend_id;
    __u32 weight;
    __be32 addr;
    __u32 vni;
    __u8 inner_mac[6];
};

/*
 * Fills out[0..TABLE_SIZE) with each row's winning backend_id.
 * member_count == 0 fills every row with MARLIN_NO_BACKEND -- a VIP with no
 * members is a validation warning (docs/design/20-configuration-validation.md),
 * not something the caller must special-case.
 *
 * Deterministic: identical table_seed and member set (any order) produce an
 * identical block on every instance and every run, which is the property
 * docs/design/21-active-active.md's cross-instance agreement depends on.
 */
void fwd_gen_block(const __u8 table_seed[16], const struct fwd_gen_member *members, __u32 member_count, __u32 out[TABLE_SIZE]);
