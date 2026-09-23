/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * SipHash-2-4 for marlind's fwd_table generation (docs/design/12-selection.md).
 * A third from-scratch transcription in this tree, host-only: neither
 * existing copy fits here. <marlin/siphash.h> pulls in the BPF-only
 * <bpf/bpf_helpers.h>, which cannot share a translation unit with the
 * userspace <bpf/bpf.h> the reconciler links against, and
 * data-plane/tests/packet/xdp_siphash.c belongs to the test tree, not to a
 * shipped binary. All three carry the same length contract -- whole 8-byte
 * blocks only -- and the same byte-wise little-endian load, so every one
 * produces an identical digest for identical bytes.
 */

#pragma once

#if defined(__bpf__)
#error "include/marlind/ is host-only; do not include it from BPF sources"
#endif

#include <linux/types.h>

/*
 * len must be a multiple of 8; there is no partial-tail handling, matching
 * marlin_siphash()'s contract. Callers with a ragged input (fwd_gen.c's row
 * and score buffers) pack it into a zero-filled multiple-of-8 buffer first --
 * see docs/design/12-selection.md's byte encoding.
 */
__u64 marlind_siphash(const void *data, __u32 len, const __u8 key[16]);
