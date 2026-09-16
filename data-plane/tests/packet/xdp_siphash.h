/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * A from-scratch SipHash-2-4 transcription for the QUIC connection-ID
 * steering cases (xdp_80_quic.c) and their own vector self-check
 * (xdp_50_siphash.c). marlin_siphash() cannot be reused here: siphash.h
 * pulls in the real <bpf/bpf_helpers.h>, which cannot coexist with the
 * userspace <bpf/bpf.h> that maps.h and fib.h need, and this tier has no
 * stubs/bpf shadow to fall back on -- the same constraint, and the same
 * remedy, as xdp_encap.h's test_ipv4_csum(). xdp_50_siphash.c's case is
 * what makes this transcription trustworthy; without it every QUIC
 * assertion is asserting against itself.
 */

#pragma once

#include <linux/types.h>

__u64 sip_hash64(const void *data, __u32 len, const __u8 key[16]);
