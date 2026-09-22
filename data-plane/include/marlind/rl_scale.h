/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * The operator-unit -> scaled-token-field conversion docs/design/28-rate-limiting.md
 * requires (rate << RL_TOKEN_SHIFT, divided by the 953.67/sec tick rate,
 * truncated to 953 as that document states it). Header-only and shared by
 * conf_check.c (does tokens_per_sec round to a zero refill?) and
 * reconcile.c (the actual value written to config.rl_refill/rl_burst), so
 * the two can never disagree about what "zero" means.
 */

#pragma once

#if defined(__bpf__)
#error "include/marlind/ is host-only; do not include it from BPF sources"
#endif

#include <linux/types.h>

#include <marlin/abi/defines.h>

static inline __u32 marlind_scale_refill(__u32 tokens_per_sec)
{
    return (__u32)(((__u64)tokens_per_sec << RL_TOKEN_SHIFT) / 953);
}

static inline __u32 marlind_scale_burst(__u32 burst_packets)
{
    return (__u32)((__u64)burst_packets << RL_TOKEN_SHIFT);
}
