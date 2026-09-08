/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Host stand-in for bpf_ktime_get_ns(), reached through
 * tests/stubs/bpf/bpf_helpers.h. Settable rather than reading the real
 * clock: ratelimit.c is time-dependent by design, and a native case needs
 * to seed an exact tick delta, not race the wall clock to produce one.
 */

#pragma once

#include <linux/types.h>

static __u64 time_stub_now_ns;

static __attribute__((unused)) void time_stub_set_ns(__u64 ns)
{
    time_stub_now_ns = ns;
}

static __attribute__((unused)) __u64 time_stub_get_ns(void)
{
    return time_stub_now_ns;
}
