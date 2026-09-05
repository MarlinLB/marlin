/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * XDP entry point for the data plane application.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <marlin.h>

int xdp_main(struct xdp_md *ctx)
{
    return XDP_PASS;
}

char _license[] SEC("license") = "Dual GPL/BSD";
