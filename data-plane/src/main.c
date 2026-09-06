/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * XDP entry point for the data plane application.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
    __u32 packet_size;

    packet_size = ctx->data_end - ctx->data;
    bpf_printk("Packet received: size=%u\n", packet_size);

    return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL"; // NOLINT(readability-identifier-naming) -- libbpf loader convention (SEC("license"))
