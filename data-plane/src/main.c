/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * XDP entry point for the data plane application.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <marlin.h>
#include <marlin/maps.h>

static __always_inline int xdp_load_config(struct marlin_ctx *ctx)
{
    const struct marlin_config *cfgp;
    __u32 zero = 0;

    cfgp = bpf_map_lookup_elem(&config, &zero);

    if(!cfgp) {
        return MARLIN_DROP_MAP_BOUNDS;
    }

    __builtin_memcpy(&ctx->cfg, cfgp, sizeof(ctx->cfg));
    return MARLIN_OK;
}

SEC("xdp")

int xdp_main(struct xdp_md *ctx)
{
    struct marlin_ctx mctx;
    __u32 packet_size;
    int rc;

    __builtin_memset(&mctx, 0, sizeof(mctx));
    rc = xdp_load_config(&mctx);

    if(rc != MARLIN_OK) {
        bpf_printk("Failed to load config: rc=%d\n", rc);
        return XDP_ABORTED;
    }

    packet_size = ctx->data_end - ctx->data;
    bpf_printk("Packet received: size=%u\n", packet_size);

    return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL"; // NOLINT(readability-identifier-naming) -- libbpf loader convention (SEC("license"))
