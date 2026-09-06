/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * XDP entry point for the data plane application.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <marlin.h>
#include <marlin/maps.h>
#include <marlin/parse.h>
#include <marlin/stats.h>

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

static __always_inline int marlin_action(int rc)
{
    switch(rc) {
    case MARLIN_PASS_VIP_MISS:
    case MARLIN_PASS_ICMP_ECHO:
    case MARLIN_PASS_NOT_FORWARDED:
        return XDP_PASS;
    case MARLIN_OK_TX:
        return XDP_TX;
    case MARLIN_OK_REDIRECT:
        return XDP_REDIRECT;
    default:
        return XDP_DROP;
    }
}

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
    struct marlin_ctx mctx;
    int rc;

    __builtin_memset(&mctx, 0, sizeof(mctx));
    rc = xdp_load_config(&mctx);

    if(rc != MARLIN_OK) {
        bpf_printk("Failed to load config: rc=%d\n", rc);
        return XDP_ABORTED;
    }

    rc = marlin_parse(ctx, &mctx);
    marlin_count(rc);

    if(rc != MARLIN_OK) {
        return marlin_action(rc);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL"; // NOLINT(readability-identifier-naming) -- libbpf loader convention (SEC("license"))
