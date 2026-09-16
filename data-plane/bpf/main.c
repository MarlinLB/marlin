/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * XDP entry point for the data plane application.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <marlin.h>
#include <marlin/balancer.h>
#include <marlin/build.h>
#include <marlin/compiler.h>
#include <marlin/maps.h>
#include <marlin/parser.h>
#include <marlin/stats.h>
#include <marlin/version.h>

#ifdef MARLIN_DEBUG
#define MARLIN_DBG(...) bpf_printk(__VA_ARGS__)
#else
#define MARLIN_DBG(...) \
    do {                \
    } while(0)
#endif

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

/*
 * Maps MARLIN return codes to XDP actions.
 */
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

    /* Redirect to absent tx_ports is countable XDP_ABORTED, not silent loss. */
    case MARLIN_DROP_NO_TX_PORT:
    case MARLIN_ABORT_NULLREF:
        return XDP_ABORTED;

    default:
        return XDP_DROP;
    }
}

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
    struct marlin_ctx *mctx;
    __u32 zero = 0;
    int rc;

    mctx = bpf_map_lookup_elem(&mctx_scratch, &zero);

    if(unlikely(!mctx)) {
        MARLIN_DBG("Failed to look up per-CPU scratch state\n");
        marlin_stats_reason(MARLIN_DROP_MAP_BOUNDS);
        return XDP_ABORTED;
    }

    __builtin_memset(mctx, 0, sizeof(*mctx));
    rc = xdp_load_config(mctx);

    if(unlikely(rc != MARLIN_OK)) {
        MARLIN_DBG("Failed to load config: rc=%d\n", rc);
        marlin_stats_reason(rc);
        return XDP_ABORTED;
    }

    rc = marlin_parse(ctx, mctx);

    if(rc != MARLIN_OK) {
        MARLIN_DBG("Packet parsing failed: rc=%d\n", rc);
        marlin_stats_reason(rc);
        return marlin_action(rc);
    }

    rc = marlin_balancer_process(ctx, mctx);
    marlin_stats_reason(rc);

    return marlin_action(rc);
}

char _license[] SEC("license") = "Dual BSD/GPL"; // NOLINT(readability-identifier-naming) -- libbpf loader convention (SEC("license"))

_Static_assert(sizeof(MARLIN_BPF_VERSION) <= MARLIN_VERSION_MAX, "MARLIN_BPF_VERSION too long for struct marlin_build");
const volatile struct marlin_build MARLIN_BUILD SEC(".rodata.marlin_version") = {
    .magic = MARLIN_BUILD_MAGIC,
    .version = MARLIN_BPF_VERSION,
};
