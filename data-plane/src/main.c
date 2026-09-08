/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * XDP entry point for the data plane application.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <marlin.h>
#include <marlin/acl.h>
#include <marlin/encap.h>
#include <marlin/maps.h>
#include <marlin/nexthop.h>
#include <marlin/parser.h>
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

    /* Redirect to absent tx_ports is countable XDP_ABORTED, not silent loss. */
    case MARLIN_DROP_NO_TX_PORT:
    case MARLIN_ABORT_NULLREF:
        return XDP_ABORTED;

    default:
        return XDP_DROP;
    }
}

/* Interim nexthop.c call site; remove with balancer.c. */
static __always_inline int xdp_interim_nexthop(struct xdp_md *ctx, struct marlin_ctx *mctx)
{
    const struct backend *bep;
    __u32 zero = 0;
    int rc;

    bep = bpf_map_lookup_elem(&backends, &zero);

    if(!bep || (bep->flags & MARLIN_BE_F_STATE) == 0) {
        return MARLIN_OK;
    }

    __builtin_memcpy(&mctx->backend, bep, sizeof(mctx->backend));

    if(ENCAP_MODE(mctx->backend.flags) == MARLIN_MODE_L2DSR) {
        return marlin_nexthop_l2dsr(ctx, mctx);
    }

    /*
     * Encapsulation precedes next-hop resolution: nexthop.c's FIB lookup and
     * MAC-swap default both need the already-encapsulated frame.
     */
    switch(ENCAP_MODE(mctx->backend.flags)) {
    case MARLIN_MODE_IPIP:
        rc = marlin_ipip_encap_packet(ctx, mctx);
        break;
    case MARLIN_MODE_GUE:
        rc = marlin_gue_encap_packet(ctx, mctx);
        break;
    case MARLIN_MODE_VXLAN:
        rc = marlin_vxlan_encap_packet(ctx, mctx);
        break;
    default:
        rc = MARLIN_OK;
        break;
    }

    if(rc != MARLIN_OK) {
        return rc;
    }

    return marlin_nexthop_encapsulate(ctx, mctx);
}

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
    struct marlin_ctx mctx;
    __u8 *origin_ip;
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
        bpf_printk("Packet parsing failed: rc=%d\n", rc);
        return marlin_action(rc);
    }

    mctx.acl_verdict = (__u8)marlin_acl_check(&mctx);

    if(mctx.acl_verdict == MARLIN_ACL_BLOCK) {
        rc = MARLIN_DROP_ACL_BLOCKED;
        marlin_count(rc);
        return marlin_action(rc);
    }

    origin_ip = (__u8 *)&mctx.tuple.src[0];

    bpf_printk("Processing packet, size=%u origin ip=%u.%u.%u.%u\n", mctx.pkt_len, origin_ip[0], origin_ip[1], origin_ip[2],
               origin_ip[3]);

    /* Interim, see xdp_interim_nexthop above. MARLIN_OK means it declined. */
    rc = xdp_interim_nexthop(ctx, &mctx);

    if(rc != MARLIN_OK) {
        marlin_count(rc);
        return marlin_action(rc);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL"; // NOLINT(readability-identifier-naming) -- libbpf loader convention (SEC("license"))
