/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Parsing implementation for the Marlin data plane application.
 *
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <marlin/abi/types.h>
#include <marlin/compiler.h>
#include <marlin/proto.h>
#include <marlin/parse.h>

#define MARLIN_L3_OFF_ETH ((__u16)ETH_HLEN)

static __always_inline const struct ethhdr *marlin_parse_eth(const void *data, const void *data_end)
{
    const struct ethhdr *eth = data;

    if((const void *)(eth + 1) > data_end) {
        return NULL;
    }

    return eth;
}

static __always_inline __u32 marlin_parse_frag4(__be16 frag_off)
{
    if((frag_off & bpf_htons(IP_OFFSET)) != 0) {
        return MARLIN_CTX_F_FRAG;
    }

    if((frag_off & bpf_htons(IP_MF)) != 0) {
        return MARLIN_CTX_F_FRAG_FIRST;
    }

    return 0;
}

static __always_inline int marlin_parse_ipv4(const void *data, const void *data_end, __u16 l3_off, struct marlin_ctx *mctx,
                                             __u32 *l4_off)
{
    const struct iphdr *iph = (const struct iphdr *)((const char *)data + l3_off);
    __u32 hdr_len;

    if((const void *)(iph + 1) > data_end) {
        return MARLIN_DROP_PARSE_ERROR;
    }

    if(iph->ihl < MARLIN_IPV4_IHL_MIN) {
        return MARLIN_DROP_PARSE_ERROR;
    }

    hdr_len = (__u32)iph->ihl * 4U;

    if((const void *)((const char *)iph + hdr_len) > data_end) {
        return MARLIN_DROP_PARSE_ERROR;
    }

    mctx->tuple.family = AF_INET;
    mctx->tuple.proto = iph->protocol;
    mctx->tuple.src[0] = iph->saddr; /* client */
    mctx->tuple.dst[0] = iph->daddr; /* VIP    */
    mctx->l3_off = l3_off;
    mctx->l4_off = (__u16)((__u32)l3_off + hdr_len);
    mctx->flags |= marlin_parse_frag4(iph->frag_off);

    *l4_off = (__u32)l3_off + hdr_len;

    return MARLIN_OK;
}

static __always_inline int marlin_parse_l4(const void *data, const void *data_end, __u32 l4_off, struct marlin_ctx *mctx)
{
    switch(mctx->tuple.proto) {
    case IPPROTO_TCP: {
        const struct tcphdr *tcp = (const struct tcphdr *)((const char *)data + l4_off);

        if((const void *)(tcp + 1) > data_end) {
            return MARLIN_DROP_PARSE_ERROR;
        }

        mctx->tuple.sport = tcp->source;
        mctx->tuple.dport = tcp->dest;
        return MARLIN_OK;
    }
    case IPPROTO_UDP: {
        const struct udphdr *udp = (const struct udphdr *)((const char *)data + l4_off);

        if((const void *)(udp + 1) > data_end) {
            return MARLIN_DROP_PARSE_ERROR;
        }

        mctx->tuple.sport = udp->source;
        mctx->tuple.dport = udp->dest;
        return MARLIN_OK;
    }
    default:
        return MARLIN_PASS_NOT_FORWARDED;
    }
}

int marlin_parse(struct xdp_md *ctx, struct marlin_ctx *mctx)
{
    /* A global subprogram's BTF struct-pointer argument is nullable below
     * kernel 6.9 (__arg_nonnull); the 6.0 floor requires this check or the
     * program is rejected at load (docs/design/01-scope.md).
     */
    if(mctx == NULL) {
        return MARLIN_DROP_PARSE_ERROR;
    }

    const void *data = (const void *)(unsigned long)ctx->data;         // NOLINT(performance-no-int-to-ptr)
    const void *data_end = (const void *)(unsigned long)ctx->data_end; // NOLINT(performance-no-int-to-ptr)
    const struct ethhdr *eth;
    __u32 l4_off = 0;
    int rc;

    mctx->pkt_len = (__u16)(ctx->data_end - ctx->data);

    eth = marlin_parse_eth(data, data_end);

    if(eth == NULL) {
        return MARLIN_DROP_PARSE_ERROR;
    }

    if(eth->h_proto != bpf_htons(ETH_P_IP)) {
        return MARLIN_PASS_NOT_FORWARDED;
    }

    rc = marlin_parse_ipv4(data, data_end, MARLIN_L3_OFF_ETH, mctx, &l4_off);

    if(rc != MARLIN_OK) {
        return rc;
    }

    if((mctx->flags & MARLIN_CTX_F_FRAG_ANY) != 0U) {
        return MARLIN_DROP_FRAG_UNSUPPORTED;
    }

    return marlin_parse_l4(data, data_end, l4_off, mctx);
}
