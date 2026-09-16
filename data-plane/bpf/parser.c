/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Parsing implementation for the Marlin data plane application.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <marlin/abi/types.h>
#include <marlin/proto.h>
#include <marlin/parser.h>

#define MARLIN_L3_OFF_ETH        ((__u16)ETH_HLEN)

/* Embedded headers in ICMP error payloads rarely include extensions. */
#define MARLIN_ICMP_EMB_EXT_HDRS 2

/* Local to this translation unit; downstream uses packet_tuple instead. */
struct marlin_l3 {
    __be32 src[4];
    __be32 dst[4];
    __u32 l4_off;
    __u32 flags;
    __u8 proto;
    __u8 pad[3];
};

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

static __always_inline __u32 marlin_parse_frag6(__be16 frag_off)
{
    if((frag_off & bpf_htons(IP6_OFFSET)) != 0) {
        return MARLIN_CTX_F_FRAG;
    }

    if((frag_off & bpf_htons(IP6_MF)) != 0) {
        return MARLIN_CTX_F_FRAG_FIRST;
    }

    return 0;
}

static __always_inline int marlin_is_ext6(__u8 nexthdr)
{
    return nexthdr == IPPROTO_HOPOPTS || nexthdr == IPPROTO_ROUTING || nexthdr == IPPROTO_DSTOPTS || nexthdr == IPPROTO_FRAGMENT;
}

/*
 * Marlin cannot reach the ports behind ESP or AH. One predicate for the
 * three sites this policy applies to: the IPv6 extension-header chain, the
 * port parse both families share, and marlin_parse()'s own check below --
 * which exists because the first two run only on a packet that already
 * cleared the fragment shortcut, and a non-first fragment never does.
 */
static __always_inline int marlin_proto_unsupported(__u8 proto)
{
    return proto == IPPROTO_ESP || proto == IPPROTO_AH;
}

_Static_assert(MARLIN_L3_OFF_ETH + sizeof(struct ipv6hdr) + ((unsigned long)MAX_EXT_HDRS * 2048UL) < 0x10000UL,
               "the IPv6 extension-header walk must not push l4_off past marlin_ctx.l4_off's width");

static __always_inline int marlin_walk_ext6(const void *data, const void *data_end, __u32 off, __u8 nexthdr, __u32 max_ext,
                                            struct marlin_l3 *out)
{
#pragma clang loop unroll(full)
    for(__u32 i = 0; i <= MAX_EXT_HDRS; i++) {
        const struct ipv6_opt_hdr *eh;
        __u32 hdr_len;

        if(marlin_proto_unsupported(nexthdr)) {
            return MARLIN_DROP_UNSUPPORTED_PROTO;
        }

        if(!marlin_is_ext6(nexthdr)) {
            out->proto = nexthdr;
            out->l4_off = off;
            return MARLIN_OK;
        }

        if(i >= max_ext) {
            return MARLIN_DROP_EXT_HDR_LIMIT;
        }

        eh = (const struct ipv6_opt_hdr *)((const char *)data + off);

        if((const void *)(eh + 1) > data_end) {
            return MARLIN_DROP_PARSE_ERROR;
        }

        if(nexthdr == IPPROTO_FRAGMENT) {
            const struct marlin_frag_hdr *fh = (const struct marlin_frag_hdr *)eh;

            if((const void *)(fh + 1) > data_end) {
                return MARLIN_DROP_PARSE_ERROR;
            }

            out->flags |= marlin_parse_frag6(fh->frag_off);

            /* Non-first fragments carry payload, not headers. */
            if((out->flags & MARLIN_CTX_F_FRAG) != 0U) {
                out->proto = fh->nexthdr;
                out->l4_off = off + sizeof(*fh);
                return MARLIN_OK;
            }

            hdr_len = sizeof(*fh);
        } else {
            hdr_len = ((__u32)eh->hdrlen + 1U) * 8U;
        }

        nexthdr = eh->nexthdr;
        off += hdr_len;
    }

    return MARLIN_DROP_EXT_HDR_LIMIT;
}

static __always_inline int marlin_parse_l3(const void *data, const void *data_end, __u32 l3_off, __u8 family, __u32 max_ext,
                                           struct marlin_l3 *out)
{
    __builtin_memset(out, 0, sizeof(*out));

    if(family == AF_INET) {
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

        out->src[0] = iph->saddr;
        out->dst[0] = iph->daddr;
        out->proto = iph->protocol;
        out->l4_off = l3_off + hdr_len;
        out->flags = marlin_parse_frag4(iph->frag_off);

        return MARLIN_OK;
    }

    const struct ipv6hdr *ip6 = (const struct ipv6hdr *)((const char *)data + l3_off);

    if((const void *)(ip6 + 1) > data_end) {
        return MARLIN_DROP_PARSE_ERROR;
    }

    __builtin_memcpy(out->src, &ip6->saddr, sizeof(out->src));
    __builtin_memcpy(out->dst, &ip6->daddr, sizeof(out->dst));

    return marlin_walk_ext6(data, data_end, l3_off + sizeof(*ip6), ip6->nexthdr, max_ext, out);
}

static __always_inline int marlin_parse_ports(const void *data, const void *data_end, __u32 l4_off, __u8 proto, __be16 *sport,
                                              __be16 *dport)
{
    const struct marlin_l4_ports *ports;

    if(marlin_proto_unsupported(proto)) {
        return MARLIN_DROP_UNSUPPORTED_PROTO;
    }

    if(proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
        return MARLIN_PASS_NOT_FORWARDED;
    }

    ports = (const struct marlin_l4_ports *)((const char *)data + l4_off);

    if((const void *)(ports + 1) > data_end) {
        return MARLIN_DROP_PARSE_ERROR;
    }

    *sport = ports->sport;
    *dport = ports->dport;

    return MARLIN_OK;
}

static __always_inline __u32 marlin_parse_quic(const void *data, const void *data_end, __u32 l4_off, struct marlin_ctx *mctx)
{
    const struct udphdr *udp = (const struct udphdr *)((const char *)data + l4_off);
    const __u8 *form;
    __u16 udp_len;

    if((const void *)(udp + 1) > data_end) {
        return 0;
    }

    udp_len = bpf_ntohs(udp->len);

    if(udp_len < MARLIN_UDP_HLEN) {
        /* Declared length shorter than the header itself: subtracting would underflow. */
        mctx->udp_payload_len = 0;
        return 0;
    }

    udp_len -= MARLIN_UDP_HLEN;
    mctx->udp_payload_len = (udp_len > 0xff) ? 0xff : (__u8)udp_len;

    if(mctx->udp_payload_len == 0) {
        return 0;
    }

    form = (const __u8 *)udp + MARLIN_UDP_HLEN;

    if((const void *)(form + 1) > data_end) {
        return 0;
    }

    return (*form & MARLIN_QUIC_LONG_HEADER) == 0 ? MARLIN_CTX_F_QUIC : 0;
}

static __always_inline int marlin_proto_is_icmp(__u8 family, __u8 proto)
{
    return (family == AF_INET && proto == IPPROTO_ICMP) || (family == AF_INET6 && proto == IPPROTO_ICMPV6);
}

static __always_inline int marlin_icmp_is_error(__u8 family, __u8 type)
{
    if(family == AF_INET) {
        return type == ICMP_DEST_UNREACH || type == ICMP_TIME_EXCEEDED || type == ICMP_PARAMETERPROB;
    }

    return type == ICMPV6_DEST_UNREACH || type == ICMPV6_PKT_TOOBIG || type == ICMPV6_TIME_EXCEED || type == ICMPV6_PARAMPROB;
}

static __always_inline int marlin_icmp_is_echo(__u8 family, __u8 type)
{
    if(family == AF_INET) {
        return type == ICMP_ECHO || type == ICMP_ECHOREPLY;
    }

    return type == ICMPV6_ECHO_REQUEST || type == ICMPV6_ECHO_REPLY;
}

static __always_inline int marlin_parse_icmp(const void *data, const void *data_end, __u32 l4_off, __u8 family, struct marlin_l3 *emb,
                                             struct marlin_ctx *mctx)
{
    const struct marlin_icmphdr *icmp = (const struct marlin_icmphdr *)((const char *)data + l4_off);
    __be16 emb_sport = 0;
    __be16 emb_dport = 0;
    int rc;

    if((const void *)((const char *)icmp + 2) > data_end) {
        return MARLIN_DROP_PARSE_ERROR;
    }

    if(!marlin_icmp_is_error(family, icmp->type)) {
        /* Non-error ICMP (ND, MLD, etc.) must reach host stack. */
        return marlin_icmp_is_echo(family, icmp->type) ? MARLIN_PASS_ICMP_ECHO : MARLIN_PASS_NOT_FORWARDED;
    }

    if((const void *)(icmp + 1) > data_end) {
        return MARLIN_DROP_ICMP_UNPARSEABLE;
    }

    rc = marlin_parse_l3(data, data_end, l4_off + sizeof(*icmp), family, MARLIN_ICMP_EMB_EXT_HDRS, emb);

    if(rc != MARLIN_OK) {
        return MARLIN_DROP_ICMP_UNPARSEABLE;
    }

    if((emb->flags & MARLIN_CTX_F_FRAG) != 0U) {
        return MARLIN_DROP_ICMP_UNPARSEABLE;
    }

    if(marlin_parse_ports(data, data_end, emb->l4_off, emb->proto, &emb_sport, &emb_dport) != MARLIN_OK) {
        return MARLIN_DROP_ICMP_UNPARSEABLE;
    }

    __builtin_memcpy(mctx->tuple.dst, emb->src, sizeof(mctx->tuple.dst));
    __builtin_memcpy(mctx->tuple.src, emb->dst, sizeof(mctx->tuple.src));
    mctx->tuple.dport = emb_sport;
    mctx->tuple.sport = emb_dport;
    mctx->tuple.proto = emb->proto;
    mctx->flags |= MARLIN_CTX_F_ICMP;

    return MARLIN_OK;
}

int marlin_parse(struct xdp_md *ctx, struct marlin_ctx *mctx)
{
    if(ctx == NULL || mctx == NULL) {
        return MARLIN_ABORT_NULLREF;
    }

    const void *data = (const void *)(unsigned long)ctx->data;         // NOLINT(performance-no-int-to-ptr)
    const void *data_end = (const void *)(unsigned long)ctx->data_end; // NOLINT(performance-no-int-to-ptr)
    const struct ethhdr *eth;
    struct marlin_l3 l3;
    __u8 family;
    int rc;

    mctx->pkt_len = (__u16)(ctx->data_end - ctx->data);

    eth = marlin_parse_eth(data, data_end);

    if(eth == NULL) {
        return MARLIN_DROP_PARSE_ERROR;
    }

    if(eth->h_proto == bpf_htons(ETH_P_IP)) {
        family = AF_INET;
    } else if(eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        family = AF_INET6;
    } else {
        return MARLIN_PASS_NOT_FORWARDED;
    }

    rc = marlin_parse_l3(data, data_end, MARLIN_L3_OFF_ETH, family, MAX_EXT_HDRS, &l3);

    if(rc != MARLIN_OK) {
        return rc;
    }

    mctx->tuple.family = family;
    mctx->tuple.proto = l3.proto;
    __builtin_memcpy(mctx->tuple.src, l3.src, sizeof(mctx->tuple.src));
    __builtin_memcpy(mctx->tuple.dst, l3.dst, sizeof(mctx->tuple.dst));
    mctx->l3_off = MARLIN_L3_OFF_ETH;
    mctx->l4_off = (__u16)l3.l4_off;
    mctx->flags |= l3.flags;

    /*
     * Applied ahead of the fragment shortcut below so it binds regardless of
     * fragment state: IPv4 carries the protocol in the base header
     * unconditionally, and IPv6's fragment header walk has already copied
     * fh->nexthdr into l3.proto by the time either path reaches here. An
     * unfragmented ESP/AH packet is unsupported_proto; leaving its fragment
     * tails admitted would be a second, inconsistent policy for the same
     * protocol.
     */
    if(marlin_proto_unsupported(l3.proto)) {
        return MARLIN_DROP_UNSUPPORTED_PROTO;
    }

    if((mctx->flags & MARLIN_CTX_F_FRAG) != 0U) {
        /* Fragment tails carry no ICMP or port headers. */
        return marlin_proto_is_icmp(family, l3.proto) ? MARLIN_PASS_NOT_FORWARDED : MARLIN_OK;
    }

    if(marlin_proto_is_icmp(family, l3.proto)) {
        return marlin_parse_icmp(data, data_end, l3.l4_off, family, &l3, mctx);
    }

    rc = marlin_parse_ports(data, data_end, l3.l4_off, l3.proto, &mctx->tuple.sport, &mctx->tuple.dport);

    if(rc == MARLIN_OK && l3.proto == IPPROTO_UDP) {
        mctx->flags |= marlin_parse_quic(data, data_end, l3.l4_off, mctx);
    }

    return rc;
}
