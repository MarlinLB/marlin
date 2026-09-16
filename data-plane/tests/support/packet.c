/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Definitions for tests/packet.h's arena and pb_* builders. Built once per
 * tier (data-plane/Makefile) rather than included inline -- see the header
 * comment on tests/support/harness.c for why.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include <bpf/bpf_endian.h>

#include <marlin/proto.h>

#include "../packet.h"

unsigned char *pb_arena;
__u32 pb_len;

/*
 * xdp_md.data/data_end are __u32 (parser.c:295-296), so the arena must live
 * below 4 GiB. MAP_FIXED_NOREPLACE over a hint keeps this off the tiny
 * addresses a plain mmap(NULL, ...) tends to return on some setups; MAP_32BIT
 * is the fallback for whichever succeeds first.
 */
static void pb_init_arena(void)
{
    static const unsigned long hints[] = {0x20000000UL, 0x30000000UL, 0x40000000UL, 0x50000000UL};
    size_t i;

    if(pb_arena != NULL) {
        return;
    }

    for(i = 0; i < sizeof(hints) / sizeof(hints[0]); i++) {
        void *p = mmap((void *)hints[i], PB_ARENA_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);

        if(p != MAP_FAILED) {
            pb_arena = (unsigned char *)p;
            break;
        }
    }

#ifdef MAP_32BIT
    if(pb_arena == NULL) {
        void *p = mmap(NULL, PB_ARENA_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);

        if(p != MAP_FAILED) {
            pb_arena = (unsigned char *)p;
        }
    }
#endif

    if(pb_arena == NULL || (unsigned long)pb_arena + PB_ARENA_SIZE > 0xffffffffUL) {
        fprintf(stderr, "packet.c: could not map a %u-byte arena below 4 GiB\n", (unsigned int)PB_ARENA_SIZE);
        abort();
    }
}

__u32 pb_reset(void)
{
    pb_init_arena();
    memset(pb_arena, 0, PB_ARENA_SIZE);
    pb_len = 0;
    return pb_len;
}

__u32 pb_raw(const void *bytes, __u32 len)
{
    memcpy(pb_arena + pb_len, bytes, len);
    pb_len += len;
    return pb_len;
}

__u32 pb_pad(__u32 n)
{
    pb_len += n;
    return pb_len;
}

__u32 pb_eth(__u16 ethertype_host)
{
    struct ethhdr eth;

    memset(&eth, 0, sizeof(eth));
    eth.h_proto = bpf_htons(ethertype_host);
    return pb_raw(&eth, sizeof(eth));
}

__u32 pb_ipv4(__u8 proto, __u8 ihl, __u16 frag_off_host, __be32 saddr, __be32 daddr)
{
    struct iphdr iph;
    __u32 opt_bytes;

    memset(&iph, 0, sizeof(iph));
    iph.version = 4;
    iph.ihl = ihl;
    iph.protocol = proto;
    iph.frag_off = bpf_htons(frag_off_host);
    iph.saddr = saddr;
    iph.daddr = daddr;

    pb_raw(&iph, sizeof(iph));

    opt_bytes = (ihl > 5) ? ((__u32)ihl - 5U) * 4U : 0U;
    if(opt_bytes > 0) {
        pb_pad(opt_bytes);
    }

    return pb_len;
}

__u32 pb_ipv6(__u8 nexthdr, const unsigned char src[16], const unsigned char dst[16])
{
    struct ipv6hdr ip6;

    memset(&ip6, 0, sizeof(ip6));
    ip6.version = 6;
    ip6.nexthdr = nexthdr;
    ip6.hop_limit = 64;
    memcpy(&ip6.saddr, src, 16);
    memcpy(&ip6.daddr, dst, 16);

    return pb_raw(&ip6, sizeof(ip6));
}

__u32 pb_ext6(__u8 nexthdr, __u8 hdrlen)
{
    struct ipv6_opt_hdr eh;
    __u32 total = ((__u32)hdrlen + 1U) * 8U;

    memset(&eh, 0, sizeof(eh));
    eh.nexthdr = nexthdr;
    eh.hdrlen = hdrlen;

    pb_raw(&eh, sizeof(eh));
    pb_pad(total - (__u32)sizeof(eh));

    return pb_len;
}

__u32 pb_frag6(__u8 nexthdr, __u16 frag_off_host)
{
    struct marlin_frag_hdr fh;

    memset(&fh, 0, sizeof(fh));
    fh.nexthdr = nexthdr;
    fh.frag_off = bpf_htons(frag_off_host);

    return pb_raw(&fh, sizeof(fh));
}

__u32 pb_ports(__u16 sport_host, __u16 dport_host)
{
    struct marlin_l4_ports ports;

    ports.sport = bpf_htons(sport_host);
    ports.dport = bpf_htons(dport_host);

    return pb_raw(&ports, sizeof(ports));
}

/*
 * Full 8-byte UDP header -- source and dest overlay marlin_l4_ports exactly
 * as pb_ports() writes them. len_host is marlin_parse_quic()'s declared-
 * payload bound (docs/design/30-quic.md); check is filled in so a captured
 * packet's fixed header matches the wire but is never read by parser.c.
 */
__u32 pb_udp(__u16 sport_host, __u16 dport_host, __u16 len_host)
{
    struct {
        __be16 source;
        __be16 dest;
        __be16 len;
        __be16 check;
    } udp;

    udp.source = bpf_htons(sport_host);
    udp.dest = bpf_htons(dport_host);
    udp.len = bpf_htons(len_host);
    udp.check = 0;

    return pb_raw(&udp, sizeof(udp));
}

__u32 pb_quic_form(__u8 first_byte)
{
    return pb_raw(&first_byte, sizeof(first_byte));
}

__u32 pb_quic_cid(__u8 first_byte, const __u8 *cid, __u32 cid_len)
{
    pb_raw(&first_byte, sizeof(first_byte));
    return pb_raw(cid, cid_len);
}

__u32 pb_icmp(__u8 type, __u8 code)
{
    struct marlin_icmphdr icmp;

    memset(&icmp, 0, sizeof(icmp));
    icmp.type = type;
    icmp.code = code;

    return pb_raw(&icmp, sizeof(icmp));
}

__u32 pb_truncate(__u32 n)
{
    pb_len = n;
    return pb_len;
}

void pb_xdp(struct xdp_md *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->data = (__u32)(unsigned long)pb_arena;
    ctx->data_end = (__u32)((unsigned long)pb_arena + pb_len);
}
