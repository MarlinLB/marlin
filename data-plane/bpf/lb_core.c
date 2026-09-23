/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * lb_core.c — load-balancing core: admission control, VIP resolution, per-VIP
 * accounting, backend selection (5-tuple hash or QUIC connection ID),
 * encapsulation dispatch and post-encap frame checks.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>

#include <bpf/bpf_helpers.h>

#include <marlin/marlin.h>
#include <marlin/lb_core.h>
#include <marlin/maps.h>
#include <marlin/siphash.h>
#include <marlin/ratelimit.h>
#include <marlin/stats.h>
#include <marlin/acl.h>
#include <marlin/proto.h>
#include <marlin/encap.h>
#include <marlin/nexthop.h>
#include <marlin/compiler.h>

#include <marlin/abi/types.h>

_Static_assert(sizeof(((struct packet_tuple *)0)->src) % 8 == 0, "packet_tuple.src must be 8-byte sized for marlin_siphash()");
_Static_assert(sizeof(struct packet_tuple) % 8 == 0, "packet_tuple must be 8-byte sized: VIP_HASH_5TUPLE feeds in the whole struct");
_Static_assert(sizeof(struct marlin_quic_input) % 8 == 0,
               "marlin_quic_input must be 8-byte sized: marlin_siphash() consumes it whole");
_Static_assert(sizeof(struct marlin_ports_input) % 8 == 0,
               "marlin_ports_input must be 8-byte sized: marlin_siphash() consumes it whole");
_Static_assert(MARLIN_QUIC_CID_MAX - MARLIN_QUIC_CID_ENTROPY_OFF == sizeof(((struct marlin_quic_input *)0)->entropy),
               "entropy[] must exactly fit the entropy bytes of a longest-permitted connection ID");
_Static_assert(MARLIN_QUIC_CID_MIN - MARLIN_QUIC_CID_ENTROPY_OFF >= MARLIN_QUIC_CID_ENTROPY_MIN,
               "a shortest-permitted connection ID must still carry its entropy bytes");
_Static_assert((MARLIN_QUIC_CID_GEN_MASK & MARLIN_QUIC_CID_CHECK_MASK) == 0,
               "format byte: the generation and check fields must not overlap");

static __always_inline void marlin_lb_vip_key(const struct marlin_ctx *pkt, struct vip_key *key)
{
    __builtin_memset(key, 0, sizeof(*key));

    key->family = pkt->tuple.family;
    key->proto = pkt->tuple.proto;
    key->port = pkt->tuple.dport;

    if(key->family == AF_INET) {
        key->addr4 = pkt->tuple.dst[0];
    } else {
        __builtin_memcpy(key->addr6, pkt->tuple.dst, sizeof(key->addr6));
    }
}

static __always_inline int marlin_lb_filter(const struct marlin_ctx *pkt, __u32 vflags)
{
    if(!(pkt->cfg.flags & CFG_RL_ENABLE)) {
        return MARLIN_OK;
    }

    if(!(vflags & VIP_RATELIMIT)) {
        return MARLIN_OK;
    }

    if(pkt->acl_verdict == MARLIN_ACL_ALLOW) {
        return MARLIN_OK;
    }

    return marlin_ratelimit(pkt);
}

static __always_inline int marlin_lb_encap_packet(struct xdp_md *xdp, struct marlin_ctx *pkt)
{
    switch(ENCAP_MODE(pkt->backend.flags)) {
    case MARLIN_MODE_IPIP:
        return marlin_ipip_encap_packet(xdp, pkt);

    case MARLIN_MODE_GUE:
        return marlin_gue_encap_packet(xdp, pkt);

    case MARLIN_MODE_VXLAN:
        return marlin_vxlan_encap_packet(xdp, pkt);

    default:
        return MARLIN_DROP_MAP_BOUNDS;
    }
}

static __always_inline int marlin_lb_validate(const struct marlin_ctx *pkt, __u32 length)
{
    if(pkt->pkt_len < ETH_HLEN) {
        return MARLIN_DROP_ENCAP_LENGTH;
    }

    if(length != (__u32)pkt->pkt_len) {
        return MARLIN_DROP_ENCAP_LENGTH;
    }

    return MARLIN_OK;
}

static __always_inline int marlin_lb_acl_enforce(const struct marlin_ctx *pkt, const struct vip_meta *vmeta)
{
    if(pkt->acl_verdict != MARLIN_ACL_BLOCK) {
        return MARLIN_OK;
    }

    if(vmeta != NULL && !(vmeta->flags & VIP_ACL)) {
        return MARLIN_OK;
    }

    return MARLIN_DROP_ACL_BLOCKED;
}

static __always_inline const struct vip_meta *marlin_lb_select_vip(const struct marlin_ctx *pkt)
{
    const struct vip_meta *hit;
    struct vip_key key;

    marlin_lb_vip_key(pkt, &key);
    hit = bpf_map_lookup_elem(&vip_map, &key);

    if(hit) {
        return hit;
    }

    key.port = 0;

    return bpf_map_lookup_elem(&vip_map, &key);
}

static __always_inline int marlin_lb_admit(const struct marlin_ctx *pkt, const struct vip_meta *vmeta)
{
    int ret;

    if(vmeta == NULL) {
        ret = marlin_lb_acl_enforce(pkt, NULL);

        return ret != MARLIN_OK ? ret : MARLIN_PASS_VIP_MISS;
    }

    if(vmeta->vip_num >= MAX_VIPS) {
        return MARLIN_DROP_MAP_BOUNDS;
    }

    marlin_stats_vip(vmeta->vip_num, pkt->pkt_len);
    ret = marlin_lb_acl_enforce(pkt, vmeta);

    if(ret != MARLIN_OK) {
        return ret;
    }

    return marlin_lb_filter(pkt, vmeta->flags);
}

static __always_inline int marlin_lb_check_frag(const struct marlin_ctx *pkt, const struct vip_meta *vmeta)
{
    if(!(vmeta->flags & (VIP_HASH_5TUPLE | VIP_HASH_PORTS))) {
        return MARLIN_OK;
    }

    if(!(pkt->flags & MARLIN_CTX_F_FRAG_ANY)) {
        return MARLIN_OK;
    }

    return MARLIN_DROP_FRAG_UNSUPPORTED;
}

static __always_inline __u32 marlin_lb_quic_decode(struct xdp_md *xdp, const struct marlin_ctx *pkt, const struct vip_meta *vmeta)
{
    struct marlin_quic_input quic_in;
    __u32 clen, elen, pos, id;
    __u8 header[MARLIN_QUIC_CID_ENTROPY_OFF];
    __u64 mix;

    if(pkt->flags & MARLIN_CTX_F_FRAG_ANY) {
        return MARLIN_NO_BACKEND;
    }

    clen = VIP_QUIC_CID_LEN(vmeta->flags);

    if(clen < MARLIN_QUIC_CID_MIN || clen > MARLIN_QUIC_CID_MAX) {
        return MARLIN_NO_BACKEND;
    }

    if(pkt->udp_payload_len < 1 + clen) {
        return MARLIN_NO_BACKEND;
    }

    elen = clen - MARLIN_QUIC_CID_ENTROPY_OFF;
    pos = (__u32)pkt->l4_off + MARLIN_UDP_HLEN + 1;

    if(bpf_xdp_load_bytes(xdp, pos, header, sizeof(header)) < 0) {
        return MARLIN_NO_BACKEND;
    }

    if(header[0] & MARLIN_QUIC_CID_GEN_MASK) {
        marlin_stats_reason(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
        return MARLIN_NO_BACKEND;
    }

    __builtin_memset(&quic_in, 0, sizeof(quic_in));
    quic_in.domain = MARLIN_QUIC_SIPHASH_DOMAIN;

    if(bpf_xdp_load_bytes(xdp, pos + MARLIN_QUIC_CID_ENTROPY_OFF, quic_in.entropy, elen) < 0) {
        return MARLIN_NO_BACKEND;
    }

    mix = marlin_siphash(&quic_in, sizeof(quic_in), vmeta->hash_key);

    if((header[0] & MARLIN_QUIC_CID_CHECK_MASK) != (__u8)((mix >> 16) & MARLIN_QUIC_CID_CHECK_MASK)) {
        marlin_stats_reason(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);

        return MARLIN_NO_BACKEND;
    }

    id = (((__u32)header[1] << 8) | (__u32)header[2]) ^ (__u32)(mix & 0xffff);

    if(id >= MAX_BACKENDS) {
        return MARLIN_NO_BACKEND;
    }

    return id;
}

static __always_inline const struct backend *marlin_lb_select_backend_by_hash(const struct marlin_ctx *pkt,
                                                                              const struct vip_meta *vmeta)
{
    __u32 fkey, bid;
    const __u32 *cell;
    __u64 mix;

    if(vmeta->vip_num >= MAX_VIPS) {
        return NULL;
    }

    if(likely(vmeta->flags & VIP_HASH_5TUPLE)) {
        mix = marlin_siphash(&pkt->tuple, sizeof(pkt->tuple), vmeta->hash_key);
    } else if(vmeta->flags & VIP_HASH_PORTS) {
        struct marlin_ports_input ports_in;

        __builtin_memset(&ports_in, 0, sizeof(ports_in));
        ports_in.sport = pkt->tuple.sport;
        ports_in.dport = pkt->tuple.dport;

        mix = marlin_siphash(&ports_in, sizeof(ports_in), vmeta->hash_key);
    } else {
        mix = marlin_siphash(pkt->tuple.src, sizeof(pkt->tuple.src), vmeta->hash_key);
    }

    fkey = vmeta->vip_num * TABLE_SIZE + (__u32)(mix & (TABLE_SIZE - 1));
    cell = bpf_map_lookup_elem(&fwd_table, &fkey);

    if(cell == NULL) {
        return NULL;
    }

    bid = *cell;

    if(bid == MARLIN_NO_BACKEND || bid >= MAX_BACKENDS) {
        return NULL;
    }

    return bpf_map_lookup_elem(&backends, &bid);
}

static __always_inline const struct backend *marlin_lb_select_backend_quic(struct xdp_md *xdp, const struct marlin_ctx *pkt,
                                                                           const struct vip_meta *vmeta)
{
    const struct backend *be;
    __u32 bid;

    bid = marlin_lb_quic_decode(xdp, pkt, vmeta);

    if(bid == MARLIN_NO_BACKEND) {
        return NULL;
    }

    be = bpf_map_lookup_elem(&backends, &bid);

    if(be == NULL || !(be->flags & MARLIN_BE_F_STATE)) {
        return NULL;
    }

    marlin_stats_reason(MARLIN_COUNT_QUIC_CID_ROUTED);

    return be;
}

static __always_inline int marlin_lb_load_backend(struct marlin_ctx *pkt, const struct backend *target)
{
    if(target == NULL) {
        return MARLIN_DROP_NO_BACKEND;
    }

    __builtin_memcpy(&pkt->backend, target, sizeof(struct backend));
    marlin_stats_backend(pkt->backend.id, pkt->pkt_len);

    if(!(pkt->backend.flags & MARLIN_BE_F_STATE)) {
        return MARLIN_DROP_BACKEND_DOWN;
    }

    return MARLIN_OK;
}

static __always_inline const struct backend *marlin_lb_select_backend(struct xdp_md *md, struct marlin_ctx *pkt,
                                                                      const struct vip_meta *vip)
{
    const struct backend *be;

    if((vip->flags & VIP_QUIC) && (pkt->flags & MARLIN_CTX_F_QUIC)) {
        be = marlin_lb_select_backend_quic(md, pkt, vip);

        if(be != NULL) {
            return be;
        }
    }

    return marlin_lb_select_backend_by_hash(pkt, vip);
}

static __always_inline int marlin_lb_process_packet(struct xdp_md *md, struct marlin_ctx *pkt, const struct vip_meta *vip)
{
    const struct backend *target;
    __u32 frame_len;
    int rc;

    rc = marlin_lb_check_frag(pkt, vip);

    if(unlikely(rc != MARLIN_OK)) {
        return rc;
    }

    target = marlin_lb_select_backend(md, pkt, vip);
    rc = marlin_lb_load_backend(pkt, target);

    if(unlikely(rc != MARLIN_OK)) {
        return rc;
    }

    frame_len = (__u32)bpf_xdp_get_buff_len(md);
    rc = marlin_lb_validate(pkt, frame_len);

    if(unlikely(rc != MARLIN_OK)) {
        return rc;
    }

    if(ENCAP_MODE(pkt->backend.flags) != MARLIN_MODE_L2DSR) {
        pkt->flags |= vip->flags & VIP_DSCP_MASK;
        rc = marlin_lb_encap_packet(md, pkt);

        if(unlikely(rc != MARLIN_OK)) {
            return rc;
        }

        rc = marlin_nexthop_encapsulate(md, pkt);
    } else {
        rc = marlin_nexthop_l2dsr(md, pkt);
    }

    return rc;
}

int marlin_lb_process(struct xdp_md *md, struct marlin_ctx *pkt)
{
    const struct vip_meta *vmeta;
    int rc;

    if(unlikely(md == NULL || pkt == NULL)) {
        return MARLIN_ABORT_NULLREF;
    }

    pkt->acl_verdict = (__u8)marlin_acl_check(pkt);

    vmeta = marlin_lb_select_vip(pkt);
    rc = marlin_lb_admit(pkt, vmeta);

    if(unlikely(rc != MARLIN_OK)) {
        return rc;
    }

    return marlin_lb_process_packet(md, pkt, vmeta);
}
