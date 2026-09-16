/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * balancer.c — Marlin packet pipeline: ACL check, VIP lookup, metering,
 * backend selection by hash or QUIC connection ID, encapsulation and frame
 * validation.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>

#include <bpf/bpf_helpers.h>

#include <marlin/marlin.h>
#include <marlin/balancer.h>
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

_Static_assert(sizeof(((struct packet_tuple *)0)->src) % 8 == 0, "packet_tuple.src length must be a multiple of 8");
_Static_assert(sizeof(struct packet_tuple) % 8 == 0, "packet_tuple length must be a multiple of 8: VIP_HASH_5TUPLE hashes it whole");
_Static_assert(sizeof(struct marlin_quic_input) % 8 == 0,
               "marlin_quic_input length must be a multiple of 8: marlin_siphash() hashes it whole");
_Static_assert(MARLIN_QUIC_CID_MAX - MARLIN_QUIC_CID_ENTROPY_OFF == sizeof(((struct marlin_quic_input *)0)->entropy),
               "the entropy buffer must hold a maximum-length connection ID's entropy exactly");
_Static_assert(MARLIN_QUIC_CID_MIN - MARLIN_QUIC_CID_ENTROPY_OFF >= MARLIN_QUIC_CID_ENTROPY_MIN,
               "a minimum-length connection ID must still carry its entropy bytes");
_Static_assert((MARLIN_QUIC_CID_GEN_MASK & MARLIN_QUIC_CID_CHECK_MASK) == 0,
               "the generation and check fields overlap in the format byte");

static __always_inline void marlin_balancer_vip_key(const struct marlin_ctx *mctx, struct vip_key *vkey)
{
    __builtin_memset(vkey, 0, sizeof(*vkey));

    vkey->family = mctx->tuple.family;
    vkey->proto = mctx->tuple.proto;
    vkey->port = mctx->tuple.dport;

    if(vkey->family == AF_INET) {
        vkey->addr4 = mctx->tuple.dst[0];
    } else {
        __builtin_memcpy(vkey->addr6, mctx->tuple.dst, sizeof(vkey->addr6));
    }
}

static __always_inline int marlin_balancer_filter(const struct marlin_ctx *mctx, __u32 vip_flags)
{
    if(!(mctx->cfg.flags & CFG_RL_ENABLE)) {
        return MARLIN_OK;
    }

    if(!(vip_flags & VIP_RATELIMIT)) {
        return MARLIN_OK;
    }

    if(mctx->acl_verdict == MARLIN_ACL_ALLOW) {
        return MARLIN_OK;
    }

    return marlin_ratelimit(mctx);
}

static __always_inline int marlin_balancer_encap_packet(struct xdp_md *ctx, struct marlin_ctx *mctx)
{
    switch(ENCAP_MODE(mctx->backend.flags)) {
    case MARLIN_MODE_IPIP:
        return marlin_ipip_encap_packet(ctx, mctx);

    case MARLIN_MODE_GUE:
        return marlin_gue_encap_packet(ctx, mctx);

    case MARLIN_MODE_VXLAN:
        return marlin_vxlan_encap_packet(ctx, mctx);

    default:
        return MARLIN_DROP_MAP_BOUNDS;
    }
}

static __always_inline int marlin_balancer_validate(const struct marlin_ctx *mctx, __u32 frame_len)
{
    if(mctx->pkt_len < ETH_HLEN) {
        return MARLIN_DROP_ENCAP_LENGTH;
    }

    if(frame_len != (__u32)mctx->pkt_len) {
        return MARLIN_DROP_ENCAP_LENGTH;
    }

    return MARLIN_OK;
}

static __always_inline int marlin_balancer_acl_enforce(const struct marlin_ctx *mctx, const struct vip_meta *vip)
{
    if(mctx->acl_verdict != MARLIN_ACL_BLOCK) {
        return MARLIN_OK;
    }

    if(vip != NULL && !(vip->flags & VIP_ACL)) {
        return MARLIN_OK;
    }

    return MARLIN_DROP_ACL_BLOCKED;
}

/*
 * Retrieve the VIP corresponding to the current packet. To save stack space, a live pointer is used.
 */
static __always_inline const struct vip_meta *marlin_balancer_vip(const struct marlin_ctx *mctx)
{
    const struct vip_meta *meta;
    struct vip_key vkey;

    marlin_balancer_vip_key(mctx, &vkey);
    meta = bpf_map_lookup_elem(&vip_map, &vkey);

    if(meta) {
        return meta;
    }

    /* Port-agnostic VIP: retry with port 0. */
    vkey.port = 0;

    return bpf_map_lookup_elem(&vip_map, &vkey);
}

static __always_inline int marlin_balancer_admit(const struct marlin_ctx *mctx, const struct vip_meta *vip)
{
    int ret;

    if(vip == NULL) {
        ret = marlin_balancer_acl_enforce(mctx, NULL);

        return ret != MARLIN_OK ? ret : MARLIN_PASS_VIP_MISS;
    }

    if(vip->vip_num >= MAX_VIPS) {
        return MARLIN_DROP_MAP_BOUNDS;
    }

    marlin_stats_vip(vip->vip_num, mctx->pkt_len);
    ret = marlin_balancer_acl_enforce(mctx, vip);

    if(ret != MARLIN_OK) {
        return ret;
    }

    return marlin_balancer_filter(mctx, vip->flags);
}

static __always_inline int marlin_balancer_frag(const struct marlin_ctx *mctx, const struct vip_meta *vip)
{
    if(!(vip->flags & VIP_HASH_5TUPLE)) {
        return MARLIN_OK;
    }

    if(!(mctx->flags & MARLIN_CTX_F_FRAG_ANY)) {
        return MARLIN_OK;
    }

    return MARLIN_DROP_FRAG_UNSUPPORTED;
}

static __always_inline __u32 marlin_balancer_quic_decode(struct xdp_md *ctx, const struct marlin_ctx *mctx, const struct vip_meta *vip)
{
    struct marlin_quic_input in;
    __u32 cid_len, ent_len, off, id;
    __u8 hdr[MARLIN_QUIC_CID_ENTROPY_OFF];
    __u64 mask;

    if(mctx->flags & MARLIN_CTX_F_FRAG_ANY) {
        return 0;
    }

    cid_len = VIP_QUIC_CID_LEN(vip->flags);

    if(cid_len < MARLIN_QUIC_CID_MIN || cid_len > MARLIN_QUIC_CID_MAX) {
        return 0;
    }

    ent_len = cid_len - MARLIN_QUIC_CID_ENTROPY_OFF;
    off = (__u32)mctx->l4_off + MARLIN_UDP_HLEN + 1;

    if(bpf_xdp_load_bytes(ctx, off, hdr, sizeof(hdr)) < 0) {
        return 0;
    }

    if(hdr[0] & MARLIN_QUIC_CID_GEN_MASK) {
        marlin_stats_reason(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
        return 0;
    }

    __builtin_memset(&in, 0, sizeof(in));
    in.domain = MARLIN_QUIC_SIPHASH_DOMAIN;

    if(bpf_xdp_load_bytes(ctx, off + MARLIN_QUIC_CID_ENTROPY_OFF, in.entropy, ent_len) < 0) {
        return 0;
    }

    mask = marlin_siphash(&in, sizeof(in), vip->hash_key);

    if((hdr[0] & MARLIN_QUIC_CID_CHECK_MASK) != (__u8)((mask >> 16) & MARLIN_QUIC_CID_CHECK_MASK)) {
        marlin_stats_reason(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
        return 0;
    }

    id = (((__u32)hdr[1] << 8) | (__u32)hdr[2]) ^ (__u32)(mask & 0xffff);

    if(id >= MAX_BACKENDS) {
        return 0;
    }

    return id;
}

static __always_inline const struct backend *marlin_balancer_select_backend_by_hash(const struct marlin_ctx *mctx,
                                                                                    const struct vip_meta *vip)
{
    __u32 vip_num, fwd_key, id;
    const __u32 *slot;
    __u64 hash;

    vip_num = vip->vip_num;

    if(vip_num >= MAX_VIPS) {
        return NULL;
    }

    if(likely(vip->flags & VIP_HASH_5TUPLE)) {
        hash = marlin_siphash(&mctx->tuple, sizeof(mctx->tuple), vip->hash_key);
    } else {
        hash = marlin_siphash(mctx->tuple.src, sizeof(mctx->tuple.src), vip->hash_key);
    }

    fwd_key = vip_num * TABLE_SIZE + (__u32)(hash & (TABLE_SIZE - 1));
    slot = bpf_map_lookup_elem(&fwd_table, &fwd_key);

    if(!slot) {
        return NULL;
    }

    id = *slot;

    if(id == 0 || id >= MAX_BACKENDS) {
        return NULL;
    }

    return bpf_map_lookup_elem(&backends, &id);
}

static __always_inline const struct backend *marlin_balancer_select_backend_quic(struct xdp_md *ctx, const struct marlin_ctx *mctx,
                                                                                 const struct vip_meta *vip)
{
    const struct backend *target;
    __u32 id;

    id = marlin_balancer_quic_decode(ctx, mctx, vip);

    if(id == 0) {
        return NULL;
    }

    target = bpf_map_lookup_elem(&backends, &id);

    if(target == NULL || !(target->flags & MARLIN_BE_F_STATE)) {
        return NULL;
    }

    marlin_stats_reason(MARLIN_COUNT_QUIC_CID_ROUTED);
    return target;
}

static __always_inline int marlin_balancer_load_backend(struct marlin_ctx *mctx, const struct backend *backend)
{
    if(backend == NULL) {
        return MARLIN_DROP_NO_BACKEND;
    }

    __builtin_memcpy(&mctx->backend, backend, sizeof(struct backend));
    marlin_stats_backend(mctx->backend.id, mctx->pkt_len);

    if(!(mctx->backend.flags & MARLIN_BE_F_STATE)) {
        return MARLIN_DROP_BACKEND_DOWN;
    }

    return MARLIN_OK;
}

static __always_inline const struct backend *marlin_balancer_select_backend(struct xdp_md *ctx, const struct marlin_ctx *mctx,
                                                                            const struct vip_meta *vip)
{
    const struct backend *target;

    if((vip->flags & VIP_QUIC) && (mctx->flags & MARLIN_CTX_F_QUIC)) {
        target = marlin_balancer_select_backend_quic(ctx, mctx, vip);

        if(target != NULL) {
            return target;
        }
    }

    return marlin_balancer_select_backend_by_hash(mctx, vip);
}

static __always_inline int marlin_balancer_process_packet(struct xdp_md *ctx, struct marlin_ctx *mctx, const struct vip_meta *vip)
{
    const struct backend *target;
    __u32 frame_len;
    int rc;

    rc = marlin_balancer_frag(mctx, vip);

    if(unlikely(rc != MARLIN_OK)) {
        return rc;
    }

    target = marlin_balancer_select_backend(ctx, mctx, vip);
    rc = marlin_balancer_load_backend(mctx, target);

    if(unlikely(rc != MARLIN_OK)) {
        return rc;
    }

    frame_len = (__u32)bpf_xdp_get_buff_len(ctx);
    rc = marlin_balancer_validate(mctx, frame_len);

    if(unlikely(rc != MARLIN_OK)) {
        return rc;
    }

    if(ENCAP_MODE(mctx->backend.flags) != MARLIN_MODE_L2DSR) {
        rc = marlin_balancer_encap_packet(ctx, mctx);

        if(unlikely(rc != MARLIN_OK)) {
            return rc;
        }

        rc = marlin_nexthop_encapsulate(ctx, mctx);
    } else {
        rc = marlin_nexthop_l2dsr(ctx, mctx);
    }

    return rc;
}

/*
 * Balancer entry point — the only global subprogram of this unit. Requires a parsed
 * mctx carrying a config snapshot (see file header).
 */
int marlin_balancer_process(struct xdp_md *ctx, struct marlin_ctx *mctx)
{
    const struct vip_meta *vip;
    int rc;

    if(unlikely(ctx == NULL || mctx == NULL)) {
        return MARLIN_ABORT_NULLREF;
    }

    mctx->acl_verdict = (__u8)marlin_acl_check(mctx);

    vip = marlin_balancer_vip(mctx);
    rc = marlin_balancer_admit(mctx, vip);

    if(unlikely(rc != MARLIN_OK)) {
        return rc;
    }

    return marlin_balancer_process_packet(ctx, mctx, vip);
}
