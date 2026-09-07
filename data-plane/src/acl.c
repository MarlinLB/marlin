/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * ACL implementation. The implementation split on the IP address
 * family (v4/v6).
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <marlin/marlin.h>
#include <marlin/abi/defines.h>
#include <marlin/acl.h>
#include <marlin/maps.h>

_Static_assert(sizeof(((struct acl_key6 *)0)->addr) == sizeof(((struct packet_tuple *)0)->src),
               "acl_key6.addr must be exactly packet_tuple.src wide");

static __always_inline int acl_check_v4(const struct marlin_ctx *mctx)
{
    struct acl_key4 key;

    key.prefixlen = (__u32)(sizeof(key.addr) * 8);
    key.addr = mctx->tuple.src[0];

    if((mctx->cfg.acl_lists & ACL_LISTS_BIT(ACL_LIST_ALLOW, ACL_FAMILY_V4)) != 0U &&
       bpf_map_lookup_elem(&acl_allow_v4, &key) != NULL) {
        return MARLIN_ACL_ALLOW;
    }

    if((mctx->cfg.acl_lists & ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4)) != 0U &&
       bpf_map_lookup_elem(&acl_block_v4, &key) != NULL) {
        return MARLIN_ACL_BLOCK;
    }

    return MARLIN_ACL_NONE;
}

static __always_inline int acl_check_v6(const struct marlin_ctx *mctx)
{
    struct acl_key6 key;

    /* See acl_check_v4(): full width, not the rule's own prefix length. */
    key.prefixlen = (__u32)(sizeof(key.addr) * 8);
    __builtin_memcpy(key.addr, mctx->tuple.src, sizeof(key.addr));

    if((mctx->cfg.acl_lists & ACL_LISTS_BIT(ACL_LIST_ALLOW, ACL_FAMILY_V6)) != 0U &&
       bpf_map_lookup_elem(&acl_allow_v6, &key) != NULL) {
        return MARLIN_ACL_ALLOW;
    }

    if((mctx->cfg.acl_lists & ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V6)) != 0U &&
       bpf_map_lookup_elem(&acl_block_v6, &key) != NULL) {
        return MARLIN_ACL_BLOCK;
    }

    return MARLIN_ACL_NONE;
}

int marlin_acl_check(const struct marlin_ctx *mctx)
{
    if((mctx->cfg.flags & CFG_ACL_ENABLE) == 0U) {
        return MARLIN_ACL_NONE;
    }

    switch(mctx->tuple.family) {
    case AF_INET:
        return acl_check_v4(mctx);

    case AF_INET6:
        return acl_check_v6(mctx);

    default:
        return MARLIN_ACL_NONE;
    }
}
