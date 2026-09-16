/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Where the ACL verdict is enforced relative to VIP admission
 * (docs/design/27-source-filtering.md): one blocked source has three
 * different outcomes depending on what it was addressed to. Reuses
 * seed_acl_cfg/udp_vip_seed/udp_vip_clear from xdp_fixture.h.
 */

#include <string.h>

#include <linux/bpf.h>
#include <linux/in.h>

#include <marlin/marlin.h>

#include "../harness.h"
#include "../packet.h"
#include "maps.h"
#include "prog.h"
#include "xdp_fixture.h"

/*
 * Where the ACL verdict is applied, not whether it is computed: the verdict is
 * taken before the VIP lookup and enforced after it, so one blocked source has
 * three outcomes depending on what it was addressed to
 * (docs/design/27-source-filtering.md).
 */
static void acl_placement_setup(__be32 blocked)
{
    xdp_vip_clear();
    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_block_v4", 32, blocked, 1);
    seed_acl_cfg(CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));
}

static void acl_placement_teardown(void)
{
    struct marlin_config cfg;

    udp_vip_clear();
    xdp_acl_clear("acl_block_v4");

    memset(&cfg, 0, sizeof(cfg));
    xdp_seed_config(&cfg);
}

MARLIN_TEST(blocked_source_to_non_vip_dest_is_dropped)
{
    __u64 before;
    struct xdp_run_result result;

    acl_placement_setup(ACL_ADDR4(10, 60, 60, 1));
    before = xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED);

    build_udp4(ACL_ADDR4(10, 60, 60, 1), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED));

    acl_placement_teardown();
}

MARLIN_TEST(blocked_source_to_vip_without_acl_flag_is_forwarded)
{
    __u64 before;
    struct xdp_run_result result;

    acl_placement_setup(ACL_ADDR4(10, 60, 60, 2));
    udp_vip_seed(0); /* the VIP opts out of the block list */
    before = xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED);

    build_udp4(ACL_ADDR4(10, 60, 60, 2), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    CHECK_EQ(before, xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED));

    acl_placement_teardown();
}

MARLIN_TEST(blocked_source_to_vip_with_acl_flag_is_dropped)
{
    __u64 before;
    struct xdp_run_result result;

    acl_placement_setup(ACL_ADDR4(10, 60, 60, 3));
    udp_vip_seed(VIP_ACL);
    before = xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED);

    build_udp4(ACL_ADDR4(10, 60, 60, 3), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED));

    acl_placement_teardown();
}
