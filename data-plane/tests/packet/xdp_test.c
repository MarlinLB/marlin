#define _GNU_SOURCE

#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <linux/bpf.h>
#include <linux/udp.h>

#include <marlin/abi/types.h>
#include <marlin/marlin.h>
#include <marlin/proto.h>

#include "../harness.h"
#include "../packet.h"
#include "fib.h"
#include "maps.h"
#include "prog.h"

#define V4_SRC 0x0a0a0a0aU /* 10.10.10.10 */
#define V4_DST 0x0b0b0b0bU /* 11.11.11.11 */

static const unsigned char SRC6[16] = {0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
                                       0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80};
static const unsigned char DST6[16] = {0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
                                       0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90};

static unsigned char out_buf[XDP_TEST_RUN_MAX_SIZE];

static struct xdp_run_result run_current_packet(void)
{
    return xdp_run(pb_arena, pb_len, out_buf, sizeof(out_buf), 0);
}

static struct xdp_run_result run_packet_on(__u32 ingress_ifindex)
{
    return xdp_run(pb_arena, pb_len, out_buf, sizeof(out_buf), ingress_ifindex);
}

#define NH_INGRESS_IFINDEX 1U

#define NH_BACKEND_ADDR 0x0c0c0c0cU /* 12.12.12.12 */

static const unsigned char NH_MARLIN_MAC[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
static const unsigned char NH_ROUTER_MAC[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
static const unsigned char NH_BACKEND_MAC[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x03};

static const unsigned char NH_DECOY_MAC[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0b};

static const unsigned char VXLAN_INNER_MAC[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x04};

static const unsigned char ALT_BACKEND_MAC[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x05};

/* ---- VIP and backend fixture ------------------------------------------ */

/*
 * balancer.c refuses a forwarding-table slot of 0, so no fixture backend may
 * live at index 0 of the backends array.
 */
#define NH_BACKEND_ID  1U
#define ALT_BACKEND_ID 2U

#define NH_VIP_NUM  0U
#define UDP_VIP_NUM 1U
#define ALT_VIP_NUM 2U

/*
 * Every fixture VIP shares one hash key. Its value is arbitrary to the
 * forwarding cases, which fill a VIP's whole block so the row SipHash picks
 * cannot matter, but the QUIC cases forge a connection ID against it and so
 * need it to be a value userspace knows.
 */
#define VIP_FIXTURE_HASH_KEY_BYTE 0x5aU

static void vip_key4(struct vip_key *key, __be32 addr, __u16 port_host, __u8 proto)
{
    memset(key, 0, sizeof(*key));
    key->addr4 = addr;
    key->port = bpf_htons(port_host);
    key->proto = proto;
    key->family = AF_INET;
}

static void vip_key6(struct vip_key *key, const unsigned char addr16[16], __u16 port_host, __u8 proto)
{
    memset(key, 0, sizeof(*key));
    memcpy(key->addr6, addr16, sizeof(key->addr6));
    key->port = bpf_htons(port_host);
    key->proto = proto;
    key->family = AF_INET6;
}

static void vip_meta_init(struct vip_meta *meta, __u32 vip_num, __u32 flags)
{
    memset(meta, 0, sizeof(*meta));
    meta->vip_num = vip_num;
    meta->flags = flags;
    memset(meta->hash_key, VIP_FIXTURE_HASH_KEY_BYTE, sizeof(meta->hash_key));
}

static void vip_seed4(__be32 addr, __u16 port_host, __u8 proto, __u32 vip_num, __u32 flags)
{
    struct vip_key key;
    struct vip_meta meta;

    vip_key4(&key, addr, port_host, proto);
    vip_meta_init(&meta, vip_num, flags);
    xdp_vip_add(&key, &meta);
}

static void vip_seed6(const unsigned char addr16[16], __u16 port_host, __u8 proto, __u32 vip_num, __u32 flags)
{
    struct vip_key key;
    struct vip_meta meta;

    vip_key6(&key, addr16, port_host, proto);
    vip_meta_init(&meta, vip_num, flags);
    xdp_vip_add(&key, &meta);
}

/*
 * L2DSR with a stored MAC and MARLIN_BE_F_FIB clear returns MARLIN_OK_TX
 * straight out of nexthop.c, without a FIB lookup. A case about something
 * upstream of next-hop resolution uses this to observe "was forwarded" as a
 * plain XDP_TX, with no route or neighbour to set up.
 */
static void backend_seed_l2dsr(__u32 id, const unsigned char *mac)
{
    struct backend be;

    memset(&be, 0, sizeof(be));
    be.flags = (__u8)(MARLIN_MODE_L2DSR | MARLIN_BE_F_STATE);
    be.addr = NH_BACKEND_ADDR;
    be.id = (__u16)id;

    if(mac != NULL) {
        memcpy(be.mac, mac, ETH_ALEN);
    }

    xdp_backend_write(id, &be);
}

/*
 * The VIP the build_udp4()/build_udp6() frames land on, with a reachable
 * backend behind it. Cases that would otherwise assert only "not dropped"
 * need it: without a VIP every outcome collapses onto the XDP_PASS of a VIP
 * miss, and an admitted packet becomes indistinguishable from one the step
 * under test never ran for.
 */
static void udp_vip_seed(__u32 flags)
{
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    vip_seed4(V4_DST, 53, IPPROTO_UDP, UDP_VIP_NUM, flags);
    vip_seed6(DST6, 53, IPPROTO_UDP, UDP_VIP_NUM, flags);
    xdp_fwd_fill(UDP_VIP_NUM, NH_BACKEND_ID);
}

static void udp_vip_clear(void)
{
    struct vip_key key;

    vip_key4(&key, V4_DST, 53, IPPROTO_UDP);
    xdp_vip_del(&key);
    vip_key6(&key, DST6, 53, IPPROTO_UDP);
    xdp_vip_del(&key);
    xdp_fwd_clear(UDP_VIP_NUM);
    xdp_backend_clear(NH_BACKEND_ID);
}

MARLIN_TEST(ok_ipv4_tcp_is_pass_and_uncounted)
{
    __u64 before = xdp_drop_stats_total(MARLIN_PASS_NOT_FORWARDED);
    struct xdp_run_result result;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(11111, 80);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
    CHECK_MEM(pb_arena, out_buf, pb_len); /* marlin_parse is read-only */

    CHECK_EQ(before, xdp_drop_stats_total(MARLIN_PASS_NOT_FORWARDED));
}

MARLIN_TEST(ok_ipv6_udp_is_pass)
{
    struct xdp_run_result result;

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_UDP, SRC6, DST6);
    pb_ports(53, 33333);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
}

MARLIN_TEST(not_forwarded_arp_is_pass_and_counted)
{
    __u64 before = xdp_drop_stats_total(MARLIN_PASS_NOT_FORWARDED);
    struct xdp_run_result result;

    pb_reset();
    pb_eth(ETH_P_ARP); /* exactly ETH_HLEN bytes: the XDP_TEST_RUN_MIN_SIZE floor */

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_PASS_NOT_FORWARDED));
}

MARLIN_TEST(not_forwarded_sctp_is_pass_and_counted)
{
    __u64 before = xdp_drop_stats_total(MARLIN_PASS_NOT_FORWARDED);
    struct xdp_run_result result;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_SCTP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_PASS_NOT_FORWARDED));
}

MARLIN_TEST(icmp_echo_request_is_pass_and_counted)
{
    __u64 before = xdp_drop_stats_total(MARLIN_PASS_ICMP_ECHO);
    struct xdp_run_result result;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ICMP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_icmp(ICMP_ECHO, 0);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_PASS_ICMP_ECHO));
}

MARLIN_TEST(unsupported_proto_esp_is_drop_and_counted)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_UNSUPPORTED_PROTO);
    struct xdp_run_result result;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ESP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_UNSUPPORTED_PROTO));
}

MARLIN_TEST(parse_error_truncated_ipv4_is_drop_and_distinct_from_ext_hdr_limit)
{
    __u64 parse_error_before = xdp_drop_stats_total(MARLIN_DROP_PARSE_ERROR);
    __u64 ext_hdr_limit_before = xdp_drop_stats_total(MARLIN_DROP_EXT_HDR_LIMIT);
    struct xdp_run_result result;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_truncate(14 + 10); /* 10 of the IPv4 header's 20 bytes: iph+1 > data_end */

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(parse_error_before + 1, xdp_drop_stats_total(MARLIN_DROP_PARSE_ERROR));
    CHECK_EQ(ext_hdr_limit_before, xdp_drop_stats_total(MARLIN_DROP_EXT_HDR_LIMIT));
}

MARLIN_TEST(parse_error_minimal_frame_no_l3_bytes_is_drop)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_PARSE_ERROR);
    struct xdp_run_result result;

    pb_reset();
    pb_eth(ETH_P_IP); /* data_end right at ETH_HLEN: the min data_size_in itself, zero IPv4 bytes */

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_PARSE_ERROR));
}

MARLIN_TEST(ext_hdr_limit_nine_headers_is_drop_and_distinct_from_parse_error)
{
    __u64 ext_hdr_limit_before = xdp_drop_stats_total(MARLIN_DROP_EXT_HDR_LIMIT);
    __u64 parse_error_before = xdp_drop_stats_total(MARLIN_DROP_PARSE_ERROR);
    struct xdp_run_result result;
    int i;

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_HOPOPTS, SRC6, DST6);
    for(i = 0; i < 9; i++) {
        pb_ext6(IPPROTO_HOPOPTS, 0); /* 9 > MAX_EXT_HDRS(8): see parser_test.c's walk_ext6_nine_headers_is_limit */
    }

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(ext_hdr_limit_before + 1, xdp_drop_stats_total(MARLIN_DROP_EXT_HDR_LIMIT));
    CHECK_EQ(parse_error_before, xdp_drop_stats_total(MARLIN_DROP_PARSE_ERROR));
}

MARLIN_TEST(icmp_unparseable_no_embedded_header_is_drop_and_counted)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_ICMP_UNPARSEABLE);
    struct xdp_run_result result;

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ICMP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_icmp(ICMP_DEST_UNREACH, 0); /* data_end ends here: zero bytes of embedded header */

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_ICMP_UNPARSEABLE));
}

#define ACL_ADDR4(a, b, c, d) bpf_htonl(((__u32)(a) << 24) | ((__u32)(b) << 16) | ((__u32)(c) << 8) | (__u32)(d))

static void seed_acl_cfg(__u32 flags, __u16 acl_lists)
{
    struct marlin_config cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.flags = flags;
    cfg.acl_lists = acl_lists;
    xdp_seed_config(&cfg);
}

static void build_udp4(__be32 src, __be32 dst)
{
    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_UDP, MARLIN_IPV4_IHL_MIN, 0, src, dst);
    pb_ports(11111, 53);
}

static void build_udp6(const unsigned char src[16], const unsigned char dst[16])
{
    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_UDP, src, dst);
    pb_ports(11111, 53);
}

MARLIN_TEST(acl_key_struct_sizes_match_lpm_prefixlen_widths)
{
    CHECK_EQ(8, sizeof(struct acl_key4));
    CHECK_EQ(20, sizeof(struct acl_key6));
}

MARLIN_TEST(acl_v4_block_matched_is_drop_and_counted)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED);
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_block_v4", 32, ACL_ADDR4(10, 20, 20, 20), 1);
    seed_acl_cfg(CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));

    build_udp4(ACL_ADDR4(10, 20, 20, 20), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED));
}

MARLIN_TEST(acl_v4_block_missed_is_pass)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED);
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_block_v4", 32, ACL_ADDR4(10, 20, 20, 20), 1);
    seed_acl_cfg(CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));

    build_udp4(ACL_ADDR4(10, 20, 20, 21), V4_DST); /* one host away from the blocked entry */
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
    CHECK_EQ(before, xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED));
}

MARLIN_TEST(acl_v6_block_matched_is_drop_and_counted)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED);
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v6");
    xdp_acl_clear("acl_block_v6");
    xdp_acl_add6("acl_block_v6", 128, SRC6, 1);
    seed_acl_cfg(CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V6));

    build_udp6(SRC6, DST6);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED));
}

MARLIN_TEST(acl_v6_block_missed_is_pass)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED);
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v6");
    xdp_acl_clear("acl_block_v6");
    xdp_acl_add6("acl_block_v6", 128, SRC6, 1);
    seed_acl_cfg(CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V6));

    build_udp6(DST6, SRC6); /* DST6 as the client address: not the blocked SRC6 entry */
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
    CHECK_EQ(before, xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED));
}

MARLIN_TEST(acl_v4_allow_beats_covering_block_is_pass)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED);
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_allow_v4", 32, ACL_ADDR4(10, 30, 30, 30), 1);
    xdp_acl_add4("acl_block_v4", 32, ACL_ADDR4(10, 30, 30, 30), 2); /* same host, both lists */
    seed_acl_cfg(CFG_ACL_ENABLE, (__u16)(ACL_LISTS_BIT(ACL_LIST_ALLOW, ACL_FAMILY_V4) | ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4)));

    build_udp4(ACL_ADDR4(10, 30, 30, 30), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
    CHECK_EQ(before, xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED));
}

MARLIN_TEST(acl_v6_allow_beats_covering_block_is_pass)
{
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v6");
    xdp_acl_clear("acl_block_v6");
    xdp_acl_add6("acl_allow_v6", 128, SRC6, 1);
    xdp_acl_add6("acl_block_v6", 128, SRC6, 2);
    seed_acl_cfg(CFG_ACL_ENABLE, (__u16)(ACL_LISTS_BIT(ACL_LIST_ALLOW, ACL_FAMILY_V6) | ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V6)));

    build_udp6(SRC6, DST6);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
}

MARLIN_TEST(acl_v4_slash24_block_covers_inside_not_outside)
{
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_block_v4", 24, ACL_ADDR4(10, 40, 50, 0), 1);
    seed_acl_cfg(CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));

    build_udp4(ACL_ADDR4(10, 40, 50, 7), V4_DST); /* inside 10.40.50.0/24 */
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);

    build_udp4(ACL_ADDR4(10, 40, 51, 7), V4_DST); /* outside it: third octet differs */
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
}

MARLIN_TEST(acl_v4_slash32_block_does_not_cover_neighbour)
{
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_block_v4", 32, ACL_ADDR4(10, 60, 60, 6), 1);
    seed_acl_cfg(CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));

    build_udp4(ACL_ADDR4(10, 60, 60, 6), V4_DST); /* the exact blocked host */
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);

    build_udp4(ACL_ADDR4(10, 60, 60, 7), V4_DST); /* its neighbour: last octet differs */
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
}

MARLIN_TEST(acl_v4_nested_block_prefixes_in_one_trie)
{
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_block_v4", 8, ACL_ADDR4(10, 0, 0, 0), 1);
    xdp_acl_add4("acl_block_v4", 24, ACL_ADDR4(10, 130, 40, 0), 2);
    xdp_acl_add4("acl_block_v4", 32, ACL_ADDR4(10, 130, 40, 5), 3);
    seed_acl_cfg(CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));

    build_udp4(ACL_ADDR4(10, 130, 40, 5), V4_DST); /* matches all three entries */
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);

    build_udp4(ACL_ADDR4(10, 130, 40, 9), V4_DST); /* in the /24 and /8, not the /32 */
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);

    build_udp4(ACL_ADDR4(10, 130, 99, 9), V4_DST); /* in the /8 only */
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);

    build_udp4(ACL_ADDR4(11, 130, 40, 5), V4_DST); /* outside the /8: first octet differs */
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
}

MARLIN_TEST(acl_v4_slash8_allow_beats_slash32_block)
{
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_allow_v4", 8, ACL_ADDR4(10, 0, 0, 0), 1);
    xdp_acl_add4("acl_block_v4", 32, ACL_ADDR4(10, 70, 70, 70), 2);
    seed_acl_cfg(CFG_ACL_ENABLE, (__u16)(ACL_LISTS_BIT(ACL_LIST_ALLOW, ACL_FAMILY_V4) | ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4)));

    build_udp4(ACL_ADDR4(10, 70, 70, 70), V4_DST); /* the more specific block entry, exactly */
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
}

MARLIN_TEST(acl_v4_equal_length_allow_beats_block)
{
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_allow_v4", 32, ACL_ADDR4(10, 80, 80, 80), 1);
    xdp_acl_add4("acl_block_v4", 32, ACL_ADDR4(10, 80, 80, 80), 2);
    seed_acl_cfg(CFG_ACL_ENABLE, (__u16)(ACL_LISTS_BIT(ACL_LIST_ALLOW, ACL_FAMILY_V4) | ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4)));

    build_udp4(ACL_ADDR4(10, 80, 80, 80), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
}

MARLIN_TEST(acl_v4_slash32_allow_beats_slash8_block_but_not_its_neighbour)
{
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_block_v4", 8, ACL_ADDR4(10, 0, 0, 0), 1);
    xdp_acl_add4("acl_allow_v4", 32, ACL_ADDR4(10, 90, 90, 90), 2);
    seed_acl_cfg(CFG_ACL_ENABLE, (__u16)(ACL_LISTS_BIT(ACL_LIST_ALLOW, ACL_FAMILY_V4) | ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4)));

    build_udp4(ACL_ADDR4(10, 90, 90, 90), V4_DST); /* the allowed host: escapes the /8 block */
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);

    build_udp4(ACL_ADDR4(10, 90, 90, 91), V4_DST); /* one host over: still just the /8 block */
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
}

MARLIN_TEST(acl_empty_list_bit_clear_skips_a_present_allow_rule)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED);
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_allow_v4", 32, ACL_ADDR4(10, 105, 105, 105), 1);
    xdp_acl_add4("acl_block_v4", 8, ACL_ADDR4(10, 0, 0, 0), 2);                 /* covers the allow entry */
    seed_acl_cfg(CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4)); /* the allow bit claims the list is empty */

    build_udp4(ACL_ADDR4(10, 105, 105, 105), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED));
}

MARLIN_TEST(acl_empty_list_bit_clear_skips_a_present_block_rule)
{
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_block_v4", 32, ACL_ADDR4(10, 100, 100, 100), 1);
    seed_acl_cfg(CFG_ACL_ENABLE, 0); /* the rule exists; acl_lists claims the list is empty */

    build_udp4(ACL_ADDR4(10, 100, 100, 100), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
}

MARLIN_TEST(acl_disabled_skips_a_present_block_rule)
{
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_block_v4", 32, ACL_ADDR4(10, 110, 110, 110), 1);
    seed_acl_cfg(0, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4)); /* CFG_ACL_ENABLE clear */

    build_udp4(ACL_ADDR4(10, 110, 110, 110), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
}

MARLIN_TEST(acl_v4_non_first_fragment_blocked_source_is_drop)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED);
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_block_v4", 32, ACL_ADDR4(10, 120, 120, 120), 1);
    seed_acl_cfg(CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0x0040 /* offset set, MF clear: non-first, last fragment */,
            ACL_ADDR4(10, 120, 120, 120), V4_DST);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED));
}

MARLIN_TEST(acl_v4_first_fragment_blocked_source_is_drop)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED);
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_block_v4", 32, ACL_ADDR4(10, 125, 125, 125), 1);
    seed_acl_cfg(CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, IP_MF /* offset zero, MF set: first fragment, more follow */,
            ACL_ADDR4(10, 125, 125, 125), V4_DST);
    pb_ports(443, 51000);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED));
}

MARLIN_TEST(acl_v6_non_first_fragment_blocked_source_is_drop)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED);
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v6");
    xdp_acl_clear("acl_block_v6");
    xdp_acl_add6("acl_block_v6", 128, SRC6, 1);
    seed_acl_cfg(CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V6));

    pb_reset();
    pb_eth(ETH_P_IPV6);
    pb_ipv6(IPPROTO_FRAGMENT, SRC6, DST6);
    pb_frag6(IPPROTO_TCP, 0x0008 /* offset set, MF clear: non-first, last fragment */);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED));
}

MARLIN_TEST(acl_icmp_embedded_client_blocked_is_drop)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED);
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_block_v4", 32, ACL_ADDR4(10, 9, 9, 9), 1);
    seed_acl_cfg(CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ICMP, MARLIN_IPV4_IHL_MIN, 0, ACL_ADDR4(198, 51, 100, 1) /* router: irrelevant here */, V4_DST);
    pb_icmp(ICMP_DEST_UNREACH, 0);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, ACL_ADDR4(203, 0, 113, 5) /* embedded src: the VIP, unread */,
            ACL_ADDR4(10, 9, 9, 9) /* embedded dst: the client, becomes tuple.src */);
    pb_ports(443, 51000);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED));
}

MARLIN_TEST(acl_icmp_transit_router_blocked_is_pass)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED);
    struct xdp_run_result result;

    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_block_v4", 32, ACL_ADDR4(10, 9, 9, 9), 1); /* same rule as above */
    seed_acl_cfg(CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));

    pb_reset();
    pb_eth(ETH_P_IP);
    pb_ipv4(IPPROTO_ICMP, MARLIN_IPV4_IHL_MIN, 0, ACL_ADDR4(10, 9, 9, 9) /* the blocked address, now the outer source */, V4_DST);
    pb_icmp(ICMP_DEST_UNREACH, 0);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, ACL_ADDR4(203, 0, 113, 5) /* embedded src: the VIP, unread */,
            ACL_ADDR4(10, 9, 9, 10) /* embedded dst: an unblocked client */);
    pb_ports(443, 51000);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
    CHECK_EQ(before, xdp_drop_stats_total(MARLIN_DROP_ACL_BLOCKED));
}

/* ---- Rate limit (docs/design/28-rate-limiting.md) --------------------- */

/*
 * ratelimit.c's own scaling constant, re-derived from the same RL_TOKEN_SHIFT
 * rather than exposed by any header -- it is a fixed unit conversion, not
 * the algorithm under test, the same reasoning that lets nh_check_frame()
 * below reimplement the IPv4 checksum independently.
 */
#define RL_ONE_TOKEN ((__u32)1U << RL_TOKEN_SHIFT)

static void seed_rl_cfg(__u32 flags, __u32 refill, __u32 burst)
{
    struct marlin_config cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.flags = flags;
    cfg.rl_refill = refill;
    cfg.rl_burst = burst;
    xdp_seed_config(&cfg);
}

static void rl_addr4(unsigned char out[16], __be32 addr)
{
    memset(out, 0, 16);
    memcpy(out, &addr, sizeof(addr));
}

/*
 * The same clock bpf_ktime_get_ns() reports, so a timestamp built from this
 * and fed to xdp_rl_seed() lands in the same tick unit ratelimit.c computes
 * `now` in -- bpf_prog_test_run has no way to fake the kernel's clock, so a
 * case that needs a *relative* offset from "now" reads this instead.
 */
static __u64 rl_now_ticks(void)
{
    struct timespec ts;

    if(clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        fprintf(stderr, "packet-tests: clock_gettime(CLOCK_MONOTONIC) failed: %s\n", strerror(errno));
        exit(1);
    }

    return (((__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec) >> RL_TICK_SHIFT) & 0xffffffffULL;
}

MARLIN_TEST(rl_disabled_does_not_meter)
{
    unsigned char addr16[16];
    __u64 after;
    struct xdp_run_result result;

    rl_addr4(addr16, ACL_ADDR4(10, 40, 40, 1));
    xdp_rl_clear();
    udp_vip_seed(VIP_RATELIMIT);
    seed_rl_cfg(0, 0, 0); /* CFG_RL_ENABLE clear */
    xdp_rl_seed(AF_INET, addr16, 0); /* drained, were it read at all */

    build_udp4(ACL_ADDR4(10, 40, 40, 1), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);

    CHECK_TRUE(xdp_rl_get(AF_INET, addr16, &after));
    CHECK_EQ(0, after); /* untouched: the gate returns before any map access */

    udp_vip_clear();
}

MARLIN_TEST(rl_vip_without_ratelimit_flag_is_not_metered)
{
    unsigned char addr16[16];
    __u64 after;
    struct xdp_run_result result;

    rl_addr4(addr16, ACL_ADDR4(10, 40, 40, 7));
    xdp_rl_clear();
    udp_vip_seed(0); /* VIP_RATELIMIT clear, config enabled */
    seed_rl_cfg(CFG_RL_ENABLE, 0, 3 * RL_ONE_TOKEN);
    xdp_rl_seed(AF_INET, addr16, 0);

    build_udp4(ACL_ADDR4(10, 40, 40, 7), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval); /* a drained bucket would have dropped it */

    CHECK_TRUE(xdp_rl_get(AF_INET, addr16, &after));
    CHECK_EQ(0, after);

    udp_vip_clear();
}

MARLIN_TEST(rl_first_packet_inserts_charged_bucket)
{
    unsigned char addr16[16];
    __u64 state;
    struct xdp_run_result result;

    rl_addr4(addr16, ACL_ADDR4(10, 40, 40, 2));
    xdp_rl_clear();
    udp_vip_seed(VIP_RATELIMIT);
    seed_rl_cfg(CFG_RL_ENABLE, 0, 3 * RL_ONE_TOKEN);

    build_udp4(ACL_ADDR4(10, 40, 40, 2), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);

    CHECK_TRUE(xdp_rl_get(AF_INET, addr16, &state));
    CHECK_EQ(2 * RL_ONE_TOKEN, state & 0xffffffffULL); /* burst less the one token this packet spent */

    udp_vip_clear();
}

MARLIN_TEST(rl_fixed_budget_admits_n_then_drops)
{
    unsigned char addr16[16];
    __u64 before;
    struct xdp_run_result result;
    int i;

    rl_addr4(addr16, ACL_ADDR4(10, 40, 40, 3));
    xdp_rl_clear();
    udp_vip_seed(VIP_RATELIMIT);
    /* refill 0: a fixed budget with no time dependence, so the Nth packet
     * always admits and the N+1th always drops regardless of how long the
     * case takes to run.
     */
    seed_rl_cfg(CFG_RL_ENABLE, 0, 3 * RL_ONE_TOKEN);
    before = xdp_drop_stats_total(MARLIN_DROP_RATELIMITED);

    build_udp4(ACL_ADDR4(10, 40, 40, 3), V4_DST);

    for(i = 0; i < 3; i++) {
        result = run_current_packet();
        CHECK_EQ(0, result.err);
        CHECK_XDP(XDP_TX, result.retval);
    }

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_RATELIMITED));

    udp_vip_clear();
}

MARLIN_TEST(rl_refill_clamps_to_burst)
{
    unsigned char addr16[16];
    __u64 state;
    struct xdp_run_result result;

    rl_addr4(addr16, ACL_ADDR4(10, 40, 40, 4));
    xdp_rl_clear();
    udp_vip_seed(VIP_RATELIMIT);
    /* A rate high enough that elapsed * rate overflows 32 bits after even a
     * handful of ticks; rl_spend()'s clamp before the add is what keeps
     * this exact rather than wrapping. Robust to the two ways a stale
     * timestamp of 0 can be read: as an ordinary (very large) elapsed, or,
     * on a long-uptime test host, as a 32-bit-wrapped "future" timestamp --
     * both paths in rl_spend() converge on a full bucket.
     */
    seed_rl_cfg(CFG_RL_ENABLE, 1U << 30, 5 * RL_ONE_TOKEN);
    xdp_rl_seed(AF_INET, addr16, 0);

    build_udp4(ACL_ADDR4(10, 40, 40, 4), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);

    CHECK_TRUE(xdp_rl_get(AF_INET, addr16, &state));
    CHECK_EQ(4 * RL_ONE_TOKEN, state & 0xffffffffULL); /* clamped to burst, less the one token spent */

    udp_vip_clear();
}

MARLIN_TEST(rl_future_timestamp_resyncs)
{
    unsigned char addr16[16];
    __u64 state;
    __u64 future_state;
    struct xdp_run_result result;

    rl_addr4(addr16, ACL_ADDR4(10, 40, 40, 5));
    xdp_rl_clear();
    udp_vip_seed(VIP_RATELIMIT);
    seed_rl_cfg(CFG_RL_ENABLE, 0, 5 * RL_ONE_TOKEN);

    /*
     * A drained bucket stamped ahead of "now" -- what the 32-bit tick
     * counter's wrap produces roughly every 52 days of uptime, or a clock
     * stepped backwards. Without rl_spend()'s resync this source would stay
     * dropped until "now" caught back up to the stale timestamp; 1,000,000
     * ticks (~17.5 minutes) puts it far enough ahead that no plausible test
     * run duration closes the gap on its own.
     */
    future_state = (rl_now_ticks() + 1000000ULL) << 32; /* tokens: 0 */
    xdp_rl_seed(AF_INET, addr16, future_state);

    build_udp4(ACL_ADDR4(10, 40, 40, 5), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);

    CHECK_TRUE(xdp_rl_get(AF_INET, addr16, &state));
    CHECK_EQ(4 * RL_ONE_TOKEN, state & 0xffffffffULL);

    udp_vip_clear();
}

MARLIN_TEST(rl_v4_and_v6_same_bytes_are_distinct_buckets)
{
    static const unsigned char addr16[16] = {0x0a, 0x01, 0x02, 0x03};
    struct xdp_run_result result;

    xdp_rl_clear();
    udp_vip_seed(VIP_RATELIMIT);
    seed_rl_cfg(CFG_RL_ENABLE, 0, 3 * RL_ONE_TOKEN);

    /* 10.1.2.3 and the IPv6 address 0a01:0203:: share these exact 16 bytes
     * (docs/design/28-rate-limiting.md); family is what keeps them in
     * separate buckets.
     */
    xdp_rl_seed(AF_INET, addr16, 0); /* v4 bucket: drained */
    xdp_rl_seed(AF_INET6, addr16, 3 * RL_ONE_TOKEN); /* v6 bucket, same bytes: full */

    build_udp4(ACL_ADDR4(10, 1, 2, 3), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval); /* the v4 bucket is drained */

    build_udp6(addr16, DST6);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval); /* the v6 bucket, same bytes, is full */

    udp_vip_clear();
}

MARLIN_TEST(rl_allow_verdict_survives_rate_limiter)
{
    unsigned char addr16[16];
    __u64 after;
    struct marlin_config cfg;
    struct xdp_run_result result;

    rl_addr4(addr16, ACL_ADDR4(10, 40, 40, 6));
    xdp_acl_clear("acl_allow_v4");
    xdp_acl_clear("acl_block_v4");
    xdp_acl_add4("acl_allow_v4", 32, ACL_ADDR4(10, 40, 40, 6), 1);
    xdp_rl_clear();
    xdp_rl_seed(AF_INET, addr16, 0); /* drained: any further packet would ratelimit if metered at all */
    udp_vip_seed(VIP_ACL | VIP_RATELIMIT);

    memset(&cfg, 0, sizeof(cfg));
    cfg.flags = CFG_ACL_ENABLE | CFG_RL_ENABLE;
    cfg.acl_lists = ACL_LISTS_BIT(ACL_LIST_ALLOW, ACL_FAMILY_V4);
    cfg.rl_refill = 0;
    cfg.rl_burst = 3 * RL_ONE_TOKEN;
    xdp_seed_config(&cfg);

    build_udp4(ACL_ADDR4(10, 40, 40, 6), V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval); /* the allow verdict, not an empty bucket, is why */

    CHECK_TRUE(xdp_rl_get(AF_INET, addr16, &after));
    CHECK_EQ(0, after); /* untouched: an allow verdict returns before any map access */

    udp_vip_clear();

    /*
     * config is process-global and outlives a case (seed_encap_cfg's
     * comment above). Unlike a leftover ACL rule, CFG_RL_ENABLE affects
     * every source, not just ones a rule names: left set here, every test
     * after this one that never reseeds config -- the nexthop/FIB cases
     * below, which all send from the same V4_SRC -- drains that source's
     * bucket a token at a time until one drops for ratelimited instead of
     * the reason it meant to test. Reset to the all-off state every test
     * before this section assumed.
     */
    memset(&cfg, 0, sizeof(cfg));
    xdp_seed_config(&cfg);
}

/* ---- Next hop, FIB and encapsulation ---------------------------------- */

/*
 * Every case in this section sends the frame nh_build_frame() or
 * nh_build_frame_v6() builds, so the VIP and forwarding-table entries those
 * frames need are seeded and torn down by nh_backend_seed()/nh_backend_clear()
 * rather than repeated in forty case bodies. The whole forwarding block is
 * filled with the one backend id, which is what lets these cases assert
 * selection without knowing which row SipHash picked.
 */
static void nh_vip_seed(__u32 flags)
{
    vip_seed4(V4_DST, 80, IPPROTO_TCP, NH_VIP_NUM, flags);
    vip_seed6(DST6, 80, IPPROTO_TCP, NH_VIP_NUM, flags);
    xdp_fwd_fill(NH_VIP_NUM, NH_BACKEND_ID);
}

static void nh_vip_clear(void)
{
    struct vip_key key;

    vip_key4(&key, V4_DST, 80, IPPROTO_TCP);
    xdp_vip_del(&key);
    vip_key6(&key, DST6, 80, IPPROTO_TCP);
    xdp_vip_del(&key);
    xdp_fwd_clear(NH_VIP_NUM);
}

static void nh_backend_write(const struct backend *be)
{
    xdp_backend_write(NH_BACKEND_ID, be);
}

static void nh_backend_clear(void)
{
    struct backend be;

    memset(&be, 0, sizeof(be));
    nh_backend_write(&be);
    nh_vip_clear();
}

static void nh_backend_seed(__u8 mode_and_flags, __be32 addr, const unsigned char *mac, __u32 egress_ifindex, __u32 vni,
                            const unsigned char *inner_mac)
{
    struct backend be;

    memset(&be, 0, sizeof(be));
    be.flags = (__u8)(mode_and_flags | MARLIN_BE_F_STATE);
    be.addr = addr;
    be.egress_ifindex = egress_ifindex;
    be.vni = vni;
    be.id = (__u16)NH_BACKEND_ID;

    if(mac != NULL) {
        memcpy(be.mac, mac, ETH_ALEN);
    }

    if(inner_mac != NULL) {
        memcpy(be.inner_mac, inner_mac, ETH_ALEN);
    }

    nh_backend_write(&be);
    nh_vip_seed(VIP_HASH_5TUPLE);
}

static void nh_build_frame(void)
{
    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(11111, 80);
}

static void nh_check_frame(const unsigned char *expect_dst, const unsigned char *expect_src, __u32 out_len)
{
    unsigned char expect[ETH_HLEN];

    CHECK_EQ(pb_len, out_len);
    memcpy(expect, pb_arena, ETH_HLEN);
    memcpy(expect, expect_dst, ETH_ALEN);
    memcpy(expect + ETH_ALEN, expect_src, ETH_ALEN);
    CHECK_MEM(expect, out_buf, sizeof(expect));
    CHECK_MEM(pb_arena + ETH_HLEN, out_buf + ETH_HLEN, pb_len - ETH_HLEN);
}

#define IPIP_TUNNEL_SRC 0x0d0d0d0dU /* 13.13.13.13 */

/*
 * config is process-global and outlives a case: every ipip_* case seeds its
 * own tunnel_src/max_frame rather than relying on what an earlier case left,
 * mirroring seed_acl_cfg's discipline above.
 */
static void seed_encap_cfg(__be32 tunnel_src, __u16 max_frame)
{
    struct marlin_config cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.tunnel_src = tunnel_src;
    cfg.max_frame = max_frame;
    xdp_seed_config(&cfg);
}

static void nh_build_frame_v6(void)
{
    pb_reset();
    pb_eth(ETH_P_IPV6);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv6(IPPROTO_TCP, SRC6, DST6);
    pb_ports(11111, 80);
}

/*
 * A from-scratch reimplementation, not a call into csum.h: including
 * <marlin/csum.h> here would drag in the real <bpf/bpf_helpers.h> for
 * __always_inline, which conflicts with the userspace <bpf/bpf.h>/
 * <bpf/libbpf.h> this tier's own fib.h needs (both declare
 * bpf_map_update_elem et al. with incompatible signatures). An independent
 * implementation also means this assertion does not share a bug with the
 * one it is checking; tests/csum_test.c verifies csum.h's own algorithm.
 */
static __sum16 test_ipv4_csum(const struct iphdr *iph)
{
    struct iphdr tmp = *iph;
    const __u8 *p = (const __u8 *)&tmp;
    __u32 sum = 0;
    __u32 i;

    tmp.check = 0;

    for(i = 0; i + 1 < sizeof(tmp); i += 2) {
        sum += ((__u32)p[i] << 8) | p[i + 1];
    }

    sum = (sum & 0xffffU) + (sum >> 16);
    sum = (sum & 0xffffU) + (sum >> 16);

    return bpf_htons((__u16)~sum);
}

/*
 * IPIP-specific sibling of nh_check_frame(): the frame grew by
 * MARLIN_OVERHEAD_IPIP, so neither "same length" nor "everything past
 * ETH_HLEN is unchanged" applies. Asserts the outer Ethernet addresses, the
 * whole outer IPv4 header byte-for-byte, and that the inner packet moved
 * without otherwise changing.
 */
static void ipip_check_frame(const unsigned char *expect_dst, const unsigned char *expect_src, __be32 tunnel_src,
                             __be32 backend_addr, __u8 inner_family, __u32 out_len)
{
    unsigned char expect_eth[ETH_HLEN];
    __be16 outer_proto = bpf_htons(ETH_P_IP);
    struct iphdr expect_iph;

    CHECK_EQ(pb_len + MARLIN_OVERHEAD_IPIP, out_len);

    /*
     * The outer network layer is always IPv4 regardless of inner_family
     * (docs/design/14-forwarding-modes.md SS7.5): the arriving frame's
     * EtherType is not what the outer header carries, even though it
     * mirrors inner_family exactly (parser.c).
     */
    memcpy(expect_eth, pb_arena, ETH_HLEN);
    memcpy(expect_eth, expect_dst, ETH_ALEN);
    memcpy(expect_eth + ETH_ALEN, expect_src, ETH_ALEN);
    memcpy(expect_eth + 2 * ETH_ALEN, &outer_proto, sizeof(outer_proto));
    CHECK_MEM(expect_eth, out_buf, sizeof(expect_eth));

    memset(&expect_iph, 0, sizeof(expect_iph));
    expect_iph.version = 4;
    expect_iph.ihl = MARLIN_IPV4_IHL_MIN;
    expect_iph.frag_off = bpf_htons(IP_DF);
    expect_iph.ttl = MARLIN_OUTER_TTL;
    expect_iph.protocol = (inner_family == AF_INET6) ? IPPROTO_IPV6 : IPPROTO_IPIP;
    expect_iph.tot_len = bpf_htons((__u16)(pb_len - ETH_HLEN + MARLIN_OVERHEAD_IPIP));
    expect_iph.saddr = tunnel_src;
    expect_iph.daddr = backend_addr;
    expect_iph.check = test_ipv4_csum(&expect_iph);
    CHECK_MEM(&expect_iph, out_buf + ETH_HLEN, sizeof(expect_iph));

    CHECK_MEM(pb_arena + ETH_HLEN, out_buf + ETH_HLEN + MARLIN_OVERHEAD_IPIP, pb_len - ETH_HLEN);
}

#define GUE_TUNNEL_SRC 0x0e0e0e0eU /* 14.14.14.14 */

#define VXLAN_TUNNEL_SRC 0x0f0f0f0fU /* 15.15.15.15 */
#define VXLAN_VNI        0x00abcdefU /* arbitrary, within the 24-bit field */

/* Mirrors entropy.h's MARLIN_ENTROPY_SPORT_MIN; entropy.h cannot be included
 * here for the same reason csum.h cannot (test_ipv4_csum above).
 */
#define GUE_ENTROPY_SPORT_MIN 49152U

/* GUE-specific sibling of ipip_check_frame(): the frame grew by
 * MARLIN_OVERHEAD_GUE and gained a UDP+GUE header past the outer IPv4 one.
 * udp.source (the entropy port) is range-checked rather than matched
 * exactly -- entropy.h's algorithm is independently verified by
 * tests/entropy_test.c and tests/gue_test.c wires it against the real
 * function; this tier only needs to know a real value landed there.
 */
static void gue_check_frame(const unsigned char *expect_dst, const unsigned char *expect_src, __be32 tunnel_src,
                            __be32 backend_addr, __be16 encap_dport, __u8 inner_family, __u32 out_len)
{
    unsigned char expect_eth[ETH_HLEN];
    __be16 outer_proto = bpf_htons(ETH_P_IP);
    struct iphdr expect_iph;
    struct udphdr udp;
    struct marlin_gue_hdr expect_gue;

    CHECK_EQ(pb_len + MARLIN_OVERHEAD_GUE, out_len);

    /*
     * The outer network layer is always IPv4 regardless of inner_family
     * (docs/design/14-forwarding-modes.md SS7.5): the arriving frame's
     * EtherType is not what the outer header carries, even though it
     * mirrors inner_family exactly (parser.c).
     */
    memcpy(expect_eth, pb_arena, ETH_HLEN);
    memcpy(expect_eth, expect_dst, ETH_ALEN);
    memcpy(expect_eth + ETH_ALEN, expect_src, ETH_ALEN);
    memcpy(expect_eth + 2 * ETH_ALEN, &outer_proto, sizeof(outer_proto));
    CHECK_MEM(expect_eth, out_buf, sizeof(expect_eth));

    memset(&expect_iph, 0, sizeof(expect_iph));
    expect_iph.version = 4;
    expect_iph.ihl = MARLIN_IPV4_IHL_MIN;
    expect_iph.frag_off = bpf_htons(IP_DF);
    expect_iph.ttl = MARLIN_OUTER_TTL;
    expect_iph.protocol = IPPROTO_UDP;
    expect_iph.tot_len = bpf_htons((__u16)(pb_len - ETH_HLEN + MARLIN_OVERHEAD_GUE));
    expect_iph.saddr = tunnel_src;
    expect_iph.daddr = backend_addr;
    expect_iph.check = test_ipv4_csum(&expect_iph);
    CHECK_MEM(&expect_iph, out_buf + ETH_HLEN, sizeof(expect_iph));

    memcpy(&udp, out_buf + ETH_HLEN + sizeof(expect_iph), sizeof(udp));
    CHECK_TRUE(bpf_ntohs(udp.source) >= GUE_ENTROPY_SPORT_MIN);
    CHECK_EQ((encap_dport != 0) ? encap_dport : bpf_htons(MARLIN_GUE_DPORT_DEFAULT), udp.dest);
    CHECK_EQ(bpf_htons((__u16)(MARLIN_UDP_HLEN + sizeof(expect_gue) + (pb_len - ETH_HLEN))), udp.len);
    CHECK_EQ(0, udp.check);

    memset(&expect_gue, 0, sizeof(expect_gue));
    expect_gue.proto = (inner_family == AF_INET6) ? IPPROTO_IPV6 : IPPROTO_IPIP;
    CHECK_MEM(&expect_gue, out_buf + ETH_HLEN + sizeof(expect_iph) + sizeof(udp), sizeof(expect_gue));

    CHECK_MEM(pb_arena + ETH_HLEN, out_buf + ETH_HLEN + MARLIN_OVERHEAD_GUE, pb_len - ETH_HLEN);
}

/*
 * VXLAN-specific sibling of gue_check_frame(): the frame grew by
 * MARLIN_OVERHEAD_VXLAN, and unlike IPIP/GUE the arriving Ethernet header
 * does not become the *outer* header -- it becomes the *inner* one, with its
 * own two addresses rewritten (docs/design/14-forwarding-modes.md SS7.4).
 * expect_dst/expect_src still name the *outer* header's addresses, the same
 * convention as ipip_check_frame()/gue_check_frame(): what a next-hop MAC
 * swap would have produced. udp.source reuses GUE_ENTROPY_SPORT_MIN --
 * entropy.h's port floor is shared by GUE and VXLAN.
 */
static void vxlan_check_frame(const unsigned char *expect_dst, const unsigned char *expect_src, __be32 tunnel_src,
                              __be32 backend_addr, __be16 encap_dport, const unsigned char *inner_mac, __u32 vni,
                              __u32 out_len)
{
    unsigned char expect_eth[ETH_HLEN];
    __be16 outer_proto = bpf_htons(ETH_P_IP);
    struct ethhdr arriving_eth;
    struct ethhdr inner_eth;
    struct iphdr expect_iph;
    struct udphdr udp;
    struct marlin_vxlan_hdr expect_vxlan;

    CHECK_EQ(pb_len + MARLIN_OVERHEAD_VXLAN, out_len);

    memcpy(&arriving_eth, pb_arena, sizeof(arriving_eth));

    memset(expect_eth, 0, sizeof(expect_eth));
    memcpy(expect_eth, expect_dst, ETH_ALEN);
    memcpy(expect_eth + ETH_ALEN, expect_src, ETH_ALEN);
    memcpy(expect_eth + 2 * ETH_ALEN, &outer_proto, sizeof(outer_proto));
    CHECK_MEM(expect_eth, out_buf, sizeof(expect_eth));

    memset(&expect_iph, 0, sizeof(expect_iph));
    expect_iph.version = 4;
    expect_iph.ihl = MARLIN_IPV4_IHL_MIN;
    expect_iph.frag_off = bpf_htons(IP_DF);
    expect_iph.ttl = MARLIN_OUTER_TTL;
    expect_iph.protocol = IPPROTO_UDP;
    expect_iph.tot_len = bpf_htons((__u16)(pb_len - ETH_HLEN + MARLIN_OVERHEAD_VXLAN));
    expect_iph.saddr = tunnel_src;
    expect_iph.daddr = backend_addr;
    expect_iph.check = test_ipv4_csum(&expect_iph);
    CHECK_MEM(&expect_iph, out_buf + ETH_HLEN, sizeof(expect_iph));

    memcpy(&udp, out_buf + ETH_HLEN + sizeof(expect_iph), sizeof(udp));
    CHECK_TRUE(bpf_ntohs(udp.source) >= GUE_ENTROPY_SPORT_MIN);
    CHECK_EQ((encap_dport != 0) ? encap_dport : bpf_htons(MARLIN_VXLAN_DPORT_DEFAULT), udp.dest);
    CHECK_EQ(bpf_htons((__u16)(MARLIN_UDP_HLEN + sizeof(expect_vxlan) + pb_len)), udp.len);
    CHECK_EQ(0, udp.check);

    memset(&expect_vxlan, 0, sizeof(expect_vxlan));
    expect_vxlan.flags = MARLIN_VXLAN_FLAG_VNI;
    expect_vxlan.vni_and_reserved = bpf_htonl(vni << 8);
    CHECK_MEM(&expect_vxlan, out_buf + ETH_HLEN + sizeof(expect_iph) + sizeof(udp), sizeof(expect_vxlan));

    memcpy(&inner_eth, out_buf + MARLIN_OVERHEAD_VXLAN, sizeof(inner_eth));
    CHECK_MEM(inner_mac, inner_eth.h_dest, ETH_ALEN);
    CHECK_MEM(expect_src, inner_eth.h_source, ETH_ALEN);
    CHECK_EQ(arriving_eth.h_proto, inner_eth.h_proto);

    CHECK_MEM(pb_arena + ETH_HLEN, out_buf + MARLIN_OVERHEAD_VXLAN + ETH_HLEN, pb_len - ETH_HLEN);
}

MARLIN_TEST(fib_no_neigh_onlink_ingress_is_neigh_fallback)
{
    __u64 fallback_before = xdp_drop_stats_total(MARLIN_COUNT_NEIGH_FALLBACK);
    __u64 mismatch_before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    struct xdp_run_result result;

    fib_neigh_del(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS);
    fib_neigh_set(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS, FIB_MAC_BACKEND_A, "failed");

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_BACKEND_A, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(fallback_before + 1, xdp_drop_stats_total(MARLIN_COUNT_NEIGH_FALLBACK));
    CHECK_EQ(mismatch_before, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));

    nh_backend_clear();
    fib_neigh_del(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS);
}

MARLIN_TEST(fib_no_neigh_onlink_other_egress_is_drop)
{
    /*
     * docs/design/24-testing.md:63-64 -- on-link but FIB returns another
     * interface: drop fib_no_neigh, no frame emitted.
     */
    __u64 no_neigh_before = xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH);
    __u64 fallback_before = xdp_drop_stats_total(MARLIN_COUNT_NEIGH_FALLBACK);
    struct xdp_run_result result;

    fib_neigh_del(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS);
    fib_neigh_set(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS, FIB_MAC_BACKEND_B, "failed");

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_BACKEND_B, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(no_neigh_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH));
    CHECK_EQ(fallback_before, xdp_drop_stats_total(MARLIN_COUNT_NEIGH_FALLBACK));

    nh_backend_clear();
    fib_neigh_del(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS);
}

MARLIN_TEST(fib_no_neigh_gatewayed_ingress_is_drop)
{
    __u64 no_neigh_before = xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH);
    __u64 fallback_before = xdp_drop_stats_total(MARLIN_COUNT_NEIGH_FALLBACK);
    struct xdp_run_result result;

    fib_route_add_via(FIB_ADDR_GATEWAYED, FIB_ADDR_GATEWAY, FIB_DEV_INGRESS);
    fib_neigh_del(FIB_ADDR_GATEWAY, FIB_DEV_INGRESS);
    fib_neigh_set(FIB_ADDR_GATEWAY, FIB_DEV_INGRESS, FIB_MAC_GATEWAY, "failed");

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_GATEWAYED, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(no_neigh_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH));
    CHECK_EQ(fallback_before, xdp_drop_stats_total(MARLIN_COUNT_NEIGH_FALLBACK));

    nh_backend_clear();
    fib_neigh_del(FIB_ADDR_GATEWAY, FIB_DEV_INGRESS);
    fib_route_del(FIB_ADDR_GATEWAYED);
}

MARLIN_TEST(fib_no_neigh_onlink_ingress_zero_mac_is_drop)
{
    /*
     * docs/design/24-testing.md:66-67 -- the on-link ingress case again
     * with an all-zero backend.mac: drop, nothing left to fall back to.
     */
    __u64 no_neigh_before = xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH);
    __u64 fallback_before = xdp_drop_stats_total(MARLIN_COUNT_NEIGH_FALLBACK);
    struct xdp_run_result result;

    fib_neigh_del(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS);
    fib_neigh_set(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS, FIB_MAC_BACKEND_A, "failed");

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_BACKEND_A, NULL, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(no_neigh_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH));
    CHECK_EQ(fallback_before, xdp_drop_stats_total(MARLIN_COUNT_NEIGH_FALLBACK));

    nh_backend_clear();
    fib_neigh_del(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS);
}

MARLIN_TEST(fib_no_neigh_under_ipip_is_drop)
{
    __u64 no_neigh_before = xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH);
    struct xdp_run_result result;

    fib_neigh_del(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS);
    fib_neigh_set(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS, FIB_MAC_BACKEND_A, "failed");

    seed_encap_cfg(IPIP_TUNNEL_SRC, 1500);
    nh_backend_seed(MARLIN_MODE_IPIP | MARLIN_BE_F_FIB, FIB_ADDR_BACKEND_A, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    /*
     * Encapsulation precedes next-hop resolution: the frame already grew by
     * MARLIN_OVERHEAD_IPIP by the time the FIB lookup fails.
     */
    ipip_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, IPIP_TUNNEL_SRC, FIB_ADDR_BACKEND_A, AF_INET, result.out_len);
    CHECK_EQ(no_neigh_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH));

    nh_backend_clear();
    fib_neigh_del(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS);
}

MARLIN_TEST(fib_fallback_resolves_backend_not_vip)
{
    __u64 fallback_before = xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK);
    struct xdp_run_result result;

    fib_neigh_del(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS);
    fib_neigh_set(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS, FIB_MAC_BACKEND_A, "permanent");
    fib_route_add_onlink(V4_DST, FIB_DEV_INGRESS);
    fib_neigh_del(V4_DST, FIB_DEV_INGRESS);
    fib_neigh_set(V4_DST, FIB_DEV_INGRESS, NH_DECOY_MAC, "permanent");

    nh_backend_seed(MARLIN_MODE_L2DSR, FIB_ADDR_BACKEND_A, NULL, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(FIB_MAC_BACKEND_A, FIB_MAC_INGRESS, result.out_len);
    CHECK_EQ(fallback_before + 1, xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK));

    nh_backend_clear();
    fib_neigh_del(FIB_ADDR_BACKEND_A, FIB_DEV_INGRESS);
    fib_neigh_del(V4_DST, FIB_DEV_INGRESS);
    fib_route_del(V4_DST);
}

MARLIN_TEST(fib_flag_beats_resolved_mac)
{
    __u64 mismatch_before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    struct xdp_run_result result;

    fib_neigh_del(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS);
    fib_neigh_set(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS, FIB_MAC_BACKEND_B, "permanent");
    xdp_tx_ports_add((__u32)fib_ifindex(FIB_DEV_EGRESS));

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_BACKEND_B, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_REDIRECT, result.retval);
    nh_check_frame(FIB_MAC_BACKEND_B, FIB_MAC_EGRESS, result.out_len);
    CHECK_EQ(mismatch_before, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));

    nh_backend_seed(MARLIN_MODE_L2DSR, FIB_ADDR_BACKEND_B, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    nh_backend_clear();
    xdp_tx_ports_clear();
    fib_neigh_del(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS);
}

MARLIN_TEST(fib_l2dsr_refuses_gatewayed_ipip_forwards)
{
    __u64 gatewayed_before;
    struct xdp_run_result result;

    fib_route_add_via(FIB_ADDR_GATEWAYED, FIB_ADDR_GATEWAY, FIB_DEV_INGRESS);
    fib_neigh_del(FIB_ADDR_GATEWAY, FIB_DEV_INGRESS);
    fib_neigh_set(FIB_ADDR_GATEWAY, FIB_DEV_INGRESS, FIB_MAC_GATEWAY, "permanent");

    gatewayed_before = xdp_drop_stats_total(MARLIN_DROP_FIB_GATEWAYED);
    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_GATEWAYED, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(gatewayed_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_GATEWAYED));

    seed_encap_cfg(IPIP_TUNNEL_SRC, 1500);
    nh_backend_seed(MARLIN_MODE_IPIP | MARLIN_BE_F_FIB, FIB_ADDR_GATEWAYED, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    /*
     * The mode split is the whole point here: the same route that L2DSR
     * refused above forwards under IPIP, with the FIB's own smac/dmac
     * overwriting the outer Ethernet header ipip.c relocated.
     */
    ipip_check_frame(FIB_MAC_GATEWAY, FIB_MAC_INGRESS, IPIP_TUNNEL_SRC, FIB_ADDR_GATEWAYED, AF_INET, result.out_len);

    nh_backend_clear();
    fib_neigh_del(FIB_ADDR_GATEWAY, FIB_DEV_INGRESS);
    fib_route_del(FIB_ADDR_GATEWAYED);
}

MARLIN_TEST(fib_egress_mismatch_counts_verdict_unchanged)
{
    __u64 mismatch_before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    struct xdp_run_result result;
    int nofwd_ifindex = fib_ifindex(FIB_DEV_NOFWD);

    fib_neigh_del(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS);
    fib_neigh_set(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS, FIB_MAC_BACKEND_B, "permanent");
    xdp_tx_ports_add((__u32)fib_ifindex(FIB_DEV_EGRESS));
    xdp_tx_ports_add((__u32)nofwd_ifindex);

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_BACKEND_B, NH_BACKEND_MAC, (__u32)nofwd_ifindex, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_REDIRECT, result.retval);
    nh_check_frame(FIB_MAC_BACKEND_B, FIB_MAC_EGRESS, result.out_len);
    CHECK_EQ(mismatch_before + 1, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));

    nh_backend_clear();
    xdp_tx_ports_clear();
    fib_neigh_del(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS);
}

MARLIN_TEST(fib_egress_mismatch_plus_no_tx_port_is_drop)
{
    __u64 mismatch_before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    __u64 no_tx_port_before = xdp_drop_stats_total(MARLIN_DROP_NO_TX_PORT);
    struct xdp_run_result result;
    int nofwd_ifindex = fib_ifindex(FIB_DEV_NOFWD);

    fib_neigh_del(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS);
    fib_neigh_set(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS, FIB_MAC_BACKEND_B, "permanent");
    xdp_tx_ports_add((__u32)nofwd_ifindex); /* the FIB's own interface, mve1, is deliberately absent */

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_BACKEND_B, NH_BACKEND_MAC, (__u32)nofwd_ifindex, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_ABORTED, result.retval);
    nh_check_frame(FIB_MAC_BACKEND_B, FIB_MAC_EGRESS, result.out_len);
    CHECK_EQ(mismatch_before + 1, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));
    CHECK_EQ(no_tx_port_before + 1, xdp_drop_stats_total(MARLIN_DROP_NO_TX_PORT));

    nh_backend_clear();
    xdp_tx_ports_clear();
    fib_neigh_del(FIB_ADDR_BACKEND_B, FIB_DEV_EGRESS);
}

MARLIN_TEST(fib_blackhole_route_is_drop_and_counted)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_FIB_BLACKHOLE);
    struct xdp_run_result result;

    fib_route_add_special("blackhole", FIB_ADDR_BLACKHOLE);
    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_BLACKHOLE, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_BLACKHOLE));

    nh_backend_clear();
    fib_route_del(FIB_ADDR_BLACKHOLE);
}

MARLIN_TEST(fib_unreachable_route_is_drop_and_counted)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_FIB_UNREACHABLE);
    struct xdp_run_result result;

    fib_route_add_special("unreachable", FIB_ADDR_UNREACHABLE);
    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_UNREACHABLE, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_UNREACHABLE));

    nh_backend_clear();
    fib_route_del(FIB_ADDR_UNREACHABLE);
}

MARLIN_TEST(fib_prohibit_route_is_drop_and_counted)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_FIB_PROHIBIT);
    struct xdp_run_result result;

    fib_route_add_special("prohibit", FIB_ADDR_PROHIBIT);
    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_PROHIBIT, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_PROHIBIT));

    nh_backend_clear();
    fib_route_del(FIB_ADDR_PROHIBIT);
}

MARLIN_TEST(fib_small_mtu_route_is_frag_needed_drop)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_FRAG_NEEDED);
    struct xdp_run_result result;

    fib_route_add_mtu(FIB_ADDR_MTU_ROUTE, FIB_DEV_INGRESS, 576);
    fib_neigh_del(FIB_ADDR_MTU_ROUTE, FIB_DEV_INGRESS);
    fib_neigh_set(FIB_ADDR_MTU_ROUTE, FIB_DEV_INGRESS, FIB_MAC_BACKEND_A, "permanent");

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_MTU_ROUTE, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();
    pb_pad(700);

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_FRAG_NEEDED));

    nh_backend_clear();
    fib_neigh_del(FIB_ADDR_MTU_ROUTE, FIB_DEV_INGRESS);
    fib_route_del(FIB_ADDR_MTU_ROUTE);
}

MARLIN_TEST(fib_unrouted_destination_is_unspec_drop)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_FIB_UNSPEC);
    struct xdp_run_result result;

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_UNROUTED, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_UNSPEC));

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_INGRESS, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(before + 2, xdp_drop_stats_total(MARLIN_DROP_FIB_UNSPEC));

    nh_backend_clear();
}

MARLIN_TEST(fib_ingress_forwarding_disabled_is_drop)
{
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_FIB_FWD_DISABLED);
    struct xdp_run_result result;

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_UNROUTED, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_packet_on(fib_ifindex(FIB_DEV_NOFWD));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_FWD_DISABLED));

    nh_backend_clear();
}

MARLIN_TEST(l2dsr_stored_mac_is_tx_on_backend_mac)
{
    __u64 fallback_before = xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK);
    __u64 mismatch_before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    struct stats backend_before, backend_after;
    struct xdp_run_result result;

    nh_backend_seed(MARLIN_MODE_L2DSR, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, 0, NULL);
    backend_before = xdp_backend_stats_total(NH_BACKEND_ID);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    CHECK_EQ(fallback_before, xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK));
    CHECK_EQ(mismatch_before, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));

    /* backend_stats is metered on every forward, not only the down-backend
     * path backend_stats_counts_a_down_backend_and_keys_on_its_abi_id above
     * already asserts.
     */
    backend_after = xdp_backend_stats_total(NH_BACKEND_ID);
    CHECK_EQ(backend_before.packets + 1, backend_after.packets);
    CHECK_EQ(backend_before.bytes + pb_len, backend_after.bytes);

    nh_backend_clear();
}

MARLIN_TEST(l2dsr_egress_mismatch_counts_verdict_unchanged)
{
    __u64 before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    struct xdp_run_result result;

    nh_backend_seed(MARLIN_MODE_L2DSR, NH_BACKEND_ADDR, NH_BACKEND_MAC, NH_INGRESS_IFINDEX + 1, 0, NULL);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));

    nh_backend_clear();
}

MARLIN_TEST(l2dsr_egress_match_does_not_count)
{
    __u64 before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    struct xdp_run_result result;

    nh_backend_seed(MARLIN_MODE_L2DSR, NH_BACKEND_ADDR, NH_BACKEND_MAC, NH_INGRESS_IFINDEX, 0, NULL);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(before, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));

    nh_backend_clear();
}

MARLIN_TEST(l2dsr_zero_mac_zero_addr_is_backend_unresolved)
{
    __u64 unresolved_before = xdp_drop_stats_total(MARLIN_DROP_BACKEND_UNRESOLVED);
    __u64 fallback_before = xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK);
    struct xdp_run_result result;

    nh_backend_seed(MARLIN_MODE_L2DSR, 0, NULL, 0, 0, NULL);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(unresolved_before + 1, xdp_drop_stats_total(MARLIN_DROP_BACKEND_UNRESOLVED));
    CHECK_EQ(fallback_before, xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK));

    nh_backend_clear();
}

MARLIN_TEST(l2dsr_zero_mac_resolvable_addr_counts_mac_fallback)
{
    __u64 fallback_before = xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK);
    __u64 fwd_disabled_before = xdp_drop_stats_total(MARLIN_DROP_FIB_FWD_DISABLED);
    struct xdp_run_result result;

    nh_backend_seed(MARLIN_MODE_L2DSR, NH_BACKEND_ADDR, NULL, 0, 0, NULL);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(fallback_before + 1, xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK));
    CHECK_EQ(fwd_disabled_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_FWD_DISABLED));

    nh_backend_clear();
}

MARLIN_TEST(l2dsr_fib_flag_does_not_use_stored_mac)
{
    __u64 fallback_before = xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK);
    __u64 fwd_disabled_before = xdp_drop_stats_total(MARLIN_DROP_FIB_FWD_DISABLED);
    struct xdp_run_result result;

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(fallback_before, xdp_drop_stats_total(MARLIN_COUNT_MAC_FALLBACK));
    CHECK_EQ(fwd_disabled_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_FWD_DISABLED));

    nh_backend_clear();
}

MARLIN_TEST(ipip_encap_zero_lookup_swaps_ethernet_and_builds_outer_header)
{
    __u64 mismatch_before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    struct xdp_run_result result;

    seed_encap_cfg(IPIP_TUNNEL_SRC, 1500);
    nh_backend_seed(MARLIN_MODE_IPIP, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    ipip_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, IPIP_TUNNEL_SRC, NH_BACKEND_ADDR, AF_INET, result.out_len);
    CHECK_EQ(mismatch_before, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));

    nh_backend_clear();
}

MARLIN_TEST(ipip_encap_ipv6_inner_sets_protocol_41)
{
    struct xdp_run_result result;

    seed_encap_cfg(IPIP_TUNNEL_SRC, 1500);
    nh_backend_seed(MARLIN_MODE_IPIP, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame_v6();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    ipip_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, IPIP_TUNNEL_SRC, NH_BACKEND_ADDR, AF_INET6, result.out_len);

    nh_backend_clear();
}

MARLIN_TEST(ipip_encap_frame_too_big_drops_before_adjust_head)
{
    __u64 too_big_before;
    struct xdp_run_result result;

    /*
     * Far smaller than any encapsulated test frame: this is a wiring proof
     * that ipip.c checks and drops before touching the packet, not the
     * boundary arithmetic itself, which tests/mtu_test.c already covers.
     */
    seed_encap_cfg(IPIP_TUNNEL_SRC, 10);
    too_big_before = xdp_drop_stats_total(MARLIN_DROP_FRAME_TOO_BIG);

    nh_backend_seed(MARLIN_MODE_IPIP, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(too_big_before + 1, xdp_drop_stats_total(MARLIN_DROP_FRAME_TOO_BIG));

    nh_backend_clear();
}

MARLIN_TEST(ipip_encap_max_frame_zero_disables_the_check)
{
    struct xdp_run_result result;

    seed_encap_cfg(IPIP_TUNNEL_SRC, 0);
    nh_backend_seed(MARLIN_MODE_IPIP, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();
    pb_pad(2000); /* well past any real MTU; only max_frame == 0 lets this through */

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    ipip_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, IPIP_TUNNEL_SRC, NH_BACKEND_ADDR, AF_INET, result.out_len);

    nh_backend_clear();
}

MARLIN_TEST(gue_encap_zero_lookup_swaps_ethernet_and_builds_outer_header)
{
    __u64 mismatch_before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    struct xdp_run_result result;

    seed_encap_cfg(GUE_TUNNEL_SRC, 1500);
    nh_backend_seed(MARLIN_MODE_GUE, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    gue_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, GUE_TUNNEL_SRC, NH_BACKEND_ADDR, 0, AF_INET, result.out_len);
    CHECK_EQ(mismatch_before, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));

    nh_backend_clear();
}

MARLIN_TEST(gue_encap_ipv6_inner_sets_gue_proto_41)
{
    struct xdp_run_result result;

    seed_encap_cfg(GUE_TUNNEL_SRC, 1500);
    nh_backend_seed(MARLIN_MODE_GUE, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame_v6();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    gue_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, GUE_TUNNEL_SRC, NH_BACKEND_ADDR, 0, AF_INET6, result.out_len);

    nh_backend_clear();
}

MARLIN_TEST(gue_encap_frame_too_big_drops_before_adjust_head)
{
    __u64 too_big_before;
    struct xdp_run_result result;

    /* Far smaller than any encapsulated test frame: this is a wiring proof
     * that gue.c checks and drops before touching the packet, not the
     * boundary arithmetic itself, which tests/mtu_test.c already covers.
     */
    seed_encap_cfg(GUE_TUNNEL_SRC, 10);
    too_big_before = xdp_drop_stats_total(MARLIN_DROP_FRAME_TOO_BIG);

    nh_backend_seed(MARLIN_MODE_GUE, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(too_big_before + 1, xdp_drop_stats_total(MARLIN_DROP_FRAME_TOO_BIG));

    nh_backend_clear();
}

MARLIN_TEST(gue_encap_max_frame_zero_disables_the_check)
{
    struct xdp_run_result result;

    seed_encap_cfg(GUE_TUNNEL_SRC, 0);
    nh_backend_seed(MARLIN_MODE_GUE, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();
    pb_pad(2000); /* well past any real MTU; only max_frame == 0 lets this through */

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    gue_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, GUE_TUNNEL_SRC, NH_BACKEND_ADDR, 0, AF_INET, result.out_len);

    nh_backend_clear();
}

MARLIN_TEST(gue_encap_entropy_source_port_differs_for_different_inner_ports)
{
    /* The real-kernel counterpart to entropy_test.c's algorithm-level
     * differentiation case: proves marlin_ctx.tuple, as populated by the
     * compiled parser.c and threaded through the compiled gue.c, actually
     * varies the emitted source port -- not just the algorithm in
     * isolation (docs/design/14-forwarding-modes.md SS7.3).
     */
    struct xdp_run_result result;
    struct udphdr udp_a, udp_b;

    seed_encap_cfg(GUE_TUNNEL_SRC, 1500);
    nh_backend_seed(MARLIN_MODE_GUE, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, 0, NULL);

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(11111, 80);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    memcpy(&udp_a, out_buf + ETH_HLEN + sizeof(struct iphdr), sizeof(udp_a));

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(22222, 80);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    memcpy(&udp_b, out_buf + ETH_HLEN + sizeof(struct iphdr), sizeof(udp_b));

    CHECK_TRUE(udp_a.source != udp_b.source);

    nh_backend_clear();
}

MARLIN_TEST(vxlan_encap_zero_lookup_writes_outer_and_inner_ethernet_headers)
{
    /*
     * nexthop.c:179-181 returns before the Ethernet swap for VXLAN, so the
     * outer addresses here are the ones vxlan.c wrote, not swapped ones. It
     * builds them from the same saved addresses the swap would have used
     * (docs/design/14-forwarding-modes.md SS7.4), which is why the expected
     * outer header below is still ingress-destination-then-ingress-source.
     */
    struct xdp_run_result result;

    seed_encap_cfg(VXLAN_TUNNEL_SRC, 1500);
    nh_backend_seed(MARLIN_MODE_VXLAN, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, VXLAN_VNI, VXLAN_INNER_MAC);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    vxlan_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, VXLAN_TUNNEL_SRC, NH_BACKEND_ADDR, 0, VXLAN_INNER_MAC, VXLAN_VNI,
                      result.out_len);

    nh_backend_clear();
}

MARLIN_TEST(encap_fib_flag_beats_the_vxlan_no_swap)
{
    /*
     * The FIB path is unaffected by vxlan.c's exception
     * (docs/design/14-forwarding-modes.md SS7.4): bpf_fib_lookup() would
     * overwrite the outer addresses on success exactly as under IPIP/GUE,
     * but this route has no forwarding enabled, so the drop fires before
     * that ever happens -- the outer header at drop time is still whatever
     * vxlan.c itself wrote.
     */
    __u64 fwd_disabled_before = xdp_drop_stats_total(MARLIN_DROP_FIB_FWD_DISABLED);
    __u64 mismatch_before = xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH);
    struct xdp_run_result result;

    seed_encap_cfg(VXLAN_TUNNEL_SRC, 1500);
    nh_backend_seed(MARLIN_MODE_VXLAN | MARLIN_BE_F_FIB, NH_BACKEND_ADDR, NH_BACKEND_MAC, NH_INGRESS_IFINDEX + 1, VXLAN_VNI,
                    VXLAN_INNER_MAC);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    vxlan_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, VXLAN_TUNNEL_SRC, NH_BACKEND_ADDR, 0, VXLAN_INNER_MAC, VXLAN_VNI,
                      result.out_len);
    CHECK_EQ(fwd_disabled_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_FWD_DISABLED));
    CHECK_EQ(mismatch_before, xdp_drop_stats_total(MARLIN_COUNT_EGRESS_MISMATCH));

    nh_backend_clear();
}

MARLIN_TEST(vxlan_encap_ipv6_inner_preserves_ethertype)
{
    /*
     * Unlike IPIP/GUE, VXLAN carries no separate inner-protocol field --
     * the inner EtherType is the only family signal a receiving vxlan
     * device gets (docs/design/14-forwarding-modes.md SS7.4), so it must
     * survive relocation unchanged. vxlan_check_frame() derives its
     * expectation from the arriving frame itself, so this only needs to
     * arm a v6 frame and let the shared checker prove it.
     */
    struct xdp_run_result result;

    seed_encap_cfg(VXLAN_TUNNEL_SRC, 1500);
    nh_backend_seed(MARLIN_MODE_VXLAN, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, VXLAN_VNI, VXLAN_INNER_MAC);
    nh_build_frame_v6();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    vxlan_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, VXLAN_TUNNEL_SRC, NH_BACKEND_ADDR, 0, VXLAN_INNER_MAC, VXLAN_VNI,
                      result.out_len);

    nh_backend_clear();
}

MARLIN_TEST(vxlan_encap_frame_too_big_drops_before_adjust_head)
{
    __u64 too_big_before;
    struct xdp_run_result result;

    /* Far smaller than any encapsulated test frame: this is a wiring proof
     * that vxlan.c checks and drops before touching the packet, not the
     * boundary arithmetic itself, which tests/mtu_test.c already covers.
     */
    seed_encap_cfg(VXLAN_TUNNEL_SRC, 10);
    too_big_before = xdp_drop_stats_total(MARLIN_DROP_FRAME_TOO_BIG);

    nh_backend_seed(MARLIN_MODE_VXLAN, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, VXLAN_VNI, VXLAN_INNER_MAC);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(too_big_before + 1, xdp_drop_stats_total(MARLIN_DROP_FRAME_TOO_BIG));

    nh_backend_clear();
}

MARLIN_TEST(vxlan_encap_max_frame_zero_disables_the_check)
{
    struct xdp_run_result result;

    seed_encap_cfg(VXLAN_TUNNEL_SRC, 0);
    nh_backend_seed(MARLIN_MODE_VXLAN, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, VXLAN_VNI, VXLAN_INNER_MAC);
    nh_build_frame();
    pb_pad(2000); /* well past any real MTU; only max_frame == 0 lets this through */

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    vxlan_check_frame(NH_ROUTER_MAC, NH_MARLIN_MAC, VXLAN_TUNNEL_SRC, NH_BACKEND_ADDR, 0, VXLAN_INNER_MAC, VXLAN_VNI,
                      result.out_len);

    nh_backend_clear();
}

MARLIN_TEST(vxlan_encap_entropy_source_port_differs_for_different_inner_ports)
{
    /* The real-kernel counterpart to entropy_test.c's algorithm-level
     * differentiation case: proves marlin_ctx.tuple, as populated by the
     * compiled parser.c and threaded through the compiled vxlan.c, actually
     * varies the emitted source port -- not just the algorithm in
     * isolation (docs/design/14-forwarding-modes.md SS7.3).
     */
    struct xdp_run_result result;
    struct udphdr udp_a, udp_b;

    seed_encap_cfg(VXLAN_TUNNEL_SRC, 1500);
    nh_backend_seed(MARLIN_MODE_VXLAN, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, VXLAN_VNI, VXLAN_INNER_MAC);

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(11111, 80);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    memcpy(&udp_a, out_buf + ETH_HLEN + sizeof(struct iphdr), sizeof(udp_a));

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(22222, 80);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    memcpy(&udp_b, out_buf + ETH_HLEN + sizeof(struct iphdr), sizeof(udp_b));

    CHECK_TRUE(udp_a.source != udp_b.source);

    nh_backend_clear();
}

MARLIN_TEST(fib_cases_leave_no_route_or_neigh_state)
{
    __u64 unspec_before = xdp_drop_stats_total(MARLIN_DROP_FIB_UNSPEC);
    __u64 no_neigh_before = xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH);
    struct xdp_run_result result;

    CHECK_TRUE(xdp_tx_ports_is_empty());

    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_GATEWAYED, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();
    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(unspec_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_UNSPEC));
    nh_backend_seed(MARLIN_MODE_L2DSR | MARLIN_BE_F_FIB, FIB_ADDR_BACKEND_A, NULL, 0, 0, NULL);
    nh_build_frame();
    result = run_packet_on(fib_ifindex(FIB_DEV_INGRESS));
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(no_neigh_before + 1, xdp_drop_stats_total(MARLIN_DROP_FIB_NO_NEIGH));

    nh_backend_clear();
}

MARLIN_TEST(unknown_encap_mode_is_map_bounds_drop)
{
    /*
     * The mode field is 4 bits (ENCAP_MODE_MASK, defines.h) with only 0-3
     * assigned (MARLIN_MODE_L2DSR/IPIP/GUE/VXLAN); 4 names none of them.
     */
    __u64 before = xdp_drop_stats_total(MARLIN_DROP_MAP_BOUNDS);
    struct xdp_run_result result;

    nh_backend_seed(4, NH_BACKEND_ADDR, NH_BACKEND_MAC, 0, 0, NULL);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_MAP_BOUNDS));

    nh_backend_clear();
}

/* ---- VIP admission, backend selection and QUIC steering ---------------- */

#define QUIC_VIP_NUM  3U
#define QUIC_VIP_PORT 443U
#define QUIC_CID_LEN  8U

/* Short header: MARLIN_QUIC_LONG_HEADER clear, fixed bit set (RFC 9000 SS17.3). */
#define QUIC_SHORT_FORM ((__u8)0x40)

/*
 * Distinct from every fixture backends[] index, so a counter keyed on the map
 * index cannot pass for one keyed on backend.id.
 */
#define BAL_ABI_BACKEND_ID 7U

/*
 * marlin_siphash() cannot be reused here: siphash.h pulls in the real
 * <bpf/bpf_helpers.h>, which cannot coexist with the userspace <bpf/bpf.h>
 * that maps.h and fib.h need, and this tier has no stubs/bpf shadow to fall
 * back on. Same constraint, and same remedy, as test_ipv4_csum() above.
 * siphash_matches_published_vectors below is what makes the transcription
 * trustworthy; without it every QUIC assertion is asserting against itself.
 */
static __u64 sip_le64(const __u8 *buf)
{
    return (__u64)buf[0] | ((__u64)buf[1] << 8) | ((__u64)buf[2] << 16) | ((__u64)buf[3] << 24) | ((__u64)buf[4] << 32) |
           ((__u64)buf[5] << 40) | ((__u64)buf[6] << 48) | ((__u64)buf[7] << 56);
}

#define SIP_ROTL(x, b) (((x) << (b)) | ((x) >> (64 - (b))))

#define SIP_ROUND(v0, v1, v2, v3)  \
    do {                           \
        (v0) += (v1);              \
        (v1) = SIP_ROTL((v1), 13); \
        (v1) ^= (v0);              \
        (v0) = SIP_ROTL((v0), 32); \
        (v2) += (v3);              \
        (v3) = SIP_ROTL((v3), 16); \
        (v3) ^= (v2);              \
        (v0) += (v3);              \
        (v3) = SIP_ROTL((v3), 21); \
        (v3) ^= (v0);              \
        (v2) += (v1);              \
        (v1) = SIP_ROTL((v1), 17); \
        (v1) ^= (v2);              \
        (v2) = SIP_ROTL((v2), 32); \
    } while(0)

/* Whole 8-byte blocks only, matching marlin_siphash()'s length contract. */
static __u64 sip_hash64(const void *data, __u32 len, const __u8 key[16])
{
    const __u8 *msg = (const __u8 *)data;
    __u64 v0, v1, v2, v3;
    __u64 k0, k1, word, tail;
    __u32 i;

    k0 = sip_le64(key);
    k1 = sip_le64(key + 8);

    v0 = k0 ^ 0x736f6d6570736575ULL;
    v1 = k1 ^ 0x646f72616e646f6dULL;
    v2 = k0 ^ 0x6c7967656e657261ULL;
    v3 = k1 ^ 0x7465646279746573ULL;

    for(i = 0; i < len / 8; i++) {
        word = sip_le64(msg + i * 8);

        v3 ^= word;
        SIP_ROUND(v0, v1, v2, v3);
        SIP_ROUND(v0, v1, v2, v3);
        v0 ^= word;
    }

    tail = (__u64)len << 56;

    v3 ^= tail;
    SIP_ROUND(v0, v1, v2, v3);
    SIP_ROUND(v0, v1, v2, v3);
    v0 ^= tail;

    v2 ^= 0xff;
    SIP_ROUND(v0, v1, v2, v3);
    SIP_ROUND(v0, v1, v2, v3);
    SIP_ROUND(v0, v1, v2, v3);
    SIP_ROUND(v0, v1, v2, v3);

    return v0 ^ v1 ^ v2 ^ v3;
}

MARLIN_TEST(siphash_matches_published_vectors)
{
    __u8 key[16];
    __u8 in[24];
    int i;

    for(i = 0; i < 16; i++) {
        key[i] = (__u8)i;
    }

    for(i = 0; i < 24; i++) {
        in[i] = (__u8)i;
    }

    CHECK_EQ(0x726fdb47dd0e0e31ULL, sip_hash64(NULL, 0, key));
    CHECK_EQ(0x93f5f5799a932462ULL, sip_hash64(in, 8, key));
    CHECK_EQ(0x3f2acc7f57c29bdbULL, sip_hash64(in, 16, key));

    /* 24 bytes is sizeof(struct marlin_quic_input), the length forged below. */
    CHECK_EQ(0xb8ad50c6f649af94ULL, sip_hash64(in, 24, key));
}

/*
 * config is process-global and outlives a case (seed_acl_cfg, seed_encap_cfg
 * above). None of the cases below turn on the ACL or the rate limiter, so they
 * must clear what an earlier case enabled rather than inherit it.
 */
static void bal_setup(void)
{
    struct marlin_config cfg;

    memset(&cfg, 0, sizeof(cfg));
    xdp_seed_config(&cfg);
    xdp_vip_clear();
}

/*
 * The VIP nh_build_frame()'s frame lands on, seeded one element at a time
 * rather than through nh_backend_seed(): each case below varies exactly one of
 * the VIP flags, the forwarding-table contents or the backend entry, and needs
 * the rest held fixed.
 */
static void bal_vip_seed(__u32 vip_num, __u16 port_host, __u32 flags, __u32 fwd_id)
{
    vip_seed4(V4_DST, port_host, IPPROTO_TCP, vip_num, flags);
    xdp_fwd_fill(vip_num, fwd_id);
}

static void bal_vip_clear(__u32 vip_num, __u16 port_host)
{
    struct vip_key key;

    vip_key4(&key, V4_DST, port_host, IPPROTO_TCP);
    xdp_vip_del(&key);
    xdp_fwd_clear(vip_num);
}

static void bal_build_frame_sport(__u16 sport_host)
{
    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(sport_host, 80);
}

/*
 * Sweeps the source port against a forwarding block striped between two
 * backends and reports whether the emitted destination MAC ever changed: 1 if
 * the source port can move the selection, 0 if it never did, -1 if a packet
 * did not forward at all. Which row any one packet lands on stays unknown,
 * which is the point -- no hash is recomputed here.
 */
static int bal_sport_moves_selection(__u16 count)
{
    unsigned char first[ETH_ALEN] = {0};
    struct xdp_run_result result;
    __u16 i;

    for(i = 0; i < count; i++) {
        bal_build_frame_sport((__u16)(40000U + i));
        result = run_current_packet();

        if(result.err != 0 || result.retval != XDP_TX) {
            return -1;
        }

        if(i == 0) {
            memcpy(first, out_buf, ETH_ALEN);
        } else if(memcmp(first, out_buf, ETH_ALEN) != 0) {
            return 1;
        }
    }

    return 0;
}

MARLIN_TEST(vip_miss_is_pass_and_counted)
{
    __u64 before;
    struct xdp_run_result result;

    bal_setup();
    before = xdp_drop_stats_total(MARLIN_PASS_VIP_MISS);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_PASS, result.retval);
    nh_check_frame(NH_MARLIN_MAC, NH_ROUTER_MAC, result.out_len);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_PASS_VIP_MISS));
}

MARLIN_TEST(port_agnostic_vip_matches_any_dport)
{
    struct xdp_run_result result;

    bal_setup();
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    bal_vip_seed(NH_VIP_NUM, 0, VIP_HASH_5TUPLE, NH_BACKEND_ID);
    nh_build_frame(); /* dport 80, which no vip_map key names */

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    bal_vip_clear(NH_VIP_NUM, 0);
    xdp_backend_clear(NH_BACKEND_ID);
}

MARLIN_TEST(exact_port_vip_wins_over_port_agnostic)
{
    struct stats exact_before, any_before;
    struct xdp_run_result result;

    bal_setup();
    exact_before = xdp_vip_stats_total(NH_VIP_NUM);
    any_before = xdp_vip_stats_total(ALT_VIP_NUM);

    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    bal_vip_seed(NH_VIP_NUM, 80, VIP_HASH_5TUPLE, NH_BACKEND_ID);
    bal_vip_seed(ALT_VIP_NUM, 0, VIP_HASH_5TUPLE, NH_BACKEND_ID);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    CHECK_EQ(exact_before.packets + 1, xdp_vip_stats_total(NH_VIP_NUM).packets);
    CHECK_EQ(any_before.packets, xdp_vip_stats_total(ALT_VIP_NUM).packets);

    bal_vip_clear(NH_VIP_NUM, 80);
    bal_vip_clear(ALT_VIP_NUM, 0);
    xdp_backend_clear(NH_BACKEND_ID);
}

MARLIN_TEST(vip_stats_counts_the_ingress_frame_at_admission)
{
    struct stats before, after;
    struct xdp_run_result result;

    bal_setup();
    before = xdp_vip_stats_total(NH_VIP_NUM);

    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    bal_vip_seed(NH_VIP_NUM, 80, VIP_HASH_5TUPLE, NH_BACKEND_ID);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);

    after = xdp_vip_stats_total(NH_VIP_NUM);
    CHECK_EQ(before.packets + 1, after.packets);
    CHECK_EQ(before.bytes + pb_len, after.bytes);

    bal_vip_clear(NH_VIP_NUM, 80);
    xdp_backend_clear(NH_BACKEND_ID);
}

MARLIN_TEST(vip_num_out_of_range_is_drop)
{
    __u64 before;
    struct xdp_run_result result;

    bal_setup();
    before = xdp_drop_stats_total(MARLIN_DROP_MAP_BOUNDS);
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);

    /*
     * No forwarding block is seeded for it: MAX_VIPS owns none, which is the
     * reason admission refuses the entry in the first place.
     */
    vip_seed4(V4_DST, 80, IPPROTO_TCP, MAX_VIPS, VIP_HASH_5TUPLE);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_MAP_BOUNDS));

    bal_vip_clear(NH_VIP_NUM, 80);
    xdp_backend_clear(NH_BACKEND_ID);
}

MARLIN_TEST(empty_fwd_slot_is_no_backend)
{
    __u64 before;
    struct xdp_run_result result;

    bal_setup();
    before = xdp_drop_stats_total(MARLIN_DROP_NO_BACKEND);
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    bal_vip_seed(NH_VIP_NUM, 80, VIP_HASH_5TUPLE, 0);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_NO_BACKEND));

    bal_vip_clear(NH_VIP_NUM, 80);
    xdp_backend_clear(NH_BACKEND_ID);
}

MARLIN_TEST(out_of_range_fwd_slot_is_no_backend)
{
    __u64 before;
    struct xdp_run_result result;

    bal_setup();
    before = xdp_drop_stats_total(MARLIN_DROP_NO_BACKEND);
    bal_vip_seed(NH_VIP_NUM, 80, VIP_HASH_5TUPLE, MAX_BACKENDS);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_NO_BACKEND));

    bal_vip_clear(NH_VIP_NUM, 80);
}

MARLIN_TEST(unseeded_backend_is_backend_down)
{
    __u64 before;
    struct xdp_run_result result;

    bal_setup();
    before = xdp_drop_stats_total(MARLIN_DROP_BACKEND_DOWN);

    /* backends is an ARRAY, so the slot resolves; MARLIN_BE_F_STATE is what is missing. */
    xdp_backend_clear(NH_BACKEND_ID);
    bal_vip_seed(NH_VIP_NUM, 80, VIP_HASH_5TUPLE, NH_BACKEND_ID);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_BACKEND_DOWN));

    bal_vip_clear(NH_VIP_NUM, 80);
}

MARLIN_TEST(backend_stats_counts_a_down_backend_and_keys_on_its_abi_id)
{
    struct stats abi_before, index_before;
    struct backend be;
    struct xdp_run_result result;

    bal_setup();
    abi_before = xdp_backend_stats_total(BAL_ABI_BACKEND_ID);
    index_before = xdp_backend_stats_total(NH_BACKEND_ID);

    memset(&be, 0, sizeof(be));
    be.flags = MARLIN_MODE_L2DSR; /* no MARLIN_BE_F_STATE */
    be.addr = NH_BACKEND_ADDR;
    be.id = (__u16)BAL_ABI_BACKEND_ID;
    memcpy(be.mac, NH_BACKEND_MAC, ETH_ALEN);
    xdp_backend_write(NH_BACKEND_ID, &be);

    bal_vip_seed(NH_VIP_NUM, 80, VIP_HASH_5TUPLE, NH_BACKEND_ID);
    nh_build_frame();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);

    /* Metered on the way in, before the state check rejects the backend. */
    CHECK_EQ(abi_before.packets + 1, xdp_backend_stats_total(BAL_ABI_BACKEND_ID).packets);
    CHECK_EQ(index_before.packets, xdp_backend_stats_total(NH_BACKEND_ID).packets);

    bal_vip_clear(NH_VIP_NUM, 80);
    xdp_backend_clear(NH_BACKEND_ID);
}

MARLIN_TEST(five_tuple_hash_varies_with_source_port)
{
    bal_setup();
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    backend_seed_l2dsr(ALT_BACKEND_ID, ALT_BACKEND_MAC);
    vip_seed4(V4_DST, 80, IPPROTO_TCP, NH_VIP_NUM, VIP_HASH_5TUPLE);
    xdp_fwd_fill_striped(NH_VIP_NUM, NH_BACKEND_ID, ALT_BACKEND_ID);

    CHECK_EQ(1, bal_sport_moves_selection(32));

    bal_vip_clear(NH_VIP_NUM, 80);
    xdp_backend_clear(NH_BACKEND_ID);
    xdp_backend_clear(ALT_BACKEND_ID);
}

MARLIN_TEST(src_only_hash_ignores_source_port)
{
    bal_setup();
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    backend_seed_l2dsr(ALT_BACKEND_ID, ALT_BACKEND_MAC);
    vip_seed4(V4_DST, 80, IPPROTO_TCP, NH_VIP_NUM, 0);
    xdp_fwd_fill_striped(NH_VIP_NUM, NH_BACKEND_ID, ALT_BACKEND_ID);

    CHECK_EQ(0, bal_sport_moves_selection(32));

    bal_vip_clear(NH_VIP_NUM, 80);
    xdp_backend_clear(NH_BACKEND_ID);
    xdp_backend_clear(ALT_BACKEND_ID);
}

/*
 * A first fragment, not a later one: the ports a later fragment lacks are what
 * the exact-port VIP key is built from, so only a first fragment reaches
 * admission carrying dport 80.
 */
static void bal_build_first_fragment(void)
{
    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, IP_MF, V4_SRC, V4_DST);
    pb_ports(11111, 80);
}

MARLIN_TEST(fragment_on_five_tuple_vip_is_drop)
{
    __u64 before;
    struct xdp_run_result result;

    bal_setup();
    before = xdp_drop_stats_total(MARLIN_DROP_FRAG_UNSUPPORTED);
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    bal_vip_seed(NH_VIP_NUM, 80, VIP_HASH_5TUPLE, NH_BACKEND_ID);
    bal_build_first_fragment();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_FRAG_UNSUPPORTED));

    bal_vip_clear(NH_VIP_NUM, 80);
    xdp_backend_clear(NH_BACKEND_ID);
}

MARLIN_TEST(fragment_non_first_on_five_tuple_vip_is_drop)
{
    /*
     * The first-fragment sibling above proves MARLIN_CTX_F_FRAG_FIRST is
     * produced; this proves the plain MARLIN_CTX_F_FRAG tail is caught too
     * (docs/design/24-testing.md). A tail fragment carries no ports, so the
     * VIP must be port-agnostic for the exact-port lookup to still land here.
     */
    __u64 before;
    struct xdp_run_result result;

    bal_setup();
    before = xdp_drop_stats_total(MARLIN_DROP_FRAG_UNSUPPORTED);
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    bal_vip_seed(NH_VIP_NUM, 0, VIP_HASH_5TUPLE, NH_BACKEND_ID);

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0x0040 /* offset set, MF clear: non-first, last fragment */, V4_SRC, V4_DST);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_DROP, result.retval);
    CHECK_EQ(before + 1, xdp_drop_stats_total(MARLIN_DROP_FRAG_UNSUPPORTED));

    bal_vip_clear(NH_VIP_NUM, 0);
    xdp_backend_clear(NH_BACKEND_ID);
}

MARLIN_TEST(fragment_on_src_hash_vip_forwards)
{
    __u64 before;
    struct xdp_run_result result;

    bal_setup();
    before = xdp_drop_stats_total(MARLIN_DROP_FRAG_UNSUPPORTED);
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    bal_vip_seed(NH_VIP_NUM, 80, 0, NH_BACKEND_ID);
    bal_build_first_fragment();

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(before, xdp_drop_stats_total(MARLIN_DROP_FRAG_UNSUPPORTED));

    bal_vip_clear(NH_VIP_NUM, 80);
    xdp_backend_clear(NH_BACKEND_ID);
}

MARLIN_TEST(unflagged_vip_fragments_and_unfragmented_share_a_row)
{
    /*
     * docs/design/24-testing.md: with VIP_HASH_5TUPLE clear, both fragments
     * must still forward, and to the same backend as an unfragmented packet
     * of the same flow -- the existing guarantee the flag must not disturb.
     */
    unsigned char dmac_full[ETH_ALEN];
    unsigned char dmac_first_frag[ETH_ALEN];
    unsigned char dmac_tail_frag[ETH_ALEN];
    struct xdp_run_result result;

    bal_setup();
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    backend_seed_l2dsr(ALT_BACKEND_ID, ALT_BACKEND_MAC);
    vip_seed4(V4_DST, 0, IPPROTO_TCP, NH_VIP_NUM, 0);
    xdp_fwd_fill_striped(NH_VIP_NUM, NH_BACKEND_ID, ALT_BACKEND_ID);

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_ports(11111, 80);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    memcpy(dmac_full, out_buf, ETH_ALEN);

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, IP_MF, V4_SRC, V4_DST);
    pb_ports(11111, 80);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    memcpy(dmac_first_frag, out_buf, ETH_ALEN);

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0x0040 /* offset set, MF clear: non-first, last fragment */, V4_SRC, V4_DST);
    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    memcpy(dmac_tail_frag, out_buf, ETH_ALEN);

    CHECK_MEM(dmac_full, dmac_first_frag, ETH_ALEN);
    CHECK_MEM(dmac_full, dmac_tail_frag, ETH_ALEN);

    bal_vip_clear(NH_VIP_NUM, 0);
    xdp_backend_clear(NH_BACKEND_ID);
    xdp_backend_clear(ALT_BACKEND_ID);
}

static void bal_build_icmp_embedding_flow(__u16 flow_sport)
{
    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_ICMP, MARLIN_IPV4_IHL_MIN, 0, ACL_ADDR4(198, 51, 100, 1) /* router: irrelevant */, V4_DST);
    pb_icmp(ICMP_DEST_UNREACH, 0);
    /*
     * The embedded packet is the VIP's own response leg (docs/design/13-icmp.md):
     * src is the VIP, dst is the client, and parser.c normalizes both the
     * address and port fields back into the forward-direction tuple this
     * error reports on.
     */
    pb_ipv4(IPPROTO_TCP, MARLIN_IPV4_IHL_MIN, 0, V4_DST, V4_SRC);
    pb_ports(80, flow_sport);
}

MARLIN_TEST(icmp_error_on_five_tuple_vip_picks_the_flows_row)
{
    /*
     * docs/design/24-testing.md: fails unless parser.c recovers the embedded
     * destination port into tuple.sport, and it is the only test that
     * catches that omission.
     */
    unsigned char dmac_flow[ETH_ALEN];
    unsigned char dmac_icmp[ETH_ALEN];
    struct xdp_run_result result;
    __u16 i;

    bal_setup();
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    backend_seed_l2dsr(ALT_BACKEND_ID, ALT_BACKEND_MAC);
    vip_seed4(V4_DST, 80, IPPROTO_TCP, NH_VIP_NUM, VIP_HASH_5TUPLE);
    xdp_fwd_fill_striped(NH_VIP_NUM, NH_BACKEND_ID, ALT_BACKEND_ID);

    for(i = 0; i < 8; i++) {
        __u16 sport = (__u16)(50000U + i);

        bal_build_frame_sport(sport);
        result = run_current_packet();
        CHECK_EQ(0, result.err);
        CHECK_XDP(XDP_TX, result.retval);
        memcpy(dmac_flow, out_buf, ETH_ALEN);

        bal_build_icmp_embedding_flow(sport);
        result = run_current_packet();
        CHECK_EQ(0, result.err);
        CHECK_XDP(XDP_TX, result.retval);
        memcpy(dmac_icmp, out_buf, ETH_ALEN);

        CHECK_MEM(dmac_flow, dmac_icmp, ETH_ALEN);
    }

    bal_vip_clear(NH_VIP_NUM, 80);
    xdp_backend_clear(NH_BACKEND_ID);
    xdp_backend_clear(ALT_BACKEND_ID);
}

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

/*
 * hash_5tuple and striped give the QUIC cases control over the fallback hash
 * path's own behaviour: a fragment case needs VIP_HASH_5TUPLE clear so
 * marlin_balancer_frag() does not drop before backend selection ever runs,
 * and a migration case needs the fwd_table block striped so a fallback to
 * hash is observable at all. Every other case keeps the original uniform,
 * 5-tuple-flagged fixture, where the hash path answers with NH_BACKEND_ID for
 * every row, so a packet that comes out on ALT_BACKEND_MAC can only have been
 * steered.
 */
static void quic_vip_seed(__u32 cid_len, __u32 extra_flags, int hash_5tuple, int striped)
{
    bal_setup();
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    backend_seed_l2dsr(ALT_BACKEND_ID, ALT_BACKEND_MAC);
    vip_seed4(V4_DST, QUIC_VIP_PORT, IPPROTO_UDP, QUIC_VIP_NUM,
              (hash_5tuple ? VIP_HASH_5TUPLE : 0U) | extra_flags | ((cid_len << VIP_QUIC_CID_LEN_SHIFT) & VIP_QUIC_CID_LEN_MASK));

    if(striped) {
        xdp_fwd_fill_striped(QUIC_VIP_NUM, NH_BACKEND_ID, ALT_BACKEND_ID);
    } else {
        xdp_fwd_fill(QUIC_VIP_NUM, NH_BACKEND_ID);
    }
}

static void quic_vip_clear(void)
{
    struct vip_key key;

    vip_key4(&key, V4_DST, QUIC_VIP_PORT, IPPROTO_UDP);
    xdp_vip_del(&key);
    xdp_fwd_clear(QUIC_VIP_NUM);
    xdp_backend_clear(NH_BACKEND_ID);
    xdp_backend_clear(ALT_BACKEND_ID);
}

/*
 * Reproduces the decoder's arithmetic, not its struct layout: the hash input is
 * struct marlin_quic_input straight from proto.h, so a field moving there
 * breaks this as loudly as it breaks balancer.c.
 */
static void quic_forge_cid(__u8 *cid, __u32 cid_len, __u32 backend_id)
{
    struct marlin_quic_input in;
    struct vip_meta meta;
    __u32 i, ent_len, obfuscated;
    __u64 mask;

    ent_len = cid_len - MARLIN_QUIC_CID_ENTROPY_OFF;

    for(i = 0; i < ent_len; i++) {
        cid[MARLIN_QUIC_CID_ENTROPY_OFF + i] = (__u8)(0xa0U + i);
    }

    memset(&in, 0, sizeof(in));
    in.domain = MARLIN_QUIC_SIPHASH_DOMAIN;
    memcpy(in.entropy, cid + MARLIN_QUIC_CID_ENTROPY_OFF, ent_len);

    vip_meta_init(&meta, QUIC_VIP_NUM, 0);
    mask = sip_hash64(&in, sizeof(in), meta.hash_key);

    obfuscated = backend_id ^ (__u32)(mask & 0xffffU);

    cid[0] = (__u8)((mask >> 16) & MARLIN_QUIC_CID_CHECK_MASK);
    cid[1] = (__u8)((obfuscated >> 8) & 0xffU);
    cid[2] = (__u8)(obfuscated & 0xffU);
}

/*
 * pb_udp rather than pb_ports: the decoder reads the connection ID at
 * l4_off + MARLIN_UDP_HLEN + 1, so the full eight-byte UDP header has to be on
 * the wire for those offsets to line up. src is a parameter, not always
 * V4_SRC, so a migration case can vary it while the destination and
 * connection ID stay fixed.
 */
static void quic_build_frame(__be32 src, __u8 form_byte, const __u8 *cid, __u32 cid_len)
{
    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_UDP, MARLIN_IPV4_IHL_MIN, 0, src, V4_DST);
    pb_udp(33333, (__u16)QUIC_VIP_PORT, (__u16)(MARLIN_UDP_HLEN + 1 + cid_len));
    pb_quic_cid(form_byte, cid, cid_len);
}

/*
 * Sweeps source address against a forged CID's fallback hash selection,
 * mirroring bal_sport_moves_selection()'s "does it ever differ" construction
 * above: 1 if the emitted destination MAC ever changed, 0 if it never did, -1
 * if a packet did not forward at all.
 */
static int quic_src_sweep_dmac_changes(const __u8 *cid, __u32 cid_len, __u16 count)
{
    unsigned char first[ETH_ALEN] = {0};
    struct xdp_run_result result;
    __u16 i;

    for(i = 0; i < count; i++) {
        quic_build_frame(ACL_ADDR4(10, 70, 80, (__u8)i), QUIC_SHORT_FORM, cid, cid_len);
        result = run_current_packet();

        if(result.err != 0 || result.retval != XDP_TX) {
            return -1;
        }

        if(i == 0) {
            memcpy(first, out_buf, ETH_ALEN);
        } else if(memcmp(first, out_buf, ETH_ALEN) != 0) {
            return 1;
        }
    }

    return 0;
}

MARLIN_TEST(quic_valid_cid_routes_to_encoded_backend)
{
    __u64 routed_before;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;

    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 1, 0);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    quic_forge_cid(cid, QUIC_CID_LEN, ALT_BACKEND_ID);
    quic_build_frame(V4_SRC, QUIC_SHORT_FORM, cid, QUIC_CID_LEN);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(ALT_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(routed_before + 1, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(quic_bad_check_falls_back_to_hash)
{
    __u64 failed_before, routed_before;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;

    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    quic_forge_cid(cid, QUIC_CID_LEN, ALT_BACKEND_ID);
    cid[0] ^= 0x01; /* one check bit; the generation bits stay clear */
    quic_build_frame(V4_SRC, QUIC_SHORT_FORM, cid, QUIC_CID_LEN);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(failed_before + 1, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(quic_nonzero_generation_bits_fall_back_to_hash)
{
    __u64 failed_before, routed_before;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;

    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    quic_forge_cid(cid, QUIC_CID_LEN, ALT_BACKEND_ID);
    cid[0] |= MARLIN_QUIC_CID_GEN_MASK; /* an ID this instance did not issue */
    quic_build_frame(V4_SRC, QUIC_SHORT_FORM, cid, QUIC_CID_LEN);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(failed_before + 1, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(quic_long_header_is_not_steered)
{
    __u64 failed_before, routed_before;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;

    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    quic_forge_cid(cid, QUIC_CID_LEN, ALT_BACKEND_ID);
    quic_build_frame(V4_SRC, (__u8)(QUIC_SHORT_FORM | MARLIN_QUIC_LONG_HEADER), cid, QUIC_CID_LEN);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    /* The decoder never ran, so neither of its counters moved. */
    CHECK_EQ(failed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(quic_without_vip_quic_flag_is_not_steered)
{
    __u64 failed_before, routed_before;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;

    quic_vip_seed(QUIC_CID_LEN, 0, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    quic_forge_cid(cid, QUIC_CID_LEN, ALT_BACKEND_ID);
    quic_build_frame(V4_SRC, QUIC_SHORT_FORM, cid, QUIC_CID_LEN);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(failed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(quic_cid_len_out_of_range_falls_back_to_hash)
{
    __u64 failed_before, routed_before;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;

    quic_vip_seed(MARLIN_QUIC_CID_MIN - 1, VIP_QUIC, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    quic_forge_cid(cid, QUIC_CID_LEN, ALT_BACKEND_ID);
    quic_build_frame(V4_SRC, QUIC_SHORT_FORM, cid, QUIC_CID_LEN);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    /* Refused before the format byte is read, so nothing is counted. */
    CHECK_EQ(failed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(quic_cid_len_above_max_falls_back_to_hash)
{
    /*
     * 21..31 fit VIP_QUIC_CID_LEN's 5-bit field but exceed MARLIN_QUIC_CID_MAX
     * (20, RFC 9000 SS17.2) -- the upper-bound sibling of the MIN-1 case above.
     */
    __u64 failed_before, routed_before;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;

    quic_vip_seed(MARLIN_QUIC_CID_MAX + 1, VIP_QUIC, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    quic_forge_cid(cid, QUIC_CID_LEN, ALT_BACKEND_ID);
    quic_build_frame(V4_SRC, QUIC_SHORT_FORM, cid, QUIC_CID_LEN);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    /* Refused before the format byte is read, so nothing is counted. */
    CHECK_EQ(failed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(quic_truncated_format_byte_falls_back_to_hash)
{
    __u64 failed_before, routed_before;
    struct xdp_run_result result;

    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_UDP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_udp(33333, (__u16)QUIC_VIP_PORT, (__u16)(MARLIN_UDP_HLEN + 1));
    /* The form byte only: nothing follows it for the decoder's 3-byte load at off. */
    pb_quic_form(QUIC_SHORT_FORM);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(failed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(quic_truncated_entropy_falls_back_to_hash)
{
    __u64 failed_before, routed_before;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;

    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    /*
     * The check/id header only; on the wire below, just 2 of the 5 entropy
     * bytes an 8-byte CID's decode expects actually follow.
     */
    quic_forge_cid(cid, QUIC_CID_LEN, ALT_BACKEND_ID);

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_UDP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_udp(33333, (__u16)QUIC_VIP_PORT, (__u16)(MARLIN_UDP_HLEN + 1 + MARLIN_QUIC_CID_ENTROPY_OFF + 2));
    pb_quic_cid(QUIC_SHORT_FORM, cid, MARLIN_QUIC_CID_ENTROPY_OFF + 2);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(failed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(quic_backend_id_zero_falls_back_to_hash)
{
    __u64 failed_before, routed_before;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;

    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    quic_forge_cid(cid, QUIC_CID_LEN, 0); /* backend_id 0: fwd_table's own empty-slot sentinel */
    quic_build_frame(V4_SRC, QUIC_SHORT_FORM, cid, QUIC_CID_LEN);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    /* A valid check byte naming an id the decoder itself refuses: never
     * counted, never a backends[0] read.
     */
    CHECK_EQ(failed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(quic_backend_id_out_of_range_falls_back_to_hash)
{
    __u64 failed_before, routed_before;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;

    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    quic_forge_cid(cid, QUIC_CID_LEN, MAX_BACKENDS); /* one past backends[]'s last valid index */
    quic_build_frame(V4_SRC, QUIC_SHORT_FORM, cid, QUIC_CID_LEN);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    CHECK_EQ(failed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(quic_decoded_backend_down_falls_back_to_hash)
{
    __u64 failed_before, routed_before;
    struct stats alt_before, alt_after;
    struct backend be;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;

    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);
    alt_before = xdp_backend_stats_total(ALT_BACKEND_ID);

    /* backends is an ARRAY, so the slot resolves; MARLIN_BE_F_STATE is what is missing. */
    memset(&be, 0, sizeof(be));
    be.flags = MARLIN_MODE_L2DSR;
    be.id = (__u16)ALT_BACKEND_ID;
    memcpy(be.mac, ALT_BACKEND_MAC, ETH_ALEN);
    xdp_backend_write(ALT_BACKEND_ID, &be);

    quic_forge_cid(cid, QUIC_CID_LEN, ALT_BACKEND_ID);
    quic_build_frame(V4_SRC, QUIC_SHORT_FORM, cid, QUIC_CID_LEN);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);

    CHECK_EQ(failed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    /*
     * The rejection is marlin_balancer_select_backend_quic()'s own
     * MARLIN_BE_F_STATE check, which returns NULL before
     * marlin_balancer_load_backend() -- the only call that meters -- ever
     * sees this backend.
     */
    alt_after = xdp_backend_stats_total(ALT_BACKEND_ID);
    CHECK_EQ(alt_before.packets, alt_after.packets);

    quic_vip_clear();
}

MARLIN_TEST(quic_non_quic_udp_on_vip_quic_routes_by_hash)
{
    __u64 failed_before, routed_before;
    struct xdp_run_result result;

    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_UDP, MARLIN_IPV4_IHL_MIN, 0, V4_SRC, V4_DST);
    pb_udp(33333, (__u16)QUIC_VIP_PORT, MARLIN_UDP_HLEN); /* no payload: parser.c never reads a form byte */

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(failed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(icmp_error_on_vip_quic_routes_by_hash)
{
    __u64 failed_before, routed_before;
    struct xdp_run_result result;

    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 1, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv4(IPPROTO_ICMP, MARLIN_IPV4_IHL_MIN, 0, ACL_ADDR4(198, 51, 100, 1) /* router: irrelevant */, V4_DST);
    pb_icmp(ICMP_DEST_UNREACH, 0);
    /*
     * An embedded header carries at most 8 bytes of L4 (proto.h) -- ports
     * only, never a connection ID -- so this can only ever reach hash
     * selection; parser.c's marlin_parse_icmp() never calls the QUIC parser.
     */
    pb_ipv4(IPPROTO_UDP, MARLIN_IPV4_IHL_MIN, 0, V4_DST /* embedded src: the VIP, becomes tuple.dst */,
            V4_SRC /* embedded dst: the client, becomes tuple.src */);
    pb_ports((__u16)QUIC_VIP_PORT, 33333);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(failed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(fragmented_udp_on_vip_quic_routes_by_hash)
{
    __u64 failed_before, routed_before;
    struct xdp_run_result result;

    /*
     * VIP_HASH_5TUPLE clear: with it set, marlin_balancer_frag() would drop
     * frag_unsupported before backend selection ever runs, testing the wrong
     * guard. VIP_QUIC alone still reaches marlin_balancer_quic_decode(),
     * whose own MARLIN_CTX_F_FRAG_ANY check (balancer.c) is what this proves.
     */
    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 0, 0);
    failed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    pb_reset();
    pb_eth(ETH_P_IP);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    /* First fragment: ports are present, so admission reaches the VIP_QUIC VIP. */
    pb_ipv4(IPPROTO_UDP, MARLIN_IPV4_IHL_MIN, IP_MF, V4_SRC, V4_DST);
    pb_udp(33333, (__u16)QUIC_VIP_PORT, (__u16)(MARLIN_UDP_HLEN + 1));
    pb_quic_form(QUIC_SHORT_FORM);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    nh_check_frame(NH_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(failed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_CHECK_FAILED));
    CHECK_EQ(routed_before, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(quic_migration_same_cid_different_sources_same_backend)
{
    __u64 routed_before;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;
    __u16 i;

    quic_vip_seed(QUIC_CID_LEN, VIP_QUIC, 1, 1);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);
    quic_forge_cid(cid, QUIC_CID_LEN, ALT_BACKEND_ID);

    for(i = 0; i < 8; i++) {
        quic_build_frame(ACL_ADDR4(10, 71, 71, (__u8)i), QUIC_SHORT_FORM, cid, QUIC_CID_LEN);
        result = run_current_packet();
        CHECK_EQ(0, result.err);
        CHECK_XDP(XDP_TX, result.retval);
        nh_check_frame(ALT_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    }
    CHECK_EQ(routed_before + 8, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    quic_vip_clear();
}

MARLIN_TEST(quic_migration_needs_the_vip_quic_flag)
{
    __u8 cid[QUIC_CID_LEN];

    /*
     * Same forged CID and striped table as the migration case above, but
     * VIP_QUIC clear: selection now depends on the hash, which does depend
     * on source address, so the sweep must observe a change.
     */
    quic_vip_seed(QUIC_CID_LEN, 0, 1, 1);
    quic_forge_cid(cid, QUIC_CID_LEN, ALT_BACKEND_ID);

    CHECK_EQ(1, quic_src_sweep_dmac_changes(cid, QUIC_CID_LEN, 32));

    quic_vip_clear();
}

MARLIN_TEST(quic_cid_routes_over_ipv6)
{
    __u64 routed_before;
    struct vip_key key;
    __u8 cid[QUIC_CID_LEN];
    struct xdp_run_result result;

    bal_setup();
    backend_seed_l2dsr(NH_BACKEND_ID, NH_BACKEND_MAC);
    backend_seed_l2dsr(ALT_BACKEND_ID, ALT_BACKEND_MAC);
    vip_seed6(DST6, QUIC_VIP_PORT, IPPROTO_UDP, QUIC_VIP_NUM,
              VIP_HASH_5TUPLE | VIP_QUIC | ((QUIC_CID_LEN << VIP_QUIC_CID_LEN_SHIFT) & VIP_QUIC_CID_LEN_MASK));
    xdp_fwd_fill(QUIC_VIP_NUM, NH_BACKEND_ID);
    routed_before = xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED);

    quic_forge_cid(cid, QUIC_CID_LEN, ALT_BACKEND_ID);

    pb_reset();
    pb_eth(ETH_P_IPV6);
    memcpy(pb_arena, NH_MARLIN_MAC, ETH_ALEN);
    memcpy(pb_arena + ETH_ALEN, NH_ROUTER_MAC, ETH_ALEN);
    pb_ipv6(IPPROTO_UDP, SRC6, DST6);
    pb_udp(33333, (__u16)QUIC_VIP_PORT, (__u16)(MARLIN_UDP_HLEN + 1 + QUIC_CID_LEN));
    pb_quic_cid(QUIC_SHORT_FORM, cid, QUIC_CID_LEN);

    result = run_current_packet();
    CHECK_EQ(0, result.err);
    CHECK_XDP(XDP_TX, result.retval);
    /*
     * Proves balancer.c reads mctx->l4_off rather than a v4-shaped constant:
     * a wrong offset would decode garbage and fall back to NH_BACKEND_MAC.
     */
    nh_check_frame(ALT_BACKEND_MAC, NH_MARLIN_MAC, result.out_len);
    CHECK_EQ(routed_before + 1, xdp_drop_stats_total(MARLIN_COUNT_QUIC_CID_ROUTED));

    vip_key6(&key, DST6, QUIC_VIP_PORT, IPPROTO_UDP);
    xdp_vip_del(&key);
    xdp_fwd_clear(QUIC_VIP_NUM);
    xdp_backend_clear(NH_BACKEND_ID);
    xdp_backend_clear(ALT_BACKEND_ID);
}

int main(int argc, char **argv)
{
    const char *obj_path = (argc > 1) ? argv[1] : "build/marlin.bpf.o";
    struct marlin_config cfg;
    int rc;

    if(unshare(CLONE_NEWNET) != 0) {
        fprintf(stderr, "packet-tests: unshare(CLONE_NEWNET) failed: %s\n", strerror(errno));
        exit(1);
    }

    fib_topology_up();

    xdp_prog_load(obj_path);

    memset(&cfg, 0, sizeof(cfg));
    xdp_seed_config(&cfg);

    rc = marlin_tests_main();

    xdp_prog_unload();
    return rc;
}
