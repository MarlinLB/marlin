/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Native unit tests for acl.c. This translation unit #includes the source
 * directly and reaches its map lookups through tests/stubs/, which shadows
 * libbpf's <bpf/bpf_helpers.h> and answers bpf_map_lookup_elem out of a
 * host LPM trie keyed by the map object's address.
 */

#include <stdio.h>
#include <string.h>

#include <bpf/bpf_endian.h>

#include "harness.h"

#include "../src/acl.c"

#define ACL_ADDR4(a, b, c, d) bpf_htonl(((__u32)(a) << 24) | ((__u32)(b) << 16) | ((__u32)(c) << 8) | (__u32)(d))

#define ACL_BOTH_V4 ((__u16)(ACL_LISTS_BIT(ACL_LIST_ALLOW, ACL_FAMILY_V4) | ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4)))
#define ACL_BOTH_V6 ((__u16)(ACL_LISTS_BIT(ACL_LIST_ALLOW, ACL_FAMILY_V6) | ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V6)))

static const unsigned char SRC6[16] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                                       0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
static const unsigned char DST6[16] = {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
                                       0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30};

/*
 * Poisoned rather than zeroed, like parser_test.c's mctx_init: every field
 * the ACL is not supposed to read reads back as garbage, so dst, the ports
 * and proto all hold values a wrongly-keyed lookup would notice.
 */
static void mctx_init(struct marlin_ctx *mctx, __u8 family, __u32 flags, __u16 acl_lists)
{
    memset(mctx, 0xAA, sizeof(*mctx));
    mctx->cfg.flags = flags;
    mctx->cfg.acl_lists = acl_lists;
    mctx->tuple.family = family;
    acl_stub_reset();
}

/* src[1..3] stay poisoned: the v4 path must key on src[0] alone. */
static void mctx_src4(struct marlin_ctx *mctx, __be32 addr)
{
    mctx->tuple.src[0] = addr;
}

static void mctx_src6(struct marlin_ctx *mctx, const unsigned char addr16[16])
{
    memcpy(mctx->tuple.src, addr16, sizeof(mctx->tuple.src));
}

MARLIN_TEST(acl_key_struct_sizes_match_lpm_prefixlen_widths)
{
    CHECK_EQ(8, sizeof(struct acl_key4));
    CHECK_EQ(20, sizeof(struct acl_key6));
    CHECK_EQ(32, sizeof(((struct acl_key4 *)0)->addr) * 8);
    CHECK_EQ(128, sizeof(((struct acl_key6 *)0)->addr) * 8);
}

MARLIN_TEST(acl_null_ctx_is_none)
{
    acl_stub_reset();
    CHECK_EQ(MARLIN_ACL_NONE, marlin_acl_check(NULL));
}

MARLIN_TEST(acl_disabled_skips_a_present_block_rule)
{
    struct marlin_ctx m;

    mctx_init(&m, AF_INET, 0, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));
    acl_stub_add4(&acl_block_v4, 32, ACL_ADDR4(10, 110, 110, 110), 1);
    mctx_src4(&m, ACL_ADDR4(10, 110, 110, 110));

    CHECK_EQ(MARLIN_ACL_NONE, marlin_acl_check(&m));
    CHECK_EQ(0, acl_stub_lookups(&acl_block_v4));
}

MARLIN_TEST(acl_zero_family_is_none_and_looks_up_nothing)
{
    struct marlin_ctx m;

    mctx_init(&m, 0, CFG_ACL_ENABLE, ACL_BOTH_V4);
    acl_stub_add4(&acl_block_v4, 0, 0, 1);
    mctx_src4(&m, ACL_ADDR4(10, 1, 1, 1));

    CHECK_EQ(MARLIN_ACL_NONE, marlin_acl_check(&m));
    CHECK_EQ(0, acl_stub_lookups(&acl_block_v4));
    CHECK_EQ(0, acl_stub_lookups(&acl_allow_v4));
}

MARLIN_TEST(acl_unknown_family_af_packet_is_none)
{
    struct marlin_ctx m;

    mctx_init(&m, 17, CFG_ACL_ENABLE, ACL_BOTH_V4); /* AF_PACKET */
    acl_stub_add4(&acl_block_v4, 0, 0, 1);
    mctx_src4(&m, ACL_ADDR4(10, 1, 1, 1));

    CHECK_EQ(MARLIN_ACL_NONE, marlin_acl_check(&m));
    CHECK_EQ(0, acl_stub_lookups(&acl_block_v4));
}

MARLIN_TEST(acl_v4_block_matched_is_block)
{
    struct marlin_ctx m;

    mctx_init(&m, AF_INET, CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));
    acl_stub_add4(&acl_block_v4, 32, ACL_ADDR4(10, 20, 20, 20), 1);
    mctx_src4(&m, ACL_ADDR4(10, 20, 20, 20));

    CHECK_EQ(MARLIN_ACL_BLOCK, marlin_acl_check(&m));
    CHECK_EQ(1, acl_stub_lookups(&acl_block_v4));
}

MARLIN_TEST(acl_v4_block_missed_is_none)
{
    struct marlin_ctx m;

    mctx_init(&m, AF_INET, CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));
    acl_stub_add4(&acl_block_v4, 32, ACL_ADDR4(10, 20, 20, 20), 1);
    mctx_src4(&m, ACL_ADDR4(10, 20, 20, 21));

    CHECK_EQ(MARLIN_ACL_NONE, marlin_acl_check(&m));
    CHECK_EQ(1, acl_stub_lookups(&acl_block_v4));
}

MARLIN_TEST(acl_v4_allow_miss_block_hit_is_block)
{
    struct marlin_ctx m;

    /*
     * Mirrors xdp_test.c's acl_v4_block_matched_is_drop_and_counted, but
     * with the allow bit also set and no allow rule seeded -- the packet
     * tier's block cases all run with the allow bit clear, so this is the
     * only case where a broken allow-lookup could accidentally suppress a
     * real block.
     */
    mctx_init(&m, AF_INET, CFG_ACL_ENABLE, ACL_BOTH_V4);
    acl_stub_add4(&acl_block_v4, 32, ACL_ADDR4(10, 20, 20, 20), 1);
    mctx_src4(&m, ACL_ADDR4(10, 20, 20, 20));

    CHECK_EQ(MARLIN_ACL_BLOCK, marlin_acl_check(&m));
    CHECK_EQ(1, acl_stub_lookups(&acl_allow_v4));
    CHECK_EQ(1, acl_stub_lookups(&acl_block_v4));
}

MARLIN_TEST(acl_v4_allow_matched_is_allow)
{
    struct marlin_ctx m;

    mctx_init(&m, AF_INET, CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_ALLOW, ACL_FAMILY_V4));
    acl_stub_add4(&acl_allow_v4, 32, ACL_ADDR4(10, 30, 30, 30), 1);
    mctx_src4(&m, ACL_ADDR4(10, 30, 30, 30));

    CHECK_EQ(MARLIN_ACL_ALLOW, marlin_acl_check(&m));
}

MARLIN_TEST(acl_v6_block_matched_is_block)
{
    struct marlin_ctx m;

    mctx_init(&m, AF_INET6, CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V6));
    acl_stub_add6(&acl_block_v6, 128, SRC6, 1);
    mctx_src6(&m, SRC6);

    CHECK_EQ(MARLIN_ACL_BLOCK, marlin_acl_check(&m));
}

MARLIN_TEST(acl_v6_block_missed_is_none)
{
    struct marlin_ctx m;

    mctx_init(&m, AF_INET6, CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V6));
    acl_stub_add6(&acl_block_v6, 128, SRC6, 1);
    mctx_src6(&m, DST6);

    CHECK_EQ(MARLIN_ACL_NONE, marlin_acl_check(&m));
}

MARLIN_TEST(acl_v6_allow_matched_is_allow)
{
    struct marlin_ctx m;

    mctx_init(&m, AF_INET6, CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_ALLOW, ACL_FAMILY_V6));
    acl_stub_add6(&acl_allow_v6, 128, SRC6, 1);
    mctx_src6(&m, SRC6);

    CHECK_EQ(MARLIN_ACL_ALLOW, marlin_acl_check(&m));
}

MARLIN_TEST(acl_v4_allow_short_circuits_the_block_lookup)
{
    struct marlin_ctx m;

    mctx_init(&m, AF_INET, CFG_ACL_ENABLE, ACL_BOTH_V4);
    acl_stub_add4(&acl_allow_v4, 8, ACL_ADDR4(10, 0, 0, 0), 1);
    acl_stub_add4(&acl_block_v4, 32, ACL_ADDR4(10, 70, 70, 70), 2);
    mctx_src4(&m, ACL_ADDR4(10, 70, 70, 70));

    CHECK_EQ(MARLIN_ACL_ALLOW, marlin_acl_check(&m));
    CHECK_EQ(1, acl_stub_lookups(&acl_allow_v4));
    CHECK_EQ(0, acl_stub_lookups(&acl_block_v4));
}

MARLIN_TEST(acl_v4_slash32_allow_beats_slash8_block_but_not_its_neighbour)
{
    struct marlin_ctx m;

    mctx_init(&m, AF_INET, CFG_ACL_ENABLE, ACL_BOTH_V4);
    acl_stub_add4(&acl_block_v4, 8, ACL_ADDR4(10, 0, 0, 0), 1);
    acl_stub_add4(&acl_allow_v4, 32, ACL_ADDR4(10, 90, 90, 90), 2);

    mctx_src4(&m, ACL_ADDR4(10, 90, 90, 90));
    CHECK_EQ(MARLIN_ACL_ALLOW, marlin_acl_check(&m));

    mctx_src4(&m, ACL_ADDR4(10, 90, 90, 91));
    CHECK_EQ(MARLIN_ACL_BLOCK, marlin_acl_check(&m));

    mctx_src4(&m, ACL_ADDR4(11, 90, 90, 90));
    CHECK_EQ(MARLIN_ACL_NONE, marlin_acl_check(&m));
}

MARLIN_TEST(acl_v4_slash24_block_covers_inside_not_outside)
{
    struct marlin_ctx m;

    mctx_init(&m, AF_INET, CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));
    acl_stub_add4(&acl_block_v4, 24, ACL_ADDR4(10, 40, 50, 0), 1);

    mctx_src4(&m, ACL_ADDR4(10, 40, 50, 7)); /* inside 10.40.50.0/24 */
    CHECK_EQ(MARLIN_ACL_BLOCK, marlin_acl_check(&m));

    mctx_src4(&m, ACL_ADDR4(10, 40, 51, 7)); /* outside it: third octet differs */
    CHECK_EQ(MARLIN_ACL_NONE, marlin_acl_check(&m));
}

MARLIN_TEST(acl_v4_slash32_block_does_not_cover_neighbour)
{
    struct marlin_ctx m;

    mctx_init(&m, AF_INET, CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));
    acl_stub_add4(&acl_block_v4, 32, ACL_ADDR4(10, 60, 60, 6), 1);

    mctx_src4(&m, ACL_ADDR4(10, 60, 60, 6)); /* the exact blocked host */
    CHECK_EQ(MARLIN_ACL_BLOCK, marlin_acl_check(&m));

    mctx_src4(&m, ACL_ADDR4(10, 60, 60, 7)); /* its neighbour: last octet differs */
    CHECK_EQ(MARLIN_ACL_NONE, marlin_acl_check(&m));
}

MARLIN_TEST(acl_v4_nested_block_prefixes_in_one_trie)
{
    struct marlin_ctx m;

    mctx_init(&m, AF_INET, CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));
    acl_stub_add4(&acl_block_v4, 8, ACL_ADDR4(10, 0, 0, 0), 1);
    acl_stub_add4(&acl_block_v4, 24, ACL_ADDR4(10, 130, 40, 0), 2);
    acl_stub_add4(&acl_block_v4, 32, ACL_ADDR4(10, 130, 40, 5), 3);

    mctx_src4(&m, ACL_ADDR4(10, 130, 40, 5));
    CHECK_EQ(MARLIN_ACL_BLOCK, marlin_acl_check(&m));

    mctx_src4(&m, ACL_ADDR4(10, 130, 99, 9));
    CHECK_EQ(MARLIN_ACL_BLOCK, marlin_acl_check(&m));

    mctx_src4(&m, ACL_ADDR4(11, 130, 40, 5));
    CHECK_EQ(MARLIN_ACL_NONE, marlin_acl_check(&m));
}

MARLIN_TEST(acl_v4_equal_length_allow_beats_block)
{
    struct marlin_ctx m;

    mctx_init(&m, AF_INET, CFG_ACL_ENABLE, ACL_BOTH_V4);
    acl_stub_add4(&acl_allow_v4, 32, ACL_ADDR4(10, 80, 80, 80), 1);
    acl_stub_add4(&acl_block_v4, 32, ACL_ADDR4(10, 80, 80, 80), 2);
    mctx_src4(&m, ACL_ADDR4(10, 80, 80, 80));

    CHECK_EQ(MARLIN_ACL_ALLOW, marlin_acl_check(&m));
}

MARLIN_TEST(acl_v6_slash32_allow_beats_slash128_block)
{
    struct marlin_ctx m;
    unsigned char allow6[16];

    memset(allow6, 0, sizeof(allow6));
    memcpy(allow6, SRC6, 4);

    mctx_init(&m, AF_INET6, CFG_ACL_ENABLE, ACL_BOTH_V6);
    acl_stub_add6(&acl_allow_v6, 32, allow6, 1);
    acl_stub_add6(&acl_block_v6, 128, SRC6, 2);
    mctx_src6(&m, SRC6);

    CHECK_EQ(MARLIN_ACL_ALLOW, marlin_acl_check(&m));
}

MARLIN_TEST(acl_v6_nested_block_prefixes_in_one_trie)
{
    struct marlin_ctx m;
    unsigned char block32[16];
    unsigned char block64[16];
    unsigned char probe[16];

    /*
     * Mirrors acl_v4_nested_block_prefixes_in_one_trie: three entries in one
     * trie sharing a prefix, so the kernel's trie builds an intermediate
     * node at that shared prefix -- a single-leaf trie never walks it.
     */
    memset(block32, 0, sizeof(block32));
    memcpy(block32, SRC6, 4);
    memset(block64, 0, sizeof(block64));
    memcpy(block64, SRC6, 8);

    mctx_init(&m, AF_INET6, CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V6));
    acl_stub_add6(&acl_block_v6, 32, block32, 1);
    acl_stub_add6(&acl_block_v6, 64, block64, 2);
    acl_stub_add6(&acl_block_v6, 128, SRC6, 3);

    mctx_src6(&m, SRC6); /* matches all three entries */
    CHECK_EQ(MARLIN_ACL_BLOCK, marlin_acl_check(&m));

    memcpy(probe, SRC6, sizeof(probe));
    probe[15] ^= 0x01; /* in the /64 and /32, not the /128 */
    mctx_src6(&m, probe);
    CHECK_EQ(MARLIN_ACL_BLOCK, marlin_acl_check(&m));

    memcpy(probe, SRC6, sizeof(probe));
    probe[8] ^= 0x01; /* in the /32 only */
    mctx_src6(&m, probe);
    CHECK_EQ(MARLIN_ACL_BLOCK, marlin_acl_check(&m));

    memcpy(probe, SRC6, sizeof(probe));
    probe[0] ^= 0x01; /* outside the /32: leading byte differs */
    mctx_src6(&m, probe);
    CHECK_EQ(MARLIN_ACL_NONE, marlin_acl_check(&m));
}

MARLIN_TEST(acl_v6_equal_length_allow_beats_block)
{
    struct marlin_ctx m;

    mctx_init(&m, AF_INET6, CFG_ACL_ENABLE, ACL_BOTH_V6);
    acl_stub_add6(&acl_allow_v6, 128, SRC6, 1);
    acl_stub_add6(&acl_block_v6, 128, SRC6, 2);
    mctx_src6(&m, SRC6);

    CHECK_EQ(MARLIN_ACL_ALLOW, marlin_acl_check(&m));
}

MARLIN_TEST(acl_v6_slash128_allow_beats_slash32_block_but_not_its_neighbour)
{
    struct marlin_ctx m;
    unsigned char block32[16];
    unsigned char neighbour[16];

    memset(block32, 0, sizeof(block32));
    memcpy(block32, SRC6, 4);
    memcpy(neighbour, SRC6, sizeof(neighbour));
    neighbour[15] ^= 0x01; /* still inside the /32, distinct from the /128 allow */

    mctx_init(&m, AF_INET6, CFG_ACL_ENABLE, ACL_BOTH_V6);
    acl_stub_add6(&acl_block_v6, 32, block32, 1);
    acl_stub_add6(&acl_allow_v6, 128, SRC6, 2);

    mctx_src6(&m, SRC6); /* the allowed host: escapes the /32 block */
    CHECK_EQ(MARLIN_ACL_ALLOW, marlin_acl_check(&m));

    mctx_src6(&m, neighbour); /* one host over: still just the /32 block */
    CHECK_EQ(MARLIN_ACL_BLOCK, marlin_acl_check(&m));
}

MARLIN_TEST(acl_v4_allow_bit_clear_lets_the_covering_block_decide)
{
    struct marlin_ctx m;

    mctx_init(&m, AF_INET, CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));
    acl_stub_add4(&acl_allow_v4, 32, ACL_ADDR4(10, 105, 105, 105), 1);
    acl_stub_add4(&acl_block_v4, 8, ACL_ADDR4(10, 0, 0, 0), 2);
    mctx_src4(&m, ACL_ADDR4(10, 105, 105, 105));

    CHECK_EQ(MARLIN_ACL_BLOCK, marlin_acl_check(&m));
    CHECK_EQ(0, acl_stub_lookups(&acl_allow_v4));
    CHECK_EQ(1, acl_stub_lookups(&acl_block_v4));
}

MARLIN_TEST(acl_v4_block_bit_clear_skips_a_present_block_rule)
{
    struct marlin_ctx m;

    mctx_init(&m, AF_INET, CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_ALLOW, ACL_FAMILY_V4));
    acl_stub_add4(&acl_block_v4, 32, ACL_ADDR4(10, 100, 100, 100), 1);
    mctx_src4(&m, ACL_ADDR4(10, 100, 100, 100));

    CHECK_EQ(MARLIN_ACL_NONE, marlin_acl_check(&m));
    CHECK_EQ(0, acl_stub_lookups(&acl_block_v4));
}

MARLIN_TEST(acl_v6_allow_bit_clear_lets_the_covering_block_decide)
{
    struct marlin_ctx m;

    mctx_init(&m, AF_INET6, CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V6));
    acl_stub_add6(&acl_allow_v6, 128, SRC6, 1);
    acl_stub_add6(&acl_block_v6, 32, SRC6, 2);
    mctx_src6(&m, SRC6);

    CHECK_EQ(MARLIN_ACL_BLOCK, marlin_acl_check(&m));
    CHECK_EQ(0, acl_stub_lookups(&acl_allow_v6));
    CHECK_EQ(1, acl_stub_lookups(&acl_block_v6));
}

MARLIN_TEST(acl_v6_block_bit_clear_skips_a_present_block_rule)
{
    struct marlin_ctx m;

    mctx_init(&m, AF_INET6, CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_ALLOW, ACL_FAMILY_V6));
    acl_stub_add6(&acl_block_v6, 128, SRC6, 1);
    mctx_src6(&m, SRC6);

    CHECK_EQ(MARLIN_ACL_NONE, marlin_acl_check(&m));
    CHECK_EQ(0, acl_stub_lookups(&acl_block_v6));
}

MARLIN_TEST(acl_v4_bit_set_on_an_empty_trie_still_looks_up)
{
    struct marlin_ctx m;

    mctx_init(&m, AF_INET, CFG_ACL_ENABLE, ACL_BOTH_V4);
    mctx_src4(&m, ACL_ADDR4(10, 1, 1, 1));

    CHECK_EQ(MARLIN_ACL_NONE, marlin_acl_check(&m));
    CHECK_EQ(1, acl_stub_lookups(&acl_allow_v4));
    CHECK_EQ(1, acl_stub_lookups(&acl_block_v4));
    CHECK_EQ(32, acl_stub_last_prefixlen(&acl_block_v4));
}

MARLIN_TEST(acl_v4_key_is_full_width_and_tuple_src_verbatim)
{
    struct marlin_ctx m;
    __be32 src = ACL_ADDR4(203, 0, 113, 9);

    mctx_init(&m, AF_INET, CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));
    acl_stub_add4(&acl_block_v4, 32, ACL_ADDR4(198, 51, 100, 1), 1); /* a deliberate miss */
    mctx_src4(&m, src);

    CHECK_EQ(MARLIN_ACL_NONE, marlin_acl_check(&m));
    CHECK_EQ(32, acl_stub_last_prefixlen(&acl_block_v4));
    CHECK_EQ(4, acl_stub_last_addr_len(&acl_block_v4));
    CHECK_MEM(&src, acl_stub_last_addr(&acl_block_v4), 4);
}

MARLIN_TEST(acl_v6_key_is_full_width_and_tuple_src_verbatim)
{
    struct marlin_ctx m;

    mctx_init(&m, AF_INET6, CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V6));
    acl_stub_add6(&acl_block_v6, 128, DST6, 1); /* a deliberate miss */
    mctx_src6(&m, SRC6);

    CHECK_EQ(MARLIN_ACL_NONE, marlin_acl_check(&m));
    CHECK_EQ(128, acl_stub_last_prefixlen(&acl_block_v6));
    CHECK_EQ(16, acl_stub_last_addr_len(&acl_block_v6));
    CHECK_MEM(SRC6, acl_stub_last_addr(&acl_block_v6), 16);
}

MARLIN_TEST(acl_v4_ignores_dst_ports_and_proto)
{
    struct marlin_ctx m;

    /*
     * mctx_init poisons the whole context, so dst, sport, dport and proto
     * all hold 0xAA.. here -- and the seeded rule is on that same value, so
     * a lookup keyed on any of them would match and block.
     */
    mctx_init(&m, AF_INET, CFG_ACL_ENABLE, ACL_BOTH_V4);
    acl_stub_add4(&acl_block_v4, 32, m.tuple.dst[0], 1);
    mctx_src4(&m, ACL_ADDR4(10, 1, 1, 1));

    CHECK_EQ(MARLIN_ACL_NONE, marlin_acl_check(&m));
}

MARLIN_TEST(acl_v4_tuple_ignores_the_upper_src_words)
{
    struct marlin_ctx m;

    /*
     * src[1..3] stay poisoned: an implementation that memcpy'd 16 bytes
     * into an acl_key4-shaped key would take them into the comparison.
     */
    mctx_init(&m, AF_INET, CFG_ACL_ENABLE, ACL_LISTS_BIT(ACL_LIST_BLOCK, ACL_FAMILY_V4));
    acl_stub_add4(&acl_block_v4, 32, ACL_ADDR4(10, 20, 20, 20), 1);
    mctx_src4(&m, ACL_ADDR4(10, 20, 20, 20));

    CHECK_EQ(MARLIN_ACL_BLOCK, marlin_acl_check(&m));
}

MARLIN_TEST(acl_v4_source_does_not_reach_the_v6_tries)
{
    struct marlin_ctx m;
    unsigned char wide[16];

    memset(wide, 0, sizeof(wide));

    mctx_init(&m, AF_INET, CFG_ACL_ENABLE, (__u16)(ACL_BOTH_V4 | ACL_BOTH_V6));
    mctx_src4(&m, ACL_ADDR4(10, 20, 20, 20));
    memcpy(wide, &m.tuple.src[0], 4);
    acl_stub_add6(&acl_block_v6, 128, wide, 1);

    CHECK_EQ(MARLIN_ACL_NONE, marlin_acl_check(&m));
    CHECK_EQ(0, acl_stub_lookups(&acl_block_v6));
    CHECK_EQ(0, acl_stub_lookups(&acl_allow_v6));
    CHECK_EQ(1, acl_stub_lookups(&acl_block_v4));
}

MARLIN_TEST(acl_v6_source_does_not_reach_the_v4_tries)
{
    struct marlin_ctx m;

    mctx_init(&m, AF_INET6, CFG_ACL_ENABLE, (__u16)(ACL_BOTH_V4 | ACL_BOTH_V6));
    mctx_src6(&m, SRC6);
    acl_stub_add4(&acl_block_v4, 32, (__be32)SRC6[0], 1);

    CHECK_EQ(MARLIN_ACL_NONE, marlin_acl_check(&m));
    CHECK_EQ(0, acl_stub_lookups(&acl_block_v4));
    CHECK_EQ(1, acl_stub_lookups(&acl_block_v6));
}

int main(void)
{
    return marlin_tests_main();
}
