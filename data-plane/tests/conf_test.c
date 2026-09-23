/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Native unit tests for marlind's file configuration: coercion
 * (conf_value.c), the parser (conf.c), and validation (conf_check.c).
 * #includes the three .c files directly, the parser_test.c pattern for a
 * translation unit that is not header-only -- see docs/REPO-STRUCTURE.md
 * Principle 5's exception. Pure host code: no bpf_* helper, no map, so
 * nothing here needs tests/stubs beyond what TEST_INCLUDES already adds.
 */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../marlind/conf_value.c"
#include "../marlind/conf_check.c"
#include "../marlind/conf.c"

#include "harness.h"

/* ---- coercion ------------------------------------------------------------ */

MARLIN_TEST(parse_ipv4_accepts_and_rejects)
{
    __be32 out;

    CHECK_TRUE(conf_parse_ipv4("203.0.113.1", &out));
    CHECK_TRUE(!conf_parse_ipv4("2001:db8::1", &out));
    CHECK_TRUE(!conf_parse_ipv4("not-an-address", &out));
    CHECK_TRUE(!conf_parse_ipv4("256.0.0.1", &out));
}

MARLIN_TEST(parse_ipv6_accepts_and_rejects)
{
    __u8 out[16];

    CHECK_TRUE(conf_parse_ipv6("2001:db8::1", out));
    CHECK_TRUE(!conf_parse_ipv6("203.0.113.1", out));
    CHECK_TRUE(!conf_parse_ipv6("not-an-address", out));
}

MARLIN_TEST(parse_mac_accepts_and_rejects)
{
    __u8 out[6];

    CHECK_TRUE(conf_parse_mac("52:54:00:ab:cd:01", out));
    CHECK_EQ(0x52, out[0]);
    CHECK_EQ(0x01, out[5]);

    CHECK_TRUE(!conf_parse_mac("52:54:00:ab:cd", out));       /* too short */
    CHECK_TRUE(!conf_parse_mac("52:54:00:ab:cd:01:02", out)); /* too long */
    CHECK_TRUE(!conf_parse_mac("52:54:00:ab:cd:zz", out));    /* not hex */
    CHECK_TRUE(!conf_parse_mac("52:54:00:ab:cd:01extra", out));
}

MARLIN_TEST(parse_hexkey16_requires_exactly_32_hex_digits)
{
    __u8 out[16];

    CHECK_TRUE(conf_parse_hexkey16("00112233445566778899aabbccddeeff", out)); /* exactly 32 hex digits */
    CHECK_EQ(0x00, out[0]);
    CHECK_EQ(0xff, out[15]);

    CHECK_TRUE(!conf_parse_hexkey16("00112233445566778899aabbccddeeff0", out)); /* 33 digits */
    CHECK_TRUE(!conf_parse_hexkey16("00112233445566778899aabbccddee", out));    /* 30 digits */
    CHECK_TRUE(conf_parse_hexkey16("00112233445566778899AABBCCDDEEFF", out));   /* uppercase accepted */
    CHECK_TRUE(!conf_parse_hexkey16("00112233445566778899aabbccddeeg0", out));  /* one non-hex nibble */
}

MARLIN_TEST(parse_proto_and_mode_and_state)
{
    __u8 proto;
    __u8 mode;
    bool up;

    CHECK_TRUE(conf_parse_proto("tcp", &proto));
    CHECK_EQ(IPPROTO_TCP, proto);
    CHECK_TRUE(conf_parse_proto("udp", &proto));
    CHECK_EQ(IPPROTO_UDP, proto);
    CHECK_TRUE(!conf_parse_proto("icmp", &proto));

    CHECK_TRUE(conf_parse_mode("vxlan", &mode));
    CHECK_EQ(MARLIN_MODE_VXLAN, mode);
    CHECK_TRUE(!conf_parse_mode("sit", &mode));

    CHECK_TRUE(conf_parse_state("up", &up) && up);
    CHECK_TRUE(conf_parse_state("down", &up) && !up);
    CHECK_TRUE(!conf_parse_state("maybe", &up));
}

MARLIN_TEST(parse_cidr_splits_family_and_reports_bits_as_given)
{
    bool is_v6;
    __u32 prefixlen;
    __u8 addr[16];

    CHECK_TRUE(conf_parse_cidr("10.0.0.0/8", &is_v6, &prefixlen, addr));
    CHECK_TRUE(!is_v6);
    CHECK_EQ(8, prefixlen);
    CHECK_TRUE(!conf_cidr_host_bits_set(addr, prefixlen, is_v6));

    /* 10.1.2.3/8 carries host bits under an /8 mask -- reported, not silently cleared. */
    CHECK_TRUE(conf_parse_cidr("10.1.2.3/8", &is_v6, &prefixlen, addr));
    CHECK_TRUE(conf_cidr_host_bits_set(addr, prefixlen, is_v6));

    CHECK_TRUE(conf_parse_cidr("2001:db8::/32", &is_v6, &prefixlen, addr));
    CHECK_TRUE(is_v6);
    CHECK_EQ(32, prefixlen);

    CHECK_TRUE(!conf_parse_cidr("10.0.0.0/33", &is_v6, &prefixlen, addr));    /* exceeds v4 width */
    CHECK_TRUE(!conf_parse_cidr("2001:db8::/129", &is_v6, &prefixlen, addr)); /* exceeds v6 width */
    CHECK_TRUE(!conf_parse_cidr("not-a-cidr", &is_v6, &prefixlen, addr));
    CHECK_TRUE(!conf_parse_cidr("10.0.0.0", &is_v6, &prefixlen, addr)); /* no slash */
}

/* ---- file helpers --------------------------------------------------------- */

static char *write_temp_conf(const char *content)
{
    static char path[] = "/tmp/marlin_conf_test_XXXXXX";
    char *p = strdup(path);
    int fd = mkstemp(p);

    CHECK_TRUE(fd >= 0);
    if(fd >= 0) {
        ssize_t len = (ssize_t)strlen(content);

        CHECK_EQ(len, write(fd, content, (size_t)len));
        close(fd);
    }
    return p;
}

static const char *golden_path(void)
{
    /* `make tests` runs from data-plane/ (docs/TESTING.md §5.3). */
    static const char *candidates[] = { "../deploy/marlin.conf.example", "deploy/marlin.conf.example" };

    for(size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        if(access(candidates[i], R_OK) == 0) {
            return candidates[i];
        }
    }
    return NULL;
}

/* ---- full-parse: the example config is the fixture that keeps itself honest --- */

MARLIN_TEST(golden_example_config_parses_and_validates)
{
    const char *path = golden_path();
    struct conf_diag diag;
    struct marlin_conf *conf;

    if(path == NULL) {
        MARLIN_SKIP("deploy/marlin.conf.example not found from this working directory");
    }

    conf_diag_reset(&diag);
    conf = conf_load(path, CONF_LOAD_FULL, false, &diag);
    for(__u32 i = 0; i < diag.count; i++) {
        MARLIN_FAIL("unexpected rejection: %s", diag.msg[i]);
    }
    CHECK_TRUE(conf != NULL);
    if(conf == NULL) {
        return;
    }

    CHECK_EQ(5, conf->backend_count);
    CHECK_EQ(3, conf->vip_count);
    CHECK_TRUE(conf->instance.tunnel_src_set);
    CHECK_EQ(2, conf->instance.tx_port_count);

    /*
     * Regression: vip[0] states acl/ratelimit only. A shared "flag" local
     * reused across get_bool() calls without being reset on an absent key
     * once leaked the previous key's value into hash_5tuple/quic -- see
     * parse_vip_flag_bits().
     */
    CHECK_EQ(VIP_ACL | VIP_RATELIMIT, conf->vips[0].meta.flags);

    /* vip[1] is the QUIC one: acl, quic, quic_cid_len=8, dscp=46. */
    CHECK_TRUE((conf->vips[1].meta.flags & VIP_ACL) != 0);
    CHECK_TRUE((conf->vips[1].meta.flags & VIP_QUIC) != 0);
    CHECK_EQ(8, VIP_QUIC_CID_LEN(conf->vips[1].meta.flags));
    CHECK_EQ(46, VIP_DSCP(conf->vips[1].meta.flags));

    /* vip[2] is IPv6 with an explicit port of 0 ("any port"), not port-absent-defaults-elsewhere. */
    CHECK_EQ(AF_INET6, conf->vips[2].key.family);
    CHECK_EQ(0, conf->vips[2].key.port);

    conf_free(conf);
}

/* ---- rejections: through the real parser, one representative case per rule --- */

MARLIN_TEST(backend_id_zero_is_rejected)
{
    static const char *text = "[instance]\ninterface=\"lo\"\n"
                              "[[backend]]\nname=\"b\"\nid=0\naddr=\"10.0.0.1\"\nmode=\"l2dsr\"\n"
                              "[[vip]]\naddr=\"203.0.113.1\"\nport=80\nproto=\"tcp\"\n"
                              "hash_key=\"00112233445566778899aabbccddeeff\"\n"
                              "table_seed=\"ffeeddccbbaa99887766554433221100\"\n"
                              "members=[{backend=\"b\",weight=1}]\n";
    char *path = write_temp_conf(text);
    struct conf_diag diag;

    conf_diag_reset(&diag);
    CHECK_TRUE(conf_load(path, CONF_LOAD_FULL, false, &diag) == NULL);
    CHECK_TRUE(diag.count > 0);
    unlink(path);
    free(path);
}

MARLIN_TEST(duplicate_backend_id_is_rejected)
{
    static const char *text = "[instance]\ninterface=\"lo\"\n"
                              "[[backend]]\nname=\"b1\"\nid=1\naddr=\"10.0.0.1\"\nmode=\"l2dsr\"\n"
                              "[[backend]]\nname=\"b2\"\nid=1\naddr=\"10.0.0.2\"\nmode=\"l2dsr\"\n";
    char *path = write_temp_conf(text);
    struct conf_diag diag;

    conf_diag_reset(&diag);
    CHECK_TRUE(conf_load(path, CONF_LOAD_FULL, false, &diag) == NULL);
    unlink(path);
    free(path);
}

MARLIN_TEST(vip_member_naming_unknown_backend_is_rejected)
{
    static const char *text = "[instance]\ninterface=\"lo\"\n"
                              "[[backend]]\nname=\"b1\"\nid=1\naddr=\"10.0.0.1\"\nmode=\"l2dsr\"\n"
                              "[[vip]]\naddr=\"203.0.113.1\"\nport=80\nproto=\"tcp\"\n"
                              "hash_key=\"00112233445566778899aabbccddeeff\"\n"
                              "table_seed=\"ffeeddccbbaa99887766554433221100\"\n"
                              "members=[{backend=\"nope\",weight=1}]\n";
    char *path = write_temp_conf(text);
    struct conf_diag diag;

    conf_diag_reset(&diag);
    CHECK_TRUE(conf_load(path, CONF_LOAD_FULL, false, &diag) == NULL);
    unlink(path);
    free(path);
}

MARLIN_TEST(vxlan_backend_requires_vni_and_inner_mac)
{
    static const char *text = "[instance]\ninterface=\"lo\"\ntunnel_src=\"203.0.113.10\"\n"
                              "[[backend]]\nname=\"b1\"\nid=1\naddr=\"10.0.0.1\"\nmode=\"vxlan\"\n";
    char *path = write_temp_conf(text);
    struct conf_diag diag;

    conf_diag_reset(&diag);
    CHECK_TRUE(conf_load(path, CONF_LOAD_FULL, false, &diag) == NULL);
    unlink(path);
    free(path);
}

MARLIN_TEST(non_vxlan_backend_rejects_vni_and_inner_mac)
{
    static const char *text = "[instance]\ninterface=\"lo\"\n"
                              "[[backend]]\nname=\"b1\"\nid=1\naddr=\"10.0.0.1\"\nmode=\"l2dsr\"\nvni=100\n";
    char *path = write_temp_conf(text);
    struct conf_diag diag;

    conf_diag_reset(&diag);
    CHECK_TRUE(conf_load(path, CONF_LOAD_FULL, false, &diag) == NULL);
    unlink(path);
    free(path);
}

MARLIN_TEST(hash_key_wrong_length_is_rejected)
{
    static const char *text = "[instance]\ninterface=\"lo\"\n"
                              "[[backend]]\nname=\"b1\"\nid=1\naddr=\"10.0.0.1\"\nmode=\"l2dsr\"\n"
                              "[[vip]]\naddr=\"203.0.113.1\"\nport=80\nproto=\"tcp\"\n"
                              "hash_key=\"00112233\"\n"
                              "table_seed=\"ffeeddccbbaa99887766554433221100\"\n"
                              "members=[{backend=\"b1\",weight=1}]\n";
    char *path = write_temp_conf(text);
    struct conf_diag diag;

    conf_diag_reset(&diag);
    CHECK_TRUE(conf_load(path, CONF_LOAD_FULL, false, &diag) == NULL);
    unlink(path);
    free(path);
}

MARLIN_TEST(acl_default_route_allow_is_rejected)
{
    static const char *text = "[instance]\ninterface=\"lo\"\n"
                              "[acl]\nenabled=true\nallow=[\"0.0.0.0/0\"]\n"
                              "[[backend]]\nname=\"b1\"\nid=1\naddr=\"10.0.0.1\"\nmode=\"l2dsr\"\n";
    char *path = write_temp_conf(text);
    struct conf_diag diag;

    conf_diag_reset(&diag);
    CHECK_TRUE(conf_load(path, CONF_LOAD_FULL, false, &diag) == NULL);
    unlink(path);
    free(path);
}

MARLIN_TEST(acl_prefix_with_host_bits_is_rejected)
{
    static const char *text = "[instance]\ninterface=\"lo\"\n"
                              "[acl]\nenabled=true\nblock=[\"10.1.2.3/8\"]\n"
                              "[[backend]]\nname=\"b1\"\nid=1\naddr=\"10.0.0.1\"\nmode=\"l2dsr\"\n";
    char *path = write_temp_conf(text);
    struct conf_diag diag;

    conf_diag_reset(&diag);
    CHECK_TRUE(conf_load(path, CONF_LOAD_FULL, false, &diag) == NULL);
    unlink(path);
    free(path);
}

MARLIN_TEST(ratelimit_without_acl_is_rejected)
{
    static const char *text = "[instance]\ninterface=\"lo\"\n"
                              "[ratelimit]\nenabled=true\ntokens_per_sec=100\nburst_packets=100\n"
                              "[[backend]]\nname=\"b1\"\nid=1\naddr=\"10.0.0.1\"\nmode=\"l2dsr\"\n";
    char *path = write_temp_conf(text);
    struct conf_diag diag;

    conf_diag_reset(&diag);
    CHECK_TRUE(conf_load(path, CONF_LOAD_FULL, false, &diag) == NULL);
    unlink(path);
    free(path);
}

MARLIN_TEST(quic_without_cid_len_is_rejected)
{
    static const char *text = "[instance]\ninterface=\"lo\"\n"
                              "[[backend]]\nname=\"b1\"\nid=1\naddr=\"10.0.0.1\"\nmode=\"l2dsr\"\n"
                              "[[vip]]\naddr=\"203.0.113.1\"\nport=80\nproto=\"tcp\"\n"
                              "hash_key=\"00112233445566778899aabbccddeeff\"\n"
                              "table_seed=\"ffeeddccbbaa99887766554433221100\"\n"
                              "quic=true\n"
                              "members=[{backend=\"b1\",weight=1}]\n";
    char *path = write_temp_conf(text);
    struct conf_diag diag;

    conf_diag_reset(&diag);
    CHECK_TRUE(conf_load(path, CONF_LOAD_FULL, false, &diag) == NULL);
    unlink(path);
    free(path);
}

/* ---- permission enforcement ------------------------------------------------ */

MARLIN_TEST(enforce_perms_rejects_a_group_writable_file)
{
    char *path = write_temp_conf("[instance]\ninterface=\"lo\"\n");
    struct conf_diag diag;
    struct marlin_conf *conf;

    CHECK_TRUE(chmod(path, 0660) == 0);

    conf_diag_reset(&diag);
    CHECK_TRUE(conf_load(path, CONF_LOAD_INSTANCE_ONLY, true, &diag) == NULL);
    CHECK_TRUE(diag.count > 0);

    /* --check's posture: same file, same mode, warned rather than refused. */
    conf_diag_reset(&diag);
    conf = conf_load(path, CONF_LOAD_INSTANCE_ONLY, false, &diag);
    CHECK_TRUE(conf != NULL);
    CHECK_TRUE(diag.warn_count > 0);
    conf_free(conf);

    unlink(path);
    free(path);
}

/* ---- conf_check() against hand-built models, no file involved -------------- */

static void init_minimal_vip(struct conf_vip *vip, struct conf_member *members, __u32 member_count)
{
    memset(vip, 0, sizeof(*vip));
    vip->key.addr4 = 0x0100007f; /* 127.0.0.1, irrelevant to these checks */
    vip->key.family = AF_INET;
    vip->key.proto = IPPROTO_TCP;
    memset(vip->meta.hash_key, 0x11, sizeof(vip->meta.hash_key));
    memset(vip->table_seed, 0x22, sizeof(vip->table_seed));
    vip->meta.vip_num = MARLIN_CONF_VIP_NUM_UNSET;
    vip->members = members;
    vip->member_count = member_count;
}

MARLIN_TEST(check_rejects_ratelimit_flag_without_acl_flag)
{
    struct marlin_conf conf;
    struct conf_backend backend;
    struct conf_member member;
    struct conf_vip vip;
    struct conf_diag diag;

    memset(&conf, 0, sizeof(conf));
    memset(&backend, 0, sizeof(backend));
    (void)snprintf(backend.name, sizeof(backend.name), "b1");
    backend.id = 1;
    backend.abi.addr = 0x0101000a;
    backend.abi.flags = MARLIN_BE_F_STATE;

    (void)snprintf(member.backend_name, sizeof(member.backend_name), "b1");
    member.weight = 1;

    init_minimal_vip(&vip, &member, 1);
    vip.meta.flags = VIP_RATELIMIT; /* VIP_ACL deliberately clear */

    conf.instance.iface[0] = '\0';
    conf.backends = &backend;
    conf.backend_count = 1;
    conf.vips = &vip;
    conf.vip_count = 1;

    conf_diag_reset(&diag);
    CHECK_TRUE(!conf_check(&conf, &diag));
}

MARLIN_TEST(check_against_previous_rejects_in_place_backend_edit)
{
    struct marlin_conf cur, prev;
    struct conf_backend cur_b, prev_b;
    struct conf_diag diag;

    memset(&cur, 0, sizeof(cur));
    memset(&prev, 0, sizeof(prev));
    memset(&cur_b, 0, sizeof(cur_b));
    memset(&prev_b, 0, sizeof(prev_b));

    prev_b.id = 1;
    prev_b.abi.addr = 0x0101000a;
    cur_b.id = 1;
    cur_b.abi.addr = 0x0201000a; /* changed in place -- disallowed */

    cur.backends = &cur_b;
    cur.backend_count = 1;
    prev.backends = &prev_b;
    prev.backend_count = 1;

    conf_diag_reset(&diag);
    CHECK_TRUE(!conf_check_against_previous(&cur, &prev, &diag));
    CHECK_TRUE(diag.count > 0);
}

MARLIN_TEST(check_against_previous_rejects_changed_interface)
{
    struct marlin_conf cur, prev;
    struct conf_diag diag;

    memset(&cur, 0, sizeof(cur));
    memset(&prev, 0, sizeof(prev));
    (void)snprintf(cur.instance.iface, sizeof(cur.instance.iface), "eth1");
    (void)snprintf(prev.instance.iface, sizeof(prev.instance.iface), "eth0");

    conf_diag_reset(&diag);
    CHECK_TRUE(!conf_check_against_previous(&cur, &prev, &diag));
}

MARLIN_TEST(check_against_previous_accepts_an_unrelated_addition)
{
    struct marlin_conf cur, prev;
    struct conf_backend cur_b;
    struct conf_diag diag;

    memset(&cur, 0, sizeof(cur));
    memset(&prev, 0, sizeof(prev));
    memset(&cur_b, 0, sizeof(cur_b));
    (void)snprintf(cur.instance.iface, sizeof(cur.instance.iface), "eth0");
    (void)snprintf(prev.instance.iface, sizeof(prev.instance.iface), "eth0");

    cur_b.id = 7; /* new backend id absent from prev: not an edit */
    cur.backends = &cur_b;
    cur.backend_count = 1;

    conf_diag_reset(&diag);
    CHECK_TRUE(conf_check_against_previous(&cur, &prev, &diag));
}

int main(void)
{
    return marlin_tests_main();
}
