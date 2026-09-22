/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Drives the vendored TOML parser (vendor/README.md) and lowers the result
 * into a struct marlin_conf. Owns every byte the model holds: every string
 * and array here is copied out of the toml_result_t before it is freed, so
 * the model outlives the parse (see conf.h).
 *
 * Shape errors (wrong type, out of range, unresolvable) are reported here,
 * inline with the parse; conf_check() (conf_check.c) runs afterwards for
 * rules that need the whole model at once.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <tomlc17.h>

#include <marlin/abi/defines.h>
#include <marlind/conf.h>
#include <marlind/conf_check.h>
#include <marlind/conf_value.h>
#include <marlind/marlind.h>

/* ---- diagnostics ------------------------------------------------------- */

void conf_diag_reset(struct conf_diag *diag)
{
    memset(diag, 0, sizeof(*diag));
}

static void diag_append(char arr[][MARLIN_CONF_DIAG_LEN], __u32 *count, __u32 *dropped, const char *fmt, va_list ap)
{
    if(*count >= MARLIN_CONF_DIAG_MAX) {
        (*dropped)++;
        return;
    }
    (void)vsnprintf(arr[*count], MARLIN_CONF_DIAG_LEN, fmt, ap);
    (*count)++;
}

void conf_diag_add(struct conf_diag *diag, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    diag_append(diag->msg, &diag->count, &diag->dropped, fmt, ap);
    va_end(ap);
}

void conf_diag_warn(struct conf_diag *diag, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    diag_append(diag->warn, &diag->warn_count, &diag->warn_dropped, fmt, ap);
    va_end(ap);
}

/* ---- generic TOML accessors, consistent (present, out) semantics ------- */

/*
 * *out is always written, even when the key is absent (to false) -- never
 * left holding whatever the caller's variable happened to contain before
 * the call. Every boolean in this schema defaults to false when omitted,
 * and a caller that reuses one bool across several keys (parse_vip_flag_bits)
 * depends on that: forgetting it once produced flags leaking from one key
 * to the next.
 */
static bool get_bool(toml_datum_t tab, const char *key, const char *path, struct conf_diag *diag, bool *present, bool *out)
{
    toml_datum_t datum = toml_get(tab, key);

    *present = datum.type != TOML_UNKNOWN;
    if(!*present) {
        *out = false;
        return true;
    }
    if(datum.type != TOML_BOOLEAN) {
        conf_diag_add(diag, "%s.%s must be a boolean", path, key);
        return false;
    }
    *out = datum.u.boolean;
    return true;
}

/* Same "*out always written" discipline as get_bool() above; absent defaults to 0. */
static bool get_int(toml_datum_t tab, const char *key, const char *path, struct conf_diag *diag, bool *present, int64_t *out)
{
    toml_datum_t datum = toml_get(tab, key);

    *present = datum.type != TOML_UNKNOWN;
    if(!*present) {
        *out = 0;
        return true;
    }
    if(datum.type != TOML_INT64) {
        conf_diag_add(diag, "%s.%s must be an integer", path, key);
        return false;
    }
    *out = datum.u.int64;
    return true;
}

/* out/outsz travel together as a single param so get_str stays under the
 * 6-parameter readability-function-size threshold. */
struct str_out {
    char *buf;
    size_t cap;
};

static bool get_str(toml_datum_t tab, const char *key, const char *path, struct conf_diag *diag, bool *present, struct str_out out)
{
    toml_datum_t datum = toml_get(tab, key);

    if(datum.type == TOML_UNKNOWN) {
        *present = false;
        return true;
    }
    *present = true;
    if(datum.type != TOML_STRING) {
        conf_diag_add(diag, "%s.%s must be a string", path, key);
        return false;
    }
    if((size_t)datum.u.str.len >= out.cap) {
        conf_diag_add(diag, "%s.%s is too long (max %zu bytes)", path, key, out.cap - 1);
        return false;
    }
    memcpy(out.buf, datum.u.str.ptr, (size_t)datum.u.str.len);
    out.buf[datum.u.str.len] = '\0';
    return true;
}

static bool req_str(toml_datum_t tab, const char *key, const char *path, struct conf_diag *diag, char *out, size_t outsz)
{
    bool present = false;

    if(!get_str(tab, key, path, diag, &present, (struct str_out){ out, outsz })) {
        return false;
    }
    if(!present) {
        conf_diag_add(diag, "%s.%s is required", path, key);
        return false;
    }
    return true;
}

/* ---- [instance] --------------------------------------------------------- */

static void parse_instance_tx_ports(toml_datum_t tab, struct conf_instance *inst, struct conf_diag *diag)
{
    toml_datum_t tx = toml_get(tab, "tx_ports");

    if(tx.type == TOML_UNKNOWN) {
        return;
    }
    if(tx.type != TOML_ARRAY) {
        conf_diag_add(diag, "instance.tx_ports must be an array of strings");
        return;
    }
    if(tx.u.arr.size > MAX_TX_PORTS) {
        conf_diag_add(diag, "instance.tx_ports has %d entries, more than MAX_TX_PORTS (%u)", tx.u.arr.size, MAX_TX_PORTS);
    }

    for(int32_t i = 0; i < tx.u.arr.size && inst->tx_port_count < MAX_TX_PORTS; i++) {
        toml_datum_t elem = tx.u.arr.elem[i];

        if(elem.type != TOML_STRING || (size_t)elem.u.str.len >= sizeof(inst->tx_ports[0])) {
            conf_diag_add(diag, "instance.tx_ports[%d] is not a valid interface name", i);
            continue;
        }
        memcpy(inst->tx_ports[inst->tx_port_count], elem.u.str.ptr, (size_t)elem.u.str.len);
        inst->tx_ports[inst->tx_port_count][elem.u.str.len] = '\0';
        inst->tx_port_count++;
    }
}

static void parse_instance(toml_datum_t top, struct conf_instance *inst, struct conf_diag *diag)
{
    toml_datum_t tab = toml_get(top, "instance");
    bool present = false;
    char tunnel_src_str[64];
    int64_t max_frame;

    if(tab.type != TOML_TABLE) {
        conf_diag_add(diag, "[instance] is required");
        return;
    }

    (void)req_str(tab, "interface", "instance", diag, inst->iface, sizeof(inst->iface));

    if(!get_str(tab, "object", "instance", diag, &present, (struct str_out){ inst->object, sizeof(inst->object) }) || !present) {
        (void)snprintf(inst->object, sizeof(inst->object), "%s", MARLIN_DEFAULT_OBJ);
    }
    if(!get_str(tab, "pin_dir", "instance", diag, &present, (struct str_out){ inst->pin_dir, sizeof(inst->pin_dir) }) || !present) {
        (void)snprintf(inst->pin_dir, sizeof(inst->pin_dir), "%s", MARLIN_DEFAULT_PIN_DIR);
    }

    if(get_str(tab, "tunnel_src", "instance", diag, &present, (struct str_out){ tunnel_src_str, sizeof(tunnel_src_str) }) && present) {
        if(!conf_parse_ipv4(tunnel_src_str, &inst->tunnel_src)) {
            conf_diag_add(diag, "instance.tunnel_src is not a valid IPv4 address");
        } else {
            inst->tunnel_src_set = true;
        }
    }

    parse_instance_tx_ports(tab, inst, diag);

    if(get_int(tab, "max_frame", "instance", diag, &present, &max_frame) && present) {
        if(max_frame < 0 || max_frame > 0xffff) {
            conf_diag_add(diag, "instance.max_frame out of range (0-65535)");
        } else {
            inst->max_frame = (__u16)max_frame;
            inst->max_frame_set = true;
        }
    }
}

/* ---- [acl] --------------------------------------------------------------- */

static bool append_acl_entry(struct conf_acl_entry **arr, __u32 *count, __u32 prefixlen, const __u8 addr[16])
{
    struct conf_acl_entry *grown = realloc(*arr, ((size_t)*count + 1) * sizeof(**arr));

    if(grown == NULL) {
        return false;
    }
    *arr = grown;
    grown[*count].prefixlen = prefixlen;
    memcpy(grown[*count].addr, addr, 16);
    (*count)++;
    return true;
}

static void parse_acl_array(toml_datum_t tab, const char *key, struct conf_acl *acl, bool is_allow, struct conf_diag *diag)
{
    toml_datum_t arr = toml_get(tab, key);

    if(arr.type == TOML_UNKNOWN) {
        return;
    }
    if(arr.type != TOML_ARRAY) {
        conf_diag_add(diag, "acl.%s must be an array of strings", key);
        return;
    }

    for(int32_t i = 0; i < arr.u.arr.size; i++) {
        toml_datum_t elem = arr.u.arr.elem[i];
        bool is_v6 = false;
        __u32 prefixlen = 0;
        __u8 addr[16];
        bool ok;

        if(elem.type != TOML_STRING || !conf_parse_cidr(elem.u.s, &is_v6, &prefixlen, addr)) {
            conf_diag_add(diag, "acl.%s[%d] is not a valid CIDR prefix", key, i);
            continue;
        }

        if(is_allow) {
            ok = is_v6 ? append_acl_entry(&acl->allow_v6, &acl->allow_v6_count, prefixlen, addr)
                       : append_acl_entry(&acl->allow_v4, &acl->allow_v4_count, prefixlen, addr);
        } else {
            ok = is_v6 ? append_acl_entry(&acl->block_v6, &acl->block_v6_count, prefixlen, addr)
                       : append_acl_entry(&acl->block_v4, &acl->block_v4_count, prefixlen, addr);
        }
        if(!ok) {
            conf_diag_add(diag, "out of memory parsing acl.%s[%d]", key, i);
        }
    }
}

static void parse_acl(toml_datum_t top, struct conf_acl *acl, struct conf_diag *diag)
{
    toml_datum_t tab = toml_get(top, "acl");
    bool present = false;

    if(tab.type == TOML_UNKNOWN) {
        return;
    }
    if(tab.type != TOML_TABLE) {
        conf_diag_add(diag, "[acl] must be a table");
        return;
    }

    (void)get_bool(tab, "enabled", "acl", diag, &present, &acl->enabled);
    parse_acl_array(tab, "allow", acl, true, diag);
    parse_acl_array(tab, "block", acl, false, diag);
}

/* ---- [ratelimit] ----------------------------------------------------------- */

static void parse_ratelimit(toml_datum_t top, struct conf_ratelimit *rl, struct conf_diag *diag)
{
    toml_datum_t tab = toml_get(top, "ratelimit");
    bool present = false;
    int64_t val;

    if(tab.type == TOML_UNKNOWN) {
        return;
    }
    if(tab.type != TOML_TABLE) {
        conf_diag_add(diag, "[ratelimit] must be a table");
        return;
    }

    (void)get_bool(tab, "enabled", "ratelimit", diag, &present, &rl->enabled);

    if(get_int(tab, "tokens_per_sec", "ratelimit", diag, &present, &val) && present) {
        if(val < 0 || val > 0xffffffffLL) {
            conf_diag_add(diag, "ratelimit.tokens_per_sec out of range");
        } else {
            rl->tokens_per_sec = (__u32)val;
        }
    }
    if(get_int(tab, "burst_packets", "ratelimit", diag, &present, &val) && present) {
        if(val < 0 || val > 0xffffffffLL) {
            conf_diag_add(diag, "ratelimit.burst_packets out of range");
        } else {
            rl->burst_packets = (__u32)val;
        }
    }
}

/* ---- [[backend]] ------------------------------------------------------- */

static void backend_set_encap_dport_default(struct conf_backend *backend, __u8 mode, bool stated, __u16 host_value)
{
    if(stated) {
        backend->abi.encap_dport = htons(host_value);
        return;
    }
    if(mode == MARLIN_MODE_GUE) {
        backend->abi.encap_dport = htons(MARLIN_GUE_DPORT_DEFAULT);
    } else if(mode == MARLIN_MODE_VXLAN) {
        backend->abi.encap_dport = htons(MARLIN_VXLAN_DPORT_DEFAULT);
    } else {
        backend->abi.encap_dport = 0;
    }
}

static void parse_backend_id(toml_datum_t tab, struct conf_backend *backend, const char *path, struct conf_diag *diag)
{
    bool present = false;
    int64_t val;

    if(get_int(tab, "id", path, diag, &present, &val) && present) {
        if(val < 0 || val >= MAX_BACKENDS) {
            conf_diag_add(diag, "%s.id out of range (0-%u)", path, MAX_BACKENDS - 1);
        } else {
            backend->id = (__u16)val;
        }
    } else if(!present) {
        conf_diag_add(diag, "%s.id is required", path);
    }
}

static void parse_backend_addr(toml_datum_t tab, struct conf_backend *backend, const char *path, struct conf_diag *diag)
{
    char addr_str[64];

    if(req_str(tab, "addr", path, diag, addr_str, sizeof(addr_str))) {
        if(!conf_parse_ipv4(addr_str, &backend->abi.addr)) {
            conf_diag_add(diag, "%s.addr is not a valid IPv4 address", path);
        }
    }
}

static __u8 parse_backend_mode(toml_datum_t tab, struct conf_backend *backend, const char *path, struct conf_diag *diag)
{
    char mode_str[16];
    __u8 mode = MARLIN_MODE_L2DSR;

    if(req_str(tab, "mode", path, diag, mode_str, sizeof(mode_str))) {
        if(!conf_parse_mode(mode_str, &mode)) {
            conf_diag_add(diag, "%s.mode must be one of l2dsr, ipip, gue, vxlan", path);
        }
    }
    backend->abi.flags = mode;
    if(mode != MARLIN_MODE_L2DSR) {
        backend->abi.flags |= MARLIN_BE_F_ENCAP_REQUIRED;
    }
    return mode;
}

static void parse_backend_state(toml_datum_t tab, struct conf_backend *backend, const char *path, struct conf_diag *diag)
{
    char state_str[8];
    bool present = false;
    bool up = true;

    if(get_str(tab, "state", path, diag, &present, (struct str_out){ state_str, sizeof(state_str) }) && present) {
        if(!conf_parse_state(state_str, &up)) {
            conf_diag_add(diag, "%s.state must be \"up\" or \"down\"", path);
        }
    }
    if(up) {
        backend->abi.flags |= MARLIN_BE_F_STATE;
    }
}

static void parse_backend_mac(toml_datum_t tab, struct conf_backend *backend, const char *path, struct conf_diag *diag)
{
    char mac_str[32];
    bool present = false;

    if(get_str(tab, "mac", path, diag, &present, (struct str_out){ mac_str, sizeof(mac_str) }) && present) {
        if(!conf_parse_mac(mac_str, backend->abi.mac)) {
            conf_diag_add(diag, "%s.mac is not a valid MAC address", path);
        } else {
            backend->mac_stated = true;
        }
    }
}

static void parse_backend_fib_egress(toml_datum_t tab, struct conf_backend *backend, const char *path, struct conf_diag *diag)
{
    bool present = false;

    if(get_bool(tab, "fib", path, diag, &present, &backend->fib_value)) {
        backend->fib_stated = present;
    }

    if(get_str(tab, "egress", path, diag, &present, (struct str_out){ backend->egress, sizeof(backend->egress) }) && present) {
        backend->has_egress = true;
    }
}

static void parse_backend_encap(toml_datum_t tab, struct conf_backend *backend, __u8 mode, const char *path, struct conf_diag *diag)
{
    bool present = false;
    bool dport_present = false;
    int64_t val;

    if(get_int(tab, "encap_dport", path, diag, &dport_present, &val)) {
        if(dport_present && (val < 0 || val > 0xffff)) {
            conf_diag_add(diag, "%s.encap_dport out of range (0-65535)", path);
            dport_present = false;
        }
    } else {
        /*
         * get_int() already reported the type error; encap_dport must not
         * be treated as stated when val was never written.
         */
        dport_present = false;
    }
    backend_set_encap_dport_default(backend, mode, dport_present, dport_present ? (__u16)val : 0);

    if(get_int(tab, "vni", path, diag, &present, &val) && present) {
        if(val < 0 || val > 0xffffff) {
            conf_diag_add(diag, "%s.vni out of range (0-0xffffff)", path);
        } else {
            backend->abi.vni = (__u32)val;
            backend->vni_stated = true;
        }
    }
}

static void parse_backend_inner_mac(toml_datum_t tab, struct conf_backend *backend, const char *path, struct conf_diag *diag)
{
    char inner_mac_str[32];
    bool present = false;

    if(get_str(tab, "inner_mac", path, diag, &present, (struct str_out){ inner_mac_str, sizeof(inner_mac_str) }) && present) {
        if(!conf_parse_mac(inner_mac_str, backend->abi.inner_mac)) {
            conf_diag_add(diag, "%s.inner_mac is not a valid MAC address", path);
        } else {
            backend->inner_mac_stated = true;
        }
    }
}

static void parse_one_backend(toml_datum_t tab, struct conf_backend *backend, __u32 idx, struct conf_diag *diag)
{
    char path[32];
    __u8 mode;

    (void)snprintf(path, sizeof(path), "backend[%u]", idx);
    (void)req_str(tab, "name", path, diag, backend->name, sizeof(backend->name));

    parse_backend_id(tab, backend, path, diag);
    parse_backend_addr(tab, backend, path, diag);
    mode = parse_backend_mode(tab, backend, path, diag);
    parse_backend_state(tab, backend, path, diag);
    parse_backend_mac(tab, backend, path, diag);
    parse_backend_fib_egress(tab, backend, path, diag);
    parse_backend_encap(tab, backend, mode, path, diag);
    parse_backend_inner_mac(tab, backend, path, diag);
}

static void parse_backends(toml_datum_t top, struct marlin_conf *conf, struct conf_diag *diag)
{
    toml_datum_t arr = toml_get(top, "backend");

    if(arr.type == TOML_UNKNOWN) {
        return;
    }
    if(arr.type != TOML_ARRAY) {
        conf_diag_add(diag, "[[backend]] must be an array of tables");
        return;
    }

    conf->backends = calloc((size_t)arr.u.arr.size, sizeof(*conf->backends));
    if(conf->backends == NULL && arr.u.arr.size > 0) {
        conf_diag_add(diag, "out of memory parsing [[backend]]");
        return;
    }
    conf->backend_count = (__u32)arr.u.arr.size;

    for(int32_t i = 0; i < arr.u.arr.size; i++) {
        toml_datum_t tab = arr.u.arr.elem[i];

        if(tab.type != TOML_TABLE) {
            conf_diag_add(diag, "backend[%d] must be a table", i);
            continue;
        }
        parse_one_backend(tab, &conf->backends[i], (__u32)i, diag);
    }
}

/* ---- [[vip]] ------------------------------------------------------------ */

static void parse_vip_flag_bits(toml_datum_t tab, struct conf_vip *vip, const char *path, struct conf_diag *diag)
{
    bool present = false;
    bool flag = false;
    int64_t val;

    if(get_bool(tab, "acl", path, diag, &present, &flag) && flag) {
        vip->meta.flags |= VIP_ACL;
    }
    if(get_bool(tab, "ratelimit", path, diag, &present, &flag) && flag) {
        vip->meta.flags |= VIP_RATELIMIT;
    }
    if(get_bool(tab, "hash_5tuple", path, diag, &present, &flag) && flag) {
        vip->meta.flags |= VIP_HASH_5TUPLE;
    }
    if(get_bool(tab, "quic", path, diag, &present, &flag) && flag) {
        vip->meta.flags |= VIP_QUIC;
    }

    if(get_int(tab, "quic_cid_len", path, diag, &present, &val) && present) {
        if(val < 0 || val > 31) {
            conf_diag_add(diag, "%s.quic_cid_len out of range (0-31)", path);
        } else {
            vip->meta.flags |= ((__u32)val << VIP_QUIC_CID_LEN_SHIFT) & VIP_QUIC_CID_LEN_MASK;
        }
    }
    if(get_int(tab, "dscp", path, diag, &present, &val) && present) {
        if(val < 0 || val > 63) {
            conf_diag_add(diag, "%s.dscp out of range (0-63)", path);
        } else {
            vip->meta.flags |= ((__u32)val << VIP_DSCP_SHIFT) & VIP_DSCP_MASK;
        }
    }
}

static void parse_vip_address(toml_datum_t tab, struct conf_vip *vip, const char *path, struct conf_diag *diag)
{
    char addr_str[64];

    if(!req_str(tab, "addr", path, diag, addr_str, sizeof(addr_str))) {
        return;
    }

    if(conf_parse_ipv4(addr_str, &vip->key.addr4)) {
        vip->key.family = AF_INET;
        return;
    }
    __u8 addr6[16];

    if(conf_parse_ipv6(addr_str, addr6)) {
        vip->key.family = AF_INET6;
        memcpy(vip->key.addr6, addr6, 16);
        return;
    }
    conf_diag_add(diag, "%s.addr is not a valid IPv4 or IPv6 address", path);
}

static void parse_vip_member(toml_datum_t elem, struct conf_member *member, const char *path, struct conf_diag *diag)
{
    int64_t weight;
    bool present = false;

    if(elem.type != TOML_TABLE) {
        conf_diag_add(diag, "%s is not a table (expected { backend = ..., weight = ... })", path);
        return;
    }
    (void)req_str(elem, "backend", path, diag, member->backend_name, sizeof(member->backend_name));
    if(get_int(elem, "weight", path, diag, &present, &weight) && present) {
        if(weight <= 0 || weight > 0xffffffffLL) {
            conf_diag_add(diag, "%s.weight out of range", path);
        } else {
            member->weight = (__u32)weight;
        }
    } else if(!present) {
        conf_diag_add(diag, "%s.weight is required", path);
    }
}

static void parse_vip_members(toml_datum_t tab, struct conf_vip *vip, const char *path, struct conf_diag *diag)
{
    toml_datum_t arr = toml_get(tab, "members");

    if(arr.type != TOML_ARRAY) {
        conf_diag_add(diag, "%s.members is required and must be an array", path);
        return;
    }

    vip->members = calloc((size_t)arr.u.arr.size, sizeof(*vip->members));
    if(vip->members == NULL && arr.u.arr.size > 0) {
        conf_diag_add(diag, "out of memory parsing %s.members", path);
        return;
    }
    vip->member_count = (__u32)arr.u.arr.size;

    for(int32_t i = 0; i < arr.u.arr.size; i++) {
        char mpath[48];

        (void)snprintf(mpath, sizeof(mpath), "%s.members[%d]", path, i);
        parse_vip_member(arr.u.arr.elem[i], &vip->members[i], mpath, diag);
    }
}

static void parse_one_vip(toml_datum_t tab, struct conf_vip *vip, __u32 idx, struct conf_diag *diag)
{
    char path[24];
    char proto_str[8];
    char hash_key_str[40];
    char table_seed_str[40];
    int64_t port;
    bool present = false;

    (void)snprintf(path, sizeof(path), "vip[%u]", idx);

    parse_vip_address(tab, vip, path, diag);

    if(get_int(tab, "port", path, diag, &present, &port)) {
        if(present && (port < 0 || port > 0xffff)) {
            conf_diag_add(diag, "%s.port out of range (0-65535)", path);
        } else {
            vip->key.port = htons((__u16)port);
        }
    }

    if(req_str(tab, "proto", path, diag, proto_str, sizeof(proto_str))) {
        if(!conf_parse_proto(proto_str, &vip->key.proto)) {
            conf_diag_add(diag, "%s.proto must be \"tcp\" or \"udp\"", path);
        }
    }

    if(req_str(tab, "hash_key", path, diag, hash_key_str, sizeof(hash_key_str))) {
        if(!conf_parse_hexkey16(hash_key_str, vip->meta.hash_key)) {
            conf_diag_add(diag, "%s.hash_key must be exactly 32 hex digits", path);
        }
    }
    if(req_str(tab, "table_seed", path, diag, table_seed_str, sizeof(table_seed_str))) {
        if(!conf_parse_hexkey16(table_seed_str, vip->table_seed)) {
            conf_diag_add(diag, "%s.table_seed must be exactly 32 hex digits", path);
        }
    }

    parse_vip_flag_bits(tab, vip, path, diag);
    parse_vip_members(tab, vip, path, diag);

    vip->meta.vip_num = MARLIN_CONF_VIP_NUM_UNSET;
}

static void parse_vips(toml_datum_t top, struct marlin_conf *conf, struct conf_diag *diag)
{
    toml_datum_t arr = toml_get(top, "vip");

    if(arr.type == TOML_UNKNOWN) {
        return;
    }
    if(arr.type != TOML_ARRAY) {
        conf_diag_add(diag, "[[vip]] must be an array of tables");
        return;
    }

    conf->vips = calloc((size_t)arr.u.arr.size, sizeof(*conf->vips));
    if(conf->vips == NULL && arr.u.arr.size > 0) {
        conf_diag_add(diag, "out of memory parsing [[vip]]");
        return;
    }
    conf->vip_count = (__u32)arr.u.arr.size;

    for(int32_t i = 0; i < arr.u.arr.size; i++) {
        toml_datum_t tab = arr.u.arr.elem[i];

        if(tab.type != TOML_TABLE) {
            conf_diag_add(diag, "vip[%d] must be a table", i);
            continue;
        }
        parse_one_vip(tab, &conf->vips[i], (__u32)i, diag);
    }
}

/* ---- file access, load, free -------------------------------------------- */

/*
 * Opens and permission-checks path in one step, on the fd that is actually
 * parsed -- checking by path with stat() and reopening separately would
 * leave a TOCTOU gap between the check and the read. Reused by --check
 * (enforce=false, a warning) and by --attach/SIGHUP (enforce=true, a
 * rejection): see conf.h's conf_load() comment for why the two differ.
 */
static FILE *open_conf_file(const char *path, bool enforce, struct conf_diag *diag)
{
    struct stat st;
    FILE *fp;
    int fd = open(path, O_RDONLY | O_CLOEXEC);

    if(fd < 0) {
        conf_diag_add(diag, "%s: %s", path, strerror(errno));
        return NULL;
    }
    if(fstat(fd, &st) != 0) {
        conf_diag_add(diag, "%s: %s", path, strerror(errno));
        close(fd);
        return NULL;
    }

    bool bad_owner = st.st_uid != 0;
    bool bad_write = (st.st_mode & (S_IWGRP | S_IWOTH)) != 0;

    if(bad_owner || bad_write) {
        if(enforce) {
            if(bad_owner) {
                conf_diag_add(diag, "%s is not owned by root; refusing to read it (chown root)", path);
            }
            if(bad_write) {
                conf_diag_add(diag, "%s is group- or world-writable; refusing to read it (chmod 0640)", path);
            }
            close(fd);
            return NULL;
        }
        if(bad_owner) {
            conf_diag_warn(diag, "%s is not owned by root -- would be refused outside --check", path);
        }
        if(bad_write) {
            conf_diag_warn(diag, "%s is group- or world-writable -- would be refused outside --check", path);
        }
    }
    if((st.st_mode & S_IROTH) != 0) {
        conf_diag_warn(diag, "%s is world-readable; it holds every VIP's hash_key and table_seed", path);
    }

    fp = fdopen(fd, "r");
    if(fp == NULL) {
        conf_diag_add(diag, "%s: %s", path, strerror(errno));
        close(fd);
        return NULL;
    }
    return fp;
}

struct marlin_conf *conf_load(const char *path, enum conf_load_mode mode, bool enforce_perms, struct conf_diag *diag)
{
    __u32 before = diag->count;
    FILE *fp;
    toml_result_t result;
    struct marlin_conf *conf;

    fp = open_conf_file(path, enforce_perms, diag);
    if(fp == NULL) {
        return NULL;
    }

    result = toml_parse_file(fp);
    (void)fclose(fp);

    if(!result.ok) {
        conf_diag_add(diag, "%s: %s", path, result.errmsg);
        toml_free(result);
        return NULL;
    }

    conf = calloc(1, sizeof(*conf));
    if(conf == NULL) {
        conf_diag_add(diag, "out of memory parsing %s", path);
        toml_free(result);
        return NULL;
    }

    parse_instance(result.toptab, &conf->instance, diag);

    if(mode == CONF_LOAD_INSTANCE_ONLY) {
        toml_free(result);
        if(diag->count != before) {
            conf_free(conf);
            return NULL;
        }
        return conf;
    }

    parse_acl(result.toptab, &conf->acl, diag);
    parse_ratelimit(result.toptab, &conf->ratelimit, diag);
    parse_backends(result.toptab, conf, diag);
    parse_vips(result.toptab, conf, diag);

    toml_free(result);

    if(diag->count != before) {
        conf_free(conf);
        return NULL;
    }

    if(!conf_check(conf, diag)) {
        conf_free(conf);
        return NULL;
    }

    return conf;
}

void conf_free(struct marlin_conf *conf)
{
    if(conf == NULL) {
        return;
    }

    free(conf->acl.allow_v4);
    free(conf->acl.block_v4);
    free(conf->acl.allow_v6);
    free(conf->acl.block_v6);

    for(__u32 i = 0; i < conf->vip_count; i++) {
        free(conf->vips[i].members);
    }
    free(conf->vips);
    free(conf->backends);
    free(conf);
}
