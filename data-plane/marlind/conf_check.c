/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Definitions for conf_check.h.
 */

#include <net/if.h>
#include <string.h>

#include <marlin/abi/defines.h>
#include <marlin/lb_core.h>
#include <marlind/conf_check.h>
#include <marlind/conf_value.h>
#include <marlind/rl_scale.h>

static bool ifname_eq(const char *lhs, const char *rhs)
{
    return strncmp(lhs, rhs, IF_NAMESIZE) == 0;
}

static bool is_attach_or_txport(const struct conf_instance *inst, const char *name)
{
    if(ifname_eq(name, inst->iface)) {
        return true;
    }
    for(__u32 i = 0; i < inst->tx_port_count; i++) {
        if(ifname_eq(name, inst->tx_ports[i])) {
            return true;
        }
    }
    return false;
}

static void check_instance(struct conf_instance *inst, struct conf_diag *diag)
{
    if(inst->iface[0] == '\0') {
        conf_diag_add(diag, "instance.interface is required");
        return;
    }

    inst->ifindex = (int)if_nametoindex(inst->iface);
    if(inst->ifindex == 0) {
        conf_diag_warn(diag, "instance.interface %s not found on this host -- skipping host-dependent checks", inst->iface);
    }

    for(__u32 i = 0; i < inst->tx_port_count; i++) {
        for(__u32 j = i + 1; j < inst->tx_port_count; j++) {
            if(ifname_eq(inst->tx_ports[i], inst->tx_ports[j])) {
                conf_diag_add(diag, "instance.tx_ports[%u] duplicates tx_ports[%u] (%s)", j, i, inst->tx_ports[i]);
            }
        }
        if(ifname_eq(inst->tx_ports[i], inst->iface)) {
            conf_diag_warn(diag, "instance.tx_ports[%u] names the attach interface, which never needs to be listed", i);
        }
    }
}

static void check_one_backend(struct conf_backend *backend, const struct conf_instance *inst, struct conf_diag *diag)
{
    __u8 mode = ENCAP_MODE(backend->abi.flags);

    if(backend->abi.addr == 0) {
        conf_diag_add(diag, "backend[%s].addr is required", backend->name);
    }

    if((backend->abi.flags & MARLIN_BE_F_ENCAP_REQUIRED) != 0 && !inst->tunnel_src_set) {
        conf_diag_add(diag, "backend[%s] encapsulates but instance.tunnel_src is unset", backend->name);
    }

    if(mode == MARLIN_MODE_VXLAN) {
        if(!backend->vni_stated || backend->abi.vni == 0 || (backend->abi.vni & MARLIN_VNI_RESERVED) != 0) {
            conf_diag_add(diag, "backend[%s].vni is unset or out of range (0 < vni <= 0xffffff)", backend->name);
        }
        bool inner_mac_zero = true;

        for(int i = 0; i < 6; i++) {
            if(backend->abi.inner_mac[i] != 0) {
                inner_mac_zero = false;
                break;
            }
        }
        if(!backend->inner_mac_stated || inner_mac_zero) {
            conf_diag_add(diag, "backend[%s].inner_mac is required for vxlan and must not be all-zero", backend->name);
        }
    } else if(backend->vni_stated || backend->inner_mac_stated) {
        conf_diag_add(diag, "backend[%s].vni/inner_mac are only meaningful for mode = \"vxlan\"", backend->name);
    }

    if(backend->has_egress && !is_attach_or_txport(inst, backend->egress)) {
        conf_diag_add(diag, "backend[%s].egress (%s) is neither the attach interface nor in tx_ports", backend->name, backend->egress);
    }

    /*
     * The default: set wherever a mac is stated, clear otherwise
     * (docs/design/31-file-configuration.md §3.1). An explicit fib= key
     * always wins, mac stated or not.
     */
    bool fib = backend->fib_stated ? backend->fib_value : backend->mac_stated;

    if(fib) {
        backend->abi.flags |= MARLIN_BE_F_FIB;
    } else {
        backend->abi.flags &= (__u8)~MARLIN_BE_F_FIB;
    }
}

static void check_backends(struct marlin_conf *conf, struct conf_diag *diag)
{
    if(conf->backend_count > MAX_BACKENDS - 1) {
        conf_diag_add(diag, "%u backends configured, more than MAX_BACKENDS - 1 (%u)", conf->backend_count, MAX_BACKENDS - 1);
    }

    for(__u32 i = 0; i < conf->backend_count; i++) {
        struct conf_backend *backend = &conf->backends[i];

        if(backend->id == MARLIN_NO_BACKEND) {
            conf_diag_add(diag, "backend[%s].id is 0, the sentinel for \"no backend\"", backend->name);
        }
        if(backend->id >= MAX_BACKENDS) {
            conf_diag_add(diag, "backend[%s].id %u is out of range (< %u)", backend->name, backend->id, MAX_BACKENDS);
        }

        for(__u32 j = i + 1; j < conf->backend_count; j++) {
            if(strncmp(backend->name, conf->backends[j].name, MARLIN_CONF_NAME_MAX) == 0) {
                conf_diag_add(diag, "backend name \"%s\" is duplicated", backend->name);
            }
            if(backend->id == conf->backends[j].id) {
                conf_diag_add(diag, "backend id %u is duplicated (\"%s\" and \"%s\")", backend->id, backend->name,
                              conf->backends[j].name);
            }
        }

        check_one_backend(backend, &conf->instance, diag);
    }
}

static const struct conf_backend *find_backend(const struct marlin_conf *conf, const char *name)
{
    for(__u32 i = 0; i < conf->backend_count; i++) {
        if(strncmp(conf->backends[i].name, name, MARLIN_CONF_NAME_MAX) == 0) {
            return &conf->backends[i];
        }
    }
    return NULL;
}

static void check_vip_members(struct conf_vip *vip, const struct marlin_conf *conf, struct conf_diag *diag)
{
    bool any_up = vip->member_count == 0; /* an empty list warns below, not here */

    for(__u32 i = 0; i < vip->member_count; i++) {
        struct conf_member *member = &vip->members[i];
        const struct conf_backend *backend = find_backend(conf, member->backend_name);

        if(backend == NULL) {
            conf_diag_add(diag, "vip[%u].members[%u] names unknown backend \"%s\"", (unsigned)(vip - conf->vips), i,
                          member->backend_name);
            continue;
        }
        member->backend_id = backend->id;
        if((backend->abi.flags & MARLIN_BE_F_STATE) != 0) {
            any_up = true;
        }

        if(member->weight == 0) {
            conf_diag_add(diag, "vip[%u].members[%u] (%s) weight must be non-zero", (unsigned)(vip - conf->vips), i,
                          member->backend_name);
        }

        for(__u32 j = i + 1; j < vip->member_count; j++) {
            if(strncmp(member->backend_name, vip->members[j].backend_name, MARLIN_CONF_NAME_MAX) == 0) {
                conf_diag_add(diag, "vip[%u].members lists \"%s\" more than once", (unsigned)(vip - conf->vips), member->backend_name);
            }
        }
    }

    if(vip->member_count == 0) {
        conf_diag_warn(diag, "vip[%u] has no members", (unsigned)(vip - conf->vips));
    } else if(!any_up) {
        conf_diag_warn(diag, "vip[%u] has no member in state = \"up\"", (unsigned)(vip - conf->vips));
    }
}

static void check_one_vip(struct conf_vip *vip, const struct marlin_conf *conf, struct conf_diag *diag)
{
    unsigned idx = (unsigned)(vip - conf->vips);
    bool quic = (vip->meta.flags & VIP_QUIC) != 0;
    __u32 cid_len = VIP_QUIC_CID_LEN(vip->meta.flags);
    __u32 dscp = VIP_DSCP(vip->meta.flags);

    if(quic && (cid_len < 7 || cid_len > 20)) {
        conf_diag_add(diag, "vip[%u].quic_cid_len must be 7-20 when quic = true", idx);
    }
    if(dscp > 63) {
        conf_diag_add(diag, "vip[%u].dscp must be 0-63", idx);
    }
    if((vip->meta.flags & VIP_RATELIMIT) != 0 && (vip->meta.flags & VIP_ACL) == 0) {
        conf_diag_add(diag, "vip[%u].ratelimit = true requires acl = true", idx);
    }

    check_vip_members(vip, conf, diag);
}

static void check_vips(struct marlin_conf *conf, struct conf_diag *diag)
{
    if(conf->vip_count > MAX_VIPS) {
        conf_diag_add(diag, "%u VIPs configured, more than MAX_VIPS (%u)", conf->vip_count, MAX_VIPS);
    }

    for(__u32 i = 0; i < conf->vip_count; i++) {
        struct conf_vip *vip = &conf->vips[i];

        for(__u32 j = i + 1; j < conf->vip_count; j++) {
            if(vip_key_eq(&vip->key, &conf->vips[j].key)) {
                conf_diag_add(diag, "vip[%u] duplicates vip[%u]'s address/port/proto", i, j);
            }
        }

        check_one_vip(vip, conf, diag);
    }
}

static void check_acl_list(const struct conf_acl_entry *entries, __u32 count, bool is_v6, const char *list_name,
                           struct conf_diag *diag)
{
    static const __u8 zero16[16] = { 0 };
    int width = is_v6 ? 16 : 4;

    if(count > MAX_ACL_ENTRIES) {
        conf_diag_add(diag, "acl.%s has %u entries, more than MAX_ACL_ENTRIES (%u)", list_name, count, MAX_ACL_ENTRIES);
    }

    for(__u32 i = 0; i < count; i++) {
        const struct conf_acl_entry *entry = &entries[i];

        if(entry->prefixlen == 0 && memcmp(entry->addr, zero16, (size_t)width) == 0 && strstr(list_name, "allow") != NULL) {
            conf_diag_add(diag, "acl.%s[%u] is a default route (0.0.0.0/0 or ::/0), which nullifies the blocklist entirely", list_name,
                          i);
        }
        if(conf_cidr_host_bits_set(entry->addr, entry->prefixlen, is_v6)) {
            conf_diag_add(diag, "acl.%s[%u] has host bits set below its prefix length", list_name, i);
        }
        if((!is_v6 && entry->prefixlen < 8) || (is_v6 && entry->prefixlen < 32)) {
            conf_diag_warn(diag, "acl.%s[%u] is broader than /%d, which is unusually wide for an allow rule", list_name, i,
                           is_v6 ? 32 : 8);
        }
    }
}

/* True if `outer` (already known to have prefixlen <= inner's) covers inner's address on outer's own prefix bits. */
static bool prefix_covers(const struct conf_acl_entry *outer, const struct conf_acl_entry *inner, int width)
{
    if(outer->prefixlen > inner->prefixlen) {
        return false;
    }
    for(int byte = 0; byte < width; byte++) {
        __u32 bit_base = (__u32)byte * 8;

        if(bit_base >= outer->prefixlen) {
            break;
        }
        if(bit_base + 8 <= outer->prefixlen) {
            if(outer->addr[byte] != inner->addr[byte]) {
                return false;
            }
            continue;
        }
        __u32 keep = outer->prefixlen - bit_base;
        __u8 mask = (__u8)(0xff << (8 - keep));

        if((outer->addr[byte] & mask) != (inner->addr[byte] & mask)) {
            return false;
        }
    }
    return true;
}

static void check_acl_dead_rules(const struct conf_acl *acl, struct conf_diag *diag)
{
    for(__u32 i = 0; i < acl->block_v4_count; i++) {
        for(__u32 j = 0; j < acl->allow_v4_count; j++) {
            if(prefix_covers(&acl->allow_v4[j], &acl->block_v4[i], 4)) {
                conf_diag_warn(diag, "acl.block[%u] (v4) is wholly covered by acl.allow[%u], and therefore dead", i, j);
                break;
            }
        }
    }
    for(__u32 i = 0; i < acl->block_v6_count; i++) {
        for(__u32 j = 0; j < acl->allow_v6_count; j++) {
            if(prefix_covers(&acl->allow_v6[j], &acl->block_v6[i], 16)) {
                conf_diag_warn(diag, "acl.block[%u] (v6) is wholly covered by acl.allow[%u], and therefore dead", i, j);
                break;
            }
        }
    }
}

static void check_acl(const struct conf_acl *acl, struct conf_diag *diag)
{
    check_acl_list(acl->allow_v4, acl->allow_v4_count, false, "allow (v4)", diag);
    check_acl_list(acl->block_v4, acl->block_v4_count, false, "block (v4)", diag);
    check_acl_list(acl->allow_v6, acl->allow_v6_count, true, "allow (v6)", diag);
    check_acl_list(acl->block_v6, acl->block_v6_count, true, "block (v6)", diag);
    check_acl_dead_rules(acl, diag);
}

static void check_ratelimit(const struct marlin_conf *conf, struct conf_diag *diag)
{
    const struct conf_ratelimit *rl = &conf->ratelimit;

    if(!rl->enabled) {
        return;
    }

    if(!conf->acl.enabled) {
        conf_diag_add(diag, "ratelimit.enabled = true requires acl.enabled = true");
    }
    if(rl->burst_packets == 0 || rl->burst_packets > 0xffffffU) {
        conf_diag_add(diag, "ratelimit.burst_packets must be 1-16777215");
    }

    bool any_metered = false;

    for(__u32 i = 0; i < conf->vip_count; i++) {
        if((conf->vips[i].meta.flags & VIP_RATELIMIT) != 0) {
            any_metered = true;
            break;
        }
    }
    if(!any_metered) {
        conf_diag_warn(diag, "ratelimit.enabled = true but no vip carries ratelimit = true");
    } else if(marlind_scale_refill(rl->tokens_per_sec) == 0) {
        conf_diag_add(diag, "ratelimit.tokens_per_sec (%u) scales to a zero refill; the bucket would never refill",
                      rl->tokens_per_sec);
    }
}

bool conf_check(struct marlin_conf *conf, struct conf_diag *diag)
{
    __u32 before = diag->count;

    check_instance(&conf->instance, diag);
    check_backends(conf, diag);
    check_vips(conf, diag);
    check_acl(&conf->acl, diag);
    check_ratelimit(conf, diag);

    return diag->count == before;
}

static bool backend_identity_changed(const struct conf_backend *cur, const struct conf_backend *prev)
{
    return cur->abi.addr != prev->abi.addr || ENCAP_MODE(cur->abi.flags) != ENCAP_MODE(prev->abi.flags) ||
           cur->abi.encap_dport != prev->abi.encap_dport || cur->abi.vni != prev->abi.vni ||
           memcmp(cur->abi.inner_mac, prev->abi.inner_mac, sizeof(cur->abi.inner_mac)) != 0;
}

bool conf_check_against_previous(const struct marlin_conf *cur, const struct marlin_conf *prev, struct conf_diag *diag)
{
    __u32 before = diag->count;

    if(!ifname_eq(cur->instance.iface, prev->instance.iface)) {
        conf_diag_add(diag, "instance.interface changed (%s -> %s); restart marlind instead of reloading", prev->instance.iface,
                      cur->instance.iface);
    }
    if(strncmp(cur->instance.object, prev->instance.object, PATH_MAX) != 0) {
        conf_diag_add(diag, "instance.object changed; restart marlind instead of reloading");
    }
    if(strncmp(cur->instance.pin_dir, prev->instance.pin_dir, PATH_MAX) != 0) {
        conf_diag_add(diag, "instance.pin_dir changed; restart marlind instead of reloading");
    }

    for(__u32 i = 0; i < cur->backend_count; i++) {
        const struct conf_backend *cb = &cur->backends[i];

        for(__u32 j = 0; j < prev->backend_count; j++) {
            const struct conf_backend *pb = &prev->backends[j];

            if(cb->id != pb->id) {
                continue;
            }
            if(backend_identity_changed(cb, pb)) {
                conf_diag_add(diag,
                              "backend id %u changed addr/mode/encap_dport/vni/inner_mac in place; remove and re-add it "
                              "under a new id instead",
                              cb->id);
            }
            break;
        }
    }

    return diag->count == before;
}
