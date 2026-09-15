/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Preflight -- asserts host state, never configures it. Mirrors the checks
 * formerly in deploy/marlin-load.sh's load(), minus the already-attached
 * check: bpf_link_create() reports that itself, atomically.
 */

#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>

#include <linux/ethtool.h>
#include <linux/magic.h>
#include <linux/sockios.h>

#include <bpf/libbpf.h>

#include <marlind/build.h>
#include <marlind/compat.h>
#include <marlind/log.h>
#include <marlind/preflight.h>

static void check_root(void)
{
    if(geteuid() != 0) {
        die("must run as root");
    }
}

static void check_obj_readable(const char *path)
{
    if(access(path, R_OK) != 0) {
        die("no object at %s -- build it: make -C data-plane", path);
    }
}

/*
 * Refuses before load_and_pin_maps() opens the object for real, so an
 * object below the floor -- or one predating the build-version map
 * entirely, which by construction predates every version a floor can
 * name -- creates and pins nothing. The second bpf_object__open_file()
 * this costs is one process-startup call, traded for surfacing the
 * refusal before any host state changes.
 */
static void check_object_version(const char *path)
{
    struct bpf_object *obj;
    const struct marlin_build *build;
    char version[MARLIN_VERSION_MAX + 1];
    enum marlind_compat compat;

    obj = bpf_object__open_file(path, NULL);
    if(obj == NULL) {
        die("failed to open %s", path);
    }

    build = marlin_build_from_object(obj);
    if(build == NULL) {
        bpf_object__close(obj);
        die_with(EXIT_INCOMPATIBLE, "%s carries no build version; marlind requires %s or newer", path, MARLIND_MIN_BPF_VERSION);
    }

    marlind_build_version(build, version, sizeof(version));
    bpf_object__close(obj);

    compat = marlind_bpf_object_supported(version);
    if(compat == MARLIND_COMPAT_TOO_OLD) {
        die_with(EXIT_INCOMPATIBLE, "%s is version %s; marlind requires %s or newer", path, version, MARLIND_MIN_BPF_VERSION);
    }
    if(compat == MARLIND_COMPAT_UNPARSEABLE) {
        die_with(EXIT_INCOMPATIBLE, "%s has an unparseable build version %s; marlind requires %s or newer", path, version,
                 MARLIND_MIN_BPF_VERSION);
    }
}

/*
 * bpffs must already be mounted. Mounting it here would need CAP_SYS_ADMIN,
 * which this process does not hold (docs/DEPLOYMENT.md §1.6), and an
 * in-unit mount does not reach the host under systemd's mount-namespacing
 * hardening -- so this asserts, it does not fix.
 */
static void check_bpffs_mounted(void)
{
    struct statfs st;

    if(statfs("/sys/fs/bpf", &st) != 0 || st.f_type != BPF_FS_MAGIC) {
        die("/sys/fs/bpf is not mounted: mount -t bpf bpf /sys/fs/bpf");
    }
}

/*
 * ETHTOOL_GSTRINGS/GFEATURES return the kernel's ETH_SS_FEATURES names
 * ("rx-lro", "rx-gro-hw"), not ethtool(8)'s cosmetic long names
 * ("large-receive-offload") -- those exist only in the CLI tool's own
 * display table, never on the wire.
 */
static bool ethtool_feature_active(const char *iface, const char *feature, bool *found)
{
    struct ethtool_sset_info *sset;
    struct ethtool_gstrings *strings;
    struct ethtool_gfeatures *features;
    struct ifreq ifr;
    uint32_t nstrings;
    uint32_t nblocks;
    bool active = false;
    int fd;
    uint32_t i;

    *found = false;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0) {
        return false;
    }

    sset = calloc(1, sizeof(*sset) + sizeof(uint32_t));
    if(sset == NULL) {
        close(fd);
        return false;
    }
    sset->cmd = ETHTOOL_GSSET_INFO;
    sset->reserved = 0;
    sset->sset_mask = 1ULL << ETH_SS_FEATURES;

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface);
    ifr.ifr_data = (void *)sset;

    if(ioctl(fd, SIOCETHTOOL, &ifr) != 0 || sset->sset_mask == 0) {
        free(sset);
        close(fd);
        return false;
    }
    nstrings = sset->data[0];
    free(sset);

    if(nstrings == 0) {
        close(fd);
        return false;
    }

    strings = calloc(1, sizeof(*strings) + (size_t)nstrings * ETH_GSTRING_LEN);
    if(strings == NULL) {
        close(fd);
        return false;
    }
    strings->cmd = ETHTOOL_GSTRINGS;
    strings->string_set = ETH_SS_FEATURES;
    strings->len = nstrings;
    ifr.ifr_data = (void *)strings;

    if(ioctl(fd, SIOCETHTOOL, &ifr) != 0) {
        free(strings);
        close(fd);
        return false;
    }

    nblocks = (nstrings + 31) / 32;
    features = calloc(1, sizeof(*features) + (size_t)nblocks * sizeof(struct ethtool_get_features_block));
    if(features == NULL) {
        free(strings);
        close(fd);
        return false;
    }
    features->cmd = ETHTOOL_GFEATURES;
    features->size = nblocks;
    ifr.ifr_data = (void *)features;

    if(ioctl(fd, SIOCETHTOOL, &ifr) != 0) {
        free(features);
        free(strings);
        close(fd);
        return false;
    }

    for(i = 0; i < nstrings; i++) {
        const char *name = (const char *)&strings->data[(size_t)i * ETH_GSTRING_LEN];

        if(strncmp(name, feature, ETH_GSTRING_LEN) == 0) {
            uint32_t block = i / 32;
            uint32_t bit = i % 32;

            *found = true;
            active = (features->features[block].active & (1u << bit)) != 0;
            break;
        }
    }

    free(features);
    free(strings);
    close(fd);
    return active;
}

/*
 * LRO merges arriving frames in hardware before XDP sees them; the datapath
 * assumes ingress is never larger than a standard frame and does not
 * handle multi-buffer packets (docs/DEPLOYMENT.md §1.3). A feature this
 * driver does not expose is treated as off, matching the tolerant
 * `2>/dev/null` behaviour of the shell preflight this replaces.
 */
static void check_offload_off(const char *iface)
{
    bool found, active;

    active = ethtool_feature_active(iface, "rx-lro", &found);
    if(found && active) {
        die("LRO is on for %s: ethtool -K %s lro off", iface, iface);
    }

    active = ethtool_feature_active(iface, "rx-gro-hw", &found);
    if(found && active) {
        die("hardware GRO is on for %s: ethtool -K %s rx-gro-hw off", iface, iface);
    }
}

void preflight(const struct config *cfg)
{
    check_root();
    check_obj_readable(cfg->obj_path);
    check_object_version(cfg->obj_path);
    check_bpffs_mounted();
    check_offload_off(cfg->iface);
}
