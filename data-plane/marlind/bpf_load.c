/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Load marlin.bpf.o, pin its maps and program, and create the bpf_link that
 * attaches it in native XDP mode.
 */

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/if_link.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <marlind/bpf_load.h>
#include <marlind/build.h>
#include <marlind/log.h>
#include <marlind/marlind.h>

static int print_diagnostics(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if(level > LIBBPF_WARN) {
        return 0;
    }

    return vfprintf(stderr, fmt, args);
}

/*
 * Sets a pin path on every user-defined map before loading, so libbpf's own
 * reuse logic (bpf_object__load() -> bpf_object__reuse_map()) picks up
 * whatever is already pinned under pin_dir and creates the rest -- the
 * program always loads fresh from obj_path, but map contents and VIP
 * configuration survive both a restart and a datapath upgrade, as long as no
 * map's definition has changed. A definition that did change fails reuse
 * with a libbpf error; `marlind --unpin` clears the old pins deliberately.
 *
 * Internal maps (.rodata, .bss, ...) are excluded from all of this: their
 * libbpf-generated names contain a '.', and the kernel's bpffs refuses to
 * look up any name containing one (EPERM -- reserved for future extensions),
 * so pinning one the way the loop below pins ordinary maps cannot work at
 * all. Reusing one across an upgrade would also silently keep its old
 * contents -- exactly wrong for .rodata.marlin_version, the one internal map
 * this object carries, when a version bump is the reason for the upgrade.
 * pin_version() below pins it separately, once loaded, under a name this
 * loader chooses instead of one libbpf derived from the object's basename.
 */
struct bpf_object *load_and_pin_maps(const char *obj_path, const char *pin_dir)
{
    struct bpf_object *obj;
    struct bpf_map *map;
    char path[PATH_MAX];
    int err;

    libbpf_set_print(print_diagnostics);

    obj = bpf_object__open_file(obj_path, NULL);
    if(obj == NULL) {
        die("failed to open %s", obj_path);
    }

    bpf_object__for_each_map(map, obj)
    {
        int n;

        if(bpf_map__is_internal(map)) {
            continue;
        }

        n = snprintf(path, sizeof(path), "%s/%s", pin_dir, bpf_map__name(map));

        if(n < 0 || (size_t)n >= sizeof(path)) {
            die("pin path too long for map %s", bpf_map__name(map));
        }
        if(bpf_map__set_pin_path(map, path) != 0) {
            die("failed to set pin path for map %s", bpf_map__name(map));
        }
    }

    err = bpf_object__load(obj);
    if(err != 0) {
        die("failed to load %s: %s", obj_path, strerror(-err));
    }

    /*
     * NULL, not pin_dir: bpf_object__pin_maps() given a directory pins every
     * autocreate map under it by name regardless of whether a pin_path was
     * set above, which would re-introduce exactly the internal-map pin the
     * loop above just avoided. NULL pins only maps that already carry one.
     */
    err = bpf_object__pin_maps(obj, NULL);
    if(err != 0) {
        die("failed to pin maps under %s: %s", pin_dir, strerror(-err));
    }

    return obj;
}

/*
 * The version global is excluded from load_and_pin_maps() above, so it is
 * pinned here instead, after load, on the same always-replace discipline
 * pin_program() below uses: unconditionally, replacing any stale pin from a
 * previous version. This is what lets `marlind --status` and `bpftool map
 * dump pinned <pin_dir>/version` see the version of what actually loaded,
 * not of whatever last succeeded -- a map nothing in the datapath reads
 * would otherwise never appear in a running program's bpf_prog_info.map_ids,
 * leaving no path from an attached program back to its own version.
 *
 * Not fatal if absent: an obj_path built before this map existed still
 * attaches, just with nothing for --status to show.
 */
void pin_version(struct bpf_object *obj, const char *pin_dir)
{
    struct bpf_map *map = marlin_find_build_map(obj);
    char path[PATH_MAX];
    int n;

    if(map == NULL) {
        return;
    }

    n = snprintf(path, sizeof(path), "%s/%s", pin_dir, MARLIN_VERSION_PIN);
    if(n < 0 || (size_t)n >= sizeof(path)) {
        die("pin path too long for the version map");
    }

    if(unlink(path) != 0 && errno != ENOENT) {
        die("failed to remove stale pin %s: %s", path, strerror(errno));
    }

    if(bpf_map__pin(map, path) != 0) {
        die("failed to pin the build-version map at %s: %s", path, strerror(errno));
    }
}

struct bpf_program *pin_program(struct bpf_object *obj, const char *obj_path, const char *prog_pin)
{
    struct bpf_program *prog;

    prog = bpf_object__find_program_by_name(obj, MARLIN_PROG_NAME);
    if(prog == NULL) {
        die("%s has no program named %s", obj_path, MARLIN_PROG_NAME);
    }

    /* Stale from a previous load; bpf_program__pin() fails EEXIST otherwise. */
    if(unlink(prog_pin) != 0 && errno != ENOENT) {
        die("failed to remove stale pin %s: %s", prog_pin, strerror(errno));
    }

    if(bpf_program__pin(prog, prog_pin) != 0) {
        die("failed to pin %s at %s: %s", MARLIN_PROG_NAME, prog_pin, strerror(errno));
    }

    return prog;
}

/*
 * Not bpf_program__attach_xdp(): it passes no attach flags, and with none
 * set the kernel silently falls back to generic/SKB mode on a driver
 * without native XDP support -- the exact order-of-magnitude regression
 * docs/design/02-architecture.md refuses. XDP_FLAGS_DRV_MODE here makes
 * that fail loudly instead.
 */
int attach_link(int prog_fd, const char *iface, int ifindex)
{
    LIBBPF_OPTS(bpf_link_create_opts, opts, .flags = XDP_FLAGS_DRV_MODE);
    int link_fd;

    link_fd = bpf_link_create(prog_fd, ifindex, BPF_XDP, &opts);
    if(link_fd < 0) {
        int err = -link_fd;

        if(err == EBUSY) {
            die("%s already has an XDP program attached -- stop it first", iface);
        }
        die("failed to attach to ifindex %d: %s", ifindex, strerror(err));
    }

    return link_fd;
}
