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
 * Sets a pin path on every map before loading, so libbpf's own reuse logic
 * (bpf_object__load() -> bpf_object__reuse_map()) picks up whatever is
 * already pinned under pin_dir and creates the rest -- the program always
 * loads fresh from obj_path, but map contents and VIP configuration survive
 * both a restart and a datapath upgrade, as long as no map's definition has
 * changed. A definition that did change fails reuse with a libbpf error;
 * `marlind --unpin` clears the old pins deliberately.
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
        int n = snprintf(path, sizeof(path), "%s/%s", pin_dir, bpf_map__name(map));

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

    err = bpf_object__pin_maps(obj, pin_dir);
    if(err != 0) {
        die("failed to pin maps under %s: %s", pin_dir, strerror(-err));
    }

    return obj;
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
