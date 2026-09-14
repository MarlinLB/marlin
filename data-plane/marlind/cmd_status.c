/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * status -- one-shot probe, no output parsing anywhere.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <linux/bpf.h>

#include <bpf/bpf.h>

#include <marlind/cmd.h>
#include <marlind/log.h>
#include <marlind/marlind.h>

int attach_probe(const struct config *cfg, struct attach_probe *probe)
{
    __u32 id = 0;
    __u32 pinned_prog_id = 0;
    bool have_pinned_id = false;
    int pin_fd;

    memset(probe, 0, sizeof(*probe));

    pin_fd = bpf_obj_get(cfg->prog_pin);
    if(pin_fd >= 0) {
        struct bpf_prog_info info;
        __u32 info_len = sizeof(info);

        memset(&info, 0, sizeof(info));
        if(bpf_obj_get_info_by_fd(pin_fd, &info, &info_len) == 0) {
            pinned_prog_id = info.id;
            have_pinned_id = true;
        }
        close(pin_fd);
    }

    for(;;) {
        struct bpf_link_info info;
        __u32 info_len = sizeof(info);
        int link_fd;
        int err = bpf_link_get_next_id(id, &id);

        if(err != 0) {
            /*
             * -ENOENT is "no more links" -- normal loop exit. Anything else
             * (EPERM without CAP_BPF, most likely) is a real failure that
             * must not be reported as "not attached": an unprivileged
             * caller would otherwise see a false negative instead of being
             * told why the probe couldn't run.
             */
            if(err != -ENOENT) {
                die("failed to enumerate BPF links: %s", strerror(-err));
            }
            break;
        }

        link_fd = bpf_link_get_fd_by_id(id);
        if(link_fd < 0) {
            continue;
        }

        memset(&info, 0, sizeof(info));
        if(bpf_obj_get_info_by_fd(link_fd, &info, &info_len) != 0) {
            close(link_fd);
            continue;
        }
        close(link_fd);

        if(info.type != BPF_LINK_TYPE_XDP || info.xdp.ifindex != (__u32)cfg->ifindex) {
            continue;
        }

        probe->link_id = info.id;
        probe->prog_id = info.prog_id;

        if(!have_pinned_id || info.prog_id != pinned_prog_id) {
            return EXIT_FOREIGN;
        }
        return EXIT_ATTACHED;
    }

    return EXIT_NOT_ATTACHED;
}

int cmd_status(void)
{
    struct config cfg;
    struct attach_probe probe;
    int rc;

    load_config(&cfg);
    rc = attach_probe(&cfg, &probe);

    switch(rc) {
    case EXIT_FOREIGN:
        printf("foreign: link %u on %s runs prog id %u, pins under %s expect a different program\n", probe.link_id, cfg.iface,
               probe.prog_id, cfg.pin_dir);
        break;
    case EXIT_ATTACHED:
        printf("attached: %s (id %u) on %s (ifindex %d) via link %u; pins under %s\n", MARLIN_PROG_NAME, probe.prog_id, cfg.iface,
               cfg.ifindex, probe.link_id, cfg.pin_dir);
        break;
    default:
        printf("not attached: no XDP link on %s\n", cfg.iface);
        break;
    }

    return rc;
}
