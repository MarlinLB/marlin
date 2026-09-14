/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Configuration from environment. See marlind.h for struct config and
 * load_config()'s prototype; see main.c's file header for the Env: list.
 */

#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <marlind/log.h>
#include <marlind/marlind.h>

#define MARLIN_DEFAULT_OBJ     "/usr/lib/marlin/marlin.bpf.o"
#define MARLIN_DEFAULT_PIN_DIR "/sys/fs/bpf/marlin"

void load_config(struct config *cfg)
{
    const char *pindir;
    int n;

    memset(cfg, 0, sizeof(*cfg));

    cfg->iface = getenv("IFACE");
    if(cfg->iface == NULL || cfg->iface[0] == '\0') {
        die("IFACE is unset -- set it in /etc/marlin/marlin.env");
    }

    cfg->obj_path = getenv("MARLIN_OBJ");
    if(cfg->obj_path == NULL || cfg->obj_path[0] == '\0') {
        cfg->obj_path = MARLIN_DEFAULT_OBJ;
    }

    pindir = getenv("MARLIN_PIN_DIR");
    if(pindir == NULL || pindir[0] == '\0') {
        pindir = MARLIN_DEFAULT_PIN_DIR;
    }

    n = snprintf(cfg->pin_dir, sizeof(cfg->pin_dir), "%s", pindir);
    if(n < 0 || (size_t)n >= sizeof(cfg->pin_dir)) {
        die("MARLIN_PIN_DIR too long");
    }

    n = snprintf(cfg->prog_pin, sizeof(cfg->prog_pin), "%s/%s", cfg->pin_dir, MARLIN_PROG_NAME);
    if(n < 0 || (size_t)n >= sizeof(cfg->prog_pin)) {
        die("MARLIN_PIN_DIR too long");
    }

    cfg->ifindex = (int)if_nametoindex(cfg->iface);
    if(cfg->ifindex == 0) {
        die("no such interface: %s", cfg->iface);
    }
}
