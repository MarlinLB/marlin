/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Shared configuration type and CLI exit codes for the marlind loader.
 * Host-only: marlind links against libbpf and glibc, so this header must
 * never be reachable from a -target bpf translation unit.
 */

#pragma once

#if defined(__bpf__)
#error "include/marlind/ is host-only; do not include it from BPF sources"
#endif

#include <limits.h>

#include <marlind/version.h> /* generated from data-plane/marlind/VERSION; defines MARLIND_VERSION */

/* bpftool pins each program under its C function name, not its section name. */
#define MARLIN_PROG_NAME       "xdp_main"

/* Pinned under <pin_dir>/version; the .rodata global marlin.bpf.o's own copy comes from. */
#define MARLIN_VERSION_PIN     "version"

#define EXIT_ATTACHED          0
#define EXIT_USAGE             1
#define EXIT_NOT_ATTACHED      3
#define EXIT_FOREIGN           4
#define EXIT_INCOMPATIBLE      5

struct config {
    const char *iface;
    int ifindex;
    const char *obj_path;
    char pin_dir[PATH_MAX];
    char prog_pin[PATH_MAX];
};

void load_config(struct config *cfg);

/* MARLIN_OBJ resolved against its default, with no other config or env requirement. */
const char *config_obj_path(void);
