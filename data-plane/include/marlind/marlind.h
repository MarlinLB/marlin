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

/* bpftool pins each program under its C function name, not its section name. */
#define MARLIN_PROG_NAME       "xdp_main"

/*
 * A literal, not a build-time git describe: no packaging exists yet
 * (docs/DEPLOYMENT.md), and a -D on every marlind TU would rebuild the
 * whole loader on each commit and make tarball builds disagree with git
 * builds. See docs/PHASES.md's open-decision table for where this comes
 * from once packaging does exist.
 */
#define MARLIN_VERSION          "0.0.0-dev"

#define EXIT_ATTACHED          0
#define EXIT_USAGE             1
#define EXIT_NOT_ATTACHED      3
#define EXIT_FOREIGN           4

struct config {
    const char *iface;
    int ifindex;
    const char *obj_path;
    char pin_dir[PATH_MAX];
    char prog_pin[PATH_MAX];
};

void load_config(struct config *cfg);
