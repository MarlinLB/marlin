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

#include <marlind/conf.h>    /* struct marlin_conf, enum conf_load_mode */
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
/*
 * A configuration file that fails to parse or validate. Distinct from
 * EXIT_USAGE (a CLI mistake, retryable by fixing the invocation): this is
 * "unfixable by retrying, only by replacing a file", the same class
 * EXIT_INCOMPATIBLE names for an object below marlind's floor -- see
 * deploy/marlind.service's RestartPreventExitStatus and
 * docs/design/31-file-configuration.md §7.
 */
#define EXIT_CONFIG            6

#define MARLIN_DEFAULT_OBJ     "/usr/lib/marlin/marlin.bpf.o"
#define MARLIN_DEFAULT_PIN_DIR "/sys/fs/bpf/marlin"

/* File-managed mode's default; see main.c's --config handling. */
#define MARLIN_DEFAULT_CONF    "/etc/marlind/marlin.conf"

/*
 * XDP_ATTACH_NATIVE is the only mode --attach uses without --xdp-mode, and
 * refuses rather than silently degrading if the driver lacks native XDP
 * support (docs/design/02-architecture.md). XDP_ATTACH_GENERIC is an
 * explicit, operator-requested exception for a host whose native XDP_TX is
 * broken outright rather than merely absent -- discovered on this repo's own
 * netns rigs under a WSL2 kernel, where a veth's native XDP_TX silently
 * drops any frame grown by bpf_xdp_adjust_head() (ethtool -S's
 * rx_queue_N_xdp_tx_errors counts it; the BPF program itself sees no
 * failure). Never chosen automatically -- see main.c's --xdp-mode.
 */
enum xdp_attach_mode {
    XDP_ATTACH_NATIVE = 0,
    XDP_ATTACH_GENERIC,
};

/*
 * conf_path/file are NULL in environment-managed mode (no --config given).
 * With --config, [instance] is the only source of iface/obj_path/pin_dir --
 * docs/design/31-file-configuration.md D-F3.
 */
struct config {
    const char *iface;
    int ifindex;
    const char *obj_path;
    char pin_dir[PATH_MAX];
    char prog_pin[PATH_MAX];

    const char *conf_path;
    struct marlin_conf *file;
};

/*
 * mode is ignored in environment-managed mode (conf_path == NULL). With a
 * file, CONF_LOAD_INSTANCE_ONLY is what --status and --unpin want: they
 * read only iface/pin_dir, so a file whose backends are momentarily wrong
 * should not stop them from working (docs/design/31-file-configuration.md).
 */
void load_config(struct config *cfg, const char *conf_path, enum conf_load_mode mode);
void free_config(struct config *cfg);

/* Logs every warning then every error from a conf_load() call via logmsg(), prefixed with path. */
void conf_diag_log(const char *path, const struct conf_diag *diag);

/* MARLIN_OBJ/[instance].object resolved against its default, with no other requirement. */
const char *config_obj_path(const char *conf_path);
