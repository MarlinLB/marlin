/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * The three marlind subcommands, and the silent attach-state probe both
 * status and unpin need. Kept out of attach_probe(): it must never print,
 * so that `marlind --unpin` can call it without emitting a status line
 * ahead of its own.
 */

#pragma once

#include <stdint.h>

#include <marlind/marlind.h>

struct attach_probe {
    uint32_t link_id;
    uint32_t prog_id;
};

/* Returns EXIT_ATTACHED, EXIT_FOREIGN or EXIT_NOT_ATTACHED; prints nothing. */
int attach_probe(const struct config *cfg, struct attach_probe *probe);

/* conf_path is NULL for environment-managed mode; see marlind.h's load_config(). */
int cmd_attach(const char *conf_path);
int cmd_status(const char *conf_path);
int cmd_unpin(const char *conf_path);

/*
 * Parses and validates conf_path with no privilege and no map access
 * (docs/design/31-file-configuration.md §7); every rejection is printed to
 * stderr. Returns EXIT_ATTACHED on success, EXIT_CONFIG on rejection.
 */
int cmd_check(const char *conf_path);
