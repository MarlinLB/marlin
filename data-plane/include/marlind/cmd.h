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

int cmd_attach(void);
int cmd_status(void);
int cmd_unpin(void);
