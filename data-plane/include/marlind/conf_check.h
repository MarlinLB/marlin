/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Semantic validation of a parsed struct marlin_conf: every rule in
 * docs/design/20-configuration-validation.md, unchanged, plus the file-form
 * additions in docs/design/31-file-configuration.md §8. Runs after conf.c has
 * finished coercing every value, so every failure here is about the
 * *combination* of values, never about a value's shape.
 *
 * conf_check() also resolves what parsing alone cannot: interface names to
 * ifindex, member backend names to backend_id, and the per-backend `fib`
 * default. It mutates the model it is given for exactly those derived
 * fields, and rejects rather than mutates everything else.
 */

#pragma once

#if defined(__bpf__)
#error "include/marlind/ is host-only; do not include it from BPF sources"
#endif

#include <stdbool.h>

#include <marlind/conf.h>

/* Runs every check in the file header above. Warnings are non-fatal and land in diag->warn. */
bool conf_check(struct marlin_conf *conf, struct conf_diag *diag);

/*
 * The in-place-edit rules that only make sense against a previous
 * generation (docs/design/20-configuration-validation.md, "An in-place edit
 * of the mode bits...") and the restart-only [instance] keys
 * (docs/design/31-file-configuration.md §7). Skipped at startup, where there
 * is no baseline.
 */
bool conf_check_against_previous(const struct marlin_conf *cur, const struct marlin_conf *prev, struct conf_diag *diag);
