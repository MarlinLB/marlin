/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Logging and systemd notification. die() is _Noreturn on this declaration,
 * not only on its definition: without it, callers such as cmd_unpin()'s
 * opendir() failure path read as falling through to code that assumes a
 * non-NULL dir/fd, which is what an undeclared-noreturn die() made the
 * static analyzer flag.
 */

#pragma once

void logmsg(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
_Noreturn void die(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* Like die(), but with a caller-chosen exit code -- EXIT_INCOMPATIBLE, not EXIT_USAGE, for a version floor breach. */
_Noreturn void die_with(int code, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

/*
 * Reimplements sd_notify(3) over its wire format directly rather than
 * linking libsystemd, for one call site.
 */
void notify(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
