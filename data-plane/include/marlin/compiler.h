/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Compiler-specific definitions for the Marlin data plane application.
 */

#pragma once

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1) // NOLINT(readability-identifier-naming) -- kernel convention, not UPPER_CASE
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0) // NOLINT(readability-identifier-naming) -- kerne convention, not UPPER_CASE
#endif
