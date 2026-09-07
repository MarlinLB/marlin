/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Source-filtering verdict and the marlin_acl_check() prototype
 * (docs/design/27-source-filtering.md, docs/design/03-translation-units.md).
 * Only marlin_acl_check() is a global subprogram; the per-family checks are
 * static to acl.c.
 */

#pragma once

#include <marlin/marlin.h>

enum marlin_acl_verdict {
    MARLIN_ACL_NONE = 0, /* no rule matched, or the ACL is disabled */
    MARLIN_ACL_ALLOW,    /* admit, and never meter */
    MARLIN_ACL_BLOCK,    /* drop, MARLIN_DROP_ACL_BLOCKED */
};

int marlin_acl_check(const struct marlin_ctx *mctx);
