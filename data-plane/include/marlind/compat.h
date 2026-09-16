/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * The oldest marlin.bpf.o this marlind will attach, and the comparator that
 * enforces it. A compatibility claim about other builds, not a fact about
 * this one -- unlike marlin/version.h and marlind/version.h, this is a
 * hand-written literal, never generated. verifier_stats deliberately does
 * not include this header: it is a dev tool that inspects arbitrary
 * objects and must not refuse any of them.
 */

#pragma once

#if defined(__bpf__)
#error "include/marlind/ is host-only; do not include it from BPF sources"
#endif

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <marlin/build.h>

/*
 * Bumped by hand alongside data-plane/marlind/VERSION whenever a marlind
 * change relies on a marlin.bpf.o feature older objects lack. Must itself
 * parse (marlind_bpf_object_supported() below) and must not exceed a
 * struct marlin_build's version field, or no object -- including one built
 * from the same tree -- could ever clear it.
 */
#define MARLIND_MIN_BPF_VERSION "0.0.0-dev"

_Static_assert(sizeof(MARLIND_MIN_BPF_VERSION) <= MARLIN_VERSION_MAX,
               "MARLIND_MIN_BPF_VERSION too long for struct marlin_build's version field");

enum marlind_vercmp {
    MARLIND_VERCMP_LESS,
    MARLIND_VERCMP_EQUAL,
    MARLIND_VERCMP_GREATER,
    MARLIND_VERCMP_UNPARSEABLE,
};

enum marlind_compat {
    MARLIND_COMPAT_OK,
    MARLIND_COMPAT_TOO_OLD,
    MARLIND_COMPAT_UNPARSEABLE,
};

struct marlind_semver {
    unsigned long major;
    unsigned long minor;
    unsigned long patch;
    bool prerelease;
};

/*
 * Consumes decimal digits at *p into *out, advancing *p past them. Bounds
 * the accumulator itself rather than parsing then range-checking, so a
 * version field with an absurd digit count (an object is untrusted input)
 * cannot overflow `unsigned long` before the check runs.
 */
static inline bool marlind_parse_uint_field(const char **cur, unsigned long *out)
{
    const char *str = *cur;
    unsigned long val = 0;
    int ndigits = 0;

    while(*str >= '0' && *str <= '9') {
        if(val > (0xffffffffUL - 9) / 10) {
            return false;
        }
        val = val * 10 + (unsigned long)(*str - '0');
        str++;
        ndigits++;
    }

    if(ndigits == 0) {
        return false;
    }

    *out = val;
    *cur = str;
    return true;
}

/*
 * major.minor.patch, each an unsigned decimal, then optionally a '-'
 * pre-release or '+' build metadata tag whose content this project never
 * inspects beyond the '-' tag's presence (docs/design/29-versions.md).
 * Anything else after the patch number -- a suffix with neither separator,
 * a fourth dotted field, a leading 'v' -- is malformed rather than guessed
 * at: an object's embedded version is untrusted input, and a wrong guess
 * here is a compatibility check that silently accepts what it should
 * refuse.
 */
static inline bool marlind_parse_semver(const char *str, struct marlind_semver *out)
{
    const char *cur = str;

    if(!marlind_parse_uint_field(&cur, &out->major) || *cur != '.') {
        return false;
    }
    cur++;

    if(!marlind_parse_uint_field(&cur, &out->minor) || *cur != '.') {
        return false;
    }
    cur++;

    if(!marlind_parse_uint_field(&cur, &out->patch)) {
        return false;
    }

    if(*cur == '-') {
        out->prerelease = true;
    } else if(*cur == '+' || *cur == '\0') {
        out->prerelease = false;
    } else {
        return false;
    }

    return true;
}

/*
 * Reduced SemVer 2.0.0 precedence (SS11): numeric major.minor.patch, build
 * metadata ignored (SS10), a pre-release ordered below its own release
 * (SS11.3). Narrowed from full SS11.4 in one place only -- two pre-releases
 * of the same triple compare equal rather than ordering by identifier --
 * which cannot misorder any version this project has produced and is
 * documented, not hedged, in docs/design/29-versions.md. Unparseable input
 * is a third outcome, never coerced to LESS: a floor exists to refuse old
 * objects, not ones this comparator merely failed to read.
 */
static inline enum marlind_vercmp marlind_version_cmp(const char *lhs, const char *rhs)
{
    struct marlind_semver va;
    struct marlind_semver vb;

    if(!marlind_parse_semver(lhs, &va) || !marlind_parse_semver(rhs, &vb)) {
        return MARLIND_VERCMP_UNPARSEABLE;
    }

    if(va.major != vb.major) {
        return va.major < vb.major ? MARLIND_VERCMP_LESS : MARLIND_VERCMP_GREATER;
    }
    if(va.minor != vb.minor) {
        return va.minor < vb.minor ? MARLIND_VERCMP_LESS : MARLIND_VERCMP_GREATER;
    }
    if(va.patch != vb.patch) {
        return va.patch < vb.patch ? MARLIND_VERCMP_LESS : MARLIND_VERCMP_GREATER;
    }

    if(va.prerelease == vb.prerelease) {
        return MARLIND_VERCMP_EQUAL;
    }
    return va.prerelease ? MARLIND_VERCMP_LESS : MARLIND_VERCMP_GREATER;
}

static inline enum marlind_compat marlind_bpf_object_supported(const char *version)
{
    switch(marlind_version_cmp(version, MARLIND_MIN_BPF_VERSION)) {
    case MARLIND_VERCMP_UNPARSEABLE:
        return MARLIND_COMPAT_UNPARSEABLE;
    case MARLIND_VERCMP_LESS:
        return MARLIND_COMPAT_TOO_OLD;
    default:
        return MARLIND_COMPAT_OK;
    }
}

/*
 * struct marlin_build's version field is 64 bytes read straight from an
 * object file marlind did not write and need not be NUL-terminated --
 * strnlen() bounds the scan to sizeof(build->version) so an all-non-NUL
 * field cannot run this past the struct. `out` must hold at least
 * MARLIN_VERSION_MAX + 1 bytes.
 */
static inline void marlind_build_version(const struct marlin_build *build, char *out, size_t out_sz)
{
    size_t len;

    if(out_sz == 0) {
        return;
    }

    len = strnlen(build->version, sizeof(build->version));
    if(len >= out_sz) {
        len = out_sz - 1;
    }

    memcpy(out, build->version, len);
    out[len] = '\0';
}
