/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Native unit tests for the version comparator and minimum marlin.bpf.o
 * version marlind refuses to attach below (include/marlind/compat.h). Pure
 * string/struct manipulation: no bpf_* helper, no map, so nothing here
 * needs tests/stubs.
 */

#include <string.h>

#include <marlin/build.h>
#include <marlind/compat.h>

#include "harness.h"

MARLIN_TEST(version_cmp_equal_triples_compare_equal)
{
    CHECK_EQ(MARLIND_VERCMP_EQUAL, marlind_version_cmp("1.2.3", "1.2.3"));
}

MARLIN_TEST(version_cmp_orders_major_then_minor_then_patch)
{
    CHECK_EQ(MARLIND_VERCMP_LESS, marlind_version_cmp("1.0.0", "2.0.0"));
    CHECK_EQ(MARLIND_VERCMP_GREATER, marlind_version_cmp("2.0.0", "1.0.0"));
    CHECK_EQ(MARLIND_VERCMP_LESS, marlind_version_cmp("1.1.0", "1.2.0"));
    CHECK_EQ(MARLIND_VERCMP_GREATER, marlind_version_cmp("1.2.0", "1.1.0"));
    CHECK_EQ(MARLIND_VERCMP_LESS, marlind_version_cmp("1.2.3", "1.2.4"));
    CHECK_EQ(MARLIND_VERCMP_GREATER, marlind_version_cmp("1.2.4", "1.2.3"));
}

/*
 * The highest-value case here: a byte-wise or strcmp()-style comparison
 * gets this backwards, because "10" sorts before "9" lexicographically.
 */
MARLIN_TEST(version_cmp_is_numeric_not_lexicographic)
{
    CHECK_EQ(MARLIND_VERCMP_GREATER, marlind_version_cmp("1.10.0", "1.9.0"));
    CHECK_EQ(MARLIND_VERCMP_GREATER, marlind_version_cmp("1.0.10", "1.0.9"));
}

MARLIN_TEST(version_cmp_prerelease_is_below_its_release)
{
    CHECK_EQ(MARLIND_VERCMP_LESS, marlind_version_cmp("1.0.0-dev", "1.0.0"));
    CHECK_EQ(MARLIND_VERCMP_GREATER, marlind_version_cmp("1.0.0", "1.0.0-dev"));
}

/*
 * Pins the deliberate narrowing from full SemVer SS11.4 documented in
 * docs/design/29-versions.md: two pre-releases of one triple are not
 * ordered by identifier, only equated. Exists so a later "fix" toward full
 * SS11.4 precedence is a decision, not an accident.
 */
MARLIN_TEST(version_cmp_does_not_order_two_prereleases)
{
    CHECK_EQ(MARLIND_VERCMP_EQUAL, marlind_version_cmp("1.0.0-rc.1", "1.0.0-rc.2"));
    CHECK_EQ(MARLIND_VERCMP_EQUAL, marlind_version_cmp("1.0.0-dev", "1.0.0-alpha"));
}

MARLIN_TEST(version_cmp_ignores_build_metadata)
{
    CHECK_EQ(MARLIND_VERCMP_EQUAL, marlind_version_cmp("1.0.0+abc", "1.0.0"));
    CHECK_EQ(MARLIND_VERCMP_EQUAL, marlind_version_cmp("1.0.0-dev+abc", "1.0.0-dev"));
}

/*
 * Unparseable is a third outcome, never coerced to LESS -- an object
 * whose version this comparator cannot read is not the same thing as one
 * that read as too old.
 */
MARLIN_TEST(version_cmp_rejects_malformed_input_without_calling_it_lower)
{
    static const char *bad[] = {
        "",
        "1",
        "1.2",
        "1.2.3.4",
        "v1.2.3",
        "1.2.x",
        "abc",
        "99999999999999999999.0.0",
    };
    size_t i;

    for(i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        CHECK_EQ(MARLIND_VERCMP_UNPARSEABLE, marlind_version_cmp(bad[i], "1.0.0"));
    }
}

/*
 * struct marlin_build's version field need not be NUL-terminated -- an
 * object marlind did not write can fill it edge to edge. On the stack so
 * ASan (data-plane/Makefile's TEST_SANITIZE) catches an overread rather
 * than passing quietly.
 */
MARLIN_TEST(build_version_bounds_a_field_with_no_terminator)
{
    struct marlin_build build;
    char out[MARLIN_VERSION_MAX + 1];

    memset(&build, 'A', sizeof(build));
    build.magic = MARLIN_BUILD_MAGIC;

    marlind_build_version(&build, out, sizeof(out));

    CHECK_EQ(MARLIN_VERSION_MAX, strlen(out));
    CHECK_EQ('\0', out[MARLIN_VERSION_MAX]);
}

/* Fails make tests the moment someone types a malformed floor. */
MARLIN_TEST(min_bpf_version_is_itself_parseable)
{
    CHECK_EQ(MARLIND_COMPAT_OK, marlind_bpf_object_supported(MARLIND_MIN_BPF_VERSION));
}

/*
 * Documents the trap a "0.0.0" floor would be: under the pre-release rule
 * above, 0.0.0-dev < 0.0.0, so the floor must itself carry "-dev" for as
 * long as data-plane/bpf/VERSION does, or --attach refuses the object
 * built alongside it in the same `make all`.
 */
MARLIN_TEST(the_current_tree_clears_its_own_floor)
{
    CHECK_EQ(MARLIND_COMPAT_OK, marlind_bpf_object_supported("0.0.0-dev"));
}

int main(void)
{
    return marlin_tests_main();
}
