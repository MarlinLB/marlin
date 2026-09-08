/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Shadows libbpf's <bpf/bpf_helpers.h> for the native tier only, reached by
 * putting tests/stubs ahead of the system include path. libbpf's version
 * declares every helper as a function pointer holding its helper id --
 * bpf_map_lookup_elem is literally (void *)1 -- which compiles on the host
 * and segfaults when called, so a translation unit that reads a map, or
 * that calls a helper like bpf_xdp_adjust_head(), cannot be tested natively
 * against it. The map macros expand to the same field declarations
 * libbpf's do, so include/marlin/maps.h is compiled unmodified.
 */

#pragma once

/*
 * Also claims libbpf's own guard, so the real header is inert if some other
 * include path ever reaches it after this one. */
#define __BPF_HELPERS__

#include "../map_stub.h"
#include "../xdp_stub.h"

#define __uint(name, val)  int (*name)[val]
#define __type(name, val)  typeof(val) *name
#define __array(name, val) typeof(val) *name[]

/*
 * No section attribute: nothing native reads ELF sections, and a custom
 * section would exclude the map objects from AddressSanitizer's global
 * instrumentation -- these are the objects whose addresses the stub keys on.
 * `used` still matters, so a map only ever referenced by address survives -O1.
 */
#define SEC(name) __attribute__((used))

#undef __always_inline
#define __always_inline inline __attribute__((always_inline))

#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif
#ifndef __weak
#define __weak __attribute__((weak))
#endif
#ifndef __hidden
#define __hidden __attribute__((visibility("hidden")))
#endif

#ifndef NULL
#define NULL ((void *)0)
#endif

static __attribute__((unused)) void *bpf_map_lookup_elem(void *map, const void *key)
{
    return acl_stub_lookup(map, key);
}

static __attribute__((unused)) long bpf_xdp_adjust_head(struct xdp_md *ctx, int delta)
{
    return xdp_stub_adjust_head(ctx, delta);
}

/*
 * nexthop.c's FIB fallback and redirect path are the packet tier's job
 * (tests/packet/xdp_test.c's nexthop_interim_* section, a real kernel FIB):
 * unlike bpf_map_lookup_elem and bpf_xdp_adjust_head, there is no native
 * model of either helper here. These exist only so the translation unit
 * links; a native case that reaches past a NULL-argument check into either
 * would need the packet tier instead, not a fake result from here.
 */
static __attribute__((unused)) long bpf_fib_lookup(void *ctx, struct bpf_fib_lookup *params, int plen, __u32 flags)
{
    (void)ctx;
    (void)params;
    (void)plen;
    (void)flags;
    fprintf(stderr, "tests: bpf_fib_lookup() has no native stub; run the packet tier instead\n");
    exit(1);
}

static __attribute__((unused)) long bpf_redirect_map(void *map, __u64 key, __u64 flags)
{
    (void)map;
    (void)key;
    (void)flags;
    fprintf(stderr, "tests: bpf_redirect_map() has no native stub; run the packet tier instead\n");
    exit(1);
}
