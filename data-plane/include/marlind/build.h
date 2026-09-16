/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Reads marlin.bpf.o's embedded struct marlin_build back out of an opened
 * bpf_object -- shared by marlind (--version, --status, pin_version() in
 * bpf_load.c) and verifier_stats, neither of which otherwise depends on the
 * other.
 */

#pragma once

#if defined(__bpf__)
#error "include/marlind/ is host-only; do not include it from BPF sources"
#endif

#include <bpf/libbpf.h>

#include <marlin/build.h>

/*
 * Matched by magic, not by map name: bpftool gen object links marlin.bpf.o
 * from several TUs, and libbpf derives internal map names from the object's
 * own basename (internal_map_name(), libbpf.c), which this header has no
 * business assuming. Works both before and after bpf_object__load(): the
 * map is never reused (load_and_pin_maps() in bpf_load.c excludes internal
 * maps deliberately), so the anonymous buffer bpf_map__initial_value()
 * returns is what a fresh load also just wrote into the kernel map.
 */
static inline struct bpf_map *marlin_find_build_map(struct bpf_object *obj)
{
    struct bpf_map *map;

    bpf_object__for_each_map(map, obj)
    {
        size_t value_size = 0;
        const void *value;

        if(!bpf_map__is_internal(map)) {
            continue;
        }

        value = bpf_map__initial_value(map, &value_size);
        if(value != NULL && value_size == sizeof(struct marlin_build) &&
           ((const struct marlin_build *)value)->magic == MARLIN_BUILD_MAGIC) {
            return map;
        }
    }

    return NULL;
}

/* Returns NULL if obj predates this map, or holds no such global at all. */
static inline const struct marlin_build *marlin_build_from_object(struct bpf_object *obj)
{
    struct bpf_map *map = marlin_find_build_map(obj);
    size_t value_size;

    if(map == NULL) {
        return NULL;
    }

    return bpf_map__initial_value(map, &value_size);
}
