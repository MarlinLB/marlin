/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Reconciles marlin.bpf.o's maps to a parsed struct marlin_conf
 * (docs/design/31-file-configuration.md). The configuration file is
 * authoritative and the maps are not (docs/design/19-control-plane.md,
 * "Restart and reconciliation") -- every write here is unconditional, and a
 * map is read back only to learn what this reconcile must remove.
 */

#pragma once

#if defined(__bpf__)
#error "include/marlind/ is host-only; do not include it from BPF sources"
#endif

#include <stdbool.h>

#include <bpf/libbpf.h>

#include <marlind/conf.h>

/*
 * Reconciles every map in obj to conf, in the write order
 * docs/design/12-selection.md, docs/design/27-source-filtering.md and
 * docs/design/31-file-configuration.md §8 require. Returns true on success;
 * on false the caller decides whether that is fatal (startup: yes, refuse
 * before attaching; SIGHUP reload: no, log and keep serving the previous
 * generation -- docs/design/31-file-configuration.md §7).
 *
 * obj must already be loaded (bpf_object__load()) with every map pinned or
 * freshly created -- the same object cmd_attach.c holds between
 * load_and_pin_maps() and attach_link().
 *
 * conf is not const: this is where vip_meta.vip_num is allocated
 * (docs/design/31-file-configuration.md §5), and it is written back into
 * conf->vips[].meta so a caller keeping this model as the next reload's
 * baseline sees the assignment that is now live in vip_map.
 */
bool reconcile_apply(struct bpf_object *obj, struct marlin_conf *conf, struct conf_diag *diag);
