/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Load marlin.bpf.o, pin its maps and program, and create the bpf_link that
 * attaches it in native XDP mode.
 */

#pragma once

#include <bpf/libbpf.h>

struct bpf_object *load_and_pin_maps(const char *obj_path, const char *pin_dir);
struct bpf_program *pin_program(struct bpf_object *obj, const char *obj_path, const char *prog_pin);
int attach_link(int prog_fd, const char *iface, int ifindex);
