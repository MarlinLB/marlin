/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * lb_core.h - Load balancing core header: LB core API definitions.
 * The LB core is the core processing entity of packets in the Marlin
 * load balancer. This TU defines wether the packet is safe to balance,
 * and to which backend the packet is sent.
 */

#pragma once

#include <linux/bpf.h>

#include <marlin/marlin.h>

#define MARLIN_NO_BACKEND 0

extern int marlin_lb_process(struct xdp_md *md, struct marlin_ctx *pkt);
