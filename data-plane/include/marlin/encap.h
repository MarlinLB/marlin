/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Protocol encapsulation definitions. Contains the TU
 * definitions for different encapsulation protocols used in Marlin.
 */

#pragma once

#include <linux/bpf.h>
#include <marlin/marlin.h>

int marlin_gue_encap_packet(struct xdp_md *ctx, struct marlin_ctx *mctx);
int marlin_vxlan_encap_packet(struct xdp_md *ctx, struct marlin_ctx *mctx);
int marlin_ipip_encap_packet(struct xdp_md *ctx, struct marlin_ctx *mctx);
