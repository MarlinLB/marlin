/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Wire-protocol constants the UAPI headers do not supply under -target bpf.
 * NOT ABI: nothing here is mirrored by the control plane (docs/REPO-STRUCTURE.md,
 * "every file under abi/ has a C# counterpart -- nothing else does").
 */

#pragma once

#include <linux/types.h>

#ifndef IP_OFFSET
#define IP_OFFSET 0x1fff
#endif
#ifndef IP_MF
#define IP_MF 0x2000
#endif
#ifndef IP_DF
#define IP_DF 0x4000 /* unused in Phase 1; the encap units set it in 2b */
#endif

#define MARLIN_IPV4_IHL_MIN 5
