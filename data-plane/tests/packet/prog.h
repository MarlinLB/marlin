/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Loads build/marlin.bpf.o and runs xdp_main through bpf_prog_test_run_opts
 * -- the tier that runs the code as compiled for the datapath, alongside the
 * native tier that runs parser.c on the host (docs/design/24-testing.md,
 * "Native unit tests"). Declarations only -- defined once in prog.c and
 * linked into every xdp_*.c in this directory (data-plane/Makefile).
 */

#pragma once

#include <linux/bpf.h>
#include <linux/if_ether.h>

#include <bpf/libbpf.h>

#define XDP_PROG_NAME "xdp_main"

extern struct bpf_object *xdp_obj;
extern int xdp_prog_fd;

/*
 * Routes libbpf's own diagnostics -- including the verifier log on a load
 * failure -- to the same stderr stream as MARLIN_FAIL, so a rejected
 * program is diagnosable from test output alone. This is what makes the
 * tier double as docs/PHASES.md's verifier-load gate.
 */
void xdp_prog_load(const char *obj_path);
void xdp_prog_unload(void);

/*
 * The kernel's XDP PROG_TEST_RUN path (bpf_test_init) rejects data_size_in
 * below ETH_HLEN; packet.h's arena has no floor of its own, so a case built
 * under it would otherwise fail with an opaque -EINVAL instead of a
 * readable assertion. The upper bound here is a conservative guard, not a
 * kernel rejection -- the kernel clamps an oversized frame into fragments
 * rather than failing -- kept well under one page (256 is
 * XDP_PACKET_HEADROOM; the kernel also reserves a fixed skb_shared_info
 * tailroom) so every case here stays single-buffer and easy to reason about.
 */
#define XDP_TEST_RUN_MIN_SIZE ((__u32)ETH_HLEN)
#define XDP_TEST_RUN_MAX_SIZE ((__u32)(4096 - 256 - 320))

struct xdp_run_result {
    int retval;  /* the xdp_action xdp_main returned */
    __u32 out_len;
    int err;     /* 0, or a negative errno from a rejected data_size_in or the syscall */
};

/*
 * out_buf/out_buf_len is the frame after xdp_main runs -- the exact-byte
 * half of docs/design/24-testing.md:6 that opts.retval alone cannot assert.
 */
struct xdp_run_result xdp_run(const void *data_in, __u32 data_size_in, void *out_buf, __u32 out_buf_len,
                               __u32 ingress_ifindex);
