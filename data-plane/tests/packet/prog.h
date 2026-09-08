/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Loads build/marlin.bpf.o and runs xdp_main through bpf_prog_test_run_opts
 * -- the tier that runs the code as compiled for the datapath, alongside the
 * native tier that runs parser.c on the host (docs/design/24-testing.md,
 * "Native unit tests").
 */

#pragma once

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define XDP_PROG_NAME "xdp_main"

static struct bpf_object *xdp_obj;
static int xdp_prog_fd = -1;

/*
 * libbpf 1.x reports open/load failures as NULL/-1 with errno set, not the
 * pre-1.0 libbpf_get_error() encoding -- that function no longer exists.
 */
static int xdp_prog_print_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if(level > LIBBPF_INFO) {
        return 0;
    }

    return vfprintf(stderr, fmt, args);
}

/*
 * Routes libbpf's own diagnostics -- including the verifier log on a load
 * failure -- to the same stderr stream as MARLIN_FAIL, so a rejected
 * program is diagnosable from test output alone. This is what makes the
 * tier double as docs/PHASES.md's verifier-load gate.
 */
static void xdp_prog_load(const char *obj_path)
{
    struct bpf_program *prog;

    libbpf_set_print(xdp_prog_print_fn);

    xdp_obj = bpf_object__open_file(obj_path, NULL);
    if(xdp_obj == NULL) {
        fprintf(stderr, "packet-tests: failed to open %s: %s\n", obj_path, strerror(errno));
        exit(1);
    }

    if(bpf_object__load(xdp_obj) != 0) {
        fprintf(stderr, "packet-tests: failed to load %s (see verifier log above): %s\n", obj_path, strerror(errno));
        exit(1);
    }

    prog = bpf_object__find_program_by_name(xdp_obj, XDP_PROG_NAME);
    if(prog == NULL) {
        fprintf(stderr, "packet-tests: program \"%s\" not found in %s\n", XDP_PROG_NAME, obj_path);
        exit(1);
    }

    xdp_prog_fd = bpf_program__fd(prog);
    if(xdp_prog_fd < 0) {
        fprintf(stderr, "packet-tests: no fd for program \"%s\": %s\n", XDP_PROG_NAME, strerror(errno));
        exit(1);
    }
}

static void xdp_prog_unload(void)
{
    if(xdp_obj != NULL) {
        bpf_object__close(xdp_obj);
        xdp_obj = NULL;
    }

    xdp_prog_fd = -1;
}

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
static struct xdp_run_result xdp_run(const void *data_in, __u32 data_size_in, void *out_buf, __u32 out_buf_len,
                                     __u32 ingress_ifindex)
{
    struct xdp_run_result result;
    struct xdp_md ctx_in;
    struct xdp_md ctx_out;

    memset(&result, 0, sizeof(result));

    if(data_size_in < XDP_TEST_RUN_MIN_SIZE || data_size_in > XDP_TEST_RUN_MAX_SIZE) {
        /*
         * retval stays out of enum xdp_action range (never a bare memset(0),
         * which reads as the plausible-looking XDP_ABORTED) so this failure
         * cannot be mistaken for a verdict the program returned.
         */
        fprintf(stderr, "packet-tests: data_size_in=%u outside the kernel's [%u, %u] for XDP PROG_TEST_RUN\n",
                data_size_in, XDP_TEST_RUN_MIN_SIZE, XDP_TEST_RUN_MAX_SIZE);
        result.err = -EINVAL;
        result.retval = -1;
        return result;
    }

    /*
     * bpf_prog_test_run_xdp (net/bpf/test_run.c) rejects ctx_in outright
     * unless ctx->data_end == data_size_in exactly -- "There can't be user
     * provided data before the meta data" -- so this is not optional
     * zero-fill; data_meta must be 0 (no metadata) and data stays 0 (no
     * headroom claimed for it), but data_end must mirror data_size_in or
     * every call is rejected with -EINVAL before xdp_main ever runs.
     *
     * ingress_ifindex must stay 0 until a case supplies a real interface:
     * a non-zero value sends the kernel through dev_get_by_index() and
     * then xdp_rxq_info_is_reg() (xdp_convert_md_to_buff), which no
     * interface satisfies outside the netns/veth integration tier -- not
     * even loopback registers XDP rxq info. This does not mean the program
     * observes ingress_ifindex 0: xdp_convert_md_to_buff() only overrides
     * the rxq for a non-zero value, so a zero one leaves the run bound to
     * the calling process's network namespace's loopback device, and
     * ctx->ingress_ifindex reads that device's ifindex -- 1, not 0. See
     * xdp_test.c's nexthop_interim_* section for where that matters.
     */
    memset(&ctx_in, 0, sizeof(ctx_in));
    ctx_in.data_end = data_size_in;
    ctx_in.ingress_ifindex = ingress_ifindex;

    LIBBPF_OPTS(bpf_test_run_opts, opts,
                .data_in = data_in,
                .data_size_in = data_size_in,
                .data_out = out_buf,
                .data_size_out = out_buf_len,
                .ctx_in = &ctx_in,
                .ctx_size_in = sizeof(ctx_in),
                .ctx_out = &ctx_out,
                .ctx_size_out = sizeof(ctx_out),
                .repeat = 1);

    if(bpf_prog_test_run_opts(xdp_prog_fd, &opts) != 0) {
        fprintf(stderr, "packet-tests: bpf_prog_test_run_opts failed: %s\n", strerror(errno));
        result.err = -errno;
        result.retval = -1;
        return result;
    }

    result.retval = (int)opts.retval;
    result.out_len = opts.data_size_out;
    return result;
}
