/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Host stand-in for bpf_xdp_adjust_head(), reached through
 * tests/stubs/bpf/bpf_helpers.h's bpf_xdp_adjust_head. The real helper moves
 * ctx->data within a frame's headroom, established once at attach time and
 * not recoverable from struct xdp_md itself, so a case must hand it over
 * with xdp_stub_attach() before calling anything that adjusts the head.
 * Whether that move is honoured is a pure function of the arguments and the
 * attached bounds -- no time, no per-CPU state -- which is what makes it
 * soundly native-testable.
 */

#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>

/*
 * Bounds enough shadow for XDP_PACKET_HEADROOM in front plus a 64 KiB frame
 * behind, with a tail guard past data_end -- wider than any pkt_len this
 * tree builds. xdp_stub_attach() dies rather than truncate silently if a
 * case ever needs more.
 */
#define XDP_STUB_SHADOW_MAX (72u * 1024u)
#define XDP_STUB_TAILGUARD  16u
#define XDP_STUB_FILL       0x5a

static unsigned char xdp_stub_shadow[XDP_STUB_SHADOW_MAX];
static unsigned char *xdp_stub_hard_start;
static unsigned int xdp_stub_window;
static int xdp_stub_attached;
static unsigned int xdp_stub_calls_;
static int xdp_stub_last_delta_;

static void xdp_stub_die(const char *what)
{
    fprintf(stderr, "tests: xdp stub: %s\n", what);
    exit(1);
}

/*
 * hard_start is the lowest address bpf_xdp_adjust_head() may move ctx->data
 * to -- the frame's real allocation start, not the arena's. data/len name
 * the frame within it. Paints [hard_start, data) and the XDP_STUB_TAILGUARD
 * bytes past data+len with a non-zero fill -- pb_reset() leaves the arena
 * zeroed, so "wrote zeros here" stays visible -- and snapshots the whole
 * window so a later diff can name exactly which bytes a call touched.
 */
static __attribute__((unused)) void xdp_stub_attach(void *hard_start, void *data, unsigned int len)
{
    unsigned char *start = (unsigned char *)hard_start;
    unsigned char *frame = (unsigned char *)data;
    unsigned int headroom = (unsigned int)(frame - start);
    unsigned int window = headroom + len + XDP_STUB_TAILGUARD;

    if(frame < start) {
        xdp_stub_die("data below hard_start");
    }

    if(window > XDP_STUB_SHADOW_MAX) {
        xdp_stub_die("frame wider than the shadow window");
    }

    memset(start, XDP_STUB_FILL, headroom);
    memset(frame + len, XDP_STUB_FILL, XDP_STUB_TAILGUARD);
    memcpy(xdp_stub_shadow, start, window);

    xdp_stub_hard_start = start;
    xdp_stub_window = window;
    xdp_stub_attached = 1;
    xdp_stub_calls_ = 0;
    xdp_stub_last_delta_ = 0;
}

static __attribute__((unused)) void xdp_stub_reset(void)
{
    xdp_stub_attached = 0;
    xdp_stub_hard_start = NULL;
    xdp_stub_window = 0;
    xdp_stub_calls_ = 0;
    xdp_stub_last_delta_ = 0;
}

static __attribute__((unused)) unsigned int xdp_stub_calls(void)
{
    return xdp_stub_calls_;
}

static __attribute__((unused)) int xdp_stub_last_delta(void)
{
    return xdp_stub_last_delta_;
}

/*
 * First/last byte offset (relative to hard_start) that no longer matches
 * the attach-time snapshot, or -1 if nothing has changed. This is the only
 * way to catch a write that lands inside the mmap'd packet arena
 * (tests/packet.h) -- AddressSanitizer has no redzones there.
 */
static __attribute__((unused)) int xdp_stub_diff_first(void)
{
    unsigned int i;

    for(i = 0; i < xdp_stub_window; i++) {
        if(xdp_stub_hard_start[i] != xdp_stub_shadow[i]) {
            return (int)i;
        }
    }

    return -1;
}

static __attribute__((unused)) int xdp_stub_diff_last(void)
{
    unsigned int i;

    for(i = xdp_stub_window; i > 0; i--) {
        if(xdp_stub_hard_start[i - 1] != xdp_stub_shadow[i - 1]) {
            return (int)(i - 1);
        }
    }

    return -1;
}

/*
 * Models net/core/filter.c's bpf_xdp_adjust_head(): moves ctx->data by
 * delta (negative grows the frame at the front, the direction ipip.c uses)
 * and refuses a move that would cross hard_start or leave under ETH_HLEN
 * before data_end. data_end is never touched -- callers that re-derive
 * pkt_len from data_end - data depend on that -- and the newly exposed
 * headroom is left as whatever xdp_stub_attach() painted it, not zeroed,
 * matching the kernel. Bytes between the old and new data are left alone,
 * which is what ipip.c relies on when it reads the relocated frame back
 * from the new offset. A rejected call still counts: ordering assertions
 * (frame_fits checked before adjust_head is even reached) need the count to
 * move only when the helper is actually called.
 */
static __attribute__((unused)) long xdp_stub_adjust_head(struct xdp_md *ctx, int delta)
{
    unsigned char *data = (unsigned char *)(unsigned long)ctx->data;
    unsigned char *data_end = (unsigned char *)(unsigned long)ctx->data_end;
    unsigned char *want = data + delta;

    if(!xdp_stub_attached) {
        xdp_stub_die("bpf_xdp_adjust_head() called before xdp_stub_attach()");
    }

    xdp_stub_calls_++;
    xdp_stub_last_delta_ = delta;

    if(want < xdp_stub_hard_start || want > data_end - ETH_HLEN) {
        return -EINVAL;
    }

    ctx->data = (__u32)(unsigned long)want;
    return 0;
}
