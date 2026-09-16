/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Entry point for the bpf_prog_test_run tier: brings up the FIB netns
 * fixture, loads build/marlin.bpf.o, and runs every case the other xdp_*.c
 * files in this directory registered (docs/design/24-testing.md, "Native
 * unit tests"). No MARLIN_TEST case lives in this file, deliberately --
 * see the header comment on tests/support/harness.c for why the case
 * registry is shared rather than per-TU.
 */
#define _GNU_SOURCE

#include <sched.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../harness.h"
#include "fib.h"
#include "maps.h"
#include "prog.h"

int main(int argc, char **argv)
{
    const char *obj_path = (argc > 1) ? argv[1] : "build/marlin.bpf.o";
    struct marlin_config cfg;
    int rc;

    if(unshare(CLONE_NEWNET) != 0) {
        fprintf(stderr, "packet-tests: unshare(CLONE_NEWNET) failed: %s\n", strerror(errno));
        exit(1);
    }

    fib_topology_up();

    xdp_prog_load(obj_path);

    memset(&cfg, 0, sizeof(cfg));
    xdp_seed_config(&cfg);

    rc = marlin_tests_main();

    xdp_prog_unload();
    return rc;
}
