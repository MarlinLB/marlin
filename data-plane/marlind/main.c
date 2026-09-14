/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Marlin data-plane loader. Creates the bpf_link that attaches marlin.bpf.o
 * to an interface in native XDP mode and holds it for as long as this
 * process runs, so that the process being alive is the only measure of
 * "attached" a caller ever needs -- see docs/design/02-architecture.md and
 * docs/DEPLOYMENT.md §1.2. A link-owned attach cannot be replaced or removed
 * from outside this process; `ip link set ... xdp off` and `bpftool net
 * detach` both fail with EBUSY against it.
 *
 * Usage: marlind attach | status | unload
 *
 *   attach  preflight, load (reusing pinned maps), pin, attach, then block
 *           until SIGTERM/SIGINT or the interface disappears
 *   status  one-shot probe of the current attach state; see EXIT_* below
 *   unload  remove the pins; refuses while attached
 *
 * Env: IFACE (required), MARLIN_OBJ, MARLIN_PIN_DIR (see load_config()).
 */

#include <stdio.h>
#include <string.h>

#include <marlind/cmd.h>
#include <marlind/marlind.h>

static void usage(const char *argv0)
{
    fprintf(stderr, "usage: %s attach|status|unload\n", argv0);
}

int main(int argc, char **argv)
{
    if(argc != 2) {
        usage(argv[0]);
        return EXIT_USAGE;
    }

    if(strcmp(argv[1], "attach") == 0) {
        return cmd_attach();
    }
    if(strcmp(argv[1], "status") == 0) {
        return cmd_status();
    }
    if(strcmp(argv[1], "unload") == 0) {
        return cmd_unload();
    }

    usage(argv[0]);
    return EXIT_USAGE;
}
