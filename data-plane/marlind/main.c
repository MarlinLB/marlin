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
 * Usage: marlind --attach | --status | --unpin | --help | --version
 *
 *   --attach  preflight, load (reusing pinned maps), pin, attach, then block
 *             until SIGTERM/SIGINT or the interface disappears
 *   --status  one-shot probe of the current attach state; see EXIT_* below
 *   --unpin   remove the pins; refuses while attached
 *
 * There is no --detach: the attach is bpf_link-owned and held for the
 * process's lifetime, so SIGTERM is the only way to end it.
 *
 * Env: IFACE (required), MARLIN_OBJ, MARLIN_PIN_DIR (see load_config()).
 */

#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include <bpf/libbpf.h>

#include <marlind/build.h>
#include <marlind/cmd.h>
#include <marlind/marlind.h>

enum mode {
    MODE_NONE = 0,
    MODE_ATTACH,
    MODE_STATUS,
    MODE_UNPIN,
};

static void usage(FILE *out, const char *argv0)
{
    fprintf(out, "usage: %s --attach|--status|--unpin\n", argv0);
    fprintf(out, "       %s --help|--version\n", argv0);
}

/*
 * A mismatched pair is visible here, before attaching, rather than only
 * after -- config_obj_path(), not load_config(): --version must exit 0 with
 * no IFACE set (docs/DEPLOYMENT.md), and opening a file to read its .rodata
 * needs no privilege.
 */
static void print_version(void)
{
    const char *path = config_obj_path();
    struct bpf_object *obj;

    printf("marlind %s\n", MARLIN_VERSION);

    obj = bpf_object__open_file(path, NULL);
    if(obj == NULL) {
        return;
    }

    const struct marlin_build *build = marlin_build_from_object(obj);

    if(build != NULL) {
        const char *base = strrchr(path, '/');

        printf("%s %.*s (%s)\n", base != NULL ? base + 1 : path, (int)sizeof(build->version), build->version, path);
    }

    bpf_object__close(obj);
}

int main(int argc, char **argv)
{
    static const struct option opts[] = {
        {"attach",  no_argument, NULL, 'a'},
        {"status",  no_argument, NULL, 's'},
        {"unpin",   no_argument, NULL, 'u'},
        {"help",    no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        {NULL,      0,           NULL, 0  },
    };
    enum mode mode = MODE_NONE;
    int c;

    /*
     * Leading '+' stops getopt from permuting argv: there are no operands
     * to reorder past, and it makes the optind != argc check below an
     * exact "was there a leftover argument" test rather than one a
     * permuted argv could dodge.
     */
    while((c = getopt_long(argc, argv, "+hV", opts, NULL)) != -1) {
        switch(c) {
        case 'a':
            if(mode != MODE_NONE) {
                usage(stderr, argv[0]);
                return EXIT_USAGE;
            }
            mode = MODE_ATTACH;
            break;
        case 's':
            if(mode != MODE_NONE) {
                usage(stderr, argv[0]);
                return EXIT_USAGE;
            }
            mode = MODE_STATUS;
            break;
        case 'u':
            if(mode != MODE_NONE) {
                usage(stderr, argv[0]);
                return EXIT_USAGE;
            }
            mode = MODE_UNPIN;
            break;
        case 'h':
            usage(stdout, argv[0]);
            return 0;
        case 'V':
            print_version();
            return 0;
        default:
            usage(stderr, argv[0]);
            return EXIT_USAGE;
        }
    }

    if(mode == MODE_NONE || optind != argc) {
        usage(stderr, argv[0]);
        return EXIT_USAGE;
    }

    switch(mode) {
    case MODE_ATTACH:
        return cmd_attach();
    case MODE_STATUS:
        return cmd_status();
    case MODE_UNPIN:
        return cmd_unpin();
    default:
        usage(stderr, argv[0]);
        return EXIT_USAGE;
    }
}
