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
 * Single-threaded by construction: cmd_attach()'s wait is one epoll_wait
 * loop over a signalfd and a netlink socket, not a thread pool, and no
 * marlind source spawns a thread or forks. Nothing here needs to be
 * reentrant or async-signal-safe beyond that.
 *
 * Env: IFACE (required), MARLIN_OBJ, MARLIN_PIN_DIR (see load_config()).
 */

#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include <bpf/libbpf.h>

#include <marlind/build.h>
#include <marlind/cmd.h>
#include <marlind/compat.h>
#include <marlind/marlind.h>

enum mode {
    MODE_NONE = 0,
    MODE_ATTACH,
    MODE_STATUS,
    MODE_UNPIN,
};

static void usage(FILE *out, const char *argv0)
{
    (void)fprintf(out, "usage: %s --attach|--status|--unpin\n", argv0);
    (void)fprintf(out, "       %s --help|--version\n", argv0);
}

/*
 * An incompatible pair is visible here, before attaching, rather than only
 * during preflight -- config_obj_path(), not load_config(): --version must
 * exit 0 regardless of compatibility (docs/DEPLOYMENT.md), and opening a
 * file to read its .rodata needs no privilege. marlind and marlin.bpf.o
 * version independently (data-plane/marlind/VERSION, data-plane/bpf/VERSION),
 * so the two figures below are not expected to match -- what matters is
 * whether the object clears MARLIND_MIN_BPF_VERSION, checked here the same
 * way preflight's check_object_version() checks it before --attach.
 */
static void print_version(void)
{
    const char *path = config_obj_path();
    struct bpf_object *obj;

    printf("marlind %s\n", MARLIND_VERSION);

    obj = bpf_object__open_file(path, NULL);
    if(obj == NULL) {
        printf("marlin.bpf.o: no object at %s\n", path);
        return;
    }

    const struct marlin_build *build = marlin_build_from_object(obj);
    const char *base = strrchr(path, '/');

    if(build == NULL) {
        printf("%s (no embedded build version) (%s)\n", base != NULL ? base + 1 : path, path);
        printf("marlind requires marlin.bpf.o %s or newer -- --attach will refuse this object\n", MARLIND_MIN_BPF_VERSION);
    } else {
        char version[MARLIN_VERSION_MAX + 1];

        marlind_build_version(build, version, sizeof(version));
        printf("%s %s (%s)\n", base != NULL ? base + 1 : path, version, path);

        if(marlind_bpf_object_supported(version) != MARLIND_COMPAT_OK) {
            printf("marlind requires marlin.bpf.o %s or newer -- --attach will refuse this object\n", MARLIND_MIN_BPF_VERSION);
        }
    }

    bpf_object__close(obj);
}

int main(int argc, char **argv)
{
    static const struct option opts[] = {
        { "attach", no_argument, NULL, 'a' }, { "status", no_argument, NULL, 's' },  { "unpin", no_argument, NULL, 'u' },
        { "help", no_argument, NULL, 'h' },   { "version", no_argument, NULL, 'V' }, { NULL, 0, NULL, 0 },
    };
    enum mode mode = MODE_NONE;
    int opt;

    /*
     * Leading '+' stops getopt from permuting argv: there are no operands
     * to reorder past, and it makes the optind != argc check below an
     * exact "was there a leftover argument" test rather than one a
     * permuted argv could dodge.
     */
    while((opt = getopt_long(argc, argv, "+hV", opts, NULL)) != -1) {
        switch(opt) {
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
