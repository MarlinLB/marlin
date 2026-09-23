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
 * Usage: marlind --attach | --status | --unpin | --check | --help | --version
 *
 *   --attach  preflight, load (reusing pinned maps), pin, attach, then block
 *             until SIGTERM/SIGINT, SIGHUP, or the interface disappears
 *   --status  one-shot probe of the current attach state; see EXIT_* below
 *   --unpin   remove the pins; refuses while attached
 *   --check   validate a configuration file with no privilege and no map
 *             access; needs --config (docs/design/31-file-configuration.md §7)
 *
 * --xdp-mode <native|generic>, with --attach only: native is the default and
 * refuses rather than silently degrading if the driver lacks native XDP
 * support (docs/design/02-architecture.md). generic is an explicit,
 * logged-on-attach exception for a host whose native XDP_TX is broken
 * outright, not merely absent -- marlind.h's enum xdp_attach_mode.
 *
 * --config <path> selects file-managed mode (docs/design/31-file-configuration.md):
 * [instance] then becomes the only source of the interface, object and pin
 * directory, and the environment variables below are ignored, with a
 * warning if set. Without --config, the environment is unchanged.
 *
 * There is no --detach: the attach is bpf_link-owned and held for the
 * process's lifetime, so SIGTERM is the only way to end it. SIGHUP reloads
 * --config's file in place rather than restarting.
 *
 * Single-threaded by construction: cmd_attach()'s wait is one epoll_wait
 * loop over a signalfd and a netlink socket, not a thread pool, and no
 * marlind source spawns a thread or forks. Nothing here needs to be
 * reentrant or async-signal-safe beyond that.
 *
 * Env (ignored with --config): IFACE (required), MARLIN_OBJ, MARLIN_PIN_DIR
 * (see load_config()).
 */

#include <getopt.h>
#include <stdbool.h>
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
    MODE_CHECK,
};

static void usage(FILE *out, const char *argv0)
{
    (void)fprintf(out, "usage: %s [--config <path>] --attach [--xdp-mode <native|generic>]\n", argv0);
    (void)fprintf(out, "       %s [--config <path>] --status|--unpin\n", argv0);
    (void)fprintf(out, "       %s [--config <path>] --check\n", argv0);
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
 *
 * The License lines below repeat the SPDX identifier every source file in
 * marlind/ and bpf/ already carries in its own header: both artefacts are
 * covered by the same expression, hence one constant for both lines.
 */
#define MARLIN_SPDX_LICENSE "GPL-2.0-only OR BSD-2-Clause"

static void print_version(const char *conf_path)
{
    const char *path = config_obj_path(conf_path);
    struct bpf_object *obj;

    printf("marlind %s\n", MARLIND_VERSION);
    printf("License: %s\n", MARLIN_SPDX_LICENSE);

    obj = bpf_object__open_file(path, NULL);
    if(obj == NULL) {
        printf("marlin.bpf.o: no object at %s\n", path);
        return;
    }

    const struct marlin_build *build = marlin_build_from_object(obj);
    const char *base = strrchr(path, '/');
    bool below_floor;

    if(build == NULL) {
        printf("%s (no embedded build version) (%s)\n", base != NULL ? base + 1 : path, path);
        below_floor = true;
    } else {
        char version[MARLIN_VERSION_MAX + 1];

        marlind_build_version(build, version, sizeof(version));
        printf("%s %s (%s)\n", base != NULL ? base + 1 : path, version, path);
        below_floor = marlind_bpf_object_supported(version) != MARLIND_COMPAT_OK;
    }

    printf("License: %s\n", MARLIN_SPDX_LICENSE);
    if(below_floor) {
        printf("marlind requires marlin.bpf.o %s or newer -- --attach will refuse this object\n", MARLIND_MIN_BPF_VERSION);
    }

    bpf_object__close(obj);
}

/* No short form; getopt_long identifies it by a value past the short-option set. */
enum {
    OPT_XDP_MODE = 256
};

/* Maps a mode-select short option to its enum mode; anything else is a getopt_long bug. */
static enum mode mode_from_opt(int opt)
{
    switch(opt) {
    case 'a':
        return MODE_ATTACH;
    case 's':
        return MODE_STATUS;
    case 'u':
        return MODE_UNPIN;
    case 'k':
        return MODE_CHECK;
    default:
        return MODE_NONE;
    }
}

int main(int argc, char **argv)
{
    static const struct option opts[] = {
        { "attach", no_argument, NULL, 'a' },
        { "status", no_argument, NULL, 's' },
        { "unpin", no_argument, NULL, 'u' },
        { "check", no_argument, NULL, 'k' },
        { "config", required_argument, NULL, 'c' },
        { "help", no_argument, NULL, 'h' },
        { "version", no_argument, NULL, 'V' },
        { "xdp-mode", required_argument, NULL, OPT_XDP_MODE },
        { NULL, 0, NULL, 0 },
    };
    enum mode mode = MODE_NONE;
    const char *conf_path = NULL;
    enum xdp_attach_mode xdp_mode = XDP_ATTACH_NATIVE;
    bool xdp_mode_set = false;
    bool want_help = false;
    bool want_version = false;
    int opt;

    /*
     * Leading '+' stops getopt from permuting argv: there are no operands
     * to reorder past, and it makes the optind != argc check below an
     * exact "was there a leftover argument" test rather than one a
     * permuted argv could dodge.
     */
    while((opt = getopt_long(argc, argv, "+c:hV", opts, NULL)) != -1) {
        switch(opt) {
        case 'a':
        case 's':
        case 'u':
        case 'k':
            if(mode != MODE_NONE) {
                usage(stderr, argv[0]);
                return EXIT_USAGE;
            }
            mode = mode_from_opt(opt);
            break;
        case 'c':
            conf_path = optarg;
            break;
        case OPT_XDP_MODE:
            if(strcmp(optarg, "native") == 0) {
                xdp_mode = XDP_ATTACH_NATIVE;
            } else if(strcmp(optarg, "generic") == 0) {
                xdp_mode = XDP_ATTACH_GENERIC;
            } else {
                (void)fprintf(stderr, "%s: --xdp-mode must be \"native\" or \"generic\"\n", argv[0]);
                return EXIT_USAGE;
            }
            xdp_mode_set = true;
            break;
        case 'h':
            /*
             * Recorded rather than acted on immediately: --config given
             * ahead of --help/--version must still be consumed by getopt
             * (it takes an argument), and print_version() wants it to
             * resolve [instance].object -- see the file header.
             */
            want_help = true;
            break;
        case 'V':
            want_version = true;
            break;
        default:
            usage(stderr, argv[0]);
            return EXIT_USAGE;
        }
    }

    if(want_help) {
        usage(stdout, argv[0]);
        return 0;
    }
    if(want_version) {
        print_version(conf_path);
        return 0;
    }

    if(mode == MODE_NONE || optind != argc) {
        usage(stderr, argv[0]);
        return EXIT_USAGE;
    }
    if(xdp_mode_set && mode != MODE_ATTACH) {
        (void)fprintf(stderr, "%s: --xdp-mode only applies to --attach\n", argv[0]);
        return EXIT_USAGE;
    }
    if(mode == MODE_CHECK && conf_path == NULL) {
        conf_path = MARLIN_DEFAULT_CONF;
    }

    switch(mode) {
    case MODE_ATTACH:
        return cmd_attach(conf_path, xdp_mode);
    case MODE_STATUS:
        return cmd_status(conf_path);
    case MODE_UNPIN:
        return cmd_unpin(conf_path);
    case MODE_CHECK:
        return cmd_check(conf_path);
    default:
        usage(stderr, argv[0]);
        return EXIT_USAGE;
    }
}
