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

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/ethtool.h>
#include <linux/if_link.h>
#include <linux/magic.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

/* bpftool pins each program under its C function name, not its section name. */
#define MARLIN_PROG_NAME       "xdp_main"

#define MARLIN_DEFAULT_OBJ     "/usr/lib/marlin/marlin.bpf.o"
#define MARLIN_DEFAULT_PIN_DIR "/sys/fs/bpf/marlin"

#define EXIT_ATTACHED          0
#define EXIT_USAGE             1
#define EXIT_NOT_ATTACHED      3
#define EXIT_FOREIGN           4

struct config {
    const char *iface;
    int ifindex;
    const char *obj_path;
    char pin_dir[PATH_MAX];
    char prog_pin[PATH_MAX];
};

/* ---------------------------------------------------------------------------
 * Logging and notification
 * ------------------------------------------------------------------------ */

static void logmsg(const char *fmt, ...)
{
    va_list ap;

    fprintf(stderr, "marlind: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

/*
 * _Noreturn matters beyond documentation: without it, cmd_unload()'s callers
 * of die() read as falling through to code that assumes a non-NULL dir/fd,
 * which is what an undeclared-noreturn die() made the static analyzer flag
 * at the opendir() failure path below.
 */
static _Noreturn void die(const char *fmt, ...)
{
    va_list ap;

    fprintf(stderr, "marlind: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    exit(EXIT_USAGE);
}

/*
 * Reimplements sd_notify(3) over its wire format directly rather than
 * linking libsystemd, for one call site. Handles the abstract-socket
 * convention (a leading '@' maps to a leading NUL, per systemd's docs).
 */
static void notify(const char *fmt, ...)
{
    const char *sock_path = getenv("NOTIFY_SOCKET");
    struct sockaddr_un addr;
    char msg[512];
    va_list ap;
    size_t len;
    int fd;

    if(sock_path == NULL || sock_path[0] == '\0') {
        return;
    }

    len = strlen(sock_path);
    if(len == 0 || len >= sizeof(addr.sun_path)) {
        return;
    }

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if(fd < 0) {
        return;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, sock_path, len + 1);
    if(addr.sun_path[0] == '@') {
        addr.sun_path[0] = '\0';
    }

    (void)sendto(fd, msg, strlen(msg), 0, (struct sockaddr *)&addr, sizeof(addr));
    close(fd);
}

/* ---------------------------------------------------------------------------
 * Configuration
 * ------------------------------------------------------------------------ */

static void load_config(struct config *cfg)
{
    const char *pindir;
    int n;

    memset(cfg, 0, sizeof(*cfg));

    cfg->iface = getenv("IFACE");
    if(cfg->iface == NULL || cfg->iface[0] == '\0') {
        die("IFACE is unset -- set it in /etc/marlin/marlin.env");
    }

    cfg->obj_path = getenv("MARLIN_OBJ");
    if(cfg->obj_path == NULL || cfg->obj_path[0] == '\0') {
        cfg->obj_path = MARLIN_DEFAULT_OBJ;
    }

    pindir = getenv("MARLIN_PIN_DIR");
    if(pindir == NULL || pindir[0] == '\0') {
        pindir = MARLIN_DEFAULT_PIN_DIR;
    }

    n = snprintf(cfg->pin_dir, sizeof(cfg->pin_dir), "%s", pindir);
    if(n < 0 || (size_t)n >= sizeof(cfg->pin_dir)) {
        die("MARLIN_PIN_DIR too long");
    }

    n = snprintf(cfg->prog_pin, sizeof(cfg->prog_pin), "%s/%s", cfg->pin_dir, MARLIN_PROG_NAME);
    if(n < 0 || (size_t)n >= sizeof(cfg->prog_pin)) {
        die("MARLIN_PIN_DIR too long");
    }

    cfg->ifindex = (int)if_nametoindex(cfg->iface);
    if(cfg->ifindex == 0) {
        die("no such interface: %s", cfg->iface);
    }
}

/* ---------------------------------------------------------------------------
 * Preflight -- asserts host state, never configures it. Mirrors the checks
 * formerly in deploy/marlin-load.sh's load(), minus the already-attached
 * check: bpf_link_create() below reports that itself, atomically.
 * ------------------------------------------------------------------------ */

static void check_root(void)
{
    if(geteuid() != 0) {
        die("must run as root");
    }
}

static void check_obj_readable(const char *path)
{
    if(access(path, R_OK) != 0) {
        die("no object at %s -- build it: make -C data-plane", path);
    }
}

/*
 * bpffs must already be mounted. Mounting it here would need CAP_SYS_ADMIN,
 * which this process does not hold (docs/DEPLOYMENT.md §1.6), and an
 * in-unit mount does not reach the host under systemd's mount-namespacing
 * hardening -- so this asserts, it does not fix.
 */
static void check_bpffs_mounted(void)
{
    struct statfs st;

    if(statfs("/sys/fs/bpf", &st) != 0 || st.f_type != BPF_FS_MAGIC) {
        die("/sys/fs/bpf is not mounted: mount -t bpf bpf /sys/fs/bpf");
    }
}

/*
 * ETHTOOL_GSTRINGS/GFEATURES return the kernel's ETH_SS_FEATURES names
 * ("rx-lro", "rx-gro-hw"), not ethtool(8)'s cosmetic long names
 * ("large-receive-offload") -- those exist only in the CLI tool's own
 * display table, never on the wire.
 */
static bool ethtool_feature_active(const char *iface, const char *feature, bool *found)
{
    struct ethtool_sset_info *sset;
    struct ethtool_gstrings *strings;
    struct ethtool_gfeatures *features;
    struct ifreq ifr;
    uint32_t nstrings;
    uint32_t nblocks;
    bool active = false;
    int fd;
    uint32_t i;

    *found = false;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0) {
        return false;
    }

    sset = calloc(1, sizeof(*sset) + sizeof(uint32_t));
    if(sset == NULL) {
        close(fd);
        return false;
    }
    sset->cmd = ETHTOOL_GSSET_INFO;
    sset->reserved = 0;
    sset->sset_mask = 1ULL << ETH_SS_FEATURES;

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface);
    ifr.ifr_data = (void *)sset;

    if(ioctl(fd, SIOCETHTOOL, &ifr) != 0 || sset->sset_mask == 0) {
        free(sset);
        close(fd);
        return false;
    }
    nstrings = sset->data[0];
    free(sset);

    if(nstrings == 0) {
        close(fd);
        return false;
    }

    strings = calloc(1, sizeof(*strings) + (size_t)nstrings * ETH_GSTRING_LEN);
    if(strings == NULL) {
        close(fd);
        return false;
    }
    strings->cmd = ETHTOOL_GSTRINGS;
    strings->string_set = ETH_SS_FEATURES;
    strings->len = nstrings;
    ifr.ifr_data = (void *)strings;

    if(ioctl(fd, SIOCETHTOOL, &ifr) != 0) {
        free(strings);
        close(fd);
        return false;
    }

    nblocks = (nstrings + 31) / 32;
    features = calloc(1, sizeof(*features) + (size_t)nblocks * sizeof(struct ethtool_get_features_block));
    if(features == NULL) {
        free(strings);
        close(fd);
        return false;
    }
    features->cmd = ETHTOOL_GFEATURES;
    features->size = nblocks;
    ifr.ifr_data = (void *)features;

    if(ioctl(fd, SIOCETHTOOL, &ifr) != 0) {
        free(features);
        free(strings);
        close(fd);
        return false;
    }

    for(i = 0; i < nstrings; i++) {
        const char *name = (const char *)&strings->data[(size_t)i * ETH_GSTRING_LEN];

        if(strncmp(name, feature, ETH_GSTRING_LEN) == 0) {
            uint32_t block = i / 32;
            uint32_t bit = i % 32;

            *found = true;
            active = (features->features[block].active & (1u << bit)) != 0;
            break;
        }
    }

    free(features);
    free(strings);
    close(fd);
    return active;
}

/*
 * LRO merges arriving frames in hardware before XDP sees them; the datapath
 * assumes ingress is never larger than a standard frame and does not
 * handle multi-buffer packets (docs/DEPLOYMENT.md §1.3). A feature this
 * driver does not expose is treated as off, matching the tolerant
 * `2>/dev/null` behaviour of the shell preflight this replaces.
 */
static void check_offload_off(const char *iface)
{
    bool found, active;

    active = ethtool_feature_active(iface, "rx-lro", &found);
    if(found && active) {
        die("LRO is on for %s: ethtool -K %s lro off", iface, iface);
    }

    active = ethtool_feature_active(iface, "rx-gro-hw", &found);
    if(found && active) {
        die("hardware GRO is on for %s: ethtool -K %s rx-gro-hw off", iface, iface);
    }
}

/* ---------------------------------------------------------------------------
 * Load, pin, attach
 * ------------------------------------------------------------------------ */

static int print_diagnostics(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if(level > LIBBPF_WARN) {
        return 0;
    }

    return vfprintf(stderr, fmt, args);
}

/*
 * Sets a pin path on every map before loading, so libbpf's own reuse logic
 * (bpf_object__load() -> bpf_object__reuse_map()) picks up whatever is
 * already pinned under pin_dir and creates the rest -- the program always
 * loads fresh from obj_path, but map contents and VIP configuration survive
 * both a restart and a datapath upgrade, as long as no map's definition has
 * changed. A definition that did change fails reuse with a libbpf error;
 * `marlind unload` clears the old pins deliberately.
 */
static struct bpf_object *load_and_pin_maps(const char *obj_path, const char *pin_dir)
{
    struct bpf_object *obj;
    struct bpf_map *map;
    char path[PATH_MAX];
    int err;

    libbpf_set_print(print_diagnostics);

    obj = bpf_object__open_file(obj_path, NULL);
    if(obj == NULL) {
        die("failed to open %s", obj_path);
    }

    bpf_object__for_each_map(map, obj)
    {
        int n = snprintf(path, sizeof(path), "%s/%s", pin_dir, bpf_map__name(map));

        if(n < 0 || (size_t)n >= sizeof(path)) {
            die("pin path too long for map %s", bpf_map__name(map));
        }
        if(bpf_map__set_pin_path(map, path) != 0) {
            die("failed to set pin path for map %s", bpf_map__name(map));
        }
    }

    err = bpf_object__load(obj);
    if(err != 0) {
        die("failed to load %s: %s", obj_path, strerror(-err));
    }

    err = bpf_object__pin_maps(obj, pin_dir);
    if(err != 0) {
        die("failed to pin maps under %s: %s", pin_dir, strerror(-err));
    }

    return obj;
}

static struct bpf_program *pin_program(struct bpf_object *obj, const char *prog_pin)
{
    struct bpf_program *prog;

    prog = bpf_object__find_program_by_name(obj, MARLIN_PROG_NAME);
    if(prog == NULL) {
        die("%s has no program named %s", MARLIN_PROG_NAME, MARLIN_PROG_NAME);
    }

    /* Stale from a previous load; bpf_program__pin() fails EEXIST otherwise. */
    if(unlink(prog_pin) != 0 && errno != ENOENT) {
        die("failed to remove stale pin %s: %s", prog_pin, strerror(errno));
    }

    if(bpf_program__pin(prog, prog_pin) != 0) {
        die("failed to pin %s at %s: %s", MARLIN_PROG_NAME, prog_pin, strerror(errno));
    }

    return prog;
}

/*
 * Not bpf_program__attach_xdp(): it passes no attach flags, and with none
 * set the kernel silently falls back to generic/SKB mode on a driver
 * without native XDP support -- the exact order-of-magnitude regression
 * docs/design/02-architecture.md refuses. XDP_FLAGS_DRV_MODE here makes
 * that fail loudly instead.
 */
static int attach_link(int prog_fd, const char *iface, int ifindex)
{
    LIBBPF_OPTS(bpf_link_create_opts, opts, .flags = XDP_FLAGS_DRV_MODE);
    int link_fd;

    link_fd = bpf_link_create(prog_fd, ifindex, BPF_XDP, &opts);
    if(link_fd < 0) {
        int err = -link_fd;

        if(err == EBUSY) {
            die("%s already has an XDP program attached -- stop it first", iface);
        }
        die("failed to attach to ifindex %d: %s", ifindex, strerror(err));
    }

    return link_fd;
}

/* ---------------------------------------------------------------------------
 * attach -- load, pin, attach, then block for the process lifetime
 * ------------------------------------------------------------------------ */

/*
 * A held bpf_link implies "attached" for every case except one: the
 * netdev itself disappearing, which tears the link down without this
 * process's cooperation. Watched for over netlink rather than polled, so
 * the gap between truth and this process's belief about it is zero rather
 * than one probe interval.
 */
static int open_link_monitor(void)
{
    struct sockaddr_nl addr;
    int fd;
    int group = RTNLGRP_LINK;

    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
    if(fd < 0) {
        die("failed to open netlink socket: %s", strerror(errno));
    }

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    if(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        die("failed to bind netlink socket: %s", strerror(errno));
    }

    if(setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group)) != 0) {
        die("failed to join RTNLGRP_LINK: %s", strerror(errno));
    }

    return fd;
}

/* Returns true once a RTM_DELLINK for our ifindex is seen. */
static bool link_monitor_saw_dellink(int fd, int ifindex)
{
    char buf[4096];
    ssize_t len;

    for(;;) {
        len = recv(fd, buf, sizeof(buf), 0);
        if(len < 0) {
            return false;
        }

        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;

        while(NLMSG_OK(nlh, len)) {
            if(nlh->nlmsg_type == RTM_DELLINK) {
                struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);

                if(ifi->ifi_index == ifindex) {
                    return true;
                }
            }
            nlh = NLMSG_NEXT(nlh, len);
        }
    }
}

static int open_signal_fd(void)
{
    sigset_t mask;
    int fd;

    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);

    if(sigprocmask(SIG_BLOCK, &mask, NULL) != 0) {
        die("sigprocmask: %s", strerror(errno));
    }

    fd = signalfd(-1, &mask, SFD_CLOEXEC);
    if(fd < 0) {
        die("signalfd: %s", strerror(errno));
    }

    return fd;
}

static int cmd_attach(void)
{
    struct config cfg;
    struct bpf_object *obj;
    struct bpf_program *prog;
    int link_fd, sig_fd, nl_fd, epfd;
    struct epoll_event ev, events[2];

    load_config(&cfg);

    check_root();
    check_obj_readable(cfg.obj_path);
    check_bpffs_mounted();
    check_offload_off(cfg.iface);

    /*
     * Subscribed before attaching, not after: a RTM_DELLINK landing in the
     * gap between preflight's if_nametoindex() and a successful
     * bpf_link_create() would otherwise go unseen, leaving this process
     * believing it is attached after the kernel has already torn the
     * interface (and with it, the link) down.
     */
    sig_fd = open_signal_fd();
    nl_fd = open_link_monitor();

    epfd = epoll_create1(EPOLL_CLOEXEC);
    if(epfd < 0) {
        die("epoll_create1: %s", strerror(errno));
    }

    ev.events = EPOLLIN;
    ev.data.fd = sig_fd;
    if(epoll_ctl(epfd, EPOLL_CTL_ADD, sig_fd, &ev) != 0) {
        die("epoll_ctl(sig_fd): %s", strerror(errno));
    }
    ev.data.fd = nl_fd;
    if(epoll_ctl(epfd, EPOLL_CTL_ADD, nl_fd, &ev) != 0) {
        die("epoll_ctl(nl_fd): %s", strerror(errno));
    }

    obj = load_and_pin_maps(cfg.obj_path, cfg.pin_dir);
    prog = pin_program(obj, cfg.prog_pin);
    link_fd = attach_link(bpf_program__fd(prog), cfg.iface, cfg.ifindex);

    logmsg("attached %s to %s (xdpdrv), pinned under %s", MARLIN_PROG_NAME, cfg.iface, cfg.pin_dir);
    notify("READY=1\nSTATUS=attached %s to %s (ifindex %d); pins under %s", MARLIN_PROG_NAME, cfg.iface, cfg.ifindex, cfg.pin_dir);

    for(;;) {
        int n = epoll_wait(epfd, events, 2, -1);
        int i;

        if(n < 0) {
            if(errno == EINTR) {
                continue;
            }
            die("epoll_wait: %s", strerror(errno));
        }

        for(i = 0; i < n; i++) {
            if(events[i].data.fd == sig_fd) {
                logmsg("stopping: detaching %s from %s", MARLIN_PROG_NAME, cfg.iface);
                notify("STOPPING=1");
                close(link_fd);
                return EXIT_ATTACHED;
            }
            if(events[i].data.fd == nl_fd && link_monitor_saw_dellink(nl_fd, cfg.ifindex)) {
                logmsg("%s was removed -- the datapath is no longer attached", cfg.iface);
                notify("STATUS=%s removed; datapath no longer attached", cfg.iface);
                return EXIT_NOT_ATTACHED;
            }
        }
    }
}

/* ---------------------------------------------------------------------------
 * status -- one-shot probe, no output parsing anywhere
 * ------------------------------------------------------------------------ */

static int cmd_status(void)
{
    struct config cfg;
    __u32 id = 0;
    __u32 pinned_prog_id = 0;
    bool have_pinned_id = false;
    int pin_fd;

    load_config(&cfg);

    pin_fd = bpf_obj_get(cfg.prog_pin);
    if(pin_fd >= 0) {
        struct bpf_prog_info info;
        __u32 info_len = sizeof(info);

        memset(&info, 0, sizeof(info));
        if(bpf_obj_get_info_by_fd(pin_fd, &info, &info_len) == 0) {
            pinned_prog_id = info.id;
            have_pinned_id = true;
        }
        close(pin_fd);
    }

    for(;;) {
        struct bpf_link_info info;
        __u32 info_len = sizeof(info);
        int link_fd;
        int err = bpf_link_get_next_id(id, &id);

        if(err != 0) {
            /*
             * -ENOENT is "no more links" -- normal loop exit. Anything else
             * (EPERM without CAP_BPF, most likely) is a real failure that
             * must not be reported as "not attached": an unprivileged
             * caller would otherwise see a false negative instead of being
             * told why the probe couldn't run.
             */
            if(err != -ENOENT) {
                die("failed to enumerate BPF links: %s", strerror(-err));
            }
            break;
        }

        link_fd = bpf_link_get_fd_by_id(id);
        if(link_fd < 0) {
            continue;
        }

        memset(&info, 0, sizeof(info));
        if(bpf_obj_get_info_by_fd(link_fd, &info, &info_len) != 0) {
            close(link_fd);
            continue;
        }
        close(link_fd);

        if(info.type != BPF_LINK_TYPE_XDP || info.xdp.ifindex != (__u32)cfg.ifindex) {
            continue;
        }

        if(!have_pinned_id || info.prog_id != pinned_prog_id) {
            printf("foreign: link %u on %s runs prog id %u, pins under %s expect a different program\n", info.id, cfg.iface,
                   info.prog_id, cfg.pin_dir);
            return EXIT_FOREIGN;
        }

        printf("attached: %s (id %u) on %s (ifindex %d) via link %u; pins under %s\n", MARLIN_PROG_NAME, info.prog_id, cfg.iface,
               cfg.ifindex, info.id, cfg.pin_dir);
        return EXIT_ATTACHED;
    }

    printf("not attached: no XDP link on %s\n", cfg.iface);
    return EXIT_NOT_ATTACHED;
}

/* ---------------------------------------------------------------------------
 * unload -- deliberate; never run by the unit
 * ------------------------------------------------------------------------ */

static int cmd_unload(void)
{
    struct config cfg;
    struct dirent *entry;
    DIR *dir;

    load_config(&cfg);

    /*
     * A pin removed while attached does not stop forwarding -- the running
     * program holds its own map references independent of the pin -- but
     * it does erase the reuse path a restart depends on, silently turning
     * the next `attach` into a fresh, empty table. Refuse rather than let
     * that happen by accident.
     */
    if(cmd_status() == EXIT_ATTACHED) {
        die("%s is currently attached -- stop the service before unloading its pins", cfg.iface);
    }

    if(unlink(cfg.prog_pin) != 0 && errno != ENOENT) {
        die("failed to remove %s: %s", cfg.prog_pin, strerror(errno));
    }

    dir = opendir(cfg.pin_dir);
    if(dir == NULL) {
        if(errno == ENOENT) {
            return 0;
        }
        die("failed to open %s: %s", cfg.pin_dir, strerror(errno));
    }

    while((entry = readdir(dir)) != NULL) {
        char path[PATH_MAX];
        int n;

        if(strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        n = snprintf(path, sizeof(path), "%s/%s", cfg.pin_dir, entry->d_name);
        if(n < 0 || (size_t)n >= sizeof(path)) {
            continue;
        }
        (void)unlink(path);
    }
    closedir(dir);

    if(rmdir(cfg.pin_dir) != 0 && errno != ENOENT) {
        die("failed to remove %s: %s", cfg.pin_dir, strerror(errno));
    }

    logmsg("removed pins under %s", cfg.pin_dir);
    return 0;
}

int main(int argc, char **argv)
{
    if(argc != 2) {
        fprintf(stderr, "usage: %s attach|status|unload\n", argv[0]);
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

    fprintf(stderr, "usage: %s attach|status|unload\n", argv[0]);
    return EXIT_USAGE;
}
