/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * attach -- load, pin, attach, then block for the process lifetime.
 */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <bpf/libbpf.h>

#include <marlind/bpf_load.h>
#include <marlind/cmd.h>
#include <marlind/conf.h>
#include <marlind/conf_check.h>
#include <marlind/log.h>
#include <marlind/marlind.h>
#include <marlind/preflight.h>
#include <marlind/reconcile.h>

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

/*
 * SIGHUP is the reload signal (docs/design/31-file-configuration.md §7):
 * added to the same mask as SIGTERM/SIGINT so the epoll loop below gains a
 * third branch rather than a new mechanism, and reload runs in the main
 * loop rather than a handler, so nothing needs to be async-signal-safe.
 */
static int open_signal_fd(void)
{
    sigset_t mask;
    int fd;

    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGHUP);

    if(sigprocmask(SIG_BLOCK, &mask, NULL) != 0) {
        die("sigprocmask: %s", strerror(errno));
    }

    fd = signalfd(-1, &mask, SFD_CLOEXEC);
    if(fd < 0) {
        die("signalfd: %s", strerror(errno));
    }

    return fd;
}

/*
 * Reads and drains exactly one queued signal. signalfd is level-triggered,
 * so leaving it unread would spin epoll_wait(); reading it is also how
 * SIGHUP is told apart from SIGTERM/SIGINT now that more than one signal
 * shares this fd.
 */
static int read_signal(int fd)
{
    struct signalfd_siginfo si;
    ssize_t nread = read(fd, &si, sizeof(si));

    if(nread != (ssize_t)sizeof(si)) {
        return 0;
    }
    return (int)si.ssi_signo;
}

/*
 * Re-parses cfg->conf_path, checks it against the currently applied model,
 * and reconciles the maps to it. Never exits: a rejected reload logs and
 * keeps the previous generation attached and serving
 * (docs/design/31-file-configuration.md §7) -- the opposite of --attach's
 * startup posture, where a bad file must refuse before anything is
 * attached.
 */
static void handle_reload(struct config *cfg, struct bpf_object *obj)
{
    struct conf_diag diag;
    struct marlin_conf *next;

    if(cfg->conf_path == NULL) {
        logmsg("SIGHUP has no effect in environment-managed mode (no --config given)");
        return;
    }

    conf_diag_reset(&diag);
    next = conf_load(cfg->conf_path, CONF_LOAD_FULL, true, &diag);
    if(next == NULL) {
        conf_diag_log(cfg->conf_path, &diag);
        logmsg("SIGHUP: %s rejected, keeping the previous generation attached", cfg->conf_path);
        return;
    }

    if(!conf_check_against_previous(next, cfg->file, &diag)) {
        conf_diag_log(cfg->conf_path, &diag);
        logmsg("SIGHUP: %s rejected (restart-only key or in-place edit), keeping the previous generation attached", cfg->conf_path);
        conf_free(next);
        return;
    }
    conf_diag_log(cfg->conf_path, &diag); /* warnings only past this point */

    if(!reconcile_apply(obj, next, &diag)) {
        conf_diag_log(cfg->conf_path, &diag);
        logmsg("SIGHUP: %s: reconcile failed partway through -- maps may be a mix of old and new; "
               "fix the underlying problem and send SIGHUP again",
               cfg->conf_path);
        conf_free(next);
        return;
    }

    conf_free(cfg->file);
    cfg->file = next;
    logmsg("SIGHUP: reloaded %s (%u backend(s), %u vip(s))", cfg->conf_path, next->backend_count, next->vip_count);
    notify("STATUS=attached %s to %s (ifindex %d); reloaded %s", MARLIN_PROG_NAME, cfg->iface, cfg->ifindex, cfg->conf_path);
}

/* Registers sig_fd and nl_fd with a fresh epoll instance; each failure is fatal. */
static int open_event_loop(int sig_fd, int nl_fd)
{
    struct epoll_event ev;
    int epfd;

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

    return epfd;
}

/*
 * Between load_and_pin_maps() and attach_link(): maps survive restarts by
 * design (docs/design/02-architecture.md) and may hold the previous
 * generation's contents, so attaching first would forward under stale
 * configuration for the length of the reconcile
 * (docs/design/31-file-configuration.md §1). A rejection here is fatal --
 * the opposite of handle_reload()'s posture -- because nothing has attached
 * yet.
 */
static void reconcile_startup(const struct config *cfg, struct bpf_object *obj)
{
    struct conf_diag diag;

    if(cfg->file == NULL) {
        return;
    }

    conf_diag_reset(&diag);
    if(!reconcile_apply(obj, cfg->file, &diag)) {
        conf_diag_log(cfg->conf_path, &diag);
        die_with(EXIT_CONFIG, "%s: reconcile failed; refusing to attach", cfg->conf_path);
    }
    conf_diag_log(cfg->conf_path, &diag);
}

int cmd_attach(const char *conf_path, enum xdp_attach_mode xdp_mode)
{
    struct config cfg;
    struct bpf_object *obj;
    struct bpf_program *prog;
    int link_fd, sig_fd, nl_fd, epfd;
    struct epoll_event events[2];

    load_config(&cfg, conf_path, CONF_LOAD_FULL);
    preflight(&cfg);

    /*
     * Subscribed before attaching, not after: a RTM_DELLINK landing in the
     * gap between preflight's if_nametoindex() and a successful
     * bpf_link_create() would otherwise go unseen, leaving this process
     * believing it is attached after the kernel has already torn the
     * interface (and with it, the link) down.
     */
    sig_fd = open_signal_fd();
    nl_fd = open_link_monitor();
    epfd = open_event_loop(sig_fd, nl_fd);

    obj = load_and_pin_maps(cfg.obj_path, cfg.pin_dir);
    pin_version(obj, cfg.pin_dir);
    reconcile_startup(&cfg, obj);

    prog = pin_program(obj, cfg.obj_path, cfg.prog_pin);
    link_fd = attach_link(bpf_program__fd(prog), cfg.iface, cfg.ifindex, xdp_mode);

    logmsg("attached %s to %s (%s), pinned under %s", MARLIN_PROG_NAME, cfg.iface,
           xdp_mode == XDP_ATTACH_GENERIC ? "xdpgeneric" : "xdpdrv", cfg.pin_dir);
    if(xdp_mode == XDP_ATTACH_GENERIC) {
        logmsg("--xdp-mode=generic: this is an order-of-magnitude throughput regression versus "
               "native XDP (docs/design/02-architecture.md) -- not for production use");
    }
    notify("READY=1\nSTATUS=attached %s to %s (ifindex %d); pins under %s", MARLIN_PROG_NAME, cfg.iface, cfg.ifindex, cfg.pin_dir);

    for(;;) {
        int nready = epoll_wait(epfd, events, 2, -1);

        if(nready < 0) {
            if(errno == EINTR) {
                continue;
            }
            die("epoll_wait: %s", strerror(errno));
        }

        for(int i = 0; i < nready; i++) {
            if(events[i].data.fd == sig_fd) {
                int signo = read_signal(sig_fd);

                if(signo == SIGHUP) {
                    handle_reload(&cfg, obj);
                    continue;
                }
                logmsg("stopping: detaching %s from %s", MARLIN_PROG_NAME, cfg.iface);
                notify("STOPPING=1");
                close(link_fd);
                free_config(&cfg);
                return EXIT_ATTACHED;
            }
            if(events[i].data.fd == nl_fd && link_monitor_saw_dellink(nl_fd, cfg.ifindex)) {
                logmsg("%s was removed -- the datapath is no longer attached", cfg.iface);
                notify("STATUS=%s removed; datapath no longer attached", cfg.iface);
                free_config(&cfg);
                return EXIT_NOT_ATTACHED;
            }
        }
    }
}
