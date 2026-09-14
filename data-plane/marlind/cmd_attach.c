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
#include <marlind/log.h>
#include <marlind/marlind.h>
#include <marlind/preflight.h>

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

int cmd_attach(void)
{
    struct config cfg;
    struct bpf_object *obj;
    struct bpf_program *prog;
    int link_fd, sig_fd, nl_fd, epfd;
    struct epoll_event ev, events[2];

    load_config(&cfg);
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
    prog = pin_program(obj, cfg.obj_path, cfg.prog_pin);
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
