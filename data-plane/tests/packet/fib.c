/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Definitions for fib.h's FIB fixture. See the header comment on
 * tests/support/harness.c for why this is a separate translation unit rather
 * than included inline. <arpa/inet.h> is deliberately never included here:
 * it pulls in <netinet/in.h>, whose IPPROTO_* enum collides with the
 * <linux/in.h> one packet.h already brings in (both this file and the
 * xdp_*.c files it serves must live in the tree that built the datapath,
 * which uses the kernel UAPI headers throughout) -- so addresses are
 * formatted by hand instead.
 */

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/if_link.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "fib.h"

/*
 * fatal: exit(1) on a non-zero exit status. Callers pass 0 for teardown --
 * a "del" against state a failed earlier case never created must not stop
 * the next case from running (the same reasoning as tests/packet/maps.h's
 * xdp_acl_clear).
 */
static int fib_ip(int fatal, ...)
{
    const char *argv[20];
    int argc = 0;
    const char *arg;
    va_list ap;
    pid_t pid;
    int status;

    argv[argc++] = "ip";
    va_start(ap, fatal);
    while((arg = va_arg(ap, const char *)) != NULL) {
        if(argc >= (int)(sizeof(argv) / sizeof(argv[0])) - 1) {
            fprintf(stderr, "fib.c: too many ip(8) arguments\n");
            exit(1);
        }
        argv[argc++] = arg;
    }
    va_end(ap);
    argv[argc] = NULL;

    pid = fork();
    if(pid < 0) {
        fprintf(stderr, "fib.c: fork failed: %s\n", strerror(errno));
        exit(1);
    }

    if(pid == 0) {
        /*
         * Non-fatal calls are teardown against state a failed earlier case
         * never created (the comment above) -- ip(8)'s "No such file or
         * directory" on those is expected noise, not a diagnostic, so it is
         * suppressed rather than left to obscure a real failure's output.
         */
        if(!fatal) {
            int devnull = open("/dev/null", O_WRONLY);

            if(devnull >= 0) {
                dup2(devnull, STDERR_FILENO);
                close(devnull);
            }
        }

        execvp("ip", (char *const *)argv);
        fprintf(stderr, "fib.c: execvp(ip) failed: %s\n", strerror(errno));
        _exit(127);
    }

    if(waitpid(pid, &status, 0) < 0) {
        fprintf(stderr, "fib.c: waitpid failed: %s\n", strerror(errno));
        exit(1);
    }

    if(!WIFEXITED(status)) {
        fprintf(stderr, "fib.c: ip(8) terminated abnormally\n");
        exit(1);
    }

    if(fatal && WEXITSTATUS(status) != 0) {
        fprintf(stderr, "fib.c: ip(8) exited %d\n", WEXITSTATUS(status));
        exit(1);
    }

    return WEXITSTATUS(status);
}

/*
 * "255.255.255.255\0": 16 bytes -- not <netinet/in.h>'s INET_ADDRSTRLEN,
 * which this file avoids depending on (see the file header comment on why
 * <arpa/inet.h> is not included at all).
 */
#define FIB_ADDRSTRLEN 16

/*
 * addr is already network (big-endian) byte order by construction --
 * bpf_htonl() and every FIB_ADDR_* constant produce one -- so byte 0 of its
 * in-memory representation is the leading octet on every host, regardless
 * of the host's own endianness.
 */
static const char *fib_addr_str(__be32 addr, char buf[FIB_ADDRSTRLEN])
{
    const unsigned char *b = (const unsigned char *)&addr;

    snprintf(buf, FIB_ADDRSTRLEN, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    return buf;
}

static const char *fib_mac_str(const unsigned char mac[ETH_ALEN], char buf[18])
{
    snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

int fib_ifindex(const char *dev)
{
    unsigned int idx = if_nametoindex(dev);

    if(idx == 0) {
        fprintf(stderr, "fib.c: if_nametoindex(%s) failed: %s\n", dev, strerror(errno));
        exit(1);
    }

    return (int)idx;
}

static void fib_addr_add(const char *dev, __be32 addr, int prefixlen)
{
    char abuf[FIB_ADDRSTRLEN];
    char cidr[FIB_ADDRSTRLEN + 4];

    fib_addr_str(addr, abuf);
    snprintf(cidr, sizeof(cidr), "%s/%d", abuf, prefixlen);
    fib_ip(1, "addr", "add", cidr, "dev", dev, NULL);
}

void fib_route_add_onlink(__be32 addr, const char *dev)
{
    char abuf[FIB_ADDRSTRLEN];
    char cidr[FIB_ADDRSTRLEN + 4];

    fib_addr_str(addr, abuf);
    snprintf(cidr, sizeof(cidr), "%s/32", abuf);
    fib_ip(1, "route", "add", cidr, "dev", dev, NULL);
}

void fib_route_add_via(__be32 addr, __be32 gw, const char *dev)
{
    char abuf[FIB_ADDRSTRLEN];
    char gbuf[FIB_ADDRSTRLEN];
    char cidr[FIB_ADDRSTRLEN + 4];

    fib_addr_str(addr, abuf);
    fib_addr_str(gw, gbuf);
    snprintf(cidr, sizeof(cidr), "%s/32", abuf);
    fib_ip(1, "route", "add", cidr, "via", gbuf, "dev", dev, NULL);
}

void fib_route_add_special(const char *type, __be32 addr)
{
    char abuf[FIB_ADDRSTRLEN];
    char cidr[FIB_ADDRSTRLEN + 4];

    fib_addr_str(addr, abuf);
    snprintf(cidr, sizeof(cidr), "%s/32", abuf);
    fib_ip(1, "route", "add", type, cidr, NULL);
}

void fib_route_add_mtu(__be32 addr, const char *dev, int mtu)
{
    char abuf[FIB_ADDRSTRLEN];
    char cidr[FIB_ADDRSTRLEN + 4];
    char mtubuf[16];

    fib_addr_str(addr, abuf);
    snprintf(cidr, sizeof(cidr), "%s/32", abuf);
    snprintf(mtubuf, sizeof(mtubuf), "%d", mtu);
    fib_ip(1, "route", "add", cidr, "dev", dev, "mtu", "lock", mtubuf, NULL);
}

void fib_route_del(__be32 addr)
{
    char abuf[FIB_ADDRSTRLEN];
    char cidr[FIB_ADDRSTRLEN + 4];

    fib_addr_str(addr, abuf);
    snprintf(cidr, sizeof(cidr), "%s/32", abuf);
    fib_ip(0, "route", "del", cidr, NULL);
}

void fib_neigh_set(__be32 addr, const char *dev, const unsigned char mac[ETH_ALEN], const char *nud)
{
    char abuf[FIB_ADDRSTRLEN];
    char macbuf[18];

    fib_addr_str(addr, abuf);
    fib_mac_str(mac, macbuf);
    fib_ip(1, "neigh", "replace", abuf, "lladdr", macbuf, "dev", dev, "nud", nud, NULL);
}

void fib_neigh_del(__be32 addr, const char *dev)
{
    char abuf[FIB_ADDRSTRLEN];

    fib_addr_str(addr, abuf);
    fib_ip(0, "neigh", "del", abuf, "dev", dev, NULL);
}

/* ---- topology: process-wide, built once ------------------------------ */

static int fib_anchor_fd = -1;

/*
 * A two-instruction XDP_PASS program, not xdp_main: any frame this
 * namespace generates on its own (IGMP membership reports on addr add,
 * IPv6 ND/MLD) must not run through xdp_main and move drop_stats, which
 * would break every delta assertion in this file. mov64 r0, XDP_PASS;
 * exit -- <bpf/bpf_insn.h> ships no builder macros in this libbpf, so the
 * two instructions are written out by opcode.
 */
static void fib_anchor_load(void)
{
    struct bpf_insn insns[2];
    LIBBPF_OPTS(bpf_prog_load_opts, opts);

    memset(insns, 0, sizeof(insns));
    insns[0].code = 0xb7; /* BPF_ALU64 | BPF_MOV | BPF_K */
    insns[0].dst_reg = 0; /* BPF_REG_0 */
    insns[0].imm = XDP_PASS;
    insns[1].code = 0x95; /* BPF_JMP | BPF_EXIT */

    fib_anchor_fd = bpf_prog_load(BPF_PROG_TYPE_XDP, "fib_anchor", "GPL", insns, 2, &opts);
    if(fib_anchor_fd < 0) {
        fprintf(stderr, "fib.c: failed to load the XDP_PASS anchor: %s\n", strerror(errno));
        exit(1);
    }
}

/*
 * Registers XDP rxq info on dev (veth_enable_xdp(), called from
 * veth_xdp_set() only once IFF_UP and a program are both present) -- what
 * makes a non-zero ctx_in.ingress_ifindex naming dev acceptable to
 * xdp_convert_md_to_buff() (net/bpf/test_run.c). Attach after bringing the
 * device up, so this call is what completes the pair, not a race with it.
 */
static void fib_anchor_attach(const char *dev)
{
    int ifindex = fib_ifindex(dev);

    if(bpf_xdp_attach(ifindex, fib_anchor_fd, XDP_FLAGS_DRV_MODE, NULL) != 0) {
        fprintf(stderr, "fib.c: failed to attach the XDP_PASS anchor to %s (ifindex %d): %s\n", dev, ifindex,
                strerror(errno));
        exit(1);
    }
}

static void fib_veth_pair(const char *dev, const char *peer, const unsigned char mac[ETH_ALEN])
{
    char macbuf[18];

    fib_mac_str(mac, macbuf);
    fib_ip(1, "link", "add", dev, "type", "veth", "peer", "name", peer, NULL);
    fib_ip(1, "link", "set", dev, "address", macbuf, NULL); /* before "up": some drivers refuse a live change */
    fib_ip(1, "link", "set", dev, "up", NULL);
    fib_ip(1, "link", "set", peer, "up", NULL);
}

/*
 * Per device, never conf.all/conf.default/net.ipv4.ip_forward: a global
 * write reaches lo too, and three of xdp_40_fib.c's FWD_DISABLED assertions
 * depend on lo staying at 0. Plain open()+write()
 * rather than sysctl(8): /proc/sys/net is resolved through the calling
 * task's net namespace, so this lands in the one main() unshared without a
 * procps dependency.
 */
static void fib_forwarding_on(const char *dev)
{
    char path[64];
    int fd;

    snprintf(path, sizeof(path), "/proc/sys/net/ipv4/conf/%s/forwarding", dev);
    fd = open(path, O_WRONLY);
    if(fd < 0) {
        fprintf(stderr, "fib.c: open %s: %s\n", path, strerror(errno));
        exit(1);
    }

    if(write(fd, "1", 1) != 1) {
        fprintf(stderr, "fib.c: write %s: %s\n", path, strerror(errno));
        exit(1);
    }

    close(fd);
}

void fib_topology_up(void)
{
    fib_veth_pair(FIB_DEV_INGRESS, FIB_DEV_INGRESS_PEER, FIB_MAC_INGRESS);
    fib_veth_pair(FIB_DEV_EGRESS, FIB_DEV_EGRESS_PEER, FIB_MAC_EGRESS);
    fib_veth_pair(FIB_DEV_NOFWD, FIB_DEV_NOFWD_PEER, FIB_MAC_NOFWD);

    fib_addr_add(FIB_DEV_INGRESS, FIB_ADDR_INGRESS, 24);
    fib_addr_add(FIB_DEV_EGRESS, FIB_ADDR_EGRESS, 24);

    fib_forwarding_on(FIB_DEV_INGRESS);
    fib_forwarding_on(FIB_DEV_EGRESS);
    /* FIB_DEV_NOFWD is left at 0: the point of that device. */

    fib_anchor_load();
    fib_anchor_attach(FIB_DEV_INGRESS);
    fib_anchor_attach(FIB_DEV_NOFWD);
}
