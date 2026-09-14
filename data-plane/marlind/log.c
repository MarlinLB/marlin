/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Logging and systemd notification.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <marlind/log.h>
#include <marlind/marlind.h>

void logmsg(const char *fmt, ...)
{
    va_list ap;

    fprintf(stderr, "marlind: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

_Noreturn void die(const char *fmt, ...)
{
    va_list ap;

    fprintf(stderr, "marlind: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    exit(EXIT_USAGE);
}

void notify(const char *fmt, ...)
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
