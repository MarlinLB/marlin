/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * unpin -- deliberate; never run by the unit.
 */

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <marlind/cmd.h>
#include <marlind/log.h>
#include <marlind/marlind.h>

int cmd_unpin(void)
{
    struct config cfg;
    struct attach_probe probe;
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
    if(attach_probe(&cfg, &probe) == EXIT_ATTACHED) {
        die("%s is currently attached -- stop the service before unpinning", cfg.iface);
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
