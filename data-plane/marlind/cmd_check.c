/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * check -- validates a configuration file with no privilege and no map
 * access (docs/design/31-file-configuration.md §7). What makes
 * ExecStartPre= safe to wire and lets CI validate an integrator's file
 * before it is installed.
 */

#include <stdio.h>

#include <marlind/cmd.h>
#include <marlind/conf.h>
#include <marlind/marlind.h>

int cmd_check(const char *conf_path)
{
    const char *path = conf_path != NULL ? conf_path : MARLIN_DEFAULT_CONF;
    struct conf_diag diag;
    struct marlin_conf *conf;

    conf_diag_reset(&diag);
    /* enforce_perms = false: --check is deliberately runnable by a user who does not own the file
     * (docs/design/31-file-configuration.md §7). */
    conf = conf_load(path, CONF_LOAD_FULL, false, &diag);

    for(__u32 i = 0; i < diag.warn_count; i++) {
        (void)fprintf(stderr, "%s: warning: %s\n", path, diag.warn[i]);
    }
    for(__u32 i = 0; i < diag.count; i++) {
        (void)fprintf(stderr, "%s: %s\n", path, diag.msg[i]);
    }
    if(diag.dropped > 0) {
        (void)fprintf(stderr, "%s: %u further error(s) not shown\n", path, diag.dropped);
    }

    if(conf == NULL) {
        return EXIT_CONFIG;
    }

    (void)printf("%s: ok (%u backend(s), %u vip(s))\n", path, conf->backend_count, conf->vip_count);
    conf_free(conf);
    return 0;
}
