/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Configuration from environment or, with --config, from a file
 * (docs/design/31-file-configuration.md). See marlind.h for struct config and
 * load_config()'s prototype; see main.c's file header for the Env: list.
 * A file replaces the environment input entirely (D-F3): with --config,
 * [instance] is the only source of iface/obj_path/pin_dir, and IFACE/
 * MARLIN_OBJ/MARLIN_PIN_DIR are ignored, with a warning if set.
 */

#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <marlind/conf.h>
#include <marlind/log.h>
#include <marlind/marlind.h>

const char *config_obj_path(const char *conf_path)
{
    static char buf[PATH_MAX];

    if(conf_path == NULL) {
        const char *obj_path = getenv("MARLIN_OBJ");

        if(obj_path == NULL || obj_path[0] == '\0') {
            obj_path = MARLIN_DEFAULT_OBJ;
        }
        return obj_path;
    }

    /*
     * Best-effort, for `marlind --version`'s banner alone: this must exit 0
     * regardless of compatibility (docs/DEPLOYMENT.md), so an unreadable or
     * malformed file here falls back to the default rather than failing --
     * the real refusal happens in load_config_file() below, on the path
     * that actually attaches.
     */
    struct conf_diag diag;
    struct marlin_conf *conf;

    conf_diag_reset(&diag);
    conf = conf_load(conf_path, CONF_LOAD_INSTANCE_ONLY, false, &diag);
    if(conf == NULL) {
        return MARLIN_DEFAULT_OBJ;
    }
    (void)snprintf(buf, sizeof(buf), "%s", conf->instance.object);
    conf_free(conf);
    return buf;
}

static void warn_ignored_env(const char *name)
{
    const char *val = getenv(name);

    if(val != NULL && val[0] != '\0') {
        logmsg("--config given: ignoring %s (set in the environment but superseded by [instance])", name);
    }
}

void conf_diag_log(const char *path, const struct conf_diag *diag)
{
    for(__u32 i = 0; i < diag->warn_count; i++) {
        logmsg("%s: warning: %s", path, diag->warn[i]);
    }
    for(__u32 i = 0; i < diag->count; i++) {
        logmsg("%s: %s", path, diag->msg[i]);
    }
    if(diag->dropped > 0) {
        logmsg("%s: %u further error(s) not shown", path, diag->dropped);
    }
    if(diag->warn_dropped > 0) {
        logmsg("%s: %u further warning(s) not shown", path, diag->warn_dropped);
    }
}

static void load_config_file(struct config *cfg, const char *conf_path, enum conf_load_mode mode)
{
    struct conf_diag diag;
    int len;

    warn_ignored_env("IFACE");
    warn_ignored_env("MARLIN_OBJ");
    warn_ignored_env("MARLIN_PIN_DIR");

    conf_diag_reset(&diag);
    cfg->file = conf_load(conf_path, mode, true, &diag);
    conf_diag_log(conf_path, &diag);
    if(cfg->file == NULL) {
        die_with(EXIT_CONFIG, "%s: configuration rejected (see above)", conf_path);
    }

    cfg->iface = cfg->file->instance.iface;
    cfg->obj_path = cfg->file->instance.object;

    len = snprintf(cfg->pin_dir, sizeof(cfg->pin_dir), "%s", cfg->file->instance.pin_dir);
    if(len < 0 || (size_t)len >= sizeof(cfg->pin_dir)) {
        die_with(EXIT_CONFIG, "%s: instance.pin_dir too long", conf_path);
    }
    len = snprintf(cfg->prog_pin, sizeof(cfg->prog_pin), "%s/%s", cfg->pin_dir, MARLIN_PROG_NAME);
    if(len < 0 || (size_t)len >= sizeof(cfg->prog_pin)) {
        die_with(EXIT_CONFIG, "%s: instance.pin_dir too long", conf_path);
    }

    /*
     * conf_check() already resolved instance.ifindex, but only as a warning
     * (docs/design/31-file-configuration.md §7 note on `--check` running on
     * a host that is not the target) -- for a real attach or status probe
     * it is fatal.
     */
    cfg->ifindex = (int)if_nametoindex(cfg->iface);
    if(cfg->ifindex == 0) {
        die_with(EXIT_CONFIG, "no such interface: %s", cfg->iface);
    }
}

static void load_config_env(struct config *cfg)
{
    const char *pindir;
    int len;

    cfg->iface = getenv("IFACE");
    if(cfg->iface == NULL || cfg->iface[0] == '\0') {
        die("IFACE is unset -- set it in /etc/marlin/marlin.env, or use --config");
    }

    cfg->obj_path = config_obj_path(NULL);

    pindir = getenv("MARLIN_PIN_DIR");
    if(pindir == NULL || pindir[0] == '\0') {
        pindir = MARLIN_DEFAULT_PIN_DIR;
    }

    len = snprintf(cfg->pin_dir, sizeof(cfg->pin_dir), "%s", pindir);
    if(len < 0 || (size_t)len >= sizeof(cfg->pin_dir)) {
        die("MARLIN_PIN_DIR too long");
    }

    len = snprintf(cfg->prog_pin, sizeof(cfg->prog_pin), "%s/%s", cfg->pin_dir, MARLIN_PROG_NAME);
    if(len < 0 || (size_t)len >= sizeof(cfg->prog_pin)) {
        die("MARLIN_PIN_DIR too long");
    }

    cfg->ifindex = (int)if_nametoindex(cfg->iface);
    if(cfg->ifindex == 0) {
        die("no such interface: %s", cfg->iface);
    }
}

void load_config(struct config *cfg, const char *conf_path, enum conf_load_mode mode)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->conf_path = conf_path;

    if(conf_path == NULL) {
        load_config_env(cfg);
    } else {
        load_config_file(cfg, conf_path, mode);
    }
}

void free_config(struct config *cfg)
{
    if(cfg->file != NULL) {
        conf_free(cfg->file);
        cfg->file = NULL;
    }
}
