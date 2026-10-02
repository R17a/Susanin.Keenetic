#define _GNU_SOURCE
#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef SUSANIN_PLATFORM
#define SUSANIN_PLATFORM "keenetic"
#endif

struct susanin_dirs {
    const char *bin;
    const char *etc;
    const char *var;
    const char *tools;
    const char *tool_dirs[6];
};

static const struct susanin_dirs keenetic_dirs = {
    "/opt/susanin/bin", "/opt/susanin/etc",
    "/opt/susanin/var", "/opt/susanin/tools",
    { "/opt/sbin", "/opt/bin", "/usr/sbin", "/usr/bin", NULL }
};

static const struct susanin_dirs openwrt_dirs = {
    "/usr/bin", "/etc/susanin",
    "/var/lib/susanin", "/usr/lib/susanin",
    { "/usr/sbin", "/usr/bin", "/sbin", "/bin", NULL }
};

static const struct susanin_dirs *dirs(void)
{
    static const struct susanin_dirs *d = NULL;
    if (!d) {
        const char *p = getenv("SUSANIN_PLATFORM");
        if (!p || !*p)
            p = SUSANIN_PLATFORM;
        d = strcmp(p, "openwrt") == 0 ? &openwrt_dirs : &keenetic_dirs;
    }
    return d;
}

static const char *ovr(const char *env, const char *def)
{
    const char *p = getenv(env);
    return p && *p ? p : def;
}

const char *susanin_bindir(void)
{
    return ovr("SUSANIN_BINDIR", dirs()->bin);
}

const char *susanin_etcdir(void)
{
    return ovr("SUSANIN_ETCDIR", dirs()->etc);
}

const char *susanin_vardir(void)
{
    return ovr("SUSANIN_VARDIR", dirs()->var);
}

const char *susanin_toolsdir(void)
{
    return ovr("SUSANIN_TOOLSDIR", dirs()->tools);
}

const char *const *susanin_tool_dirs(void)
{
    return dirs()->tool_dirs;
}

void susanin_join(char *out, size_t n, const char *dir, const char *rel)
{
    if (!out || !n)
        return;
    if (dir && *dir)
        snprintf(out, n, "%s/%s", dir, rel);
    else
        snprintf(out, n, "%s", rel);
}
