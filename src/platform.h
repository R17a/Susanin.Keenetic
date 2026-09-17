#ifndef SUSANIN_PLATFORM_H
#define SUSANIN_PLATFORM_H

#include <stddef.h>

/*
 * Platform layer: where Susanin keeps its files and looks for external tools.
 *
 * The platform is chosen at build time with -DSUSANIN_PLATFORM=keenetic|openwrt
 * (default: keenetic) and can be overridden at runtime with the SUSANIN_PLATFORM
 * env var. Individual directories can be overridden too (mainly for testing):
 * SUSANIN_BINDIR, SUSANIN_ETCDIR, SUSANIN_VARDIR, SUSANIN_TOOLSDIR.
 *
 * Default (keenetic/Entware) keeps the historical layout, so behaviour on
 * Keenetic/Entware is unchanged:
 *   bin   /opt/susanin/bin
 *   etc   /opt/susanin/etc
 *   var   /opt/susanin/var
 *   tools /opt/susanin/tools
 * OpenWRT:
 *   bin   /usr/bin
 *   etc   /etc/susanin
 *   var   /var/lib/susanin
 *   tools /usr/lib/susanin
 */

const char *susanin_bindir(void);
const char *susanin_etcdir(void);
const char *susanin_vardir(void);
const char *susanin_toolsdir(void);

/* NULL-terminated list of directories searched for external tools
 * (iptables/ipset/conntrack/ip), in priority order. */
const char *const *susanin_tool_dirs(void);

/* Writes "<dir>/<rel>" into out (absolute when dir is non-empty). */
void susanin_join(char *out, size_t n, const char *dir, const char *rel);

#endif
