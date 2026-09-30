#define _GNU_SOURCE
#include "discover.h"
#include "log.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DISC_MAXIF 64

/* Интерфейс в списке discover_exclude? */
static int csv_has(const char *list, const char *name)
{
    char buf[256], *save = NULL, *tok;
    if (!list || !list[0] || !name || !name[0])
        return 0;
    snprintf(buf, sizeof(buf), "%s", list);
    for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        while (*tok == ' ' || *tok == '\t')
            tok++;
        if (!strcmp(tok, name))
            return 1;
    }
    return 0;
}

static void append_csv(char *dst, size_t n, const char *val)
{
    size_t l;
    if (!dst || !n || !val || !val[0])
        return;
    if (csv_has(dst, val))
        return;
    l = strlen(dst);
    if (l && l + 1 < n) {
        dst[l++] = ',';
        dst[l] = '\0';
    }
    if (l < n)
        snprintf(dst + l, n - l, "%s", val);
}

static int iface_excluded(const susanin_config *c, const char *name)
{
    return csv_has(c->discover_exclude, name);
}

static int iface_exists(const char *name)
{
    char p[300];
    snprintf(p, sizeof(p), "/sys/class/net/%s", name);
    return access(p, F_OK) == 0;
}

/* Кандидат на egress: имена nwg, wg, amnezia, ovpn. */
static int is_egress_name(const char *n)
{
    return !strncmp(n, "nwg", 3) || !strncmp(n, "wg", 2) ||
           !strncmp(n, "amnezia", 7) || !strncmp(n, "ovpn", 4);
}

/* Список UP-интерфейсов — из sysfs (/sys/class/net/<if>/flags, IFF_UP),
 * без вызова внешних программ/shell. */
static int list_up(char names[][64], int max)
{
    DIR *d = opendir("/sys/class/net");
    struct dirent *e;
    int n = 0;
    if (!d)
        return 0;
    while ((e = readdir(d)) != NULL && n < max) {
        char p[300], buf[64];
        unsigned long flags;
        FILE *fp;
        if (e->d_name[0] == '.')
            continue;
        snprintf(p, sizeof(p), "/sys/class/net/%s/flags", e->d_name);
        fp = fopen(p, "r");
        if (!fp)
            continue;
        if (!fgets(buf, sizeof(buf), fp)) {
            fclose(fp);
            continue;
        }
        fclose(fp);
        flags = strtoul(buf, NULL, 0);
        if (!(flags & IFF_UP) || (flags & IFF_LOOPBACK))
            continue;
        snprintf(names[n], 64, "%.63s", e->d_name);
        n++;
    }
    closedir(d);
    return n;
}

/* Список устройств с default-маршрутом — из /proc/net/route
 * (Destination=00000000, флаг RTF_UP), без внешних программ. */
static int list_default_devs(char names[][64], int max)
{
    FILE *fp = fopen("/proc/net/route", "r");
    char line[256];
    int n = 0;
    if (!fp)
        return 0;
    if (!fgets(line, sizeof(line), fp)) {      /* заголовок */
        fclose(fp);
        return 0;
    }
    while (fgets(line, sizeof(line), fp) && n < max) {
        char iface[64], dest[32], flags[32];
        if (sscanf(line, "%63s %31s %31s", iface, dest, flags) != 3)
            continue;
        if (strcmp(dest, "00000000") != 0)
            continue;
        if ((strtoul(flags, NULL, 16) & 0x0001UL) == 0)   /* RTF_UP */
            continue;
        snprintf(names[n], 64, "%s", iface);
        n++;
    }
    fclose(fp);
    return n;
}

static int iface_addr4(const char *name, char *out, size_t outsz)
{
    struct ifaddrs *ifa, *p;
    out[0] = '\0';
    if (getifaddrs(&ifa) != 0)
        return -1;
    for (p = ifa; p; p = p->ifa_next) {
        const struct sockaddr_in *sin;
        if (!p->ifa_addr || !p->ifa_name)
            continue;
        if (p->ifa_addr->sa_family != AF_INET)
            continue;
        if (strcmp(p->ifa_name, name) != 0)
            continue;
        sin = (const struct sockaddr_in *)p->ifa_addr;
        if (inet_ntop(AF_INET, &sin->sin_addr, out, outsz))
            break;
        out[0] = '\0';
    }
    freeifaddrs(ifa);
    return out[0] ? 0 : -1;
}

/* IPv4-сеть интерфейса в виде CIDR (a.b.c.d/len). */
static int iface_cidr4(const char *name, char *out, size_t outsz)
{
    struct ifaddrs *ifa, *p;
    out[0] = '\0';
    if (getifaddrs(&ifa) != 0)
        return -1;
    for (p = ifa; p; p = p->ifa_next) {
        const struct sockaddr_in *sin;
        unsigned long m;
        int len = 0;
        char ab[INET_ADDRSTRLEN];
        if (!p->ifa_addr || !p->ifa_name || !p->ifa_netmask)
            continue;
        if (p->ifa_addr->sa_family != AF_INET)
            continue;
        if (strcmp(p->ifa_name, name) != 0)
            continue;
        sin = (const struct sockaddr_in *)p->ifa_addr;
        m = ntohl(((const struct sockaddr_in *)p->ifa_netmask)->sin_addr.s_addr);
        while (len < 32 && (m & 0x80000000UL)) {
            len++;
            m <<= 1;
        }
        if (!inet_ntop(AF_INET, &sin->sin_addr, ab, sizeof(ab)))
            break;
        snprintf(out, outsz, "%s/%d", ab, len);
        break;
    }
    freeifaddrs(ifa);
    return out[0] ? 0 : -1;
}

/* Добавить серверные туннели (qWDTT wdtt0/wdttraw0 и т.п.) в LAN: интерфейс
 * в lan_interfaces и его IPv4-сеть в lan_subnets. Пусто — ничего не делаем. */
static void merge_lan_servers(const susanin_config *c, susanin_discovery *d)
{
    char buf[256], *save = NULL, *tok;
    if (!c->lan_server_interfaces[0])
        return;
    snprintf(buf, sizeof(buf), "%s", c->lan_server_interfaces);
    for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        char cidr[64];
        while (*tok == ' ' || *tok == '\t')
            tok++;
        if (!*tok)
            continue;
        if (!iface_exists(tok))
            continue;
        append_csv(d->lan_interfaces, sizeof(d->lan_interfaces), tok);
        if (iface_cidr4(tok, cidr, sizeof(cidr)) == 0)
            append_csv(d->lan_subnets, sizeof(d->lan_subnets), cidr);
    }
}

int discover_defaults(susanin_discovery *d, const susanin_config *c)
{
    char up[DISC_MAXIF][64], defs[DISC_MAXIF][64];
    int nup, ndef, i, first = -1, defpick = -1, chosen;
    if (!d || !c)
        return -1;
    memset(d, 0, sizeof(*d));
    d->routing_table = c->routing_table ? c->routing_table : 100;

    nup = list_up(up, DISC_MAXIF);
    ndef = list_default_devs(defs, DISC_MAXIF);

    /* LAN: оставляем заданные интерфейсы как есть. НЕ выбрасываем временно
     * отсутствующие (напр. oc0 создаётся OpenConnect по требованию) — иначе
     * после rescan их трафик перестанет обрабатываться. */
    snprintf(d->lan_interfaces, sizeof(d->lan_interfaces), "%s",
             c->lan_interfaces[0] ? c->lan_interfaces : "br0");
    snprintf(d->lan_subnets, sizeof(d->lan_subnets), "%s",
             c->lan_subnets[0] ? c->lan_subnets : "192.168.1.0/24");

    /* qWDTT/серверные туннели как LAN (если заданы и существуют). */
    merge_lan_servers(c, d);

    /* tproxy: внешний трафик уходит в Xray, egress-интерфейс не используется —
     * оставляем как есть, без предупреждений и подмены. */
    if (c->egress_type[0] && strcmp(c->egress_type, "tproxy") == 0) {
        snprintf(d->egress_interface, sizeof(d->egress_interface), "%s",
                 c->egress_interface[0] ? c->egress_interface : "");
        goto egress_addr;
    }

    /* Egress: если сконфигурированный интерфейс существует — оставляем его;
     * иначе выбираем первый подходящий UP-кандидат, приоритет — default dev. */
    if (c->egress_interface[0] && iface_exists(c->egress_interface) &&
        !iface_excluded(c, c->egress_interface)) {
        snprintf(d->egress_interface, sizeof(d->egress_interface), "%s", c->egress_interface);
    } else {
        for (i = 0; i < nup; i++) {
            if (!is_egress_name(up[i]) || iface_excluded(c, up[i]))
                continue;
            if (first < 0)
                first = i;
            {
                int j;
                for (j = 0; j < ndef; j++) {
                    if (!strcmp(defs[j], up[i])) {
                        defpick = i;
                        break;
                    }
                }
            }
            if (defpick >= 0)
                break;
        }
        chosen = (defpick >= 0) ? defpick : first;
        if (chosen >= 0) {
            snprintf(d->egress_interface, sizeof(d->egress_interface), "%s", up[chosen]);
            slogf(SL_INFO, "discover: egress auto -> %s", up[chosen]);
        } else if (c->egress_interface[0]) {
            snprintf(d->egress_interface, sizeof(d->egress_interface), "%s", c->egress_interface);
            slogf(SL_WARN, "discover: VPN-интерфейс не найден, оставляю '%s'",
                  c->egress_interface);
        } else {
            snprintf(d->egress_interface, sizeof(d->egress_interface), "nwg0");
        }
    }

egress_addr:
    /* Адрес выбранного egress. */
    if (iface_addr4(d->egress_interface, d->egress_address, sizeof(d->egress_address)) != 0)
        snprintf(d->egress_address, sizeof(d->egress_address), "%s",
                 c->egress_address[0] ? c->egress_address : "");
    return 0;
}

void discover_print(const susanin_discovery *d)
{
    if (!d)
        return;
    printf("egress_interface=%s\n", d->egress_interface);
    printf("egress_address=%s\n", d->egress_address);
    printf("lan_interfaces=%s\n", d->lan_interfaces);
    printf("lan_subnets=%s\n", d->lan_subnets);
    printf("routing_table=%d\n", d->routing_table);
}
