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

/* Жив ли хотя бы один кандидат egress_interface (может быть списком). */
static int egress_any_alive(const susanin_config *c)
{
    int i;
    if (c->n_egress > 0) {
        for (i = 0; i < c->n_egress; i++) {
            if (c->egress_list[i][0] && iface_exists(c->egress_list[i]) &&
                !iface_excluded(c, c->egress_list[i]))
                return 1;
        }
        return 0;
    }
    return iface_exists(c->egress_interface) && !iface_excluded(c, c->egress_interface);
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

/* Подсеть пула OpenConnect по адресу ocN. На Keenetic tun
 * point-to-point: локальный адрес приходит как /32 (172.16.5.1,
 * peer 172.16.5.3), поэтому /32 расширяем до /24. Более широкую
 * маску (если прошивка её отдала) оставляем как есть. */
static int iface_oc_pool(const char *name, char *out, size_t outsz)
{
    char cidr[64], ip[INET_ADDRSTRLEN];
    struct in_addr a;
    int len;
    if (iface_cidr4(name, cidr, sizeof(cidr)) != 0)
        return -1;
    if (sscanf(cidr, "%15[^/]/%d", ip, &len) != 2)
        return -1;
    if (len != 32) {
        snprintf(out, outsz, "%s", cidr);
        return 0;
    }
    if (inet_pton(AF_INET, ip, &a) != 1)
        return -1;
    a.s_addr = htonl(ntohl(a.s_addr) & 0xffffff00u);
    if (!inet_ntop(AF_INET, &a, ip, sizeof(ip)))
        return -1;
    snprintf(out, outsz, "%s/24", ip);
    return 0;
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

/* OpenConnect-сервер на этом роутере: /var/run/ocserv/ocserv.conf создаётся
 * штатной службой. Процесс на Keenetic может не называться ocserv, поэтому
 * определяем по файлу. На части прошивок Keenetic этого файла нет, зато при
 * подключённом клиенте существует ocN — это второй признак. */
static int ocserv_alive(void)
{
    int i;
    if (access("/var/run/ocserv/ocserv.conf", R_OK) == 0)
        return 1;
    for (i = 0; i < DISC_MAXIF; i++) {
        char name[32];
        snprintf(name, sizeof(name), "oc%d", i);
        if (iface_exists(name))
            return 1;
    }
    return 0;
}

/* Пул клиентов OpenConnect из того же конфига (ipv4-network=172.16.5.0/24). */
static int ocserv_pool(char *out, size_t n)
{
    FILE *f = fopen("/var/run/ocserv/ocserv.conf", "r");
    char line[256];
    if (!f)
        return -1;
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        size_t l;
        if (strncmp(p, "ipv4-network", 12) != 0)
            continue;
        while (*p && *p != '=')
            p++;
        if (*p == '=')
            p++;
        while (*p == ' ' || *p == '\t')
            p++;
        l = strlen(p);
        while (l && (p[l - 1] == '\n' || p[l - 1] == '\r' || p[l - 1] == ' '))
            p[--l] = '\0';
        if (*p) {
            snprintf(out, n, "%s", p);
            fclose(f);
            return 0;
        }
    }
    fclose(f);
    return -1;
}

static int csv_has_oc(const char *csv)
{
    char buf[256], *save = NULL, *tok;
    snprintf(buf, sizeof(buf), "%s", csv ? csv : "");
    for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        while (*tok == ' ' || *tok == '\t')
            tok++;
        if (tok[0] == 'o' && tok[1] == 'c')
            return 1;
    }
    return 0;
}

/* OpenConnect — НЕ у всех: сами 'oc+' в lan_interfaces не добавляем, если
 * сервер не найден. Задача этой функции — поддержать тех, кто уже указал
 * oc+/ocN вручную, и не терять пул клиентов после rescan (регрессия
 * 2026-10-14: «часть сайтов висит, status зелёный»). */
static void merge_ocserv(const susanin_config *c, susanin_discovery *d)
{
    char pool[64], cidr[64];
    int i;
    (void)c;
    if (!csv_has_oc(d->lan_interfaces))
        return;
    if (!ocserv_alive())
        return;

    /* Держим шаблон oc+, а не только текущий ocN: после переподключения
     * клиента имя может смениться (oc1, oc2, ...). */
    append_csv(d->lan_interfaces, sizeof(d->lan_interfaces), "oc+");

    if (ocserv_pool(pool, sizeof(pool)) == 0 && strchr(pool, '/')) {
        if (!csv_has(d->lan_subnets, pool))
            append_csv(d->lan_subnets, sizeof(d->lan_subnets), pool);
        return;
    }

    /* Файла с ipv4-network нет (штатный Keenetic): берём адрес живого ocN
     * и расширяем /32 до /24 — именно так выглядит пул на стенде. */
    for (i = 0; i < DISC_MAXIF; i++) {
        char name[32];
        snprintf(name, sizeof(name), "oc%d", i);
        if (!iface_exists(name))
            continue;
        if (iface_oc_pool(name, cidr, sizeof(cidr)) == 0 &&
            !csv_has(d->lan_subnets, cidr))
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
    /* Клиенты OpenConnect-сервера — держим 'oc+' и подсеть пула. */
    merge_ocserv(c, d);

    /* tproxy: внешний трафик уходит в Xray, egress-интерфейс не используется —
     * оставляем как есть, без предупреждений и подмены. */
    if (c->egress_type[0] && strcmp(c->egress_type, "tproxy") == 0) {
        snprintf(d->egress_interface, sizeof(d->egress_interface), "%s",
                 c->egress_interface[0] ? c->egress_interface : "");
        goto egress_addr;
    }

    /* Egress: список фейловера оставляем, если жив хотя бы один кандидат, но
     * ДОБИРАЕМ живые VPN-интерфейсы, которых в списке ещё нет: второй туннель
     * может подняться позже (или быть включён после установки), и rescan должен
     * его увидеть — раньше список не менялся, пока в нём был хоть один живой. */
    if (c->egress_interface[0] && egress_any_alive(c)) {
        snprintf(d->egress_interface, sizeof(d->egress_interface), "%s", c->egress_interface);
        for (i = 0; i < nup; i++) {
            if (!is_egress_name(up[i]) || iface_excluded(c, up[i]))
                continue;
            if (csv_has(d->egress_interface, up[i]))
                continue;
            append_csv(d->egress_interface, sizeof(d->egress_interface), up[i]);
            slogf(SL_INFO, "discover: egress += %s (новый живой туннель)", up[i]);
        }
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
    /* Адреса egress — по индексу: для списка «nwg1,nwg0» собираем
     * «10.8.1.2,10.200.0.2», иначе health-проба второго туннеля шла бы без
     * своего source-адреса. Если у интерфейса адреса нет — берём из конфига. */
    {
        char list[256], addrs[256], buf[256], *save = NULL, *tok;
        size_t used = 0;
        list[0] = '\0';
        snprintf(buf, sizeof(buf), "%s", d->egress_interface);
        for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
            int n;
            while (*tok == ' ')
                tok++;
            if (!*tok || used + 2 >= sizeof(list))
                continue;
            if (iface_addr4(tok, addrs, sizeof(addrs)) != 0)
                continue;
            n = snprintf(list + used, sizeof(list) - used, "%s%s",
                         used ? "," : "", addrs);
            if (n > 0 && (size_t)n < sizeof(list) - used)
                used += (size_t)n;
        }
        if (list[0])
            snprintf(d->egress_address, sizeof(d->egress_address), "%s", list);
        else
            snprintf(d->egress_address, sizeof(d->egress_address), "%s",
                     c->egress_address[0] ? c->egress_address : "");
    }
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
