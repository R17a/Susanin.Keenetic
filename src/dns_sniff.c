#define _GNU_SOURCE
#include "dns_sniff.h"
#include "backend.h"
#include "log.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define DNS_MAX_ENTRIES 2048
#define DNS_DOMAIN_MAX  128

typedef struct {
    char domain[DNS_DOMAIN_MAX];
    char ip[16];
    time_t expire;
    int pinned;
    int pinned_never;
} dns_entry;

static dns_entry g_tab[DNS_MAX_ENTRIES];
static int g_fd = -1;
static int g_started = 0;
static const susanin_config *g_cfg = NULL;

static unsigned long dns_hash(const char *s)
{
    unsigned long h = 5381;
    for (; *s; s++)
        h = ((h << 5) + h) ^ (unsigned char)tolower((unsigned char)*s);
    return h;
}

static void dns_store(const char *domain, const char *ip, int ttl)
{
    time_t now = time(NULL);
    unsigned long h;
    int idx;

    if (!domain[0] || !ip[0])
        return;
    h = dns_hash(domain) % DNS_MAX_ENTRIES;
    for (idx = 0; idx < DNS_MAX_ENTRIES; idx++) {
        int s = (int)((h + (unsigned long)idx) % DNS_MAX_ENTRIES);
        dns_entry *e = &g_tab[s];
        if (e->domain[0] && e->expire > now &&
            !strcasecmp(e->domain, domain)) {
            snprintf(e->ip, sizeof(e->ip), "%s", ip);
            e->expire = now + ttl;
            return;
        }
        if (!e->domain[0] || e->expire <= now) {
            snprintf(e->domain, sizeof(e->domain), "%s", domain);
            snprintf(e->ip, sizeof(e->ip), "%s", ip);
            e->expire = now + ttl;
            e->pinned = 0;
            e->pinned_never = 0;
            return;
        }
    }
}

/* Разбор DNS-имени с поддержкой сжатия. nextoff — позиция после имени. */
static int dns_name(const uint8_t *p, int len, int off, char *out, unsigned outn,
                    int *nextoff)
{
    int jumps = 0, first = 1, o = off;
    unsigned outl = 0;
    *nextoff = off;
    if (outn)
        out[0] = '\0';
    while (o >= 0 && o < len) {
        uint8_t l = p[o];
        if ((l & 0xc0) == 0xc0) {
            int ptr;
            if (o + 1 >= len)
                return -1;
            ptr = ((l & 0x3f) << 8) | p[o + 1];
            if (first) { *nextoff = o + 2; first = 0; }
            if (++jumps > 20)
                return -1;
            o = ptr;
            continue;
        }
        if (l == 0) {
            if (first)
                *nextoff = o + 1;
            break;
        }
        if (o + 1 + l > len)
            return -1;
        if (outl + (unsigned)l + 2 >= outn)
            return -1;
        if (outl)
            out[outl++] = '.';
        memcpy(out + outl, p + o + 1, (size_t)l);
        outl += (unsigned)l;
        o += 1 + l;
    }
    if (outn)
        out[outl] = '\0';
    return 0;
}

static void dns_parse(const uint8_t *p, int len)
{
    int qd, an, off, i, ttlcap;
    char qname[DNS_DOMAIN_MAX];
    uint16_t flags;

    if (len < 12)
        return;
    flags = (uint16_t)((p[2] << 8) | p[3]);
    if (!(flags & 0x8000))
        return;                     /* только ответы */
    qd = (p[4] << 8) | p[5];
    an = (p[6] << 8) | p[7];
    if (qd < 1 || an < 1)
        return;
    if (dns_name(p, len, 12, qname, sizeof(qname), &off) != 0)
        return;
    if (off + 4 > len)
        return;
    off += 4;                       /* qtype + qclass */

    ttlcap = (g_cfg && g_cfg->dns_sniff_ttl > 0) ? g_cfg->dns_sniff_ttl : 300;
    for (i = 0; i < an && off + 10 <= len; i++) {
        int type, cls, rdlen, ttl;
        char aname[DNS_DOMAIN_MAX];
        int noff;
        if (dns_name(p, len, off, aname, sizeof(aname), &noff) != 0)
            return;
        off = noff;
        if (off + 10 > len)
            return;
        type = (p[off] << 8) | p[off + 1];
        cls = (p[off + 2] << 8) | p[off + 3];
        ttl = (p[off + 4] << 24) | (p[off + 5] << 16) |
              (p[off + 6] << 8) | p[off + 7];
        rdlen = (p[off + 8] << 8) | p[off + 9];
        off += 10;
        if (off + rdlen > len)
            return;
        if (type == 1 && cls == 1 && rdlen == 4) {
            char ip[16];
            if (ttl <= 0 || ttl > ttlcap)
                ttl = ttlcap;
            snprintf(ip, sizeof(ip), "%u.%u.%u.%u",
                     p[off], p[off + 1], p[off + 2], p[off + 3]);
            dns_store(aname[0] ? aname : qname, ip, ttl);
        }
        off += rdlen;
    }
}

int dns_sniff_start(const susanin_config *cfg)
{
    struct sockaddr_ll sll;
    char iface[64] = "";
    unsigned idx;
    int fd;

    if (g_started)
        return 0;
    g_cfg = cfg;
    if (cfg->dns_sniff_iface[0])
        snprintf(iface, sizeof(iface), "%s", cfg->dns_sniff_iface);
    else {
        const char *p = cfg->lan_interfaces;
        while (*p == ' ')
            p++;
        for (idx = 0; idx < sizeof(iface) - 1 && p[idx] && p[idx] != ','; idx++)
            iface[idx] = p[idx];
        iface[idx] = '\0';
    }
    if (!iface[0]) {
        slogf(SL_WARN, "dns_sniff: не задан интерфейс — выключено");
        return -1;
    }
    fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
    if (fd < 0) {
        slogf(SL_WARN, "dns_sniff: socket(AF_PACKET) не удался — выключено");
        return -1;
    }
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_IP);
    sll.sll_ifindex = (int)if_nametoindex(iface);
    if (sll.sll_ifindex == 0 ||
        bind(fd, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
        slogf(SL_WARN, "dns_sniff: не привязаться к %s — выключено", iface);
        close(fd);
        return -1;
    }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    g_fd = fd;
    g_started = 1;
    slogf(SL_INFO, "dns_sniff: слушаю DNS на %s", iface);
    return 0;
}

void dns_sniff_stop(void)
{
    if (g_fd >= 0)
        close(g_fd);
    g_fd = -1;
    g_started = 0;
}

void dns_sniff_poll(void)
{
    uint8_t buf[2048];
    int guard = 0;

    if (!g_started || g_fd < 0)
        return;
    while (guard++ < 128) {
        ssize_t r = recv(g_fd, buf, sizeof(buf), 0);
        unsigned ihl, ulen;
        if (r <= 0)
            break;
        if (r < 20)
            continue;
        ihl = (unsigned)(buf[0] & 0x0f) * 4;
        if (ihl < 20 || (ssize_t)ihl + 8 > r || buf[9] != 17)
            continue;
        {
            const uint8_t *udp = buf + ihl;
            uint16_t sp = (uint16_t)((udp[0] << 8) | udp[1]);
            uint16_t dp = (uint16_t)((udp[2] << 8) | udp[3]);
            if (sp != 53 && dp != 53)
                continue;
            ulen = (unsigned)((udp[4] << 8) | udp[5]);
            if (ulen < 8 || ihl + ulen > (unsigned)r)
                continue;
            dns_parse(udp + 8, (int)(ulen - 8));
        }
    }
}

static int zone_match(const char *domain, const char *zone_in)
{
    char zone[DNS_DOMAIN_MAX];
    size_t dl, zl;
    unsigned i;
    for (i = 0; zone_in[i] && i < sizeof(zone) - 1; i++)
        zone[i] = (char)tolower((unsigned char)zone_in[i]);
    zone[i] = '\0';
    if (zone[0] == '*') {
        const char *z = zone + 1;
        while (*z == '.')
            z++;
        memmove(zone, z, strlen(z) + 1);
    }
    dl = strlen(domain);
    zl = strlen(zone);
    if (zl == 0 || dl < zl)
        return 0;
    if (!strcasecmp(domain, zone))
        return 1;
    if (dl > zl && domain[dl - zl - 1] == '.' &&
        !strcasecmp(domain + dl - zl, zone))
        return 1;
    return 0;
}

static int list_match(const char *file, const char *domain)
{
    FILE *fp;
    char line[320];
    int hit = 0;
    if (!file || !file[0])
        return 0;
    fp = fopen(file, "r");
    if (!fp)
        return 0;
    while (fgets(line, sizeof(line), fp)) {
        char *p = line + strlen(line);
        while (p > line && (p[-1] == ' ' || p[-1] == '\t' ||
                            p[-1] == '\r' || p[-1] == '\n'))
            *--p = '\0';
        p = line;
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '\0' || *p == '#')
            continue;
        if (strchr(p, '/') || strchr(p, ':'))
            continue;               /* CIDR/IPv6 — не домен */
        if (zone_match(domain, p)) {
            hit = 1;
            break;
        }
    }
    fclose(fp);
    return hit;
}

void dns_sniff_reconcile(const susanin_config *cfg)
{
    int i;
    time_t now = time(NULL);
    if (!g_started)
        return;
    for (i = 0; i < DNS_MAX_ENTRIES; i++) {
        dns_entry *e = &g_tab[i];
        if (!e->domain[0] || e->expire <= now)
            continue;
        if (!e->pinned && list_match(cfg->vpn_always_file, e->domain)) {
            backend_ipset_add(cfg, 0, 1, e->ip, cfg->ok_ttl);
            backend_ipset_add(cfg, 1, 1, e->ip, cfg->ok_ttl);
            e->pinned = 1;
            slogf(SL_INFO, "dns-sniff: %s -> %s pinned (vpn_always)", e->domain, e->ip);
        }
        if (!e->pinned_never && list_match(cfg->vpn_never_file, e->domain)) {
            backend_set_add(cfg, "susanin_never", e->ip, 0);
            e->pinned_never = 1;
            slogf(SL_INFO, "dns-sniff: %s -> %s (vpn_never)", e->domain, e->ip);
        }
    }
}

int dns_sniff_count(void)
{
    int i, n = 0;
    time_t now = time(NULL);
    for (i = 0; i < DNS_MAX_ENTRIES; i++)
        if (g_tab[i].domain[0] && g_tab[i].expire > now)
            n++;
    return n;
}

int dns_sniff_domain_of(const char *ip, char *domain_out, unsigned n)
{
    int i;
    time_t now = time(NULL);
    if (domain_out && n)
        domain_out[0] = '\0';
    if (!ip)
        return 0;
    for (i = 0; i < DNS_MAX_ENTRIES; i++) {
        dns_entry *e = &g_tab[i];
        if (e->domain[0] && e->expire > now && !strcmp(e->ip, ip)) {
            if (domain_out && n)
                snprintf(domain_out, n, "%s", e->domain);
            return 1;
        }
    }
    return 0;
}
