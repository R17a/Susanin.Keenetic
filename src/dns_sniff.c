#define _GNU_SOURCE
#include "dns_sniff.h"
#include "backend.h"
#include "log.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define DNS_MAX_ENTRIES 2048
/* DNS_DOMAIN_MAX — в dns_sniff.h (нужен и классификатору). */

typedef struct {
    char domain[DNS_DOMAIN_MAX];
    char ip[16];
    time_t expire;
    int pinned;
    int pinned_never;
    /* Кэш вердиктов по спискам: reconcile каждые 10 с на каждую живую запись
     * выполнял до 5 полных проходов vpn_always/vpn_never (сотни зон) плюс
     * суффикс-проверку TLD. Вердикты пересчитываются только при смене
     * поколения списков (файлы перечитаны / TLD-набор изменён). */
    unsigned vgen;          /* поколение списков, на котором считали */
    signed char v_always;   /* -1 = не считали, 0/1 = вердикт */
    signed char v_never;
    signed char v_ru;
} dns_entry;

static dns_entry g_tab[DNS_MAX_ENTRIES];

int dns_sniff_is_ru_domain(const susanin_config *cfg, const char *dom);
/* T4: слушаем ВСЕ LAN-интерфейсы (br0, br1, oc+ клиенты и т.п.), а не только
 * первый: DNS клиента OpenConnect (oc0) иначе не виден, и его адреса не
 * пинятся в vpn_always. Один сокет AF_PACKET на интерфейс. */
#define DNS_MAX_IFACES 8
static int g_fds[DNS_MAX_IFACES];
static char g_open[DNS_MAX_IFACES][64];   /* имена интерфейсов, к которым привязаны */
static int g_nfd = 0;
static int g_started = 0;
static const susanin_config *g_cfg = NULL;
static susanin_state *g_state = NULL;   /* для персиста пинов (может быть NULL) */

/* Кэш содержимого списка (vpn_always/vpn_never): файл перечитывается только при
 * смене mtime/размера, а не на каждую запись DNS-таблицы раз в 10 секунд. */
typedef struct {
    char path[256];
    long long mtime, size;
    char *data;              /* домены через '\n' */
} lcache;
static lcache lc[2];
/* Поколение списков: растёт при любом перечитывании vpn_always/vpn_never или
 * смене набора RU-TLD — кэш вердиктов записей при этом сбрасывается. */
static unsigned g_list_gen = 1;

static void reconcile_entry(const susanin_config *cfg, dns_entry *e, int i,
                            time_t now);

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
    int idx, reuse = -1;
    dns_entry *e;

    if (!domain[0] || !ip[0])
        return;
    h = dns_hash(domain) % DNS_MAX_ENTRIES;
    /* Домен ищем среди живых И истёкших записей: домен, который спрашивают
     * реже dns_sniff_ttl, раньше терял запись вместе с pinned-флагами, и
     * reconcile каждые dns_sniff_ttl секунд заново пинил его с логом. Теперь
     * та же пара домен+IP просто оживает; при смене IP флаги сбрасываются
     * (старый пин относится к прежнему адресу), и новый адрес пинится сразу. */
    for (idx = 0; idx < DNS_MAX_ENTRIES; idx++) {
        int s = (int)((h + (unsigned long)idx) % DNS_MAX_ENTRIES);
        e = &g_tab[s];
        if (!e->domain[0]) {
            if (reuse < 0) reuse = s;
            continue;
        }
        if (!strcasecmp(e->domain, domain)) {
            if (strcmp(e->ip, ip) != 0) {
                snprintf(e->ip, sizeof(e->ip), "%s", ip);
                e->pinned = 0;
                e->pinned_never = 0;
            }
            e->expire = now + ttl;
            if (g_cfg)
                reconcile_entry(g_cfg, e, s, now);   /* мгновенный пин */
            return;
        }
        if (e->expire <= now && reuse < 0)
            reuse = s;
    }
    if (reuse < 0)
        return;                 /* таблица полна живыми — не вытесняем */
    e = &g_tab[reuse];
    snprintf(e->domain, sizeof(e->domain), "%s", domain);
    snprintf(e->ip, sizeof(e->ip), "%s", ip);
    e->expire = now + ttl;
    e->pinned = 0;
    e->pinned_never = 0;
    e->vgen = 0;                /* вердикты ещё не считали */
    e->v_always = -1;
    e->v_never = -1;
    e->v_ru = -1;
    if (g_cfg)
        reconcile_entry(g_cfg, e, reuse, now);       /* мгновенный пин */
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
            /* Пиним ИМЯ, КОТОРОЕ СПРОСИЛ КЛИЕНТ, а не только владельца
             * A-записи. У CDN-хостов (EdgeOne, CloudFront, Fastly и т.п.)
             * ответ приходит как CNAME: aname — это каноническое имя
             * (*.eo.dnse3.com, *.cloudfront.net), и списки vpn_always/
             * vpn_never по нужному домену с ним не совпадают. Из-за этого
             * www.tencentcloud.com, api.deepseek.com и подобные не пинились
             * вообще, и решение по каждому адресу принимало автообучение
             * (CONFIRMED -> D1 -> soft-direct) — то есть маршрут «плавал»
             * от соединения к соединению. Каноническое имя тоже сохраняем:
             * если в списке указана сама CDN-зона, пин по ней должен работать. */
            if (qname[0])
                dns_store(qname, ip, ttl);
            if (aname[0] && strcasecmp(aname, qname) != 0)
                dns_store(aname, ip, ttl);
        }
        off += rdlen;
    }
}

/* Открыть сокет на конкретном интерфейсе. 0 = слушаем. */
static int sniff_bind(const char *name)
{
    unsigned idx;
    int fd;
    struct sockaddr_ll sll;

    if (g_nfd >= DNS_MAX_IFACES)
        return -1;
    idx = if_nametoindex(name);
    if (idx == 0)
        return -1;                  /* интерфейса сейчас нет */
    fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
    if (fd < 0)
        return -1;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_IP);
    sll.sll_ifindex = (int)idx;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
        slogf(SL_WARN, "dns_sniff: не привязаться к %s — пропускаю", name);
        close(fd);
        return -1;
    }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    g_fds[g_nfd] = fd;
    snprintf(g_open[g_nfd], sizeof(g_open[0]), "%s", name);
    g_nfd++;
    slogf(SL_INFO, "dns_sniff: слушаю DNS на %s", name);
    return 0;
}

static int sniff_is_open(const char *name)
{
    int i;
    for (i = 0; i < g_nfd; i++)
        if (!strcmp(g_open[i], name))
            return 1;
    return 0;
}

/* Раскрыть шаблон ("oc+", "wdtt*") по фактическим интерфейсам и открыть
 * недостающие. Клиент OpenConnect создаёт ocN только при подключении, поэтому
 * проверяем это периодически (в reconcile), а не только на старте. */
static void sniff_try_name(const char *name)
{
    if (strpbrk(name, "+*") != NULL) {
        char prefix[64];
        size_t n = strcspn(name, "+*");
        DIR *d;
        struct dirent *de;
        if (n >= sizeof(prefix))
            n = sizeof(prefix) - 1;
        memcpy(prefix, name, n);
        prefix[n] = '\0';
        d = opendir("/sys/class/net");
        if (!d)
            return;
        while ((de = readdir(d)) != NULL && g_nfd < DNS_MAX_IFACES) {
            if (de->d_name[0] == '.')
                continue;
            if (strncmp(de->d_name, prefix, n) != 0)
                continue;
            if (sniff_is_open(de->d_name))
                continue;
            sniff_bind(de->d_name);
        }
        closedir(d);
        return;
    }
    if (sniff_is_open(name))
        return;
    if (if_nametoindex(name) == 0) {
        slogf(SL_DEBUG, "dns_sniff: %s сейчас нет — пропускаю", name);
        return;
    }
    sniff_bind(name);
}

/* Пройтись по списку интерфейсов из конфига и дооткрыть недостающие. */
static void sniff_sync(const susanin_config *cfg)
{
    char list[256];
    const char *p;

    if (cfg->dns_sniff_iface[0])
        snprintf(list, sizeof(list), "%s", cfg->dns_sniff_iface);
    else
        snprintf(list, sizeof(list), "%s", cfg->lan_interfaces);
    p = list;
    while (*p && g_nfd < DNS_MAX_IFACES) {
        char name[64];
        size_t l = 0;
        while (*p == ',' || *p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        while (*p && *p != ',' && *p != ' ' && *p != '\t' &&
               l < sizeof(name) - 1)
            name[l++] = *p++;
        name[l] = '\0';
        if (name[0])
            sniff_try_name(name);
    }
}

int dns_sniff_start(const susanin_config *cfg)
{
    if (g_started)
        return 0;
    g_cfg = cfg;
    g_nfd = 0;
    sniff_sync(cfg);
    if (g_nfd == 0) {
        slogf(SL_WARN, "dns_sniff: не привязаться ни к одному интерфейсу — выключено");
        return -1;
    }
    g_started = 1;
    return 0;
}

/* Закрыть сокет и убрать его из массива (интерфейс исчез). */
static void sniff_drop(int f)
{
    int i;
    if (g_fds[f] >= 0)
        close(g_fds[f]);
    for (i = f; i < g_nfd - 1; i++) {
        g_fds[i] = g_fds[i + 1];
        memcpy(g_open[i], g_open[i + 1], sizeof(g_open[0]));
    }
    g_nfd--;
    if (g_nfd >= 0 && g_nfd < DNS_MAX_IFACES) {
        g_fds[g_nfd] = -1;
        g_open[g_nfd][0] = '\0';
    }
}

void dns_sniff_stop(void)
{
    int i;
    for (i = 0; i < g_nfd; i++)
        if (g_fds[i] >= 0)
            close(g_fds[i]);
    for (i = 0; i < DNS_MAX_IFACES; i++) {
        g_fds[i] = -1;
        g_open[i][0] = '\0';
    }
    g_nfd = 0;
    g_started = 0;
    for (i = 0; i < 2; i++) {          /* кэш списков — освобождаем */
        if (lc[i].data) {
            free(lc[i].data);
            lc[i].data = NULL;
        }
        lc[i].path[0] = '\0';
        lc[i].mtime = lc[i].size = 0;
    }
}

void dns_sniff_poll(void)
{
    uint8_t buf[2048];
    int f;

    if (!g_started || g_nfd <= 0)
        return;
    /* Пины, применённые сразу при DNS-ответе, копятся в один батч ipset:
     * без него каждый пин был бы отдельным fork'ом ipset. */
    backend_batch_begin();
    for (f = 0; f < g_nfd; ) {
        int guard = 0, dropped = 0;
        while (guard++ < 128) {
            ssize_t r = recv(g_fds[f], buf, sizeof(buf), 0);
            unsigned ihl, ulen;
            if (r == 0)
                break;
            if (r < 0) {
                /* Интерфейс удалён (VPN отключили) — закрываем сокет, чтобы не
                 * копить мёртвые fd; новый появится и будет открыт в reconcile. */
                if (errno == ENODEV || errno == ENETDOWN || errno == EBADF) {
                    sniff_drop(f);
                    dropped = 1;
                }
                break;
            }
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
        if (!dropped)
            f++;
    }
    backend_batch_end();
}

static int zone_match(const char *domain, const char *zone_in)
{
    char zone[DNS_DOMAIN_MAX];
    size_t dl, zl;
    unsigned i;
    /* zone_in уже приведён к нижнему регистру при загрузке кэша списка —
     * tolower на каждую зону на каждую запись раньше стоил заметной доли
     * reconcile. */
    for (i = 0; zone_in[i] && i < sizeof(zone) - 1; i++)
        zone[i] = zone_in[i];
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

static const char *list_cache(int slot, const char *file)
{
    lcache *c;
    struct stat sb;
    FILE *fp;
    char line[320];
    char *buf;
    size_t cap = 2048, len = 0;

    if (slot < 0 || slot > 1 || !file || !file[0])
        return NULL;
    c = &lc[slot];
    if (c->data && !strcmp(c->path, file) && stat(file, &sb) == 0 &&
        c->mtime == (long long)sb.st_mtime && c->size == (long long)sb.st_size)
        return c->data;
    if (c->data) {
        free(c->data);
        c->data = NULL;
    }
    c->path[0] = '\0';
    fp = fopen(file, "r");
    if (!fp)
        return NULL;
    buf = malloc(cap);
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    buf[0] = '\0';
    while (fgets(line, sizeof(line), fp)) {
        char *p = line + strlen(line);
        size_t l;
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
        l = strlen(p);
        if (len + l + 2 > cap) {
            char *nb;
            cap = (len + l + 2) * 2;
            nb = realloc(buf, cap);
            if (!nb)
                break;
            buf = nb;
        }
        {
            size_t j;
            for (j = 0; j < l; j++)
                buf[len + j] = (char)tolower((unsigned char)p[j]);
            len += l;
        }
        buf[len++] = '\n';
        buf[len] = '\0';
    }
    fclose(fp);
    c->data = buf;
    snprintf(c->path, sizeof(c->path), "%s", file);
    if (stat(file, &sb) == 0) {
        c->mtime = (long long)sb.st_mtime;
        c->size = (long long)sb.st_size;
    } else {
        c->mtime = 0;
        c->size = 0;
    }
    g_list_gen++;   /* список перечитан — кэш вердиктов записей недействителен */
    return c->data;
}

static int list_match(int slot, const char *file, const char *domain)
{
    const char *data, *p;
    char line[320];

    if (!file || !file[0])
        return 0;
    data = list_cache(slot, file);
    if (!data)
        return 0;
    p = data;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t l = nl ? (size_t)(nl - p) : strlen(p);
        if (l >= sizeof(line))
            l = sizeof(line) - 1;
        memcpy(line, p, l);
        line[l] = '\0';
        if (line[0] && zone_match(domain, line))
            return 1;
        if (!nl)
            break;
        p = nl + 1;
    }
    return 0;
}

void dns_sniff_set_state(susanin_state *st)
{
    g_state = st;
}

void dns_sniff_reset_pins(void)
{
    int i;
    /* Пины в ipset'ах сброшены (flush) — снимаем флаги, чтобы reconcile
     * применил их заново. Значения из state при этом уже восстановлены. */
    for (i = 0; i < DNS_MAX_ENTRIES; i++) {
        g_tab[i].pinned = 0;
        g_tab[i].pinned_never = 0;
    }
}

/* Другая живая запись с тем же IP всё ещё покрывается списком (slot 0=always,
 * 1=never) — тогда пин снимать нельзя, только сбросить флаг у нашей записи. */
static int other_entry_matches(time_t now, int skip, int slot,
                               const susanin_config *cfg, const char *ip)
{
    int i;
    for (i = 0; i < DNS_MAX_ENTRIES; i++) {
        dns_entry *e = &g_tab[i];
        if (i == skip || !e->domain[0] || e->expire <= now || strcmp(e->ip, ip) != 0)
            continue;
        if (slot == 0 ? (e->pinned && list_match(0, cfg->vpn_always_file, e->domain))
                      : (e->pinned_never && list_match(1, cfg->vpn_never_file, e->domain)))
            return 1;
    }
    return 0;
}

/* Вердикты записи по спискам — из кэша; пересчёт только при смене поколения
 * списков (файлы vpn_always/vpn_never перечитаны или изменён набор RU-TLD). */
static void entry_verdicts(const susanin_config *cfg, dns_entry *e)
{
    if (e->vgen == g_list_gen && e->v_always >= 0)
        return;
    e->v_always = (signed char)list_match(0, cfg->vpn_always_file, e->domain);
    e->v_never = (signed char)list_match(1, cfg->vpn_never_file, e->domain);
    e->v_ru = (signed char)dns_sniff_is_ru_domain(cfg, e->domain);
    e->vgen = g_list_gen;
}

/* Применить решения по одной записи: вызывается и периодическим reconcile, и
 * сразу из dns_store (C1) — новый домен из списка уезжает в туннель/прямой
 * с первого соединения, а не через окно до 10 с. */
static void reconcile_entry(const susanin_config *cfg, dns_entry *e, int i,
                            time_t now)
{
    int va, ru_force;
    if (!cfg || !e->domain[0] || e->expire <= now)
        return;
    entry_verdicts(cfg, e);
    va = e->v_always;
    if (!e->pinned && va) {
        backend_ok_pin_add(cfg, e->ip, cfg->ok_ttl);
        e->pinned = 1;
        if (g_state) {                      /* переживёт re-provision/рестарт */
            /* Тот же срок, что и в ipset (ok_ttl), и только продление:
             * state_touch создаёт запись или продлевает существующую. */
            state_touch(st_ok(g_state, 0), e->ip, now, cfg->ok_ttl);
            state_touch(st_ok(g_state, 1), e->ip, now, cfg->ok_ttl);
        }
        slogf(SL_INFO, "dns-sniff: %s -> %s pinned (vpn_always)", e->domain, e->ip);
    }
    /* r7.8: RU-домены — активный direct (пин в never), а не только
     * «не учить»: IP .рф-сайта может совпадать с выученным VPN-адресом
     * чужого сервиса (общий CDN/хостинг) и уезжать в туннель вместе с
     * ним. Ручной vpn_always для конкретного домена сильнее guard'а. */
    ru_force = cfg->ru_guard && cfg->ru_guard_direct && e->v_ru && !va;
    if (!e->pinned_never && (e->v_never || ru_force)) {
        backend_set_add(cfg, "susanin_never", e->ip, 0);
        e->pinned_never = 1;
        if (g_state)
            /* В ipset запись бессрочная (ttl 0) — в state так же. */
            state_touch(&g_state->never, e->ip, now, 0);
        /* Конфликт ok <-> never: адрес мог быть уже выучен в VPN — снимаем
         * и рвём его соединения, иначе «прямо» не заработает. */
        if (g_state) {
            if (state_has(st_ok(g_state, 0), e->ip, now) ||
                state_has(st_ok(g_state, 1), e->ip, now) ||
                state_has(st_test(g_state, 0), e->ip, now) ||
                state_has(st_test(g_state, 1), e->ip, now)) {
                state_remove(st_ok(g_state, 0), e->ip);
                state_remove(st_ok(g_state, 1), e->ip);
                state_remove(st_test(g_state, 0), e->ip);
                state_remove(st_test(g_state, 1), e->ip);
                backend_ok_pin_del(cfg, e->ip);
                backend_ct_flush_ip(e->ip);
                slogf(SL_INFO, "dns-sniff: %s -> %s снят из VPN (конфликт с vpn_never)",
                      e->domain, e->ip);
            }
        }
        slogf(SL_INFO, "dns-sniff: %s -> %s (%s)", e->domain, e->ip,
              e->v_never ? "vpn_never" : "ru-guard");
    }
    /* Снятие пина, когда записи УЖЕ НЕТ в списке: раньше dns_sniff-пин
     * переживал удаление строки (never — бессрочно, always — до ok_ttl),
     * и пользователь не мог «отпустить» адрес правкой списка
     * Флаг сбрасываем в любом случае;
     * сам пин — только если его не держит другая живая запись. */
    if (e->pinned && !va) {
        e->pinned = 0;
        if (!other_entry_matches(now, i, 0, cfg, e->ip)) {
            backend_ok_pin_del(cfg, e->ip);
            if (g_state) {
                state_remove(st_ok(g_state, 0), e->ip);
                state_remove(st_ok(g_state, 1), e->ip);
            }
            slogf(SL_INFO, "dns-sniff: %s -> %s unpinned (нет в vpn_always)",
                  e->domain, e->ip);
        }
    }
    if (e->pinned_never && !e->v_never && !ru_force) {
        e->pinned_never = 0;
        if (!other_entry_matches(now, i, 1, cfg, e->ip)) {
            backend_set_del(cfg, "susanin_never", e->ip);
            if (g_state)
                state_remove(&g_state->never, e->ip);
            backend_ct_flush_ip(e->ip);
            slogf(SL_INFO, "dns-sniff: %s -> %s unpinned (нет в vpn_never)",
                  e->domain, e->ip);
        }
    }
}

void dns_sniff_reconcile(const susanin_config *cfg)
{
    int i;
    time_t now = time(NULL);
    if (!g_started)
        return;
    /* Клиент OpenConnect создаёт ocN только при подключении, а шаблон "oc+"
     * нельзя привязать напрямую (if_nametoindex("oc+") == 0): дооткрываем
     * появившиеся интерфейсы здесь, не дожидаясь перезапуска агента. */
    sniff_sync(cfg);
    /* Пины этого прохода — одним батчем (ipset restore): без него каждый пин
     * это отдельный fork ipset, а с 0.4.6 dns_store пишет и qname, и CNAME —
     * записей вдвое больше. Вне batch буфер копит и nothing-операции — конец
     * обязан быть строго после begin. */
    backend_batch_begin();
    for (i = 0; i < DNS_MAX_ENTRIES; i++) {
        dns_entry *e = &g_tab[i];
        if (!e->domain[0] || e->expire <= now)
            continue;
        reconcile_entry(cfg, e, i, now);
    }
    backend_batch_end();
    /* r5.4: счётчик «RU в VPN» для панели (не чаще раза в минуту). */
    dns_sniff_ru_audit(cfg);
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

/* --- r5: RU-домены -------------------------------------------------------- */

/* Суффикс-матчер TLD из cfg->ru_guard_tlds (".ru,.рф,.xn--p1ai,..."):
 * сравнение регистронезависимое, совпадение только по границе метки.
 * Список TLD разбирается один раз и кэшируется: прежняя версия копировала
 * строку конфига и strtok'ила её на каждый вызов (вызов — на каждую запись
 * reconcile и в классификаторе). При изменении набора увеличивается
 * поколение списков — кэш вердиктов dns_entry сбрасывается. */
int dns_sniff_is_ru_domain(const susanin_config *cfg, const char *dom)
{
    static char tld_src[256];
    static char tld[16][64];
    static int tld_n;
    size_t dl;
    int i;
    if (!cfg || !dom || !dom[0] || !cfg->ru_guard_tlds[0])
        return 0;
    if (strcmp(tld_src, cfg->ru_guard_tlds) != 0) {
        char buf[256], *save = NULL, *tok;
        snprintf(tld_src, sizeof(tld_src), "%s", cfg->ru_guard_tlds);
        snprintf(buf, sizeof(buf), "%s", cfg->ru_guard_tlds);
        tld_n = 0;
        for (tok = strtok_r(buf, ",", &save); tok && tld_n < 16;
             tok = strtok_r(NULL, ",", &save)) {
            size_t tl, k;
            while (*tok == ' ' || *tok == '\t')
                tok++;
            tl = strlen(tok);
            if (!tl || tl >= sizeof(tld[0]))
                continue;
            for (k = 0; k < tl; k++)    /* храним в нижнем регистре */
                tld[tld_n][k] = (char)tolower((unsigned char)tok[k]);
            tld[tld_n][tl] = '\0';
            tld_n++;
        }
        g_list_gen++;
    }
    dl = strlen(dom);
    for (i = 0; i < tld_n; i++) {
        size_t tl = strlen(tld[i]);
        size_t k;
        if (!tl || dl < tl)
            continue;
        for (k = 0; k < tl; k++)
            if (tolower((unsigned char)dom[dl - tl + k]) != tld[i][k])
                break;
        if (k == tl)
            return 1;
    }
    return 0;
}

/* r5.4: аудит «российское в VPN». Считаем RU-домены из сниффера, чей IP
 * сейчас в ok_tcp (VPN), пишем счётчик и список в файл для веб-процесса
 * (панель — отдельный процесс, память сниффера ему недоступна). Не чаще
 * раза в минуту; файл перезаписываем только при изменении содержимого. */
void dns_sniff_ru_audit(const susanin_config *cfg)
{
    static char last[512];
    static time_t last_run;
    char line[512], tmp[544];
    int i, cnt = 0, used = 0;
    time_t now = time(NULL);
    char seen[16][DNS_DOMAIN_MAX];
    if (!cfg || !g_state || now - last_run < 60)
        return;
    last_run = now;
    line[0] = '\0';
    for (i = 0; i < DNS_MAX_ENTRIES; i++) {
        dns_entry *e = &g_tab[i];
        char kf[64];
        int j, dup = 0;
        if (!e->domain[0] || e->expire <= now)
            continue;
        if (!dns_sniff_is_ru_domain(cfg, e->domain))
            continue;
        state_key(kf, sizeof(kf), e->ip, 0);
        if (!state_has(&g_state->ok_tcp, kf, now)) {
            state_key(kf, sizeof(kf), e->ip, 443);
            if (!state_has(&g_state->ok_tcp, kf, now))
                continue;
        }
        for (j = 0; j < cnt; j++)
            if (!strcmp(seen[j], e->domain)) { dup = 1; break; }
        if (dup || cnt >= 16)
            continue;
        snprintf(seen[cnt++], DNS_DOMAIN_MAX, "%.*s", DNS_DOMAIN_MAX - 1, e->domain);
    }
    used = snprintf(line, sizeof(line), "%d", cnt);
    for (i = 0; i < cnt && used < (int)sizeof(line) - DNS_DOMAIN_MAX - 1; i++)
        used += snprintf(line + used, sizeof(line) - used, " %s", seen[i]);
    if (!strcmp(line, last))
        return;
    snprintf(last, sizeof(last), "%s", line);
    snprintf(tmp, sizeof(tmp), "/opt/susanin/var/ru-in-vpn");
    {
        char wp[560];
        FILE *f;
        snprintf(wp, sizeof(wp), "%s.tmp", tmp);
        f = fopen(wp, "w");
        if (f) {
            fprintf(f, "%s\n", line);
            fclose(f);
            rename(wp, tmp);
        }
    }
}
