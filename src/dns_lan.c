#define _GNU_SOURCE
#include "dns_lan.h"
#include "config.h"
#include "log.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* DNS-форвардер для LAN: клиенты спрашивают 53 на роутере (правило DNAT ставит
 * datapath), а мы уводим запрос в туннель через SOCKS5-UDP Xray. Смысл: DNS
 * самого роутера идёт напрямую, и на пути «роутер -> провайдер» ответы
 * подменяются/фильтруются (например, image.tmdb.org -> 127.0.0.1), а через
 * туннель приходит настоящий адрес. Есть кэш и fail-open: если туннель не
 * ответил, по настройке спрашиваем напрямую, чтобы не оставить дом без DNS. */

#define DNS_LAN_PORT 5353
#define DNS_LAN_CACHE 128
#define DNS_LAN_MAX_UP 4
#define DNS_LAN_WAIT_MS 700
#define DNS_LAN_FALLBACK_MS 500
#define DNS_LAN_REASSOC_SEC 60

typedef struct {
    char key[264];       /* "имя|qtype" в нижнем регистре */
    time_t expire;
    unsigned char *resp;
    unsigned short len;
} dl_entry;

static const susanin_config *g_cfg;
static int g_fd = -1;
static time_t g_started;
static struct sockaddr_in g_up[DNS_LAN_MAX_UP];
static int g_up_n;
static dl_entry g_cache[DNS_LAN_CACHE];
static unsigned long g_q_total, g_q_cache, g_q_tunnel, g_q_direct, g_q_fail;

static int g_ctl = -1;                 /* TCP-контроль SOCKS5 */
static struct sockaddr_in g_relay;     /* куда слать датаграммы */
static time_t g_assoc_at;

static void dl_stats_reset(void)
{
    g_q_total = g_q_cache = g_q_tunnel = g_q_direct = g_q_fail = 0;
}

static int dl_send(int fd, const void *buf, size_t n, const struct sockaddr_in *to)
{
    return (int)sendto(fd, buf, n, 0, (const struct sockaddr *)to, sizeof(*to));
}

/* Отправка по уже соединённому TCP (SOCKS-контроль). */
static int dl_send_tcp(int fd, const void *buf, size_t n)
{
    return (int)send(fd, buf, n, MSG_NOSIGNAL);
}

/* Таймаут на блокирующих операциях с SOCKS, чтобы главный цикл не вставал. */
static void dl_set_timeout(int fd, int ms)
{
    struct timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* Ждать ответ на fd до timeout_ms; 1 = есть данные. */
static int dl_wait(int fd, int timeout_ms)
{
    struct pollfd p;
    p.fd = fd;
    p.events = POLLIN;
    p.revents = 0;
    return poll(&p, 1, timeout_ms) == 1 && (p.revents & POLLIN);
}

/* Разбор вопроса: имя в нижнем регистре + qtype. 1 = ок. */
static int dl_question(const unsigned char *m, int len, char *key, size_t kn,
                       unsigned *qtype, char *name, size_t nn)
{
    int qd = (m[4] << 8) | m[5];
    int off = 12, i = 0, labels = 0;

    if (len < 12 || qd < 1)
        return 0;
    while (off < len && m[off] && labels < 32) {
        int l = m[off];
        if (off + 1 + l > len)
            return 0;
        if (i + l + 2 >= (int)nn)
            return 0;
        if (i)
            name[i++] = '.';
        for (int k = 0; k < l; k++) {
            unsigned char c = m[off + 1 + k];
            if (c >= 'A' && c <= 'Z')
                c = (unsigned char)(c - 'A' + 'a');
            name[i++] = (char)c;
        }
        off += 1 + l;
        labels++;
    }
    if (off + 5 > len)
        return 0;
    name[i] = '\0';
    *qtype = (unsigned)((m[off + 1] << 8) | m[off + 2]);
    snprintf(key, kn, "%s|%u", name, *qtype);
    return 1;
}

/* Минимальный TTL из ответа (сек, не больше 3600). */
static int dl_ttl(const unsigned char *m, int len)
{
    int qd = (m[4] << 8) | m[5];
    int an = (m[6] << 8) | m[7];
    int off = 12, i, best = 3600;

    for (i = 0; i < qd && off < len; i++) {
        while (off < len && m[off]) {
            if ((m[off] & 0xc0) == 0xc0) {
                off += 2;
                break;
            }
            off += 1 + m[off];
        }
        if (off < len && !m[off])
            off++;
        off += 4;
    }
    for (i = 0; i < an && off + 10 <= len; i++) {
        while (off < len) {
            if ((m[off] & 0xc0) == 0xc0) {
                off += 2;
                break;
            }
            if (!m[off]) {
                off++;
                break;
            }
            off += 1 + m[off];
        }
        if (off + 10 > len)
            break;
        {
            unsigned long t = ((unsigned long)m[off + 4] << 24) |
                              ((unsigned long)m[off + 5] << 16) |
                              ((unsigned long)m[off + 6] << 8) |
                              (unsigned long)m[off + 7];
            int rd = (m[off + 8] << 8) | m[off + 9];
            if (t < (unsigned long)best)
                best = (int)t;
            off += 10 + rd;
        }
    }
    if (best < 1)
        best = 1;
    if (best > 3600)
        best = 3600;
    return best;
}

static dl_entry *dl_cache_slot(const char *key, time_t now)
{
    int i, free_i = -1, oldest = 0;

    for (i = 0; i < DNS_LAN_CACHE; i++) {
        if (!g_cache[i].key[0]) {
            if (free_i < 0)
                free_i = i;
            continue;
        }
        if (!strcmp(g_cache[i].key, key))
            return &g_cache[i];
        if (g_cache[i].expire < g_cache[oldest].expire)
            oldest = i;
    }
    if (free_i >= 0)
        return &g_cache[free_i];
    (void)now;
    return &g_cache[oldest];
}

static void dl_cache_put(const char *key, const unsigned char *resp, int len, int ttl)
{
    dl_entry *e = dl_cache_slot(key, time(NULL));
    unsigned char *p = malloc((size_t)len);

    if (!p)
        return;
    memcpy(p, resp, (size_t)len);
    free(e->resp);
    e->resp = p;
    e->len = (unsigned short)(len > 65535 ? 65535 : len);
    snprintf(e->key, sizeof(e->key), "%s", key);
    e->expire = time(NULL) + ttl;
}

static dl_entry *dl_cache_get(const char *key, time_t now)
{
    int i;
    for (i = 0; i < DNS_LAN_CACHE; i++)
        if (g_cache[i].key[0] && g_cache[i].expire > now &&
            !strcmp(g_cache[i].key, key))
            return &g_cache[i];
    return NULL;
}

/* --- SOCKS5 UDP ASSOCIATE ------------------------------------------------ */

static void dl_assoc_close(void)
{
    if (g_ctl >= 0)
        close(g_ctl);
    g_ctl = -1;
}

static int dl_assoc_open(void)
{
    unsigned char buf[64];
    int n;
    struct sockaddr_in sa;
    const char *host = g_cfg->socks_addr[0] ? g_cfg->socks_addr : "127.0.0.1";
    int port = g_cfg->socks_port > 0 ? g_cfg->socks_port : 1080;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1)
        return -1;
    g_ctl = socket(AF_INET, SOCK_STREAM, 0);
    if (g_ctl < 0)
        return -1;
    dl_set_timeout(g_ctl, 2000);
    if (connect(g_ctl, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        dl_assoc_close();
        return -1;
    }
    buf[0] = 0x05; buf[1] = 0x01; buf[2] = 0x00;
    if (dl_send_tcp(g_ctl, buf, 3) < 0) {
        dl_assoc_close();
        return -1;
    }
    n = (int)recv(g_ctl, buf, 2, MSG_WAITALL);
    if (n != 2 || buf[0] != 0x05 || buf[1] != 0x00) {
        dl_assoc_close();
        return -1;
    }
    /* UDP ASSOCIATE, адрес 0.0.0.0:0 — пусть прокси выберет сам. */
    memset(buf, 0, 10);
    buf[0] = 0x05; buf[1] = 0x03; buf[2] = 0x00; buf[3] = 0x01;
    if (dl_send_tcp(g_ctl, buf, 10) < 0) {
        dl_assoc_close();
        return -1;
    }
    n = (int)recv(g_ctl, buf, sizeof(buf), MSG_WAITALL);
    if (n < 10 || buf[0] != 0x05 || buf[1] != 0x00 || buf[3] != 0x01) {
        dl_assoc_close();
        return -1;
    }
    memset(&g_relay, 0, sizeof(g_relay));
    g_relay.sin_family = AF_INET;
    memcpy(&g_relay.sin_addr, buf + 4, 4);
    memcpy(&g_relay.sin_port, buf + 8, 2);
    if (g_relay.sin_addr.s_addr == 0)
        g_relay.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    g_assoc_at = time(NULL);
    return 0;
}

/* Отправить DNS-запрос через SOCKS-UDP и дождаться ответа с тем же id.
 * Возврат — длина ответа или -1. */
static int dl_tunnel(const unsigned char *q, int qlen, unsigned char *resp,
                     int rn, int timeout_ms, int upidx)
{
    unsigned char pkt[1500];
    int hdr = 10, n;
    struct sockaddr_in up;

    if (upidx < 0 || upidx >= g_up_n)
        upidx = 0;
    up = g_up[upidx];

    if (g_ctl < 0 || time(NULL) - g_assoc_at > DNS_LAN_REASSOC_SEC) {
        dl_assoc_close();
        if (dl_assoc_open() != 0)
            return -1;
    }
    /* адрес назначения — текущий upstream */
    pkt[0] = 0x00; pkt[1] = 0x00; pkt[2] = 0x00; pkt[3] = 0x01;
    memcpy(pkt + 4, &up.sin_addr.s_addr, 4);
    memcpy(pkt + 8, &up.sin_port, 2);
    memcpy(pkt + hdr, q, (size_t)qlen);
    if (dl_send(g_fd, pkt, (size_t)(hdr + qlen), &g_relay) < 0)
        return -1;
    if (!dl_wait(g_fd, timeout_ms))
        return -1;
    n = (int)recv(g_fd, pkt, sizeof(pkt), 0);
    if (n <= hdr || pkt[3] != 0x01)
        return -1;
    n -= hdr;
    if (n > rn)
        n = rn;
    memcpy(resp, pkt + hdr, (size_t)n);
    return n;
}

/* Прямой запрос (fail-open): обычный UDP к upstream. */
static int dl_direct(const unsigned char *q, int qlen, unsigned char *resp,
                     int rn, int timeout_ms)
{
    struct sockaddr_in from;
    socklen_t fl = sizeof(from);
    int i, n;

    for (i = 0; i < g_up_n && i < 2; i++) {
        if (dl_send(g_fd, q, (size_t)qlen, &g_up[i]) < 0)
            continue;
        if (!dl_wait(g_fd, timeout_ms))
            continue;
        n = (int)recvfrom(g_fd, resp, (size_t)rn, 0,
                          (struct sockaddr *)&from, &fl);
        if (n > 12)
            return n;
    }
    return -1;
}

/* --- публичное ----------------------------------------------------------- */

static void dl_parse_upstreams(const susanin_config *cfg)
{
    const char *p = cfg->dns_lan_upstream;
    g_up_n = 0;
    while (*p && g_up_n < DNS_LAN_MAX_UP) {
        char tok[64];
        size_t l = 0;
        struct in_addr a;
        while (*p == ',' || *p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        while (*p && *p != ',' && *p != ' ' && *p != '\t' && l < sizeof(tok) - 1)
            tok[l++] = *p++;
        tok[l] = '\0';
        if (inet_pton(AF_INET, tok, &a) == 1) {
            g_up[g_up_n].sin_family = AF_INET;
            g_up[g_up_n].sin_addr = a;
            g_up[g_up_n].sin_port = htons(53);
            g_up_n++;
        }
    }
    if (g_up_n == 0) {
        inet_pton(AF_INET, "8.8.8.8", &g_up[0].sin_addr);
        inet_pton(AF_INET, "1.1.1.1", &g_up[1].sin_addr);
        g_up[0].sin_family = g_up[1].sin_family = AF_INET;
        g_up[0].sin_port = g_up[1].sin_port = htons(53);
        g_up_n = 2;
    }
}

int dns_lan_start(const susanin_config *cfg)
{
    int i;

    if (!cfg || !cfg->dns_lan)
        return -1;
    if (g_fd >= 0)
        return 0;
    g_cfg = cfg;
    dl_parse_upstreams(cfg);
    g_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_fd < 0) {
        slogf(SL_WARN, "dns_lan: сокет не создан (%s)", strerror(errno));
        return -1;
    }
    {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
        sa.sin_port = htons(DNS_LAN_PORT);
        if (bind(g_fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
            slogf(SL_WARN, "dns_lan: порт %d не занят (%s)", DNS_LAN_PORT,
                  strerror(errno));
            close(g_fd);
            g_fd = -1;
            return -1;
        }
    }
    fcntl(g_fd, F_SETFL, fcntl(g_fd, F_GETFL, 0) | O_NONBLOCK);
    for (i = 0; i < DNS_LAN_CACHE; i++) {
        free(g_cache[i].resp);
        memset(&g_cache[i], 0, sizeof(g_cache[i]));
    }
    dl_stats_reset();
    g_started = time(NULL);
    slogf(SL_INFO, "dns_lan: слушаю DNS клиентов на порту %d, в туннель через "
          "%s:%d, upstream", DNS_LAN_PORT,
          cfg->socks_addr[0] ? cfg->socks_addr : "127.0.0.1",
          cfg->socks_port > 0 ? cfg->socks_port : 1080);
    return 0;
}

void dns_lan_stop(void)
{
    int i;
    if (g_fd >= 0)
        close(g_fd);
    g_fd = -1;
    dl_assoc_close();
    for (i = 0; i < DNS_LAN_CACHE; i++) {
        free(g_cache[i].resp);
        memset(&g_cache[i], 0, sizeof(g_cache[i]));
    }
    g_started = 0;
}

void dns_lan_reload(const susanin_config *cfg)
{
    if (!cfg)
        return;
    if (cfg->dns_lan) {
        g_cfg = cfg;
        dl_parse_upstreams(cfg);
        if (g_fd < 0)
            dns_lan_start(cfg);
    } else if (g_fd >= 0) {
        dns_lan_stop();
        slogf(SL_INFO, "dns_lan: выключен reload-ом");
    }
}

/* Один проход: не больше двух запросов и короткие ожидания — иначе
 * главный цикл встаёт на время ответа upstream. */
void dns_lan_poll(void)
{
    unsigned char q[1500], resp[1500];
    int budget;

    if (g_fd < 0 || !g_cfg || !g_cfg->dns_lan)
        return;
    for (budget = 0; budget < 2; budget++) {
        struct sockaddr_in from;
        socklen_t fl = sizeof(from);
        int n = (int)recvfrom(g_fd, q, sizeof(q), 0,
                              (struct sockaddr *)&from, &fl);
        char key[264], name[256];
        unsigned qtype = 0, id;
        dl_entry *e;
        int rn;

        if (n < 12)
            break;
        /* Ответы от upstream (идят на этот же сокет) не должны попадать в
         * обработку запросов: у них QR=1. */
        if (q[2] & 0x80)
            continue;
        if (!dl_question(q, n, key, sizeof(key), &qtype, name, sizeof(name)))
            continue;
        g_q_total++;
        id = (unsigned)((q[0] << 8) | q[1]);
        e = dl_cache_get(key, time(NULL));
        if (e) {
            if (e->len >= 12) {
                memcpy(resp, e->resp, e->len);
                resp[0] = (unsigned char)(id >> 8);
                resp[1] = (unsigned char)(id & 0xff);
                dl_send(g_fd, resp, e->len, &from);
                g_q_cache++;
            }
            continue;
        }
        rn = -1;
        {
            int u;
            for (u = 0; u < g_up_n && rn <= 12; u++)
                rn = dl_tunnel(q, n, resp, sizeof(resp), DNS_LAN_WAIT_MS, u);
        }
        if (rn > 12) {
            g_q_tunnel++;
        } else if (g_cfg->dns_lan_fallback == 1) {
            rn = dl_direct(q, n, resp, sizeof(resp), DNS_LAN_FALLBACK_MS);
            if (rn > 12)
                g_q_direct++;
        }
        if (rn <= 12) {
            g_q_fail++;
            continue;
        }
        dl_send(g_fd, resp, (size_t)rn, &from);
        {
            int ttl = dl_ttl(resp, rn);
            if (ttl > 0)
                dl_cache_put(key, resp, rn, ttl);
        }
    }
}

int dns_lan_stats(char *out, size_t n)
{
    if (!out || n == 0)
        return 0;
    snprintf(out, n, "listen=%d upstreams=%d queries=%lu cached=%lu tunnel=%lu "
             "direct=%lu fail=%lu", g_fd >= 0 ? DNS_LAN_PORT : 0,
             g_up_n, g_q_total, g_q_cache, g_q_tunnel, g_q_direct, g_q_fail);
    return (int)g_q_total;
}

int dns_lan_active(void)
{
    return g_fd >= 0;
}
