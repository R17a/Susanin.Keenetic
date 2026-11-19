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
#include <stdarg.h>
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

#define DNS_LAN_PORT 5399
#define DNS_LAN_CACHE 128
#define DNS_LAN_MAX_UP 4
#define DNS_LAN_WAIT_MS 800
#define DNS_LAN_FALLBACK_MS 400
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
static time_t g_tunnel_dead_until;
static int g_tunnel_fail;

/* Куда уводить запросы:
 *   0 — через SOCKS5-UDP Xray (egress_type=tproxy);
 *   1 — через интерфейс туннеля SO_BINDTODEVICE (egress_type=interface,
 *       например WireGuard nwg0);
 *   2 — туннеля нет: спрашиваем напрямую (режим dns_lan смысла не имеет). */
#define DL_VIA_SOCKS  0
#define DL_VIA_IFACE  1
#define DL_VIA_DIRECT 2
static int g_mode = DL_VIA_DIRECT;
static int g_tun_fd = -1;
static int g_udp_fd = -1;   /* SOCKS-UDP: источник 127.0.0.1, как у TCP-контроля */
static char g_tun_name[32];

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

/* Прочитать ровно n байт: reply SOCKS приходит коротким, а recv с
 * MSG_WAITALL ждал бы весь буфер и упирался в таймаут. */
static int dl_recv_n(int fd, void *buf, size_t n)
{
    size_t got = 0;

    while (got < n) {
        int r = (int)recv(fd, (char *)buf + got, n - got, 0);
        if (r <= 0)
            return -1;
        got += (size_t)r;
    }
    return 0;
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

/* Редкий WARN: причины отказа SOCKS, чтобы не гадать по «нет ответа». */
static void dl_warn(const char *fmt, ...)
{
    static time_t last;
    time_t now = time(NULL);
    va_list ap;

    if (now - last < 20)
        return;
    last = now;
    va_start(ap, fmt);
    {
        char buf[256];
        vsnprintf(buf, sizeof(buf), fmt, ap);
        slogf(SL_WARN, "dns_lan: %s", buf);
    }
    va_end(ap);
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
        dl_warn("SOCKS connect %s:%d не удался: %s", host, port, strerror(errno));
        dl_assoc_close();
        return -1;
    }
    buf[0] = 0x05; buf[1] = 0x01; buf[2] = 0x00;
    if (dl_send_tcp(g_ctl, buf, 3) < 0) {
        dl_assoc_close();
        return -1;
    }
    if (dl_recv_n(g_ctl, buf, 2) != 0 || buf[0] != 0x05 || buf[1] != 0x00) {
        dl_warn("SOCKS приветствие: ответ %02x %02x (ждём 05 00)", buf[0], buf[1]);
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
    {
        unsigned char hdr[4];
        unsigned char addr[18];
        int alen;
        if (dl_recv_n(g_ctl, hdr, 4) != 0 || hdr[0] != 0x05 || hdr[1] != 0x00) {
            dl_warn("SOCKS UDP ASSOCIATE: ответ ver=%d rep=%d atyp=%d",
                    hdr[0], hdr[1], hdr[3]);
            dl_assoc_close();
            return -1;
        }
        if (hdr[3] == 0x01)            /* IPv4 */
            alen = 4;
        else if (hdr[3] == 0x04)       /* IPv6 */
            alen = 16;
        else if (hdr[3] == 0x03) {     /* домен */
            unsigned char l;
            if (dl_recv_n(g_ctl, &l, 1) != 0) {
                dl_assoc_close();
                return -1;
            }
            alen = 1 + l;
        } else {
            dl_assoc_close();
            return -1;
        }
        if (alen > (int)sizeof(addr) - 2 || dl_recv_n(g_ctl, addr, (size_t)alen + 2) != 0) {
            dl_assoc_close();
            return -1;
        }
        memset(&g_relay, 0, sizeof(g_relay));
        g_relay.sin_family = AF_INET;
        if (hdr[3] == 0x01)
            memcpy(&g_relay.sin_addr, addr, 4);
        else
            g_relay.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        memcpy(&g_relay.sin_port, addr + alen, 2);
    }
    (void)n;
    if (g_relay.sin_addr.s_addr == 0)
        g_relay.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    g_assoc_at = time(NULL);
    dl_warn("SOCKS ассоциация открыта, релей %s:%d",
            inet_ntoa(g_relay.sin_addr), ntohs(g_relay.sin_port));
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
    if (dl_send(g_udp_fd >= 0 ? g_udp_fd : g_fd, pkt, (size_t)(hdr + qlen),
                &g_relay) < 0)
        return -1;
    if (!dl_wait(g_udp_fd >= 0 ? g_udp_fd : g_fd, timeout_ms))
        return -1;
    for (;;) {
        int off, left;
        n = (int)recv(g_udp_fd >= 0 ? g_udp_fd : g_fd, pkt, sizeof(pkt), 0);
        if (n < 4)
            return -1;
        /* RSV(2) FRAG(1) ATYP(1) ADDR PORT DATA — адрес может быть любого типа */
        off = 3;
        {
            int a = pkt[off];
            if (a == 1)
                off += 1 + 4;
            else if (a == 4)
                off += 1 + 16;
            else if (a == 3) {
                if (n < 5)
                    return -1;
                off += 2 + pkt[off + 1];
            } else {
                return -1;
            }
            off += 2;           /* port */
        }
        if (off + 12 > n)
            return -1;
        left = n - off;
        /* Чужой/запоздалый ответ (id не наш) — дочитываем следующий. */
        if (pkt[off] != q[0] || pkt[off + 1] != q[1]) {
            if (!dl_wait(g_udp_fd >= 0 ? g_udp_fd : g_fd, 200))
                return -1;
            continue;
        }
        if (left > rn)
            left = rn;
        memcpy(resp, pkt + off, (size_t)left);
        return left;
    }
}

/* Интерфейс туннеля из egress_interface: первый, на который удалось
 * привязаться. В egress_interface бывает "tproxy" — его пропускаем. */
static int dl_iface_open(const susanin_config *cfg)
{
    char list[sizeof(cfg->egress_interface)];
    char *tok, *save = NULL;
    int fd;

    if (g_tun_fd >= 0) {
        close(g_tun_fd);
        g_tun_fd = -1;
        g_tun_name[0] = '\0';
    }
    snprintf(list, sizeof(list), "%s", cfg->egress_interface);
    for (tok = strtok_r(list, ", \t", &save); tok;
         tok = strtok_r(NULL, ", \t", &save)) {
        if (!strcmp(tok, "tproxy") || !strcmp(tok, "xray"))
            continue;
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0)
            continue;
        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, tok,
                       (socklen_t)strlen(tok)) != 0) {
            close(fd);
            continue;
        }
        g_tun_fd = fd;
        snprintf(g_tun_name, sizeof(g_tun_name), "%s", tok);
        return 0;
    }
    return -1;
}

/* Запрос через интерфейс туннеля: обычный UDP, но пакет уходит в туннель. */
static int dl_iface_query(const unsigned char *q, int qlen, unsigned char *resp,
                          int rn, int timeout_ms)
{
    struct sockaddr_in from;
    socklen_t fl = sizeof(from);
    int i, n;

    if (g_tun_fd < 0)
        return -1;
    for (i = 0; i < g_up_n && i < 2; i++) {
        if (dl_send(g_tun_fd, q, (size_t)qlen, &g_up[i]) < 0)
            continue;
        if (!dl_wait(g_tun_fd, timeout_ms))
            continue;
        n = (int)recvfrom(g_tun_fd, resp, (size_t)rn, 0,
                          (struct sockaddr *)&from, &fl);
        if (n > 12)
            return n;
    }
    return -1;
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
    /* Режим выхода: tproxy -> SOCKS Xray; иначе интерфейс туннеля; иначе прямо. */
    if (!strcmp(cfg->egress_type, "tproxy")) {
        g_mode = DL_VIA_SOCKS;
    } else if (cfg->egress_interface[0] && dl_iface_open(cfg) == 0) {
        g_mode = DL_VIA_IFACE;
    } else {
        g_mode = DL_VIA_DIRECT;
        slogf(SL_WARN, "dns_lan: туннеля нет (egress_type=%s, интерфейсы '%s') — "
              "DNS клиентов пойдёт напрямую, как и раньше",
              cfg->egress_type[0] ? cfg->egress_type : "(пусто)",
              cfg->egress_interface);
    }
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
    if (g_mode == DL_VIA_SOCKS) {
        struct sockaddr_in lo;
        g_udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (g_udp_fd >= 0) {
            memset(&lo, 0, sizeof(lo));
            lo.sin_family = AF_INET;
            lo.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            lo.sin_port = 0;
            if (bind(g_udp_fd, (struct sockaddr *)&lo, sizeof(lo)) != 0) {
                close(g_udp_fd);
                g_udp_fd = -1;
            }
        }
    }
    for (i = 0; i < DNS_LAN_CACHE; i++) {
        free(g_cache[i].resp);
        memset(&g_cache[i], 0, sizeof(g_cache[i]));
    }
    dl_stats_reset();
    g_started = time(NULL);
    slogf(SL_INFO, "dns_lan: слушаю DNS клиентов на порту %d, путь: %s", DNS_LAN_PORT,
          g_mode == DL_VIA_SOCKS ? "SOCKS-Xray" :
          g_mode == DL_VIA_IFACE ? g_tun_name : "напрямую (туннеля нет)");
    return 0;
}

void dns_lan_stop(void)
{
    int i;
    if (g_fd >= 0)
        close(g_fd);
    g_fd = -1;
    if (g_tun_fd >= 0)
        close(g_tun_fd);
    g_tun_fd = -1;
    if (g_udp_fd >= 0)
        close(g_udp_fd);
    g_udp_fd = -1;
    g_tun_name[0] = '\0';
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
        if (g_fd < 0) {
            dns_lan_start(cfg);
        } else if (!strcmp(cfg->egress_type, "tproxy")) {
            g_mode = DL_VIA_SOCKS;
        } else if (dl_iface_open(cfg) == 0) {
            g_mode = DL_VIA_IFACE;
        } else {
            g_mode = DL_VIA_DIRECT;
        }
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
    for (budget = 0; budget < 4; budget++) {
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
        if (g_mode == DL_VIA_SOCKS && g_tunnel_dead_until > time(NULL)) {
            /* недавно туннель не отвечал: сразу fail-open, без 1.5 с ожидания */
        } else if (g_mode == DL_VIA_SOCKS) {
            int u;
            for (u = 0; u < g_up_n && rn <= 12; u++)
                rn = dl_tunnel(q, n, resp, sizeof(resp), DNS_LAN_WAIT_MS, u);
        } else if (g_mode == DL_VIA_IFACE) {
            rn = dl_iface_query(q, n, resp, sizeof(resp), DNS_LAN_WAIT_MS);
            if (rn <= 12 && dl_iface_open(g_cfg) == 0)
                rn = dl_iface_query(q, n, resp, sizeof(resp), DNS_LAN_WAIT_MS);
        }
        if (rn > 12) {
            g_q_tunnel++;
            g_tunnel_fail = 0;
            g_tunnel_dead_until = 0;
        } else if (g_cfg->dns_lan_fallback == 1) {
            if (g_mode == DL_VIA_SOCKS && ++g_tunnel_fail >= 3) {
                g_tunnel_dead_until = time(NULL) + 60;
                g_tunnel_fail = 0;
            }
            rn = dl_direct(q, n, resp, sizeof(resp), DNS_LAN_FALLBACK_MS);
            if (rn > 12) {
                static time_t last_dir;
                time_t now = time(NULL);
                g_q_direct++;
                if (now - last_dir >= 60) {
                    last_dir = now;
                    slogf(SL_WARN, "dns_lan: туннель не ответил, ask %s напрямую "
                          "(fail-open) — ответ может быть подменён", name);
                }
            }
        }
        if (rn <= 12) {
            static time_t last_warn;
            time_t now = time(NULL);
            g_q_fail++;
            if (now - last_warn >= 60) {
                last_warn = now;
                slogf(SL_WARN, "dns_lan: upstream не ответил (%s, %s) — "
                      "проверьте SOCKS/туннель и dns_lan_upstream",
                      g_mode == DL_VIA_SOCKS ? "socks" :
                      g_mode == DL_VIA_IFACE ? g_tun_name : "direct", name);
            }
            continue;
        }
        dl_send(g_fd, resp, (size_t)rn, &from);
        if (g_cfg)
            dns_lan_write_snapshot(g_cfg);
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
    snprintf(out, n, "listen=%d via=%s upstreams=%d queries=%lu cached=%lu tunnel=%lu "
             "direct=%lu fail=%lu", g_fd >= 0 ? DNS_LAN_PORT : 0,
             g_mode == DL_VIA_SOCKS ? "socks" :
             g_mode == DL_VIA_IFACE ? g_tun_name : "direct",
             g_up_n, g_q_total, g_q_cache, g_q_tunnel, g_q_direct, g_q_fail);
    return (int)g_q_total;
}

const char *dns_lan_state_path(const susanin_config *cfg)
{
    if (cfg && !strcmp(cfg->disk_mode, "soft"))
        return DNS_LAN_SOFT_STATE_FILE;
    return DNS_LAN_STATE_FILE;
}

void dns_lan_write_snapshot(const susanin_config *cfg)
{
    char line[192];
    FILE *f = fopen(dns_lan_state_path(cfg), "w");

    if (!f)
        return;
    dns_lan_stats(line, sizeof(line));
    fprintf(f, "%s\n", line);
    fclose(f);
}

int dns_lan_active(void)
{
    return g_fd >= 0;
}
