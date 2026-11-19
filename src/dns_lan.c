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

/* DNS-форвардер для LAN. Клиенты спрашивают 53 на роутере (правило DNAT ставит
 * datapath), форвардер уводит запрос в туннель: при egress_type=tproxy — по
 * DNS-over-TCP через SOCKS5 Xray (UDP в vless+vision не проходит), при
 * egress_type=interface — обычным UDP, привязанным к интерфейсу туннеля.
 *
 * ВАЖНО: форвардер не блокирует главный цикл. Запросы живут в таблице
 * ожидающих (pending) и продвигаются по шагам: локальный резолвер (быстро и
 * дёшево) -> туннель (если ответ локального подменён) -> прямой запрос
 * (fail-open). Раньше ожидание ответа было внутри poll, и на медленном
 * upstream агент вставал на секунды: DNS у клиентов отваливался
 * (DNS_PROBE_FINISHED_NO_INTERNET), чат рвался. */

#define DNS_LAN_PORT 5399
#define DNS_LAN_CACHE 128
#define DNS_LAN_PEND 64
#define DNS_LAN_MAX_UP 4

#define DL_T_LOCAL_MS   400
#define DL_T_TUNNEL_MS  1200
#define DL_T_DIRECT_MS  800
#define DL_T_SOCKS_MS   15000   /* весь обмен DNS-over-TCP: connect+handshake+ответ */
#define DL_T_QUEUE_MS   20000   /* сколько запрос может ждать очереди к туннелю */
#define DL_MAX_TCP      16      /* одновременных обменов с SOCKS */

typedef struct {
    char key[264];
    time_t expire;
    unsigned char *resp;
    unsigned short len;
} dl_entry;

/* Один запрос клиента, который ещё не получил ответа. */
typedef struct {
    int used;
    unsigned id;
    unsigned char q[512];
    int qlen;
    struct sockaddr_in from;
    char key[264];
    char name[256];
    int state;              /* 0 = локальный, 1 = туннель (UDP), 2 = прямо,
                               3 = туннель (DNS-over-TCP через SOCKS) */
    long long at_ms;
    /* SOCKS-TCP: своё неблокирующее соединение на каждый запрос */
    int tfd;
    int stage;              /* 0 connect, 1 приветствие, 2 CONNECT, 3 ответ */
    int tlen;               /* сколько принято в tbuf */
    int tsent;              /* сколько отправлено из tbuf */
    int wait;               /* сколько байт ждём на текущей стадии */
    int up_try;             /* какой upstream пробуем (0..g_up_n-1) */
    int esc;                /* эскалация в туннель уже посчитана */
    unsigned char tbuf[1600];
} dl_pend;

static const susanin_config *g_cfg;
static int g_fd = -1;       /* 0.0.0.0:5399 — запросы клиентов */
static int g_loc_fd = -1;   /* 127.0.0.1 — локальный ndns */
static int g_tun_fd = -1;   /* сокет на интерфейсе туннеля */
static char g_tun_name[32];
static struct sockaddr_in g_up[DNS_LAN_MAX_UP];
static int g_up_n;
static dl_entry g_cache[DNS_LAN_CACHE];
static dl_pend g_pend[DNS_LAN_PEND];
static unsigned long g_q_total, g_q_cache, g_q_local, g_q_tunnel, g_q_direct;
static unsigned long g_q_fail, g_q_escalate;

#define DL_VIA_SOCKS  0
#define DL_VIA_IFACE  1
#define DL_VIA_DIRECT 2
static int g_mode = DL_VIA_DIRECT;

static long long dl_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void dl_stats_reset(void)
{
    g_q_total = g_q_cache = g_q_local = g_q_tunnel = g_q_direct = 0;
    g_q_fail = g_q_escalate = 0;
}

/* Редкий WARN: причины отказа, чтобы не гадать по «нет ответа». */
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

static int dl_send(int fd, const void *buf, size_t n, const struct sockaddr_in *to)
{
    return (int)sendto(fd, buf, n, 0, (const struct sockaddr *)to, sizeof(*to));
}

/* --- разбор DNS --------------------------------------------------------- */

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

static int skip_name(const unsigned char *m, int len, int off)
{
    while (off < len) {
        if ((m[off] & 0xc0) == 0xc0)
            return off + 2;
        if (m[off] == 0)
            return off + 1;
        off += 1 + m[off];
    }
    return -1;
}

/* Ответ годится? 0 — пусто/подмена (127.0.0.1, 0.0.0.0), 1 — есть записи. */
static int dl_answer_ok(const unsigned char *m, int len)
{
    int qd = (m[4] << 8) | m[5];
    int an = (m[6] << 8) | m[7];
    int off = 12, i, got = 0;

    if (len < 12 || (m[3] & 0x0f) != 0)
        return 0;
    for (i = 0; i < qd; i++) {
        off = skip_name(m, len, off);
        if (off < 0 || off + 4 > len)
            return 0;
        off += 4;
    }
    for (i = 0; i < an && off + 10 <= len; i++) {
        int type, rdlen;
        off = skip_name(m, len, off);
        if (off < 0 || off + 10 > len)
            break;
        type = (m[off] << 8) | m[off + 1];
        rdlen = (m[off + 8] << 8) | m[off + 9];
        off += 10;
        if (off + rdlen > len)
            break;
        if (type == 1 && rdlen == 4) {
            if (m[off] == 127 || (m[off] == 0 && m[off + 1] == 0 &&
                                  m[off + 2] == 0 && m[off + 3] == 0))
                return 0;
            got++;
        } else if (type == 28 && rdlen == 16) {
            got++;
        }
        off += rdlen;
    }
    return got > 0;
}

/* Минимальный TTL из ответа (1..3600). */
static int dl_ttl(const unsigned char *m, int len)
{
    int qd = (m[4] << 8) | m[5];
    int an = (m[6] << 8) | m[7];
    int off = 12, i, best = 3600;

    for (i = 0; i < qd && off < len; i++) {
        off = skip_name(m, len, off);
        if (off < 0 || off + 4 > len)
            return 60;
        off += 4;
    }
    for (i = 0; i < an && off + 10 <= len; i++) {
        int rd;
        unsigned long t;
        off = skip_name(m, len, off);
        if (off < 0 || off + 10 > len)
            break;
        t = ((unsigned long)m[off + 4] << 24) | ((unsigned long)m[off + 5] << 16) |
            ((unsigned long)m[off + 6] << 8) | (unsigned long)m[off + 7];
        rd = (m[off + 8] << 8) | m[off + 9];
        if (t < (unsigned long)best)
            best = (int)t;
        off += 10 + rd;
    }
    if (best < 1)
        best = 1;
    if (best > 3600)
        best = 3600;
    return best;
}

static dl_entry *dl_cache_slot(const char *key)
{
    int i, free_i = -1, oldest = -1;

    for (i = 0; i < DNS_LAN_CACHE; i++) {
        if (!g_cache[i].key[0]) {
            if (free_i < 0)
                free_i = i;
            continue;
        }
        if (!strcmp(g_cache[i].key, key))
            return &g_cache[i];
        if (oldest < 0 || g_cache[i].expire < g_cache[oldest].expire)
            oldest = i;
    }
    return free_i >= 0 ? &g_cache[free_i] : &g_cache[oldest];
}

static void dl_cache_put(const char *key, const unsigned char *resp, int len, int ttl)
{
    dl_entry *e = dl_cache_slot(key);
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

/* Сокеты форвардера не должны переживать exec: Xray и другие долгоживущие
 * потомки унаследовали бы их и держали порт даже после перезапуска агента
 * (новый агент не забиндится, а DNAT будет слать DNS в мёртвый сокет). */
static void dl_cloexec(int fd)
{
    if (fd >= 0)
        fcntl(fd, F_SETFD, fcntl(fd, F_GETFD, 0) | FD_CLOEXEC);
}

/* --- DNS-over-TCP через SOCKS5 (egress_type=tproxy) ---------------------- */
/*
 * Почему TCP, а не UDP: Xray в режиме vless+xtls-rprx-vision UDP не
 * пропускает — SOCKS5 UDP ASSOCIATE открывается, но ответов нет. DNS-over-TCP
 * идёт по тому же туннелю: SOCKS5 CONNECT на upstream:53, дальше сообщение
 * DNS с двухбайтовой длиной (RFC 1035, 4.2.2). Блокирующих вызовов нет: у
 * каждого ожидающего запроса своё неблокирующее соединение и своя стадия.
 */

static void dl_pend_done(dl_pend *p, const unsigned char *resp, int rn);
static void dl_pend_drop(dl_pend *p);
static void dl_pend_send_direct(dl_pend *p);

static int g_tcp_active;        /* сколько обменов с SOCKS идёт прямо сейчас */

static void dl_tcp_reset(dl_pend *p)
{
    if (p->tfd >= 0) {
        close(p->tfd);
        if (g_tcp_active > 0)
            g_tcp_active--;
    }
    p->tfd = -1;
    p->stage = 0;
    p->tlen = p->tsent = p->wait = 0;
}

/* Дочитать в tbuf до p->wait байт. 1 — набрали, 0 — ждём, -1 — ошибка. */
static int dl_tcp_read(dl_pend *p)
{
    while (p->tlen < p->wait) {
        ssize_t n = recv(p->tfd, p->tbuf + p->tlen,
                         sizeof(p->tbuf) - (size_t)p->tlen, 0);
        if (n > 0) {
            p->tlen += (int)n;
            continue;
        }
        if (n == 0)
            return -1;
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        return -1;
    }
    return 1;
}

/* Отправить tbuf[tsent..tlen). 1 — всё ушло, 0 — места нет, -1 — ошибка. */
static int dl_tcp_flush(dl_pend *p)
{
    while (p->tsent < p->tlen) {
        ssize_t n = send(p->tfd, p->tbuf + p->tsent,
                         (size_t)(p->tlen - p->tsent), MSG_NOSIGNAL);
        if (n > 0) {
            p->tsent += (int)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return 0;
        return -1;
    }
    return 1;
}

/* 1 — connect завершён, 0 — ещё идёт, -1 — ошибка. */
static int dl_tcp_connected(int fd)
{
    struct pollfd pf;
    int err = 0;
    socklen_t l = sizeof(err);

    pf.fd = fd;
    pf.events = POLLOUT;
    pf.revents = 0;
    if (poll(&pf, 1, 0) <= 0)
        return 0;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &l) != 0 || err != 0)
        return -1;
    return 1;
}

/* Начать обмен: неблокирующий connect к SOCKS-порту Xray. */
static int dl_tcp_start(dl_pend *p)
{
    const char *host = g_cfg->socks_addr[0] ? g_cfg->socks_addr : "127.0.0.1";
    int port = g_cfg->socks_port > 0 ? g_cfg->socks_port : 1080;
    struct sockaddr_in sa;
    int fd, fl;

    if (g_tcp_active >= DL_MAX_TCP)
        return -1;                  /* очередь: запрос останется ждать в state 0 */
    if (p->up_try >= g_up_n)
        p->up_try = 0;
    dl_tcp_reset(p);
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1)
        return -1;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    dl_cloexec(fd);
    fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) != 0) {
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 &&
        errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    g_tcp_active++;
    p->tfd = fd;
    p->stage = 0;
    p->at_ms = dl_now_ms();
    p->state = 3;
    return 0;
}

/* Обмен не удался: пробуем следующий upstream, иначе отдаём прямой запрос. */
static void dl_tcp_give_up(dl_pend *p)
{
    dl_tcp_reset(p);
    if (p->up_try + 1 < g_up_n) {
        p->up_try++;
        if (dl_tcp_start(p) == 0)
            return;
    }
    dl_warn("DNS через туннель не прошёл (%s, SOCKS-TCP)", p->name);
    if (g_cfg->dns_lan_fallback) {
        dl_pend_send_direct(p);
    } else {
        g_q_fail++;
        dl_pend_drop(p);
    }
}

/* Один шаг обмена: connect -> приветствие -> CONNECT -> запрос -> ответ.
 * Возврат: 1 — шаг завершён и можно сразу пробовать следующий (данные уже
 * пришли); 0 — ждём сокет или обмен закончен. */
static int dl_tcp_step(dl_pend *p)
{
    switch (p->stage) {
    case 0:                             /* connect к SOCKS */
        switch (dl_tcp_connected(p->tfd)) {
        case 0:
            return 0;
        case -1:
            goto fail;
        }
        p->tbuf[0] = 0x05; p->tbuf[1] = 0x01; p->tbuf[2] = 0x00;
        p->tlen = 3;
        p->tsent = 0;
        if (dl_tcp_flush(p) < 0)
            goto fail;
        p->stage = 1;
        p->tlen = p->tsent = 0;
        p->wait = 2;
        return 1;

    case 1:                             /* метод без авторизации принят */
        switch (dl_tcp_read(p)) {
        case 0:
            return 0;
        case -1:
            goto fail;
        }
        if (p->tbuf[0] != 0x05 || p->tbuf[1] != 0x00)
            goto fail;
        /* CONNECT <upstream>:53 — IP-адресом, без DNS у самого прокси */
        p->tbuf[0] = 0x05; p->tbuf[1] = 0x01; p->tbuf[2] = 0x00;
        p->tbuf[3] = 0x01;
        memcpy(p->tbuf + 4, &g_up[p->up_try].sin_addr.s_addr, 4);
        memcpy(p->tbuf + 8, &g_up[p->up_try].sin_port, 2);
        p->tlen = 10;
        p->tsent = 0;
        if (dl_tcp_flush(p) < 0)
            goto fail;
        p->stage = 2;
        p->tlen = p->tsent = 0;
        p->wait = 4;
        return 1;

    case 2:                             /* ответ на CONNECT */
        switch (dl_tcp_read(p)) {
        case 0:
            return 0;
        case -1:
            goto fail;
        }
        if (p->tbuf[0] != 0x05 || p->tbuf[1] != 0x00)
            goto fail;
        if (p->tbuf[3] == 0x01) {          /* IPv4: 4 + 2 */
            p->wait = 4 + 4 + 2;
        } else if (p->tbuf[3] == 0x04) {   /* IPv6: 16 + 2 */
            p->wait = 4 + 16 + 2;
        } else if (p->tbuf[3] == 0x03) {   /* домен: длина + имя + 2 */
            p->wait = 5;
            if (dl_tcp_read(p) != 1)
                return 0;
            p->wait = 5 + (int)p->tbuf[4] + 2;
        } else {
            goto fail;
        }
        if (dl_tcp_read(p) != 1)
            return 0;
        if (p->qlen < 12 || p->qlen > 1500)
            goto fail;
        p->tbuf[0] = (unsigned char)(p->qlen >> 8);
        p->tbuf[1] = (unsigned char)(p->qlen & 0xff);
        memcpy(p->tbuf + 2, p->q, (size_t)p->qlen);
        p->tlen = 2 + p->qlen;
        p->tsent = 0;
        if (dl_tcp_flush(p) < 0)
            goto fail;
        p->stage = 3;
        p->tlen = p->tsent = 0;
        p->wait = 2;
        return 1;

    case 3:                             /* ответ DNS */
        if (dl_tcp_read(p) != 1)
            return 0;
        if (p->wait == 2) {
            int n = (p->tbuf[0] << 8) | p->tbuf[1];
            if (n < 12 || n > 1500)
                goto fail;
            p->wait = 2 + n;
            if (dl_tcp_read(p) != 1)
                return 0;
        }
        g_q_tunnel++;
        dl_pend_done(p, p->tbuf + 2, p->wait - 2);
        return 0;
    }
    return 0;

fail:
    dl_tcp_give_up(p);
    return 0;
}

/* --- интерфейс туннеля (egress_type=interface) --------------------------- */

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
    for (tok = strtok_r(list, ", \t", &save); tok; tok = strtok_r(NULL, ", \t", &save)) {
        if (!strcmp(tok, "tproxy") || !strcmp(tok, "xray"))
            continue;
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0)
            continue;
        dl_cloexec(fd);
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

/* --- ожидающие запросы --------------------------------------------------- */

static void dl_pend_send_tunnel(dl_pend *p);
static void dl_pend_send_direct(dl_pend *p);

static dl_pend *dl_pend_new(void)
{
    int i, oldest = 0;

    for (i = 0; i < DNS_LAN_PEND; i++) {
        if (!g_pend[i].used) {
            memset(&g_pend[i], 0, sizeof(g_pend[i]));
            g_pend[i].used = 1;
            g_pend[i].tfd = -1;
            return &g_pend[i];
        }
        if (g_pend[i].at_ms < g_pend[oldest].at_ms)
            oldest = i;
    }
    if (g_pend[oldest].tfd >= 0)
        dl_tcp_reset(&g_pend[oldest]);
    g_q_fail++;
    memset(&g_pend[oldest], 0, sizeof(g_pend[oldest]));
    g_pend[oldest].used = 1;
    g_pend[oldest].tfd = -1;
    return &g_pend[oldest];
}

static void dl_pend_drop(dl_pend *p)
{
    if (p->tfd >= 0)
        dl_tcp_reset(p);
    p->tfd = -1;
    p->used = 0;
}

static void dl_pend_send_local(dl_pend *p)
{
    struct sockaddr_in ns;

    memset(&ns, 0, sizeof(ns));
    ns.sin_family = AF_INET;
    ns.sin_port = htons(53);
    ns.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (g_loc_fd >= 0 && dl_send(g_loc_fd, p->q, (size_t)p->qlen, &ns) >= 0) {
        p->state = 0;
        p->at_ms = dl_now_ms();
        return;
    }
    dl_pend_send_tunnel(p);         /* локального нет — сразу туннель */
}

static void dl_pend_send_tunnel(dl_pend *p)
{
    if (g_mode == DL_VIA_SOCKS) {
        if (g_tcp_active >= DL_MAX_TCP)
            return;                 /* очередь: ждём в state 0, at_ms не сбрасываем */
        if (dl_tcp_start(p) == 0)
            return;                 /* state = 3, дальше продвигает poll */
        p->at_ms = dl_now_ms();
    } else if (g_mode == DL_VIA_IFACE) {
        p->at_ms = dl_now_ms();
        if (g_tun_fd >= 0 && dl_send(g_tun_fd, p->q, (size_t)p->qlen, &g_up[0]) >= 0) {
            p->state = 1;
            return;
        }
        if (dl_iface_open(g_cfg) == 0 &&
            dl_send(g_tun_fd, p->q, (size_t)p->qlen, &g_up[0]) >= 0) {
            p->state = 1;
            return;
        }
    } else {
        p->at_ms = dl_now_ms();
    }
    p->state = 2;                   /* в туннель не вышло — напрямую */
    (void)dl_send(g_fd, p->q, (size_t)p->qlen, &g_up[0]);
}

static void dl_pend_send_direct(dl_pend *p)
{
    p->at_ms = dl_now_ms();
    p->state = 2;
    (void)dl_send(g_fd, p->q, (size_t)p->qlen, &g_up[0]);
}

/* Ответ пришёл: отдать клиенту, закэшировать, освободить. */
static void dl_pend_done(dl_pend *p, const unsigned char *resp, int rn)
{
    if (rn > 12) {
        unsigned char out[1500];
        memcpy(out, resp, (size_t)rn);
        out[0] = (unsigned char)(p->id >> 8);
        out[1] = (unsigned char)(p->id & 0xff);
        dl_send(g_fd, out, (size_t)rn, &p->from);
        if (dl_answer_ok(out, rn)) {
            int ttl = dl_ttl(out, rn);
            if (ttl > 0)
                dl_cache_put(p->key, out, rn, ttl);
        }
    }
    dl_pend_drop(p);
}

/* Найти ожидающий по id и вопросу. */
static dl_pend *dl_pend_find(const unsigned char *msg, int n)
{
    int i;
    unsigned id;

    if (n < 12)
        return NULL;
    id = (unsigned)((msg[0] << 8) | msg[1]);
    for (i = 0; i < DNS_LAN_PEND; i++)
        if (g_pend[i].used && g_pend[i].id == id)
            return &g_pend[i];
    return NULL;
}

/* Разобрать входящие пакеты и продвинуть запросы по шагам. */
static void dl_drain_clients(void)
{
    int i;
    for (i = 0; i < 32; i++) {
        unsigned char q[1500];
        struct sockaddr_in from;
        socklen_t fl = sizeof(from);
        int n = (int)recvfrom(g_fd, q, sizeof(q), 0, (struct sockaddr *)&from, &fl);
        char key[264], name[256];
        unsigned qtype = 0;
        dl_entry *e;
        dl_pend *p;

        if (n < 12)
            return;
        if (q[2] & 0x80) {
            /* ответ на прямой запрос — сопоставить и отдать клиенту */
            p = dl_pend_find(q, n);
            if (p && p->state == 2)
                dl_pend_done(p, q, n);
            continue;
        }
        if (!dl_question(q, n, key, sizeof(key), &qtype, name, sizeof(name)))
            continue;
        g_q_total++;
        e = dl_cache_get(key, time(NULL));
        if (e && e->len >= 12) {
            unsigned char out[1500];
            memcpy(out, e->resp, e->len);
            out[0] = q[0];
            out[1] = q[1];
            dl_send(g_fd, out, e->len, &from);
            g_q_cache++;
            continue;
        }
        p = dl_pend_new();
        memcpy(p->q, q, (size_t)n);
        p->qlen = n;
        p->id = (unsigned)((q[0] << 8) | q[1]);
        p->from = from;
        snprintf(p->key, sizeof(p->key), "%s", key);
        snprintf(p->name, sizeof(p->name), "%s", name);
        if (g_cfg->dns_lan_smart && g_loc_fd >= 0) {
            dl_pend_send_local(p);   /* быстро: локальный резолвер */
        } else {
            dl_pend_send_tunnel(p);
        }
    }
}

static void dl_drain_local(void)
{
    int i;
    for (i = 0; i < 32 && g_loc_fd >= 0; i++) {
        unsigned char r[1500];
        int n = (int)recv(g_loc_fd, r, sizeof(r), 0);
        dl_pend *p;

        if (n < 12)
            return;
        p = dl_pend_find(r, n);
        if (!p || p->state != 0)
            continue;
        if (dl_answer_ok(r, n)) {
            g_q_local++;
            dl_pend_done(p, r, n);
        } else {
            /* подмена/пусто: эскалируем в туннель */
            g_q_escalate++;
            dl_pend_send_tunnel(p);
        }
    }
}

static void dl_drain_tunnel(void)
{
    int i;
    for (i = 0; i < 32; i++) {
        unsigned char r[1500];
        int n;
        dl_pend *p;

        if (g_mode != DL_VIA_IFACE)
            return;                 /* SOCKS-путь ведёт dl_tcp_tick */
        if (g_tun_fd < 0)
            return;
        {
            struct sockaddr_in from;
            socklen_t fl = sizeof(from);
            n = (int)recvfrom(g_tun_fd, r, sizeof(r), 0,
                              (struct sockaddr *)&from, &fl);
        }
        if (n < 12)
            return;
        p = dl_pend_find(r, n);
        if (!p || p->state != 1)
            continue;
        g_q_tunnel++;
        dl_pend_done(p, r, n);
    }
}

/* Продвинуть обмены DNS-over-TCP: каждый шаг может идти сразу за предыдущим,
 * пока данные уже пришли — иначе обмен растягивался на тики главного цикла. */
static void dl_tcp_tick(void)
{
    int i;

    for (i = 0; i < DNS_LAN_PEND; i++) {
        dl_pend *p = &g_pend[i];
        int guard = 0;

        if (!p->used || p->state != 3 || p->tfd < 0)
            continue;
        while (guard++ < 8 && p->state == 3 && p->tfd >= 0 &&
               dl_tcp_step(p))
            ;
    }
}

/* Просроченные: эскалация или отказ. */
static void dl_expire(void)
{
    int i;
    long long now = dl_now_ms();

    for (i = 0; i < DNS_LAN_PEND; i++) {
        dl_pend *p = &g_pend[i];
        long long age;

        if (!p->used)
            continue;
        age = now - p->at_ms;
        if (p->state == 0 && age > DL_T_QUEUE_MS) {
            g_q_fail++;
            dl_warn("очередь к туннелю переполнена (%s)", p->name);
            dl_pend_drop(p);
        } else if (p->state == 0 && age > DL_T_LOCAL_MS) {
            if (!p->esc) {
                p->esc = 1;
                g_q_escalate++;
            }
            dl_pend_send_tunnel(p);
        } else if (p->state == 1 && age > DL_T_TUNNEL_MS) {
            if (g_cfg->dns_lan_fallback)
                dl_pend_send_direct(p);
            else {
                g_q_fail++;
                dl_pend_drop(p);
            }
        } else if (p->state == 2 && age > DL_T_DIRECT_MS) {
            g_q_fail++;
            dl_warn("upstream не ответил (%s, %s)",
                    g_mode == DL_VIA_SOCKS ? "socks-tcp" :
                    g_mode == DL_VIA_IFACE ? g_tun_name : "direct", p->name);
            dl_pend_drop(p);
        } else if (p->state == 3 && age > DL_T_SOCKS_MS) {
            dl_tcp_give_up(p);
        }
    }
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
    struct sockaddr_in sa;

    if (!cfg || !cfg->dns_lan)
        return -1;
    if (g_fd >= 0)
        return 0;
    g_cfg = cfg;
    dl_parse_upstreams(cfg);
    if (!strcmp(cfg->egress_type, "tproxy"))
        g_mode = DL_VIA_SOCKS;
    else if (cfg->egress_interface[0] && dl_iface_open(cfg) == 0)
        g_mode = DL_VIA_IFACE;
    else {
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
    fcntl(g_fd, F_SETFL, fcntl(g_fd, F_GETFL, 0) | O_NONBLOCK);
    dl_cloexec(g_fd);
    /* сокет к локальному резолверу: источник 127.0.0.1 */
    {
        struct sockaddr_in lo;
        g_loc_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (g_loc_fd >= 0) {
            memset(&lo, 0, sizeof(lo));
            lo.sin_family = AF_INET;
            lo.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            lo.sin_port = 0;
            if (bind(g_loc_fd, (struct sockaddr *)&lo, sizeof(lo)) != 0) {
                close(g_loc_fd);
                g_loc_fd = -1;
            }
        }
    }
    if (g_loc_fd >= 0)
        fcntl(g_loc_fd, F_SETFL, fcntl(g_loc_fd, F_GETFL, 0) | O_NONBLOCK);
    dl_cloexec(g_loc_fd);
    dl_cloexec(g_tun_fd);
    for (i = 0; i < DNS_LAN_CACHE; i++) {
        free(g_cache[i].resp);
        memset(&g_cache[i], 0, sizeof(g_cache[i]));
    }
    memset(g_pend, 0, sizeof(g_pend));
    for (i = 0; i < DNS_LAN_PEND; i++)
        g_pend[i].tfd = -1;
    dl_stats_reset();
    slogf(SL_INFO, "dns_lan: слушаю DNS клиентов на порту %d, путь: %s%s",
          DNS_LAN_PORT,
          g_mode == DL_VIA_SOCKS ? "SOCKS-Xray (DNS-over-TCP)" :
          g_mode == DL_VIA_IFACE ? g_tun_name : "напрямую (туннеля нет)",
          cfg->dns_lan_smart ? " (сначала локальный резолвер)" : "");
    return 0;
}

void dns_lan_stop(void)
{
    int i;
    if (g_fd >= 0)
        close(g_fd);
    g_fd = -1;
    if (g_loc_fd >= 0)
        close(g_loc_fd);
    g_loc_fd = -1;
    if (g_tun_fd >= 0)
        close(g_tun_fd);
    g_tun_fd = -1;
    g_tun_name[0] = '\0';
    for (i = 0; i < DNS_LAN_PEND; i++) {
        if (g_pend[i].tfd >= 0)
            close(g_pend[i].tfd);
        g_pend[i].tfd = -1;
    }
    memset(g_pend, 0, sizeof(g_pend));
    for (i = 0; i < DNS_LAN_PEND; i++)
        g_pend[i].tfd = -1;
    g_tcp_active = 0;
    for (i = 0; i < DNS_LAN_CACHE; i++) {
        free(g_cache[i].resp);
        memset(&g_cache[i], 0, sizeof(g_cache[i]));
    }
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

/* Никаких блокирующих ожиданий: только приём и продвижение по срокам. */
void dns_lan_poll(void)
{
    if (g_fd < 0 || !g_cfg || !g_cfg->dns_lan)
        return;
    dl_drain_clients();
    dl_drain_local();
    dl_drain_tunnel();
    dl_tcp_tick();
    dl_expire();
}

int dns_lan_stats(char *out, size_t n)
{
    if (!out || n == 0)
        return 0;
    snprintf(out, n, "listen=%d via=%s upstreams=%d queries=%lu cached=%lu "
             "local=%lu escalate=%lu tunnel=%lu direct=%lu fail=%lu pend=%d",
             g_fd >= 0 ? DNS_LAN_PORT : 0,
             g_mode == DL_VIA_SOCKS ? "socks-tcp" :
             g_mode == DL_VIA_IFACE ? g_tun_name : "direct",
             g_up_n, g_q_total, g_q_cache, g_q_local, g_q_escalate,
             g_q_tunnel, g_q_direct, g_q_fail, DNS_LAN_PEND);
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

/* Идёт обмен DNS-over-TCP? Главный цикл спит короче, чтобы ответ не ждал
 * следующего тика: каждый шаг обмена — это RTT, и на 200 мс тиках ответ
 * приходит за секунды. */
int dns_lan_busy(void)
{
    int i;

    for (i = 0; i < DNS_LAN_PEND; i++)
        if (g_pend[i].used && g_pend[i].state == 3)
            return 1;
    return 0;
}
