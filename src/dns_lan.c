#define _GNU_SOURCE
#include "dns_lan.h"
#include "backend.h"
#include "config.h"
#include "log.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
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
/* Очередь ожидания: 128, а не 64 — всплеск с 5+ устройств больше не выбивает
 * живые запросы. 256 не берём: запись ~3,7 КБ, это почти +1 МБ RSS, а на
 * роутере свободно единицы мегабайт. Решение зафиксировано: остаётся 128 как
 * предел для устройств этого класса; вопрос объёма снят с повестки до появления
 * отдельного цикла у форвардера. */
#define DNS_LAN_PEND 128
#define DNS_LAN_MAX_UP 4

#define DL_T_LOCAL_MS   400
#define DL_T_TUNNEL_MS  1200
#define DL_T_DIRECT_MS  800
#define DL_T_SOCKS_MS   15000   /* весь обмен DNS-over-TCP: connect+handshake+ответ */
#define DL_T_QUEUE_MS   20000   /* сколько запрос может ждать очереди к туннелю */
/* Жёсткий бюджет на запрос: клиент ждёт не дольше. 2000 мс не хватало:
 * главный цикл агента периодически занят (обновление списков, батч ipset,
 * перепроверка датаплейна), тик форвардера опаздывал, и запрос получал
 * SERVFAIL хотя ответ уже был готов. 4000 мс — ниже типового клиентского
 * таймаута (5 с) и с запасом на два пропущенных тика. */
#define DL_T_HARD_MS    4000
#define DL_MAX_TCP      16      /* одновременных обменов с SOCKS */

/* Причина обрыва обмена с SOCKS (для журнала). */
enum {
    DL_WHY_NONE = 0,
    DL_WHY_CONNECT = 1,     /* не удалось соединиться с SOCKS-портом */
    DL_WHY_GREET = 2,       /* прокси не принял метод без аутентификации */
    DL_WHY_REP = 3,         /* прокси отказал в CONNECT к upstream */
    DL_WHY_EOF = 4,         /* прокси закрыл соединение */
    DL_WHY_IO = 5,          /* ошибка сокета */
    DL_WHY_LEN = 6,         /* неверная длина DNS-ответа */
    DL_WHY_ANSWER = 7,      /* ответ пришёл, но не принят (rcode/подмена) */
    DL_WHY_QLEN = 8         /* запрос клиента неверной длины */
};

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
    unsigned char q[1500];   /* запрос клиента:EDNS0/DNSSEC бывают больше 512 */
    int qlen;
    struct sockaddr_in from;
    char key[264];
    char name[256];
    int state;              /* 0 = локальный, 1 = туннель (UDP), 2 = прямо,
                               3 = туннель (DNS-over-TCP через SOCKS),
                               4 = ждёт свободного слота SOCKS (туннель уже
                                   выбран: это НЕ «ждём локальный ответ») */
    long long at_ms;        /* начало текущей стадии (для её таймаута) */
    long long born_ms;      /* приход от клиента: жёсткий бюджет DL_T_HARD_MS */
    /* SOCKS-TCP: своё неблокирующее соединение на каждый запрос */
    int tfd;
    int stage;              /* 0 connect, 1 приветствие, 2 CONNECT, 3 ответ */
    int tlen;               /* сколько принято в tbuf */
    int tsent;              /* сколько отправлено из tbuf */
    int sending;            /* 1 = есть недосланный хвост, стадию не меняем */
    int next_stage;         /* стадия после успешной отправки */
    int next_wait;          /* сколько байт ожидать на новой стадии */
    /* Почему оборвался обмен — только для журнала: «шаг 3» сам по себе
     * смешивает четыре разных случая (прокси закрыл связь, ошибка сокета,
     * неверная длина, ответ не принят из-за rcode). */
    int why;
    int rerr;               /* errno на момент обрыва */
    int rcode;              /* rcode ответа, который не приняли */
    int first_stage;        /* шаг первой попытки (первый upstream) */
    unsigned qtype;         /* тип запроса клиента — для журнала */
    int wait;               /* сколько байт ждём на текущей стадии */
    int up_try;             /* какой upstream пробуем (0..g_up_n-1) */
    int tun_try;            /* сколько раз запрос уходил в туннель (AY) */
    int esc;                /* эскалация в туннель уже посчитана */
    int esc_sub;            /* эскалация из-за подмены (127.x/0.0.0.0), а не таймаута */
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

/* Режим обслуживания. 0 — прежний: шаги делает тик главного цикла
 * (dns_lan_poll из engine.c). 1 — свой поток: он сам опрашивает сокеты с шагом
 * DL_THREAD_TICK_MS и делает те же шаги. В поточном режиме движок к форвардеру
 * не обращается вообще (ни poll, ни busy, ни снимок), поэтому общих изменяемых
 * данных между потоками нет — кроме флага остановки и записанной пары: их
 * достаточно, мьютексы не нужны. */
static pthread_t g_thr;
static int g_thr_on;
static volatile sig_atomic_t g_thr_stop;
static volatile time_t g_last_step;
static int g_wake_rd = -1, g_wake_wr = -1;
#define DL_THREAD_TICK_MS 50

static void dl_step(void);
static void *dl_thread_main(void *arg);

/* Очередь «поток → главный цикл» для пиннинга по подмене. Пиннинг трогает батч
 * ipset, который принадлежит главному циклу, поэтому поток только складывает
 * заявки, а применяет их движок. Частота низкая (только на подменённых
 * доменах), мьютекса достаточно. */
#define DL_PIN_QUEUE 16
typedef struct {
    char ip[16];
    char name[64];
} dl_pin_req;
static dl_pin_req g_pins[DL_PIN_QUEUE];
static int g_pin_rd, g_pin_wr;
static pthread_mutex_t g_pin_mu = PTHREAD_MUTEX_INITIALIZER;

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

/* Имя из запроса может содержать любые байты (RFC 1035 это разрешает): в
 * журнал печатаем только печатные ASCII, остальное — точкой. Без этого
 * «двоичный» QNAME попадал в лог нечитаемым мусором и пугал при разборе. */
static void dl_name_fmt(char *out, size_t n, const char *name)
{
    size_t i;

    if (n == 0)
        return;
    for (i = 0; i + 1 < n && name[i]; i++)
        out[i] = (name[i] >= 0x20 && name[i] < 0x7f) ? name[i] : '.';
    out[i] = '\0';
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

/* Заявка на пин: домен был подменён, туннель вернул настоящий адрес. Применяет
 * заявку главный цикл (см. dns_lan_drain_pins), потому что пиннинг идёт через
 * батч ipset, который принадлежит ему. */
static void dl_pin_enqueue(const char *name, const char *ip)
{
    pthread_mutex_lock(&g_pin_mu);
    if ((g_pin_wr + 1) % DL_PIN_QUEUE != g_pin_rd) {
        snprintf(g_pins[g_pin_wr].ip, sizeof(g_pins[0].ip), "%s", ip);
        snprintf(g_pins[g_pin_wr].name, sizeof(g_pins[0].name), "%.63s", name);
        g_pin_wr = (g_pin_wr + 1) % DL_PIN_QUEUE;
    }
    pthread_mutex_unlock(&g_pin_mu);
}

/* Разобрать A-записи ответа из туннеля и поставить заявки на пин. Только если
 * запрос эскалирован именно из-за подмены: при штатном ответе локального
 * резолвера и при обменах без smart-режима пиннинг не нужен. */
static void dl_pins_from_answer(const dl_pend *p, const unsigned char *m, int len)
{
    int qd, an, off = 12, i;

    if (!g_cfg || !g_cfg->dns_lan_pin || !p->esc_sub)
        return;
    if (len < 12 || (m[3] & 0x0f) != 0)
        return;                 /* не NOERROR — пинить нечего */
    qd = (m[4] << 8) | m[5];
    an = (m[6] << 8) | m[7];
    for (i = 0; i < qd; i++) {
        off = skip_name(m, len, off);
        if (off < 0 || off + 4 > len)
            return;
        off += 4;
    }
    for (i = 0; i < an && off + 10 <= len; i++) {
        int type, rdlen;
        char ip[16];

        off = skip_name(m, len, off);
        if (off < 0 || off + 10 > len)
            return;
        type = (m[off] << 8) | m[off + 1];
        rdlen = (m[off + 8] << 8) | m[off + 9];
        off += 10;
        if (off + rdlen > len)
            return;
        if (type == 1 && rdlen == 4) {
            /* повторную подмену не пиним: адрес 127/0.0.0.0 бесполезен */
            if (!(m[off] == 127 || (m[off] == 0 && m[off + 1] == 0 &&
                                    m[off + 2] == 0 && m[off + 3] == 0))) {
                snprintf(ip, sizeof(ip), "%u.%u.%u.%u",
                         m[off], m[off + 1], m[off + 2], m[off + 3]);
                dl_pin_enqueue(p->name, ip);
            }
        }
        off += rdlen;
    }
}

/* Есть ли в ответе A-запись с подменой (127.x / 0.0.0.0). */
static int dl_a_subst(const unsigned char *m, int len)
{
    int qd, an, off = 12, i;

    if (len < 12)
        return 0;
    qd = (m[4] << 8) | m[5];
    an = (m[6] << 8) | m[7];
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
            return 0;
        type = (m[off] << 8) | m[off + 1];
        rdlen = (m[off + 8] << 8) | m[off + 9];
        off += 10;
        if (off + rdlen > len)
            return 0;
        if (type == 1 && rdlen == 4 &&
            (m[off] == 127 || (m[off] == 0 && m[off + 1] == 0 &&
                               m[off + 2] == 0 && m[off + 3] == 0)))
            return 1;
        off += rdlen;
    }
    return 0;
}

/* Ответ из туннеля: NXDOMAIN — валидный ответ, положительный — проверяем на
 * подмену (127/0.0.0.0). SERVFAIL/REFUSED из туннеля считаем неудачей: раньше
 * такой ответ уходил клиенту как есть, и «DNS не работает» выглядело как
 * рабочий резолв. Для локального пути проверка мягче (dl_answer_ok): там
 * NXDOMAIN означает «нужна эскалация».
 *
 * ВАЖНО: ответ NOERROR принимается независимо от типа записи. Раньше требовался
 * A/AAAA (dl_answer_ok), и валидные ответы на запросы типа HTTPS/SVCB (65),
 * CNAME-только и NODATA считались провалом — клиент получал SERVFAIL. Именно на
 * такие типы приходится заметная часть запросов браузеров и Android-устройств. */
static int dl_tunnel_answer_ok(const unsigned char *m, int n)
{
    int rcode;

    if (n < 12)
        return 0;
    rcode = m[3] & 0x0f;
    if (rcode == 3)              /* NXDOMAIN */
        return 1;
    if (rcode != 0)
        return 0;
    return !dl_a_subst(m, n);    /* NOERROR годится, если нет подмены */
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
static void dl_pend_fail(dl_pend *p, int rcode);
static void dl_pend_send_direct(dl_pend *p);

static int g_tcp_active;        /* сколько обменов с SOCKS идёт прямо сейчас */
/* Размыкатель туннеля: подряд идущие неудачи DNS через туннель. Пока открыт,
 * новые запросы не идут в мёртвый туннель, а сразу отвечаются локально/прямо.
 * Без этого отказ туннеля превращался в «тишину» для клиента. */
static int g_tun_streak;
static time_t g_tun_first;
static time_t g_tun_until;

static int dl_tunnel_down(void)
{
    return g_tun_until && time(NULL) < g_tun_until;
}

static void dl_tunnel_failed(void)
{
    time_t now = time(NULL);

    if (!g_tun_first || now - g_tun_first > 120) {
        g_tun_first = now;
        g_tun_streak = 0;
    }
    g_tun_streak++;
    if (g_tun_streak >= 3 && !dl_tunnel_down()) {
        g_tun_until = now + 120;
        g_tun_streak = 0;
        dl_warn("туннель не отвечает на DNS — 2 мин без эскалации, "
                "отвечаю локально/прямо");
    }
}

static void dl_tunnel_ok(void)
{
    g_tun_streak = 0;
    g_tun_first = 0;
    g_tun_until = 0;
}

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
    p->sending = 0;
    p->next_stage = 0;
    p->next_wait = 0;
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
        if (n == 0) {
            p->why = DL_WHY_EOF;   /* прокси закрыл соединение */
            return -1;
        }
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        p->why = DL_WHY_IO;
        p->rerr = errno;
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
    p->why = DL_WHY_NONE;
    p->rerr = 0;
    p->rcode = 0;
    p->at_ms = dl_now_ms();
    p->state = 3;
    return 0;
}

/* Обмен не удался: пробуем следующий upstream, иначе отдаём прямой запрос. */
static void dl_tcp_give_up(dl_pend *p)
{
    /* Шаг нужно запомнить ДО dl_tcp_reset: он обнуляет p->stage, и прежняя
     * версия журнала всегда печатала «шаг 0» — то есть врала. */
    int dead_stage = p->stage;
    int retry = -2;

    if (!p->first_stage)
        p->first_stage = dead_stage;
    dl_tcp_reset(p);
    if (p->up_try + 1 < g_up_n) {
        p->up_try++;
        retry = dl_tcp_start(p);
        if (retry == 0)
            return;             /* пошли на следующий upstream */
    }
    dl_tunnel_failed();
    /* Шаг (0 — connect к SOCKS, 1 — приветствие, 2 — CONNECT, 3 — ответ),
     * причина (см. DL_WHY_*), rcode непринятого ответа, errno/rep-код, число
     * активных обменов. Без причины «шаг 3» смешивает четыре разных случая. */
    slogf(SL_WARN, "dns_lan: обмен с SOCKS прерван: шаг %d, причина %d, rcode %d, "
                   "ancount %d (тип %u, qlen %d, upstream %d из %d, первый шаг %d, "
                   "повтор=%d, активных=%d)",
          dead_stage, p->why, p->rcode, p->rerr, p->qtype, p->qlen,
          p->up_try + 1, g_up_n, p->first_stage, retry, g_tcp_active);
    {
        char nm[96];
        dl_name_fmt(nm, sizeof(nm), p->name);
        dl_warn("DNS через туннель не прошёл (%s, SOCKS-TCP)", nm);
    }
    if (g_cfg->dns_lan_fallback) {
        dl_pend_send_direct(p);
    } else {
        g_q_fail++;
        dl_pend_fail(p, 2);
    }
}

/* Подготовить отправку: данные уже лежат в tbuf. Стадия сменится только когда
 * уйдут ВСЕ байты: `dl_tcp_flush` может вернуть 0 («в сокете нет места»), и
 * прежняя версия в этом случае всё равно переходила дальше, теряя хвост запроса.
 * Ответа на обрезанный запрос не бывает никогда — обмен висел до таймаута. */
static void dl_tcp_arm(dl_pend *p, int len, int next_stage, int next_wait)
{
    p->tlen = len;
    p->tsent = 0;
    p->next_stage = next_stage;
    p->next_wait = next_wait;
    p->sending = 1;
}

/* Один шаг обмена: connect -> приветствие -> CONNECT -> запрос -> ответ.
 * Возврат: 1 — шаг завершён и можно сразу пробовать следующий (данные уже
 * пришли); 0 — ждём сокет или обмен закончен. */
static int dl_tcp_step(dl_pend *p)
{
    /* Недосланный хвост: докидываем, стадию не меняем. */
    if (p->sending) {
        int rc = dl_tcp_flush(p);

        if (rc == 0)
            return 0;               /* места нет — вернёмся на следующем тике */
        if (rc < 0) {
            p->why = DL_WHY_IO;
            p->rerr = errno;
            goto fail;
        }
        p->sending = 0;
        p->tlen = p->tsent = 0;
        p->stage = p->next_stage;
        p->wait = p->next_wait;
        return 1;
    }

    switch (p->stage) {
    case 0:                             /* connect к SOCKS */
        switch (dl_tcp_connected(p->tfd)) {
        case 0:
            return 0;
        case -1:
            p->why = DL_WHY_CONNECT;
            goto fail;
        }
        p->tbuf[0] = 0x05; p->tbuf[1] = 0x01; p->tbuf[2] = 0x00;
        dl_tcp_arm(p, 3, 1, 2);
        return 1;

    case 1:                             /* метод без авторизации принят */
        switch (dl_tcp_read(p)) {
        case 0:
            return 0;
        case -1:
            goto fail;
        }
        if (p->tbuf[0] != 0x05 || p->tbuf[1] != 0x00) {
            p->why = DL_WHY_GREET;
            goto fail;
        }
        /* CONNECT <upstream>:53 — IP-адресом, без DNS у самого прокси */
        p->tbuf[0] = 0x05; p->tbuf[1] = 0x01; p->tbuf[2] = 0x00;
        p->tbuf[3] = 0x01;
        memcpy(p->tbuf + 4, &g_up[p->up_try].sin_addr.s_addr, 4);
        memcpy(p->tbuf + 8, &g_up[p->up_try].sin_port, 2);
        dl_tcp_arm(p, 10, 2, 4);
        return 1;

    case 2:                             /* ответ на CONNECT */
        switch (dl_tcp_read(p)) {
        case 0:
            return 0;
        case -1:
            goto fail;
        }
        if (p->tbuf[0] != 0x05 || p->tbuf[1] != 0x00) {
            p->why = p->tbuf[1] ? DL_WHY_REP : DL_WHY_GREET;
            p->rerr = p->tbuf[1];   /* rep-код SOCKS для журнала */
            goto fail;
        }
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
            p->why = DL_WHY_REP;
            goto fail;
        }
        if (dl_tcp_read(p) != 1)
            return 0;
        if (p->qlen < 12 || p->qlen > 1500) {
            p->why = DL_WHY_QLEN;
            p->rerr = p->qlen;
            goto fail;
        }
        p->tbuf[0] = (unsigned char)(p->qlen >> 8);
        p->tbuf[1] = (unsigned char)(p->qlen & 0xff);
        memcpy(p->tbuf + 2, p->q, (size_t)p->qlen);
        dl_tcp_arm(p, 2 + p->qlen, 3, 2);
        return 1;

    case 3:                             /* ответ DNS */
        if (dl_tcp_read(p) != 1)
            return 0;
        if (p->wait == 2) {
            int n = (p->tbuf[0] << 8) | p->tbuf[1];
            if (n < 12 || n > 1500) {
                p->why = DL_WHY_LEN;
                p->rerr = n;
                goto fail;
            }
            p->wait = 2 + n;
            if (dl_tcp_read(p) != 1)
                return 0;
        }
        if (!dl_tunnel_answer_ok(p->tbuf + 2, p->wait - 2)) {
            p->why = DL_WHY_ANSWER;
            /* Поля DNS-сообщения начинаются с tbuf[2]: rcode — байт 3 сообщения
             * (tbuf[5]), ANCOUNT — байты 6-7 (tbuf[8..9]). */
            p->rcode = p->tbuf[5] & 0x0f;
            p->rerr = (p->tbuf[8] << 8) | p->tbuf[9];   /* ANCOUNT */
            goto fail;
        }
        g_q_tunnel++;
        dl_tunnel_ok();
        dl_pins_from_answer(p, p->tbuf + 2, p->wait - 2);
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
    int is_ay = !strcmp(cfg->egress_type, "ay");

    if (g_tun_fd >= 0) {
        close(g_tun_fd);
        g_tun_fd = -1;
        g_tun_name[0] = '\0';
    }
    /* AY: клиент поднимает собственный tun (ay0), а egress_interface в
     * конфиге намеренно остаётся прежним (nwg0/пусто) — для DNS берём ay_iface. */
    if (is_ay)
        snprintf(list, sizeof(list), "%s",
                 cfg->ay_iface[0] ? cfg->ay_iface : "ay0");
    else
        snprintf(list, sizeof(list), "%s", cfg->egress_interface);
    for (tok = strtok_r(list, ", \t", &save); tok; tok = strtok_r(NULL, ", \t", &save)) {
        if (!strcmp(tok, "tproxy") || !strcmp(tok, "xray"))
            continue;
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0)
            continue;
        dl_cloexec(fd);
        {
            /* Без O_NONBLOCK dl_drain_tunnel() делает блокирующий recvfrom и
             * вешает поток форвардера навсегда: watchdog его перезапускает,
             * а dns_lan так и не тикает (queries=0). */
            int fl = fcntl(fd, F_GETFL, 0);
            if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) != 0) {
                close(fd);
                continue;
            }
        }
        if (!is_ay &&
            setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, tok,
                       (socklen_t)strlen(tok)) != 0) {
            close(fd);
            continue;
        }
        if (is_ay) {
            /* AY: DNS идёт на резолвер сервера 10.23.0.1:53 внутри tun10.
             * Маршрут 10.23.0.0/24 dev ay0 connected, поэтому source
             * выбирается сам (10.23.0.2); ни SO_BINDTODEVICE, ни bind не нужны. */
            g_tun_fd = fd;
            snprintf(g_tun_name, sizeof(g_tun_name), "%s",
                     cfg->ay_iface[0] ? cfg->ay_iface : "ay0");
            return 0;
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
    dl_pend_fail(&g_pend[oldest], 2);   /* клиент должен получить отказ, а не тишину */
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

/* Конец секции вопроса: до него ответ можно скопировать, обнулив счётчики.
 * Копировать весь запрос нельзя — OPT/EDNS0 из ARCOUNT остался бы «висеть»
 * без записи, и клиент получил бы битый пакет. */
static int dl_qend(const unsigned char *m, int n)
{
    int off = 12;

    while (off < n && m[off]) {
        if ((m[off] & 0xc0) == 0xc0) { off += 2; break; }
        off += 1 + m[off];
    }
    if (off >= n || m[off] != 0)
        return 0;
    off += 1 + 4;                 /* корень + qtype + qclass */
    return off <= n ? off : 0;
}

/* Отказ клиенту: SERVFAIL вместо тишины. Раньше любой сбой (переполнение
 * очереди, таймаут SOCKS, таймаут прямого запроса) просто выбрасывал запрос:
 * ОС клиента висела до своего таймаута, и снаружи это выглядело как
 * «DNS не работает» без единого намёка на причину. */
static void dl_pend_fail(dl_pend *p, int rcode)
{
    unsigned char out[512];
    int n;

    n = p->qlen < 12 ? 0 : dl_qend(p->q, p->qlen);
    if (n > 0 && n <= (int)sizeof(out)) {
        memcpy(out, p->q, (size_t)n);
        out[2] = (unsigned char)(0x80 | (out[2] & 0x79));  /* QR=1, opcode как был */
        out[3] = (unsigned char)((out[3] & 0xf0) | (rcode & 0x0f));
        out[6] = out[7] = 0;      /* ANCOUNT */
        out[8] = out[9] = 0;      /* NSCOUNT */
        out[10] = out[11] = 0;    /* ARCOUNT */
        dl_send(g_fd, out, (size_t)n, &p->from);
    }
    dl_pend_drop(p);
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
    if (dl_tunnel_down()) {
        /* Размыкатель: не занимаем слоты SOCKS мёртвым туннелем — сразу прямо. */
        dl_pend_send_direct(p);
        return;
    }
    if (g_mode == DL_VIA_SOCKS) {
        if (g_tcp_active >= DL_MAX_TCP) {
            /* Очередь к SOCKS — отдельное состояние: раньше это был state 0, и
             * запрос через 400 мс «эскалировался» повторно, хотя локальный
             * ответ уже был отвергнут. at_ms — вход в очередь, жёсткий бюджет
             * (born_ms) всё равно решает. */
            p->state = 4;
            p->at_ms = dl_now_ms();
            return;
        }
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

/* Найти ожидающий по id, вопросу и (опционально) адресу клиента. Только по id
 * нельзя: за вторым NAT (TP-Link) несколько клиентов одновременно используют
 * одинаковые transaction id. Вопрос в ответе всегда тот же, что в запросе,
 * поэтому memcmp секции вопроса различает имена; from (если задан) — клиента.
 * Для ответов upstream from=NULL: там известен только id+вопрос, а одинаковый
 * вопрос у двух клиентов даёт и одинаковый ответ — отдать его любому из них
 * безопасно. */
static dl_pend *dl_pend_find(const unsigned char *msg, int n,
                             const struct sockaddr_in *from)
{
    int i, qe;

    if (n < 12)
        return NULL;
    qe = dl_qend(msg, n);
    {
        unsigned id = (unsigned)((msg[0] << 8) | msg[1]);
        for (i = 0; i < DNS_LAN_PEND; i++) {
            dl_pend *p = &g_pend[i];
            int pq;

            if (!p->used || p->id != id)
                continue;
            if (from &&
                (p->from.sin_addr.s_addr != from->sin_addr.s_addr ||
                 p->from.sin_port != from->sin_port))
                continue;
            if (qe <= 12 || p->qlen < 12)
                return p;           /* вопрос не разобрать — по id */
            pq = dl_qend(p->q, p->qlen);
            if (pq == qe && memcmp(p->q + 12, msg + 12, (size_t)(qe - 12)) == 0)
                return p;
        }
    }
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
            p = dl_pend_find(q, n, NULL);
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
        if (n < 12 || n > (int)sizeof(g_pend[0].q))
            continue;               /* не помещается в буфер запроса */
        /* Повтор от того же клиента (тот же порт, id и вопрос): не плодим
         * дубликат, а продлеваем ожидание. Именно здесь работает from — за
         * вторым NAT у разных клиентов бывают одинаковые id и вопрос. */
        p = dl_pend_find(q, n, &from);
        if (p) {
            p->at_ms = dl_now_ms();
            continue;
        }
        p = dl_pend_new();
        memcpy(p->q, q, (size_t)n);
        p->qlen = n;
        p->qtype = qtype;       /* для журнала: тип запроса (65 = HTTPS/SVCB) */
        p->id = (unsigned)((q[0] << 8) | q[1]);
        p->from = from;
        p->born_ms = dl_now_ms();
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
        p = dl_pend_find(r, n, NULL);
        if (!p || p->state != 0)
            continue;
        /* Локальный ответ: для A/AAAA пустой ответ означает блокировку и требует
         * эскалации. Для остальных типов (HTTPS/SVCB 65, CNAME-только, MX, TXT)
         * NODATA — нормальный ответ, эскалировать незачем. */
        int ok = dl_answer_ok(r, n);
        if (!ok && p->qtype != 1 && p->qtype != 28 &&
            (r[3] & 0x0f) == 0 && !dl_a_subst(r, n))
            ok = 1;
        if (ok) {
            g_q_local++;
            dl_pend_done(p, r, n);
        } else {
            /* подмена/пусто: эскалируем в туннель */
            g_q_escalate++;
            p->esc_sub = 1;     /* признак: ответ был подменён, а не «молчал» */
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
        p = dl_pend_find(r, n, NULL);
        if (!p || p->state != 1)
            continue;
        if (!dl_tunnel_answer_ok(r, n)) {
            dl_tunnel_failed();
            g_q_fail++;
            dl_pend_fail(p, 2);
            continue;
        }
        g_q_tunnel++;
        dl_tunnel_ok();
        dl_pins_from_answer(p, r, n);
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
        /* Жёсткий бюджет: клиент не ждёт дольше DL_T_HARD_MS ни на одной
         * стадии. Без него запрос в очереди SOCKS мог жить до 20 с, а при
         * сбросе at_ms на неудаче — не истекать вовсе. */
        if (p->born_ms && now - p->born_ms > DL_T_HARD_MS) {
            char nm[96];
            g_q_fail++;
            dl_name_fmt(nm, sizeof(nm), p->name);
            dl_warn("запрос дольше %d мс — SERVFAIL клиенту (%s)",
                    DL_T_HARD_MS, nm);
            dl_pend_fail(p, 2);
            continue;
        }
        if (p->state == 0 && age > DL_T_QUEUE_MS) {
            char nm[96];
            g_q_fail++;
            dl_name_fmt(nm, sizeof(nm), p->name);
            dl_warn("очередь к туннелю переполнена (%s)", nm);
            dl_pend_fail(p, 2);
        } else if (p->state == 0 && age > DL_T_LOCAL_MS) {
            if (!p->esc) {
                p->esc = 1;
                g_q_escalate++;
            }
            dl_pend_send_tunnel(p);
        } else if (p->state == 4) {
            /* Ждём слот SOCKS: как только он освободился — начинаем обмен.
             * Отдельный state не даёт повторной «эскалации» из локального
             * ожидания (см. audit п.7). */
            if (g_tcp_active < DL_MAX_TCP)
                dl_pend_send_tunnel(p);
        } else if (p->state == 1 && age > DL_T_TUNNEL_MS) {
            /* Один повтор в туннель до фолбэка: потеря одной датаграммы (а на
             * мобильном/междугороднем канале это штатные 1–3 %) не должна
             * отправлять запрос «напрямую», где в РФ для части домён ни ответа,
             * ни адреса. Бюджет укладывается в жёсткий: 1200 + 1200 + 800. */
            if (g_mode == DL_VIA_IFACE && p->tun_try < 1) {
                p->tun_try++;
                dl_pend_send_tunnel(p);
            } else {
                dl_tunnel_failed();
                if (g_cfg->dns_lan_fallback)
                    dl_pend_send_direct(p);
                else {
                    g_q_fail++;
                    dl_pend_fail(p, 2);
                }
            }
        } else if (p->state == 2 && age > DL_T_DIRECT_MS) {
            char nm[96];
            g_q_fail++;
            dl_name_fmt(nm, sizeof(nm), p->name);
            dl_warn("прямой upstream не ответил (%s, %s)",
                    g_mode == DL_VIA_SOCKS ? "socks-tcp" :
                    g_mode == DL_VIA_IFACE ? g_tun_name : "direct", nm);
            dl_pend_fail(p, 2);
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
    /* AY: единственный upstream — резолвер на стороне сервера (tun10,
     * 10.23.0.1). Он ходит в 1.1.1.1/9.9.9.9 уже из VPS, поэтому ответы
     * не подменяются провайдером. */
    if (cfg && !strcmp(cfg->egress_type, "ay")) {
        memset(&g_up[0], 0, sizeof g_up[0]);
        g_up[0].sin_family = AF_INET;
        g_up[0].sin_port = htons(53);
        inet_pton(AF_INET, "10.23.0.1", &g_up[0].sin_addr);
        g_up_n = 1;
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
    else if ((cfg->egress_interface[0] || !strcmp(cfg->egress_type, "ay")) &&
             dl_iface_open(cfg) == 0)
        g_mode = DL_VIA_IFACE;
    else {
        const char *shown = !strcmp(cfg->egress_type, "ay")
                            ? (cfg->ay_iface[0] ? cfg->ay_iface : "ay0")
                            : cfg->egress_interface;
        g_mode = DL_VIA_DIRECT;
        slogf(SL_WARN, "dns_lan: туннеля нет (egress_type=%s, интерфейсы '%s') — "
              "DNS клиентов пойдёт напрямую, как и раньше",
              cfg->egress_type[0] ? cfg->egress_type : "(пусто)",
              shown);
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
    /* Быстрый restart/crash: без SO_REUSEADDR bind может отдать EADDRINUSE и
     * форвардер не поднимется, пока ядро не отпустит старый сокет. */
    {
        int one = 1;
        (void)setsockopt(g_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    }
    if (bind(g_fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        slogf(SL_WARN, "dns_lan: порт %d не занят (%s)", DNS_LAN_PORT,
              strerror(errno));
        close(g_fd);
        g_fd = -1;
        return -1;
    }
    {
        int fl = fcntl(g_fd, F_GETFL, 0);
        if (fl < 0 || fcntl(g_fd, F_SETFL, fl | O_NONBLOCK) != 0) {
            slogf(SL_WARN, "dns_lan: O_NONBLOCK на порту %d не встал (%s)",
                  DNS_LAN_PORT, strerror(errno));
            close(g_fd);
            g_fd = -1;
            return -1;
        }
    }
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
    if (g_loc_fd >= 0) {
        int fl = fcntl(g_loc_fd, F_GETFL, 0);
        if (fl < 0 || fcntl(g_loc_fd, F_SETFL, fl | O_NONBLOCK) != 0) {
            /* Без неблокирующего режима локальный путь опасен: закрываем и
             * работаем сразу через туннель. */
            close(g_loc_fd);
            g_loc_fd = -1;
        }
    }
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
    /* Режим обслуживания выбирается здесь. Поточный: свой опрос сокетов с
     * шагом 50 мс, движок к форвардеру не обращается. Непоточный: шаги делает
     * тик движка, а во время ожидания внешних процессов (iptables/ipset/
     * conntrack) его обслуживает wait_yield через этот колбэк. */
    g_thr_on = 0;
    if (cfg->dns_lan_thread) {
        int w[2];
        if (pipe(w) == 0) {
            int fl;
            fl = fcntl(w[0], F_GETFL, 0);
            (void)fcntl(w[0], F_SETFL, (fl < 0 ? 0 : fl) | O_NONBLOCK);
            dl_cloexec(w[0]);
            dl_cloexec(w[1]);
            g_wake_rd = w[0];
            g_wake_wr = w[1];
            g_thr_stop = 0;
            if (pthread_create(&g_thr, NULL, dl_thread_main, NULL) == 0) {
                g_thr_on = 1;
                slogf(SL_INFO, "dns_lan: форвардер в своём потоке (тик %d мс)",
                      DL_THREAD_TICK_MS);
            } else {
                close(w[0]);
                close(w[1]);
                g_wake_rd = g_wake_wr = -1;
                slogf(SL_WARN, "dns_lan: поток не создан — работаю по тику движка");
            }
        } else {
            slogf(SL_WARN, "dns_lan: pipe пробуждения не создан — работаю по тику движка");
        }
    }
    if (!g_thr_on)
        backend_set_yield_cb(dns_lan_poll);
    slogf(SL_INFO, "dns_lan: слушаю DNS клиентов на порту %d, путь: %s%s",
          DNS_LAN_PORT,
          g_mode == DL_VIA_SOCKS ? "SOCKS-Xray (DNS-over-TCP)" :
          g_mode == DL_VIA_IFACE ? g_tun_name : "напрямую (туннеля нет)",
          cfg->dns_lan_smart ? " (сначала локальный резолвер)" : "");
    /* Первый снимок сразу: status не должен показывать состояние прошлого
     * запуска до первого тика/потока. */
    dns_lan_write_snapshot(cfg);
    /* DNAT ставим сразу после bind: datapath up проверяет, что 5399 слушает
     * именно агент, и при гонке старта правила не создаёт — DNS клиентов
     * уходил в NDM (queries=0). */
    backend_dns_lan_up(cfg);
    return 0;
}

void dns_lan_stop(void)
{
    int i;
    /* Сначала гасим свой поток (если он есть) и только потом закрываем сокеты:
     * иначе поток читал бы уже закрытые дескрипторы. */
    if (g_thr_on) {
        g_thr_stop = 1;
        if (g_wake_wr >= 0) {
            char c = 1;
            if (write(g_wake_wr, &c, 1) < 0) {
                /* труба переполнена — поток всё равно проснётся по таймауту */
            }
        }
        pthread_cancel(g_thr);
        pthread_join(g_thr, NULL);
        g_thr_on = 0;
        if (g_wake_rd >= 0)
            close(g_wake_rd);
        if (g_wake_wr >= 0)
            close(g_wake_wr);
        g_wake_rd = g_wake_wr = -1;
    }
    backend_set_yield_cb(NULL);   /* цикл больше не обязан нас обслуживать */
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
    /* dns_lan_reload() и dns_lan_poll() вызываются из одного потока (главный
     * цикл движка) — блокировок нет намеренно. Любой второй поток, трогающий
     * g_fd/g_mode/g_cfg, должен сначала переписать этот контракт. */
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
        backend_dns_lan_down(cfg);   /* иначе DNAT шлёт DNS в закрытый порт */
        slogf(SL_INFO, "dns_lan: выключен reload-ом");
    }
}

/* AY-интерфейс появляется позже старта форвардера (асинхронный HELLO).
 * Движок зовёт это раз в 5 с, пока сессия жива. Старт мог остаться в direct
 * (ay0 ещё не было) или поток форвардера мог умереть — поэтому не просто
 * переключаем режим, а перезапускаем форвардер уже с существующим ay0. */
int dns_lan_ay_ensure(const susanin_config *cfg)
{
    if (!cfg || !cfg->dns_lan || strcmp(cfg->egress_type, "ay") != 0)
        return -1;
    if (g_fd < 0)
        return -1;
    if (g_mode == DL_VIA_IFACE)
        return 0;
    if (dl_iface_open(cfg) == 0) {
        g_mode = DL_VIA_IFACE;
        slogf(SL_INFO, "dns_lan: AY-резолвер 10.23.0.1 — DNS клиентов через туннель");
        dns_lan_write_snapshot(cfg);
        backend_dns_lan_up(cfg);
        return 0;
    }
    return -1;
}

/* Никаких блокирующих ожиданий: только приём и продвижение по срокам. */
/* Поток форвардера: свой poll на слушающем сокете, сокете локального
 * резолвера, обменах с SOCKS и трубе пробуждения. Шаг 50 мс — компромисс между
 * задержкой ответа (каждый шаг обмена — RTT) и ценой пробуждений на mipsel. */
static void *dl_thread_main(void *arg)
{
    time_t last_snap = 0;

    (void)arg;
    for (;;) {
        struct pollfd pf[2 + DNS_LAN_PEND];
        int n = 0, i, rc;

        g_last_step = time(NULL);
        if (g_thr_stop)
            break;
        if (g_fd >= 0) {
            pf[n].fd = g_fd;
            pf[n].events = POLLIN;
            pf[n].revents = 0;
            n++;
        }
        if (g_wake_rd >= 0) {
            pf[n].fd = g_wake_rd;
            pf[n].events = POLLIN;
            pf[n].revents = 0;
            n++;
        }
        for (i = 0; i < DNS_LAN_PEND && n < (int)(sizeof(pf) / sizeof(pf[0])); i++) {
            if (g_pend[i].used && g_pend[i].tfd >= 0) {
                pf[n].fd = g_pend[i].tfd;
                /* POLLOUT нужен, пока есть недосланный хвост: иначе поток узнаёт
                 * о готовности сокета к записи только по таймауту 50 мс. */
                pf[n].events = POLLIN | (g_pend[i].sending ? POLLOUT : 0);
                pf[n].revents = 0;
                n++;
            }
        }
        rc = poll(pf, (nfds_t)n, DL_THREAD_TICK_MS);
        if (rc < 0 && errno != EINTR)
            break;
        if (g_thr_stop)
            break;
        if (g_wake_rd >= 0) {
            char drain[16];
            while (read(g_wake_rd, drain, sizeof(drain)) > 0)
                ;
        }
        dl_step();
        if (g_cfg) {
            time_t now = time(NULL);
            if (!last_snap || now - last_snap >= 60) {
                last_snap = now;
                dns_lan_write_snapshot(g_cfg);
            }
        }
    }
    /* Поток мог выйти по ошибке poll: возвращаем обслуживание движку, иначе
     * g_thr_on=1 навсегда и dns_lan молчит (DNS клиентов — таймаут). */
    g_thr_on = 0;
    backend_set_yield_cb(dns_lan_poll);
    return NULL;
}

/* Шаги форвардера. Вызывается либо из тика движка (dns_lan_poll), либо из
 * своего потока (dl_thread_main) — но никогда из обоих сразу: режим выбирается
 * при старте. */
static void dl_step(void)
{
    static time_t last_ay_try;
    static time_t last_ay_fail;

    if (g_fd < 0 || !g_cfg || !g_cfg->dns_lan)
        return;
    g_last_step = time(NULL);
    /* AY поднимается асинхронно, позже старта dns_lan. Если старт застал
     * «connecting», переключаемся на ay0, как только интерфейс появился; при
     * исчезновении tun — обратно в direct, чтобы DNS не уходил в мёртвый tun.
     * Состояние сессии здесь не читаем: интерфейс создаётся раньше ACK, а
     * гонка с потоком AY давала ложный «direct». */
    if (!strcmp(g_cfg->egress_type, "ay")) {
        if (g_mode == DL_VIA_DIRECT) {
            time_t now = time(NULL);
            if (!last_ay_try || now - last_ay_try >= 5) {
                last_ay_try = now;
                if (dl_iface_open(g_cfg) == 0) {
                    g_mode = DL_VIA_IFACE;
                    slogf(SL_INFO, "dns_lan: AY-интерфейс %s появился — DNS через него",
                          g_tun_name);
                } else if (!last_ay_fail || now - last_ay_fail >= 60) {
                    last_ay_fail = now;
                    slogf(SL_WARN, "dns_lan: AY-интерфейс %s не открылся: %s",
                          g_cfg->ay_iface[0] ? g_cfg->ay_iface : "ay0",
                          strerror(errno));
                }
            }
        }
    }
    dl_drain_clients();
    dl_drain_local();
    dl_drain_tunnel();
    dl_tcp_tick();
    dl_expire();
}

void dns_lan_poll(void)
{
    static time_t last_snap;

    if (g_thr_on)
        return;                 /* форвардер обслуживает свой поток */
    dl_step();
    /* Снимок для status пишем и из движка: если поток умер/не создан,
     * state-файл иначе остаётся от прошлого запуска (status врёт). */
    if (g_cfg) {
        time_t now = time(NULL);
        if (!last_snap || now - last_snap >= 60) {
            last_snap = now;
            dns_lan_write_snapshot(g_cfg);
        }
    }
}

int dns_lan_threaded(void)
{
    return g_thr_on;
}

int dns_lan_thread_stale(void)
{
    time_t last = g_last_step;

    if (!g_thr_on || !last)
        return 0;
    return time(NULL) - last > 10;
}

/* Есть ли заявки на пин. Проверка без блокировки: это только подсказка движку,
 * применять всё равно будет dns_lan_drain_pins под мьютексом. */
int dns_lan_pins_pending(void)
{
    return g_pin_rd != g_pin_wr;
}

/* Забрать до max заявок на пин. Вызывается из главного цикла. */
int dns_lan_drain_pins(char ips[][16], char names[][64], int max)
{
    int n = 0;

    if (!ips || !names || max <= 0)
        return 0;
    pthread_mutex_lock(&g_pin_mu);
    while (n < max && g_pin_rd != g_pin_wr) {
        snprintf(ips[n], 16, "%s", g_pins[g_pin_rd].ip);
        snprintf(names[n], 64, "%s", g_pins[g_pin_rd].name);
        g_pin_rd = (g_pin_rd + 1) % DL_PIN_QUEUE;
        n++;
    }
    pthread_mutex_unlock(&g_pin_mu);
    return n;
}

int dns_lan_pending(void)
{
    int i, n = 0;

    for (i = 0; i < DNS_LAN_PEND; i++)
        if (g_pend[i].used)
            n++;
    return n;
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
             g_q_tunnel, g_q_direct, g_q_fail, dns_lan_pending());
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

    if (g_thr_on)
        return 0;               /* поток сам просыпается, движку ускорять нечего */
    for (i = 0; i < DNS_LAN_PEND; i++)
        if (g_pend[i].used && g_pend[i].state == 3)
            return 1;
    return 0;
}
