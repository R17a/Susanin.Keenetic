#define _GNU_SOURCE
#include "classifier.h"
#include "backend.h"
#include "cdn.h"
#include "dns_sniff.h"
#include "health.h"
#include "profiles.h"
#include "vpn_never.h"
#include "log.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int is_udp(const ct_flow *f) { return f->l4proto == 17; }

/* Порты из learn_exclude_ports не участвуют в автообучении (типовой скан-шум
 * на 22/23/445/554 и т.п.): такие потоки пропускаем целиком. */
/* Служебные/прикладные порты, которые не учим и не заворачиваем никогда:
 * 500/4500 — IPsec (IKE/NAT-T); 8567 — UDP-мессенджер Битрикс24 (мобильный).
 * Иначе автообучение уводит IPsec/Битрикс в VPN, и они ломаются. */
static int service_port(unsigned p)
{
    /* 53/853 — DNS/DoT (никогда в VPN: иначе ломается резолв);
     * 500/4500 — IPsec (IKE/NAT-T); 8567 — UDP-мессенджер Битрикс24. */
    return p == 53 || p == 853 || p == 500 || p == 4500 || p == 8567;
}

/* Списки из конфига (learn_exclude_ports, lan_subnets, media_ports) парсятся
 * один раз и кэшируются: копирование строки + strtok на каждый поток в каждом
 * проходе были заметной статьёй расходов на слабом CPU. Кэш сбрасывается при
 * изменении исходной строки (reload конфига). */
static unsigned excl_ports[64];
static int excl_n;
static char excl_src[CFG_PATH_MAX];

static int port_excluded(const susanin_config *cfg, unsigned port)
{
    int i;
    if (service_port(port))
        return 1;
    if (!cfg->learn_exclude_ports[0])
        return 0;
    if (strcmp(excl_src, cfg->learn_exclude_ports) != 0) {
        char buf[CFG_PATH_MAX], *save = NULL, *tok;
        snprintf(excl_src, sizeof(excl_src), "%s", cfg->learn_exclude_ports);
        snprintf(buf, sizeof(buf), "%s", cfg->learn_exclude_ports);
        excl_n = 0;
        for (tok = strtok_r(buf, ",", &save); tok && excl_n < 64;
             tok = strtok_r(NULL, ",", &save)) {
            while (*tok == ' ' || *tok == '\t') tok++;
            if (*tok)
                excl_ports[excl_n++] = (unsigned)strtoul(tok, NULL, 10);
        }
    }
    for (i = 0; i < excl_n; i++)
        if (excl_ports[i] == port)
            return 1;
    return 0;
}

static int ip_in_cidr(const char *ip, const char *cidr)
{
    char c[64];
    char *slash;
    struct in_addr a, n;
    uint32_t mask, ah, nh;
    int pre;
    snprintf(c, sizeof(c), "%s", cidr);
    slash = strchr(c, '/');
    if (!slash)
        return 0;
    *slash = '\0';
    pre = atoi(slash + 1);
    /* Опечатка в конфиге ("/33", отрицательный) не должна давать UB-сдвиг. */
    if (pre < 0)
        pre = 0;
    if (pre > 32)
        pre = 32;
    if (inet_pton(AF_INET, ip, &a) != 1 || inet_pton(AF_INET, c, &n) != 1)
        return 0;
    mask = pre == 0 ? 0 : (0xffffffffu << (32 - pre));
    ah = ntohl(a.s_addr);
    nh = ntohl(n.s_addr);
    return (ah & mask) == (nh & mask);
}

/* LAN-подсети парами (net,mask): проверка потока — пара целочисленных
 * операций вместо копирования строки, strtok и двух inet_pton. */
typedef struct { uint32_t net, mask; } cidr4;
static cidr4 lan_c[16];
static int lan_cn;
static char lan_src[CFG_PATH_MAX];

static void lan_cache_sync(const susanin_config *cfg)
{
    char buf[CFG_PATH_MAX], *save = NULL, *tok;
    if (!strcmp(lan_src, cfg->lan_subnets))
        return;
    snprintf(lan_src, sizeof(lan_src), "%s", cfg->lan_subnets);
    snprintf(buf, sizeof(buf), "%s", cfg->lan_subnets);
    lan_cn = 0;
    for (tok = strtok_r(buf, ",", &save); tok && lan_cn < 16;
         tok = strtok_r(NULL, ",", &save)) {
        char *slash;
        uint32_t net;
        int pre;
        while (*tok == ' ') tok++;
        slash = strchr(tok, '/');
        if (!slash)
            continue;
        *slash = '\0';
        pre = atoi(slash + 1);
        if (pre < 0) pre = 0;
        if (pre > 32) pre = 32;
        net = ct_parse4(tok);
        if (!net)
            continue;   /* не IPv4 (и 0.0.0.0 — бессмысленная LAN-подсеть) */
        lan_c[lan_cn].mask = pre == 0 ? 0u : (0xffffffffu << (32 - pre));
        lan_c[lan_cn].net = net & lan_c[lan_cn].mask;
        lan_cn++;
    }
}

static int from_lan4(const susanin_config *cfg, uint32_t src4)
{
    int i;
    if (!src4)
        return 0;   /* не IPv4: строковая версия тоже давала 0 (inet_pton) */
    lan_cache_sync(cfg);
    for (i = 0; i < lan_cn; i++)
        if ((src4 & lan_c[i].mask) == lan_c[i].net)
            return 1;
    return 0;
}

static int is_private_dst(const char *dst, int *is_private)
{
    static const char *priv[] = {
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
        "224.0.0.0/4", "240.0.0.0/4", NULL
    };
    int i;
    (void)is_private;
    for (i = 0; priv[i]; i++)
        if (ip_in_cidr(dst, priv[i]))
            return 1;
    return 0;
}

/* Тот же набор диапазонов, что в строковой is_private_dst, но бинарно:
 * проверка адреса — несколько целочисленных сравнений. a == 0 означает
 * «адрес не IPv4» — не приватный (строковая версия на IPv6 тоже давала 0). */
static const struct { uint32_t net, mask; } priv4[] = {
    { 0x00000000u, 0xff000000u },   /* 0.0.0.0/8 */
    { 0x0a000000u, 0xff000000u },   /* 10.0.0.0/8 */
    { 0x64400000u, 0xffc00000u },   /* 100.64.0.0/10 */
    { 0x7f000000u, 0xff000000u },   /* 127.0.0.0/8 */
    { 0xa9fe0000u, 0xffff0000u },   /* 169.254.0.0/16 */
    { 0xac100000u, 0xfff00000u },   /* 172.16.0.0/12 */
    { 0xc0a80000u, 0xffff0000u },   /* 192.168.0.0/16 */
    { 0xe0000000u, 0xf0000000u },   /* 224.0.0.0/4 (multicast) */
    { 0xf0000000u, 0xf0000000u },   /* 240.0.0.0/4 (reserved) */
};

static int is_private4(uint32_t a)
{
    int i;
    if (!a)
        return 0;
    for (i = 0; i < (int)(sizeof(priv4) / sizeof(priv4[0])); i++)
        if ((a & priv4[i].mask) == priv4[i].net)
            return 1;
    return 0;
}

static int ours(const ct_flow *f, const susanin_config *cfg)
{
    return f->ctmark && ((f->ctmark & cfg->mark_mask) == cfg->mark_test ||
                         (f->ctmark & cfg->mark_mask) == cfg->mark_ok);
}

/* Экспорт чистых фильтров для sweep_direct() (engine.c). */
int clf_service_port(unsigned port) { return service_port(port); }
int clf_port_excluded(const susanin_config *cfg, unsigned port)
{
    return port_excluded(cfg, port);
}
int clf_is_private_dst(const char *dst) { return is_private_dst(dst, NULL); }
int clf_ip_in_cidr(const char *ip, const char *cidr) { return ip_in_cidr(ip, cidr); }
int clf_from_lan4(const susanin_config *cfg, uint32_t src4)
{
    return from_lan4(cfg, src4);
}
int clf_is_private4(uint32_t a) { return is_private4(a); }

/* rate cache (two-sample deltas). Цепочечный хэш-индекс: rc_find раньше
 * линейно strcmp'ил до 2048 ключей на каждый активный поток раз в секунду.
 * Индекс поддерживается инкрементально (вставка/вытеснение) и пересобирается
 * после уплотнения в rc_end. Связи — «номер слота + 1», 0 = «нет». */
#define RCAP 2048
#define RCHASH 1024
typedef struct {
    char key[192];
    unsigned long op, rp, ob, rb;
    time_t t;
    int seen;
    int next;
} rslot;
static rslot rc[RCAP];
static int rc_n = 0;
static int rc_head[RCHASH];     /* бакет -> номер слота + 1, 0 = пусто */

static unsigned long rc_hash(const char *s)
{
    unsigned long h = 5381;
    for (; *s; s++)
        h = ((h << 5) + h) ^ (unsigned char)*s;
    return h;
}

static void rc_rechain(void)
{
    int i;
    for (i = 0; i < RCHASH; i++) rc_head[i] = 0;
    for (i = 0; i < rc_n; i++) {
        unsigned b = rc_hash(rc[i].key) % RCHASH;
        rc[i].next = rc_head[b];
        rc_head[b] = i + 1;
    }
}

/* Вынуть слот из цепочки его текущего ключа (перед перезаписью ключа). */
static void rc_unchain(int slot)
{
    unsigned b = rc_hash(rc[slot].key) % RCHASH;
    int prev = 0, cur = rc_head[b];
    while (cur) {
        if (cur - 1 == slot) {
            if (prev)
                rc[prev - 1].next = rc[slot].next;
            else
                rc_head[b] = rc[slot].next;
            return;
        }
        prev = cur;
        cur = rc[cur - 1].next;
    }
}

static void rc_chain(int slot)
{
    unsigned b = rc_hash(rc[slot].key) % RCHASH;
    rc[slot].next = rc_head[b];
    rc_head[b] = slot + 1;
}

static void rc_begin(void)
{
    int i;
    for (i = 0; i < rc_n; i++) rc[i].seen = 0;
}

static void rc_end(void)
{
    int i, w = 0;
    for (i = 0; i < rc_n; i++)
        if (rc[i].seen) rc[w++] = rc[i];
    rc_n = w;
    rc_rechain();   /* слоты переехали — цепочки собираем заново */
}

static rslot *rc_find(const char *key)
{
    int i = rc_head[rc_hash(key) % RCHASH];
    while (i && i <= rc_n) {
        rslot *s = &rc[i - 1];
        if (strcmp(s->key, key) == 0)
            return s;
        i = s->next;
    }
    return NULL;
}

static rslot *rc_store(const char *key, const ct_flow *f, time_t now)
{
    rslot *s;
    int slot;
    if (rc_n >= RCAP) {
        /* Кэш полон: вытесняем одну самую старую запись, а не обнуляем весь
         * кэш (иначе под нагрузкой rate-детект «слепнет» целиком). */
        int i, oldest = 0;
        for (i = 1; i < rc_n; i++)
            if (rc[i].t < rc[oldest].t)
                oldest = i;
        slot = oldest;
        rc_unchain(slot);   /* прежний ключ уходит из индекса */
    } else {
        slot = rc_n++;
    }
    s = &rc[slot];
    snprintf(s->key, sizeof(s->key), "%s", key);
    s->op = f->op; s->rp = f->rp; s->ob = f->ob; s->rb = f->rb;
    s->t = now; s->seen = 1;
    s->next = 0;
    rc_chain(slot);
    return s;
}

static void flow_key(const ct_flow *f, char *buf, size_t n)
{
    snprintf(buf, n, "%s|%s|%u|%s|%u", f->proto, f->src, f->sport, f->dst, f->dport);
}

static unsigned long udelta(unsigned long cur, unsigned long prev)
{
    return cur >= prev ? cur - prev : 0;
}

/* Полные дельты между сэмплами. 1 = есть предыдущий сэмпл. */
static int rate_delta_full(const ct_flow *f, time_t now, unsigned long *dop,
                           unsigned long *drp, unsigned long *dob,
                           unsigned long *drb)
{
    char key[192];
    rslot *s;
    flow_key(f, key, sizeof(key));
    s = rc_find(key);
    if (s) {
        *dop = udelta(f->op, s->op);
        *drp = udelta(f->rp, s->rp);
        *dob = udelta(f->ob, s->ob);
        *drb = udelta(f->rb, s->rb);
        s->op = f->op; s->rp = f->rp; s->ob = f->ob; s->rb = f->rb;
        s->seen = 1; s->t = now;
        return 1;
    }
    rc_store(key, f, now);
    return 0;
}

/* returns 1 if caller should consume origActive/replSilent (has previous sample) */
static int rate_delta(const ct_flow *f, time_t now, int *orig_active, int *repl_silent)
{
    unsigned long dop, drp, dob, drb;
    if (!rate_delta_full(f, now, &dop, &drp, &dob, &drb))
        return 0;
    *orig_active = (dop > 0);
    *repl_silent = (drp == 0);
    return 1;
}

/* Гистерезис снятия из ok: считаем подряд идущие «сбои» по адресу, чтобы не
 * дёргать один и тот же адрес (OK-CHURN) из-за одного наблюдения. */
#define OFCAP 256
struct ofslot { char ip[64]; int udp; int miss; int seen; time_t at; };
static struct ofslot of[OFCAP];
static int of_n;

/* Сводка OK-CHURN: пишем в лог не каждое событие, а раз в ~5 минут. */
static time_t oc_last = 0;
static int oc_cnt = 0;
static char oc_name[80];

static struct ofslot *of_find(const char *ip, int udp)
{
    int i;
    for (i = 0; i < of_n; i++)
        if (of[i].seen && of[i].udp == udp && strcmp(of[i].ip, ip) == 0)
            return &of[i];
    return NULL;
}

static struct ofslot *of_touch(const char *ip, int udp)
{
    struct ofslot *s = of_find(ip, udp);
    if (s) {
        s->miss++;
        s->at = time(NULL);
        return s;
    }
    if (of_n >= OFCAP) {
        /* Вытесняем одну самую старую запись, а не всю таблицу: иначе при
         * переполнении терялась история наблюдений по всем адресам. */
        int k, old = 0;
        for (k = 1; k < of_n; k++)
            if (of[k].at < of[old].at)
                old = k;
        s = &of[old];
    } else {
        s = &of[of_n++];
    }
    snprintf(s->ip, sizeof(s->ip), "%s", ip);
    s->udp = udp;
    s->miss = 1;
    s->seen = 1;
    s->at = time(NULL);
    return s;
}

static void of_forget(const char *ip, int udp)
{
    struct ofslot *s = of_find(ip, udp);
    if (s)
        s->seen = 0;
}

/* Ограничитель «проб»: не более promo_per_min новых переводов в VPN в минуту
 * (0 = без лимита). Защита от лавины ложных заворотов при агрессивном детекте. */
static int promo_ok(const susanin_config *cfg, time_t now)
{
    static time_t win = 0;
    static int cnt = 0;
    if (cfg->promo_per_min <= 0)
        return 1;
    if (!win || now - win >= 60) {
        win = now;
        cnt = 0;
    }
    if (cnt >= cfg->promo_per_min)
        return 0;
    cnt++;
    return 1;
}

/* Неудачу в test-фазе признаём не раньше этого «возраста» записи: за первый RTT
 * клиент отправляет до начального окна без ответа, и на медленном апстриме это
 * дало бы ложный cooldown. Относится к ветке ESTABLISHED (и в tproxy, и в
 * interface-режиме — экспозиция начального окна там одинаковая). */
#define TEST_FAIL_MIN_AGE 3

/* Возраст записи test в секундах (0 — возраст неизвестен: test_ttl=0 или записи
 * нет). Возраст = now − (expire − test_ttl): в фазе test запись не продлевается,
 * повторный promote блокируется candidate_ok(). */
static int test_age(const state_set *st, const susanin_config *cfg,
                    const char *addr, time_t now)
{
    time_t exp;
    if (cfg->test_ttl <= 0)
        return 0;
    exp = state_at(st, addr, now);
    if (exp <= 0)
        return 0;
    return (int)(now - (exp - cfg->test_ttl));
}

/* Бюджет прямых проб: проба блокирует цикл, поэтому не более N в минуту и не
 * более M за календарную секунду (иначе один проход встал бы на 12 с). */
#define DIRECT_PROBE_MS  1200
#define DIRECT_PROBE_MAX 10
#define DIRECT_PROBE_PER_SEC 2
#define DOK_TTL_OK     300   /* «прямой путь отвечает»: не заворачивать, с */
#define DOK_TTL_BUDGET 30    /* бюджет проб исчерпан: короткая отметка (r6:
                              * раньше 120 с «замораживали» обучение на волне
                              * фан-аута Lampa/ТВ на десятки хостов в минуту) */
#define DOK_MAX        256

/* Негативный кэш «прямой путь отвечает»: адрес не заворачиваем и повторно не
 * пробуем. Фиксированная таблица — память не растёт, персист не нужен. */
typedef struct { char ip[64]; time_t until; } dokslot;
static dokslot dok[DOK_MAX];

static int dok_has(const char *ip, time_t now)
{
    int i;
    for (i = 0; i < DOK_MAX; i++)
        if (dok[i].ip[0] && dok[i].until > now && !strcmp(dok[i].ip, ip))
            return 1;
    return 0;
}

static void dok_add(const char *ip, time_t now, int ttl)
{
    int i, slot = -1;
    time_t oldest = 0;
    for (i = 0; i < DOK_MAX; i++) {
        if (!dok[i].ip[0] || dok[i].until <= now) { slot = i; break; }
        if (slot < 0 || dok[i].until < oldest) { oldest = dok[i].until; slot = i; }
    }
    if (slot < 0)
        slot = 0;
    snprintf(dok[slot].ip, sizeof(dok[slot].ip), "%s", ip);
    dok[slot].until = now + ttl;
}

static int direct_probe_budget_ok(time_t now)
{
    static time_t win = 0;
    static int cnt = 0;
    if (!win || now - win >= 60) {
        win = now;
        cnt = 0;
    }
    if (cnt >= DIRECT_PROBE_MAX)
        return 0;
    cnt++;
    return 1;
}

static int direct_probe_sec_ok(time_t now)
{
    static time_t sec = 0;
    static int cnt = 0;
    if (sec != now) {
        sec = now;
        cnt = 0;
    }
    if (cnt >= DIRECT_PROBE_PER_SEC)
        return 0;
    cnt++;
    return 1;
}

/* L1–L6: пороги обучения (learn_strict увеличивает требования). */
static unsigned long lmin_op(const susanin_config *c)
{
    int v = c->learn_min_op > 0 ? c->learn_min_op : 1;
    return (unsigned long)(c->learn_strict ? v * 2 : v);
}

static unsigned long lmin_bytes(const susanin_config *c)
{
    int v = c->learn_min_bytes > 0 ? c->learn_min_bytes : 1;
    return (unsigned long)(c->learn_strict ? v * 2 : v);
}

static unsigned long cmin_bytes(const susanin_config *c)
{
    int v = c->confirm_min_bytes > 0 ? c->confirm_min_bytes : 1;
    return (unsigned long)(c->learn_strict ? v * 2 : v);
}

/* Подтверждения агрегации: префикс уходит в ok_net только после N РАЗНЫХ
 * адресов (aggregate_confirm). Таблица фиксированного размера — память не растёт. */
#define AG_CONF 64
#define AG_HIST 3        /* помним до 3 последних адресов префикса */
#define AG_WINDOW_S 600  /* серия подтверждений живёт 10 минут */
typedef struct { char cidr[64]; char last[AG_HIST][64]; int n; time_t at; } agslot;
static agslot ag[AG_CONF];

/* Вариант с явным порогом (frozen-наследию нужен свой, выше media/CDN). */
static int ag_confirm_n(int want, const char *cidr, const char *addr)
{
    int i, k, free_i = -1, oldest = 0;
    if (want < 1)
        want = 1;
    time_t now = time(NULL);
    for (i = 0; i < AG_CONF; i++) {
        if (ag[i].cidr[0] && !strcmp(ag[i].cidr, cidr)) {
            if (now - ag[i].at > AG_WINDOW_S) {   /* серия остыла — считаем заново */
                ag[i].n = 0;
                for (k = 0; k < AG_HIST; k++)
                    ag[i].last[k][0] = '\0';
            }
            for (k = 0; k < AG_HIST; k++)         /* повтор того же адреса не считаем */
                if (ag[i].last[k][0] && !strcmp(ag[i].last[k], addr)) {
                    ag[i].at = now;
                    return ag[i].n >= want;
                }
            for (k = AG_HIST - 1; k > 0; k--)     /* сдвигаем историю адресов */
                memcpy(ag[i].last[k], ag[i].last[k - 1], sizeof(ag[i].last[k]));
            snprintf(ag[i].last[0], sizeof(ag[i].last[0]), "%s", addr);
            ag[i].n++;
            ag[i].at = now;
            return ag[i].n >= want;
        }
        if (!ag[i].cidr[0] && free_i < 0)
            free_i = i;
        if (ag[i].at < ag[oldest].at)
            oldest = i;
    }
    i = free_i >= 0 ? free_i : oldest;   /* нет свободных — вытесняем самую старую */
    snprintf(ag[i].cidr, sizeof(ag[i].cidr), "%s", cidr);
    for (k = 0; k < AG_HIST; k++)
        ag[i].last[k][0] = '\0';
    snprintf(ag[i].last[0], sizeof(ag[i].last[0]), "%s", addr);
    ag[i].n = 1;
    ag[i].at = now;
    return want <= 1;
}

static int ag_confirm(const susanin_config *cfg, const char *cidr, const char *addr)
{
    return ag_confirm_n(cfg->aggregate_confirm > 1 ? cfg->aggregate_confirm : 1,
                        cidr, addr);
}

/* r4.2: ТСПУ замораживает не адреса, а целые
 * сети хостингов (Hetzner/OVH/DO/Vultr/M247...). Если N РАЗНЫХ IP одного
 * префикса подтвердились как «нужен VPN» — заморозка сетевая: заносим префикс
 * в susanin_ok_net, новые IP сети уедут в VPN сразу, без проб и бюджета.
 * vpn_never приоритетнее (соседи «напрямую» не уезжают), как в cdn/media. */
static void frozen_net_aggregate(classifier_ctx *ctx, const ct_flow *f)
{
    const susanin_config *cfg = ctx->cfg;
    struct in_addr a, b;
    char ab[INET_ADDRSTRLEN];
    char cidr[64];
    uint32_t ah, mask;
    int pre, want;
    time_t now = time(NULL);
    if (!cfg->frozen_net_enabled)
        return;
    if (backend_set_test(cfg, "susanin_never", f->dst) == 0) {
        slogf(SL_DEBUG, "FROZEN-NET: не агрегирую %s — адрес в vpn_never", f->dst);
        return;
    }
    if (inet_pton(AF_INET, f->dst, &a) != 1)
        return;
    pre = cfg->frozen_net_prefix > 0 ? cfg->frozen_net_prefix : 24;
    if (pre < 8)
        pre = 8;
    if (pre > 32)
        pre = 32;
    ah = ntohl(a.s_addr);
    mask = pre == 0 ? 0 : (0xffffffffu << (32 - pre));
    b.s_addr = htonl(ah & mask);
    if (!inet_ntop(AF_INET, &b, ab, sizeof(ab)))
        return;
    snprintf(cidr, sizeof(cidr), "%s/%d", ab, pre);
    want = cfg->frozen_net_min_ips >= 1 ? cfg->frozen_net_min_ips : 3;
    if (!ag_confirm_n(want, cidr, f->dst)) {
        slogf(SL_DEBUG, "FROZEN-NET: %s копит подтверждения (нужно %d разных IP)",
              cidr, want);
        return;
    }
    if (state_has(&ctx->st->net, cidr, now)) {
        backend_net_add(cfg, cidr, cfg->frozen_net_ttl);
        state_touch(&ctx->st->net, cidr, now, cfg->frozen_net_ttl);
        return;
    }
    backend_net_add(cfg, cidr, cfg->frozen_net_ttl);
    state_touch(&ctx->st->net, cidr, now, cfg->frozen_net_ttl);
    slogf(SL_INFO, "FROZEN-NET: %s -> vpn (%d подтверждений, последний %s, ttl=%ds)",
          cidr, want, f->dst, cfg->frozen_net_ttl);
}

/* Быстрая агрегация на фазе TEST. Отдельная таблица подтверждений (не общая
 * с ag[]): окно и пороги отличаются от frozen/CDN/media, а смешение счётчиков
 * приводило бы к перекрёстному срабатыванию (чужой want достигается раньше). */
#define TN_CONF 64
#define TN_HIST 3        /* помним до 3 последних адресов префикса */
typedef struct { char cidr[64]; char last[TN_HIST][64]; int n; time_t at; } tnslot;
static tnslot tn[TN_CONF];

static int tn_confirm(int want, int win_s, const char *cidr, const char *addr)
{
    int i, k, free_i = -1, oldest = 0;
    time_t now = time(NULL);
    if (want < 1)
        want = 1;
    for (i = 0; i < TN_CONF; i++) {
        if (tn[i].cidr[0] && !strcmp(tn[i].cidr, cidr)) {
            if (now - tn[i].at > win_s) {   /* серия остыла — считаем заново */
                tn[i].n = 0;
                for (k = 0; k < TN_HIST; k++)
                    tn[i].last[k][0] = '\0';
            }
            for (k = 0; k < TN_HIST; k++)   /* повтор того же адреса не считаем */
                if (tn[i].last[k][0] && !strcmp(tn[i].last[k], addr)) {
                    tn[i].at = now;
                    return tn[i].n >= want;
                }
            for (k = TN_HIST - 1; k > 0; k--)     /* сдвигаем историю адресов */
                memcpy(tn[i].last[k], tn[i].last[k - 1], sizeof(tn[i].last[k]));
            snprintf(tn[i].last[0], sizeof(tn[i].last[0]), "%s", addr);
            tn[i].n++;
            tn[i].at = now;
            return tn[i].n >= want;
        }
        if (!tn[i].cidr[0] && free_i < 0)
            free_i = i;
        if (tn[i].at < tn[oldest].at)
            oldest = i;
    }
    i = free_i >= 0 ? free_i : oldest;   /* нет свободных — вытесняем старую */
    snprintf(tn[i].cidr, sizeof(tn[i].cidr), "%s", cidr);
    for (k = 0; k < TN_HIST; k++)
        tn[i].last[k][0] = '\0';
    snprintf(tn[i].last[0], sizeof(tn[i].last[0]), "%s", addr);
    tn[i].n = 1;
    tn[i].at = now;
    return want <= 1;
}

/* Фан-аут источника (плеер/IPTV-плейлист, сайт на целом /24 хостинга) бьёт
 * сразу по десяткам хостов одной сети; при поадресном обучении каждый ждёт
 * собственного CONFIRMED, и плейлист «прокашивается» медленно. Здесь:
 * test_net_min_ips РАЗНЫХ IP одного префикса оказались в test за
 * test_net_window секунд -> префикс пинится в susanin_ok_net на короткий
 * test_net_ttl, и следующие соединения сети идут в VPN с первого пакета.
 * Короткий TTL ограничивает радиус вреда ложного срабатывания; vpn_never и
 * ru-guard для адреса-триггера уже проверены на входе promote_test, а перед
 * самим пином адрес дополнительно проверяется в ipset susanin_never. */
static void test_net_aggregate(classifier_ctx *ctx, const ct_flow *f, time_t now)
{
    const susanin_config *cfg = ctx->cfg;
    struct in_addr b;
    char ab[INET_ADDRSTRLEN];
    char cidr[64];
    uint32_t mask;
    int pre, want, win, ttl;
    if (!cfg->test_net_enabled || !f->dst4)
        return;
    pre = cfg->test_net_prefix > 0 ? cfg->test_net_prefix : 24;
    if (pre < 8)
        pre = 8;
    if (pre > 32)
        pre = 32;
    mask = 0xffffffffu << (32 - pre);
    b.s_addr = htonl(f->dst4 & mask);
    if (!inet_ntop(AF_INET, &b, ab, sizeof(ab)))
        return;
    snprintf(cidr, sizeof(cidr), "%s/%d", ab, pre);
    /* Префикс уже запинен (frozen/CDN/media или более ранний test-net). */
    if (state_has(&ctx->st->net, cidr, now))
        return;
    want = cfg->test_net_min_ips >= 1 ? cfg->test_net_min_ips : 2;
    win = cfg->test_net_window > 0 ? cfg->test_net_window : 60;
    if (!tn_confirm(want, win, cidr, f->dst)) {
        slogf(SL_DEBUG, "TEST-NET: %s копит подтверждения (нужно %d разных IP за %d с)",
              cidr, want, win);
        return;
    }
    /* ipset-проверка (fork) — только в момент агрегации, не на каждый промоушен. */
    if (backend_set_test(cfg, "susanin_never", f->dst) == 0) {
        slogf(SL_DEBUG, "TEST-NET: не агрегирую %s — адрес в vpn_never", f->dst);
        return;
    }
    ttl = cfg->test_net_ttl > 0 ? cfg->test_net_ttl : 600;
    backend_net_add(cfg, cidr, ttl);
    state_touch(&ctx->st->net, cidr, now, ttl);
    slogf(SL_INFO, "TEST-NET: %s -> vpn (%d IP в test за %d с, последний %s, ttl=%ds)",
          cidr, want, win, f->dst, ttl);
}

/* C1/C4: при подтверждении адреса из CDN-диапазона закрепить ближайший префикс
 * CDN в susanin_ok_net (с TTL) — чтобы следующие edge-и шли в VPN сразу. */
static void cdn_aggregate(classifier_ctx *ctx, const ct_flow *f)
{
    const susanin_config *cfg = ctx->cfg;
    char cidr[64];
    if (!cfg->cdn_prefix_learn)
        return;
    if (!cdn_match(cfg, f->dst, cidr, sizeof(cidr)))
        return;
    /* Не тянем префикс, если сам адрес — из vpn_never (иначе соседи по /24,
     * которые тоже «прямые», уедут в VPN). vpn_never имеет приоритет. */
    if (backend_set_test(cfg, "susanin_never", f->dst) == 0) {
        slogf(SL_DEBUG, "CDN: не агрегирую %s — адрес в vpn_never", f->dst);
        return;
    }
    if (!ag_confirm(cfg, cidr, f->dst)) {
        slogf(SL_DEBUG, "CDN: %s копит подтверждения (нужно %d разных адресов)",
              cidr, cfg->aggregate_confirm);
        return;
    }
    /* Префикс уже изучен: продлеваем TTL и в ipset, и в state (state_touch
     * создаёт запись или продлевает существующую). */
    if (state_has(&ctx->st->net, cidr, time(NULL))) {
        backend_net_add(cfg, cidr, cfg->cdn_prefix_ttl);
        state_touch(&ctx->st->net, cidr, time(NULL), cfg->cdn_prefix_ttl);
        return;
    }
    backend_net_add(cfg, cidr, cfg->cdn_prefix_ttl);
    /* В state — чтобы префикс не терялся при re-provision/fail-open. */
    state_touch(&ctx->st->net, cidr, time(NULL), cfg->cdn_prefix_ttl);
    slogf(SL_INFO, "CDN: %s -> ok (reason=CONFIRMED %s), ttl=%ds",
          cidr, f->dst, cfg->cdn_prefix_ttl);
}

/* M1: media-класс (IPTV/видео). Детект по форме потока и агрегация префикса в
 * susanin_ok_net (VPN): достаточно один раз увидеть крупный асимметричный поток,
 * чтобы последующие шли в VPN с первого пакета (userspace, без FASTNAT). */
static unsigned media_p[32];
static int media_pn;
static char media_src[128];

static int media_port(const susanin_config *cfg, unsigned p)
{
    int i;
    if (!cfg->media_ports[0])
        return 0;
    if (strcmp(media_src, cfg->media_ports) != 0) {
        char buf[128], *save = NULL, *tok;
        snprintf(media_src, sizeof(media_src), "%s", cfg->media_ports);
        snprintf(buf, sizeof(buf), "%s", cfg->media_ports);
        media_pn = 0;
        for (tok = strtok_r(buf, ",", &save); tok && media_pn < 32;
             tok = strtok_r(NULL, ",", &save)) {
            while (*tok == ' ' || *tok == '\t') tok++;
            if (*tok)
                media_p[media_pn++] = (unsigned)strtoul(tok, NULL, 10);
        }
    }
    for (i = 0; i < media_pn; i++)
        if (media_p[i] == p)
            return 1;
    return 0;
}

/* M2: пороги media_min_rate/media_min_age раньше были объявлены и печатались,
 * но в коде НЕ проверялись: «медиа» считалась любая загрузка на портах
 * media_ports с ответом >= media_min_bytes, и два адреса утаскивали в VPN всю
 * /24 (HTML шёл, стили/картинки — нет).
 * Здесь короткая таблица кандидатов: агрегируем только если поток прожил
 * media_min_age секунд и держит скорость не ниже media_min_rate. */
#define MCAP 256
typedef struct {
    char key[192];
    time_t first, last;
    unsigned long rb;
} mslot;
static mslot mc[MCAP];
static int mc_n = 0;

static mslot *mc_find(const char *key)
{
    int i;
    for (i = 0; i < mc_n; i++)
        if (strcmp(mc[i].key, key) == 0)
            return &mc[i];
    return NULL;
}

static mslot *mc_store(const char *key, time_t now, unsigned long rb)
{
    mslot *s;
    if (mc_n >= MCAP) {
        int i, oldest = 0;
        for (i = 1; i < mc_n; i++)
            if (mc[i].last < mc[oldest].last)
                oldest = i;
        s = &mc[oldest];
    } else {
        s = &mc[mc_n++];
    }
    snprintf(s->key, sizeof(s->key), "%s", key);
    s->first = now;
    s->last = now;
    s->rb = rb;
    return s;
}

/* 1 = возраст и скорость подтверждены (можно агрегировать). Пороги выключены —
 * сразу 1 (поведение как до правки). */
static int media_quorum(const susanin_config *cfg, const ct_flow *f, time_t now)
{
    char key[192];
    mslot *s;
    long age, dt;
    unsigned long rate;
    if (cfg->media_min_age <= 0 && cfg->media_min_rate <= 0)
        return 1;
    flow_key(f, key, sizeof(key));
    s = mc_find(key);
    if (s && now - s->last > 300) {
        /* Запись «протухла» (поток не наблюдался >5 мин): возраст и скорость по
         * такому разрыву недостоверны — считаем кандидата заново. */
        s->first = now;
        s->last = now;
        s->rb = f->rb;
        return 0;
    }
    if (!s) {
        mc_store(key, now, f->rb);
        return 0;
    }
    age = (long)(now - s->first);
    dt = (long)(now - s->last);
    if (dt < 1)
        dt = 1;
    rate = udelta(f->rb, s->rb) / (unsigned long)dt;
    s->last = now;
    s->rb = f->rb;
    if (age < (long)cfg->media_min_age)
        return 0;
    if (cfg->media_min_rate > 0 && rate < (unsigned long)cfg->media_min_rate)
        return 0;
    return 1;
}

static void media_aggregate(classifier_ctx *ctx, const ct_flow *f)
{
    const susanin_config *cfg = ctx->cfg;
    struct in_addr a, b;
    char ab[INET_ADDRSTRLEN];
    char cidr[64];
    uint32_t ah, mask;
    int pre;
    if (!cfg->media_enabled)
        return;
    if (!media_port(cfg, f->dport))
        return;
    if (f->rb < (unsigned long)cfg->media_min_bytes)
        return;
    if (f->ob > 0 && f->rb < (unsigned long)cfg->media_ratio * f->ob)
        return;
    /* Пороги «настоящего медиа»: возраст и устойчивая скорость (см. выше). */
    if (!media_quorum(cfg, f, time(NULL))) {
        slogf(SL_DEBUG, "MEDIA: %s ждёт возраст/скорость (age>=%ds, rate>=%d B/s)",
              f->dst, cfg->media_min_age, cfg->media_min_rate);
        return;
    }
    /* vpn_never приоритетнее: иначе адрес из «напрямую» уедет в VPN вместе с
     * соседями по /24 (тот же guard, что в cdn_aggregate()). */
    if (backend_set_test(cfg, "susanin_never", f->dst) == 0) {
        slogf(SL_DEBUG, "MEDIA: не агрегирую %s — адрес в vpn_never", f->dst);
        return;
    }
    if (inet_pton(AF_INET, f->dst, &a) != 1)
        return;
    pre = cfg->media_prefix_max > 0 ? cfg->media_prefix_max : 24;
    if (pre > 32)
        pre = 32;
    ah = ntohl(a.s_addr);
    mask = pre == 0 ? 0 : (0xffffffffu << (32 - pre));
    b.s_addr = htonl(ah & mask);
    if (!inet_ntop(AF_INET, &b, ab, sizeof(ab)))
        return;
    snprintf(cidr, sizeof(cidr), "%s/%d", ab, pre);
    if (!ag_confirm(cfg, cidr, f->dst)) {
        slogf(SL_DEBUG, "MEDIA: %s копит подтверждения", cidr);
        return;
    }
    if (state_has(&ctx->st->net, cidr, time(NULL))) {
        backend_net_add(cfg, cidr, cfg->media_ttl);   /* уже изучен: продлить TTL */
        state_touch(&ctx->st->net, cidr, time(NULL), cfg->media_ttl);
        return;
    }
    backend_net_add(cfg, cidr, cfg->media_ttl);
    state_touch(&ctx->st->net, cidr, time(NULL), cfg->media_ttl);
    slogf(SL_INFO, "MEDIA: %s -> vpn из %s (rb=%lu, ob=%lu)", cidr, f->src,
          (unsigned long)f->rb, (unsigned long)f->ob);
}

/* Порт цели для port-aware режима: при port_aware=0 всегда 0 (обычные наборы
 * hash:ip), при 1 — dport потока (наборы hash:ip,port). */
static int flow_port(const susanin_config *cfg, const ct_flow *f)
{
    return cfg->port_aware ? (int)f->dport : 0;
}

/* Ключ состояния для потока: пара ip:порт в port-aware режиме, иначе адрес.
 * Наборы never/direct/net остаются по адресу — там ключ берётся как f->dst. */
static const char *pair_key(char *buf, size_t n, const susanin_config *cfg,
                            const ct_flow *f)
{
    state_key(buf, n, f->dst, flow_port(cfg, f));
    return buf;
}

/* Пропуск обучения — INFO, но не чаще раза в 10 минут на адрес. С r7.4a
 * виден и LAN-источник («кто запросил») — без него диагностика ТВ/приложений
 * вслепую. Таблица на 16 адресов: при волне пропусков (например, «бюджет проб
 * исчерпан» на фан-ауте источника) адреса чередуются, и с одним «последним»
 * слотом строка писалась бы каждый проход — по сути каждую секунду. */
#define SKIP_SLOTS 16
static void skip_note(const char *src, const char *ip, unsigned port,
                      time_t now, const char *why)
{
    static char last_ip[SKIP_SLOTS][64];
    static time_t last_at[SKIP_SLOTS];
    static int sn_next;
    int i, hit = -1, oldest = 0;
    for (i = 0; i < SKIP_SLOTS; i++) {
        if (!strcmp(last_ip[i], ip)) { hit = i; break; }
        if (last_at[i] < last_at[oldest]) oldest = i;
    }
    if (hit < 0)
        hit = (last_at[oldest] && now - last_at[oldest] < 600)
                  ? sn_next   /* все слоты свежие — пишем кругом */
                  : oldest;   /* есть протухший — переиспользуем его */
    else if (now - last_at[hit] < 600)
        return;
    sn_next = (hit + 1) % SKIP_SLOTS;
    snprintf(last_ip[hit], sizeof(last_ip[hit]), "%.63s", ip);
    last_at[hit] = now;
    slogf(SL_INFO, "AUTO-SUSANIN: skip %s -> %s:%u (%s)", src, ip, port, why);
}

static void promote_test(classifier_ctx *ctx, const ct_flow *f, time_t now,
                         const char *stage, const char *reason)
{
    int udp = is_udp(f);
    const susanin_config *cfg = ctx->cfg;
    char kf[64];
    pair_key(kf, sizeof(kf), cfg, f);
    int syn = !strcmp(reason, "TCP-SYN");
    /* Адрес СЕЙЧАС в vpn_never — он должен идти напрямую: не учим (иначе
     * vn_refresh/ipset и наш state расходятся, и sweep_direct рвёт его потоки).
     * Учитываем и список vpn_never, и пины DNS-снифинга (st.never). */
    if (vn_has(f->dst) || state_has(&ctx->st->never, f->dst, now)) {
        skip_note(f->src, f->dst, f->dport, now, "vpn_never");
        return;
    }
    /* Не учим в VPN адрес, недавно бывший в vpn_never: он должен идти напрямую,
     * иначе возможен «прыжок» direct <-> VPN (план п.8.3). Осознанно удалённые
     * из списка записи кулдаун НЕ получают (см. doms_reconcile). */
    if (vn_is_recently_never(f->dst, now)) {
        skip_note(f->src, f->dst, f->dport, now, "recently vpn_never");
        return;
    }
    /* r5.2 RU-guard: российские домены в VPN автоматически НЕ заворачиваем.
     * Антифрод банков/маркетплейсов/почтовых сервисов видит чужой выход и
     * рвёт соединение ещё на TCP. ТСПУ внутреннее не блокирует — бенефита от туннеля
     * нет, один вред. Ручной vpn_always сильнее: его пины сюда не приходят.
     * Без dns_sniff домен неизвестен — не мешаем обучению. */
    if (cfg->ru_guard) {
        char rgd[DNS_DOMAIN_MAX];
        rgd[0] = '\0';
        if (dns_sniff_domain_of(f->dst, rgd, sizeof(rgd)) && rgd[0] &&
            dns_sniff_is_ru_domain(cfg, rgd)) {
            skip_note(f->src, f->dst, f->dport, now, "ru-guard");
            return;
        }
    }
    /* Прямая проба — только для «SYN ушёл без ответа»: там свежий connect
     * информативен. Для DPI-RST/TCP-CLOSE/«тишины» проба бесполезна и вредна:
     * рукопожатие проходит (блокировка по SNI/данным — уже после connect), и мы
     * получили бы ложное «прямо ок», не завернув именно тот трафик, что нужно.
     * Негативный кэш тоже относится только к этому случаю: он не должен
     * запрещать обучение по сигналам SNI (DPI-RST/CLOSE). */
    if (f->l4proto == 6 && f->dport > 0 && syn) {
        if (dok_has(f->dst, now)) {
            skip_note(f->src, f->dst, f->dport, now, "недавно проверено: прямой жив");
            return;
        }
        if (!direct_probe_budget_ok(now)) {
            /* Бюджет проб исчерпан: осознанно НЕ заворачиваем (короткая отметка),
             * иначе защита отключалась бы ровно под нагрузкой. */
            dok_add(f->dst, now, DOK_TTL_BUDGET);
            skip_note(f->src, f->dst, f->dport, now, "бюджет проб исчерпан");
            return;
        }
        if (!direct_probe_sec_ok(now))
            return;   /* лимит на секунду: решим в следующий проход, не заворачиваем */
        if (health_probe_tcp_direct(f->dst, f->dport, DIRECT_PROBE_MS)) {
            dok_add(f->dst, now, DOK_TTL_OK);
            slogf(SL_INFO, "AUTO-SUSANIN: %s skip %s -> %s:%u (прямой путь отвечает)",
                  stage, f->src, f->dst, f->dport);
            return;
        }
    }
    /* D1: снимаем «мягкое прямо» (DIRECT_PREF), иначе RETURN в цепочке не даст
     * адресу уйти в VPN, когда прямой путь снова деградировал. */
    backend_set_del(cfg, "susanin_direct", f->dst);
    state_remove(&ctx->st->direct, f->dst);
    if (!promo_ok(cfg, now))
        return;
    state_add(st_test(ctx->st, udp), kf, now, cfg->test_ttl, 0);
    state_remove(st_watch(ctx->st, udp), kf);
    backend_ipset_add_port(cfg, udp, 0, f->dst, flow_port(cfg, f), cfg->test_ttl);
    /* r5.3: домен в событии обучения — «почему этот IP уехал» читается из
     * лога без why-разбора (sniffer знает, кому адрес принадлежал). */
    {
        char dm[DNS_DOMAIN_MAX];
        dm[0] = '\0';
        dns_sniff_domain_of(f->dst, dm, sizeof(dm));
        if (dm[0])
            slogf(SL_INFO, "AUTO-SUSANIN: %s %s %s -> %s:%u (%s)",
                  stage, reason, f->src, f->dst, f->dport, dm);
        else
            slogf(SL_INFO, "AUTO-SUSANIN: %s %s %s -> %s:%u",
                  stage, reason, f->src, f->dst, f->dport);
    }
    /* Пока адрес копит подтверждения, фан-аут источника бьёт по соседним IP:
     * несколько разных адресов одной сети в test — короткий пин префикса,
     * и следующие соединения сети не ждут собственного CONFIRMED. */
    test_net_aggregate(ctx, f, now);
    backend_ct_delete(f);
}

static int candidate_ok(const classifier_ctx *ctx, const ct_flow *f, time_t now)
{
    int udp = is_udp(f);
    char kf[64];
    pair_key(kf, sizeof(kf), ctx->cfg, f);
    return !state_has(st_ok(ctx->st, udp), kf, now) &&
           !state_has(st_test(ctx->st, udp), kf, now) &&
           !state_has(st_cool(ctx->st, udp), kf, now);
}

void clr_fast(classifier_ctx *ctx, const ct_flow *flows, int n, time_t now)
{
    const susanin_config *cfg = ctx->cfg;
    int i;
    for (i = 0; i < n; i++) {
        const ct_flow *f = &flows[i];
        if (f->l4proto != 6 && f->l4proto != 17) continue;
        if (f->ctmark != 0 || ours(f, cfg)) continue;
        if (!from_lan4(cfg, f->src4)) continue;
        if (is_private4(f->dst4)) continue;
        if (port_excluded(cfg, f->dport) || port_excluded(cfg, f->sport)) continue;
        if (!candidate_ok(ctx, f, now)) continue;

        if (f->l4proto == 6) {
            if (strcmp(f->tcp_state, "SYN_SENT") == 0 && f->op >= (unsigned long)cfg->fast_syn_min_op && f->rp == 0)
                promote_test(ctx, f, now, "FAST", "TCP-SYN");
            else if (strcmp(f->tcp_state, "CLOSE") == 0 && f->op >= lmin_op(cfg) &&
                     f->ob >= lmin_bytes(cfg) && f->rp == 0 && f->rb < 128)
                promote_test(ctx, f, now, "FAST", "TCP-CLOSE");
            else if (strcmp(f->tcp_state, "CLOSE") == 0 && f->rp >= 5 &&
                     f->rb >= 2048 && f->rb <= 98304 &&
                     f->ob >= 16384 && f->ob >= 2 * f->rb)
                /* r4.1: ТСПУ-заморозка — соединение живое,
                 * первые ~16-33 КБ (25 пакетов) прошли, дальше поток молча
                 * встал в обе стороны. Клиент захлебнулся ретрансмитами:
                 * sent >= 2x от полученного. Обычный TCP-CLOSE (rb<128) тут
                 * слеп: ответ-то был, просто оборвался на пороге. */
                promote_test(ctx, f, now, "FAST", "TCP-FREEZE");
            else if (f->dport == 443 && f->ob >= lmin_bytes(cfg) && f->rb < 128 &&
                     f->rp <= 1 && strcmp(f->tcp_state, "CLOSE") == 0)
                /* DPI/ТСПУ по SNI: TCP-рукопожатие прошло и отправлен ClientHello
                 * (ob растёт), но ответа нет (rb<128) и соединение сброшено.
                 * Обычные FAST-SYN/FAST-CLOSE это не ловят: SYN-ACK уже был
                 * (rp=1), поэтому срабатывает только этот сигнал. */
                promote_test(ctx, f, now, "FAST", "DPI-RST");
            else if (f->dport == 443 && f->ob >= lmin_bytes(cfg) && f->rb < 128 &&
                     f->rp <= 1 && strcmp(f->tcp_state, "ESTABLISHED") == 0)
                /* Post-handshake «тишина» по SNI: рукопожатие прошло (rp>=1),
                 * ClientHello отправлен (ob растёт), данных нет (rb<128), но
                 * соединение ещё ESTABLISHED (ТСПУ держит тишину). Ловим на FAST,
                 * не дожидаясь SOFT. */
                promote_test(ctx, f, now, "FAST", "DPI-STALL");
            else if (strcmp(f->tcp_state, "CLOSE") == 0 && f->rp >= 1 &&
                     f->rb < 128 && f->ob >= lmin_bytes(cfg) &&
                     f->op >= lmin_op(cfg))
                /* r6: плеер закрывает соединение по
                 * таймауту (~5 с): handshake прошёл, запрос отправлен, ответа
                 * НЕТ. TCP-CLOSE требует rp==0, DPI-RST — только 443; висячие
                 * HTTP-источники на замороженных сетях (порт 80!) не ловились
                 * вообще. Плюс direct-проба (после 0.4.4) помечает такие хосты
                 * «прямой жив» по успешному connect — CLOSE-EMPTY её не
                 * слушает и учит адрес дальше. */
                promote_test(ctx, f, now, "FAST", "TCP-CLOSE-EMPTY");
        } else if (f->l4proto == 17) {
            if (f->dport == 443 && f->op >= (cfg->learn_strict ? 8UL : 6UL) && f->rp == 0)
                promote_test(ctx, f, now, "FAST", "QUIC");
        }
    }
}

void clr_soft(classifier_ctx *ctx, const ct_flow *flows, int n, time_t now)
{
    const susanin_config *cfg = ctx->cfg;
    int i;
    rc_begin();
    for (i = 0; i < n; i++) {
        const ct_flow *f = &flows[i];
        if (f->l4proto != 6 && f->l4proto != 17) continue;
        if (f->ctmark != 0 || ours(f, cfg)) continue;
        if (!from_lan4(cfg, f->src4)) continue;
        if (is_private4(f->dst4)) continue;

        /* M1: media (IPTV/видео) — детект по форме потока, агрегация в VPN. */
        if ((f->l4proto == 6 && strcmp(f->tcp_state, "ESTABLISHED") == 0) ||
            f->l4proto == 17)
            media_aggregate(ctx, f);

        if (f->l4proto == 6 && strcmp(f->tcp_state, "ESTABLISHED") == 0) {
            if (f->op >= lmin_op(cfg) && f->ob >= lmin_bytes(cfg) &&
                f->rp <= 1 && f->rb < 128) {
                if (candidate_ok(ctx, f, now))
                    promote_test(ctx, f, now, "SOFT", "TCP-STALL");
                continue;
            }
            /* Late-stall для HTTPS: ответы есть, но объём мизерный — троттлинг. */
            if (f->dport == 443 && f->op >= lmin_op(cfg) &&
                f->ob >= lmin_bytes(cfg) && f->rp > 0 && f->rb < 256) {
                if (candidate_ok(ctx, f, now))
                    promote_test(ctx, f, now, "SOFT", "TCP-STALL-443");
                continue;
            }
            if (f->op >= lmin_op(cfg) && f->rp > 0) {
                unsigned long dop, drp, dob, drb;
                if (rate_delta_full(f, now, &dop, &drp, &dob, &drb)) {
                    if (dop > 0 && drp == 0) {
                        /* orig active, reply silent: watch -> late-stall.
                         * Ключ тот же, что у state/pair (ip:порт в port-aware),
                         * иначе снятие watch по паре не находит запись. */
                        char wk0[64];
                        pair_key(wk0, sizeof(wk0), cfg, f);
                        if (!state_has(st_watch(ctx->st, 0), wk0, now)) {
                            if (candidate_ok(ctx, f, now))
                                state_add(st_watch(ctx->st, 0), wk0, now, cfg->watch_ttl, 0);
                        } else {
                            time_t at = state_at(st_watch(ctx->st, 0), wk0, now);
                            if (at && (int)(at - now) <= cfg->watch_retry_below) {
                                if (candidate_ok(ctx, f, now)) {
                                    state_remove(st_watch(ctx->st, 0), wk0);
                                    promote_test(ctx, f, now, "SOFT", "TCP-LATE-STALL");
                                }
                            }
                        }
                    } else if (dop > 0 && drp > 0 && drb < 256 &&
                               dob >= lmin_bytes(cfg)) {
                        /* C1: starvation — поток жив, но ответ идёт «по капле»
                         * (ТСПУ шейпит, а не рвёт). Для CDN — немедленный
                         * promote. Для прочих сетей (r4.1, заморозка хостингов) — строгая форма (>=16 КБ отправлено за
                         * окно, <128 байт получено) и подтверждение через watch,
                         * как late-stall: второе окно подряд -> VPN. */
                        char cidr[64];
                        int is_cdn = cdn_match(cfg, f->dst, cidr, sizeof(cidr));
                        if (is_cdn && candidate_ok(ctx, f, now)) {
                            promote_test(ctx, f, now, "SOFT", "CDN-STARVATION");
                        } else if (!is_cdn && drb < 128 && dob >= 16384UL) {
                            char wk2[64];
                            pair_key(wk2, sizeof(wk2), cfg, f);
                            if (!state_has(st_watch(ctx->st, 0), wk2, now)) {
                                if (candidate_ok(ctx, f, now))
                                    state_add(st_watch(ctx->st, 0), wk2, now, cfg->watch_ttl, 0);
                            } else {
                                time_t at = state_at(st_watch(ctx->st, 0), wk2, now);
                                if (at && (int)(at - now) <= cfg->watch_retry_below) {
                                    if (candidate_ok(ctx, f, now)) {
                                        state_remove(st_watch(ctx->st, 0), wk2);
                                        promote_test(ctx, f, now, "SOFT", "TCP-STARVE");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else if (f->l4proto == 17) {
            if (!f->has_reply) {
                /* Порог UDP-обучения настраивается (udp_min_op, по умолчанию 3).
                 * Прежние 12 были недостижимы на практике: голосовой хендшейк
                 * (Discord RTC) — это 3 echo-пакета с нового локального порта,
                 * после чего клиент сдаётся и заводит следующий сокет. В итоге
                 * адрес голосового сервера не попадал в susanin_test_udp, поток
                 * шёл напрямую и «маршрут не строился». */
                unsigned long umin = (cfg->udp_min_op > 0)
                                         ? (unsigned long)cfg->udp_min_op : 12UL;
                if (f->dport != 443 && f->dport != 53 && f->dport != 67 &&
                    f->dport != 68 && f->dport != 123 &&
                    !port_excluded(cfg, f->dport) &&
                    f->op >= umin && f->rp == 0) {
                    if (candidate_ok(ctx, f, now))
                        promote_test(ctx, f, now, "SOFT", "UDP");
                }
            } else if (f->dport == 443 && f->op >= 8) {
                int oa, rs;
                if (rate_delta(f, now, &oa, &rs) && oa && rs) {
                    char wk1[64];
                    pair_key(wk1, sizeof(wk1), cfg, f);
                    if (!state_has(st_watch(ctx->st, 1), wk1, now)) {
                        if (candidate_ok(ctx, f, now))
                            state_add(st_watch(ctx->st, 1), wk1, now, cfg->watch_ttl, 0);
                    } else {
                        time_t at = state_at(st_watch(ctx->st, 1), wk1, now);
                        if (at && (int)(at - now) <= cfg->watch_retry_below) {
                            if (candidate_ok(ctx, f, now)) {
                                state_remove(st_watch(ctx->st, 1), wk1);
                                promote_test(ctx, f, now, "SOFT", "QUIC-LATE-STALL");
                            }
                        }
                    }
                }
            }
        }
    }
    rc_end();
}

void clr_judge(classifier_ctx *ctx, const ct_flow *flows, int n, time_t now)
{
    const susanin_config *cfg = ctx->cfg;
    int i;
    for (i = 0; i < n; i++) {
        const ct_flow *f = &flows[i];
        int udp;
        int good, failed, healthy = 0;
        char kf[64];
        pair_key(kf, sizeof(kf), cfg, f);
        if (f->l4proto != 6 && f->l4proto != 17) continue;
        if (!from_lan4(cfg, f->src4)) continue;
        udp = is_udp(f);

        if (!ours(f, cfg)) continue;

        if ((f->ctmark & cfg->mark_mask) == cfg->mark_test) {
            int tp = (strcmp(cfg->egress_type, "tproxy") == 0);
            if (!state_has(st_test(ctx->st, udp), kf, now)) continue;
            good = failed = 0;
            if (f->l4proto == 6) {
                /* В tproxy локальный Xray отвечает SYN-ACK/ACK даже когда апстрим
                 * мёртв, поэтому «есть ответы» ничего не доказывает: подтверждаем
                 * только по реальным данным (rb). */
                if (tp) {
                    if (f->rb >= cmin_bytes(cfg)) good = 1;
                } else if (f->rp >= 2 || f->rb >= cmin_bytes(cfg)) {
                    good = 1;
                }
                if (tp) {
                    /* tproxy: Xray отвечает сам, поэтому «нет ответов» (rp == 0)
                     * недостижимо — неудачу определяем по отсутствию реальных
                     * данных при состоявшемся соединении, но не раньше, чем запись
                     * прожила TEST_FAIL_MIN_AGE (см. выше). Возраст ищем по тому же
                     * ключу, что и запись (kf): в port-aware режиме это пара
                     * «ip:порт», и поиск по голому адресу не находил запись —
                     * детект провала test молча не срабатывал. */
                    if (test_age(st_test(ctx->st, udp), cfg, kf, now) >= TEST_FAIL_MIN_AGE &&
                        strcmp(f->tcp_state, "ESTABLISHED") == 0 &&
                        f->op >= lmin_op(cfg) && f->ob >= lmin_bytes(cfg) &&
                        f->rb < 128)
                        failed = 1;
                } else if ((strcmp(f->tcp_state, "SYN_SENT") == 0 && f->op >= 3 &&
                            f->rp == 0) ||
                           (strcmp(f->tcp_state, "ESTABLISHED") == 0 &&
                            test_age(st_test(ctx->st, udp), cfg, kf, now) >= TEST_FAIL_MIN_AGE &&
                            f->op >= lmin_op(cfg) && f->ob >= lmin_bytes(cfg) &&
                            f->rp <= 1 && f->rb < 128)) {
                    /* SYN_SENT без единого ответа — сигнал немедленный (окна данных
                     * ещё нет); ESTABLISHED без реальных данных — только после
                     * TEST_FAIL_MIN_AGE, иначе первое окно TCP даёт ложный cooldown. */
                    failed = 1;
                }
            } else {
                if (f->rp >= 1) good = 1;
                if ((f->dport == 443 && f->op >= lmin_op(cfg) && f->rp == 0) ||
                    (f->dport != 443 && f->op >= lmin_op(cfg) * 2 && f->rp == 0)) failed = 1;
            }
            if (good) {
                state_add(st_ok(ctx->st, udp), kf, now, cfg->ok_ttl, 0);
                state_remove(st_test(ctx->st, udp), kf);
                state_remove(st_watch(ctx->st, udp), kf);
                state_remove(st_cool(ctx->st, udp), kf);
                backend_ipset_add_port(cfg, udp, 1, f->dst, flow_port(cfg, f), cfg->ok_ttl);
                backend_ipset_del_port(cfg, udp, 0, f->dst, flow_port(cfg, f));
                {
                    char dm2[DNS_DOMAIN_MAX];
                    dm2[0] = '\0';
                    dns_sniff_domain_of(f->dst, dm2, sizeof(dm2));
                    if (dm2[0])
                        slogf(SL_INFO, "AUTO-SUSANIN: CONFIRMED %s -> %s:%u (%s)",
                              f->src, f->dst, f->dport, dm2);
                    else
                        slogf(SL_INFO, "AUTO-SUSANIN: CONFIRMED %s -> %s:%u",
                              f->src, f->dst, f->dport);
                }
                cdn_aggregate(ctx, f);
                frozen_net_aggregate(ctx, f);
                profile_auto_learn(ctx->cfg, f->dst);
            } else if (failed) {
                state_remove(st_test(ctx->st, udp), kf);
                state_remove(st_watch(ctx->st, udp), kf);
                state_add(st_cool(ctx->st, udp), kf, now, cfg->cooldown_ttl, 0);
                backend_ipset_del_port(cfg, udp, 0, f->dst, flow_port(cfg, f));
                slogf(SL_INFO, "AUTO-SUSANIN: COOLDOWN %s:%u", f->dst, f->dport);
                backend_ct_delete(f);
            }
        } else if ((f->ctmark & cfg->mark_mask) == cfg->mark_ok) {
            int tp = (strcmp(cfg->egress_type, "tproxy") == 0);
            if (!state_has(st_ok(ctx->st, udp), kf, now)) continue;
            healthy = failed = 0;
            if (f->l4proto == 6) {
                /* tproxy: ответы приходят от локального Xray — «здоровым» считаем
                 * только адрес, от которого есть реальные данные. */
                if (tp) {
                    if (f->rb >= 128) healthy = 1;
                } else if (f->rp >= 2 || f->rb >= 128) {
                    healthy = 1;
                }
                /* rp==0 (а не rp<=1): любой ответ означает живой адрес — так
                 * долгоживущие соединения мессенджеров (Telegram/WhatsApp) не
                 * вылетают из ok из-за одного «тихого» среза. */
                if ((strcmp(f->tcp_state, "SYN_SENT") == 0 && f->op >= 4 && f->rp == 0) ||
                    (strcmp(f->tcp_state, "ESTABLISHED") == 0 && f->op >= 15 &&
                     f->ob >= 5000 && f->rp == 0 && f->rb < 128)) failed = 1;
            } else {
                if (f->rp >= 1) healthy = 1;
                if (f->dport == 443 && f->op >= 16 && f->rp == 0) failed = 1;
            }
            if (failed && !healthy) {
                if (cfg->ok_evict_misses > 1) {
                    struct ofslot *os = of_touch(f->dst, udp);
                    if (os->miss < cfg->ok_evict_misses)
                        continue;   /* ещё наблюдаем — из ok не снимаем */
                    os->seen = 0;
                }
                state_remove(st_ok(ctx->st, udp), kf);
                state_remove(st_test(ctx->st, udp), kf);
                state_remove(st_watch(ctx->st, udp), kf);
                state_add(st_cool(ctx->st, udp), kf, now, cfg->cooldown_ok_ttl, 0);
                backend_ipset_del_port(cfg, udp, 1, f->dst, flow_port(cfg, f));
                /* D1: адрес в VPN (ok) деградирует — пробуем «прямо» (мягкое
                 * «прямо» с TTL). Если и прямой путь плох, обучение вернёт VPN. */
                if (cfg->auto_direct && cfg->direct_pref_ttl > 0) {
                    backend_set_add(cfg, "susanin_direct", f->dst, cfg->direct_pref_ttl);
                    state_add(&ctx->st->direct, f->dst, now, cfg->direct_pref_ttl, 0);
                    slogf(SL_INFO, "D1: %s -> soft-direct (%ds)", f->dst,
                          cfg->direct_pref_ttl);
                }
                slogf(SL_DEBUG, "AUTO-SUSANIN: OK-CHURN %s:%u", f->dst, f->dport);
                oc_cnt++;
                snprintf(oc_name, sizeof(oc_name), "%s:%u", f->dst, f->dport);
                if (!oc_last) {
                    oc_last = now;
                } else if (now - oc_last >= 300) {
                    slogf(SL_INFO, "AUTO-SUSANIN: OK-CHURN: %d за ~5 мин (последний %s)",
                          oc_cnt, oc_name);
                    oc_cnt = 0;
                    oc_last = now;
                }
                backend_ct_delete(f);
            } else if (healthy && !failed) {
                of_forget(f->dst, udp);
                time_t at = state_at(st_ok(ctx->st, udp), kf, now);
                if (at && (int)(at - now) <= cfg->ok_refresh_below) {
                    state_add(st_ok(ctx->st, udp), kf, now, cfg->ok_ttl, 1);
                    backend_ipset_add_port(cfg, udp, 1, f->dst, flow_port(cfg, f), cfg->ok_ttl);
                }
            }
        }
    }
}
