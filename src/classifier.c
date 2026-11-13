#define _GNU_SOURCE
#include "classifier.h"
#include "backend.h"
#include "cdn.h"
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

static int port_excluded(const susanin_config *cfg, unsigned port)
{
    char buf[256], *save = NULL, *tok;
    if (service_port(port))
        return 1;
    if (!cfg->learn_exclude_ports[0])
        return 0;
    snprintf(buf, sizeof(buf), "%s", cfg->learn_exclude_ports);
    for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        while (*tok == ' ' || *tok == '\t') tok++;
        if ((unsigned)strtoul(tok, NULL, 10) == port)
            return 1;
    }
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
    if (inet_pton(AF_INET, ip, &a) != 1 || inet_pton(AF_INET, c, &n) != 1)
        return 0;
    mask = pre == 0 ? 0 : (0xffffffffu << (32 - pre));
    ah = ntohl(a.s_addr);
    nh = ntohl(n.s_addr);
    return (ah & mask) == (nh & mask);
}

static int from_lan(const susanin_config *cfg, const char *src)
{
    char buf[512], *save = NULL, *tok;
    snprintf(buf, sizeof(buf), "%s", cfg->lan_subnets);
    for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        while (*tok == ' ') tok++;
        if (ip_in_cidr(src, tok))
            return 1;
    }
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

/* rate cache (two-sample deltas) */
#define RCAP 2048
typedef struct {
    char key[192];
    unsigned long op, rp, ob, rb;
    time_t t;
    int seen;
} rslot;
static rslot rc[RCAP];
static int rc_n = 0;

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
}

static rslot *rc_find(const char *key)
{
    int i;
    for (i = 0; i < rc_n; i++)
        if (strcmp(rc[i].key, key) == 0)
            return &rc[i];
    return NULL;
}

static rslot *rc_store(const char *key, const ct_flow *f, time_t now)
{
    rslot *s;
    if (rc_n >= RCAP) {
        /* Кэш полон: вытесняем одну самую старую запись, а не обнуляем весь
         * кэш (иначе под нагрузкой rate-детект «слепнет» целиком). */
        int i, oldest = 0;
        for (i = 1; i < rc_n; i++)
            if (rc[i].t < rc[oldest].t)
                oldest = i;
        s = &rc[oldest];
    } else {
        s = &rc[rc_n++];
    }
    snprintf(s->key, sizeof(s->key), "%s", key);
    s->op = f->op; s->rp = f->rp; s->ob = f->ob; s->rb = f->rb;
    s->t = now; s->seen = 1;
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
#define DOK_TTL_BUDGET 120   /* бюджет проб исчерпан: короткая отметка */
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

/* r4.2 (2026-11-13, разбор habr 1104904): ТСПУ замораживает не адреса, а целые
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
static int media_port(const susanin_config *cfg, unsigned p)
{
    char buf[128], *save = NULL, *tok;
    if (!cfg->media_ports[0])
        return 0;
    snprintf(buf, sizeof(buf), "%s", cfg->media_ports);
    for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        while (*tok == ' ' || *tok == '\t') tok++;
        if ((unsigned)strtoul(tok, NULL, 10) == p)
            return 1;
    }
    return 0;
}

/* M2: пороги media_min_rate/media_min_age раньше были объявлены и печатались,
 * но в коде НЕ проверялись: «медиа» считалась любая загрузка на портах
 * media_ports с ответом >= media_min_bytes, и два адреса утаскивали в VPN всю
 * /24 (инцидент reg.ru 2026-10-16: HTML шёл, стили/картинки — нет).
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
    slogf(SL_INFO, "MEDIA: %s -> vpn (rb=%lu, ob=%lu)", cidr,
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

/* Пропуск обучения — INFO, но не чаще раза в 10 минут на адрес: на DEBUG
 * вопрос «почему адрес не заворачивается в VPN» был неразбираем
 * (2026-11-12, случай dnevnik.ru). */
static void skip_note(const char *ip, unsigned port, time_t now, const char *why)
{
    static char last_ip[64];
    static time_t last_at;
    if (strcmp(last_ip, ip) != 0 || now - last_at >= 600) {
        snprintf(last_ip, sizeof(last_ip), "%.63s", ip);
        last_at = now;
        slogf(SL_INFO, "AUTO-SUSANIN: skip %s:%u (%s)", ip, port, why);
    }
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
        skip_note(f->dst, f->dport, now, "vpn_never");
        return;
    }
    /* Не учим в VPN адрес, недавно бывший в vpn_never: он должен идти напрямую,
     * иначе возможен «прыжок» direct <-> VPN (план п.8.3). Осознанно удалённые
     * из списка записи кулдаун НЕ получают (см. doms_reconcile). */
    if (vn_is_recently_never(f->dst, now)) {
        skip_note(f->dst, f->dport, now, "recently vpn_never");
        return;
    }
    /* Прямая проба — только для «SYN ушёл без ответа»: там свежий connect
     * информативен. Для DPI-RST/TCP-CLOSE/«тишины» проба бесполезна и вредна:
     * рукопожатие проходит (блокировка по SNI/данным — уже после connect), и мы
     * получили бы ложное «прямо ок», не завернув именно тот трафик, что нужно.
     * Негативный кэш тоже относится только к этому случаю: он не должен
     * запрещать обучение по сигналам SNI (DPI-RST/CLOSE). */
    if (f->l4proto == 6 && f->dport > 0 && syn) {
        if (dok_has(f->dst, now)) {
            skip_note(f->dst, f->dport, now, "недавно проверено: прямой жив");
            return;
        }
        if (!direct_probe_budget_ok(now)) {
            /* Бюджет проб исчерпан: осознанно НЕ заворачиваем (короткая отметка),
             * иначе защита отключалась бы ровно под нагрузкой. */
            dok_add(f->dst, now, DOK_TTL_BUDGET);
            skip_note(f->dst, f->dport, now, "бюджет проб исчерпан");
            return;
        }
        if (!direct_probe_sec_ok(now))
            return;   /* лимит на секунду: решим в следующий проход, не заворачиваем */
        if (health_probe_tcp_direct(f->dst, f->dport, DIRECT_PROBE_MS)) {
            dok_add(f->dst, now, DOK_TTL_OK);
            slogf(SL_INFO, "AUTO-SUSANIN: %s skip %s:%u (прямой путь отвечает)",
                  stage, f->dst, f->dport);
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
    slogf(SL_INFO, "AUTO-SUSANIN: %s %s %s:%u", stage, reason, f->dst, f->dport);
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
        if (!from_lan(cfg, f->src)) continue;
        if (is_private_dst(f->dst, NULL)) continue;
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
                /* r4.1 (habr 1104904): ТСПУ-заморозка — соединение живое,
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
        if (!from_lan(cfg, f->src)) continue;
        if (is_private_dst(f->dst, NULL)) continue;

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
                               dob >= lmin_bytes(cfg) && candidate_ok(ctx, f, now)) {
                        /* C1: starvation — поток жив, но ответ идёт «по капле»
                         * (ТСПУ шейпит, а не рвёт). Узко для CDN, чтобы не шуметь. */
                        char cidr[64];
                        if (cdn_match(cfg, f->dst, cidr, sizeof(cidr)))
                            promote_test(ctx, f, now, "SOFT", "CDN-STARVATION");
                    } else if (dop > 0 && drp > 0 && drb < 128 && dob >= 16384UL) {
                        /* r4.1: «по капле» НЕ только у CDN: заморозка/шейпинг
                         * хостинговых сетей даёт ту же форму (отправили >=16 КБ
                         * за окно, получили <128 байт). Подтверждение через watch,
                         * как late-stall: одно окно — наблюдение, второе — VPN. */
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
        } else if (f->l4proto == 17) {
            if (!f->has_reply) {
                /* Порог UDP-обучения настраивается (udp_min_op, по умолчанию 3).
                 * Прежние 12 были недостижимы на практике: голосовой хендшейк
                 * (Discord RTC) — это 3 echo-пакета с нового локального порта,
                 * после чего клиент сдаётся и заводит следующий сокет. В итоге
                 * адрес голосового сервера не попадал в susanin_test_udp, поток
                 * шёл напрямую и «маршрут не строился» (стенд 2026-11-02). */
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
        if (!from_lan(cfg, f->src)) continue;
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
                     * прожила TEST_FAIL_MIN_AGE (см. выше). */
                    if (test_age(st_test(ctx->st, udp), cfg, f->dst, now) >= TEST_FAIL_MIN_AGE &&
                        strcmp(f->tcp_state, "ESTABLISHED") == 0 &&
                        f->op >= lmin_op(cfg) && f->ob >= lmin_bytes(cfg) &&
                        f->rb < 128)
                        failed = 1;
                } else if ((strcmp(f->tcp_state, "SYN_SENT") == 0 && f->op >= 3 &&
                            f->rp == 0) ||
                           (strcmp(f->tcp_state, "ESTABLISHED") == 0 &&
                            test_age(st_test(ctx->st, udp), cfg, f->dst, now) >= TEST_FAIL_MIN_AGE &&
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
                slogf(SL_INFO, "AUTO-SUSANIN: CONFIRMED %s:%u", f->dst, f->dport);
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
