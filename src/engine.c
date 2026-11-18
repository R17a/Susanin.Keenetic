#define _GNU_SOURCE
#include "engine.h"
#include "backend.h"
#include "cdn.h"
#include "classifier.h"
#include "conntrack.h"
#include "dns_sniff.h"
#include "health.h"
#include "log.h"
#include "release.h"
#include "state.h"
#include "udp_relay.h"
#include "vpn_always.h"
#include "vpn_never.h"
#include "vpin.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;
static volatile sig_atomic_t g_reload = 0;
static void on_sig(int s) { (void)s; g_stop = 1; }
static void on_hup(int s) { (void)s; g_reload = 1; }

typedef struct { ct_flow *v; int n; int cap; } flowlist;

static int collect(void *ud, const ct_flow *f)
{
    flowlist *L = ud;
    if (L->n >= L->cap) {
        int ncap = L->cap ? L->cap * 2 : 1024;
        ct_flow *nv = realloc(L->v, (size_t)ncap * sizeof(ct_flow));
        if (!nv)
            return 1;
        L->v = nv;
        L->cap = ncap;
    }
    L->v[L->n++] = *f;
    return 0;
}

/* Фильтры LAN/приватные — бинарные из classifier.c (clf_from_lan4/
 * clf_is_private4): строковые версии тянули inet_pton и strtok на каждый
 * поток в каждом проходе. */

/* Ключ состояния -> элемент ipset: "1.2.3.4:443" превращается в "1.2.3.4,443"
 * (в port-aware режиме), обычный адрес идёт как есть. Нужно при ре-ассерте и
 * чистках, которые обходят состояние (там ключи могут быть парами). */
static void state_ipset_add(const susanin_config *cfg, int udp, int phase_ok,
                            const char *key, int ttl)
{
    char ip[64];
    int port = 0;
    state_key_split(key, ip, sizeof(ip), &port);
    /* Смена режима port_aware: ключи «другого» формата пропускаем, иначе ipset
     * получит "ip" в hash:ip,port (или "ip,proto:port" в hash:ip) и напишет
     * ошибку на каждую запись. Такие записи просто истекают по TTL. */
    if (cfg->port_aware ? (port <= 0) : (port > 0))
        return;
    backend_ipset_add_port(cfg, udp, phase_ok, ip, port, ttl);
}

static void state_ipset_del(const susanin_config *cfg, int udp, int phase_ok,
                            const char *key)
{
    char ip[64];
    int port = 0;
    state_key_split(key, ip, sizeof(ip), &port);
    if (cfg->port_aware ? (port <= 0) : (port > 0))
        return;
    backend_ipset_del_port(cfg, udp, phase_ok, ip, port);
}

static void resync_sets(const susanin_config *cfg, susanin_state *st)
{
    int udp, phase, i;
    time_t now = time(NULL);
    backend_ipset_flush(cfg);
    /* Восстановление кэша — это сотни адресов: применяем одной пачкой
     * (`ipset restore`), иначе на каждый адрес был fork+exec и старт/re-provision
     * заметно тормозили. */
    backend_batch_begin();
    for (udp = 0; udp < 2; udp++) {
        for (phase = 0; phase < 2; phase++) {
            const state_set *set = phase ? st_ok(st, udp) : st_test(st, udp);
            for (i = 0; i < set->n; i++) {
                /* Остаток TTL: после re-provision запись не должна жить дольше. */
                int ttl = (int)(set->v[i].expire - now);
                if (ttl > 0)
                    state_ipset_add(cfg, udp, phase, set->v[i].addr, ttl);
            }
        }
    }
    /* ok_net/direct иначе теряются при любом fail-open/re-provision. */
    for (i = 0; i < st->net.n; i++) {
        int ttl = (int)(st->net.v[i].expire - now);
        if (ttl > 0)
            backend_net_add(cfg, st->net.v[i].addr, ttl);
    }
    for (i = 0; i < st->direct.n; i++) {
        int ttl = (int)(st->direct.v[i].expire - now);
        if (ttl > 0)
            backend_set_add(cfg, "susanin_direct", st->direct.v[i].addr, ttl);
    }
    for (i = 0; i < st->never.n; i++) {
        int ttl = (int)(st->never.v[i].expire - now);
        if (ttl > 0)
            backend_set_add(cfg, "susanin_never", st->never.v[i].addr, ttl);
    }
    backend_batch_end();
    /* ipset'ы пусты — пины dns_sniff применим заново на следующем reconcile. */
    dns_sniff_reset_pins();
}

/* r7.4b: аудит клиентов — «кто запросил» по LAN-хостам: потоки всего /
 * в туннеле (помеченные) / прямых. Пишется в var/clients.txt (веб-процесс
 * читает для панели; движок и панель — разные процессы). Не чаще 15 с,
 * файл перезаписывается только при изменении. */
static void clients_audit(const susanin_config *cfg, const ct_flow *flows, int n,
                          time_t now)
{
    static time_t last;
    static char lastbody[2048];
    /* r7.9: приватные источники ВНЕ lan_subnets (гостевой SSID, mesh, второй
     * роутер) — Susanin их молча игнорирует, и пользователь думает, что
     * «правила не работают» (клиент в гостевой подсети вне lan_subnets).
     * Раз в час на /24 — явная строка с командой починки. */
    static char unc[8][20];
    static time_t unc_at[8];
    static int unc_n;
    char body[2048];
    char ips[32][64];
    int tot[32], vpn[32], dir[32];
    int cnt = 0, i, j, used = 0;
    FILE *f;

    /* Пустой список — это тоже результат: ниже body сравнивается с прошлым
     * значением через strcmp, и без инициализации он читал мусор стека
     * (а при cnt == 0 цикл записи ни разу не выполнялся). */
    body[0] = '\0';
    if (now - last < 15)
        return;
    last = now;
    for (i = 0; i < n; i++) {
        const ct_flow *fl = &flows[i];
        int k = -1;
        if (fl->l4proto != 6 && fl->l4proto != 17) continue;
        if (!clf_from_lan4(cfg, fl->src4)) {
            if (fl->src4 && clf_is_private4(fl->src4)) {
                char u24[20];
                char *dot3;
                int jj;
                snprintf(u24, sizeof(u24), "%s", fl->src);
                dot3 = strrchr(u24, '.');
                if (dot3) {
                    dot3[1] = '0';
                    dot3[2] = '\0';
                }
                for (jj = 0; jj < unc_n; jj++)
                    if (!strcmp(unc[jj], u24))
                        break;
                if (jj == unc_n && jj < 8) {
                    snprintf(unc[jj], sizeof(unc[jj]), "%s", u24);
                    unc_n++;
                }
                if (jj < unc_n && now - unc_at[jj] >= 3600) {
                    unc_at[jj] = now;
                    slogf(SL_INFO, "AUTO-SUSANIN: подсеть %s — потоки из LAN, "
                          "не покрытой lan_subnets (клиенты там не обрабатываются; "
                          "добавьте подсеть в lan_subnets)", u24);
                }
            }
            continue;
        }
        if (clf_is_private4(fl->dst4)) continue;
        for (j = 0; j < cnt; j++)
            if (!strcmp(ips[j], fl->src)) { k = j; break; }
        if (k < 0) {
            if (cnt >= 32) continue;
            k = cnt++;
            snprintf(ips[k], sizeof(ips[k]), "%s", fl->src);
            tot[k] = vpn[k] = dir[k] = 0;
        }
        tot[k]++;
        if (fl->ctmark != 0) vpn[k]++; else dir[k]++;
    }
    for (j = 0; j < cnt && used < (int)sizeof(body) - 80; j++)
        used += snprintf(body + used, sizeof(body) - used,
                         "%s %d %d %d\n", ips[j], tot[j], vpn[j], dir[j]);
    if (!strcmp(body, lastbody))
        return;
    snprintf(lastbody, sizeof(lastbody), "%s", body);
    if ((f = fopen("/opt/susanin/var/clients.txt.tmp", "w")) != NULL) {
        fputs(body, f);
        fclose(f);
        rename("/opt/susanin/var/clients.txt.tmp", "/opt/susanin/var/clients.txt");
    }
}

static void sweep_direct(const susanin_config *cfg, susanin_state *st,
                         const ct_flow *flows, int n)
{
    int i, done = 0;
    time_t now = time(NULL);
    /* Ограничиваем число удалений за проход (backend_ct_delete форкает
     * `conntrack`): не допускаем залпа форков на слабом CPU. */
    for (i = 0; i < n && done < 200; i++) {
        const ct_flow *f = &flows[i];
        int udp;
        if (f->ctmark != 0) continue;
        if (!clf_from_lan4(cfg, f->src4)) continue;
        /* Адреса из vpn_never должны ходить напрямую — их не трогаем: и те, что
         * сейчас в списке (vn_has), и пины DNS-снифинга (st.never), и недавно
         * снятые. */
        if (vn_has(f->dst) || state_has(&st->never, f->dst, now) ||
            vn_is_recently_never(f->dst, now))
            continue;
        if (f->l4proto != 6 && f->l4proto != 17) continue;
        /* Те же фильтры, что в clr_fast: служебные порты (53/853/500/4500/8567)
         * и приватные адреса не рвём. */
        if (clf_port_excluded(cfg, f->dport) || clf_port_excluded(cfg, f->sport)) continue;
        if (clf_is_private4(f->dst4)) continue;
        udp = (f->l4proto == 17);
        /* Ключ состояния потока: пара ip:порт в port-aware, иначе адрес.
         * Без этого в pair-режиме проверки не находили записи и потоки к
         * уже подтверждённым адресам не сбрасывались. */
        {
            char kf[64];
            state_key(kf, sizeof(kf), f->dst,
                      cfg->port_aware ? (int)f->dport : 0);
            /* «Мягко-прямо» (D1) и кандидатов в обучение не сбрасываем. */
            if (state_has(&st->direct, f->dst, now)) continue;
            if (state_has(st_test(st, udp), kf, now)) continue;
            if (state_has(st_watch(st, udp), kf, now)) continue;
            if (state_has(st_ok(st, udp), kf, now)) {
                backend_ct_delete(f);
                done++;
            }
        }
    }
}

/* vpn_never: уже помеченные (VPN) потоки к «прямым» адресам. never_state_clean()
 * убирает запись из кэша, но само соединение живёт (браузер держит keep-alive
 * минуты-часы), а sweep_direct() такие потоки специально пропускает
 * (ctmark != 0). Раз в минуту рвём их точечно и пишем причину в лог: иначе
 * «добавил в never, а сайт всё равно идёт через VPN». */
static void never_sweep_marked(const susanin_config *cfg, susanin_state *st,
                               const ct_flow *flows, int n, time_t now)
{
    int i, done = 0;
    for (i = 0; i < n && done < 64; i++) {
        const ct_flow *f = &flows[i];
        if (f->ctmark == 0)
            continue;
        /* Метки профилей (0x40000000 и т.п.) лежат ВНЕ mark_mask основной схемы —
         * такой поток ведёт профиль со своим туннелем. Если адрес попал и в
         * профиль, и в vpn_never, рвать его каждую минуту нельзя (профиль будет
         * «дёргаться»). Приоритет явный: профиль > never. */
        if (f->ctmark & ~cfg->mark_mask)
            continue;
        if (!clf_from_lan4(cfg, f->src4))
            continue;
        if (f->l4proto != 6 && f->l4proto != 17)
            continue;
        if (!vn_has(f->dst) && !state_has(&st->never, f->dst, now))
            continue;
        if (clf_is_private4(f->dst4) || clf_service_port(f->dport))
            continue;
        backend_ct_delete(f);
        done++;
        slogf(SL_INFO, "vpn_never: сброшен помеченный поток %s:%u (должен идти напрямую)",
              f->dst, f->dport);
    }
}

/* vpn_never: убрать адреса из state (ok/test/cool/direct), чтобы state не
 * расходился с ipset'ами после vn_refresh(). Иначе sweep_direct рвёт прямые
 * потоки к never-адресам, а resync_sets возвращает их в ok-ipset. */
static void never_state_clean(const susanin_config *cfg, susanin_state *st, time_t now)
{
    int udp, k, i, flushed = 0;
    for (udp = 0; udp < 2; udp++) {
        state_set *sets[3];
        sets[0] = st_ok(st, udp);
        sets[1] = st_test(st, udp);
        sets[2] = st_cool(st, udp);
        for (k = 0; k < 3; k++) {
            state_set *s = sets[k];
            for (i = s->n - 1; i >= 0; i--) {
                const char *key = s->v[i].addr;   /* в pair-режиме это "ip:порт" */
                char bare[64];
                int bport = 0;
                state_key_split(key, bare, sizeof(bare), &bport);
                /* vn_has()/st->never работают с ГОЛЫМ адресом — пару разбираем. */
                if (!vn_has(bare) && !state_has(&st->never, bare, now))
                    continue;
                if (k == 0)
                    state_ipset_del(cfg, udp, 1, key);   /* ok */
                else if (k == 1)
                    state_ipset_del(cfg, udp, 0, key);   /* test */
                state_remove(s, key);
                slogf(SL_DEBUG, "vpn_never: %s убран из кэша (%s)", bare,
                      udp ? "udp" : "tcp");
                /* Рвём уже установленные потоки к этому адресу: иначе открытое
                 * соединение продолжает идти в туннель, пока не умрёт само
                 * (conntrack не переоценивает правила для существующих сессий).
                 * Бюджет — чтобы не форкать conntrack на каждый адрес пачкой. */
                if (flushed < 100) {
                    backend_ct_flush_ip(bare);
                    flushed++;
                }
            }
        }
    }
    for (i = st->direct.n - 1; i >= 0; i--) {
        const char *ip = st->direct.v[i].addr;
        if (!vn_has(ip))
            continue;
        backend_set_del(cfg, "susanin_direct", ip);
        state_remove(&st->direct, ip);
    }
    (void)now;
}

/* Bounded GC (upstream v0.12 idea): keep per-proto ok-cache within a limit by
 * evicting the oldest entries. Runs periodically; 0 in config disables. */
static void trim_ok(const susanin_config *cfg, susanin_state *st)
{
    int udp;
    if (cfg->ok_max_entries <= 0)
        return;
    for (udp = 0; udp < 2; udp++) {
        state_set *set = st_ok(st, udp);
        while (set->n > cfg->ok_max_entries && set->n > 0) {
            char ip[64];
            snprintf(ip, sizeof(ip), "%s", set->v[0].addr);
            state_ipset_del(cfg, udp, 1, ip);
            state_remove(set, ip);
            slogf(SL_INFO, "GC: evict ok %s (%s), limit %d", ip,
                  udp ? "udp" : "tcp", cfg->ok_max_entries);
        }
    }
}

/* Health egress: пробы идут в ОТДЕЛЬНОМ процессе (probe_job_*), поэтому главный
 * цикл не блокируется connect/recv — иначе dns_sniff_poll и датаплейн ждут до
 * нескольких секунд. Здесь — окно проб и оценка состояния кандидата. */
#define EG_WIN 6          /* сколько последних проб учитываем */
#define EG_MIN_RATIO 30   /* порог доли успехов, % — иначе кандидат DOWN */
/* Сколько подряд проверить «процесс Xray есть, а порт не слушается», прежде чем
 * звать принудительный restart (S93 умеет kill -9 и не стартует при D-state). */
#define FORCED_RESTART_TRIES 3
static int eg_ok[CFG_MAX_EGRESS][EG_WIN];
static int eg_tot[CFG_MAX_EGRESS][EG_WIN];
static int eg_wi[CFG_MAX_EGRESS];
static int eg_lead[CFG_MAX_EGRESS];   /* сколько ПРОБ кандидат «лучший» (race) */
static unsigned eg_gen;               /* сколько сэмплов применено (см. eg_apply) */

/* Сброс окна проб (перечитывание конфига: пороги/адреса могли измениться). */
static void eg_reset(void)
{
    memset(eg_ok, 0, sizeof(eg_ok));
    memset(eg_tot, 0, sizeof(eg_tot));
    memset(eg_wi, 0, sizeof(eg_wi));
    memset(eg_lead, 0, sizeof(eg_lead));
    eg_gen = 0;
}

static int eg_ratio(int i)   /* доля успехов за окно, % */
{
    int k, o = 0, t = 0;
    if (i < 0 || i >= CFG_MAX_EGRESS)
        return 0;
    for (k = 0; k < EG_WIN; k++) {
        o += eg_ok[i][k];
        t += eg_tot[i][k];
    }
    return t > 0 ? (o * 100) / t : 0;
}

static void eg_apply(const susanin_config *cfg, int i, int ok, int total, int lat,
                     int *up, int *miss, time_t *up_since, int *lat_ms, time_t now)
{
    int deb;
    if (i < 0 || i >= CFG_MAX_EGRESS)
        return;
    if (lat < 0) {   /* интерфейса нет — сразу DOWN */
        eg_ok[i][eg_wi[i]] = 0;
        eg_tot[i][eg_wi[i]] = 1;
        eg_wi[i] = (eg_wi[i] + 1) % EG_WIN;
        if (up[i])
            slogf(SL_WARN, "egress %s отсутствует — DOWN", cfg->egress_list[i]);
        up[i] = 0;
        miss[i] = 0;
        if (lat_ms)
            lat_ms[i] = 0;
        return;
    }
    eg_ok[i][eg_wi[i]] = ok;
    eg_tot[i][eg_wi[i]] = total > 0 ? total : 1;
    eg_wi[i] = (eg_wi[i] + 1) % EG_WIN;
    eg_gen++;                      /* новая проба — «тик» для race/failback */
    if (lat_ms)
        lat_ms[i] = lat;
    if (eg_ratio(i) >= EG_MIN_RATIO) {
        miss[i] = 0;
        if (!up[i]) {
            up[i] = 1;
            up_since[i] = now;
            slogf(SL_INFO, "egress %s UP", cfg->egress_list[i]);
        }
        return;
    }
    if (!up[i])
        return;
    deb = cfg->health_miss_debounce > 0 ? cfg->health_miss_debounce : 1;
    if (++miss[i] >= deb) {
        up[i] = 0;
        miss[i] = 0;
        slogf(SL_WARN, "egress %s DOWN", cfg->egress_list[i]);
    }
}

/* --- Пробы в отдельном процессе ------------------------------------------- */

/* Кандидат-резерв через Xray: в egress_interface можно указать "tproxy"/"xray"
 * (P1). Такой кандидат проверяется SOCKS-пробой апстрима Xray,
 * а при переключении на него датаплейн пересобирается в tproxy-режиме. */
static int egress_is_tproxy(const char *name)
{
    return name && (!strcmp(name, "tproxy") || !strcmp(name, "xray"));
}

static pid_t pj_pid = 0;
static int pj_fd = -1;
static time_t pj_start = 0;
static char pj_buf[1024];
static size_t pj_len = 0;

static int probe_job_busy(void) { return pj_pid > 0; }

/* Завершить процесс проб (выход из движка или перечитывание конфига). */
static void probe_job_stop(void)
{
    if (pj_pid > 0) {
        int st;
        kill(pj_pid, SIGKILL);
        waitpid(pj_pid, &st, 0);
        pj_pid = 0;
    }
    if (pj_fd >= 0) {
        close(pj_fd);
        pj_fd = -1;
    }
    pj_len = 0;
}

static void probe_job_start(const susanin_config *cfg, int n)
{
    int fd[2];
    pid_t pid;
    if (pj_pid > 0 || n <= 0)
        return;
    if (pipe(fd) != 0)
        return;
    pid = fork();
    if (pid < 0) {
        close(fd[0]);
        close(fd[1]);
        return;
    }
    if (pid == 0) {
        /* Ребёнок: только пробы и строки результата, без общей памяти. */
        int i;
        close(fd[0]);
        if (strcmp(cfg->egress_type, "tproxy") == 0) {
            /* tproxy: путь один (Xray + его outbound), поэтому проверяем апстрим
             * через локальный SOCKS. До 3 адресов из health_probe: успех — если
             * ответил хотя бы один (один адрес мог резаться маршрутом Xray).
             * Результат пишем для всех кандидатов — так он попадает в общий
             * fail-open/failover-механизм. */
            char buf[512], *save = NULL, *tok;
            int ok = 0, total = 0, lat = 0, naddr = 0;
            int port = cfg->health_tcp_port > 0 ? cfg->health_tcp_port : CFG_DEF_HEALTH_TCP_PORT;
            struct timespec t0, t1;
            snprintf(buf, sizeof(buf), "%s", cfg->health_probe);
            clock_gettime(CLOCK_MONOTONIC, &t0);
            for (tok = strtok_r(buf, ",", &save); tok && naddr < 3;
                 tok = strtok_r(NULL, ",", &save)) {
                while (*tok == ' ')
                    tok++;
                if (!*tok)
                    continue;
                naddr++;
                total++;
                if (health_probe_via_socks(cfg, tok, port, 1500)) {
                    ok = 1;
                    break;
                }
            }
            clock_gettime(CLOCK_MONOTONIC, &t1);
            lat = (int)((t1.tv_sec - t0.tv_sec) * 1000 +
                        (t1.tv_nsec - t0.tv_nsec) / 1000000);
            for (i = 0; i < n && i < CFG_MAX_EGRESS; i++) {
                char line[128];
                snprintf(line, sizeof(line), "%d %d %d %d\n", i, ok,
                         total > 0 ? total : 1, ok ? lat : 0);
                if (write(fd[1], line, strlen(line)) < 0)
                    break;
            }
            _exit(0);
        }
        for (i = 0; i < n && i < CFG_MAX_EGRESS; i++) {
            char np[256], line[128];
            int ok = 0, total = 0, lat = -1;
            struct timespec t0, t1;
            const char *psrc = cfg->egress_addr[i][0] ? cfg->egress_addr[i]
                                                      : cfg->egress_addr[0];
            if (egress_is_tproxy(cfg->egress_list[i])) {
                /* Резервный путь через Xray: проверяем апстрим по SOCKS. */
                char pb[512], *save = NULL, *tok;
                int naddr = 0;
                int tport = cfg->health_tcp_port > 0 ? cfg->health_tcp_port : CFG_DEF_HEALTH_TCP_PORT;
                clock_gettime(CLOCK_MONOTONIC, &t0);
                snprintf(pb, sizeof(pb), "%s", cfg->health_probe);
                for (tok = strtok_r(pb, ",", &save); tok && naddr < 3;
                     tok = strtok_r(NULL, ",", &save)) {
                    while (*tok == ' ')
                        tok++;
                    if (!*tok)
                        continue;
                    naddr++;
                    total++;
                    if (health_probe_via_socks(cfg, tok, tport, 1500)) {
                        ok = 1;
                        break;
                    }
                }
                clock_gettime(CLOCK_MONOTONIC, &t1);
                lat = (int)((t1.tv_sec - t0.tv_sec) * 1000 +
                            (t1.tv_nsec - t0.tv_nsec) / 1000000);
                if (total == 0)
                    total = 1;
                snprintf(line, sizeof(line), "%d %d %d %d\n", i, ok,
                         total, ok ? lat : 0);
                if (write(fd[1], line, strlen(line)) < 0)
                    break;
                continue;
            }
            snprintf(np, sizeof(np), "/sys/class/net/%s", cfg->egress_list[i]);
            if (access(np, F_OK) == 0) {
                clock_gettime(CLOCK_MONOTONIC, &t0);
                health_probe_dev(cfg, cfg->egress_list[i], psrc, &ok, &total);
                /* ICMP может молчать, а туннель быть живым (залипшее NAT-состояние
                 * на промежуточном сервере по ICMP-ID): страховочная TCP-проба. */
                if (ok == 0 && total > 0 &&
                    health_probe_tcp_egress(cfg, cfg->egress_list[i], psrc,
                                            cfg->health_tcp_port)) {
                    slogf(SL_DEBUG, "health %s: ICMP 0/%d, TCP %d — считаю живым",
                          cfg->egress_list[i], total,
                          cfg->health_tcp_port > 0 ? cfg->health_tcp_port : CFG_DEF_HEALTH_TCP_PORT);
                    ok = total;
                }
                clock_gettime(CLOCK_MONOTONIC, &t1);
                lat = (int)((t1.tv_sec - t0.tv_sec) * 1000 +
                            (t1.tv_nsec - t0.tv_nsec) / 1000000);
            }
            snprintf(line, sizeof(line), "%d %d %d %d\n", i, ok, total, lat);
            if (write(fd[1], line, strlen(line)) < 0)
                break;
        }
        _exit(0);
    }
    close(fd[1]);
    (void)fcntl(fd[0], F_SETFL, O_NONBLOCK);
    pj_fd = fd[0];
    pj_pid = pid;
    pj_start = time(NULL);
    pj_len = 0;
}

/* Забрать готовые результаты (не блокируясь) и завершить процесс проб. */
static void probe_job_poll(const susanin_config *cfg, int *up, int *miss,
                           time_t *up_since, int *lat_ms, time_t now)
{
    if (pj_fd >= 0) {
        for (;;) {
            ssize_t r = read(pj_fd, pj_buf + pj_len, sizeof(pj_buf) - pj_len - 1);
            char *p;
            if (r <= 0)
                break;
            pj_len += (size_t)r;
            pj_buf[pj_len] = '\0';
            p = pj_buf;
            for (;;) {
                char *nl = strchr(p, '\n');
                int i, ok, total, lat;
                if (!nl)
                    break;
                *nl = '\0';
                if (sscanf(p, "%d %d %d %d", &i, &ok, &total, &lat) == 4)
                    eg_apply(cfg, i, ok, total, lat, up, miss, up_since, lat_ms, now);
                p = nl + 1;
            }
            /* Остаток без '\n' переносим в начало буфера. */
            pj_len = strlen(p);
            memmove(pj_buf, p, pj_len + 1);
            if (pj_len + 1 >= sizeof(pj_buf))
                pj_len = 0;
        }
    }
    if (pj_pid > 0) {
        int st;
        pid_t w = waitpid(pj_pid, &st, WNOHANG);
        int hung = (now - pj_start) > 120;   /* проба зависла — не ждём вечно */
        if (w == pj_pid || hung) {
            if (w != pj_pid) {
                kill(pj_pid, SIGKILL);
                waitpid(pj_pid, &st, 0);
            }
            if (pj_fd >= 0)
                close(pj_fd);
            pj_fd = -1;
            pj_pid = 0;
        }
    }
}

/* --- Аудит пинов, поставленных автообучением (VPIN) ----------------------
 * Автообучение уводит адрес в VPN по одной улике (FAST-детект «SYN без
 * ответа»/DPI-сигнал) и дальше не проверяет, что через туннель адрес вообще
 * работает. На живых кейсах это давало «залипшие» адреса: прямой путь живой,
 * туннель до адреса мёртв или в разы медленнее — а трафик идёт через VPN,
 * потому что пин стоит и сам не снимется (D1 откладывает возврат на час).
 *
 * Здесь: адрес, выученный классификатором (vpin_note), через vpin_interval
 * проверяется ЧЕРЕЗ ТУННЕЛЬ — на тот же порт, куда ходил подтверждающий
 * поток. Не отвечает два промаха подряд или медленнее VPIN_SLOW_MS — пин
 * снимается, адрес уходит напрямую с мягким «прямо» (susanin_direct),
 * чтобы не выучиться обратно тем же FAST-детектом. «Пробовать нечем»
 * (Xray лёг, SOCKS не слушает) промахом не считается: иначе рестарт Xray
 * снимал бы пины пачкой. Если туннель хорош —
 * адрес остаётся в VPN и позже (через два интервала) проверяется, не ожил ли
 * прямой путь: тогда пин снимается уже по хорошей новости.
 *
 * Ручные пины vpn_always сюда не попадают: vpin_note() зовёт только
 * классификатор, у ручных пинов другой путь. */
#define VPIN_TIMEOUT_MS 2500
#define VPIN_SLOW_MS    1800
#define VPIN_BATCH      4
/* Запасной порт пробы, если поток-улика не оставил порт (0 в слоте). */
#define VPIN_PROBE_FALLBACK_PORT 443
/* Одно измерение не решает судьбу пина: снимаем только после двух промахов
 * подряд (первый мог быть transient), перепроверка — через половину
 * интервала, но не чаще раза в 30 с. */
#define VPIN_FAILS_TO_UNPIN 2
#define VPIN_RETRY_MIN_S    30
/* Q_DIRECT: трижды «прямой мёртв» подряд — адрес, видимо, легитимно живёт
 * только в VPN; снимаем слот из аудита, иначе проверка прямого пути
 * перезапускалась бы вечно (постоянные fork'и). */
#define VPIN_DIRECT_MAXFAIL 3

/* Состояния пробы: 0 = адрес не отвечает, 1 = отвечает, 2 = мерить нечем
 * (SOCKS не слушает / датаплейн вниз). На «2» родитель ничего не снимает —
 * это состояние инфраструктуры, а не адреса. */
enum { VPIN_PROBE_DEAD = 0, VPIN_PROBE_OK = 1, VPIN_PROBE_NA = 2 };

static pid_t vq_pid = 0;
static int vq_fd = -1;
static time_t vq_start = 0;
static char vq_buf[1024];
static size_t vq_len = 0;

static int vq_retry_iv(const susanin_config *cfg)
{
    int iv = cfg->vpin_interval / 2;
    return iv > VPIN_RETRY_MIN_S ? iv : VPIN_RETRY_MIN_S;
}

static void vq_stop(void);   /* defined below; нужен выключению аудита в vq_tick */

/* Снять пин и вернуть адрес на прямой путь мягко (susanin_direct). */
static void vq_unpin(susanin_state *stp, const susanin_config *cfg, const char *ip, time_t now)
{
    int udp;
    for (udp = 0; udp < 2; udp++) {
        state_remove(st_ok(stp, udp), ip);
        state_remove(st_test(stp, udp), ip);
        backend_ipset_del(cfg, udp, 0, ip);
        backend_ipset_del(cfg, udp, 1, ip);
    }
    /* Живые соединения держат старую метку: без сброса долгоживущий сокет
     * (WebSocket/pull) остался бы на мёртвом пути до собственного таймаута. */
    backend_ct_flush_ip(ip);
    if (cfg->direct_pref_ttl > 0) {
        backend_set_add(cfg, "susanin_direct", ip, cfg->direct_pref_ttl);
        state_add(&stp->direct, ip, now, cfg->direct_pref_ttl, 0);
    }
}

/* Вердикт привязан к адресу и запрошенному состоянию, а не к индексу слота:
 * между fork пробы и сбором результатов слот могли вытеснить новым адресом
 * (очередь конечна), и прежнее «применить к idx» снимало бы чужой пин.
 * Слот не найден или состояние сменилось — вердикт отбрасываем в skip. */
static void vq_apply(susanin_state *stp, const susanin_config *cfg,
                     const char *ip, int state, int ok, int lat, time_t now)
{
    int i = vpin_find(ip, state);
    int nf;

    if (i < 0) {
        vpin_bump(3);
        return;
    }
    if (state == VPIN_Q_VPN) {
        if (ok == VPIN_PROBE_NA) {
            /* Мерить было нечем (Xray лёг / SOCKS не слушает / датаплейн
             * вниз): это не новость про адрес. Снимаем только «срок проверки
             * просрочен», никаких снятий пина. */
            vpin_bump(3);
            vpin_set(i, VPIN_Q_VPN, now);
            return;
        }
        if (ok == VPIN_PROBE_OK && lat <= VPIN_SLOW_MS) {
            vpin_set(i, VPIN_Q_DIRECT, now);
            return;
        }
        nf = vpin_fail(i, now, vq_retry_iv(cfg));
        if (nf < VPIN_FAILS_TO_UNPIN) {
            slogf(SL_DEBUG, "VPIN: %s — %s через туннель (%d мс), промах %d/%d, "
                  "перепроверка через %d с", ip,
                  ok == VPIN_PROBE_OK ? "медленно" : "нет ответа", lat, nf,
                  VPIN_FAILS_TO_UNPIN, vq_retry_iv(cfg));
            return;
        }
        /* Снятие пина — решение с трафик-эффектом: при дефолтном
         * log_level=warn оно обязано быть видно в логе. */
        vpin_bump(ok == VPIN_PROBE_OK ? 1 : 0);
        slogf(SL_WARN, "VPIN: %s — %s через туннель (%d мс), два промаха подряд, "
              "возвращаю напрямую", ip,
              ok == VPIN_PROBE_OK ? "медленно" : "нет ответа", lat);
        vq_unpin(stp, cfg, ip, now);
        vpin_free_idx(i);
        return;
    }
    /* Q_DIRECT: ожил ли прямой путь. */
    if (ok == VPIN_PROBE_NA) {
        vpin_bump(3);
        vpin_set(i, VPIN_Q_DIRECT, now);
        return;
    }
    if (ok == VPIN_PROBE_OK) {
        vpin_bump(2);
        slogf(SL_WARN, "VPIN: %s — прямой путь снова жив, снимаю VPN-пин", ip);
        vq_unpin(stp, cfg, ip, now);
        vpin_free_idx(i);
        return;
    }
    nf = vpin_fail(i, now, 0);
    if (nf >= VPIN_DIRECT_MAXFAIL) {
        /* Прямой стабильно мёртв: адрес легитимно живёт только в VPN,
         * бессмысленно вечно перезапускать пробы. */
        slogf(SL_DEBUG, "VPIN: %s — прямой мёртв %d раз подряд, снимаю с аудита",
              ip, nf);
        vpin_free_idx(i);
    }
}

static void vq_collect(susanin_state *stp, const susanin_config *cfg, time_t now)
{
    if (vq_fd >= 0) {
        for (;;) {
            ssize_t r = read(vq_fd, vq_buf + vq_len, sizeof(vq_buf) - vq_len - 1);
            char *p;
            if (r <= 0)
                break;
            vq_len += (size_t)r;
            vq_buf[vq_len] = '\0';
            p = vq_buf;
            for (;;) {
                char *nl = strchr(p, '\n');
                char ip[16];
                int stt, ok, lat;
                if (!nl)
                    break;
                *nl = '\0';
                if (sscanf(p, "%15s %d %d %d", ip, &stt, &ok, &lat) == 4)
                    vq_apply(stp, cfg, ip, stt, ok, lat, now);
                p = nl + 1;
            }
            vq_len = strlen(p);
            memmove(vq_buf, p, vq_len + 1);
            if (vq_len + 1 >= sizeof(vq_buf))
                vq_len = 0;
        }
    }
    if (vq_pid > 0) {
        int wst;
        pid_t w = waitpid(vq_pid, &wst, WNOHANG);
        int hung = (now - vq_start) > 60;
        if (w == vq_pid || hung) {
            if (w != vq_pid) {
                kill(vq_pid, SIGKILL);
                waitpid(vq_pid, &wst, 0);
            }
            if (vq_fd >= 0)
                close(vq_fd);
            vq_fd = -1;
            vq_pid = 0;
        }
    }
}

/* Снимок очереди/счётчиков для `status` и `why`: это отдельные процессы,
 * память движка им недоступна (тот же путь, что и со счётчиками dns_sniff).
 * Пишем только при изменении; в disk_mode=soft не пишем вовсе — смысл режима
 * в отсутствии записей на носитель. */
static void vq_status_write(const susanin_config *cfg)
{
    static char last[3584];
    char buf[3584], wp[64];
    int m;

    if (!strcmp(cfg->disk_mode, "soft"))
        return;
    m = vpin_format(buf, sizeof(buf), cfg->vpin_check, cfg->vpin_interval);
    if (m <= 0 || !strcmp(buf, last))
        return;
    snprintf(last, sizeof(last), "%s", buf);
    snprintf(wp, sizeof(wp), "%s.tmp", VPIN_STATS_FILE);
    {
        FILE *f = fopen(wp, "w");
        if (!f)
            return;
        fprintf(f, "%s\n", buf);
        fclose(f);
        rename(wp, VPIN_STATS_FILE);
    }
}

static void vq_child(const susanin_config *cfg, const int *idx, int n, int fd)
{
    int k;
    /* «Нечем мерить» решаем здесь, в ребёнке: backend_ready() — это форки
     * iptables/ip, а главный цикл блокировать нельзя. Локальный SOCKS —
     * дверь в туннель Xray: если его некому слушать или правила датаплейна
     * сняты, ответ пробы ничего не говорит про адрес. */
    int socks_port = cfg->socks_port > 0 ? cfg->socks_port : CFG_DEF_SOCKS_PORT;
    int vpn_measurable = backend_local_listen(socks_port) && backend_ready(cfg);

    for (k = 0; k < n; k++) {
        const char *ip = vpin_ip(idx[k]);
        int stt = vpin_state(idx[k]);
        unsigned port = (unsigned)vpin_port(idx[k]);
        struct timespec t0, t1;
        int ok, lat;
        char line[64];
        if (!ip)
            continue;
        /* Пробуем тот порт, на котором адрес подтвердил жизнь (улика из
         * потока), а не 443: IPTV/медиа-сервисы на 8000/1935/554 на 443
         * молчат, и «нет ответа» означало бы снятие живого пина. */
        if (port == 0)
            port = VPIN_PROBE_FALLBACK_PORT;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        if (stt == VPIN_Q_VPN)
            ok = vpn_measurable
                     ? health_probe_via_socks(cfg, ip, (int)port, VPIN_TIMEOUT_MS)
                     : VPIN_PROBE_NA;
        else
            ok = health_probe_tcp_direct(ip, port, VPIN_TIMEOUT_MS) ? 1 : 0;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        lat = (int)((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000);
        /* Строка привязана к адресу и запрошенному состоянию: родитель
         * сверит их со своей очередью (слот за время пробы мог смениться). */
        snprintf(line, sizeof(line), "%s %d %d %d\n", ip, stt, ok, lat);
        if (write(fd, line, strlen(line)) < 0)
            break;
    }
}

static void vq_tick(susanin_state *stp, const susanin_config *cfg, time_t now)
{
    int idx[VPIN_BATCH], n, fd[2];
    pid_t pid;
    int vpn_iv, direct_iv;

    if (!cfg->vpin_check) {
        /* Аудит выключен (в т.ч. Reload-ом): незавершённого ребёнка
         * обязательно пожинать — иначе зомби висит в таблице процессов
         * до выхода движка. Снимок пишем и тут: `status` не должен
         * показывать устаревшее «check=1». */
        if (vq_pid > 0)
            vq_stop();
        vq_status_write(cfg);
        return;
    }
    vq_status_write(cfg);
    if (vq_pid > 0) {
        vq_collect(stp, cfg, now);
        return;
    }
    vpn_iv = cfg->vpin_interval;
    /* Без переполнения signed: парсер клампится в INT_MAX, и «vpn_iv * 2»
     * на большом интервале давало бы отрицательный direct_iv — все Q_DIRECT
     * становились due каждый проход цикла. */
    direct_iv = vpn_iv > INT_MAX / 2 ? INT_MAX : vpn_iv * 2;
    n = vpin_due(now, vpn_iv, direct_iv, idx, VPIN_BATCH);
    if (n <= 0)
        return;
    /* Никакой фильтрации Q_VPN постфактум: в режиме без туннельной пробы
     * vpin_note кладёт записи сразу в Q_DIRECT, а при смене режима
     * vpin_set_tunnel_probe переводит существующие. Прежний фильтр
     * оставлял отброшенные Q_VPN вечно due и вытеснял Q_DIRECT из batch. */
    if (pipe(fd) != 0)
        return;
    pid = fork();
    if (pid < 0) {
        close(fd[0]);
        close(fd[1]);
        return;
    }
    if (pid == 0) {
        close(fd[0]);
        vq_child(cfg, idx, n, fd[1]);
        _exit(0);
    }
    close(fd[1]);
    (void)fcntl(fd[0], F_SETFL, O_NONBLOCK);
    vq_fd = fd[0];
    vq_pid = pid;
    vq_start = now;
    vq_len = 0;
}

static void vq_stop(void)
{
    if (vq_pid > 0) {
        int wst;
        kill(vq_pid, SIGKILL);
        waitpid(vq_pid, &wst, 0);
        vq_pid = 0;
    }
    if (vq_fd >= 0) {
        close(vq_fd);
        vq_fd = -1;
    }
    vq_len = 0;
}

/* Есть ли УЖЕ процесс Xray с НАШИМ конфигом. Нужен, чтобы watchdog не поднимал
 * новый экземпляр поверх зависшего: на роутере накопилось
 * ~14 процессов `xray run -config /opt/susanin/etc/xray-tproxy.json` (часть в
 * состоянии D), память 101/122 МБ, load average ~20 — интернет «завис». Причина:
 * stop/start Xray опирался на `pidof xray` (в окружении init-скриптов его может
 * не быть) и на один SIGTERM без ожидания завершения.
 *
 * Условие строгое: в cmdline должны быть И «xray», И наш конфиг, И «run»
 * (иначе открытый `vi xray-tproxy.json` или `tail -f` по этому файлу выглядели бы
 * как «наш Xray» и блокировали watchdog). */
static int xray_proc_exists(void)
{
    DIR *d = opendir("/proc");
    struct dirent *de;
    int found = 0;

    if (!d)
        return 0;
    while (!found && (de = readdir(d)) != NULL) {
        char path[80], buf[512];
        size_t n, i;
        FILE *f;
        if (de->d_name[0] < '0' || de->d_name[0] > '9')
            continue;
        snprintf(path, sizeof(path), "/proc/%.12s/cmdline", de->d_name);
        f = fopen(path, "r");
        if (!f)
            continue;
        n = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        buf[n] = '\0';
        for (i = 0; i < n; i++)
            if (buf[i] == '\0')
                buf[i] = ' ';
        if (backend_is_our_xray_cmdline(buf))
            found = 1;
    }
    closedir(d);
    return found;
}

/* Watchdog Xray: поднять упавший процесс (tproxy). Пробуем init-скрипт
 * (перезапускает Xray с актуальным xray_loglevel/GOGC/GOMEMLIMIT), иначе —
 * прямой запуск бинаря. Возврат rc system(); 0/неважно — проверяем порт.
 *
 * Два важных момента:
 *  - запуск делаем АСИНХРОННО (`&`): S93 restart теперь ждёт завершения процесса
 *    (до 15 с) и стартует с паузой, а блокировать главный цикл агента нельзя —
 *    вызывающая сторона и так опрашивает порт после вызова;
 *  - «есть ли наш процесс» проверяем из C через xray_proc_exists(), а не через
 *    `sh -c`-цикл по /proc: командная строка самого sh содержит путь к конфигу,
 *    поэтому прежний цикл находил САМ СЕБЯ, делал exit 0 и никогда не запускал
 *    Xray (проверено экспериментом). */
/* Причина последнего неудачного запуска Xray — для лога и диагностики.
 * Раньше spawn() молча возвращал -1, и в логе оставалось только «не удалось
 * запустить», без причины: наблюдения показали, что по такому логу
 * нельзя отличить отсутствие бинаря от нехватки ресурсов на fork(). */
static char xray_spawn_err[160];
static char g_agentlog[256];   /* путь файла лога агента ('' = soft/no file) */

/* Свободная память ядра, КБ (из /proc/meminfo); -1 — не прочитать. */
static long mem_available_kb(void)
{
    FILE *f = fopen("/proc/meminfo", "r");
    char line[128];
    long kb = -1;

    if (!f)
        return -1;
    while (fgets(line, sizeof(line), f)) {
        if (!strncmp(line, "MemAvailable:", 13)) {
            kb = strtol(line + 13, NULL, 10);
            break;
        }
    }
    fclose(f);
    return kb;
}

/* Что было в конце прошлого запуска. Нужено потому, что после обрыва питания
 * или OOM-убийства первая строка нового лога — единственное, что оператор
 * видит, а последняя строка старого («почему всё встало») остаётся необработанной
 * где-то в середине файла. Читаем только то, что было в файле ДО нас. */
static void log_prev_run(off_t upto)
{
    char buf[4096];
    char l1[256], l2[256];
    size_t got = 0, len;
    off_t from;
    int clean = 0, n = 0;
    char *p;
    FILE *f;

    if (upto <= 0 || !g_agentlog[0])
        return;
    f = fopen(g_agentlog, "rb");
    if (!f)
        return;
    from = upto - (off_t)sizeof(buf);
    if (from < 0)
        from = 0;
    if (fseek(f, (long)from, SEEK_SET) != 0) {
        fclose(f);
        return;
    }
    got = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (!got)
        return;
    buf[got] = '\0';
    if (strstr(buf, "engine stopped"))
        clean = 1;

    /* две последние непустые строки того запуска (идём с конца) */
    l1[0] = l2[0] = '\0';
    p = buf + got;
    while (p > buf && n < 2) {
        char *e = p;
        char *dst;

        while (p > buf && *(p - 1) != '\n')
            p--;
        if (e - p > 1) {
            dst = (n == 0) ? l1 : l2;
            len = (size_t)(e - p);
            if (len >= sizeof(l1))
                len = sizeof(l1) - 1;
            memcpy(dst, p, len);
            dst[len] = '\0';
            n++;
        }
        if (p > buf)
            p--;                       /* пропустить перевод строки */
    }

    if (clean)
        slogf(SL_INFO, "прошлый запуск завершён штатно; его последняя строка: %s", l1);
    else
        slogf(SL_WARN, "прошлый запуск не завершался штатно (обрыв питания, kill или "
              "зависание). Строки того запуска: [%s]%s%s",
              l1, l2[0] ? " | " : "", l2);
}

/* Сколько device работает: по /proc/uptime. Отделяет «упал сервис» от
 * «перезагрузилось устройство» — без этого в логе эти два случая выглядят
 * одинаково («engine started»). */
static void log_boot_age(void)
{
    double up = 0;
    FILE *f = fopen("/proc/uptime", "r");

    if (f) {
        if (fscanf(f, "%lf", &up) != 1)
            up = 0;
        fclose(f);
    }
    slogf(SL_INFO, "uptime устройства: %.0f с%s", up,
          up < 120 ? " (устройство только что загрузилось)" : "");
}

/* Обрезка лога Xray до max_kb. На роутере без swap большой лог — это прямая
 * потеря памяти: /tmp/xray.log вырос до 15 МБ в tmpfs, свободная
 * память ушла ниже watermark и OOM-killer убил сам Xray (интернет встал).
 * max_kb <= 0 — не трогаем. */
#define XRAY_LOG_PATH "/opt/susanin/var/xray.log"

static void xray_log_trim(int max_kb)
{
    const char *path = XRAY_LOG_PATH;
    struct stat st;
    int fd;

    if (max_kb <= 0)
        return;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return;
    if (st.st_size <= (off_t)max_kb * 1024)
        return;
    fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0)
        return;
    close(fd);
    slogf(SL_INFO, "tproxy: xray.log обрезан (был больше %d КБ)", max_kb);
}

/* Можно ли сейчас поднимать Xray: при свободной памяти меньше порога запуск
 * только приближает OOM, и ядро убьёт Xray через секунды после старта
 * (попытки подряд, каждая заканчивалась убийством процесса).
 * Возврат: 1 — можно, 0 — нельзя. */
static int xray_mem_ok(const susanin_config *cfg)
{
    long avail;

    if (cfg->xray_min_mem_kb <= 0)
        return 1;
    avail = mem_available_kb();
    if (avail < 0)              /* /proc/meminfo недоступен — не мешаем старту */
        return 1;
    return avail >= cfg->xray_min_mem_kb;
}

/* Дети, которых агент породил сам (прямой старт xray, shell S93): их надо
 * пожинать, иначе после каждого падения Xray в /proc копятся зомби.
 * Массив маленький — дольше 2–3 процессов живой породы за раз не бывает. */
static pid_t g_xray_kids[4];

static void kid_track(pid_t p)
{
    int i;
    if (p <= 0)
        return;
    for (i = 0; i < 4; i++)
        if (g_xray_kids[i] == p)
            return;
    for (i = 0; i < 4; i++) {
        if (g_xray_kids[i] <= 0) {
            g_xray_kids[i] = p;
            return;
        }
    }
    {
        int st;
        (void)waitpid(g_xray_kids[0], &st, WNOHANG);  /* не копим зомби при вытеснении */
        g_xray_kids[0] = p;
    }
}

/* Вызывается из главного цикла: собираем завершившихся детей без блокировки.
 * waitpid только по нашим pid — чужих (probe_job) не трогаем. */
static void kids_poll(void)
{
    int i;
    for (i = 0; i < 4; i++) {
        pid_t p = g_xray_kids[i];
        if (p > 0) {
            int st;
            pid_t r = waitpid(p, &st, WNOHANG);
            if (r == p || (r < 0 && errno != EINTR))
                g_xray_kids[i] = 0;
        }
    }
}

/* Записать pid нашего Xray туда же, куда пишет S93xray-tproxy: тогда
 * `S93 status/stop` видят процесс, поднятый агентом (в 0.4.5 pidfile терялся). */
static void write_xray_pidfile(pid_t pid)
{
    FILE *f = fopen("/opt/susanin/var/xray.pid", "w");
    if (f) {
        fprintf(f, "%d\n", (int)pid);
        fclose(f);
    }
}

/* Прямой запуск Xray без shell: fork/execl. Это FALLBACK: на роутере
 * S93xray-tproxy падал с "sh: -c requires an argument", и Xray не поднимался
 * вообще. Штатный путь — S93 (см. restart_xray_process).
 * Возврат: 0 — процесс создан, -1 — не удалось (причина в xray_spawn_err). */
static int spawn_xray_direct(const susanin_config *cfg)
{
    pid_t pid;
    int fd;

    xray_spawn_err[0] = '\0';
    /* r7.7: порт уже слушается — Xray жив. Потеря pidfile (read-only носитель,
     * сбой журнала) не повод плодить второй экземпляр: на Viva накопилось 9
     * процессов xray, туннель дышал на ладан. */
    if (backend_local_listen(cfg->tproxy_port))
        return 0;
    if (!xray_mem_ok(cfg)) {
        snprintf(xray_spawn_err, sizeof(xray_spawn_err),
                 "мало свободной памяти: MemAvailable=%ld КБ < xray_min_mem_kb=%d",
                 mem_available_kb(), cfg->xray_min_mem_kb);
        return -1;
    }
    xray_log_trim(cfg->xray_log_max_kb);
    if (access("/opt/sbin/xray", X_OK) != 0) {
        snprintf(xray_spawn_err, sizeof(xray_spawn_err), "access /opt/sbin/xray: %s",
                 strerror(errno));
        return -1;
    }
    pid = fork();
    if (pid < 0) {
        snprintf(xray_spawn_err, sizeof(xray_spawn_err), "fork: %s", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        setsid();
        fd = open("/opt/susanin/var/xray.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            dup2(fd, 1);
            dup2(fd, 2);
            if (fd > 2)
                close(fd);
        }
        /* GOGC/GOMEMLIMIT — из конфига (xray_gogc / xray_gomemlimit). Раньше
         * здесь были зашиты 50/64MiB, и эти ключи действовали только при
         * запуске через S93: настройка из susanin.conf молча игнорировалась. */
        setenv("GOGC", cfg->xray_gogc[0] ? cfg->xray_gogc : "50", 1);
        setenv("GOMEMLIMIT", cfg->xray_gomemlimit[0] ? cfg->xray_gomemlimit : "64MiB", 1);
        execl("/opt/sbin/xray", "xray", "run", "-config",
              "/opt/susanin/etc/xray-tproxy.json", (char *)NULL);
        _exit(127);
    }
    kid_track(pid);
    write_xray_pidfile(pid);
    return 0;
}

/* Асинхронный запуск штатного init-скрипта (S93xray-tproxy restart|start):
 * без shell -c (тот и падал «sh: -c requires an argument» через system()),
 * ребёнок пишет лог Xray и сам ведёт pidfile/loglevel. Главный цикл НЕ
 * блокируется: успех проверяется следующим витком по порту. */
static void spawn_xray_init(const char *action)
{
    pid_t pid;

    pid = fork();
    if (pid < 0)
        return;
    if (pid != 0) {
        kid_track(pid);
        return;
    }
    setsid();
    {
        int fd = open("/opt/susanin/var/xray.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            dup2(fd, 1);
            dup2(fd, 2);
            if (fd > 2)
                close(fd);
        }
    }
    execl("/bin/sh", "sh", "/opt/etc/init.d/S93xray-tproxy", action, (char *)NULL);
    _exit(127);
}

/* Подождать, пока Xray займёт порт. Возврат: 0 — слушает, -1 — не дождались.
 * Проверяем порт, а не pid: процесс может существовать, но не забиндиться. */
static int wait_xray_port(const susanin_config *cfg, int secs)
{
    int w;
    for (w = 0; w <= secs; w++) {
        if (backend_local_listen(cfg->tproxy_port))
            return 0;
        if (w < secs)
            sleep(1);
    }
    return -1;
}

/* Поднять Xray. Штатный путь — S93xray-tproxy (асинхронно: свой pidfile,
 * loglevel/GOGC/GOMEMLIMIT, проверка «удержался»). Прямой fork — только если
 * S93 нет/не исполняется (fallback для окружений, где S93 падал).
 * НИЧЕГО НЕ ЖДЁТ ВНУТРИ: главный цикл однопоточный, и ожидание порта здесь
 * останавливал бы dns_sniff и обучение (регресс watchdog в 0.4.6: блокировка
 * до ~30 с на попытку при backoff 60 с). Успех проверяет следующий виток
 * reconcile (dp_check_interval).
 * Возврат: 0 — породили запуск / процесс уже есть; -1 — поднять не можем. */
static int restart_xray_process(const susanin_config *cfg)
{
    /* Памятный гейт активен только при явном xray_min_mem_kb>0 (по умолчанию
     * 0 = выключен, как в 0.4.4): на 122 МБ роутере с порогом 12288 КБ Xray
     * почти никогда не поднимался после падения — долгий fail-open DIRECT и
     * «сайты грузятся медленно» (регрессия 0.4.6). */
    if (!xray_mem_ok(cfg)) {
        slogf(SL_WARN,
              "tproxy: Xray не поднимаю — мало памяти (MemAvailable=%ld КБ, порог %d КБ)",
              mem_available_kb(), cfg->xray_min_mem_kb);
        return -1;
    }

    if (xray_proc_exists()) {
        /* Процесс уже есть: второй экземпляр не поднимаем (накопление процессов
         * вешало роутер). Освободить зависший — restart_xray_forced(). */
        return 0;
    }

    xray_log_trim(cfg->xray_log_max_kb);
    if (access("/opt/etc/init.d/S93xray-tproxy", X_OK) == 0) {
        spawn_xray_init("restart");
        slogf(SL_INFO, "tproxy: запуск Xray через S93xray-tproxy restart (асинхронно)");
        return 0;
    }
    if (spawn_xray_direct(cfg) == 0) {
        slogf(SL_WARN, "tproxy: S93xray-tproxy недоступен — подняли Xray напрямую (fallback)");
        return 0;
    }
    slogf(SL_ERROR, "tproxy: Xray не запустить: %s", xray_spawn_err);
    return -1;
}


/* Снять все процессы Xray с нашим конфигом — из C, без sh -c. Важно: цикл на
 * shell тут не годится — в его собственной командной строке есть литерал запуска
 * Xray ("... xray run -config /opt/susanin/etc/xray-tproxy.json"), поэтому он
 * находит САМ СЕБЯ и убивает свой же shell (замечание повторной проверки: тот же
 * класс ошибки, что и раньше). Возврат — сколько процессов снято. */
static int xray_kill_all(void)
{
    DIR *d = opendir("/proc");
    struct dirent *de;
    int killed = 0;

    if (!d)
        return 0;
    while ((de = readdir(d)) != NULL) {
        char path[80], buf[512];
        size_t n, i;
        FILE *f;
        long pid;
        if (de->d_name[0] < '0' || de->d_name[0] > '9')
            continue;
        pid = strtol(de->d_name, NULL, 10);
        if (pid <= 1 || pid == (long)getpid())
            continue;
        snprintf(path, sizeof(path), "/proc/%.12s/cmdline", de->d_name);
        f = fopen(path, "r");
        if (!f)
            continue;
        n = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        buf[n] = '\0';
        for (i = 0; i < n; i++)
            if (buf[i] == '\0')
                buf[i] = ' ';
        if (backend_is_our_xray_cmdline(buf) && kill((pid_t)pid, SIGKILL) == 0)
            killed++;
    }
    closedir(d);
    return killed;
}

/* Принудительный перезапуск зависшего (живого, но не слушающего порт) Xray:
 * S93 restart умеет kill -9 и отказывается стартовать при процессе в D; без
 * init-скрипта снимаем процессы сами (xray_kill_all) и поднимаем заново. */
static void restart_xray_forced(const susanin_config *cfg)
{
    if (xray_kill_all() > 0) {
        int w;
        for (w = 0; w < 20 && xray_proc_exists(); w++)
            usleep(100000);
    }
    (void)restart_xray_process(cfg);
}

/* P2: per-profile failover — держим default в таблице профиля на первом живом
 * egress из profileN_egress (список через запятую). Идемпотентно, раз в 30 c. */
static void profile_failover_tick(const susanin_config *cfg)
{
    int p;
    if (!cfg->profile_failover)
        return;
    for (p = 0; p < cfg->n_profiles && p < CFG_MAX_PROFILES; p++) {
        char buf[CFG_PATH_MAX], chosen[64] = "", *save = NULL, *tok;
        int tbl;
        if (!cfg->profile_egress[p][0])
            continue;
        tbl = cfg->profile_table[p] ? cfg->profile_table[p] : (201 + p);
        snprintf(buf, sizeof(buf), "%s", cfg->profile_egress[p]);
        for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
            char np[256];
            while (*tok == ' ' || *tok == '\t')
                tok++;
            if (!*tok)
                continue;
            snprintf(np, sizeof(np), "/sys/class/net/%s", tok);
            if (access(np, F_OK) == 0) {
                snprintf(chosen, sizeof(chosen), "%s", tok);
                break;
            }
        }
        if (!chosen[0])
            continue;
        {
            char cmd[300];
            int rc;
            snprintf(cmd, sizeof(cmd),
                     "ip route replace default dev %s table %d >/dev/null 2>&1",
                     chosen, tbl);
            rc = system(cmd);
            (void)rc;
        }
    }
}

/* Применить профили (P1/P2). Статические наборы профилей, ip rule и маршрут в
 * таблице профиля пересобирает tools/profiles.sh. Раньше он вызывался ТОЛЬКО из
 * init-скрипта при старте службы, поэтому «правка конфига → Reload» профили не
 * применяла, хотя подсказка панели обещала обратное. */
static void profiles_apply(const susanin_config *cfg)
{
    int rc;
    if (!cfg || cfg->n_profiles <= 0)
        return;
    rc = system("sh /opt/susanin/tools/profiles.sh up >/dev/null 2>&1");
    if (rc == 0)
        slogf(SL_INFO, "profiles: применено %d профил(ей) (profiles.sh up)", cfg->n_profiles);
    else
        slogf(SL_WARN, "profiles: profiles.sh up завершился с кодом %d (профили могут не работать)", rc);
}

/* Стартовый egress (и после reload). Режим датаплейна задаёт конфиг: при
 * egress_type=tproxy физические интерфейсы в egress_interface — это транспорт
 * или резерв Xray, а не запрос на смену режима. Раньше здесь безусловно звали
 * backend_set_egress(egress_list[0]), и при tproxy+первом интерфейсе агент сам
 * снимал tproxy-правила (регрессия RC1). Если в списке есть псевдоним
 * tproxy/xray — стартуем с него. */
static int engine_pick_start_egress(const susanin_config *cfg)
{
    int i;
    if (cfg->n_egress <= 0)
        return 0;
    if (strcmp(cfg->egress_type, "tproxy") != 0) {
        backend_set_egress(cfg, cfg->egress_list[0]);
        return 0;
    }
    for (i = 0; i < cfg->n_egress; i++) {
        if (egress_is_tproxy(cfg->egress_list[i])) {
            backend_set_egress(cfg, cfg->egress_list[i]);
            return i;
        }
    }
    return 0;   /* tproxy уже активен по конфигу — переключать нечего */
}

/* Значения, которые код прочтёт иначе, чем задумано, должны быть видны в логе,
 * а не в поведении: молчаливый кламп, «агрегация выключилась из-за
 * отрицательного порога» или «метрики неразличимы из-за mask=0» обнаруживаются
 * только по факту простоя. stage — откуда проверяем (старт/reload), чтобы в
 * логе было понятно, каким конфигом живёт процесс.
 *
 * Проверка не меняет ни одного значения: право молча подменять конфиг
 * оператора — это ровно тот класс ошибок, который мы убираем. */
static void cfg_check(const susanin_config *cfg, const char *stage)
{
    char prob[2048];
    const char *p = prob;
    int n;

    n = config_validate(cfg, prob, sizeof(prob));
    if (n <= 0)
        return;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        char one[512];

        if (len >= sizeof(one))
            len = sizeof(one) - 1;
        memcpy(one, p, len);
        one[len] = '\0';
        slogf(SL_WARN, "конфиг (%s): %s", stage, one);
        if (!nl)
            break;
        p = nl + 1;
    }
}

/* Нижняя граница интервала аудита — 30 с: проба — это ребёнок с сетевыми
 * таймаутами по 2.5 с, интервал 0/1 превращал бы цикл в вечную гонку fork'ов.
 * Клампим ОДИН раз при старте/перечитывании и говорим об этом в логе — молча
 * подменять конфиг оператора нельзя, а кламппить каждый проход бессмысленно
 * (замечание о значении печатает config_validate). */
static void vpin_interval_fix(susanin_config *cfg)
{
    if (cfg->vpin_interval < VPIN_RETRY_MIN_S) {
        slogf(SL_WARN, "vpin_interval=%d: минимальный период аудита пинов %d с — "
              "дальше работает %d", cfg->vpin_interval, VPIN_RETRY_MIN_S,
              VPIN_RETRY_MIN_S);
        cfg->vpin_interval = VPIN_RETRY_MIN_S;
    }
}

int engine_run(susanin_config *cfg, const char *conf_path)
{
    susanin_state st;
    classifier_ctx ctx;
    flowlist L;
    vpn_always *va = NULL;
    vpn_never *nv = NULL;
    int tunnel_up = 1, dp_ok = 0, ei = 0, dp_fails = 0;
    int eg_up[CFG_MAX_EGRESS];
    int eg_miss[CFG_MAX_EGRESS];
    int eg_lat[CFG_MAX_EGRESS];
    time_t eg_up_since[CFG_MAX_EGRESS];
    time_t last[4] = { 0, 0, 0, 0 };
    time_t last_save = 0;
    time_t last_recon = 0;
    time_t last_dpfast = 0;
    time_t dp_unk_since = 0;   /* с какого момента датаплейн не удаётся проверить */
    time_t next_dp_try = 0;
    time_t last_force = 0;
    time_t last_never = 0;
    int never_pending = 0;
    /* Явный Reload: списки перечитываются в этом же проходе, но сами refresh-и
     * молчат, когда меняться нечему. Флаг нужен, чтобы по одному разу сказать
     * оператору, что именно перечитано (или почему не перечитано). */
    int just_reloaded = 0;
    time_t last_trim = 0;
    time_t last_sweep = 0;
    time_t last_nsweep = 0;
    time_t all_down_since = 0;
    time_t last_allwarn = 0;
    time_t last_cdn = 0;
    time_t last_release = 0;
    time_t next_xray_try = 0;
    time_t last_logrot = 0;
    off_t log_prev_size = 0;   /* размер лога до наших записей (для разбора прошлого запуска) */
    time_t last_xlogrot = 0;   /* рантайм-ротация xray.log (раз в минуту) */
    int xray_tries = 0;
    int stuck_tries = 0;      /* подряд «процесс есть, но порт не слушается» */
    int idle_mult = 1;        /* адаптивный период проходов классификатора (1 или 2) */
    int idle_cnt = 0;         /* подряд проходов без событий обучения */
    time_t last_dnssniff = 0;
    time_t last_prof = 0;
    int force_pending = 0;
    const char *state_path = "/opt/susanin/var/susanin.state";

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    signal(SIGHUP, on_hup);     /* reload конфига */
    {
        const char *lf = getenv("SUSANIN_LOG");
        struct stat lst;
        int soft = (strcmp(cfg->disk_mode, "soft") == 0);
        off_t prev_sz = (!soft && lf && *lf && stat(lf, &lst) == 0) ? lst.st_size : 0;

        /* disk_mode=soft означает, что ЛОГА НЕТ (см. TROUBLESHOOTING.md,
         * USER_GUIDE.md): вывод демона и панели уводится в /dev/null на уровне
         * susanin.sh, поэтому здесь не открываем свой fd и не запоминаем путь:
         * ротация файла, который никто не пишет, трогала бы носитель впустую.
         * Именно этого режима и не хватало: раньше редирект оболочки был
         * безусловный, и soft давал худшее сочетание — флешка стирается
         * записями, которые панель отказывается показывать. */
        if (lf && *lf && !soft) {
            int fd = open(lf, O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (fd >= 0) {
                dup2(fd, 1);
                dup2(fd, 2);
                if (fd > 2)
                    close(fd);
                snprintf(g_agentlog, sizeof(g_agentlog), "%s", lf);
            }
        }
        log_prev_size = prev_sz;
    }
    slog_init(cfg->log_level);
    backend_batch_enable(cfg->ipset_batch);
    if (g_agentlog[0] && path_on_tmpfs(g_agentlog))
        slogf(SL_WARN, "log: %s лежит на tmpfs (это RAM!): рост логов отнимает память, "
                       "при reboot улики исчезают. Держите лог на flash (так дешевле "
                       "для носителя, чем кажется) или disk_mode=soft", g_agentlog);
    if (strcmp(cfg->disk_mode, "soft") == 0)
        /* В soft это сообщение уходит в /dev/null — по определению режима.
         * Остаётся для случая, когда soft включён, а логи всё же пишутся
         * вручную (перенаправленный запуск без оболочки). */
        slogf(SL_INFO, "disk_mode=soft: лог не ведётся (вывод в /dev/null), "
              "state не сохраняется (кроме soft_state_interval), бэкапов нет");
    if (cfg->ok_ttl == 0)
        slogf(SL_WARN, "ok_ttl=0: выученные адреса не истекают (наборы будут расти); "
                       "рекомендуется конечный TTL, напр. ok_ttl=21600");
    if (cfg->udp_relay)
        udp_relay_start(cfg);
    if (cfg->dns_sniff || cfg->sni_sniff)
        dns_sniff_start(cfg);

    state_init(&st);
    vpin_reset();
    /* Режим туннельной пробы: локальный SOCKS (а значит, и смысл Q_VPN)
     * бывает только в tproxy; остальное очереди сообщает сам движок. */
    vpin_set_tunnel_probe(strcmp(cfg->egress_type, "tproxy") == 0, time(NULL));
    dns_sniff_set_state(&st);   /* пины dns_sniff переживают re-provision/рестарт */
    ctx.cfg = cfg;
    ctx.st = &st;
    memset(&L, 0, sizeof(L));

    {
        char perr[256];
        if (backend_preflight(cfg, perr, sizeof(perr)) != 0)
            slogf(SL_ERROR, "preflight: %s", perr);
    }
    if (cdn_load(cfg) > 0)
        slogf(SL_INFO, "CDN: загружено %d диапазонов из %s", cdn_count(), cfg->cdn_ranges_file);
    last_cdn = time(NULL);
    /* W6: кэш релиза читаем сразу, но сеть дёргаем не на старте, а через 30 с —
     * чтобы не удлинять запуск агента на недоступном GitHub. */
    release_init(cfg);
    last_release = time(NULL);
    if (cfg->release_check && cfg->release_check_interval > 30)
        last_release -= (time_t)(cfg->release_check_interval - 30);
    /* Стартуем с приоритетного egress (фейловер переключит при падении).
     * В tproxy-режиме режим не меняем: см. engine_pick_start_egress(). */
    ei = engine_pick_start_egress(cfg);
    {
        int i;
        time_t tn = time(NULL);
        for (i = 0; i < cfg->n_egress; i++) {
            eg_up[i] = 1;
            eg_miss[i] = 0;
            eg_up_since[i] = tn;
        }
    }
    if (strcmp(cfg->egress_type, "tproxy") == 0) {
        /* Xray мог запускаться параллельно — даём ему ~10 c забиндить порт,
         * иначе на старте уходим в fail-open из-за гонки. */
        (void)wait_xray_port(cfg, 10);
    }
    if (strcmp(cfg->egress_type, "tproxy") == 0 &&
        !backend_local_listen(cfg->tproxy_port) && cfg->xray_watchdog) {
        /* Xray не слушает — пробуем поднять watchdog'ом (свежий старт после ребута).
         * Если процесс УЖЕ есть (завис или не смог забиндить порт), новый не
         * поднимаем: иначе копятся экземпляры и заканчивается память. */
        if (xray_proc_exists()) {
            slogf(SL_WARN, "tproxy: процесс Xray есть, но порт %d не слушается — "
                           "повторный запуск пропускаю (нужен ручной restart)",
                  cfg->tproxy_port);
        } else {
            slogf(SL_WARN, "tproxy: порт %d не слушается — поднимаю Xray (watchdog)",
                  cfg->tproxy_port);
            (void)restart_xray_process(cfg);
        }
        /* Порт может открыться не сразу: на mipsel старт занимает секунды. */
        (void)wait_xray_port(cfg, 15);
    }
    if (strcmp(cfg->egress_type, "tproxy") == 0 &&
        !backend_local_listen(cfg->tproxy_port)) {
        /* Xray не слушает — tproxy-правила не поднимаем (иначе чёрная дыра). */
        slogf(SL_ERROR,
              "tproxy: порт %d не слушается (Xray не запущен?) — правила НЕ поднимаю, "
              "трафик DIRECT. Запустите: /opt/etc/init.d/S93xray-tproxy start",
              cfg->tproxy_port);
        backend_teardown(cfg);
        dp_ok = 0;
        next_dp_try = time(NULL) + 15;
    } else if (backend_provision(cfg) == 0) {
        dp_ok = 1;
        dp_fails = 0;
        profiles_apply(cfg);
    } else {
        slogf(SL_ERROR, "data plane is NOT active; traffic stays DIRECT until set-up succeeds");
        dp_fails = 1;
        next_dp_try = time(NULL) + 60;
    }
    if (state_load(state_path, &st) == 0)
        slogf(SL_INFO, "restored cache from %s", state_path);
    if (tunnel_up)
        resync_sets(cfg, &st);
    if (cfg->vpn_always_file[0])
        va = va_new();
    if (cfg->vpn_never_file[0])
        nv = vn_new();
    slogf(SL_INFO, "engine started (egress=%s table=%d)", cfg->egress_interface, cfg->routing_table);
    log_boot_age();
    log_prev_run(log_prev_size);
    cfg_check(cfg, "старт");
    vpin_interval_fix(cfg);
    if (va && tunnel_up) {
        last_force = time(NULL);
        backend_batch_begin();
        force_pending = va_refresh(va, cfg);
        backend_batch_end();
    }
    if (nv) {
        int nchanged = 0;
        last_never = time(NULL);
        backend_batch_begin();
        never_pending = vn_refresh2(nv, cfg, &nchanged);
        backend_batch_end();
        /* Тяжёлую чистку state делаем только при реальном изменении набора. */
        if (nchanged)
            never_state_clean(cfg, &st, last_never);
    }

    while (!g_stop) {
        time_t now = time(NULL);

        kids_poll();     /* пожинать детей прямого запуска Xray/S93 (без зомби) */
        udp_relay_tick();    /* работник жив? перезапуск убитого/упавшего (B1) */

        if (cfg->dns_sniff || cfg->sni_sniff) {
            static time_t sn_at;
            char sn[512];

            /* Один poll за проход: раньше dns_sniff_poll() вызывался дважды
             * при dns_sniff=1 (второй — пережиток, когда SNI жил отдельным
             * вызовом), и каждый кадр вычитывался из сокетов в два захода. */
            dns_sniff_poll();   /* DNS-ответы и SNI из TLS ClientHello */
            /* Раз в 5 минут: сводка на DEBUG, снимок для status/why и не более
             * одного WARN. Прежнее одно условие «пакеты идут, сохранено 0»
             * сливало три разные поломки в одну и допускало вывод про
             * «направление захвата», который счётчики не доказывали: тот же
             * «0 сохранено» дают не-DNS-трафик и битый разбор ответов.
             * Случай «кадров нет вовсе» предупреждением не отмечаем: это
             * может быть тишина в доме, а различить его помогают status/why.
             * Контур обслуживания — общий для DNS- и SNI-снифинга. */
            if (!sn_at) {
                sn_at = now;
                /* Снимок и на первом проходе: счётчики обнулены после
                 * рестарта, а иначе status/why до пяти минут показывали бы
                 * прошлый запуск. */
                dns_sniff_stats_write(cfg);
            } else if (now - sn_at >= 300) {
                sn_at = now;
                dns_sniff_stats(sn, sizeof(sn));
                slogf(SL_DEBUG, "dns_sniff: %s", sn);
                dns_sniff_stats_write(cfg);   /* снимок для панели и why */
                /* WARN — только по DNS-контуру: при dns_sniff=0 ответов и
                 * записей из них ждать нечего, предупреждение было бы ложью. */
                if (cfg->dns_sniff) {
                    dns_sniff_counters cn;
                    char ifs[128], qs[128];
                    int i, nu = 0, qu = 0;

                    dns_sniff_get_counters(&cn);
                    ifs[0] = qs[0] = '\0';
                    for (i = 0; i < cn.niface; i++) {
                        if (!cn.name[i][0])
                            continue;
                        if (nu < (int)sizeof(ifs) - 32)
                            nu += snprintf(ifs + nu, sizeof(ifs) - nu,
                                           nu ? ",%s" : "%s", cn.name[i]);
                        if (cn.iface_queries[i] && qu < (int)sizeof(qs) - 32)
                            qu += snprintf(qs + qu, sizeof(qs) - qu,
                                           qu ? ",%s" : "%s", cn.name[i]);
                    }
                    if (!nu)
                        snprintf(ifs, sizeof(ifs), "-");
                    if (cn.answers > 0 && cn.parse_fail > 0 && cn.stored == 0)
                        /* Ответы вытаскиваем из сокета, а в таблицу не
                         * попадает ни одной пары, и разбор при этом ругался на
                         * битые сообщения — настоящая поломка разбора. Без
                         * parse_fail>0 тот же ноль дают честные ответы без
                         * A-записей (NXDOMAIN, только AAAA), и WARN врал бы. */
                        slogf(SL_WARN, "dns_sniff: ответы приходят (%lu), в таблицу "
                              "не лёг ни один (parse_fail=%lu) — разбор не доходит "
                              "до таблицы: %s", cn.answers, cn.parse_fail, sn);
                    else if (cn.queries > 0 && cn.answers == 0)
                        /* Вот здесь предположение про интерфейс/направление
                         * уместно: запросы на перечисленных видим, ответы на
                         * них — нет. */
                        slogf(SL_WARN, "dns_sniff: запросы видим (%lu, с %s), "
                              "ответов нет; слушаем %s — проверить, проходят ли "
                              "ответы через эти интерфейсы: %s",
                              cn.queries, qs[0] ? qs : "-", ifs, sn);
                    else if (cn.frames > 0 && cn.queries == 0 && cn.answers == 0)
                        /* Формулировка без упрёка в «не то направление»:
                         * направление по этим числам не доказать. */
                        slogf(SL_WARN, "dns_sniff: на захвате ни запросов, ни "
                              "ответов DNS (frames=%lu, udp53=%lu): слушаем %s — "
                              "там нет трафика UDP/53 (DoT/DoH/QUIC) либо "
                              "выбраны не те интерфейсы: %s",
                              cn.frames, cn.udp53, ifs, sn);
                }
            }
        }

        vq_tick(&st, cfg, now);   /* аудит пинов автообучения: жив ли путь через туннель */

        if (g_reload) {
            susanin_config nc;
            g_reload = 0;
            if (conf_path && config_load(conf_path, &nc) == 0) {
                char old_level[24];
                int old_sl;
                snprintf(old_level, sizeof(old_level), "%s", cfg->log_level);
                old_sl = slog_level();
                *cfg = nc;
                backend_batch_enable(cfg->ipset_batch);
                /* Уровень применялся только при старте процесса: правка
                 * log_level в конфиге и Reload оставляли прежний поток —
                 * «сделал тише, а оно пишет». slog_init дешёвый и побочных
                 * эффектов не имеет. */
                slog_init(cfg->log_level);
                if (slog_level() != old_sl)
                    slogf(SL_WARN, "log_level: %s -> %s (применено без перезапуска)",
                          old_level[0] ? old_level : "(пусто)",
                          cfg->log_level[0] ? cfg->log_level : "(пусто)");
                slogf(SL_INFO, "config reloaded: %s", conf_path);
                cfg_check(cfg, "reload");
                vpin_interval_fix(cfg);
                /* Смена режима egress меняет и смысл записей аудита:
                 * без tproxy туннельную пробу мерить нечем. */
                vpin_set_tunnel_probe(strcmp(cfg->egress_type, "tproxy") == 0, now);
                /* Модули списков создавались только при старте службы. Если
                 * vpn_always_file/vpn_never_file появился (или исчез) в уже
                 * работающем процессе, Reload обязан отреагировать: иначе
                 * настройка из панели не применялась никогда, и даже сводка
                 * после Reload не печаталась — молчание казалось успехом. */
                if (!va && cfg->vpn_always_file[0]) {
                    va = va_new();
                    if (va) {
                        va_mark_dirty(va);
                        last_force = 0;
                        slogf(SL_INFO, "vpn_always: модуль поднят reload-ом");
                    } else {
                        slogf(SL_ERROR, "vpn_always: не выделено памяти, "
                              "список не активен до перезапуска");
                    }
                } else if (va && !cfg->vpn_always_file[0]) {
                    /* Порядок важен: сначала refresh (он при пустом пути снимает
                     * пины), потом освобождение модуля — иначе адреса остались
                     * бы в susanin_ok_* бессрочно. */
                    backend_batch_begin();
                    force_pending = va_refresh(va, cfg);
                    backend_batch_end();
                    va_free(va);
                    va = NULL;
                    slogf(SL_INFO, "vpn_always: путь очищен, пины сняты, модуль выключен");
                }
                if (!nv && cfg->vpn_never_file[0]) {
                    nv = vn_new();
                    if (nv) {
                        vn_mark_dirty(nv);
                        last_never = 0;
                        slogf(SL_INFO, "vpn_never: модуль поднят reload-ом");
                    } else {
                        slogf(SL_ERROR, "vpn_never: не выделено памяти, "
                              "список не активен до перезапуска");
                    }
                } else if (nv && !cfg->vpn_never_file[0]) {
                    int nch = 0;
                    backend_batch_begin();
                    never_pending = vn_refresh2(nv, cfg, &nch);
                    backend_batch_end();
                    vn_free(nv);
                    nv = NULL;
                    slogf(SL_INFO, "vpn_never: путь очищен, пины сняты, модуль выключен");
                }
                /* Работник udp-relay держит конфиг, с которым запущен:
                 * при смене значимых полей — перезапуск, при выключении
                 * udp_relay — остановка. */
                udp_relay_reload(cfg);
                /* Снифер同样 мог быть включён/выключен уже в работающем
                 * процессе: раньше ключ применялся только при старте службы. */
                dns_sniff_reload(cfg);
                /* W6: перечитать настройку индикатора релиза; при включении —
                 * проверка в ближайшие 30 с, а не через 12 ч. */
                release_init(cfg);
                last_release = now;
                if (cfg->release_check && cfg->release_check_interval > 30)
                    last_release -= (time_t)(cfg->release_check_interval - 30);
                /* Пробы и их окно — заново: адреса/пороги могли измениться.
                 * Аудит пинов — тем же порядком: работающий ребёнок держит
                 * старый конфиг и старый пайп, после Reload он невалиден. */
                probe_job_stop();
                vq_stop();
                eg_reset();
                {
                    char perr[256];
                    if (backend_preflight(cfg, perr, sizeof(perr)) != 0)
                        slogf(SL_ERROR, "preflight: %s", perr);
                }
                ei = 0;
                {
                    int i;
                    for (i = 0; i < cfg->n_egress; i++) {
                        eg_up[i] = 1;
                        eg_miss[i] = 0;
                        eg_up_since[i] = now;
                    }
                }
                /* Режим берём из конфига; смена режима — только при явном
                 * псевдониме tproxy/xray или смене egress_type. */
                ei = engine_pick_start_egress(cfg);
                if (strcmp(cfg->egress_type, "tproxy") == 0 &&
                    !backend_local_listen(cfg->tproxy_port)) {
                    slogf(SL_ERROR, "tproxy: порт %d не слушается — правила не поднимаю (DIRECT)",
                          cfg->tproxy_port);
                    backend_teardown(cfg);
                    backend_ct_flush_vpn(cfg);
                    dp_ok = 0;
                    next_dp_try = now + 15;
                } else if (backend_provision(cfg) == 0) {
                    dp_ok = 1;
                    dp_fails = 0;
                    /* Reload должен применять и профили: раньше они
                     * пересобирались только при старте службы. */
                    profiles_apply(cfg);
                } else {
                    dp_ok = 0;
                    dp_fails++;
                    next_dp_try = now + (60 << (dp_fails < 5 ? dp_fails : 4));
                }
                last_force = 0;
                last_never = 0;
                just_reloaded = 1;
            } else {
                slogf(SL_ERROR, "config reload failed: %s",
                      conf_path ? conf_path : "?");
            }
        }

        /* Сканируем /proc/net/nf_conntrack только когда это реально нужно
         * (классификатор / sweep / health), а не 5 раз в секунду — на слабом
         * CPU это заметная экономия. */
        {
            int need_scan = 0;
            if (tunnel_up &&
                (now - last[0] >= cfg->fast_interval * idle_mult ||
                 now - last[1] >= cfg->soft_interval * idle_mult ||
                 now - last[2] >= cfg->judge_interval * idle_mult))
                need_scan = 1;
            if (dp_ok && tunnel_up && now - last_sweep >= 60)
                need_scan = 1;
            if (dp_ok && tunnel_up && now - last_nsweep >= 60)
                need_scan = 1;
            if (now - last[3] >= cfg->health_interval)
                need_scan = 1;
            if (need_scan) {
                static unsigned long ol_rep;
                static time_t ol_at;
                unsigned long ol;

                L.n = 0;
                if (conntrack_scan("/proc/net/nf_conntrack", collect, &L) < 0)
                    slogf(SL_DEBUG, "conntrack scan failed");
                /* Счётчик без читателя — мёртвый код: ровно так же год назад
                 * жил dns_sniff_count(). Сообщаем не чаще раза в 5 минут, но
                 * дельту копят, чтобы не потерять ни одного случая. */
                ol = conntrack_overlong();
                if (ol > ol_rep && (!ol_at || now - ol_at >= 300)) {
                    slogf(SL_WARN, "conntrack: %lu записей длиннее %d байт — эти "
                          "потоки не были разобраны и не участвовали в обучении",
                          ol - ol_rep, CT_LINE_MAX);
                    ol_rep = ol;
                    ol_at = now;
                }
            }
        }

        if (tunnel_up) {
            int ran = 0;
            /* Проход обучения применяем одним батчем ipset (restore): иначе
             * каждая add/del на волне промоушенов — отдельный fork+exec, и на
             * MIPS классификатор захлёбывается вилками. Пустая пачка
             * сбрасывается без fork'ов. */
            backend_batch_begin();
            if (now - last[0] >= cfg->fast_interval * idle_mult) { last[0] = now; clr_fast(&ctx, L.v, L.n, now); ran = 1; }
            if (now - last[1] >= cfg->soft_interval * idle_mult) { last[1] = now; clr_soft(&ctx, L.v, L.n, now); ran = 1; }
            if (now - last[2] >= cfg->judge_interval * idle_mult) { last[2] = now; clr_judge(&ctx, L.v, L.n, now); ran = 1; }
            backend_batch_end();
            /* Адаптивный период: 15 проходов подряд без событий обучения
             * (ничего не учим, не подтверждаем, не берём под наблюдение) —
             * интервалы удваиваются, парсинг conntrack вдвое реже. Первое же
             * событие возвращает обычный темп: цена простоя — не более +1 с
             * к реакции на новый заблокированный поток. */
            if (ran) {
                if (clf_take_events() > 0) {
                    idle_cnt = 0;
                    idle_mult = 1;
                } else if (++idle_cnt >= 15 && idle_mult < 2) {
                    idle_mult = 2;
                }
            }
            clients_audit(cfg, L.v, L.n, now);
        }

        /* Периодически сбрасываем «залипшие» прямые потоки (mark=0) по адресам
         * из ok/vpn_always, чтобы они переустановились через туннель (bounded). */
        if (dp_ok && tunnel_up && now - last_sweep >= 60) {
            last_sweep = now;
            sweep_direct(cfg, &st, L.v, L.n);
        }

        /* И обратное: помеченные (VPN) потоки к адресам из vpn_never — точечно
         * рвём, иначе они «залипают» в туннеле до конца соединения. */
        if (dp_ok && tunnel_up && now - last_nsweep >= 60) {
            last_nsweep = now;
            never_sweep_marked(cfg, &st, L.v, L.n, now);
        }

        /* Health/failover/failback. Пробы ждут в отдельном процессе: забираем
         * готовые результаты каждый проход и не блокируем цикл. В tproxy
         * проверяем апстрим Xray (SOCKS5), иначе — egress-интерфейсы. */
        probe_job_poll(cfg, eg_up, eg_miss, eg_up_since, eg_lat, now);
        {
            if (now - last[3] >= cfg->health_interval) {
                last[3] = now;
                /* Пробы — всегда в отдельном процессе (в tproxy там SOCKS-проба
                 * апстрима Xray): главный цикл не блокируется. */
                if (!probe_job_busy())
                    probe_job_start(cfg, cfg->n_egress);
            }
            {
            int i, pref = -1, flushed = 0;
            for (i = 0; i < cfg->n_egress; i++)
                if (eg_up[i]) { pref = i; break; }

            if (pref < 0) {
                if (all_down_since == 0)
                    all_down_since = now;
                if (tunnel_up) {
                    tunnel_up = 0;
                    slogf(SL_ERROR, "all egress DOWN, fail-open DIRECT");
                    backend_ipset_flush(cfg);
                    /* Помеченные потоки (MARK_OK) иначе продолжат идти в мёртвый
                     * туннель: сбрасываем conntrack для VPN-метки. */
                    backend_ct_flush_vpn(cfg);
                    va_mark_dirty(va);
                    vn_mark_dirty(nv);
                }
                /* Тихий простой — главная причина «непонятно, почему не работает»:
                 * после первой ERROR в лог больше ничего не писалось. */
                if (now - last_allwarn >= 300) {
                    last_allwarn = now;
                    slogf(SL_WARN,
                          "health: все egress недоступны %ld c — трафик DIRECT, обучение стоит",
                          (long)(now - all_down_since));
                }
            } else {
                all_down_since = 0;
                int need_switch = 0, failback = 0;
                if (!eg_up[ei]) {
                    need_switch = 1;          /* активный мёртв — переключаемся */
                } else if (pref < ei) {
                    /* Активный жив, но ожил более приоритетный (Master). При
                     * включённом автовыборе (race) возврат не делаем: иначе два
                     * механизма «пинают» трафик друг другом. */
                    int deb = cfg->egress_failback_debounce > 0
                                  ? cfg->egress_failback_debounce : 0;
                    if (!cfg->egress_race && cfg->egress_failback &&
                        (deb == 0 || now - eg_up_since[pref] >= deb)) {
                        need_switch = 1;
                        failback = 1;
                    }
                }
                if (need_switch) {
                    int was = ei;
                    /* Fail-safe для кандидата-резерва tproxy (Xray): если Xray
                     * не слушает порт, переключение не делаем — иначе трафик
                     * уйдёт «в никуда». */
                    if (egress_is_tproxy(cfg->egress_list[pref]) &&
                        !backend_local_listen(cfg->tproxy_port)) {
                        slogf(SL_WARN,
                              "egress %s: Xray не слушает порт %d — переключение отложено",
                              cfg->egress_list[pref], cfg->tproxy_port);
                    } else {
                        ei = pref;
                        memset(eg_lead, 0, sizeof(eg_lead));   /* счёт лидерства — заново */
                        slogf(SL_WARN, "egress %s -> %s (%s)", cfg->egress_list[was],
                              cfg->egress_list[ei], failback ? "failback" : "failover");
                        backend_set_egress(cfg, cfg->egress_list[ei]);
                        if (!flushed) {
                            backend_ct_flush_vpn(cfg);
                            flushed = 1;
                        }
                    }
                }
                if (!tunnel_up) {
                    /* resync_sets() сбрасывает ipset'ы (и пины vpn_always/
                     * vpn_never). Помечаем списки «грязными» и возвращаем
                     * на следующем проходе. */
                    tunnel_up = 1;
                    slogf(SL_INFO, "tunnel UP via %s, recovery", cfg->egress_list[ei]);
                    /* Маршрут в таблице исчезает вместе с интерфейсом (ядро
                     * удаляет default dev <iface> при выключении VPN), и без
                     * него метка не находит default → пакет уходит напрямую.
                     * В tproxy-режиме вызов ничего не меняет (см. backend.c). */
                    backend_set_egress(cfg, cfg->egress_list[ei]);
                    resync_sets(cfg, &st);
                    sweep_direct(cfg, &st, L.v, L.n);
                    va_mark_dirty(va);
                    vn_mark_dirty(nv);
                    last_force = 0;
                }
            }

            /* N3: race — на быстрейший живой egress. Счёт лидерства идёт по
             * ПРОБАМ (eg_gen растёт в eg_apply), а не по итерациям цикла (200 мс),
             * иначе «3 тика» = 0,6 с. Переключаемся только при заметной выгоде. */
            if (cfg->egress_race) {
                static unsigned race_seen;
                int best = -1;
                for (i = 0; i < cfg->n_egress; i++) {
                    if (!eg_up[i] || eg_ratio(i) < EG_MIN_RATIO)
                        continue;
                    if (best < 0 || (eg_lat[i] > 0 &&
                        (eg_lat[best] == 0 || eg_lat[i] < eg_lat[best])))
                        best = i;
                }
                if (eg_gen != race_seen) {   /* пришла новая проба */
                    race_seen = eg_gen;
                    for (i = 0; i < cfg->n_egress; i++)
                        eg_lead[i] = (i == best) ? eg_lead[i] + 1 : 0;
                }
                if (best >= 0 && best != ei && eg_lead[best] >= 3 &&
                    eg_lat[best] > 0 && eg_lat[ei] > 0 &&
                    eg_lat[best] * 100 <= eg_lat[ei] * 75 &&
                    eg_lat[ei] - eg_lat[best] >= 20) {
                    slogf(SL_WARN, "race: %s -> %s (fastest %dms, было %dms)",
                          cfg->egress_list[ei], cfg->egress_list[best],
                          eg_lat[best], eg_lat[ei]);
                    ei = best;
                    eg_lead[best] = 0;
                    backend_set_egress(cfg, cfg->egress_list[ei]);
                    if (!flushed)
                        backend_ct_flush_vpn(cfg);
                }
            }
            }
        }

        {
            /* Обычный режим — раз в 5 минут. Soft — редко (по умолчанию раз в
             * 12 часов), чтобы почти не писать на носитель. 0 = не сохранять. */
            int every = (strcmp(cfg->disk_mode, "soft") == 0)
                            ? cfg->soft_state_interval
                            : 300;
            if (every > 0 && now - last_save >= every) {
                last_save = now;
                /* Без этого «обучение не переживает рестарт» выглядело бы как
                 * поломка логики: state просто не записан (полный носитель,
                 * севшая флешка, EBUSY). */
                if (state_save(state_path, &st) != 0)
                    slogf(SL_WARN, "state: сохранить %s не удалось — после "
                          "рестарта обучения начнётся с нуля", state_path);
            }
        }

        if (cfg->cdn_ranges_interval > 0 &&
            now - last_cdn >= (time_t)cfg->cdn_ranges_interval) {
            last_cdn = now;
            cdn_refresh(cfg);   /* асинхронно: скачивание в отдельном процессе */
        }
        cdn_poll(cfg);          /* пожать ребёнка; при успехе перечитать диапазоны */

        if (cfg->release_check && cfg->release_check_interval > 0 &&
            now - last_release >= (time_t)cfg->release_check_interval) {
            last_release = now;
            release_check_now(cfg);
        }

        /* Обслуживание снифинга ( пины по спискам, дооткрытие появившихся
         * интерфейсов, аудит «RU в VPN») нужно обоим источникам имени: и DNS,
         * и SNI. Раньше контур висел на dns_sniff, и при sni_sniff=1 снятие
         * устаревших пинов не работало вовсе. */
        if ((cfg->dns_sniff || cfg->sni_sniff) && tunnel_up &&
            now - last_dnssniff >= 10) {
            last_dnssniff = now;
            dns_sniff_reconcile(cfg);
        }

        if (cfg->n_profiles > 0 && now - last_prof >= 30) {
            last_prof = now;
            profile_failover_tick(cfg);
        }

        if (now - last_trim >= 30) {
            int udp;
            last_trim = now;
            /* Вытеснения GC — тоже пачкой (state_ipset_del вне батча — fork). */
            backend_batch_begin();
            trim_ok(cfg, &st);
            backend_batch_end();
            /* Протухшие записи не должны копиться: state_expire() не вызывался. */
            for (udp = 0; udp < 2; udp++) {
                state_expire(st_test(&st, udp), now);
                state_expire(st_ok(&st, udp), now);
                state_expire(st_watch(&st, udp), now);
                state_expire(st_cool(&st, udp), now);
            }
            state_expire(&st.net, now);
            state_expire(&st.direct, now);
            /* Пины DNS-снифинга в «никогда»: чистим по TTL и держим лимит,
             * иначе набор растёт без ограничения. */
            state_expire(&st.never, now);
            while (st.never.n > 4096) {
                char ip[64];
                snprintf(ip, sizeof(ip), "%s", st.never.v[0].addr);
                backend_set_del(cfg, "susanin_never", ip);
                state_remove(&st.never, ip);
                slogf(SL_DEBUG, "never: вытесняю пину %s (лимит 4096)", ip);
            }
        }

        /* Быстрый контроль датаплейна: NDM может снести правила в любой момент,
         * поэтому проверяем чаще общего reconcile — меньше окно fail-open.
         * Только при tunnel_up: пока живого egress нет (VPN отключили), маршрута
         * в таблице тоже нет, и проверка давала бы ложное «data plane missing»
         * с перепровижном каждые 5 c и падением dp_ok на 60 c. */
        if (dp_ok && tunnel_up && now - last_dpfast >= 5) {
            int unk = 0;

            last_dpfast = now;
            if (!backend_ready_ex(cfg, &unk)) {
                dp_unk_since = 0;
                slogf(SL_WARN, "data plane missing (fast check), re-provisioning");
                if (backend_provision(cfg) == 0) {
                    backend_mark_reprov("rules missing (fast re-provision)");
                    if (tunnel_up) {
                        /* Никакого resync_sets()/flush здесь: ре-провижн правил
                         * не теряет ipset'ы, а flush на каждом быстром проходе
                         * давал churn (ok_tcp 507↔252, ok_net 19↔6) и на окно
                         * оставлял адреса vpn_always без пина — поток успевал
                         * уйти напрямую. Списки только помечаем «грязными». */
                        sweep_direct(cfg, &st, L.v, L.n);
                        va_mark_dirty(va);
                        vn_mark_dirty(nv);
                        last_force = 0;
                    }
                } else {
                    dp_ok = 0;
                    dp_fails = 1;
                    next_dp_try = now + 60;
                }
                last_recon = now;   /* не дублировать в общем reconcile */
            } else if (unk) {
                /* Проверить не удалось: правила могут быть сняты, а мы этого не
                 * видим. Перепровижнивать по «не знаю» нельзя (гон при залёгшем
                 * локе), но и молчать нельзя: прежняя версия на этом же rc=4
                 * возвращала «готово» и окно fail-open становилось неограниченно
                 * по времени. Поэтому — предупреждение раз в 5 минут, а не
                 * каждое молчание цикла. */
                if (!dp_unk_since)
                    dp_unk_since = now;
                else if (now - dp_unk_since >= 300) {
                    slogf(SL_WARN, "датаплейн не проверялся %u с: xtables-lock занят — "
                          "пропажу правил увидеть нельзя",
                          (unsigned)(now - dp_unk_since));
                    dp_unk_since = now;
                }
            } else {
                dp_unk_since = 0;
            }
        }

        if (now - last_recon >= (cfg->dp_check_interval > 0 ? cfg->dp_check_interval : CFG_DEF_DP_CHECK_INTERVAL)) {
            int tproxy = (strcmp(cfg->egress_type, "tproxy") == 0);
            int tp_ok = !tproxy || backend_local_listen(cfg->tproxy_port);
            last_recon = now;
            if (tproxy && tp_ok) {
                xray_tries = 0;     /* Xray жив — сбрасываем счётчик watchdog */
                stuck_tries = 0;
            }
            /* Watchdog Xray — НЕЗАВИСИМО от состояния датаплейна: если tproxy и
             * порт не слушается, поднимаем Xray с backoff. Раньше это работало
             * только при dp_ok=1, поэтому после падения Xray (dp_ok=0) агент
             * оставался в fail-open навсегда. */
            if (tproxy && !tp_ok && cfg->xray_watchdog && now >= next_xray_try) {
                int back;
                if (xray_proc_exists()) {
                    /* Процесс есть, а порт не слушается: висит (D-state) или не
                     * смог забиндиться. НОВЫЙ экземпляр не поднимаем — иначе
                     * копятся процессы и кончается память.
                     * Но и «ждать вечно» нельзя: после FORCED_RESTART_TRIES таких
                     * проверок зовём S93 restart — он умеет kill -9 и отказывается
                     * стартовать, если процесс в D. */
                    stuck_tries++;
                    if (stuck_tries >= FORCED_RESTART_TRIES) {
                        slogf(SL_WARN, "tproxy: Xray есть, но :%d не слушает (%d проверок) — "
                                       "принудительный restart", cfg->tproxy_port, stuck_tries);
                        restart_xray_forced(cfg);
                        stuck_tries = 0;
                        /* Ждать порт здесь нельзя: запуск асинхронный, а sleep
                         * в цикле останавливает dns_sniff и обучение. Следующий
                         * виток reconcile увидит слушателя и сбросит счётчики. */
                        next_xray_try = time(NULL) + 30;
                    } else {
                        slogf(SL_WARN, "tproxy: процесс Xray есть, но :%d не слушает — "
                                       "повторный запуск пропускаю (проверка %d из %d)",
                              cfg->tproxy_port, stuck_tries, FORCED_RESTART_TRIES);
                        next_xray_try = time(NULL) + 60;
                    }
                } else {
                    xray_tries++;
                    /* Backoff 15/30/60 c, потолок 60 c — безопасен, когда попытка
                     * асинхронная: в 0.4.6 при потолке 60 с подъём блокировал
                     * главный цикл до ~30 с, и полцикла dns_sniff/обучение стояли. */
                    back = 15 << (xray_tries > 3 ? 2 : (xray_tries - 1));
                    if (back > 60)
                        back = 60;
                    slogf(SL_WARN, "tproxy: Xray :%d не слушает — поднимаю (try %d, повтор через %d c)",
                          cfg->tproxy_port, xray_tries, back);
                    if (restart_xray_process(cfg) != 0)
                        slogf(SL_ERROR, "tproxy: Xray не поднялся (try %d) — трафик DIRECT, "
                                        "следующая попытка через %d c",
                              xray_tries, back);
                    /* Успех («порт слушает») и сброс счётчиков — на следующем
                     * витке reconcile: там же, где вычисляется tp_ok. */
                    next_xray_try = time(NULL) + back;
                }
            }
            if (dp_ok && tproxy && !tp_ok) {
                /* Xray умер — снимаем правила (fail-open DIRECT); watchdog выше
                 * уже пытается поднять Xray. Conntrack VPN-метки тоже чистим:
                 * иначе помеченные потоки останутся в мёртвом туннеле. */
                slogf(SL_ERROR, "tproxy: Xray :%d пропал — снимаю правила, fail-open DIRECT "
                                "(процесс %s)", cfg->tproxy_port,
                      xray_proc_exists() ? "есть" : "нет");
                backend_teardown(cfg);
                backend_ct_flush_vpn(cfg);
                /* P5 не зависит от Xray: возвращаем правила, чтобы прокси на
                 * роутере продолжал ходить через proxy_egress (nwg0). */
                if (backend_p5_up(cfg) == 0)
                    slogf(SL_INFO, "tproxy: P5 (proxy_egress) оставлен активным при fail-open");
                dp_ok = 0;
                next_dp_try = now + 15;
            } else if (dp_ok && tunnel_up && !backend_ready(cfg)) {
                /* Was active and disappeared (e.g. NDM/firewall rebuild). */
                slogf(SL_WARN, "data plane missing (NDM rebuild?), re-provisioning");
                if (backend_provision(cfg) == 0) {
                    dp_fails = 0;
                    backend_mark_reprov("rules missing (NDM rebuild)");
                    if (tunnel_up) {
                        /* Без resync_sets()/flush: при пересборке netfilter
                         * ipset'ы не теряются, а flush давал churn и окно без
                         * пинов vpn_always (см. fast re-provision выше). */
                        sweep_direct(cfg, &st, L.v, L.n);
                        last_force = 0;
                        va_mark_dirty(va);
                        vn_mark_dirty(nv);
                    }
                } else {
                    dp_ok = 0;
                    dp_fails = 1;
                    next_dp_try = now + 60;
                }
            } else if (!dp_ok && now >= next_dp_try) {
                /* Never provisioned (or lost earlier): retry with backoff
                 * (60s, 120s, 240s, ... — чтобы не «долбить» в цикле). */
                if (!tp_ok) {
                    slogf(SL_WARN, "tproxy: жду Xray на :%d — правила не поднимаю (DIRECT)",
                          cfg->tproxy_port);
                    next_dp_try = now + 60;
                } else if (backend_provision(cfg) == 0) {
                    dp_ok = 1;
                    dp_fails = 0;
                    slogf(SL_INFO, "data plane provisioned");
                    if (tunnel_up) {
                        resync_sets(cfg, &st);
                        sweep_direct(cfg, &st, L.v, L.n);
                        last_force = 0;
                        va_mark_dirty(va);
                        vn_mark_dirty(nv);
                    }
                } else {
                    dp_fails++;
                    next_dp_try = now + (60 << (dp_fails < 5 ? dp_fails : 4));
                }
            }
        }

        /* Периоды списков берём с той же подстановкой, что и модули: голый
         * vpn_always_interval=0 давал `now - last >= 0`, то есть перечитывание
         * и резолв списков на КАЖДОМ проходе цикла — при том, что проверка
         * конфига трактует 0 как «взять действующий default». */
        if (tunnel_up && va &&
            (force_pending ||
             now - last_force >= (time_t)(cfg->vpn_always_interval > 0
                        ? cfg->vpn_always_interval : CFG_DEF_VPN_LIST_INTERVAL) ||
             va_changed(va, cfg))) {
            time_t prev = last_force;
            last_force = now;
            backend_batch_begin();
            force_pending = va_refresh(va, cfg);
            backend_batch_end();
            if (force_pending)
                last_force = prev;  /* догоняем оставшиеся домены вскоре */
        }

        if (nv &&
            (never_pending ||
             now - last_never >= (time_t)(cfg->vpn_never_interval > 0
                        ? cfg->vpn_never_interval : CFG_DEF_VPN_LIST_INTERVAL) ||
             vn_changed(nv, cfg))) {
            time_t prev = last_never;
            int nchanged = 0;
            last_never = now;
            backend_batch_begin();
            never_pending = vn_refresh2(nv, cfg, &nchanged);
            backend_batch_end();
            /* Чистим state только когда набор реально изменился: иначе обход всех
             * записей с inet_pton случался бы каждые 200 мс. */
            if (nchanged)
                never_state_clean(cfg, &st, now);
            if (never_pending)
                last_never = prev;
        }

        /* Сводка по обоим спискам — ОДНА точка, после того как оба refresh
         * отработаны. Раньше печать стояла внутри ветки «сводка», из-за чего
         * слово «перечитан» появлялось и когда va_refresh вышел по раннему
         * return (пустой путь), и когда список ещё только применяется
         * (домены не все разрешены), и когда nv/va вообще не созданы — то
         * есть наблюдаемость, ради которой сводку и заводили, сама же и
         * вводила в заблуждение. */
        if (just_reloaded) {
            int nd = 0, nip = 0, nnet = 0, nnd = 0, nnt = 0;

            if (!cfg->vpn_always_file[0])
                slogf(SL_INFO, "vpn_always: список не задан (vpn_always_file пуст)");
            else if (!va)
                slogf(SL_WARN, "vpn_always: модуль не создан (не выделена память) — "
                      "список не активен до перезапуска");
            else if (!tunnel_up)
                slogf(SL_INFO, "vpn_always: отложен до подъёма туннеля (fail-open)");
            else {
                va_counts(va, &nd, &nip, &nnet);
                if (force_pending)
                    slogf(SL_INFO, "vpn_always: применяется (доменов=%d, запинено пока "
                          "ip=%d net=%d; остальные — в следующих проходах)",
                          nd, nip, nnet);
                else
                    slogf(SL_INFO, "vpn_always: применён (доменов=%d, запинено ip=%d net=%d)",
                          nd, nip, nnet);
            }

            if (!cfg->vpn_never_file[0])
                slogf(SL_INFO, "vpn_never: список не задан (vpn_never_file пуст)");
            else if (!nv)
                slogf(SL_WARN, "vpn_never: модуль не создан (не выделена память) — "
                      "список не активен до перезапуска");
            else {
                vn_counts(nv, &nnd, &nnt);
                if (never_pending)
                    slogf(SL_INFO, "vpn_never: применяется (доменов=%d, direct пока=%d; "
                          "остальные — в следующих проходах)", nnd, nnt);
                else
                    slogf(SL_INFO, "vpn_never: применён (доменов=%d, direct=%d)",
                          nnd, nnt);
            }
        }
        just_reloaded = 0;

        /* Ротация логов по размеру в рантайме: раньше — только
         * при старте службы; долгий аптайм + INFO/debug = раздутый файл
         * (в tmpfs — прямая потеря RAM). Агент чистит и свой лог, и web-лог:
         * писатели с O_APPEND продолжают с нового EOF. */
        if (now - last_logrot >= 300) {
            last_logrot = now;
            /* Свой и web-лог вращаем только там, где они есть: в soft вывод
             * процессов идёт в /dev/null (смысл режима по документации — лог не
             * ведётся), и крутить файл, который никто не пишет, значило бы
             * трогать носитель впустую. xray.log ниже — исключение намеренное:
             * его пишет Xray, и его лимит защищает память, а не наблюдения. */
            if (strcmp(cfg->disk_mode, "soft") != 0) {
                if (g_agentlog[0])
                    log_rotate_if_big(g_agentlog, 4096, 1024);
                log_rotate_if_big("/opt/susanin/var/susanin-web.log", 2048, 512);
            }
        }

        /* xray.log раньше урезался только при спавне Xray. Долгоживой Xray с
         * поднятым loglevel раздувал tmpfs ровно тем способом, из-за которого
         * порог и появился (OOM-killer убивает Xray — интернет в доме встаёт).
         * Здесь ротация чаще и с сохранением хвоста: обнуление файла теряло и
         * тот контекст, ради которого лог и читают. */
        if (cfg->xray_log_max_kb > 0 && now - last_xlogrot >= 60) {
            long keep = cfg->xray_log_max_kb / 4;

            last_xlogrot = now;
            log_rotate_if_big(XRAY_LOG_PATH, cfg->xray_log_max_kb,
                              keep > 0 ? keep : 64);
        }

        usleep(200000);
    }

    probe_job_stop();
    udp_relay_stop();
    dns_sniff_stop();
    vq_stop();
    vpin_reset();
    if (state_save(state_path, &st) != 0)
        slogf(SL_WARN, "state: сохранить %s при остановке не удалось", state_path);
    slogf(SL_INFO, "engine stopped");
    va_free(va);
    vn_free(nv);
    state_free(&st);
    free(L.v);
    return 0;
}
