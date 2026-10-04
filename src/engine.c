#define _GNU_SOURCE
#include "engine.h"
#include "backend.h"
#include "cdn.h"
#include "classifier.h"
#include "conntrack.h"
#include "dns_sniff.h"
#include "health.h"
#include "log.h"
#include "state.h"
#include "udp_relay.h"
#include "vpn_always.h"
#include "vpn_never.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static void resync_sets(const susanin_config *cfg, susanin_state *st)
{
    int udp, phase, i;
    time_t now = time(NULL);
    backend_ipset_flush(cfg);
    for (udp = 0; udp < 2; udp++) {
        for (phase = 0; phase < 2; phase++) {
            const state_set *set = phase ? st_ok(st, udp) : st_test(st, udp);
            for (i = 0; i < set->n; i++) {
                /* Остаток TTL: после re-provision запись не должна жить дольше. */
                int ttl = (int)(set->v[i].expire - now);
                if (ttl > 0)
                    backend_ipset_add(cfg, udp, phase, set->v[i].addr, ttl);
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
    /* ipset'ы пусты — пины dns_sniff применим заново на следующем reconcile. */
    dns_sniff_reset_pins();
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
        if (!from_lan(cfg, f->src)) continue;
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
        if (clf_is_private_dst(f->dst)) continue;
        udp = (f->l4proto == 17);
        /* «Мягко-прямо» (D1) и кандидатов в обучение не сбрасываем. */
        if (state_has(&st->direct, f->dst, now)) continue;
        if (state_has(st_test(st, udp), f->dst, now)) continue;
        if (state_has(st_watch(st, udp), f->dst, now)) continue;
        if (state_has(st_ok(st, udp), f->dst, now)) {
            backend_ct_delete(f);
            done++;
        }
    }
}

/* vpn_never: убрать адреса из state (ok/test/cool/direct), чтобы state не
 * расходился с ipset'ами после vn_refresh(). Иначе sweep_direct рвёт прямые
 * потоки к never-адресам, а resync_sets возвращает их в ok-ipset. */
static void never_state_clean(const susanin_config *cfg, susanin_state *st, time_t now)
{
    int udp, k, i;
    for (udp = 0; udp < 2; udp++) {
        state_set *sets[3];
        sets[0] = st_ok(st, udp);
        sets[1] = st_test(st, udp);
        sets[2] = st_cool(st, udp);
        for (k = 0; k < 3; k++) {
            state_set *s = sets[k];
            for (i = s->n - 1; i >= 0; i--) {
                const char *ip = s->v[i].addr;
                if (!vn_has(ip) && !state_has(&st->never, ip, now))
                    continue;
                if (k == 0)
                    backend_ipset_del(cfg, udp, 1, ip);   /* ok */
                else if (k == 1)
                    backend_ipset_del(cfg, udp, 0, ip);   /* test */
                state_remove(s, ip);
                slogf(SL_DEBUG, "vpn_never: %s убран из кэша (%s)", ip,
                      udp ? "udp" : "tcp");
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
            backend_ipset_del(cfg, udp, 1, ip);
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
            int port = cfg->health_tcp_port > 0 ? cfg->health_tcp_port : 443;
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
            snprintf(np, sizeof(np), "/sys/class/net/%s", cfg->egress_list[i]);
            if (access(np, F_OK) == 0) {
                clock_gettime(CLOCK_MONOTONIC, &t0);
                health_probe_dev(cfg, cfg->egress_list[i], psrc, &ok, &total);
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

/* Watchdog Xray: поднять упавший процесс (tproxy). Пробуем init-скрипт
 * (перезапускает Xray с актуальным xray_loglevel/GOGC/GOMEMLIMIT), иначе —
 * прямой запуск бинаря. Возврат rc system(); 0/неважно — проверяем порт. */
static void restart_xray_process(void)
{
    int rc;
    if (access("/opt/etc/init.d/S93xray-tproxy", X_OK) == 0) {
        rc = system("/opt/etc/init.d/S93xray-tproxy restart >/dev/null 2>&1");
        (void)rc;
        return;
    }
    rc = system("pidof xray >/dev/null 2>&1 || "
                "(/opt/sbin/xray run -config /opt/susanin/etc/xray-tproxy.json "
                ">>/opt/susanin/var/xray.log 2>&1 &)");
    (void)rc;
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
    time_t next_dp_try = 0;
    time_t last_force = 0;
    time_t last_never = 0;
    int never_pending = 0;
    time_t last_trim = 0;
    time_t last_sweep = 0;
    time_t last_cdn = 0;
    time_t next_xray_try = 0;
    int xray_tries = 0;
    time_t last_dnssniff = 0;
    time_t last_prof = 0;
    int force_pending = 0;
    const char *state_path = "/opt/susanin/var/susanin.state";

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    signal(SIGHUP, on_hup);     /* reload конфига */
    {
        const char *lf = getenv("SUSANIN_LOG");
        /* disk_mode=soft: файл лога не ведём (минимум записей на носитель). */
        if (lf && *lf && strcmp(cfg->disk_mode, "soft") != 0) {
            int fd = open(lf, O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (fd >= 0) {
                dup2(fd, 1);
                dup2(fd, 2);
                if (fd > 2)
                    close(fd);
            }
        }
    }
    slog_init(cfg->log_level);
    if (strcmp(cfg->disk_mode, "soft") == 0)
        slogf(SL_INFO, "disk_mode=soft: log file off, state not saved, no backups");
    if (cfg->ok_ttl == 0)
        slogf(SL_WARN, "ok_ttl=0: выученные адреса не истекают (наборы будут расти); "
                       "рекомендуется конечный TTL, напр. ok_ttl=21600");
    if (cfg->udp_relay)
        udp_relay_start(cfg);
    if (cfg->dns_sniff)
        dns_sniff_start(cfg);

    state_init(&st);
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
    /* Стартуем с первого egress из списка (фейловер переключит при падении). */
    if (cfg->n_egress > 0)
        backend_set_egress(cfg, cfg->egress_list[0]);
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
        int w;
        for (w = 0; w < 10 && !backend_local_listen(cfg->tproxy_port); w++)
            sleep(1);
    }
    if (strcmp(cfg->egress_type, "tproxy") == 0 &&
        !backend_local_listen(cfg->tproxy_port) && cfg->xray_watchdog) {
        /* Xray не слушает — пробуем поднять watchdog'ом (свежий старт после ребута). */
        slogf(SL_WARN, "tproxy: порт %d не слушается — поднимаю Xray (watchdog)",
              cfg->tproxy_port);
        restart_xray_process();
        {
            int w;
            for (w = 0; w < 10 && !backend_local_listen(cfg->tproxy_port); w++)
                sleep(1);
        }
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
    if (va && tunnel_up) {
        last_force = time(NULL);
        force_pending = va_refresh(va, cfg);
    }
    if (nv) {
        int nchanged = 0;
        last_never = time(NULL);
        never_pending = vn_refresh2(nv, cfg, &nchanged);
        /* Тяжёлую чистку state делаем только при реальном изменении набора. */
        if (nchanged)
            never_state_clean(cfg, &st, last_never);
    }

    while (!g_stop) {
        time_t now = time(NULL);

        if (cfg->dns_sniff)
            dns_sniff_poll();

        if (g_reload) {
            susanin_config nc;
            g_reload = 0;
            if (conf_path && config_load(conf_path, &nc) == 0) {
                *cfg = nc;
                slogf(SL_INFO, "config reloaded: %s", conf_path);
                /* Пробы и их окно — заново: адреса/пороги могли измениться. */
                probe_job_stop();
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
                if (cfg->n_egress > 0)
                    backend_set_egress(cfg, cfg->egress_list[0]);
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
                } else {
                    dp_ok = 0;
                    dp_fails++;
                    next_dp_try = now + (60 << (dp_fails < 5 ? dp_fails : 4));
                }
                last_force = 0;
                last_never = 0;
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
                (now - last[0] >= cfg->fast_interval ||
                 now - last[1] >= cfg->soft_interval ||
                 now - last[2] >= cfg->judge_interval))
                need_scan = 1;
            if (dp_ok && tunnel_up && now - last_sweep >= 60)
                need_scan = 1;
            if (now - last[3] >= cfg->health_interval)
                need_scan = 1;
            if (need_scan) {
                L.n = 0;
                if (conntrack_scan("/proc/net/nf_conntrack", collect, &L) < 0)
                    slogf(SL_DEBUG, "conntrack scan failed");
            }
        }

        if (tunnel_up) {
            if (now - last[0] >= cfg->fast_interval) { last[0] = now; clr_fast(&ctx, L.v, L.n, now); }
            if (now - last[1] >= cfg->soft_interval) { last[1] = now; clr_soft(&ctx, L.v, L.n, now); }
            if (now - last[2] >= cfg->judge_interval) { last[2] = now; clr_judge(&ctx, L.v, L.n, now); }
        }

        /* Периодически сбрасываем «залипшие» прямые потоки (mark=0) по адресам
         * из ok/vpn_always, чтобы они переустановились через туннель (bounded). */
        if (dp_ok && tunnel_up && now - last_sweep >= 60) {
            last_sweep = now;
            sweep_direct(cfg, &st, L.v, L.n);
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
            } else {
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
                if (!tunnel_up) {
                    /* resync_sets() сбрасывает ipset'ы (и пины vpn_always/
                     * vpn_never). Помечаем списки «грязными» и возвращаем
                     * на следующем проходе. */
                    tunnel_up = 1;
                    slogf(SL_INFO, "tunnel UP via %s, recovery", cfg->egress_list[ei]);
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
                state_save(state_path, &st);
            }
        }

        if (cfg->cdn_ranges_interval > 0 &&
            now - last_cdn >= (time_t)cfg->cdn_ranges_interval) {
            last_cdn = now;
            cdn_refresh(cfg);
        }

        if (cfg->dns_sniff && tunnel_up && now - last_dnssniff >= 10) {
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
            trim_ok(cfg, &st);
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
         * поэтому проверяем чаще общего reconcile — меньше окно fail-open. */
        if (dp_ok && now - last_dpfast >= 5) {
            last_dpfast = now;
            if (!backend_ready(cfg)) {
                slogf(SL_WARN, "data plane missing (fast check), re-provisioning");
                if (backend_provision(cfg) == 0) {
                    backend_mark_reprov("rules missing (fast re-provision)");
                    if (tunnel_up) {
                        resync_sets(cfg, &st);
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
            }
        }

        if (now - last_recon >= (cfg->dp_check_interval > 0 ? cfg->dp_check_interval : 15)) {
            int tproxy = (strcmp(cfg->egress_type, "tproxy") == 0);
            int tp_ok = !tproxy || backend_local_listen(cfg->tproxy_port);
            last_recon = now;
            if (tproxy && tp_ok)
                xray_tries = 0;     /* Xray жив — сбрасываем счётчик watchdog */
            /* Watchdog Xray — НЕЗАВИСИМО от состояния датаплейна: если tproxy и
             * порт не слушается, поднимаем Xray с backoff. Раньше это работало
             * только при dp_ok=1, поэтому после падения Xray (dp_ok=0) агент
             * оставался в fail-open навсегда. */
            if (tproxy && !tp_ok && cfg->xray_watchdog && now >= next_xray_try) {
                int w, back;
                xray_tries++;
                back = 15 << (xray_tries < 5 ? xray_tries : 4);
                if (back > 900)
                    back = 900;
                next_xray_try = now + back;
                slogf(SL_WARN, "tproxy: Xray :%d не слушает — поднимаю (try %d)",
                      cfg->tproxy_port, xray_tries);
                restart_xray_process();
                for (w = 0; w < 5 && !backend_local_listen(cfg->tproxy_port); w++)
                    sleep(1);
                tp_ok = backend_local_listen(cfg->tproxy_port);
                if (tp_ok) {
                    slogf(SL_INFO, "tproxy: Xray поднят watchdog'ом");
                    xray_tries = 0;
                    next_xray_try = 0;
                }
            }
            if (dp_ok && tproxy && !tp_ok) {
                /* Xray умер — снимаем правила (fail-open DIRECT); watchdog выше
                 * уже пытается поднять Xray. Conntrack VPN-метки тоже чистим:
                 * иначе помеченные потоки останутся в мёртвом туннеле. */
                slogf(SL_ERROR, "tproxy: Xray :%d пропал — снимаю правила, fail-open DIRECT",
                      cfg->tproxy_port);
                backend_teardown(cfg);
                backend_ct_flush_vpn(cfg);
                dp_ok = 0;
                next_dp_try = now + 15;
            } else if (dp_ok && !backend_ready(cfg)) {
                /* Was active and disappeared (e.g. NDM/firewall rebuild). */
                slogf(SL_WARN, "data plane missing (NDM rebuild?), re-provisioning");
                if (backend_provision(cfg) == 0) {
                    dp_fails = 0;
                    backend_mark_reprov("rules missing (NDM rebuild)");
                    if (tunnel_up) {
                        resync_sets(cfg, &st);
                        /* Сбросить «залипшие» прямые потоки (mark=0) по адресам
                         * из ok-наборов, чтобы они переустановились через туннель. */
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

        if (tunnel_up && va &&
            (force_pending ||
             now - last_force >= (time_t)cfg->vpn_always_interval ||
             va_changed(va, cfg))) {
            time_t prev = last_force;
            last_force = now;
            force_pending = va_refresh(va, cfg);
            if (force_pending)
                last_force = prev;  /* догоняем оставшиеся домены вскоре */
        }

        if (nv &&
            (never_pending ||
             now - last_never >= (time_t)cfg->vpn_never_interval ||
             vn_changed(nv, cfg))) {
            time_t prev = last_never;
            int nchanged = 0;
            last_never = now;
            never_pending = vn_refresh2(nv, cfg, &nchanged);
            /* Чистим state только когда набор реально изменился: иначе обход всех
             * записей с inet_pton случался бы каждые 200 мс. */
            if (nchanged)
                never_state_clean(cfg, &st, now);
            if (never_pending)
                last_never = prev;
        }

        usleep(200000);
    }

    probe_job_stop();
    udp_relay_stop();
    dns_sniff_stop();
    state_save(state_path, &st);
    slogf(SL_INFO, "engine stopped");
    va_free(va);
    vn_free(nv);
    state_free(&st);
    free(L.v);
    return 0;
}
