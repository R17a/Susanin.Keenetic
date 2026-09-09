#define _GNU_SOURCE
#include "engine.h"
#include "backend.h"
#include "classifier.h"
#include "conntrack.h"
#include "health.h"
#include "log.h"
#include "state.h"
#include "vpn_always.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;
static void on_sig(int s) { (void)s; g_stop = 1; }

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
    int udp, phase;
    backend_ipset_flush(cfg);
    for (udp = 0; udp < 2; udp++) {
        for (phase = 0; phase < 2; phase++) {
            const state_set *set = phase ? st_ok(st, udp) : st_test(st, udp);
            int i;
            for (i = 0; i < set->n; i++) {
                int ttl = phase ? cfg->ok_ttl : cfg->test_ttl;
                backend_ipset_add(cfg, udp, phase, set->v[i].addr, ttl);
            }
        }
    }
}

static void sweep_direct(const susanin_config *cfg, susanin_state *st,
                         const ct_flow *flows, int n)
{
    int i;
    time_t now = time(NULL);
    for (i = 0; i < n; i++) {
        const ct_flow *f = &flows[i];
        int udp;
        if (f->ctmark != 0) continue;
        if (!from_lan(cfg, f->src)) continue;
        if (f->l4proto != 6 && f->l4proto != 17) continue;
        udp = (f->l4proto == 17);
        if (state_has(st_ok(st, udp), f->dst, now))
            backend_ct_delete(f);
    }
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

int engine_run(const susanin_config *cfg)
{
    susanin_state st;
    classifier_ctx ctx;
    flowlist L;
    vpn_always *va = NULL;
    int tunnel_up = 1, miss = 0;
    time_t last[4] = { 0, 0, 0, 0 };
    time_t last_save = 0;
    time_t last_recon = 0;
    time_t last_force = 0;
    time_t last_trim = 0;
    int force_pending = 0;
    const char *state_path = "/opt/susanin/var/susanin.state";

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    {
        const char *lf = getenv("SUSANIN_LOG");
        if (lf && *lf) {
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

    state_init(&st);
    ctx.cfg = cfg;
    ctx.st = &st;
    memset(&L, 0, sizeof(L));

    if (backend_provision(cfg) != 0)
        slogf(SL_ERROR, "datapath provisioning failed");
    if (state_load(state_path, &st) == 0)
        slogf(SL_INFO, "restored cache from %s", state_path);
    if (tunnel_up)
        resync_sets(cfg, &st);
    if (cfg->vpn_always_file[0])
        va = va_new();
    slogf(SL_INFO, "engine started (egress=%s table=%d)", cfg->egress_interface, cfg->routing_table);
    if (va && tunnel_up) {
        last_force = time(NULL);
        force_pending = va_refresh(va, cfg);
    }

    while (!g_stop) {
        time_t now = time(NULL);
        L.n = 0;
        if (conntrack_scan("/proc/net/nf_conntrack", collect, &L) < 0)
            slogf(SL_DEBUG, "conntrack scan failed");

        if (tunnel_up) {
            if (now - last[0] >= cfg->fast_interval) { last[0] = now; clr_fast(&ctx, L.v, L.n, now); }
            if (now - last[1] >= cfg->soft_interval) { last[1] = now; clr_soft(&ctx, L.v, L.n, now); }
            if (now - last[2] >= cfg->judge_interval) { last[2] = now; clr_judge(&ctx, L.v, L.n, now); }
        }

        if (now - last[3] >= cfg->health_interval) {
            int ok = 0, total = 0;
            last[3] = now;
            health_probe(cfg, &ok, &total);
            if (ok > 0) {
                miss = 0;
                if (!tunnel_up) {
                    tunnel_up = 1;
                    slogf(SL_INFO, "tunnel UP, recovery");
                    resync_sets(cfg, &st);
                    sweep_direct(cfg, &st, L.v, L.n);
                    last_force = 0;
                }
            } else {
                miss++;
                if (miss >= cfg->health_miss_debounce && tunnel_up) {
                    tunnel_up = 0;
                    miss = 0;
                    slogf(SL_ERROR, "tunnel DOWN, fail-open DIRECT");
                    backend_ipset_flush(cfg);
                    va_mark_dirty(va);
                }
            }
        }

        if (now - last_save >= 300) {
            last_save = now;
            state_save(state_path, &st);
        }

        if (now - last_trim >= 30) {
            last_trim = now;
            trim_ok(cfg, &st);
        }

        if (now - last_recon >= 15) {
            last_recon = now;
            if (!backend_ready(cfg)) {
                slogf(SL_WARN, "data plane missing (NDM rebuild?), re-provisioning");
                if (backend_provision(cfg) == 0 && tunnel_up) {
                    resync_sets(cfg, &st);
                    last_force = 0;
                    va_mark_dirty(va);
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

        usleep(200000);
    }

    state_save(state_path, &st);
    slogf(SL_INFO, "engine stopped");
    va_free(va);
    state_free(&st);
    free(L.v);
    return 0;
}
