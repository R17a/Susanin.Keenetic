#define _GNU_SOURCE
#include "vpn_never.h"
#include "vpn_always.h"
#include "backend.h"
#include "log.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define VN_MAXDOM 256
#define VN_MAXIP  32
#define VN_TRACK  2048
#define VN_BUDGET_MS 4000
#define VN_QUERY_MAX_MS 2000
#define VN_BACKOFF_S 60
#define VN_SET "susanin_never"

typedef struct {
    char name[256];
    char ips[VN_MAXIP][16];
    int nips;
    int is_net;
    int fail_logged;
    time_t next_try;
} vn_dom;

struct vpn_never {
    vn_dom dom[VN_MAXDOM];
    int nd;
    char track[VN_TRACK][64];
    int ntrack;
    long long seen_mtime;
    long long seen_size;
    int seen_exists;
    int warned;
    int dirty;
};

vpn_never *vn_new(void)
{
    return calloc(1, sizeof(vpn_never));
}

void vn_free(vpn_never *v)
{
    free(v);
}

void vn_mark_dirty(vpn_never *v)
{
    if (v)
        v->dirty = 1;
}

static void trim_line(char *s)
{
    char *p = s + strlen(s);
    while (p > s && (p[-1] == ' ' || p[-1] == '\t' || p[-1] == '\r' ||
                     p[-1] == '\n'))
        *--p = '\0';
}

static int valid_cidr(const char *s, char *out, size_t n)
{
    char buf[48], *slash, *e;
    struct in_addr a;
    long pre;
    if (strlen(s) >= sizeof(buf))
        return 0;
    snprintf(buf, sizeof(buf), "%s", s);
    slash = strchr(buf, '/');
    if (!slash)
        return 0;
    *slash = '\0';
    if (inet_pton(AF_INET, buf, &a) != 1)
        return 0;
    errno = 0;
    pre = strtol(slash + 1, &e, 10);
    if (e == slash + 1 || *e != '\0' || errno != 0 || pre < 0 || pre > 32)
        return 0;
    snprintf(out, n, "%s", s);
    return 1;
}

static int valid_name(const char *s, char *out, size_t n)
{
    struct in_addr a;
    const char *p;
    size_t len = strlen(s);
    if (len == 0 || len >= n)
        return 0;
    if (inet_pton(AF_INET, s, &a) == 1) {
        snprintf(out, n, "%s", s);
        return 1;
    }
    if (strchr(s, '/'))
        return valid_cidr(s, out, n);
    if (len > 253)
        return 0;
    for (p = s; *p; p++) {
        char c = (char)tolower((unsigned char)*p);
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '.' || c == '-'))
            return 0;
    }
    snprintf(out, n, "%s", s);
    return 1;
}

static int file_load(const char *path, char names[][256], int maxnames)
{
    FILE *fp = fopen(path, "r");
    char line[320];
    int n = 0;
    if (!fp)
        return -1;
    while (fgets(line, sizeof(line), fp)) {
        char buf[256];
        int i;
        size_t l;
        trim_line(line);
        if (line[0] == '\0' || line[0] == '#')
            continue;
        if (!valid_name(line, buf, sizeof(buf)))
            continue;
        if (n >= maxnames)
            break;
        for (i = 0; i < n; i++)
            if (strcmp(names[i], buf) == 0)
                break;
        if (i == n) {
            l = strlen(buf) + 1;
            if (l > sizeof(names[n]))
                l = sizeof(names[n]);
            memcpy(names[n], buf, l);
            names[n][sizeof(names[n]) - 1] = '\0';
            n++;
        }
    }
    fclose(fp);
    return n;
}

static vn_dom *dom_find(vpn_never *v, const char *name)
{
    int i;
    for (i = 0; i < v->nd; i++)
        if (strcmp(v->dom[i].name, name) == 0)
            return &v->dom[i];
    return NULL;
}

static void doms_reconcile(vpn_never *v, char names[][256], int n)
{
    vn_dom keep[VN_MAXDOM];
    int nk = 0, i;
    for (i = 0; i < n && i < VN_MAXDOM; i++) {
        vn_dom *old = dom_find(v, names[i]);
        vn_dom *d = &keep[nk++];
        if (old)
            *d = *old;
        else {
            size_t l;
            memset(d, 0, sizeof(*d));
            l = strlen(names[i]) + 1;
            if (l > sizeof(d->name))
                l = sizeof(d->name);
            memcpy(d->name, names[i], l);
            d->name[sizeof(d->name) - 1] = '\0';
            d->is_net = strchr(d->name, '/') ? 1 : 0;
            d->next_try = 0;
        }
    }
    memcpy(v->dom, keep, (size_t)nk * sizeof(vn_dom));
    v->nd = nk;
}

static int tracked_has(const vpn_never *v, const char *val)
{
    int i;
    for (i = 0; i < v->ntrack; i++)
        if (strcmp(v->track[i], val) == 0)
            return 1;
    return 0;
}

static void tracked_add(vpn_never *v, const char *val)
{
    size_t l;
    if (v->ntrack >= VN_TRACK)
        return;
    l = strlen(val) + 1;
    if (l > sizeof(v->track[0]))
        l = sizeof(v->track[0]);
    memcpy(v->track[v->ntrack], val, l);
    v->track[v->ntrack][sizeof(v->track[0]) - 1] = '\0';
    v->ntrack++;
}

static void tracked_remove(vpn_never *v, const char *val)
{
    int i, w = 0;
    for (i = 0; i < v->ntrack; i++) {
        if (strcmp(v->track[i], val) == 0)
            continue;
        if (w != i)
            memcpy(v->track[w], v->track[i], 64);
        w++;
    }
    v->ntrack = w;
}

static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int vn_changed(vpn_never *v, const susanin_config *cfg)
{
    struct stat st;
    int had;
    if (!v || !cfg->vpn_never_file[0])
        return 0;
    had = v->seen_exists;
    if (stat(cfg->vpn_never_file, &st) != 0)
        return had ? 1 : 0;
    if (!had)
        return 1;
    return st.st_mtime != v->seen_mtime || st.st_size != v->seen_size;
}

int vn_refresh(vpn_never *v, const susanin_config *cfg)
{
    char names[VN_MAXDOM][256];
    char server[64];
    char desired[VN_TRACK][64];
    char (*des)[64] = desired;
    struct stat st;
    time_t now = time(NULL);
    int i, nd = 0, added = 0, removed = 0, pending = 0;
    long long t0 = now_ms();
    int interval = cfg->vpn_never_interval > 0 ? cfg->vpn_never_interval : 300;

    if (!v || !cfg->vpn_never_file[0])
        return 0;

    if (stat(cfg->vpn_never_file, &st) != 0) {
        if (v->seen_exists) {
            v->seen_exists = 0;
            v->nd = 0;
            while (v->ntrack > 0) {
                backend_set_del(cfg, VN_SET, v->track[0]);
                slogf(SL_INFO, "vpn_never: unpin %s (file removed)",
                      v->track[0]);
                tracked_remove(v, v->track[0]);
            }
        } else if (!v->warned) {
            v->warned = 1;
            slogf(SL_INFO, "vpn_never: %s absent (disabled)",
                  cfg->vpn_never_file);
        }
        return 0;
    }
    v->seen_exists = 1;
    v->warned = 0;
    if (!v->seen_mtime || v->seen_mtime != st.st_mtime ||
        v->seen_size != st.st_size) {
        int nf = file_load(cfg->vpn_never_file, names, VN_MAXDOM);
        if (nf >= 0)
            doms_reconcile(v, names, nf);
        v->seen_mtime = st.st_mtime;
        v->seen_size = st.st_size;
    }

    va_pick_resolver(cfg, server, sizeof(server));

    for (i = 0; i < v->nd; i++) {
        vn_dom *d = &v->dom[i];
        long long spent;
        int n, k;
        if (d->next_try > now)
            continue;
        if (d->is_net) {
            d->next_try = now + interval;
            continue;
        }
        {
            struct in_addr lit;
            if (inet_pton(AF_INET, d->name, &lit) == 1) {
                snprintf(d->ips[0], 16, "%.15s", d->name);
                d->nips = 1;
                d->next_try = now + interval;
                continue;
            }
        }
        spent = now_ms() - t0;
        if (spent >= VN_BUDGET_MS) {
            pending = 1;
            continue;
        }
        {
            long left = VN_BUDGET_MS - (long)spent;
            int to = VN_QUERY_MAX_MS;
            if (left < 300)
                left = 300;
            if (to > left)
                to = (int)left;
            n = va_dns_query(server, d->name, d->ips, VN_MAXIP, to);
        }
        if (n > 0) {
            for (k = 0; k < n; k++)
                slogf(SL_DEBUG, "vpn_never: %s -> %s", d->name, d->ips[k]);
            d->nips = n;
            d->fail_logged = 0;
            d->next_try = now + interval;
        } else {
            if (d->nips == 0 && !d->fail_logged) {
                slogf(SL_INFO, "vpn_never: %s resolve failed (no A records)",
                      d->name);
                d->fail_logged = 1;
            }
            d->next_try = now + VN_BACKOFF_S;
        }
    }

    for (i = 0; i < v->nd; i++) {
        int k;
        if (v->dom[i].is_net) {
            int j;
            for (j = 0; j < nd; j++)
                if (strcmp(des[j], v->dom[i].name) == 0)
                    break;
            if (j == nd && nd < VN_TRACK)
                snprintf(des[nd++], 64, "%s", v->dom[i].name);
            continue;
        }
        for (k = 0; k < v->dom[i].nips && nd < VN_TRACK; k++) {
            int j;
            for (j = 0; j < nd; j++)
                if (strcmp(des[j], v->dom[i].ips[k]) == 0)
                    break;
            if (j == nd)
                snprintf(des[nd++], 64, "%s", v->dom[i].ips[k]);
        }
    }

    for (i = 0; i < v->ntrack; ) {
        int j;
        for (j = 0; j < nd; j++)
            if (strcmp(v->track[i], des[j]) == 0)
                break;
        if (j == nd) {
            backend_set_del(cfg, VN_SET, v->track[i]);
            slogf(SL_INFO, "vpn_never: allow-direct off %s", v->track[i]);
            removed++;
            tracked_remove(v, v->track[i]);
        } else {
            i++;
        }
    }
    for (i = 0; i < nd; i++) {
        if (tracked_has(v, des[i]) && !v->dirty)
            continue;
        backend_set_add(cfg, VN_SET, des[i], 0);
        if (!tracked_has(v, des[i]))
            tracked_add(v, des[i]);
        added++;
    }
    v->dirty = 0;

    if (added || removed)
        slogf(SL_INFO, "vpn_never: +%d/-%d entries, %d domain(s), now %d direct",
              added, removed, v->nd, v->ntrack);

    return pending;
}
