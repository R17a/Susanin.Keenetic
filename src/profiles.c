#define _GNU_SOURCE
#include "profiles.h"
#include "backend.h"
#include "log.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define PROF_MAX_RANGES 4096

typedef struct {
    uint32_t net;
    int bits;
} prof_range;

typedef struct {
    char path[CFG_PATH_MAX];
    time_t mtime;
    int loaded;
    int n;
    prof_range v[PROF_MAX_RANGES];
} prof_cache;

static prof_cache g_cache[CFG_MAX_PROFILES];

/* Имя набора: как в profiles.sh (нижний регистр, только a-z0-9_). */
static void prof_set_name(const char *name, char *out, unsigned n)
{
    unsigned j = 0;
    const char *pfx = "susanin_prof_";
    for (; *pfx && j + 1 < n; pfx++)
        out[j++] = *pfx;
    for (; name && *name && j + 1 < n; name++) {
        unsigned char c = (unsigned char)*name;
        if (isalnum(c))
            out[j++] = (char)tolower(c);
        else if (c == '_' || c == '-' || c == ' ')
            out[j++] = '_';
    }
    out[j] = '\0';
}

static void prof_load(prof_cache *pc, const char *path)
{
    FILE *fp;
    struct stat st;
    char line[320];

    if (pc->loaded && !strcmp(pc->path, path)) {
        if (stat(path, &st) != 0 || st.st_mtime == pc->mtime)
            return;                 /* без изменений */
    }
    snprintf(pc->path, sizeof(pc->path), "%s", path);
    pc->n = 0;
    pc->loaded = 1;
    pc->mtime = (stat(path, &st) == 0) ? st.st_mtime : 0;
    fp = fopen(path, "r");
    if (!fp)
        return;
    while (fgets(line, sizeof(line), fp)) {
        char *p = line, *slash;
        struct in_addr a, n;
        int bits;
        char *q = line + strlen(line);
        while (q > line && (q[-1] == '\n' || q[-1] == '\r' ||
                            q[-1] == ' ' || q[-1] == '\t'))
            *--q = '\0';
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '\0' || *p == '#' || pc->n >= PROF_MAX_RANGES)
            continue;
        slash = strchr(p, '/');
        if (slash) {
            *slash = '\0';
            bits = atoi(slash + 1);
        } else {
            bits = 32;
        }
        if (inet_pton(AF_INET, p, &a) != 1)
            continue;
        if (bits < 0 || bits > 32)
            continue;
        n.s_addr = 0;
        if (bits > 0) {
            uint32_t mask = 0xffffffffu << (32 - bits);
            n.s_addr = htonl(ntohl(a.s_addr) & mask);
        }
        pc->v[pc->n].net = ntohl(n.s_addr);
        pc->v[pc->n].bits = bits;
        pc->n++;
    }
    fclose(fp);
}

static int prof_match(const prof_cache *pc, const char *ip)
{
    struct in_addr a;
    uint32_t ah;
    int i, bits, mbits;
    if (inet_pton(AF_INET, ip, &a) != 1)
        return 0;
    ah = ntohl(a.s_addr);
    for (i = 0; i < pc->n; i++) {
        uint32_t mask;
        bits = pc->v[i].bits;
        mbits = bits;
        mask = mbits == 0 ? 0 : (0xffffffffu << (32 - mbits));
        if ((ah & mask) == (pc->v[i].net & mask))
            return 1;
    }
    return 0;
}

void profile_auto_learn(const susanin_config *cfg, const char *ip)
{
    int p;
    if (!cfg || !ip || !ip[0])
        return;
    for (p = 0; p < cfg->n_profiles && p < CFG_MAX_PROFILES; p++) {
        char set[80];
        if (!cfg->profile_auto[p] || !cfg->profile_list[p][0])
            continue;
        prof_load(&g_cache[p], cfg->profile_list[p]);
        if (!prof_match(&g_cache[p], ip))
            continue;
        prof_set_name(cfg->profile_name[p], set, sizeof(set));
        if (backend_set_add(cfg, set, ip, 0) == 0)
            slogf(SL_INFO, "profile '%s': %s -> %s (auto)",
                  cfg->profile_name[p], ip, set);
    }
}
