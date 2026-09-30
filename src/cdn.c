#define _GNU_SOURCE
#include "cdn.h"
#include "log.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define CDN_MAX_RANGES 512

typedef struct {
    uint32_t net;   /* сетевой адрес (host order) */
    int pre;        /* длина префикса */
} cdn_range;

static cdn_range g[CDN_MAX_RANGES];
static int gn = 0;

static uint32_t pre_mask(int pre)
{
    if (pre <= 0)
        return 0;
    if (pre >= 32)
        return 0xffffffffu;
    return 0xffffffffu << (32 - pre);
}

int cdn_load(const susanin_config *c)
{
    FILE *fp;
    char line[128];
    int n = 0;
    gn = 0;
    if (!c || !c->cdn_ranges_file[0])
        return 0;
    fp = fopen(c->cdn_ranges_file, "r");
    if (!fp)
        return 0;
    while (fgets(line, sizeof(line), fp) && n < CDN_MAX_RANGES) {
        char *h = strchr(line, '#');
        char *slash;
        struct in_addr a;
        int pre;
        if (h)
            *h = '\0';
        {
            char *p = line;
            while (*p == ' ' || *p == '\t')
                p++;
            slash = strchr(p, '/');
            if (!slash)
                continue;
            *slash = '\0';
            pre = atoi(slash + 1);
            if (pre < 0 || pre > 32)
                continue;
            if (inet_pton(AF_INET, p, &a) != 1)
                continue;
            g[n].net = ntohl(a.s_addr) & pre_mask(pre);
            g[n].pre = pre;
            n++;
        }
    }
    fclose(fp);
    gn = n;
    return n;
}

int cdn_match(const susanin_config *c, const char *ip, char *out, size_t outsz)
{
    struct in_addr a;
    uint32_t ah;
    int i, best = -1, pre;
    if (!c || gn <= 0 || !ip || !out || !outsz)
        return 0;
    if (inet_pton(AF_INET, ip, &a) != 1)
        return 0;
    ah = ntohl(a.s_addr);
    for (i = 0; i < gn; i++) {
        if ((ah & pre_mask(g[i].pre)) != g[i].net)
            continue;
        if (best < 0 || g[i].pre > g[best].pre)
            best = i;
    }
    if (best < 0)
        return 0;
    pre = g[best].pre;
    /* Не шире cdn_prefix_max: например, совпал 104.16.0.0/13, а cdn_prefix_max=24
     * → агрегируем только /24 вокруг адреса (меньше «радиус» и нагрузка). */
    if (c->cdn_prefix_max > pre)
        pre = c->cdn_prefix_max;
    if (pre > 32)
        pre = 32;
    {
        uint32_t base = ah & pre_mask(pre);
        struct in_addr b;
        char ab[INET_ADDRSTRLEN];
        b.s_addr = htonl(base);
        if (!inet_ntop(AF_INET, &b, ab, sizeof(ab)))
            return 0;
        snprintf(out, outsz, "%s/%d", ab, pre);
    }
    return 1;
}

int cdn_count(void)
{
    return gn;
}

static int run_to_file(char *const argv[], const char *path)
{
    pid_t pid = fork();
    int st = -1;
    if (pid < 0)
        return -1;
    if (pid == 0) {
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            dup2(fd, 1);
            dup2(fd, 2);
            if (fd > 2)
                close(fd);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    if (waitpid(pid, &st, 0) < 0)
        return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

int cdn_refresh(const susanin_config *c)
{
    char tmp[CFG_PATH_MAX + 8];
    char *wget_argv[8];
    char *curl_argv[8];
    int rc;
    if (!c || !c->cdn_ranges_url[0] || !c->cdn_ranges_file[0])
        return -1;
    snprintf(tmp, sizeof(tmp), "%s.tmp", c->cdn_ranges_file);

    wget_argv[0] = "wget";
    wget_argv[1] = "-q";
    wget_argv[2] = "-T";
    wget_argv[3] = "10";
    wget_argv[4] = "-O";
    wget_argv[5] = tmp;
    wget_argv[6] = (char *)c->cdn_ranges_url;
    wget_argv[7] = NULL;
    rc = run_to_file(wget_argv, tmp);

    if (rc != 0) {
        curl_argv[0] = "curl";
        curl_argv[1] = "-fsS";
        curl_argv[2] = "--max-time";
        curl_argv[3] = "10";
        curl_argv[4] = "-o";
        curl_argv[5] = tmp;
        curl_argv[6] = (char *)c->cdn_ranges_url;
        curl_argv[7] = NULL;
        rc = run_to_file(curl_argv, tmp);
    }
    if (rc != 0) {
        unlink(tmp);
        return -1;
    }
    if (rename(tmp, c->cdn_ranges_file) != 0) {
        unlink(tmp);
        return -1;
    }
    cdn_load(c);
    slogf(SL_INFO, "CDN: диапазоны обновлены (%d сетей) из %s", gn, c->cdn_ranges_url);
    return 0;
}
