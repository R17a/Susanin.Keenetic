#define _GNU_SOURCE
#include "release.h"
#include "log.h"
#include "version.h"

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/wait.h>
#include <unistd.h>

#define RELEASE_API "https://api.github.com/repos/R17a/Susanin.Keenetic/releases/latest"
#define RELEASE_WEB "https://github.com/R17a/Susanin.Keenetic/releases/tag/"
#define RELEASE_CACHE "/opt/susanin/var/release.state"
#define RELEASE_TMP "/opt/susanin/var/release.json.tmp"
#define RELEASE_DEFAULT_INTERVAL 43200   /* 12 ч */
#define RELEASE_BODY_MAX (256 * 1024)

static release_info g_info;
static time_t g_last_attempt;

static void copy_tag(const char *src, char *dst, size_t n)
{
    size_t i = 0;
    if (!dst || n == 0)
        return;
    if (!src)
        src = "";
    while ((src[0] == 'v' || src[0] == 'V') && src[1])
        src++;
    while (src[i] && i + 1 < n) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

/* Простое извлечение строкового поля JSON: ключ ищется вместе с кавычками,
 * escape-последовательности декодируются только базовые (tag/URL без \u). */
static int json_string(const char *json, const char *key, char *out, size_t outsz)
{
    const char *p;
    size_t i = 0;
    if (!json || !key || !out || outsz == 0)
        return -1;
    p = strstr(json, key);
    if (!p)
        return -1;
    p += strlen(key);
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        p++;
    if (*p != ':')
        return -1;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        p++;
    if (*p != '"')
        return -1;
    p++;
    while (*p && *p != '"' && i + 1 < outsz) {
        if (*p == '\\' && p[1]) {
            p++;
            switch (*p) {
            case 'n': out[i++] = '\n'; break;
            case 'r': out[i++] = '\r'; break;
            case 't': out[i++] = '\t'; break;
            default:  out[i++] = *p; break;
            }
            p++;
        } else {
            out[i++] = *p++;
        }
    }
    if (*p != '"')
        return -1;
    out[i] = '\0';
    return 0;
}

int release_parse_payload(const char *json, char *tag, size_t tagsz,
                          char *url, size_t urlsz)
{
    char raw[RELEASE_TAG_MAX];
    char rawurl[RELEASE_URL_MAX];
    if (!tag || tagsz == 0)
        return -1;
    tag[0] = '\0';
    if (url && urlsz)
        url[0] = '\0';
    if (json_string(json, "\"tag_name\"", raw, sizeof(raw)) != 0)
        return -1;
    copy_tag(raw, tag, tagsz);
    if (tag[0] == '\0' || !isdigit((unsigned char)tag[0]))
        return -1;
    if (url && urlsz) {
        if (json_string(json, "\"html_url\"", rawurl, sizeof(rawurl)) == 0 &&
            (strncmp(rawurl, "https://", 8) == 0 || strncmp(rawurl, "http://", 7) == 0)) {
            snprintf(url, urlsz, "%s", rawurl);
        } else {
            snprintf(url, urlsz, "%sv%s", RELEASE_WEB, tag);
        }
    }
    return 0;
}

typedef struct {
    unsigned maj, min, pat;
    int pre, rank;
    unsigned prenum;
} rver;

/* rank: 0 dev, 1 alpha, 2 beta, 3 rc, 4 прочий суффикс. */
static void parse_ver(const char *s, rver *v)
{
    char *end;
    memset(v, 0, sizeof(*v));
    if (!s)
        return;
    while (*s == ' ' || *s == '\t')
        s++;
    while (*s == 'v' || *s == 'V')
        s++;
    v->maj = (unsigned)strtoul(s, &end, 10);
    if (end == s)
        return;
    s = end;
    if (*s == '.') {
        v->min = (unsigned)strtoul(s + 1, &end, 10);
        if (end == s + 1)
            return;
        s = end;
    }
    if (*s == '.') {
        v->pat = (unsigned)strtoul(s + 1, &end, 10);
        if (end == s + 1)
            return;
        s = end;
    }
    if (*s != '.' && *s != '-')
        return;
    v->pre = 1;
    s++;
    if (strncasecmp(s, "dev", 3) == 0) {
        v->rank = 0;
        v->prenum = (unsigned)strtoul(s + 3, NULL, 10);
    } else if (strncasecmp(s, "alpha", 5) == 0) {
        v->rank = 1;
        v->prenum = (unsigned)strtoul(s + 5, NULL, 10);
    } else if (strncasecmp(s, "beta", 4) == 0) {
        v->rank = 2;
        v->prenum = (unsigned)strtoul(s + 4, NULL, 10);
    } else if (strncasecmp(s, "rc", 2) == 0) {
        v->rank = 3;
        v->prenum = (unsigned)strtoul(s + 2, NULL, 10);
    } else {
        v->rank = 4;
        v->prenum = (unsigned)strtoul(s, NULL, 10);
    }
}

int release_version_cmp(const char *a, const char *b)
{
    rver va, vb;
    parse_ver(a, &va);
    parse_ver(b, &vb);
    if (va.maj != vb.maj)
        return va.maj < vb.maj ? -1 : 1;
    if (va.min != vb.min)
        return va.min < vb.min ? -1 : 1;
    if (va.pat != vb.pat)
        return va.pat < vb.pat ? -1 : 1;
    if (va.pre != vb.pre)
        return va.pre ? -1 : 1;       /* dev/RC старее релиза */
    if (va.pre) {
        if (va.rank != vb.rank)
            return va.rank < vb.rank ? -1 : 1;
        if (va.prenum != vb.prenum)
            return va.prenum < vb.prenum ? -1 : 1;
    }
    return 0;
}

const release_info *release_get(void)
{
    return &g_info;
}

int release_update_available(const char *current)
{
    return g_info.tag[0] && release_version_cmp(g_info.tag, current) > 0;
}

static void cache_load(void)
{
    FILE *fp;
    char line[RELEASE_URL_MAX + 64];
    memset(&g_info, 0, sizeof(g_info));
    fp = fopen(RELEASE_CACHE, "r");
    if (!fp)
        return;
    while (fgets(line, sizeof(line), fp)) {
        char *nl = line + strlen(line);
        while (nl > line && (nl[-1] == '\n' || nl[-1] == '\r'))
            *--nl = '\0';
        if (strncmp(line, "tag=", 4) == 0)
            copy_tag(line + 4, g_info.tag, sizeof(g_info.tag));
        else if (strncmp(line, "url=", 4) == 0)
            snprintf(g_info.url, sizeof(g_info.url), "%.*s",
                     (int)sizeof(g_info.url) - 1, line + 4);
        else if (strncmp(line, "checked=", 8) == 0)
            g_info.checked = (time_t)strtol(line + 8, NULL, 10);
    }
    fclose(fp);
}

static void cache_save(void)
{
    char tmp[sizeof(RELEASE_CACHE) + 8];
    FILE *fp;
    snprintf(tmp, sizeof(tmp), "%s.tmp", RELEASE_CACHE);
    fp = fopen(tmp, "w");
    if (!fp)
        return;
    if (g_info.tag[0])
        fprintf(fp, "tag=%s\n", g_info.tag);
    if (g_info.url[0])
        fprintf(fp, "url=%s\n", g_info.url);
    fprintf(fp, "checked=%ld\n", (long)g_info.checked);
    fflush(fp);
    fclose(fp);
    if (rename(tmp, RELEASE_CACHE) != 0)
        unlink(tmp);
}

static int fetch_to_file(char *const argv[], const char *path)
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

static int fetch_payload(void)
{
    char *wget_argv[8];
    char *curl_argv[8];
    int rc;

    wget_argv[0] = "wget";
    wget_argv[1] = "-q";
    wget_argv[2] = "-T";
    wget_argv[3] = "10";
    wget_argv[4] = "-O";
    wget_argv[5] = (char *)RELEASE_TMP;
    wget_argv[6] = (char *)RELEASE_API;
    wget_argv[7] = NULL;
    rc = fetch_to_file(wget_argv, RELEASE_TMP);

    if (rc != 0) {
        curl_argv[0] = "curl";
        curl_argv[1] = "-fsS";
        curl_argv[2] = "--max-time";
        curl_argv[3] = "10";
        curl_argv[4] = "-o";
        curl_argv[5] = (char *)RELEASE_TMP;
        curl_argv[6] = (char *)RELEASE_API;
        curl_argv[7] = NULL;
        rc = fetch_to_file(curl_argv, RELEASE_TMP);
    }
    return rc == 0 ? 0 : -1;
}

static int read_payload(char *buf, size_t n)
{
    FILE *fp = fopen(RELEASE_TMP, "r");
    size_t got;
    if (!fp)
        return -1;
    got = fread(buf, 1, n - 1, fp);
    fclose(fp);
    buf[got] = '\0';
    return got > 0 ? 0 : -1;
}

void release_init(const susanin_config *c)
{
    (void)c;
    g_last_attempt = 0;
    cache_load();
}

int release_check_now(const susanin_config *c)
{
    char *buf;
    char tag[RELEASE_TAG_MAX], url[RELEASE_URL_MAX];
    time_t now = time(NULL);
    int interval;

    if (!c || !c->release_check)
        return -1;
    interval = c->release_check_interval > 0 ? c->release_check_interval
                                             : RELEASE_DEFAULT_INTERVAL;
    if (g_info.checked > 0 && now >= g_info.checked &&
        now - g_info.checked < (time_t)interval && g_info.tag[0])
        return 0;
    /* Не долбим GitHub при ошибке: следующая попытка не раньше чем через 60 с. */
    if (g_last_attempt > 0 && now >= g_last_attempt && now - g_last_attempt < 60)
        return -1;
    g_last_attempt = now;

    if (fetch_payload() != 0) {
        g_info.checked = now;
        slogf(SL_DEBUG, "release: GitHub недоступен, проверка отложена");
        unlink(RELEASE_TMP);
        return -1;
    }
    buf = malloc(RELEASE_BODY_MAX);
    if (!buf) {
        unlink(RELEASE_TMP);
        return -1;
    }
    if (read_payload(buf, RELEASE_BODY_MAX) != 0 ||
        release_parse_payload(buf, tag, sizeof(tag), url, sizeof(url)) != 0) {
        free(buf);
        unlink(RELEASE_TMP);
        g_info.checked = now;
        slogf(SL_WARN, "release: не удалось разобрать ответ GitHub");
        return -1;
    }
    free(buf);
    unlink(RELEASE_TMP);
    snprintf(g_info.tag, sizeof(g_info.tag), "%s", tag);
    snprintf(g_info.url, sizeof(g_info.url), "%s", url);
    g_info.checked = now;
    cache_save();
    slogf(SL_INFO, "release: последний на GitHub — %s%s", g_info.tag,
          release_update_available(SUSANIN_VERSION) ? " (есть обновление)" : "");
    return 0;
}
