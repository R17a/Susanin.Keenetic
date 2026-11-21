#define _GNU_SOURCE
#include "release.h"
#include "backend.h"
#include "log.h"
#include "version.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
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

/* --- разбор JSON без внешних библиотек -------------------------------------
 * Нужны только строковые поля верхнего уровня объекта релиза (tag_name,
 * html_url). Полноценный парсер здесь избыточен, но и strstr недостаточно:
 * ключ может встретиться внутри значения или вложенного объекта (author.
 * html_url). Ниже — обход верхнего уровня: строки, объекты и массивы
 * пропускаются с учётом кавычек и глубины. \uXXXX не декодируется (tag/URL
 * GitHub его не содержат), остальные escape — базовые. */
static const char *json_ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        p++;
    return p;
}

/* Разобрать строку с кавычкой; out==NULL — только пропустить. NULL — ошибка. */
static const char *json_str(const char *p, char *out, size_t n)
{
    size_t i = 0;

    if (*p != '"')
        return NULL;
    p++;
    while (*p && *p != '"') {
        char c;

        if (*p == '\\' && p[1]) {
            p++;
            switch (*p) {
            case 'n': c = '\n'; break;
            case 'r': c = '\r'; break;
            case 't': c = '\t'; break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            case '/': c = '/'; break;
            case '"': c = '"'; break;
            case '\\': c = '\\'; break;
            default:  c = *p; break;
            }
            p++;
        } else {
            c = *p++;
        }
        if (out && i + 1 < n)
            out[i++] = c;
    }
    if (*p != '"')
        return NULL;
    p++;
    if (out && n)
        out[i] = '\0';
    return p;
}

/* Пропустить значение (строку, объект/массив или литерал). NULL — ошибка. */
static const char *json_skip(const char *p)
{
    p = json_ws(p);
    if (*p == '"')
        return json_str(p, NULL, 0);
    if (*p == '{' || *p == '[') {
        int depth = 0;

        while (*p) {
            if (*p == '"') {
                p = json_str(p, NULL, 0);
                if (!p)
                    return NULL;
                continue;
            }
            if (*p == '{' || *p == '[')
                depth++;
            else if (*p == '}' || *p == ']') {
                if (--depth == 0)
                    return p + 1;
            }
            p++;
        }
        return NULL;
    }
    while (*p && *p != ',' && *p != '}' && *p != ']')
        p++;
    return p;
}

/* Строковое поле верхнего уровня объекта. 0 — найдено. */
static int json_top_string(const char *json, const char *key,
                           char *out, size_t outsz)
{
    const char *p;
    char kbuf[128];

    if (!json || !key || !out || outsz == 0)
        return -1;
    p = json_ws(json);
    if (*p != '{')
        return -1;
    p++;
    for (;;) {
        p = json_ws(p);
        if (*p == '}')
            return -1;
        p = json_str(p, kbuf, sizeof(kbuf));
        if (!p)
            return -1;
        p = json_ws(p);
        if (*p != ':')
            return -1;
        p = json_ws(p + 1);
        if (*p == '"') {
            char vbuf[512];
            const char *q = json_str(p, vbuf, sizeof(vbuf));

            if (!q)
                return -1;
            if (!strcmp(kbuf, key)) {
                size_t l = strlen(vbuf);

                if (outsz && l >= outsz)
                    l = outsz - 1;
                if (l)
                    memcpy(out, vbuf, l);
                if (outsz)
                    out[l] = '\0';
                return 0;
            }
            p = q;
        } else {
            p = json_skip(p);
            if (!p)
                return -1;
        }
        p = json_ws(p);
        if (*p == ',') {
            p++;
            continue;
        }
        return -1;              /* '}' или мусор: поля нет */
    }
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
    if (json_top_string(json, "tag_name", raw, sizeof(raw)) != 0)
        return -1;
    copy_tag(raw, tag, tagsz);
    if (tag[0] == '\0' || !isdigit((unsigned char)tag[0]))
        return -1;
    if (url && urlsz) {
        /* Только ВЕРХНИЙ уровень: html_url внутри author — это профиль
         * автора, а не ссылка на релиз. */
        if (json_top_string(json, "html_url", rawurl, sizeof(rawurl)) == 0 &&
            (strncmp(rawurl, "https://", 8) == 0 ||
             strncmp(rawurl, "http://", 7) == 0)) {
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

/* Загрузка ответа GitHub — АСИНХРОННО: главный цикл не ждёт загрузчик.
 * Раньше fetch_to_file() крутил waitpid+usleep до 20 с прямо в цикле, и на это
 * время вставал dns_lan (DNS всей LAN). Теперь: start_fetch() форкает ребёнка и
 * возвращает pid, release_poll() забирает результат в следующем тике. */
static pid_t g_fetch_pid;
static int g_fetch_attempt;
static int g_fetch_n;
static time_t g_fetch_at;
static const susanin_config *g_fetch_cfg;

static void start_attempt(const susanin_config *c, int a);
static int read_payload(char *buf, size_t n);
static void cache_save(void);

static pid_t start_fetch(char *const argv[])
{
    pid_t pid = fork();

    if (pid < 0)
        return -1;
    if (pid == 0) {
        /* Тело пишет сам curl/wget через -o/-O; stdout/stderr уводим в /dev/null,
         * иначе текст ошибки загрузчика попадал бы в payload-файл. */
        int devnull = open("/dev/null", O_WRONLY);
        setsid();               /* своя группа: kill(-pid) добьёт внуков */
        if (devnull >= 0) {
            dup2(devnull, 1);
            dup2(devnull, 2);
            if (devnull > 2)
                close(devnull);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    return pid;
}

/* Один вариант загрузки (0 — через SOCKS Xray, затем wget, затем curl). */
static void start_attempt(const susanin_config *c, int a)
{
    char *argv[10];
    char socks_url[128];
    pid_t pid;

    argv[0] = NULL;
    if (a == 0 && c && strcmp(c->egress_type, "tproxy") == 0 &&
        backend_local_listen(c->socks_port > 0 ? c->socks_port : CFG_DEF_SOCKS_PORT)) {
        /* Прямой api.github.com с роутера душат провайдеры/ТСПУ — спрашиваем
         * через SOCKS Xray (тот же путь, что и загрузка обновлений). */
        snprintf(socks_url, sizeof(socks_url), "socks5h://%.60s:%d",
                 c->socks_addr[0] ? c->socks_addr : "127.0.0.1",
                 c->socks_port > 0 ? c->socks_port : CFG_DEF_SOCKS_PORT);
        argv[0] = "curl";
        argv[1] = "-fsS";
        argv[2] = "--max-time";
        argv[3] = "15";
        argv[4] = "-x";
        argv[5] = socks_url;
        argv[6] = "-o";
        argv[7] = (char *)RELEASE_TMP;
        argv[8] = (char *)RELEASE_API;
        argv[9] = NULL;
    } else if (a == 0) {
        argv[0] = "wget";
        argv[1] = "-q";
        argv[2] = "-T";
        argv[3] = "10";
        argv[4] = "-O";
        argv[5] = (char *)RELEASE_TMP;
        argv[6] = (char *)RELEASE_API;
        argv[7] = NULL;
    } else {
        argv[0] = "curl";
        argv[1] = "-fsS";
        argv[2] = "--max-time";
        argv[3] = "10";
        argv[4] = "-o";
        argv[5] = (char *)RELEASE_TMP;
        argv[6] = (char *)RELEASE_API;
        argv[7] = NULL;
    }
    g_fetch_cfg = c;
    g_fetch_at = time(NULL);
    pid = start_fetch(argv);
    g_fetch_pid = pid;
}

/* Разобрать загруженный payload и обновить кэш. 0 — успех. */
static int release_finish(void)
{
    char *buf;
    char tag[RELEASE_TAG_MAX], url[RELEASE_URL_MAX];

    buf = malloc(RELEASE_BODY_MAX);
    if (!buf) {
        unlink(RELEASE_TMP);
        return -1;
    }
    if (read_payload(buf, RELEASE_BODY_MAX) != 0 ||
        release_parse_payload(buf, tag, sizeof(tag), url, sizeof(url)) != 0) {
        free(buf);
        unlink(RELEASE_TMP);
        slogf(SL_WARN, "release: не удалось разобрать ответ GitHub");
        return -1;
    }
    free(buf);
    unlink(RELEASE_TMP);
    snprintf(g_info.tag, sizeof(g_info.tag), "%s", tag);
    snprintf(g_info.url, sizeof(g_info.url), "%s", url);
    g_info.checked = time(NULL);
    cache_save();
    slogf(SL_INFO, "release: последний на GitHub — %s%s", g_info.tag,
          release_update_available(SUSANIN_VERSION) ? " (есть обновление)" : "");
    return 0;
}

/* Неблокирующий сбор результата: вызывается каждый проход главного цикла. */
/* Идёт ли асинхронная загрузка: нужно движку, чтобы не пожинать чужих детей. */
int release_busy(void)
{
    return g_fetch_pid > 0;
}

void release_poll(void)
{
    int st;
    pid_t r;

    if (g_fetch_pid <= 0)
        return;
    for (;;) {
        r = waitpid(g_fetch_pid, &st, WNOHANG);
        if (r == g_fetch_pid)
            break;
        if (r < 0) {
            if (errno == EINTR)
                continue;
            g_fetch_pid = 0;
            return;
        }
        /* r == 0: ещё качаем. Общий дедлайн — 30 с, дальше убиваем группу. */
        if (time(NULL) - g_fetch_at > 30) {
            kill(-g_fetch_pid, SIGKILL);
            kill(g_fetch_pid, SIGKILL);
            (void)waitpid(g_fetch_pid, &st, 0);
            g_fetch_pid = 0;
            slogf(SL_WARN, "release: загрузка не уложилась в 30 с — отменена");
        }
        return;
    }
    g_fetch_pid = 0;
    if (WIFEXITED(st) && WEXITSTATUS(st) == 0) {
        (void)release_finish();
        return;
    }
    if (++g_fetch_attempt < g_fetch_n) {
        start_attempt(g_fetch_cfg, g_fetch_attempt);
        return;
    }
    unlink(RELEASE_TMP);
    /* НЕ помечаем проверку выполненной: иначе неудача «замораживает»
     * устаревший бейдж на весь интервал. Повтор — не раньше 60 с. */
    g_last_attempt = time(NULL);
    slogf(SL_DEBUG, "release: GitHub недоступен, повтор через 60 с");
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
    time_t now = time(NULL);
    int interval;

    if (!c || !c->release_check)
        return -1;
    if (g_fetch_pid > 0)
        return 0;               /* загрузка уже идёт — не форкаем вторую */
    interval = c->release_check_interval > 0 ? c->release_check_interval
                                             : RELEASE_DEFAULT_INTERVAL;
    if (g_info.checked > 0 && now >= g_info.checked &&
        now - g_info.checked < (time_t)interval && g_info.tag[0])
        return 0;
    /* Не долбим GitHub при ошибке: следующая попытка не раньше чем через 60 с. */
    if (g_last_attempt > 0 && now >= g_last_attempt && now - g_last_attempt < 60)
        return -1;
    g_last_attempt = now;

    /* Асинхронно: ребёнок качает, release_poll() заберёт результат. */
    g_fetch_attempt = 0;
    g_fetch_n = (strcmp(c->egress_type, "tproxy") == 0 &&
                 backend_local_listen(c->socks_port > 0 ? c->socks_port
                                                        : CFG_DEF_SOCKS_PORT))
                    ? 3 : 2;
    start_attempt(c, 0);
    return g_fetch_pid > 0 ? 0 : -1;
}
