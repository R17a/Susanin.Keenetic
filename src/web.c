/* Встроенная веб-панель Susanin.Keenetic (W1).
 *
 * Мини-HTTP-сервер в самом агенте: без внешних зависимостей, один бинарь на
 * всех архитектурах. Слушает ТОЛЬКО LAN-адрес (web_listen), вход по токену
 * (web_token) либо без него — тогда с предупреждением. Отдаёт:
 *   GET /api/status   — JSON-снимок (read-only, ops_status_json)
 *   GET /api/config   — текущие параметры конфига (секреты маскируются)
 *   POST /api/config  — правка существующих ключей (form-urlencoded)
 *   GET /api/list?name=vpn_always|vpn_never — содержимое списка (read-only)
 *   GET /<path>       — статика из SUSANIN_WWW_ROOT
 * По умолчанию Web выключен (web_enable=0). Не трогаем чужие конфиги/порты. */

#define _GNU_SOURCE
#include "web.h"
#include "ops.h"
#include "log.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SUSANIN_WWW_ROOT
#define SUSANIN_WWW_ROOT "/opt/susanin/www"
#endif

#define REQ_MAX 8192
#define MAX_BODY 16384

static const char *status_text(int code)
{
    switch (code) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 500: return "Internal Server Error";
    default:  return "Error";
    }
}

static int send_all(int fd, const void *data, size_t n)
{
    const char *p = (const char *)data;
    while (n) {
        ssize_t w = send(fd, p, n, 0);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (w == 0)
            return -1;
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

static void reply(int fd, int code, const char *ctype, const void *body,
                  size_t len, int head_only)
{
    char hdr[256];
    int hl = snprintf(hdr, sizeof(hdr),
                      "HTTP/1.1 %d %s\r\n"
                      "Content-Type: %s\r\n"
                      "Content-Length: %zu\r\n"
                      "Cache-Control: no-store\r\n"
                      "Connection: close\r\n"
                      "X-Content-Type-Options: nosniff\r\n"
                      "\r\n",
                      code, status_text(code), ctype, len);
    if (hl < 0)
        return;
    if (send_all(fd, hdr, (size_t)hl) != 0)
        return;
    if (!head_only && len)
        send_all(fd, body, len);
}

static void reply_text(int fd, int code, const char *msg, int head_only)
{
    char body[256];
    int n = snprintf(body, sizeof(body), "%s\n", msg ? msg : "");
    if (n < 0)
        n = 0;
    reply(fd, code, "text/plain; charset=utf-8", body, (size_t)n, head_only);
}

static const char *mime_for(const char *path)
{
    const char *dot = strrchr(path, '.');
    if (!dot)
        return "application/octet-stream";
    if (!strcasecmp(dot, ".html") || !strcasecmp(dot, ".htm"))
        return "text/html; charset=utf-8";
    if (!strcasecmp(dot, ".css"))
        return "text/css; charset=utf-8";
    if (!strcasecmp(dot, ".js"))
        return "application/javascript; charset=utf-8";
    if (!strcasecmp(dot, ".json"))
        return "application/json; charset=utf-8";
    if (!strcasecmp(dot, ".svg"))
        return "image/svg+xml";
    if (!strcasecmp(dot, ".png"))
        return "image/png";
    if (!strcasecmp(dot, ".ico"))
        return "image/x-icon";
    if (!strcasecmp(dot, ".woff2"))
        return "font/woff2";
    if (!strcasecmp(dot, ".txt"))
        return "text/plain; charset=utf-8";
    return "application/octet-stream";
}

static int has_dotdot(const char *p)
{
    for (; p && p[0]; p++)
        if (p[0] == '.' && p[1] == '.')
            return 1;
    return 0;
}

/* Белый список расширений статики: через www нельзя отдать .conf/.token и пр. */
static int ext_allowed(const char *path)
{
    static const char *ok[] = { ".html", ".htm", ".css", ".js", ".svg", ".png",
                                ".jpg", ".jpeg", ".gif", ".ico", ".woff",
                                ".woff2", ".webmanifest", NULL };
    const char *dot = strrchr(path, '.');
    int i;
    if (!dot)
        return 0;
    for (i = 0; ok[i]; i++)
        if (!strcasecmp(dot, ok[i]))
            return 1;
    return 0;
}

/* Отдать файл из www_root (доступ уже проверен по токену). Путь канонизируется:
 * реальный файл обязан лежать внутри www_root (защита от симлинков и «../»), и
 * расширение — из белого списка (никаких .conf и т.п.). */
static void serve_file(int fd, const char *root, const char *rel, int head_only)
{
    char path[512];
    char *real = NULL, *rootr = NULL;
    struct stat st;
    int f;
    size_t rl;

    if (has_dotdot(rel)) {
        reply_text(fd, 403, "forbidden", head_only);
        return;
    }
    if (rel[0] == '/')
        rel++;
    if (rel[0] == '\0')
        rel = "index.html";

    {
        size_t l = strlen(rel);
        int r;
        if (l && rel[l - 1] == '/')
            r = snprintf(path, sizeof(path), "%s/%sindex.html", root, rel);
        else
            r = snprintf(path, sizeof(path), "%s/%s", root, rel);
        if (r < 0 || (size_t)r >= sizeof(path)) {
            reply_text(fd, 404, "not found", head_only);
            return;
        }
    }

    /* realpath(.., NULL) — malloc-вариант: не зависит от PATH_MAX и fortify. */
    rootr = realpath(root, NULL);
    real = realpath(path, NULL);
    if (!rootr || !real) {
        free(rootr);
        free(real);
        reply_text(fd, 404, "not found", head_only);
        return;
    }
    if (stat(real, &st) == 0 && S_ISDIR(st.st_mode)) {
        char idx[600];
        char *ri;
        int r = snprintf(idx, sizeof(idx), "%s/index.html", real);
        if (r < 0 || (size_t)r >= sizeof(idx)) {
            free(rootr);
            free(real);
            reply_text(fd, 404, "not found", head_only);
            return;
        }
        ri = realpath(idx, NULL);
        free(real);
        real = ri;
        if (!real) {
            free(rootr);
            reply_text(fd, 404, "not found", head_only);
            return;
        }
    }
    rl = strlen(rootr);
    if (strncmp(real, rootr, rl) != 0 || (real[rl] != '/' && real[rl] != '\0')) {
        free(rootr);
        free(real);
        reply_text(fd, 403, "forbidden", head_only);
        return;
    }
    if (!ext_allowed(real)) {
        free(rootr);
        free(real);
        reply_text(fd, 403, "forbidden", head_only);
        return;
    }

    f = open(real, O_RDONLY);
    if (f < 0) {
        free(rootr);
        free(real);
        reply_text(fd, 404, "not found", head_only);
        return;
    }
    if (fstat(f, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(f);
        free(rootr);
        free(real);
        reply_text(fd, 404, "not found", head_only);
        return;
    }

    {
        char hdr[256];
        int hl = snprintf(hdr, sizeof(hdr),
                          "HTTP/1.1 200 OK\r\n"
                          "Content-Type: %s\r\n"
                          "Content-Length: %lld\r\n"
                          "Cache-Control: no-store\r\n"
                          "Connection: close\r\n"
                          "X-Content-Type-Options: nosniff\r\n"
                          "\r\n",
                          mime_for(real), (long long)st.st_size);
        if (hl < 0 || send_all(fd, hdr, (size_t)hl) != 0) {
            close(f);
            free(rootr);
            free(real);
            return;
        }
    }
    if (!head_only) {
        char buf[4096];
        ssize_t r;
        while ((r = read(f, buf, sizeof(buf))) > 0) {
            if (send_all(fd, buf, (size_t)r) != 0)
                break;
        }
    }
    close(f);
    free(rootr);
    free(real);
}

/* Хвост лога агента. В soft-режиме лог на диск не пишется — отдаём пояснение. */
static void serve_log(int fd, const susanin_config *cfg, const char *query, int head_only)
{
    const char *path = "/opt/susanin/var/susanin.log";
    int want = 200, f;
    off_t sz;
    size_t cap = 65536, start, i;
    char *buf;
    ssize_t r;
    const char *out;
    size_t outlen;

    if (!strcmp(cfg->disk_mode, "soft")) {
        reply_text(fd, 200, "log disabled (disk_mode=soft)", head_only);
        return;
    }
    if (query) {
        const char *p = strstr(query, "lines=");
        if (p) {
            int v = atoi(p + 6);
            if (v > 0 && v <= 1000)
                want = v;
        }
    }
    f = open(path, O_RDONLY);
    if (f < 0) {
        reply_text(fd, 200, "(no log file)", head_only);
        return;
    }
    sz = lseek(f, 0, SEEK_END);
    start = (sz > (off_t)cap) ? (size_t)(sz - (off_t)cap) : 0;
    if (lseek(f, (off_t)start, SEEK_SET) < 0) {
        close(f);
        reply_text(fd, 200, "(log read error)", head_only);
        return;
    }
    buf = malloc(cap + 1);
    if (!buf) {
        close(f);
        reply_text(fd, 500, "oom", head_only);
        return;
    }
    r = read(f, buf, cap);
    close(f);
    if (r < 0)
        r = 0;
    buf[r] = '\0';

    {
        size_t nl = 0;
        for (i = 0; i < (size_t)r; i++)
            if (buf[i] == '\n')
                nl++;
        if (nl <= (size_t)want) {
            out = buf;
            outlen = (size_t)r;
        } else {
            size_t skip = nl - (size_t)want, seen = 0, pos = 0;
            for (i = 0; i < (size_t)r; i++) {
                if (buf[i] == '\n') {
                    seen++;
                    if (seen == skip) {
                        pos = i + 1;
                        break;
                    }
                }
            }
            out = buf + pos;
            outlen = (size_t)r - pos;
        }
    }
    reply(fd, 200, "text/plain; charset=utf-8", out, outlen, head_only);
    free(buf);
}

static int token_ok(const susanin_config *cfg, const char *req, const char *query)
{
    char need[128];
    const char *tok = cfg->web_token;

    if (!tok[0])
        return 1; /* токен не задан — доступ открыт (только LAN) */

    if (query) {
        const char *p = strstr(query, "token=");
        if (p) {
            size_t i = 0;
            p += 6;
            while (p[i] && p[i] != '&' && i + 1 < sizeof(need)) {
                need[i] = p[i];
                i++;
            }
            need[i] = '\0';
            if (!strcmp(need, tok))
                return 1;
        }
    }
    {
        const char *p = strstr(req, "susanin_token=");
        if (p) {
            size_t i = 0;
            p += 15;
            while (p[i] && p[i] != ';' && p[i] != '\r' && i + 1 < sizeof(need)) {
                need[i] = p[i];
                i++;
            }
            need[i] = '\0';
            if (!strcmp(need, tok))
                return 1;
        }
    }
    {
        const char *p = strstr(req, "X-Auth-Token:");
        if (!p)
            p = strstr(req, "x-auth-token:");
        if (p) {
            p = strchr(p, ':');
            if (p) {
                size_t i = 0;
                p++;
                while (*p == ' ' || *p == '\t')
                    p++;
                while (p[i] && p[i] != '\r' && p[i] != '\n' && i + 1 < sizeof(need)) {
                    need[i] = p[i];
                    i++;
                }
                need[i] = '\0';
                if (!strcmp(need, tok))
                    return 1;
            }
        }
    }
    return 0;
}

/* --- W3: действия (POST) --------------------------------------- */

static void json_ok(int fd, const char *extra)
{
    char b[256];
    int n = snprintf(b, sizeof(b), "{\"ok\":true%s%s}", extra ? "," : "", extra ? extra : "");
    if (n < 0)
        n = 0;
    reply(fd, 200, "application/json; charset=utf-8", b, (size_t)n, 0);
}

static void json_err(int fd, const char *msg)
{
    char b[512], esc[256];
    const char *s = msg ? msg : "";
    size_t j = 0;
    for (; *s && j + 1 < sizeof(esc); s++) {
        if (*s == '"' || *s == '\\')
            esc[j++] = '\\';
        if (*s == '\n')
            continue;
        esc[j++] = *s;
    }
    esc[j] = '\0';
    {
        int n = snprintf(b, sizeof(b), "{\"ok\":false,\"error\":\"%s\"}", esc);
        if (n < 0)
            n = 0;
        reply(fd, 200, "application/json; charset=utf-8", b, (size_t)n, 0);
    }
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Значение form-urlencoded-параметра key из тела запроса. */
static int form_get(const char *body, const char *key, char *out, size_t n)
{
    size_t klen = strlen(key);
    const char *p = body;
    if (!n)
        return 0;
    out[0] = '\0';
    while (p && *p) {
        const char *amp = strchr(p, '&');
        size_t seg = amp ? (size_t)(amp - p) : strlen(p);
        const char *eq = memchr(p, '=', seg);
        if (eq && (size_t)(eq - p) == klen && !strncmp(p, key, klen)) {
            const char *v = eq + 1;
            size_t vlen = (size_t)((p + seg) - v), i = 0, j = 0;
            while (i < vlen && j + 1 < n) {
                char c = v[i++];
                if (c == '+') {
                    c = ' ';
                } else if (c == '%' && i + 1 < vlen) {
                    int h = hexval((unsigned char)v[i]);
                    int l = hexval((unsigned char)v[i + 1]);
                    if (h >= 0 && l >= 0) {
                        c = (char)((h << 4) | l);
                        i += 2;
                    }
                }
                out[j++] = c;
            }
            out[j] = '\0';
            return 1;
        }
        p = amp ? amp + 1 : NULL;
    }
    return 0;
}

/* Разбор одной form-пары "k=v" (значения URL-декодируются). */
static int pair_get(const char *p, size_t seg, char *k, size_t ksz, char *v, size_t vsz)
{
    const char *eq = memchr(p, '=', seg);
    size_t n, i, j, vn;
    const char *vv;

    if (!eq || !ksz || !vsz)
        return 0;
    n = (size_t)(eq - p);
    j = 0;
    for (i = 0; i < n && j + 1 < ksz; i++) {
        char c = p[i];
        if (c == '+') {
            c = ' ';
        } else if (c == '%' && i + 2 < n) {
            int h = hexval((unsigned char)p[i + 1]);
            int l = hexval((unsigned char)p[i + 2]);
            if (h >= 0 && l >= 0) { c = (char)((h << 4) | l); i += 2; }
        }
        k[j++] = c;
    }
    k[j] = '\0';

    vv = eq + 1;
    vn = seg - n - 1;
    j = 0;
    for (i = 0; i < vn && j + 1 < vsz; i++) {
        char c = vv[i];
        if (c == '+') {
            c = ' ';
        } else if (c == '%' && i + 2 < vn) {
            int h = hexval((unsigned char)vv[i + 1]);
            int l = hexval((unsigned char)vv[i + 2]);
            if (h >= 0 && l >= 0) { c = (char)((h << 4) | l); i += 2; }
        }
        v[j++] = c;
    }
    v[j] = '\0';
    return 1;
}

/* Что можно править через /api/config. Секрет web_token менять нельзя;
 * web_listen не должен стать 0.0.0.0 (иначе веб не поднимется). */
static int config_value_ok(const char *k, const char *v)
{
    if (!strcmp(k, "web_token"))
        return 0;
    if (!strcmp(k, "web_listen")) {
        struct in_addr a;
        if (!v[0] || !strcmp(v, "0.0.0.0") || inet_pton(AF_INET, v, &a) != 1)
            return 0;
    }
    return 1;
}

static int signal_agent(int sig, char *err, size_t errsz)
{
    FILE *f = fopen("/opt/susanin/var/susanin-agent.pid", "r");
    long pid = 0;
    if (f) {
        if (fscanf(f, "%ld", &pid) != 1)
            pid = 0;
        fclose(f);
    }
    if (pid <= 0) {
        snprintf(err, errsz, "agent pid not found");
        return -1;
    }
    if (kill((pid_t)pid, sig) != 0) {
        snprintf(err, errsz, "kill: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static int run_script(const char *arg)
{
    pid_t p = fork();
    if (p == 0) {
        int dn = open("/dev/null", O_WRONLY);
        if (dn >= 0) {
            dup2(dn, 1);
            dup2(dn, 2);
            close(dn);
        }
        execl("/bin/sh", "sh", "/opt/susanin/tools/susanin.sh", arg, (char *)NULL);
        _exit(127);
    }
    if (p < 0)
        return -1;
    {
        int st;
        if (waitpid(p, &st, 0) < 0)
            return -1;
        return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    }
}

static int valid_entry(const char *s)
{
    if (!s || !*s || strlen(s) > 253)
        return 0;
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (!(isalnum(c) || c == '.' || c == '-' || c == '_' || c == ':' ||
              c == '/' || c == '*'))
            return 0;
    }
    return 1;
}

/* add=1 — добавить строку, add=0 — удалить. Бэкап рядом (.bak-Ymd-HMS). */
static int list_edit(const char *path, const char *val, int add,
                     char *err, size_t errsz)
{
    char bak[600], tmp[600], line[512];
    time_t t = time(NULL);
    struct tm tm;
    FILE *in, *out;
    int found = 0, changed = 0, last_nl = 1;

    localtime_r(&t, &tm);
    snprintf(bak, sizeof(bak), "%s.bak-%04d%02d%02d-%02d%02d%02d", path,
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);

    {
        FILE *s = fopen(path, "r");
        if (s) {
            FILE *d = fopen(bak, "w");
            if (d) {
                int c;
                while ((c = fgetc(s)) != EOF)
                    fputc(c, d);
                fclose(d);
            }
            fclose(s);
        }
    }

    in = fopen(path, "r");
    out = fopen(tmp, "w");
    if (!out) {
        if (in)
            fclose(in);
        snprintf(err, errsz, "cannot write list file");
        return -1;
    }
    if (in) {
        while (fgets(line, sizeof(line), in)) {
            char *p = line, *e;
            while (*p == ' ' || *p == '\t')
                p++;
            e = p + strlen(p);
            while (e > p && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ' || e[-1] == '\t'))
                *--e = '\0';
            if (!strcmp(p, val)) {
                found = 1;
                if (add) {
                    fputs(line, out);
                    last_nl = (line[0] && line[strlen(line) - 1] == '\n');
                } else {
                    changed = 1; /* строку пропускаем */
                }
                continue;
            }
            fputs(line, out);
            last_nl = (line[0] && line[strlen(line) - 1] == '\n');
        }
        fclose(in);
    }
    if (add && !found) {
        if (!last_nl)
            fputc('\n', out);
        fprintf(out, "%s\n", val);
        changed = 1;
    }
    fclose(out);
    if (changed)
        rename(tmp, path);
    else
        remove(tmp);
    return changed ? 1 : 0;
}

static void handle_action(int fd, const susanin_config *cfg, const char *target,
                          const char *body)
{
    char a[CFG_PATH_MAX], b[128], err[160];

    if (!strcmp(target, "/api/reset") || !strcmp(target, "/api/forget")) {
        if (!form_get(body, "ip", a, sizeof(a)) || !a[0]) { json_err(fd, "value required"); return; }
        ops_reset(cfg, a);
        json_ok(fd, "\"action\":\"reset\"");
        return;
    }
    if (!strcmp(target, "/api/reload")) {
        if (signal_agent(SIGHUP, err, sizeof(err)) != 0) { json_err(fd, err); return; }
        json_ok(fd, "\"action\":\"reload\"");
        return;
    }
    if (!strcmp(target, "/api/config")) {
        const char *p = body;
        int applied = 0;
        char bad[64] = "";
        while (p && *p) {
            const char *amp = strchr(p, '&');
            size_t seg = amp ? (size_t)(amp - p) : strlen(p);
            char k[64], v[512];
            if (seg && pair_get(p, seg, k, sizeof(k), v, sizeof(v)) && k[0]) {
                if (config_value_ok(k, v) &&
                    config_file_set(ops_default_conf_path(), k, v) == 0)
                    applied++;
                else if (!bad[0])
                    snprintf(bad, sizeof(bad), "%s", k);
            }
            p = amp ? amp + 1 : NULL;
        }
        if (applied > 0) {
            char e2[128];
            signal_agent(SIGHUP, e2, sizeof(e2));
            json_ok(fd, "\"action\":\"config\"");
        } else {
            char e[128];
            snprintf(e, sizeof(e), "no updatable keys (%s)", bad[0] ? bad : "none");
            json_err(fd, e);
        }
        return;
    }
    if (!strcmp(target, "/api/rescan")) {
        if (run_script("rescan") != 0) { json_err(fd, "rescan failed"); return; }
        json_ok(fd, "\"action\":\"rescan\"");
        return;
    }
    if (!strcmp(target, "/api/restart")) {
        if (run_script("restart") != 0) { json_err(fd, "restart failed"); return; }
        json_ok(fd, "\"action\":\"restart\"");
        return;
    }
    if (!strcmp(target, "/api/list")) {
        char op[8];
        const char *path = NULL;
        form_get(body, "list", b, sizeof(b));
        if (!strcmp(b, "vpn_always"))
            path = cfg->vpn_always_file;
        else if (!strcmp(b, "vpn_never"))
            path = cfg->vpn_never_file;
        if (!path || !path[0]) { json_err(fd, "bad list"); return; }
        if (!form_get(body, "value", a, sizeof(a)) || !valid_entry(a)) { json_err(fd, "bad value"); return; }
        if (!form_get(body, "op", op, sizeof(op))) { json_err(fd, "op required"); return; }
        if (!strcmp(op, "add") || !strcmp(op, "del")) {
            int r = list_edit(path, a, !strcmp(op, "add"), err, sizeof(err));
            if (r < 0) { json_err(fd, err); return; }
            signal_agent(SIGHUP, err, sizeof(err));
            json_ok(fd, "\"action\":\"list\"");
            return;
        }
        json_err(fd, "bad op");
        return;
    }
    reply_text(fd, 404, "no such api", 0);
}

static void handle_conn(int fd, const susanin_config *cfg)
{
    char req[REQ_MAX];
    char method[8] = { 0 };
    char target[1024] = { 0 };
    char body[4096] = { 0 };
    char *query = NULL;
    size_t len = 0;
    int head_only = 0;

    while (len < sizeof(req) - 1) {
        ssize_t r = recv(fd, req + len, sizeof(req) - 1 - len, 0);
        if (r <= 0)
            break;
        len += (size_t)r;
        req[len] = '\0';
        if (strstr(req, "\r\n\r\n"))
            break;
    }
    if (len == 0)
        return;

    {
        char *nl = strchr(req, ' ');
        char *sp, *t;
        size_t ml, tl;
        if (!nl) {
            reply_text(fd, 400, "bad request", 0);
            return;
        }
        ml = (size_t)(nl - req);
        if (ml >= sizeof(method))
            ml = sizeof(method) - 1;
        memcpy(method, req, ml);
        method[ml] = '\0';
        t = nl + 1;
        sp = strchr(t, ' ');
        if (!sp) {
            reply_text(fd, 400, "bad request", 0);
            return;
        }
        tl = (size_t)(sp - t);
        if (tl >= sizeof(target))
            tl = sizeof(target) - 1;
        memcpy(target, t, tl);
        target[tl] = '\0';
    }

    if (!strcmp(method, "HEAD")) {
        head_only = 1;
    } else if (strcmp(method, "GET") != 0 && strcmp(method, "POST") != 0) {
        reply_text(fd, 405, "method not allowed", 0);
        return;
    }

    query = strchr(target, '?');
    if (query) {
        *query = '\0';
        query++;
    }

    {
        const char *cl = strstr(req, "Content-Length:");
        if (!cl)
            cl = strstr(req, "content-length:");
        if (cl) {
            int want = atoi(cl + 15);
            char *end = strstr(req, "\r\n\r\n");
            size_t hdrlen = end ? (size_t)(end - req) + 4 : len;
            size_t have = (len > hdrlen) ? len - hdrlen : 0;
            size_t need = (want > 0 && (size_t)want < sizeof(body)) ? (size_t)want : 0;
            if (have > need)
                have = need;
            if (have)
                memcpy(body, req + hdrlen, have);
            while (have < need) {
                ssize_t rr = recv(fd, body + have, need - have, 0);
                if (rr <= 0)
                    break;
                have += (size_t)rr;
            }
            body[have] = '\0';
        }
    }

    if (!token_ok(cfg, req, query)) {
        reply_text(fd, 401, "unauthorized", head_only);
        return;
    }

    if (!strcmp(method, "POST")) {
        handle_action(fd, cfg, target, body);
        return;
    }

    if (!strcmp(target, "/api/status")) {
        char *jb = malloc(MAX_BODY);
        if (!jb) {
            reply_text(fd, 500, "oom", head_only);
            return;
        }
        ops_status_json(cfg, ops_default_conf_path(), jb, MAX_BODY);
        reply(fd, 200, "application/json; charset=utf-8", jb, strlen(jb), head_only);
        free(jb);
        return;
    }
    if (!strcmp(target, "/api/config")) {
        char *jb = malloc(MAX_BODY);
        if (!jb) {
            reply_text(fd, 500, "oom", head_only);
            return;
        }
        ops_config_json(cfg, ops_default_conf_path(), jb, MAX_BODY);
        reply(fd, 200, "application/json; charset=utf-8", jb, strlen(jb), head_only);
        free(jb);
        return;
    }
    if (!strcmp(target, "/api/log")) {
        serve_log(fd, cfg, query, head_only);
        return;
    }
    if (!strcmp(target, "/api/list")) {
        char name[32] = { 0 };
        char *jb;
        if (query) {
            const char *p = strstr(query, "name=");
            if (p) {
                size_t i = 0;
                p += 5;
                while (p[i] && p[i] != '&' && i + 1 < sizeof(name)) {
                    name[i] = p[i];
                    i++;
                }
                name[i] = '\0';
            }
        }
        if (strcmp(name, "vpn_always") && strcmp(name, "vpn_never")) {
            reply_text(fd, 400, "bad name", head_only);
            return;
        }
        jb = malloc(MAX_BODY);
        if (!jb) {
            reply_text(fd, 500, "oom", head_only);
            return;
        }
        ops_list_json(cfg, name, jb, MAX_BODY);
        reply(fd, 200, "application/json; charset=utf-8", jb, strlen(jb), head_only);
        free(jb);
        return;
    }
    if (!strncmp(target, "/api/", 5)) {
        reply_text(fd, 404, "no such api", head_only);
        return;
    }

    serve_file(fd, SUSANIN_WWW_ROOT, target, head_only);
}

int web_run(const susanin_config *cfg)
{
    struct sockaddr_in sa;
    int sfd, opt = 1;
    const char *listen_addr = cfg->web_listen;
    int port = cfg->web_port > 0 ? cfg->web_port : 8087;

    if (!cfg->web_enable) {
        fprintf(stderr, "web: disabled (set web_enable=1 in config)\n");
        return 0;
    }
    if (!listen_addr[0]) {
        fprintf(stderr, "web: web_listen is not set (use a LAN address, e.g. 192.168.1.1)\n");
        return 2;
    }
    if (!strcmp(listen_addr, "0.0.0.0")) {
        fprintf(stderr, "web: refusing to listen on 0.0.0.0; set a LAN address\n");
        return 2;
    }
    if (!cfg->web_token[0])
        fprintf(stderr, "web: warning: web_token is empty — access without auth (LAN only)\n");

    sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) {
        perror("web: socket");
        return 1;
    }
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, listen_addr, &sa.sin_addr) != 1) {
        fprintf(stderr, "web: invalid web_listen '%s'\n", listen_addr);
        close(sfd);
        return 2;
    }
    if (bind(sfd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        fprintf(stderr, "web: cannot bind %s:%d: %s (port busy?)\n",
                listen_addr, port, strerror(errno));
        close(sfd);
        return 1;
    }
    if (listen(sfd, 16) != 0) {
        fprintf(stderr, "web: listen failed: %s\n", strerror(errno));
        close(sfd);
        return 1;
    }

    signal(SIGCHLD, SIG_IGN);
    slog_init(cfg->log_level);
    printf("web: listening on http://%s:%d/ (www=%s)\n",
           listen_addr, port, SUSANIN_WWW_ROOT);
    slogf(SL_INFO, "web: listening on %s:%d", listen_addr, port);

    for (;;) {
        struct sockaddr_in ca;
        socklen_t cl = sizeof(ca);
        int cfd = accept(sfd, (struct sockaddr *)&ca, &cl);
        if (cfd < 0) {
            if (errno == EINTR)
                continue;
            usleep(100000);
            continue;
        }
        {
            pid_t pid = fork();
            if (pid == 0) {
                struct timeval tv;
                tv.tv_sec = 10;
                tv.tv_usec = 0;
                setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                close(sfd);
                handle_conn(cfd, cfg);
                close(cfd);
                _exit(0);
            }
            close(cfd);
        }
    }
    return 0; /* недостижимо */
}
