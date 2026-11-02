#define _GNU_SOURCE
#include "backend.h"
#include "log.h"

#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

/* Resolve an external tool via the standard Entware/usr search path.
 * Returns 0 with the absolute path in out, or -1 with the bare name
 * (PATH lookup) when not found. */
static int tool_path(const char *name, char *out, size_t n)
{
    static const char *const dirs[] = { "/opt/sbin", "/opt/bin", "/usr/sbin", "/usr/bin" };
    char p[160];
    unsigned i;
    for (i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        snprintf(p, sizeof(p), "%s/%s", dirs[i], name);
        if (access(p, X_OK) == 0) {
            snprintf(out, n, "%s", p);
            return 0;
        }
    }
    snprintf(out, n, "%s", name);
    return -1;
}

static const char *tool_ipset(void)
{
    static char buf[160];
    if (!buf[0])
        tool_path("ipset", buf, sizeof(buf));
    return buf;
}

static const char *tool_conntrack(void)
{
    static char buf[160];
    if (!buf[0])
        tool_path("conntrack", buf, sizeof(buf));
    return buf;
}

static int run_argv(char *const argv[])
{
    pid_t pid = fork();
    int st = -1;
    if (pid < 0)
        return -1;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, 1);
            dup2(devnull, 2);
            if (devnull > 2)
                close(devnull);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    if (waitpid(pid, &st, 0) < 0)
        return -1;
    if (WIFEXITED(st))
        return WEXITSTATUS(st);
    return -1;
}

/* ---- Батч ipset-операций ---------------------------------------------------
 * Между backend_batch_begin() и backend_batch_end() все add/del копятся в
 * текстовом буфере и применяются ОДНИМ `ipset restore -exist` — один fork на
 * пачку вместо fork+exec на каждую запись. Это нужно там, где за проход
 * меняются сотни записей:
 *   - resync_sets() после ре-провижна/рестарта (восстановление кэша),
 *   - обновление vpn_always/vpn_never (пины сотен IP за проход).
 * На MIPS каждый fork+exec — единицы миллисекунд, и такой залп держал главный
 * цикл секундами (в это время классификатор не работает и не выставляет
 * метки — «маршрут не строится» с задержкой).
 * Вложенность считается счётчиком; flush — на внешнем end(). */

#define BT_PATH "/tmp/susanin-ipset.batch"
#define BT_MAX (1024 * 1024)

static char *g_bt;              /* накопленные команды restore */
static size_t g_bt_len, g_bt_cap;
static int g_bt_depth;
static int g_bt_disabled;      /* 1 = батч выключен (конфиг или авария с ipset) */

void backend_batch_enable(int on)
{
    g_bt_disabled = on ? 0 : 1;
    if (g_bt_disabled) {
        g_bt_depth = 0;
        g_bt_len = 0;
    }
}

void backend_batch_begin(void)
{
    if (g_bt_disabled)
        return;
    g_bt_depth++;
}

static int bt_space(size_t need)
{
    char *p;
    size_t ncap;
    if (g_bt_len + need + 1 <= g_bt_cap)
        return 0;
    if (g_bt_len + need + 1 > BT_MAX)
        return -1;                  /* слишком большая пачка — применим поштучно */
    ncap = g_bt_cap ? g_bt_cap * 2 : 8192;
    while (ncap < g_bt_len + need + 1)
        ncap *= 2;
    p = realloc(g_bt, ncap);
    if (!p)
        return -1;
    g_bt = p;
    g_bt_cap = ncap;
    return 0;
}

/* Добавить строку команды restore. 0 = накоплено, -1 = не вышло (тогда
 * вызывающий сделает обычный fork+exec). */
static int bt_cmd(const char *fmt, ...)
{
    char line[512];
    va_list ap;
    int n;
    va_start(ap, fmt);
    n = vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    if (n <= 0 || (size_t)n >= sizeof(line))
        return -1;
    if (bt_space((size_t)n) != 0)
        return -1;
    memcpy(g_bt + g_bt_len, line, (size_t)n);
    g_bt_len += (size_t)n;
    return 0;
}

/* Записать накопленный буфер в файл (вход для `ipset restore`). */
static int bt_write_file(void)
{
    int fd = open(BT_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return -1;
    if (write(fd, g_bt, g_bt_len) != (ssize_t)g_bt_len) {
        close(fd);
        unlink(BT_PATH);
        return -1;
    }
    close(fd);
    return 0;
}

/* Сколько ждём `ipset restore`. ipset берёт глобальный lock: если процесс
 * завис (например, читает stdin, который не закрывается), ВСЕ последующие
 * вызовы ipset встают намертво, а вместе с ними и главный цикл агента (стенд
 * 2026-11-02: лог замер, метки не ставились, туннель «умер»). Поэтому любой
 * вызов ipset ограничен по времени и при таймауте убивается. */
#define BT_RESTORE_TIMEOUT_MS 1500
#define BT_APPLY_TIMEOUT_MS   2000

/* Дождаться ребёнка не дольше timeout_ms. Возврат: код выхода, -1 ошибка,
 * -2 таймаут (ребёнок убит SIGKILL). */
static int bt_wait_child(pid_t pid, int timeout_ms)
{
    int waited = 0, st = -1;
    for (;;) {
        pid_t w = waitpid(pid, &st, WNOHANG);
        if (w == pid)
            return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
        if (w < 0)
            return -1;
        if (waited >= timeout_ms) {
            kill(pid, SIGKILL);
            waitpid(pid, &st, 0);
            return -2;
        }
        usleep(20 * 1000);
        waited += 20;
    }
}

/* Применить пачку одним `ipset restore`, вернуть его код (0 = ок; -2 = завис
 * и был убит). stderr/stdout ребёнка попадает в err. */
static int bt_run_restore(char *err, size_t errsz)
{
    int p[2];
    pid_t pid;
    if (!err || !errsz)
        return -1;
    err[0] = '\0';
    if (pipe(p) != 0)
        return -1;
    pid = fork();
    if (pid == 0) {
        int in = open(BT_PATH, O_RDONLY);
        if (in >= 0) {
            dup2(in, 0);
            if (in > 2)
                close(in);
        }
        /* Без файла restore читал бы унаследованный stdin и мог висеть вечно:
         * в этом случае подставляем /dev/null (пустая пачка → мгновенный EOF). */
        if (in < 0) {
            int dn = open("/dev/null", O_RDONLY);
            if (dn >= 0) {
                dup2(dn, 0);
                if (dn > 2)
                    close(dn);
            }
        }
        dup2(p[1], 1);
        dup2(p[1], 2);
        close(p[0]);
        close(p[1]);
        {
            char *av[4];
            av[0] = (char *)tool_ipset();
            av[1] = "-exist";
            av[2] = "restore";
            av[3] = NULL;
            execvp(av[0], av);
        }
        _exit(127);
    }
    close(p[1]);
    if (pid < 0) {
        close(p[0]);
        return -1;
    }
    fcntl(p[0], F_SETFL, fcntl(p[0], F_GETFL, 0) | O_NONBLOCK);
    {
        int waited = 0, st = 0;
        int done = 0, timedout = 0;
        while (!done) {
            char tmp[256];
            ssize_t r;
            pid_t w;
            size_t got = strlen(err);
            while ((r = read(p[0], tmp, sizeof(tmp))) > 0) {
                if (got + 1 < errsz) {
                    size_t n = (size_t)r;
                    if (n > errsz - 1 - got)
                        n = errsz - 1 - got;
                    memcpy(err + got, tmp, n);
                    got += n;
                    err[got] = '\0';
                }
            }
            w = waitpid(pid, &st, WNOHANG);
            if (w == pid) {
                done = 1;
                break;
            }
            if (w < 0) {
                done = 1;
                break;
            }
            if (waited >= BT_RESTORE_TIMEOUT_MS) {
                kill(pid, SIGKILL);
                waitpid(pid, NULL, 0);
                timedout = 1;
                break;
            }
            usleep(20 * 1000);
            waited += 20;
        }
        close(p[0]);
        if (timedout)
            return -2;
        return (WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    }
}

/* Применить одну строку restore как обычную команду ipset (fallback).
 * Строка — ровно то, что понимает `ipset restore`: "add SET VAL timeout N". */
static int bt_apply_line(char *line)
{
    char *av[8];
    char *p = line;
    int n = 0;
    int rc;
    pid_t pid;
    while (*p && n < 6) {
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        av[n++] = p;
        while (*p && *p != ' ' && *p != '\t')
            p++;
        if (*p)
            *p++ = '\0';
    }
    if (n < 2)
        return -1;
    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        char *argv[8];
        int k = 0, i;
        int devnull = open("/dev/null", O_WRONLY);
        argv[k++] = (char *)tool_ipset();
        argv[k++] = "-exist";
        for (i = 0; i < n; i++)
            argv[k++] = av[i];
        argv[k] = NULL;
        if (devnull >= 0) {
            dup2(devnull, 1);
            dup2(devnull, 2);
            if (devnull > 2)
                close(devnull);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    rc = bt_wait_child(pid, BT_APPLY_TIMEOUT_MS);
    return rc;
}

static int bt_flush(void)
{
    char err[256];
    int rc;
    if (!g_bt_len)
        return 0;
    if (bt_write_file() != 0) {
        g_bt_len = 0;
        return -1;
    }
    rc = bt_run_restore(err, sizeof(err));
    if (rc == -2) {
        /* ipset завис и держит свой lock: повторять поштучно нельзя — это
         * только плодит зависшие процессы. Батч выключаем до рестарта. */
        slogf(SL_ERROR, "ipset restore завис (больше %d мс) — процесс убит, "
                        "батч ipset отключён до перезапуска агента",
              BT_RESTORE_TIMEOUT_MS);
        unlink(BT_PATH);
        g_bt_len = 0;
        backend_batch_enable(0);
        return 0;
    }
    if (rc != 0) {
        /* restore не принял пачку целиком (одна битая строка роняет весь
         * restore: раньше из-за этого после рестарта не восстанавливался кэш).
         * Применяем поштучно — медленнее, но без потери остальных записей. */
        size_t off = 0;
        int ncmd = 0, bad = 0;
        char firstbad[512] = "";
        while (off < g_bt_len) {
            char *nl = memchr(g_bt + off, '\n', g_bt_len - off);
            size_t len = nl ? (size_t)(nl - (g_bt + off)) : (g_bt_len - off);
            if (len) {
                char line[512];
                if (len >= sizeof(line))
                    len = sizeof(line) - 1;
                memcpy(line, g_bt + off, len);
                line[len] = '\0';
                ncmd++;
                if (bt_apply_line(line) != 0) {
                    if (!bad)
                        snprintf(firstbad, sizeof(firstbad), "%s", line);
                    bad++;
                }
            }
            off += len + (nl ? 1 : 0);
        }
        {
            char e[200];
            size_t i, j = 0;
            for (i = 0; err[i] && j + 1 < sizeof(e); i++) {
                if (err[i] == '\n' || err[i] == '\r')
                    break;
                e[j++] = err[i];
            }
            e[j] = '\0';
            if (bad)
                slogf(SL_WARN, "ipset restore rc=%d (%s): применено поштучно %d, "
                               "ошибок %d, первая: %s",
                      rc, e[0] ? e : "no stderr", ncmd - bad, bad, firstbad);
            else
                slogf(SL_INFO, "ipset restore rc=%d (%s): применил поштучно %d команд",
                      rc, e[0] ? e : "no stderr", ncmd);
        }
        unlink(BT_PATH);
        g_bt_len = 0;
        return 0;               /* записи всё равно применены */
    }
    unlink(BT_PATH);
    g_bt_len = 0;
    return 0;
}

int backend_batch_end(void)
{
    int rc;
    if (g_bt_depth > 0)
        g_bt_depth--;
    if (g_bt_depth > 0)
        return 0;
    rc = bt_flush();
    if (rc != 0)
        slogf(SL_ERROR, "ipset restore: пачка команд не применена (rc=%d)", rc);
    return rc;
}

/* Run argv capturing combined stdout+stderr into out (truncated to outsz). */
static int run_capture_argv(char *const argv[], char *out, size_t outsz)
{
    int p[2];
    pid_t pid;
    int st = -1;
    size_t n = 0;
    if (out && outsz)
        out[0] = '\0';
    if (pipe(p) != 0)
        return -1;
    pid = fork();
    if (pid < 0) {
        close(p[0]);
        close(p[1]);
        return -1;
    }
    if (pid == 0) {
        close(p[0]);
        dup2(p[1], 1);
        dup2(p[1], 2);
        if (p[1] > 2)
            close(p[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(p[1]);
    {
        char tmp[512];
        ssize_t r;
        while ((r = read(p[0], tmp, sizeof(tmp))) > 0) {
            if (out && n < outsz - 1) {
                size_t room = outsz - 1 - n;
                size_t take = (size_t)r < room ? (size_t)r : room;
                memcpy(out + n, tmp, take);
                n += take;
            }
        }
        if (out && outsz)
            out[n] = '\0';
    }
    close(p[0]);
    if (waitpid(pid, &st, 0) < 0)
        return -1;
    if (WIFEXITED(st))
        return WEXITSTATUS(st);
    return -1;
}

/* Log the last non-empty line of captured output (the usual place where the
 * failing tool's error message lands). */
static void log_provision_error(int rc, char *buf)
{
    char *end, *last, *p;
    if (!buf || !buf[0]) {
        slogf(SL_ERROR, "datapath provisioning failed (rc=%d, no output)", rc);
        return;
    }
    end = buf + strlen(buf);
    while (end > buf && (end[-1] == '\n' || end[-1] == '\r' || end[-1] == ' ' ||
                         end[-1] == '\t'))
        *--end = '\0';
    last = buf;
    for (p = buf; p < end; p++)
        if (*p == '\n')
            last = p + 1;
    while (*last == ' ' || *last == '\t')
        last++;
    if (*last)
        slogf(SL_ERROR, "datapath provisioning failed (rc=%d): %s", rc, last);
    else
        slogf(SL_ERROR, "datapath provisioning failed (rc=%d)", rc);
}

static void set_name(char *buf, size_t n, int proto_udp, int phase_ok)
{
    snprintf(buf, n, "susanin_%s_%s", phase_ok ? "ok" : "test",
             proto_udp ? "udp" : "tcp");
}

/* Активный egress: один интерфейс (в конфиге возможен список фейловера). */
static char g_active_egress[64];

/* Runtime-режим датаплейна: интерфейс или tproxy (Xray). В конфиге режим задаёт
 * egress_type, но список egress_interface может содержать псевдо-кандидат
 * "tproxy" (P1 из плана 2026-10-16): при переключении на него датаплейн
 * пересобирается целиком, при возврате — обратно. -1 = как в конфиге. */
static int g_tproxy_mode = -1;

static int tproxy_active(const susanin_config *c)
{
    if (g_tproxy_mode >= 0)
        return g_tproxy_mode;
    return strcmp(c->egress_type, "tproxy") == 0;
}

/* Псевдо-имя кандидата-резерва через Xray. */
static int is_tproxy_name(const char *s)
{
    return s && (!strcmp(s, "tproxy") || !strcmp(s, "xray"));
}

static const char *active_egress(const susanin_config *c)
{
    if (g_active_egress[0])
        return g_active_egress;
    if (c->n_egress > 0 && c->egress_list[0][0])
        return c->egress_list[0];
    if (c->egress_interface[0])
        return c->egress_interface;
    return "nwg0";
}

static void set_env(const susanin_config *c)
{
    char v[64];
    setenv("SUSANIN_EGRESS", active_egress(c), 1);
    setenv("SUSANIN_TABLE", (snprintf(v, sizeof(v), "%d", c->routing_table), v), 1);
    setenv("SUSANIN_MARK_OK", (snprintf(v, sizeof(v), "0x%lx", c->mark_ok), v), 1);
    setenv("SUSANIN_MARK_TEST", (snprintf(v, sizeof(v), "0x%lx", c->mark_test), v), 1);
    setenv("SUSANIN_MARK_MASK", (snprintf(v, sizeof(v), "0x%lx", c->mark_mask), v), 1);
    setenv("SUSANIN_PRI_OK", (snprintf(v, sizeof(v), "%d", c->ip_rule_priority_start), v), 1);
    setenv("SUSANIN_PRI_TEST", (snprintf(v, sizeof(v), "%d", c->ip_rule_priority_start + 1), v), 1);
    setenv("SUSANIN_LAN", c->lan_interfaces[0] ? c->lan_interfaces : "br0", 1);
    setenv("SUSANIN_TTL_TEST", (snprintf(v, sizeof(v), "%d", c->test_ttl), v), 1);
    setenv("SUSANIN_TTL_OK", (snprintf(v, sizeof(v), "%d", c->ok_ttl), v), 1);
    setenv("SUSANIN_DISK_MODE", c->disk_mode[0] ? c->disk_mode : "normal", 1);
    setenv("SUSANIN_TPROXY_PORT",
           (snprintf(v, sizeof(v), "%d",
                     tproxy_active(c) ? c->tproxy_port : 0), v), 1);
    setenv("SUSANIN_UDP_RELAY_PORT",
           (snprintf(v, sizeof(v), "%d", c->udp_relay ? c->udp_relay_port : 0), v), 1);
    setenv("SUSANIN_IPV6_BLOCK", c->ipv6_block ? "1" : "0", 1);
    setenv("SUSANIN_QUIC_BLOCK", c->quic_block ? "1" : "0", 1);
    setenv("SUSANIN_KERNEL_OFFLOAD", c->kernel_offload ? "1" : "0", 1);
    setenv("SUSANIN_KERNEL_EGRESS", c->kernel_egress, 1);
    setenv("SUSANIN_MSS_CLAMP", c->mss_clamp[0] ? c->mss_clamp : "0", 1);
    setenv("SUSANIN_MSS_CLAMP_LAN", c->mss_clamp_lan ? "1" : "0", 1);
    /* T3: DNAT 53 клиентов серверных VPN на резолвер роутера. */
    setenv("SUSANIN_DNS_HIJACK", c->dns_hijack ? "1" : "0", 1);
    setenv("SUSANIN_DNS_HIJACK_TARGET", c->dns_hijack_target, 1);
    /* Port-aware: datapath.sh создаст наборы hash:ip,port и правила dst,dst.
     * По умолчанию 0 — прежнее поведение (наборы hash:ip, матч dst). */
    setenv("SUSANIN_PORT_AWARE", c->port_aware ? "1" : "0", 1);
}

static int run_script(const susanin_config *c, const char *a1, const char *a2)
{
    char *argv[5];
    argv[0] = "sh";
    argv[1] = "/opt/susanin/tools/datapath.sh";
    argv[2] = (char *)a1;
    argv[3] = (char *)a2;
    argv[4] = NULL;
    set_env(c);
    return run_argv(argv);
}

int backend_provision(const susanin_config *c)
{
    char *argv[4];
    char out[2048];
    int rc;
    argv[0] = "sh";
    argv[1] = "/opt/susanin/tools/datapath.sh";
    argv[2] = "up";
    argv[3] = NULL;
    set_env(c);
    rc = run_capture_argv(argv, out, sizeof(out));
    if (rc != 0)
        log_provision_error(rc, out);
    return rc;
}

/* Отметка о последнем ре-провижене (для наблюдаемости в status/diagnose). */
#define DP_REPROV_FILE "/opt/susanin/var/dp-reprov"

void backend_mark_reprov(const char *reason)
{
    FILE *fp = fopen(DP_REPROV_FILE, "w");
    if (!fp)
        return;
    fprintf(fp, "%ld %s\n", (long)time(NULL),
            (reason && reason[0]) ? reason : "re-provision");
    fclose(fp);
}

int backend_read_reprov(long *when, char *reason, size_t reasonsz)
{
    FILE *fp = fopen(DP_REPROV_FILE, "r");
    char line[256], r[200] = "";
    long t = 0;
    if (!fp)
        return -1;
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    if (sscanf(line, "%ld %199[^\n]", &t, r) < 1)
        return -1;
    if (when)
        *when = t;
    if (reason && reasonsz)
        snprintf(reason, reasonsz, "%s", r);
    return 0;
}

static const char *tool_iptables(void)
{
    static char buf[160];
    if (!buf[0])
        tool_path("iptables", buf, sizeof(buf));
    return buf;
}

static const char *tool_ip(void)
{
    static char buf[160];
    if (!buf[0])
        tool_path("ip", buf, sizeof(buf));
    return buf;
}

/* Занят ли xtables-lock. iptables — общий ресурс: пока NDM пересобирает свои
 * правила, `-S`/`-C` завершается кодом 4 («Another app is currently holding the
 * xtables lock»). Правило при этом на месте — это не «датаплейн пропал». */
int backend_xt_locked(int rc, const char *out)
{
    if (rc == BACKEND_XT_LOCK_RC)
        return 1;
    return (out && strstr(out, "xtables lock")) ? 1 : 0;
}

/* Проверочный вызов с ретраями на xtables-lock. Без него агент считал занятый
 * замок пропажей правил: писал "data plane missing", перепровижнил датаплейн и
 * помечал списки грязными. На стенде 2026-10-28 rc=4 случался до 5 раз за 45 с,
 * а ложные срабатывания шли раз в 1–2 минуты. */
#define XT_LOCK_RETRIES 4
#define XT_LOCK_WAIT_US (120 * 1000)
/* Замок не отпустили за все ретраи: проверить правило нельзя, но это НЕ
 * доказательство, что его нет. T6: на 0.4.1 такой rc=4 приводил к ложному
 * «data plane missing», ре-провижну и пометке списков грязными каждые 5 с. */
#define XT_BUSY (-2)

static int run_check(char *const argv[], char *out, size_t outsz)
{
    int rc = -1, i;
    for (i = 0; i < XT_LOCK_RETRIES; i++) {
        if (i) {
            if (out && outsz)
                out[0] = '\0';
            usleep(XT_LOCK_WAIT_US);
        }
        rc = out ? run_capture_argv(argv, out, outsz) : run_argv(argv);
        if (!backend_xt_locked(rc, out))
            return rc;
    }
    slogf(SL_DEBUG, "ready check: xtables lock busy after %d tries (rc=%d) — "
                    "assume OK, retry on next pass", XT_LOCK_RETRIES, rc);
    return XT_BUSY;
}

/* Жив ли хоть один кандидат-интерфейс (не псевдоним tproxy/xray). Нужен, чтобы
 * не требовать маршрут в таблице, когда VPN-подключение отключили и интерфейс
 * исчез: маршрут уходит вместе с ним, и это не повреждение датаплейна. */
static int egress_any_present(const susanin_config *c)
{
    int i;
    char p[128];
    for (i = 0; i < c->n_egress; i++) {
        if (is_tproxy_name(c->egress_list[i]))
            continue;
        snprintf(p, sizeof(p), "/sys/class/net/%s", c->egress_list[i]);
        if (access(p, F_OK) == 0)
            return 1;
    }
    return 0;
}

/* Есть ли в списке интерфейсов запись с данным префиксом и корректным хвостом
 * (`oc`, `oc+`, `oc0`…; `wdtt`, `wdtt0`…). Подстрочное совпадение вроде
 * `vpn_ocean0` не считается. */
static int iface_prefix_in_list(const char *list, const char *pfx)
{
    size_t n = strlen(pfx);
    const char *p = list;
    while (p && *p) {
        const char *e;
        char c;
        while (*p == ',' || *p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        e = p;
        while (*e && *e != ',' && *e != ' ' && *e != '\t')
            e++;
        if ((size_t)(e - p) >= n && !strncmp(p, pfx, n)) {
            c = p[n];
            if (c == '+' || c == '\0' || c == ',' || c == ' ' ||
                c == '\t' || (c >= '0' && c <= '9'))
                return 1;
        }
        p = e;
    }
    return 0;
}

/* Готов ли датаплейн? Проверяем ФАКТИЧЕСКИЙ режим (g_tproxy_mode), а не
 * cfg->egress_type: после переключения кандидата конфиг и ядро могут
 * расходиться, и сравнение с конфигом давало вечный false → цикл
 * «data plane missing» каждые 5–15 c.
 * tproxy: нужны nat REDIRECT / mangle TPROXY / ip rule 0x1.
 * interface: цепочки SUSANIN МАЛО — NDM может снести ip rule, default в таблице
 * или разрешение в filter/FORWARD, и тогда метка ставится, а трафик идёт
 * напрямую (снаружи это «vpn_always не работает»). */
int backend_ready(const susanin_config *c)
{
    char *argv[6];
    char out[8192], needle[96];
    int rc;

    argv[0] = (char *)tool_iptables();
    argv[1] = "-t";
    argv[2] = "mangle";
    argv[3] = "-S";
    argv[4] = "SUSANIN";
    argv[5] = NULL;
    rc = run_check(argv, NULL, 0);
    if (rc == XT_BUSY)
        return 1;               /* проверить нельзя — не объявляем пропажу */
    if (rc != 0)
        return 0;

    /* T3: dns_hijack ставит DNAT 53 заранее (в т.ч. шаблоном oc+ без живого
     * клиента) и помечает правила comment-меткой susanin-dns. Если правила
     * пропали (NDM/смена режима), их надо вернуть — иначе фича «включается»
     * только после ручного restart. Чужой DNAT 53 «готовым» не считается. */
    if (c->dns_hijack &&
        (iface_prefix_in_list(c->lan_interfaces, "oc") ||
         iface_prefix_in_list(c->lan_interfaces, "wdtt") ||
         iface_prefix_in_list(c->lan_interfaces, "wdttraw"))) {
        char *na[6];
        na[0] = (char *)tool_iptables();
        na[1] = "-t"; na[2] = "nat"; na[3] = "-S"; na[4] = "PREROUTING"; na[5] = NULL;
        rc = run_check(na, out, sizeof(out));
        if (rc == XT_BUSY)
            return 1;
        if (rc != 0 || !strstr(out, "susanin-dns"))
            return 0;
    }

    if (tproxy_active(c)) {
        /* TCP REDIRECT -> tproxy_port */
        snprintf(needle, sizeof(needle), "-j REDIRECT --to-ports %d", c->tproxy_port);
        argv[0] = (char *)tool_iptables();
        argv[1] = "-t"; argv[2] = "nat"; argv[3] = "-S"; argv[4] = "PREROUTING"; argv[5] = NULL;
        rc = run_check(argv, out, sizeof(out));
        if (rc == XT_BUSY)
            return 1;
        if (rc != 0 || !strstr(out, needle))
            return 0;

        /* UDP TPROXY -> udp_relay_port (если релей включён) */
        if (c->udp_relay) {
            snprintf(needle, sizeof(needle), "TPROXY --on-port %d", c->udp_relay_port);
            argv[0] = (char *)tool_iptables();
            argv[1] = "-t"; argv[2] = "mangle"; argv[3] = "-S"; argv[4] = "PREROUTING"; argv[5] = NULL;
            rc = run_check(argv, out, sizeof(out));
            if (rc == XT_BUSY)
                return 1;
            if (rc != 0 || !strstr(out, needle))
                return 0;
        }

        /* ip rule fwmark 0x1 -> table (доставка TPROXY) */
        {
            char *ipargv[4];
            snprintf(needle, sizeof(needle), "fwmark 0x1 lookup %d", c->routing_table);
            ipargv[0] = (char *)tool_ip();
            ipargv[1] = "rule"; ipargv[2] = "show"; ipargv[3] = NULL;
            rc = run_check(ipargv, out, sizeof(out));
            if (rc == XT_BUSY)
                return 1;
            if (rc != 0 || !strstr(out, needle))
                return 0;
        }
        return 1;
    }

    /* interface-режим: цепочки SUSANIN мало. Если NDM снёс ip rule/маршрут или
     * пропало разрешение в filter/FORWARD, метка ставится, а пакет уходит
     * напрямую — снаружи это выглядит как «vpn_always не работает». */
    {
        char *ipargv[6];
        char tbl[16];
        snprintf(tbl, sizeof(tbl), "%d", c->routing_table);
        snprintf(needle, sizeof(needle), "fwmark 0x%lx/0x%lx lookup %d",
                 (unsigned long)c->mark_ok, (unsigned long)c->mark_mask,
                 c->routing_table);
        ipargv[0] = (char *)tool_ip();
        ipargv[1] = "rule"; ipargv[2] = "show"; ipargv[3] = NULL;
        rc = run_check(ipargv, out, sizeof(out));
        if (rc == XT_BUSY)
            return 1;
        if (rc != 0 || !strstr(out, needle))
            return 0;

        /* Маршрут в таблице проверяем ТОЛЬКО пока жив хоть один кандидат.
         * Когда VPN отключают в Keenetic, интерфейс исчезает и ядро вместе с ним
         * удаляет `default dev <iface>`: это НЕ повод перепровижнить датаплейн
         * (иначе цикл «data plane missing» каждые 5 c, падение dp_ok и 60 c
         * бэкоффа). Health сам объявит egress DOWN и уйдёт в fail-open, а
         * маршрут восстановится на tunnel_up (backend_set_egress). */
        if (egress_any_present(c)) {
            ipargv[0] = (char *)tool_ip();
            ipargv[1] = "route"; ipargv[2] = "show"; ipargv[3] = "table";
            ipargv[4] = tbl; ipargv[5] = NULL;
            rc = run_check(ipargv, out, sizeof(out));
            if (rc == XT_BUSY)
                return 1;
            if (rc != 0 || !strstr(out, "default"))
                return 0;
        }

        /* Политика Keenetic — FORWARD DROP; без ACCEPT по нашей метке клиенты
         * серверных VPN (oc+/wdtt+) не доходят до туннеля. */
        {
            char mbuf[48];
            char *fargv[12];
            snprintf(mbuf, sizeof(mbuf), "0x%lx/0x%lx",
                     (unsigned long)c->mark_ok, (unsigned long)c->mark_mask);
            fargv[0] = (char *)tool_iptables();
            fargv[1] = "-t"; fargv[2] = "filter"; fargv[3] = "-C";
            fargv[4] = "FORWARD"; fargv[5] = "-m"; fargv[6] = "mark";
            fargv[7] = "--mark"; fargv[8] = mbuf; fargv[9] = "-j";
            fargv[10] = "ACCEPT"; fargv[11] = NULL;
            rc = run_check(fargv, NULL, 0);
            if (rc == XT_BUSY)
                return 1;
            if (rc != 0)
                return 0;
        }
    }
    return 1;
}

/* Check the environment the data plane needs: external tools and the egress
 * interface. Returns 0, or -1 with a human-readable reason in err. */
/* LISTEN на порту в одном из /proc-файлов (tcp = IPv4, tcp6 = IPv6).
 * Xray dokodemo-door слушает обычно `::` (IPv6), поэтому проверять только
 * /proc/net/tcp недостаточно. */
static int listen_in_proc(const char *path, int port)
{
    FILE *fp = fopen(path, "r");
    char line[256];
    if (!fp)
        return 0;
    if (!fgets(line, sizeof(line), fp)) {   /* заголовок */
        fclose(fp);
        return 0;
    }
    while (fgets(line, sizeof(line), fp)) {
        char local[64] = "", rem[64] = "", sthex[16] = "";
        char *colon;
        if (sscanf(line, "%*s %63s %63s %15s", local, rem, sthex) != 3)
            continue;
        colon = strrchr(local, ':');
        if (!colon)
            continue;
        if ((unsigned)strtoul(sthex, NULL, 16) == 0x0A &&
            (unsigned)strtoul(colon + 1, NULL, 16) == (unsigned)port) {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

/* Слушает ли кто-нибудь TCP-порт на локальном адресе (IPv4 или IPv6).
 * Нужен для tproxy: без живого Xray поднимать REDIRECT/TPROXY нельзя —
 * иначе помеченный трафик уйдёт «в никуда». Если /proc/net/tcp недоступен —
 * не блокируем (возвращаем 1). */
int backend_local_listen(int port)
{
    FILE *probe = fopen("/proc/net/tcp", "r");
    if (!probe)
        return 1;               /* проверить нельзя — не мешаем */
    fclose(probe);
    if (listen_in_proc("/proc/net/tcp", port))
        return 1;
    if (listen_in_proc("/proc/net/tcp6", port))
        return 1;
    return 0;
}

int backend_preflight(const susanin_config *c, char *err, size_t errsz)
{
    char p[320];
    if (access(tool_iptables(), X_OK) != 0) {
        snprintf(err, errsz, "iptables not found (opkg update && opkg install iptables)");
        return -1;
    }
    if (access(tool_ipset(), X_OK) != 0) {
        snprintf(err, errsz, "ipset not found (opkg update && opkg install ipset)");
        return -1;
    }
    if (access(tool_conntrack(), X_OK) != 0) {
        snprintf(err, errsz, "conntrack not found (opkg update && opkg install conntrack)");
        return -1;
    }
    if (tool_path("ip", p, sizeof(p)) != 0) {
        snprintf(err, errsz, "'ip' not found (install iproute2 or busybox ip)");
        return -1;
    }
    if (c->egress_interface[0]) {
        /* Список кандидатов (фейловер): достаточно одного живого. */
        int i, alive = 0, miss = 0;
        char missing[200];
        missing[0] = '\0';
        for (i = 0; i < c->n_egress; i++) {
            size_t l;
            if (!c->egress_list[i][0])
                continue;
            snprintf(p, sizeof(p), "/sys/class/net/%s", c->egress_list[i]);
            if (access(p, F_OK) == 0) {
                alive = 1;
                continue;
            }
            miss++;
            l = strlen(missing);
            snprintf(missing + l, sizeof(missing) - l, "%s%s",
                     l ? ", " : "", c->egress_list[i]);
        }
        if (!alive) {
            snprintf(err, errsz,
                     "egress interface '%s' not found: none of the candidates exists "
                     "(check egress_interface in susanin.conf)",
                     c->egress_interface);
            return -1;
        }
        if (miss > 0)
            slogf(SL_WARN,
                  "preflight: egress %s отсутствует (кандидатов %d) — ждём подъёма туннеля",
                  missing, c->n_egress);
    }
    return 0;
}

int backend_teardown(const susanin_config *c)
{
    return run_script(c, "down", NULL);
}

/* Переключить default в таблице VPN на указанный egress (фейловер).
 * Спец-значение "tproxy"/"xray": переключение РЕЖИМА датаплейна на Xray —
 * правила interface и tproxy взаимоисключающие, поэтому делаем down+up.
 * Fail-safe: если Xray не слушает порт, режим не меняем. */
int backend_set_egress(const susanin_config *c, const char *iface)
{
    int rc, want_tproxy, was_tproxy;
    if (!iface || !iface[0])
        return -1;
    want_tproxy = is_tproxy_name(iface);
    was_tproxy = tproxy_active(c);
    /* Режим задан конфигом как tproxy, а в списке egress стоит физический
     * интерфейс: это транспорт/резерв Xray, а НЕ запрос на смену режима.
     * Раньше здесь выполнялся teardown tproxy -> interface на каждом старте
     * (регрессия 0.4.0.RC1): правила REDIRECT снимались, а backend_ready()
     * продолжал требовать их по конфигу — отсюда вечный цикл
     * «data plane missing» и адреса из vpn_always, уходящие напрямую. */
    if (was_tproxy && !want_tproxy && strcmp(c->egress_type, "tproxy") == 0) {
        snprintf(g_active_egress, sizeof(g_active_egress), "%s", iface);
        return 0;
    }
    if (want_tproxy && !backend_local_listen(c->tproxy_port)) {
        slogf(SL_ERROR,
              "egress %s: Xray не слушает порт %d — в tproxy-режим не перехожу",
              iface, c->tproxy_port);
        return -1;
    }
    if (want_tproxy && was_tproxy)
        return 0;                    /* уже в tproxy-режиме — делать нечего */
    if (want_tproxy != was_tproxy) {
        g_tproxy_mode = want_tproxy ? 1 : 0;
        /* Активный egress выставляем ДО теардауна/провижна: datapath.sh берёт
         * его из SUSANIN_EGRESS (set_env -> active_egress()), иначе после
         * возврата из tproxy маршрут встал бы на первый интерфейс конфига, а не
         * на запрошенный. */
        if (want_tproxy)
            g_active_egress[0] = '\0';   /* имя интерфейса здесь не нужно */
        else
            snprintf(g_active_egress, sizeof(g_active_egress), "%s", iface);
        (void)backend_teardown(c);
        rc = backend_provision(c);
        if (rc != 0) {
            slogf(SL_ERROR, "egress %s: пере-провижн датаплейна не удался (rc=%d)",
                  iface, rc);
            g_tproxy_mode = -1;      /* оставляем режим «по конфигу» */
            return rc;
        }
        slogf(SL_INFO, "egress: режим датаплейна -> %s",
              want_tproxy ? "tproxy" : "interface");
        return 0;
    }
    snprintf(g_active_egress, sizeof(g_active_egress), "%s", iface);
    rc = run_script(c, "egress", iface);
    if (rc != 0)
        slogf(SL_ERROR, "egress %s: переключение не удалось (rc=%d)", iface, rc);
    return rc;
}

/* Удалить из conntrack все потоки с нашей VPN-меткой (при фейловере). */
int backend_ct_flush_vpn(const susanin_config *c)
{
    char *argv[6];
    char m[64];
    snprintf(m, sizeof(m), "0x%lx/0x%lx", c->mark_ok, c->mark_mask);
    argv[0] = (char *)tool_conntrack();
    argv[1] = "-D";
    argv[2] = "--mark";
    argv[3] = m;
    argv[4] = NULL;
    return run_argv(argv);
}

/* Удалить из conntrack все потоки к указанному IP (после смены списка
 * vpn_never: адрес должен идти напрямую, а не по старому VPN-маршруту). */
int backend_ct_flush_ip(const char *ip)
{
    char *argv[6];
    if (!ip || !ip[0])
        return -1;
    argv[0] = (char *)tool_conntrack();
    argv[1] = "-D";
    argv[2] = "-d";
    argv[3] = (char *)ip;
    argv[4] = NULL;
    return run_argv(argv);
}

/* Значение элемента набора: в port-aware режиме — "ip,протокол:порт" (наборы
 * hash:ip,port), иначе обычный "ip". Протокол указывать ОБЯЗАТЕЛЬНО: в
 * hash:ip,port элемент без протокола считается TCP, и UDP-пакет с ним не
 * совпадёт (проверка Claude по документации ipset). В состоянии (state_key) для
 * тех же пар используется форма "ip:порт" — протокол там задан самим набором. */
void backend_ipset_value(const susanin_config *c, const char *ip, int port,
                         int proto_udp, char *out, size_t n)
{
    if (!out || !n)
        return;
    if (c && c->port_aware && port > 0)
        snprintf(out, n, "%.52s,%s:%d", ip ? ip : "", proto_udp ? "udp" : "tcp", port);
    else
        snprintf(out, n, "%s", ip ? ip : "");
}

int backend_ipset_add_port(const susanin_config *c, int proto_udp, int phase_ok,
                           const char *ip, int port, int ttl)
{
    char *argv[8];
    char name[64], t[32], val[80];
    set_name(name, sizeof(name), proto_udp, phase_ok);
    backend_ipset_value(c, ip, port, proto_udp, val, sizeof(val));
    /* В обычном режиме наборы hash:ip — значение с ':' или ',' (остаток от
     * port-aware) невалидно и роняет весь `ipset restore`; после рестарта из-за
     * такой строки не восстанавливался весь кэш (стенд 2026-11-02). */
    if (!(c && c->port_aware) && (!val[0] || strchr(val, ':') || strchr(val, ','))) {
        slogf(SL_DEBUG, "ipset: пропускаю невалидное значение '%s' (%s)", val, name);
        return -1;
    }
    if (g_bt_depth > 0 && bt_cmd("add %s %s timeout %d\n", name, val, ttl) == 0)
        return 0;
    snprintf(t, sizeof(t), "%d", ttl);
    argv[0] = (char *)tool_ipset();
    argv[1] = "-exist";
    argv[2] = "add";
    argv[3] = name;
    argv[4] = val;
    argv[5] = "timeout";
    argv[6] = t;
    argv[7] = NULL;
    return run_argv(argv);
}

int backend_ipset_del_port(const susanin_config *c, int proto_udp, int phase_ok,
                           const char *ip, int port)
{
    char *argv[6];
    char name[64], val[80];
    set_name(name, sizeof(name), proto_udp, phase_ok);
    backend_ipset_value(c, ip, port, proto_udp, val, sizeof(val));
    if (!(c && c->port_aware) && (!val[0] || strchr(val, ':') || strchr(val, ',')))
        return -1;              /* см. комментарий в backend_ipset_add_port */
    if (g_bt_depth > 0 && bt_cmd("del %s %s\n", name, val) == 0)
        return 0;
    argv[0] = (char *)tool_ipset();
    argv[1] = "-exist";
    argv[2] = "del";
    argv[3] = name;
    argv[4] = val;
    argv[5] = NULL;
    return run_argv(argv);
}

int backend_ipset_add(const susanin_config *c, int proto_udp, int phase_ok,
                      const char *ip, int ttl)
{
    return backend_ipset_add_port(c, proto_udp, phase_ok, ip, 0, ttl);
}

int backend_is_our_xray_cmdline(const char *cmdline)
{
    if (!cmdline || !*cmdline)
        return 0;
    return strstr(cmdline, "xray") && strstr(cmdline, "-config") &&
           strstr(cmdline, "xray-tproxy.json");
}

/* Пины по адресу: см. backend.h. Одиночный адрес для hash:net — валидный /32. */
int backend_ok_pin_add(const susanin_config *c, const char *ip, int ttl)
{
    if (c && c->port_aware)
        return backend_net_add(c, ip, ttl);
    backend_ipset_add(c, 0, 1, ip, ttl);
    backend_ipset_add(c, 1, 1, ip, ttl);
    return 0;
}

int backend_ok_pin_del(const susanin_config *c, const char *ip)
{
    if (c && c->port_aware)
        return backend_net_del(c, ip);
    backend_ipset_del(c, 0, 1, ip);
    backend_ipset_del(c, 1, 1, ip);
    return 0;
}

int backend_ipset_del(const susanin_config *c, int proto_udp, int phase_ok,
                      const char *ip)
{
    return backend_ipset_del_port(c, proto_udp, phase_ok, ip, 0);
}

int backend_ipset_flush(const susanin_config *c)
{
    char *argv[4];
    const char *proto[2] = { "tcp", "udp" };
    const char *ph[2] = { "test", "ok" };
    int p, s;
    (void)c;
    for (p = 0; p < 2; p++) {
        for (s = 0; s < 2; s++) {
            char name[64];
            snprintf(name, sizeof(name), "susanin_%s_%s", ph[p], proto[s]);
            argv[0] = (char *)tool_ipset();
            argv[1] = "flush";
            argv[2] = name;
            argv[3] = NULL;
            run_argv(argv);
        }
    }
    /* forced CIDR set (vpn_always) — must also flush on fail-open */
    argv[0] = (char *)tool_ipset();
    argv[1] = "flush";
    argv[2] = (char *)"susanin_ok_net";
    argv[3] = NULL;
    run_argv(argv);
    /* always-direct set (vpn_never) */
    argv[0] = (char *)tool_ipset();
    argv[1] = "flush";
    argv[2] = (char *)"susanin_never";
    argv[3] = NULL;
    run_argv(argv);
    return 0;
}

int backend_set_add(const susanin_config *c, const char *set, const char *val,
                    int ttl)
{
    char *argv[8];
    char t[32];
    (void)c;
    if (g_bt_depth > 0 && bt_cmd("add %s %s timeout %d\n", set, val, ttl) == 0)
        return 0;
    snprintf(t, sizeof(t), "%d", ttl);
    argv[0] = (char *)tool_ipset();
    argv[1] = "-exist";
    argv[2] = "add";
    argv[3] = (char *)set;
    argv[4] = (char *)val;
    argv[5] = "timeout";
    argv[6] = t;
    argv[7] = NULL;
    return run_argv(argv);
}

int backend_set_del(const susanin_config *c, const char *set, const char *val)
{
    char *argv[6];
    (void)c;
    if (g_bt_depth > 0 && bt_cmd("del %s %s\n", set, val) == 0)
        return 0;
    argv[0] = (char *)tool_ipset();
    argv[1] = "-exist";
    argv[2] = "del";
    argv[3] = (char *)set;
    argv[4] = (char *)val;
    argv[5] = NULL;
    return run_argv(argv);
}

int backend_set_test(const susanin_config *c, const char *set, const char *val)
{
    char *argv[5];
    (void)c;
    argv[0] = (char *)tool_ipset();
    argv[1] = "test";
    argv[2] = (char *)set;
    argv[3] = (char *)val;
    argv[4] = NULL;
    return run_argv(argv);          /* 0 = присутствует */
}

int backend_net_add(const susanin_config *c, const char *cidr, int ttl)
{
    char *argv[8];
    char t[32];
    (void)c;
    if (g_bt_depth > 0 && bt_cmd("add susanin_ok_net %s timeout %d\n", cidr, ttl) == 0)
        return 0;
    snprintf(t, sizeof(t), "%d", ttl);
    argv[0] = (char *)tool_ipset();
    argv[1] = "-exist";
    argv[2] = "add";
    argv[3] = (char *)"susanin_ok_net";
    argv[4] = (char *)cidr;
    argv[5] = "timeout";
    argv[6] = t;
    argv[7] = NULL;
    return run_argv(argv);
}

int backend_net_del(const susanin_config *c, const char *cidr)
{
    char *argv[6];
    (void)c;
    if (g_bt_depth > 0 && bt_cmd("del susanin_ok_net %s\n", cidr) == 0)
        return 0;
    argv[0] = (char *)tool_ipset();
    argv[1] = "-exist";
    argv[2] = "del";
    argv[3] = (char *)"susanin_ok_net";
    argv[4] = (char *)cidr;
    argv[5] = NULL;
    return run_argv(argv);
}

int backend_ct_delete(const ct_flow *f)
{
    static char *argv[13];
    char sport[16], dport[16];
    if (!f)
        return -1;
    if (f->l4proto != 6 && f->l4proto != 17)
        return 0;
    snprintf(sport, sizeof(sport), "%u", f->sport);
    snprintf(dport, sizeof(dport), "%u", f->dport);
    argv[0] = (char *)tool_conntrack();
    argv[1] = "-D";
    argv[2] = "-p";
    argv[3] = (char *)f->proto;
    argv[4] = "-s";
    argv[5] = (char *)f->src;
    argv[6] = "-d";
    argv[7] = (char *)f->dst;
    argv[8] = "--sport";
    argv[9] = sport;
    argv[10] = "--dport";
    argv[11] = dport;
    argv[12] = NULL;
    return run_argv(argv);
}
