#define _GNU_SOURCE
#include "backend.h"
#include "log.h"
#include "platform.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

/* Resolve an external tool via the platform search path. Returns 0 with the
 * absolute path in out, or -1 with the bare name (PATH lookup) if not found. */
static int tool_path(const char *name, char *out, size_t n)
{
    const char *const *dirs = susanin_tool_dirs();
    char p[160];
    unsigned i;
    for (i = 0; dirs[i]; i++) {
        susanin_join(p, sizeof(p), dirs[i], name);
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

static void set_env(const susanin_config *c)
{
    char v[64];
    setenv("SUSANIN_EGRESS", c->egress_interface[0] ? c->egress_interface : "nwg0", 1);
    setenv("SUSANIN_TABLE", (snprintf(v, sizeof(v), "%d", c->routing_table), v), 1);
    setenv("SUSANIN_MARK_OK", (snprintf(v, sizeof(v), "0x%lx", c->mark_ok), v), 1);
    setenv("SUSANIN_MARK_TEST", (snprintf(v, sizeof(v), "0x%lx", c->mark_test), v), 1);
    setenv("SUSANIN_PRI_OK", (snprintf(v, sizeof(v), "%d", c->ip_rule_priority_start), v), 1);
    setenv("SUSANIN_PRI_TEST", (snprintf(v, sizeof(v), "%d", c->ip_rule_priority_start + 1), v), 1);
    setenv("SUSANIN_LAN", c->lan_interfaces[0] ? c->lan_interfaces : "br0", 1);
    setenv("SUSANIN_TTL_TEST", (snprintf(v, sizeof(v), "%d", c->test_ttl), v), 1);
    setenv("SUSANIN_TTL_OK", (snprintf(v, sizeof(v), "%d", c->ok_ttl), v), 1);
    /* Directory layout for the data-plane script (no-op on Entware: /opt). */
    setenv("SUSANIN_BINDIR", susanin_bindir(), 1);
    setenv("SUSANIN_ETCDIR", susanin_etcdir(), 1);
    setenv("SUSANIN_VARDIR", susanin_vardir(), 1);
    setenv("SUSANIN_TOOLSDIR", susanin_toolsdir(), 1);
}

static int run_script(const susanin_config *c, const char *arg)
{
    char script[256];
    char *argv[4];
    susanin_join(script, sizeof(script), susanin_toolsdir(), "datapath.sh");
    argv[0] = "sh";
    argv[1] = script;
    argv[2] = (char *)arg;
    argv[3] = NULL;
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

static const char *tool_iptables(void)
{
    static char buf[160];
    if (!buf[0])
        tool_path("iptables", buf, sizeof(buf));
    return buf;
}

int backend_ready(const susanin_config *c)
{
    char *argv[6];
    (void)c;
    argv[0] = (char *)tool_iptables();
    argv[1] = "-t";
    argv[2] = "mangle";
    argv[3] = "-S";
    argv[4] = "SUSANIN";
    argv[5] = NULL;
    return run_argv(argv) == 0;
}

/* Check the environment the data plane needs: external tools and the egress
 * interface. Returns 0, or -1 with a human-readable reason in err. */
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
        snprintf(p, sizeof(p), "/sys/class/net/%s", c->egress_interface);
        if (access(p, F_OK) != 0) {
            snprintf(err, errsz,
                     "egress interface '%s' not found (check egress_interface in susanin.conf)",
                     c->egress_interface);
            return -1;
        }
    }
    return 0;
}

int backend_teardown(const susanin_config *c)
{
    return run_script(c, "down");
}

int backend_ipset_add(const susanin_config *c, int proto_udp, int phase_ok,
                      const char *ip, int ttl)
{
    char *argv[8];
    char name[64], t[32];
    (void)c;
    set_name(name, sizeof(name), proto_udp, phase_ok);
    snprintf(t, sizeof(t), "%d", ttl);
    argv[0] = (char *)tool_ipset();
    argv[1] = "-exist";
    argv[2] = "add";
    argv[3] = name;
    argv[4] = (char *)ip;
    argv[5] = "timeout";
    argv[6] = t;
    argv[7] = NULL;
    return run_argv(argv);
}

int backend_ipset_del(const susanin_config *c, int proto_udp, int phase_ok,
                      const char *ip)
{
    char *argv[6];
    char name[64];
    (void)c;
    set_name(name, sizeof(name), proto_udp, phase_ok);
    argv[0] = (char *)tool_ipset();
    argv[1] = "-exist";
    argv[2] = "del";
    argv[3] = name;
    argv[4] = (char *)ip;
    argv[5] = NULL;
    return run_argv(argv);
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
    argv[0] = (char *)tool_ipset();
    argv[1] = "-exist";
    argv[2] = "del";
    argv[3] = (char *)set;
    argv[4] = (char *)val;
    argv[5] = NULL;
    return run_argv(argv);
}

int backend_net_add(const susanin_config *c, const char *cidr, int ttl)
{
    char *argv[8];
    char t[32];
    (void)c;
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
