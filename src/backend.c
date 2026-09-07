#define _GNU_SOURCE
#include "backend.h"
#include "log.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

static const char *tool_ipset(void)
{
    static const char *p = NULL;
    if (p) return p;
    if (access("/opt/sbin/ipset", X_OK) == 0) p = "/opt/sbin/ipset";
    else if (access("/opt/bin/ipset", X_OK) == 0) p = "/opt/bin/ipset";
    else p = "ipset";
    return p;
}

static const char *tool_conntrack(void)
{
    static const char *p = NULL;
    if (p) return p;
    if (access("/opt/sbin/conntrack", X_OK) == 0) p = "/opt/sbin/conntrack";
    else if (access("/opt/bin/conntrack", X_OK) == 0) p = "/opt/bin/conntrack";
    else p = "conntrack";
    return p;
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
}

static int run_script(const susanin_config *c, const char *arg)
{
    char *argv[4];
    argv[0] = "sh";
    argv[1] = "/opt/susanin/tools/datapath.sh";
    argv[2] = (char *)arg;
    argv[3] = NULL;
    set_env(c);
    return run_argv(argv);
}

int backend_provision(const susanin_config *c)
{
    return run_script(c, "up");
}

static const char *tool_iptables(void)
{
    static const char *p = NULL;
    if (p) return p;
    if (access("/opt/sbin/iptables", X_OK) == 0) p = "/opt/sbin/iptables";
    else if (access("/opt/bin/iptables", X_OK) == 0) p = "/opt/bin/iptables";
    else p = "iptables";
    return p;
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
    return 0;
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
