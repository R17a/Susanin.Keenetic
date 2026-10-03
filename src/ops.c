#define _GNU_SOURCE
#include "ops.h"
#include "backend.h"
#include "cdn.h"
#include "log.h"
#include "state.h"
#include "vpn_always.h"
#include "version.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHAIN "SUSANIN"

const char *ops_default_conf_path(void)
{
    const char *p = getenv("SUSANIN_CONF");
    return p && *p ? p : "/opt/susanin/etc/susanin.conf";
}

static const char *tool(const char *name)
{
    static char buf[4][128];
    static int used = 0;
    const char *dirs[] = { "/opt/sbin", "/opt/bin", "/usr/sbin", "/usr/bin" };
    char p[96];
    unsigned i;
    for (i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        snprintf(p, sizeof(p), "%s/%s", dirs[i], name);
        if (access(p, X_OK) == 0) {
            if (used >= 4) return name;
            snprintf(buf[used], sizeof(buf[used]), "%s", p);
            return buf[used++];
        }
    }
    return name;
}

/* Run exe with argv, capture stdout, return exit code (or -1). */
static int run_capture(const char *exe, char *const argv[], char *out, size_t outsz)
{
    int p[2];
    pid_t pid;
    int st;
    size_t n = 0;
    if (outsz > 0)
        out[0] = '\0';
    if (pipe(p) != 0)
        return -1;
    pid = fork();
    if (pid < 0) {
        close(p[0]); close(p[1]);
        return -1;
    }
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        close(p[0]);
        dup2(p[1], 1);
        if (devnull >= 0) { dup2(devnull, 2); close(devnull); }
        close(p[1]);
        execv(exe, argv);
        _exit(127);
    }
    close(p[1]);
    {
        char tmp[4096];
        ssize_t r;
        while ((r = read(p[0], tmp, sizeof(tmp))) > 0) {
            size_t take = (size_t)r;
            if (n < outsz - 1) {
                size_t room = outsz - 1 - n;
                if (take > room)
                    take = room;
                memcpy(out + n, tmp, take);
                n += take;
            }
        }
    }
    close(p[0]);
    waitpid(pid, &st, 0);
    if (outsz > 0)
        out[n < outsz ? n : outsz - 1] = '\0';
    if (WIFEXITED(st))
        return WEXITSTATUS(st);
    return -1;
}

static int run_exit(const char *exe, char *const argv[])
{
    char out[16];
    return run_capture(exe, argv, out, sizeof(out));
}

static int cap_contains(const char *exe, char *const argv[], const char *needle)
{
    char out[8192];
    if (run_capture(exe, argv, out, sizeof(out)) != 0)
        return 0;
    return strstr(out, needle) != 0;
}

/* Count output lines that start with a digit (ipset members). Streamed so a
 * large set is not truncated by a fixed buffer (ok_max_entries can exceed a
 * 64 KiB capture). */
static int cap_count_digits(const char *exe, char *const argv[])
{
    int p[2];
    pid_t pid;
    int st, count = 0, at_bol = 1;
    if (pipe(p) != 0)
        return 0;
    pid = fork();
    if (pid < 0) {
        close(p[0]); close(p[1]);
        return 0;
    }
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        close(p[0]);
        dup2(p[1], 1);
        if (devnull >= 0) { dup2(devnull, 2); close(devnull); }
        close(p[1]);
        execv(exe, argv);
        _exit(127);
    }
    close(p[1]);
    {
        char tmp[4096];
        ssize_t r;
        size_t i;
        while ((r = read(p[0], tmp, sizeof(tmp))) > 0) {
            for (i = 0; i < (size_t)r; i++) {
                char c = tmp[i];
                if (at_bol && c >= '0' && c <= '9')
                    count++;
                at_bol = (c == '\n');
            }
        }
    }
    close(p[0]);
    waitpid(pid, &st, 0);
    return count;
}

int ops_setup(const susanin_config *base, const char *conf_path, int argc, char **argv)
{
    susanin_config cfg = *base;
    int i;
    for (i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--egress") && i + 1 < argc)
            snprintf(cfg.egress_interface, sizeof(cfg.egress_interface), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--lan") && i + 1 < argc)
            snprintf(cfg.lan_interfaces, sizeof(cfg.lan_interfaces), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--table") && i + 1 < argc)
            cfg.routing_table = atoi(argv[++i]);
    }

    if (config_save(conf_path, &cfg) != 0) {
        fprintf(stderr, "cannot write config %s\n", conf_path);
        return 1;
    }
    printf("config written: %s\n", conf_path);
    config_print(&cfg);

    printf("provisioning data plane ...\n");
    if (backend_provision(&cfg) != 0) {
        fprintf(stderr, "datapath provisioning failed (see datapath.sh output)\n");
        return 1;
    }
    printf("data plane UP (table=%d dev=%s)\n", cfg.routing_table, cfg.egress_interface);
    printf("next: susanin-agent status ; SUSANIN_CONF=%s susanin-agent run\n", conf_path);
    return 0;
}

static void print_check(const char *name, int ok)
{
    printf("  %-28s %s\n", name, ok ? "OK" : "MISSING");
}

static int count_list_lines(const char *path)
{
    FILE *fp = fopen(path, "r");
    char line[320];
    int n = 0;
    if (!fp)
        return -1;
    while (fgets(line, sizeof(line), fp)) {
        char *p = line + strlen(line);
        while (p > line && (p[-1] == ' ' || p[-1] == '\t' || p[-1] == '\r' ||
                            p[-1] == '\n'))
            *--p = '\0';
        if (line[0] == '\0' || line[0] == '#')
            continue;
        n++;
    }
    fclose(fp);
    return n;
}

int ops_status(const susanin_config *cfg, const char *conf_path)
{
    const char *ipt = tool("iptables");
    const char *ip = tool("ip");
    const char *ipset = tool("ipset");
    const char *state_path = "/opt/susanin/var/susanin.state";
    char *a[8];
    char needle[160];

    printf("susanin-agent %s\n", SUSANIN_VERSION);
    printf("config file: %s (%s)\n", conf_path,
           access(conf_path, R_OK) == 0 ? "present" : "absent");
    printf("egress=%s table=%d lan=%s\n", cfg->egress_interface,
           cfg->routing_table, cfg->lan_interfaces);
    if (strcmp(cfg->egress_type, "tproxy") == 0)
        printf("mode=tproxy port=%d (Xray %s)\n", cfg->tproxy_port,
               backend_local_listen(cfg->tproxy_port) ? "LISTEN" : "NOT LISTENING");
    else
        printf("mode=interface\n");
    printf("egress pool: n=%d failback=%d debounce=%ds race=%d\n",
           cfg->n_egress, cfg->egress_failback, cfg->egress_failback_debounce,
           cfg->egress_race);
    printf("features: dns_sniff=%d offload=%d(%s) pin_reassert=%d xray_watchdog=%d auto_direct=%d media=%d\n",
           cfg->dns_sniff, cfg->kernel_offload,
           cfg->kernel_egress[0] ? cfg->kernel_egress : "-",
           cfg->pin_reassert, cfg->xray_watchdog, cfg->auto_direct,
           cfg->media_enabled);
    if (cfg->n_profiles > 0) {
        int k;
        printf("profiles (failover=%d):\n", cfg->profile_failover);
        for (k = 0; k < cfg->n_profiles; k++)
            printf("  %s: egress=%s table=%d mark=0x%lx auto=%d list=%s\n",
                   cfg->profile_name[k][0] ? cfg->profile_name[k] : "?",
                   cfg->profile_egress[k][0] ? cfg->profile_egress[k] : "-",
                   cfg->profile_table[k], cfg->profile_mark[k],
                   cfg->profile_auto[k],
                   cfg->profile_list[k][0] ? cfg->profile_list[k] : "-");
    }

    printf("data plane:\n");
    a[0] = (char *)ipt; a[1] = "-t"; a[2] = "mangle"; a[3] = "-S"; a[4] = (char *)CHAIN; a[5] = NULL;
    print_check("chain SUSANIN", run_exit(ipt, a) == 0);

    a[0] = (char *)ipt; a[1] = "-t"; a[2] = "mangle"; a[3] = "-S"; a[4] = "PREROUTING"; a[5] = NULL;
    print_check("PREROUTING jump", cap_contains(ipt, a, "-j SUSANIN"));

    if (strcmp(cfg->egress_type, "tproxy") == 0) {
        /* tproxy: правила test/ok -> table 100 намеренно отсутствуют; вместо них
         * fwmark 0x1 + local-маршрут (UDP-релей) и nat REDIRECT (TCP). */
        a[0] = (char *)ip; a[1] = "rule"; a[2] = "show"; a[3] = NULL;
        snprintf(needle, sizeof(needle), "fwmark 0x1 lookup %d", cfg->routing_table);
        print_check("ip rule tproxy->table", cap_contains(ip, a, needle));
        {
            char tbl[16];
            snprintf(tbl, sizeof(tbl), "%d", cfg->routing_table);
            a[0] = (char *)ip; a[1] = "route"; a[2] = "show"; a[3] = "table"; a[4] = tbl; a[5] = NULL;
            print_check("local route in table", cap_contains(ip, a, "local default"));
        }
        a[0] = (char *)ipt; a[1] = "-t"; a[2] = "nat"; a[3] = "-S"; a[4] = "PREROUTING"; a[5] = NULL;
        print_check("nat REDIRECT (TCP)", cap_contains(ipt, a, "-j REDIRECT --to-ports"));
        a[0] = (char *)ipt; a[1] = "-t"; a[2] = "mangle"; a[3] = "-S"; a[4] = "PREROUTING"; a[5] = NULL;
        if (cap_contains(ipt, a, "-j TPROXY"))
            printf("  udp-relay: TPROXY present\n");
    } else {
        a[0] = (char *)ip; a[1] = "rule"; a[2] = "show"; a[3] = NULL;
        snprintf(needle, sizeof(needle), "fwmark 0x%lx lookup %d", cfg->mark_test, cfg->routing_table);
        print_check("ip rule test->table", cap_contains(ip, a, needle));
        snprintf(needle, sizeof(needle), "fwmark 0x%lx lookup %d", cfg->mark_ok, cfg->routing_table);
        print_check("ip rule ok->table", cap_contains(ip, a, needle));
        {
            char tbl[16];
            snprintf(tbl, sizeof(tbl), "%d", cfg->routing_table);
            a[0] = (char *)ip; a[1] = "route"; a[2] = "show"; a[3] = "table"; a[4] = tbl; a[5] = NULL;
            print_check("route default in table", cap_contains(ip, a, "default"));
        }
    }

    if (strcmp(cfg->egress_type, "tproxy") == 0) {
        long when = 0;
        char reason[200] = "";
        if (backend_read_reprov(&when, reason, sizeof(reason)) == 0 && when > 0) {
            long ago = (long)(time(NULL) - when);
            printf("  tproxy re-provision: %lds ago (%s)\n", ago,
                   reason[0] ? reason : "?");
        } else {
            printf("  tproxy re-provision: never\n");
        }
    }

    printf("ipset sizes:\n");
    {
        static const char *names[6] = {
            "susanin_test_tcp", "susanin_test_udp",
            "susanin_ok_tcp", "susanin_ok_udp",
            "susanin_ok_net", "susanin_never"
        };
        int k;
        for (k = 0; k < 6; k++) {
            char *b[4];
            b[0] = (char *)ipset; b[1] = "list"; b[2] = (char *)names[k]; b[3] = NULL;
            printf("  %-18s = %d\n", names[k], cap_count_digits(ipset, b));
        }
    }

    cdn_load(cfg);
    printf("cdn (prefix aggregation):\n");
    printf("  file: %s (%d nets)\n", cfg->cdn_ranges_file[0] ? cfg->cdn_ranges_file : "-",
           cdn_count());
    printf("  prefix_learn=%d prefix_max=/%d ttl=%ds refresh=%ds\n",
           cfg->cdn_prefix_learn, cfg->cdn_prefix_max, cfg->cdn_prefix_ttl,
           cfg->cdn_ranges_interval);

    printf("vpn_always (always-VPN list):\n");
    if (!cfg->vpn_always_file[0]) {
        printf("  disabled (vpn_always_file empty)\n");
    } else {
        int n = count_list_lines(cfg->vpn_always_file);
        printf("  file: %s (%s)\n", cfg->vpn_always_file,
               n < 0 ? "absent — disabled" : "present");
        if (n >= 0)
            printf("  domains: %d (refresh every %ds%s)\n", n,
                   cfg->vpn_always_interval,
                   cfg->vpn_always_dns[0] ? "" : ", resolver: auto");
    }

    printf("cache:\n");
    print_check("state file", access(state_path, R_OK) == 0);
    return 0;
}

/* Сбросить адрес (IP или домен) из кэша/ipsets и conntrack — «забыть» адрес,
 * чтобы он заново прошёл путь обучения (или был перепинен из vpn_always).
 * Для домена (и `*.домен`) сбрасываются apex + типовые/пробные поддомены
 * (best-effort: DNS не даёт перечислить все поддомены зоны). Файлы
 * vpn_always/vpn_never не изменяются. */
int ops_reset(const susanin_config *cfg, const char *arg)
{
    const char *path = "/opt/susanin/var/susanin.state";
    susanin_state st;
    char ips[32][16];
    char base[256];
    int n = 0, i, udp, zone = 0;
    struct in_addr a;

    if (!arg || !arg[0]) {
        fprintf(stderr, "usage: susanin-agent reset <ip|domain>\n");
        return 2;
    }
    memset(ips, 0, sizeof(ips));

    if (inet_pton(AF_INET, arg, &a) == 1) {
        snprintf(ips[0], sizeof(ips[0]), "%.15s", arg);
        n = 1;
    } else {
        char server[64];
        char names[8][300];
        int nn = 0, k;
        if (arg[0] == '*' && arg[1] == '.')
            snprintf(base, sizeof(base), "%.200s", arg + 2);
        else
            snprintf(base, sizeof(base), "%.200s", arg);
        zone = 1;
        va_pick_resolver(cfg, server, sizeof(server));
        snprintf(names[nn++], sizeof(names[0]), "%s", base);
        snprintf(names[nn++], sizeof(names[0]), "www.%s", base);
        snprintf(names[nn++], sizeof(names[0]), "cdn.%s", base);
        snprintf(names[nn++], sizeof(names[0]), "api.%s", base);
        snprintf(names[nn++], sizeof(names[0]), "static.%s", base);
        snprintf(names[nn++], sizeof(names[0]), "m.%s", base);
        for (k = 0; k < 2 && nn < 8; k++) {
            /* «случайные» поддомены — как при пиннинге зоны в vpn_always */
            snprintf(names[nn++], sizeof(names[0]), "susanin-%08lx%d.%s",
                     (unsigned long)(time(NULL) ^ (getpid() << 8)), k, base);
        }
        for (i = 0; i < nn && n < 32; i++) {
            char tmp[16][16];
            int m = va_dns_query(server, names[i], tmp, 16, 1500);
            int j, x;
            for (j = 0; j < m && n < 32; j++) {
                int dup = 0;
                for (x = 0; x < n; x++)
                    if (!strcmp(ips[x], tmp[j])) { dup = 1; break; }
                if (!dup)
                    snprintf(ips[n++], sizeof(ips[0]), "%.15s", tmp[j]);
            }
        }
        if (n == 0) {
            fprintf(stderr, "[susanin] reset %s: ничего не разрешилось\n", arg);
            return 1;
        }
    }

    state_init(&st);
    state_load(path, &st);
    for (i = 0; i < n; i++) {
        int removed = 0;
        for (udp = 0; udp < 2; udp++) {
            if (state_remove(st_test(&st, udp), ips[i]))
                removed++;
            if (state_remove(st_ok(&st, udp), ips[i]))
                removed++;
            if (state_remove(st_cool(&st, udp), ips[i]))
                removed++;
            backend_ipset_del(cfg, udp, 0, ips[i]);
            backend_ipset_del(cfg, udp, 1, ips[i]);
        }
        backend_set_del(cfg, "susanin_never", ips[i]);
        backend_ct_flush_ip(ips[i]);
        printf("[susanin] reset %s%s: %s removed=%d, ipsets cleared, conntrack flushed\n",
               zone ? "zone " : "", arg, ips[i], removed);
    }
    state_save(path, &st);
    state_free(&st);
    return 0;
}

static int check_missing(const susanin_config *cfg, char *a[])
{
    const char *ipt = tool("iptables");
    const char *ip = tool("ip");
    char needle[160];
    char tbl[16];
    int missing = 0;

    a[0] = (char *)ipt; a[1] = "-t"; a[2] = "mangle"; a[3] = "-S"; a[4] = (char *)CHAIN; a[5] = NULL;
    if (run_exit(ipt, a) != 0) { missing++; printf("CREATE chain %s\n", CHAIN); }
    else printf("KEEP chain %s\n", CHAIN);

    a[0] = (char *)ipt; a[1] = "-t"; a[2] = "mangle"; a[3] = "-S"; a[4] = "PREROUTING"; a[5] = NULL;
    if (!cap_contains(ipt, a, "-j SUSANIN")) { missing++; printf("CREATE PREROUTING jump -> %s\n", CHAIN); }
    else printf("KEEP PREROUTING jump -> %s\n", CHAIN);

    if (strcmp(cfg->egress_type, "tproxy") == 0) {
        /* tproxy: rule test/ok не нужны; нужен fwmark 0x1 + local-маршрут + REDIRECT. */
        a[0] = (char *)ip; a[1] = "rule"; a[2] = "show"; a[3] = NULL;
        snprintf(needle, sizeof(needle), "fwmark 0x1 lookup %d", cfg->routing_table);
        if (!cap_contains(ip, a, needle)) { missing++; printf("CREATE ip rule tproxy (fwmark 0x1)\n"); }
        else printf("KEEP ip rule tproxy\n");
        snprintf(tbl, sizeof(tbl), "%d", cfg->routing_table);
        a[0] = (char *)ip; a[1] = "route"; a[2] = "show"; a[3] = "table"; a[4] = tbl; a[5] = NULL;
        if (!cap_contains(ip, a, "local default")) { missing++; printf("CREATE local route in table %d\n", cfg->routing_table); }
        else printf("KEEP local route table %d\n", cfg->routing_table);
        a[0] = (char *)ipt; a[1] = "-t"; a[2] = "nat"; a[3] = "-S"; a[4] = "PREROUTING"; a[5] = NULL;
        if (!cap_contains(ipt, a, "-j REDIRECT --to-ports")) { missing++; printf("CREATE nat REDIRECT (TCP)\n"); }
        else printf("KEEP nat REDIRECT (TCP)\n");
        return missing;
    }

    a[0] = (char *)ip; a[1] = "rule"; a[2] = "show"; a[3] = NULL;
    snprintf(needle, sizeof(needle), "fwmark 0x%lx lookup %d", cfg->mark_test, cfg->routing_table);
    if (!cap_contains(ip, a, needle)) { missing++; printf("CREATE ip rule test (fwmark 0x%lx)\n", cfg->mark_test); }
    else printf("KEEP ip rule test\n");
    snprintf(needle, sizeof(needle), "fwmark 0x%lx lookup %d", cfg->mark_ok, cfg->routing_table);
    if (!cap_contains(ip, a, needle)) { missing++; printf("CREATE ip rule ok (fwmark 0x%lx)\n", cfg->mark_ok); }
    else printf("KEEP ip rule ok\n");

    snprintf(tbl, sizeof(tbl), "%d", cfg->routing_table);
    a[0] = (char *)ip; a[1] = "route"; a[2] = "show"; a[3] = "table"; a[4] = tbl; a[5] = NULL;
    if (!cap_contains(ip, a, "default")) { missing++; printf("CREATE default route in table %d\n", cfg->routing_table); }
    else printf("KEEP default route table %d\n", cfg->routing_table);

    return missing;
}

int ops_apply(const susanin_config *cfg, const char *conf_path, int dry_run)
{
    char *a[8];
    int missing;

    printf("=== susanin apply %s ===\n", dry_run ? "--dry-run" : "");
    if (access(conf_path, R_OK) != 0) {
        printf("config %s is MISSING; run: susanin-agent setup [--egress ... --lan ... --table N]\n",
               conf_path);
        return dry_run ? 1 : 2;
    }

    missing = check_missing(cfg, a);

    if (dry_run) {
        printf("Result: %s\n", missing ? "OUT OF SYNC" : "IN SYNC structurally");
        return missing ? 1 : 0;
    }

    if (missing) {
        if (strcmp(cfg->egress_type, "tproxy") == 0 &&
            !backend_local_listen(cfg->tproxy_port)) {
            printf("refusing: egress_type=tproxy, но Xray не слушает 127.0.0.1:%d.\n",
                   cfg->tproxy_port);
            printf("Запустите Xray (/opt/etc/init.d/S93xray-tproxy start) — иначе правила "
                   "tproxy сделают чёрную дыру.\n");
            return 3;
        }
        printf("provisioning missing objects ...\n");
        backend_provision(cfg);
    }
    printf("Result: reconciled\n");
    return 0;
}

/* --- JSON snapshot for the built-in web panel (read-only) ------ */

static void json_str(char *dst, size_t n, const char *s)
{
    size_t j = 0;
    if (!n)
        return;
    for (; s && *s && j + 7 < n; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            dst[j++] = '\\';
            dst[j++] = (char)c;
        } else if (c == '\n') {
            dst[j++] = '\\'; dst[j++] = 'n';
        } else if (c == '\r') {
            dst[j++] = '\\'; dst[j++] = 'r';
        } else if (c == '\t') {
            dst[j++] = '\\'; dst[j++] = 't';
        } else if (c < 0x20) {
            j += (size_t)snprintf(dst + j, n - j, "\\u%04x", c);
        } else {
            dst[j++] = (char)c;
        }
    }
    dst[j] = '\0';
}

static void japp(char *buf, size_t n, int *used, const char *fmt, ...)
{
    va_list ap;
    int r;
    if (*used < 0 || (size_t)*used >= n)
        return;
    va_start(ap, fmt);
    r = vsnprintf(buf + *used, n - (size_t)*used, fmt, ap);
    va_end(ap);
    if (r > 0) {
        *used += r;
        if ((size_t)*used >= n)
            *used = (int)n - 1;
    }
}

int ops_status_json(const susanin_config *cfg, const char *conf_path,
                    char *buf, size_t n)
{
    static const char *sets[6] = {
        "susanin_test_tcp", "susanin_test_udp",
        "susanin_ok_tcp", "susanin_ok_udp",
        "susanin_ok_net", "susanin_never"
    };
    const char *ipset = tool("ipset");
    const char *state_path = "/opt/susanin/var/susanin.state";
    int used = 0, k;
    char esc[CFG_PATH_MAX * 2];
    int va_count = -1, vn_count = -1;

    if (cfg->vpn_always_file[0])
        va_count = count_list_lines(cfg->vpn_always_file);
    if (cfg->vpn_never_file[0])
        vn_count = count_list_lines(cfg->vpn_never_file);

    japp(buf, n, &used, "{");
    japp(buf, n, &used, "\"version\":\"%s\",", SUSANIN_VERSION);

    json_str(esc, sizeof(esc), conf_path ? conf_path : "");
    japp(buf, n, &used, "\"config\":\"%s\",\"config_present\":%s,",
         esc, (conf_path && access(conf_path, R_OK) == 0) ? "true" : "false");

    json_str(esc, sizeof(esc), cfg->egress_interface);
    japp(buf, n, &used,
         "\"egress\":{\"interface\":\"%s\",\"type\":\"%s\",\"count\":%d,\"table\":%d,", esc,
         cfg->egress_type, cfg->n_egress, cfg->routing_table);
    json_str(esc, sizeof(esc), cfg->lan_interfaces);
    japp(buf, n, &used, "\"lan_interfaces\":\"%s\",", esc);
    json_str(esc, sizeof(esc), cfg->lan_subnets);
    japp(buf, n, &used, "\"lan_subnets\":\"%s\",", esc);
    japp(buf, n, &used, "\"mark_test\":\"0x%lx\",\"mark_ok\":\"0x%lx\"},",
         cfg->mark_test, cfg->mark_ok);

    japp(buf, n, &used, "\"ipsets\":{");
    for (k = 0; k < 6; k++) {
        char *b[4];
        int cnt;
        b[0] = (char *)ipset; b[1] = "list"; b[2] = (char *)sets[k]; b[3] = NULL;
        cnt = cap_count_digits(ipset, b);
        japp(buf, n, &used, "%s\"%s\":%d", k ? "," : "", sets[k], cnt);
    }
    japp(buf, n, &used, "},");

    json_str(esc, sizeof(esc), cfg->vpn_always_file);
    japp(buf, n, &used,
         "\"lists\":{\"vpn_always\":{\"file\":\"%s\",\"count\":%d},", esc,
         va_count);
    json_str(esc, sizeof(esc), cfg->vpn_never_file);
    japp(buf, n, &used, "\"vpn_never\":{\"file\":\"%s\",\"count\":%d}},", esc,
         vn_count);

    japp(buf, n, &used, "\"profiles\":[");
    for (k = 0; k < cfg->n_profiles; k++) {
        char ne[128], ge[128];
        json_str(ne, sizeof(ne), cfg->profile_name[k]);
        json_str(ge, sizeof(ge), cfg->profile_egress[k]);
        japp(buf, n, &used,
             "%s{\"name\":\"%s\",\"egress\":\"%s\",\"table\":%d,\"mark\":\"0x%lx\"}",
             k ? "," : "", ne, ge, cfg->profile_table[k], cfg->profile_mark[k]);
    }
    japp(buf, n, &used, "],");

    japp(buf, n, &used, "\"state_file\":%s,",
         access(state_path, R_OK) == 0 ? "true" : "false");

    json_str(esc, sizeof(esc), cfg->web_listen);
    japp(buf, n, &used,
         "\"web\":{\"enable\":%d,\"listen\":\"%s\",\"port\":%d,\"token_set\":%s}",
         cfg->web_enable, esc, cfg->web_port,
         cfg->web_token[0] ? "true" : "false");

    japp(buf, n, &used, "}");
    return used;
}

int ops_config_json(const susanin_config *cfg, const char *conf_path, char *buf, size_t n)
{
    FILE *fp;
    char line[1024];
    int used = 0, first = 1;

    japp(buf, n, &used, "{\"file\":");
    {
        char esc[CFG_PATH_MAX * 2];
        json_str(esc, sizeof(esc), conf_path ? conf_path : "");
        japp(buf, n, &used, "\"%s\",\"params\":{", esc);
    }
    fp = conf_path ? fopen(conf_path, "r") : NULL;
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            char *eq, *p, *q;
            size_t l;
            l = strlen(line);
            while (l > 0 && (line[l - 1] == '\n' || line[l - 1] == '\r' ||
                             line[l - 1] == ' ' || line[l - 1] == '\t'))
                line[--l] = '\0';
            p = line;
            while (*p == ' ' || *p == '\t')
                p++;
            if (*p == '\0' || *p == '#')
                continue;
            eq = strchr(p, '=');
            if (!eq)
                continue;
            *eq = '\0';
            q = eq + 1;
            {
                char ke[256], ve[2048];
                const char *k = p;
                const char *v = q;
                if (!strcmp(k, "web_token"))
                    v = "";  /* секрет не отдаём */
                json_str(ke, sizeof(ke), k);
                json_str(ve, sizeof(ve), v);
                japp(buf, n, &used, "%s\"%s\":\"%s\"", first ? "" : ",", ke, ve);
                first = 0;
            }
        }
        fclose(fp);
    }
    japp(buf, n, &used, "},\"token_set\":%s}", cfg->web_token[0] ? "true" : "false");
    return used;
}

int ops_list_json(const susanin_config *cfg, const char *which, char *buf, size_t n)
{
    const char *path = NULL;
    FILE *fp;
    char line[320];
    int used = 0, first = 1, count = 0;

    if (!strcmp(which, "vpn_always"))
        path = cfg->vpn_always_file;
    else if (!strcmp(which, "vpn_never"))
        path = cfg->vpn_never_file;

    japp(buf, n, &used, "[");
    if (path && path[0] && (fp = fopen(path, "r")) != NULL) {
        while (count < 8192 && fgets(line, sizeof(line), fp)) {
            char esc[sizeof(line) * 2];
            char *p = line + strlen(line);
            while (p > line && (p[-1] == ' ' || p[-1] == '\t' ||
                                p[-1] == '\r' || p[-1] == '\n'))
                *--p = '\0';
            if (line[0] == '\0' || line[0] == '#')
                continue;
            json_str(esc, sizeof(esc), line);
            japp(buf, n, &used, "%s\"%s\"", first ? "" : ",", esc);
            first = 0;
            count++;
        }
        fclose(fp);
    }
    japp(buf, n, &used, "]");
    return used;
}
