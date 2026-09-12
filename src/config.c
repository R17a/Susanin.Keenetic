#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_interval(const char *s)
{
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (end == s || v < 0)
        return 0;
    if (end && (*end == 's' || *end == '\0'))
        return (int)v;
    if (end && *end == 'm')
        return (int)(v * 60);
    if (end && *end == 'h')
        return (int)(v * 3600);
    if (end && *end == 'd')
        return (int)(v * 86400);
    if (end && *end == 'w')
        return (int)(v * 604800);
    return (int)v;
}

void config_set_defaults(susanin_config *c)
{
    memset(c, 0, sizeof(*c));
    snprintf(c->egress_interface, sizeof(c->egress_interface), "%s", "nwg0");
    snprintf(c->egress_address, sizeof(c->egress_address), "%s", "10.8.1.1");
    snprintf(c->lan_interfaces, sizeof(c->lan_interfaces), "%s", "br0");
    snprintf(c->lan_subnets, sizeof(c->lan_subnets), "%s", "192.168.1.0/24");
    c->routing_table = 100;
    c->mark_test = 0x10000000UL;
    c->mark_ok = 0x20000000UL;
    c->mark_mask = 0x30000000UL;
    c->ip_rule_priority_start = 2000;
    c->fast_interval = 1;
    c->soft_interval = 2;
    c->judge_interval = 1;
    c->health_interval = 5;
    c->fast_syn_min_op = 2;
    c->ok_ttl = 6 * 3600;
    c->ok_refresh_below = 3 * 3600;
    c->ok_max_entries = 4096;
    c->test_ttl = 60;
    c->cooldown_ttl = 5 * 60;
    c->cooldown_ok_ttl = 30;
    c->watch_ttl = 8;
    c->watch_retry_below = 4;
    c->health_miss_debounce = 4;
    snprintf(c->health_probe, sizeof(c->health_probe), "%s", "1.1.1.1,8.8.8.8");
    snprintf(c->health_probe_src, sizeof(c->health_probe_src), "%s", "10.8.1.1");
    snprintf(c->vpn_always_file, sizeof(c->vpn_always_file), "%s",
             "/opt/susanin/etc/vpn_always.txt");
    snprintf(c->vpn_always_dns, sizeof(c->vpn_always_dns), "%s", "");
    c->vpn_always_interval = 300;
    snprintf(c->vpn_never_file, sizeof(c->vpn_never_file), "%s",
             "/opt/susanin/etc/vpn_never.txt");
    c->vpn_never_interval = 300;
    snprintf(c->log_level, sizeof(c->log_level), "%s", "info");
    c->diagnostics = 0;
}

static void set_str(char *dst, size_t n, const char *v)
{
    snprintf(dst, n, "%s", v ? v : "");
}

int config_load(const char *path, susanin_config *c)
{
    FILE *fp;
    char line[512];

    config_set_defaults(c);
    if (!path)
        return 0;
    fp = fopen(path, "r");
    if (!fp)
        return -1;

    while (fgets(line, sizeof(line), fp)) {
        char *p = line, *key, *val;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0')
            continue;
        key = p;
        while (*p && *p != '=' && *p != '\n') p++;
        if (*p != '=')
            continue;
        *p++ = '\0';
        while (*p == ' ' || *p == '\t') p++;
        val = p;
        {
            char *q = val;
            while (*q && *q != '\n') q++;
            *q = '\0';
        }
        {
            char *q = val + strlen(val) - 1;
            while (q >= val && (*q == ' ' || *q == '\t' || *q == '\r')) *q-- = '\0';
        }

        if (!strcmp(key, "egress_interface"))
            set_str(c->egress_interface, sizeof(c->egress_interface), val);
        else if (!strcmp(key, "egress_address"))
            set_str(c->egress_address, sizeof(c->egress_address), val);
        else if (!strcmp(key, "lan_interfaces"))
            set_str(c->lan_interfaces, sizeof(c->lan_interfaces), val);
        else if (!strcmp(key, "lan_subnets"))
            set_str(c->lan_subnets, sizeof(c->lan_subnets), val);
        else if (!strcmp(key, "routing_table"))
            c->routing_table = (int)strtol(val, NULL, 0);
        else if (!strcmp(key, "mark_test"))
            c->mark_test = strtoul(val, NULL, 0);
        else if (!strcmp(key, "mark_ok"))
            c->mark_ok = strtoul(val, NULL, 0);
        else if (!strcmp(key, "mark_mask"))
            c->mark_mask = strtoul(val, NULL, 0);
        else if (!strcmp(key, "ip_rule_priority_start"))
            c->ip_rule_priority_start = (int)strtol(val, NULL, 0);
        else if (!strcmp(key, "fast_interval"))
            c->fast_interval = parse_interval(val);
        else if (!strcmp(key, "soft_interval"))
            c->soft_interval = parse_interval(val);
        else if (!strcmp(key, "judge_interval"))
            c->judge_interval = parse_interval(val);
        else if (!strcmp(key, "health_interval"))
            c->health_interval = parse_interval(val);
        else if (!strcmp(key, "fast_syn_min_op"))
            c->fast_syn_min_op = (int)strtol(val, NULL, 0);
        else if (!strcmp(key, "ok_ttl"))
            c->ok_ttl = parse_interval(val);
        else if (!strcmp(key, "ok_refresh_below"))
            c->ok_refresh_below = parse_interval(val);
        else if (!strcmp(key, "ok_max_entries"))
            c->ok_max_entries = (int)strtol(val, NULL, 0);
        else if (!strcmp(key, "test_ttl"))
            c->test_ttl = parse_interval(val);
        else if (!strcmp(key, "cooldown_ttl"))
            c->cooldown_ttl = parse_interval(val);
        else if (!strcmp(key, "cooldown_ok_ttl"))
            c->cooldown_ok_ttl = parse_interval(val);
        else if (!strcmp(key, "watch_ttl"))
            c->watch_ttl = parse_interval(val);
        else if (!strcmp(key, "watch_retry_below"))
            c->watch_retry_below = parse_interval(val);
        else if (!strcmp(key, "health_miss_debounce"))
            c->health_miss_debounce = (int)strtol(val, NULL, 0);
        else if (!strcmp(key, "health_probe"))
            set_str(c->health_probe, sizeof(c->health_probe), val);
        else if (!strcmp(key, "health_probe_src"))
            set_str(c->health_probe_src, sizeof(c->health_probe_src), val);
        else if (!strcmp(key, "vpn_always_file"))
            set_str(c->vpn_always_file, sizeof(c->vpn_always_file), val);
        else if (!strcmp(key, "vpn_always_dns"))
            set_str(c->vpn_always_dns, sizeof(c->vpn_always_dns), val);
        else if (!strcmp(key, "vpn_always_interval"))
            c->vpn_always_interval = parse_interval(val);
        else if (!strcmp(key, "vpn_never_file"))
            set_str(c->vpn_never_file, sizeof(c->vpn_never_file), val);
        else if (!strcmp(key, "vpn_never_interval"))
            c->vpn_never_interval = parse_interval(val);
        else if (!strcmp(key, "log_level"))
            set_str(c->log_level, sizeof(c->log_level), val);
        else if (!strcmp(key, "diagnostics"))
            c->diagnostics = (int)strtol(val, NULL, 0);
    }

    fclose(fp);
    return 0;
}

int config_save(const char *path, const susanin_config *c)
{
    FILE *fp = fopen(path, "w");
    if (!fp)
        return -1;
    fprintf(fp, "# Susanin.Keenetic configuration (generated)\n");
    fprintf(fp, "egress_interface=%s\n", c->egress_interface);
    fprintf(fp, "egress_address=%s\n", c->egress_address);
    fprintf(fp, "lan_interfaces=%s\n", c->lan_interfaces);
    fprintf(fp, "lan_subnets=%s\n", c->lan_subnets);
    fprintf(fp, "routing_table=%d\n", c->routing_table);
    fprintf(fp, "mark_test=0x%lx\n", c->mark_test);
    fprintf(fp, "mark_ok=0x%lx\n", c->mark_ok);
    fprintf(fp, "mark_mask=0x%lx\n", c->mark_mask);
    fprintf(fp, "ip_rule_priority_start=%d\n", c->ip_rule_priority_start);
    fprintf(fp, "fast_interval=%ds\n", c->fast_interval);
    fprintf(fp, "soft_interval=%ds\n", c->soft_interval);
    fprintf(fp, "judge_interval=%ds\n", c->judge_interval);
    fprintf(fp, "health_interval=%ds\n", c->health_interval);
    fprintf(fp, "fast_syn_min_op=%d\n", c->fast_syn_min_op);
    fprintf(fp, "ok_ttl=%ds\n", c->ok_ttl);
    fprintf(fp, "ok_refresh_below=%ds\n", c->ok_refresh_below);
    fprintf(fp, "ok_max_entries=%d\n", c->ok_max_entries);
    fprintf(fp, "test_ttl=%ds\n", c->test_ttl);
    fprintf(fp, "cooldown_ttl=%ds\n", c->cooldown_ttl);
    fprintf(fp, "cooldown_ok_ttl=%ds\n", c->cooldown_ok_ttl);
    fprintf(fp, "watch_ttl=%ds\n", c->watch_ttl);
    fprintf(fp, "watch_retry_below=%ds\n", c->watch_retry_below);
    fprintf(fp, "health_miss_debounce=%d\n", c->health_miss_debounce);
    fprintf(fp, "health_probe=%s\n", c->health_probe);
    fprintf(fp, "health_probe_src=%s\n", c->health_probe_src);
    fprintf(fp, "vpn_always_file=%s\n", c->vpn_always_file);
    fprintf(fp, "vpn_always_dns=%s\n", c->vpn_always_dns);
    fprintf(fp, "vpn_always_interval=%ds\n", c->vpn_always_interval);
    fprintf(fp, "vpn_never_file=%s\n", c->vpn_never_file);
    fprintf(fp, "vpn_never_interval=%ds\n", c->vpn_never_interval);
    fprintf(fp, "log_level=%s\n", c->log_level);
    fprintf(fp, "diagnostics=%d\n", c->diagnostics);
    fclose(fp);
    return 0;
}

void config_print(const susanin_config *c)
{
    printf("egress_interface=%s\n", c->egress_interface);
    printf("egress_address=%s\n", c->egress_address);
    printf("lan_interfaces=%s\n", c->lan_interfaces);
    printf("lan_subnets=%s\n", c->lan_subnets);
    printf("routing_table=%d\n", c->routing_table);
    printf("mark_test=0x%lx\n", c->mark_test);
    printf("mark_ok=0x%lx\n", c->mark_ok);
    printf("mark_mask=0x%lx\n", c->mark_mask);
    printf("ip_rule_priority_start=%d\n", c->ip_rule_priority_start);
    printf("fast_interval=%ds\n", c->fast_interval);
    printf("soft_interval=%ds\n", c->soft_interval);
    printf("judge_interval=%ds\n", c->judge_interval);
    printf("health_interval=%ds\n", c->health_interval);
    printf("fast_syn_min_op=%d\n", c->fast_syn_min_op);
    printf("ok_ttl=%ds\n", c->ok_ttl);
    printf("ok_refresh_below=%ds\n", c->ok_refresh_below);
    printf("ok_max_entries=%d\n", c->ok_max_entries);
    printf("test_ttl=%ds\n", c->test_ttl);
    printf("cooldown_ttl=%ds\n", c->cooldown_ttl);
    printf("cooldown_ok_ttl=%ds\n", c->cooldown_ok_ttl);
    printf("watch_ttl=%ds\n", c->watch_ttl);
    printf("watch_retry_below=%ds\n", c->watch_retry_below);
    printf("health_miss_debounce=%d\n", c->health_miss_debounce);
    printf("health_probe=%s\n", c->health_probe);
    printf("health_probe_src=%s\n", c->health_probe_src);
    printf("vpn_always_file=%s\n", c->vpn_always_file);
    printf("vpn_always_dns=%s\n", c->vpn_always_dns);
    printf("vpn_always_interval=%ds\n", c->vpn_always_interval);
    printf("vpn_never_file=%s\n", c->vpn_never_file);
    printf("vpn_never_interval=%ds\n", c->vpn_never_interval);
    printf("log_level=%s\n", c->log_level);
    printf("diagnostics=%d\n", c->diagnostics);
}
