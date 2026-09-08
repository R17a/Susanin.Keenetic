#ifndef SUSANIN_CONFIG_H
#define SUSANIN_CONFIG_H

#define CFG_MAX_LAN 8
#define CFG_PATH_MAX 256

typedef struct {
    char egress_interface[CFG_PATH_MAX];
    char egress_address[64];
    char lan_interfaces[CFG_PATH_MAX];
    char lan_subnets[CFG_PATH_MAX];
    int routing_table;
    unsigned long mark_test;
    unsigned long mark_ok;
    unsigned long mark_mask;
    int ip_rule_priority_start;
    int fast_interval;
    int soft_interval;
    int judge_interval;
    int health_interval;
    int fast_syn_min_op;
    int ok_ttl;
    int ok_refresh_below;
    int test_ttl;
    int cooldown_ttl;
    int cooldown_ok_ttl;
    int watch_ttl;
    int watch_retry_below;
    int health_miss_debounce;
    char health_probe[CFG_PATH_MAX];
    char health_probe_src[64];
    char vpn_always_file[CFG_PATH_MAX];
    char vpn_always_dns[CFG_PATH_MAX];
    int vpn_always_interval;
    char log_level[16];
    int diagnostics;
} susanin_config;

void config_set_defaults(susanin_config *c);
int config_load(const char *path, susanin_config *c);
int config_save(const char *path, const susanin_config *c);
void config_print(const susanin_config *c);

#endif
