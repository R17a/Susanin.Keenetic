#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Единицы длительностей (в секундах). У каждого временного параметра своя
 * единица; в файле значение пишется числом БЕЗ суффикса, а единица указана
 * в описании параметра. */
#define U_SEC   1
#define U_MIN   60
#define U_HOUR  3600

/* Разбор длительности. Голое число трактуется в единицах параметра (unit —
 * сколько секунд в единице). Суффиксы s/m/h/d/w поддержаны для совместимости
 * со старыми конфигами (напр. cooldown_ttl=5m). */
static int parse_dur(const char *s, int unit)
{
    char *end = NULL;
    long v;
    if (!s)
        return 0;
    v = strtol(s, &end, 10);
    if (end == s || v < 0)
        return 0;
    if (end) {
        if (*end == 's') return (int)v;
        if (*end == 'm') return (int)(v * 60);
        if (*end == 'h') return (int)(v * 3600);
        if (*end == 'd') return (int)(v * 86400);
        if (*end == 'w') return (int)(v * 604800);
    }
    return (int)(v * unit);
}

/* Обратное преобразование: секунды -> значение в единицах параметра. */
static int out_dur(int secs, int unit)
{
    if (unit <= 0)
        unit = 1;
    return secs / unit;
}

/* Копирование строки с ограничением (без -Wformat-truncation). */
static void copy_str(char *dst, size_t n, const char *src)
{
    size_t i = 0;
    if (!n)
        return;
    while (src && src[i] && i + 1 < n) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

/* Разбор списков egress_interface / egress_address (через запятую).
 * Значения выравниваются по индексу; допускается один адрес на все интерфейсы. */
static void parse_egress(susanin_config *c)
{
    char buf[CFG_PATH_MAX], abuf[CFG_PATH_MAX];
    char *save = NULL, *asave = NULL, *tok, *atok;
    int i = 0;

    c->n_egress = 0;
    snprintf(buf, sizeof(buf), "%s", c->egress_interface);
    snprintf(abuf, sizeof(abuf), "%s", c->egress_address);
    tok = strtok_r(buf, ",", &save);
    atok = strtok_r(abuf, ",", &asave);
    while (tok && i < CFG_MAX_EGRESS) {
        while (*tok == ' ' || *tok == '\t') tok++;
        if (*tok) {
            copy_str(c->egress_list[i], sizeof(c->egress_list[i]), tok);
            if (atok) {
                while (*atok == ' ' || *atok == '\t') atok++;
            }
            copy_str(c->egress_addr[i], sizeof(c->egress_addr[i]),
                     atok ? atok : "");
            i++;
        }
        tok = strtok_r(NULL, ",", &save);
        atok = atok ? strtok_r(NULL, ",", &asave) : NULL;
    }
    if (i == 0) {
        copy_str(c->egress_list[0], sizeof(c->egress_list[0]),
                 c->egress_interface[0] ? c->egress_interface : "nwg0");
        copy_str(c->egress_addr[0], sizeof(c->egress_addr[0]), c->egress_address);
        i = 1;
    }
    c->n_egress = i;
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
    c->soft_interval = 1;
    c->judge_interval = 1;
    c->health_interval = 5;
    c->fast_syn_min_op = 2;
    c->ok_ttl = 6 * 3600;
    c->ok_refresh_below = 3 * 3600;
    c->ok_max_entries = 4096;
    c->ok_evict_misses = 3;
    c->promo_per_min = 30;
    c->test_ttl = 60;
    c->cooldown_ttl = 5 * 60;
    c->cooldown_ok_ttl = 30;
    c->watch_ttl = 8;
    c->watch_retry_below = 4;
    c->health_miss_debounce = 4;
    snprintf(c->health_mode, sizeof(c->health_mode), "%s", "icmp");
    c->health_tcp_port = 443;
    snprintf(c->health_probe, sizeof(c->health_probe), "%s", "1.1.1.1,8.8.8.8");
    snprintf(c->vpn_always_file, sizeof(c->vpn_always_file), "%s",
             "/opt/susanin/etc/vpn_always.txt");
    snprintf(c->vpn_always_dns, sizeof(c->vpn_always_dns), "%s", "");
    c->vpn_always_interval = 300;
    snprintf(c->vpn_never_file, sizeof(c->vpn_never_file), "%s",
             "/opt/susanin/etc/vpn_never.txt");
    c->vpn_never_interval = 300;
    snprintf(c->log_level, sizeof(c->log_level), "%s", "info");
    snprintf(c->xray_loglevel, sizeof(c->xray_loglevel), "%s", "warning");
    snprintf(c->disk_mode, sizeof(c->disk_mode), "%s", "normal");
    c->soft_state_interval = 12 * 3600;   /* soft: сохранять состояние раз в 12 ч */
    /* Порты, которые не участвуют в автообучении (типовой скан-шум). */
    snprintf(c->learn_exclude_ports, sizeof(c->learn_exclude_ports), "%s",
             "22,23,53,135,137,138,139,445,554,1433,1723,3306,3389,5432,5900,6379,7547,9100,11211,27017");
    snprintf(c->discover_exclude, sizeof(c->discover_exclude), "%s",
             "wdtt0,wdttraw0,tun0,tap0");
    snprintf(c->lan_server_interfaces, sizeof(c->lan_server_interfaces), "%s", "");
    c->dp_check_interval = 15;
    c->learn_min_op = 10;
    c->learn_min_bytes = 2000;
    c->confirm_min_bytes = 512;
    c->learn_strict = 0;
    snprintf(c->cdn_ranges_file, sizeof(c->cdn_ranges_file), "%s",
             "/opt/susanin/etc/cdn_ranges.txt");
    snprintf(c->cdn_ranges_url, sizeof(c->cdn_ranges_url), "%s",
             "https://www.cloudflare.com/ips-v4");
    c->cdn_ranges_interval = 86400;
    c->cdn_prefix_learn = 1;
    c->cdn_prefix_ttl = 3600;
    c->cdn_prefix_max = 24;
    c->ipv6_block = 1;
    c->quic_block = 1;
    /* Встроенная веб-панель: по умолчанию выключена, адрес не задан. */
    c->web_enable = 0;
    snprintf(c->web_listen, sizeof(c->web_listen), "%s", "");
    c->web_port = 8087;
    snprintf(c->web_token, sizeof(c->web_token), "%s", "");
    snprintf(c->egress_type, sizeof(c->egress_type), "%s", "interface");
    c->tproxy_port = 12345;
    c->udp_relay = 0;
    c->udp_relay_port = 1081;
    snprintf(c->socks_addr, sizeof(c->socks_addr), "%s", "127.0.0.1");
    c->socks_port = 1080;
    c->n_profiles = 0;
    parse_egress(c);
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

        {
            int handled = 0, pi;
            for (pi = 1; pi <= CFG_MAX_PROFILES; pi++) {
                char pk[40];
                snprintf(pk, sizeof(pk), "profile%d_name", pi);
                if (!strcmp(key, pk)) {
                    set_str(c->profile_name[pi - 1], sizeof(c->profile_name[pi - 1]), val);
                    handled = 1; break;
                }
                snprintf(pk, sizeof(pk), "profile%d_egress", pi);
                if (!strcmp(key, pk)) {
                    set_str(c->profile_egress[pi - 1], sizeof(c->profile_egress[pi - 1]), val);
                    handled = 1; break;
                }
                snprintf(pk, sizeof(pk), "profile%d_list", pi);
                if (!strcmp(key, pk)) {
                    set_str(c->profile_list[pi - 1], sizeof(c->profile_list[pi - 1]), val);
                    handled = 1; break;
                }
                snprintf(pk, sizeof(pk), "profile%d_table", pi);
                if (!strcmp(key, pk)) {
                    c->profile_table[pi - 1] = (int)strtol(val, NULL, 0);
                    handled = 1; break;
                }
                snprintf(pk, sizeof(pk), "profile%d_mark", pi);
                if (!strcmp(key, pk)) {
                    c->profile_mark[pi - 1] = strtoul(val, NULL, 0);
                    handled = 1; break;
                }
            }
            if (handled)
                continue;
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
            c->fast_interval = parse_dur(val, U_SEC);
        else if (!strcmp(key, "soft_interval"))
            c->soft_interval = parse_dur(val, U_SEC);
        else if (!strcmp(key, "judge_interval"))
            c->judge_interval = parse_dur(val, U_SEC);
        else if (!strcmp(key, "health_interval"))
            c->health_interval = parse_dur(val, U_SEC);
        else if (!strcmp(key, "fast_syn_min_op"))
            c->fast_syn_min_op = (int)strtol(val, NULL, 0);
        else if (!strcmp(key, "ok_ttl"))
            c->ok_ttl = parse_dur(val, U_SEC);
        else if (!strcmp(key, "ok_refresh_below"))
            c->ok_refresh_below = parse_dur(val, U_HOUR);
        else if (!strcmp(key, "ok_max_entries"))
            c->ok_max_entries = (int)strtol(val, NULL, 0);
        else if (!strcmp(key, "ok_evict_misses"))
            c->ok_evict_misses = (int)strtol(val, NULL, 0);
        else if (!strcmp(key, "promo_per_min"))
            c->promo_per_min = (int)strtol(val, NULL, 0);
        else if (!strcmp(key, "test_ttl"))
            c->test_ttl = parse_dur(val, U_MIN);
        else if (!strcmp(key, "cooldown_ttl"))
            c->cooldown_ttl = parse_dur(val, U_MIN);
        else if (!strcmp(key, "cooldown_ok_ttl"))
            c->cooldown_ok_ttl = parse_dur(val, U_SEC);
        else if (!strcmp(key, "watch_ttl"))
            c->watch_ttl = parse_dur(val, U_SEC);
        else if (!strcmp(key, "watch_retry_below"))
            c->watch_retry_below = parse_dur(val, U_SEC);
        else if (!strcmp(key, "health_miss_debounce"))
            c->health_miss_debounce = (int)strtol(val, NULL, 0);
        else if (!strcmp(key, "health_mode"))
            set_str(c->health_mode, sizeof(c->health_mode), val);
        else if (!strcmp(key, "health_tcp_port"))
            c->health_tcp_port = (int)strtol(val, NULL, 0);
        else if (!strcmp(key, "health_probe"))
            set_str(c->health_probe, sizeof(c->health_probe), val);
        else if (!strcmp(key, "vpn_always_file"))
            set_str(c->vpn_always_file, sizeof(c->vpn_always_file), val);
        else if (!strcmp(key, "vpn_always_dns"))
            set_str(c->vpn_always_dns, sizeof(c->vpn_always_dns), val);
        else if (!strcmp(key, "vpn_always_interval"))
            c->vpn_always_interval = parse_dur(val, U_SEC);
        else if (!strcmp(key, "vpn_never_file"))
            set_str(c->vpn_never_file, sizeof(c->vpn_never_file), val);
        else if (!strcmp(key, "vpn_never_interval"))
            c->vpn_never_interval = parse_dur(val, U_SEC);
            else if (!strcmp(key, "log_level"))
                set_str(c->log_level, sizeof(c->log_level), val);
            else if (!strcmp(key, "xray_loglevel"))
                set_str(c->xray_loglevel, sizeof(c->xray_loglevel), val);
        else if (!strcmp(key, "disk_mode"))
            set_str(c->disk_mode, sizeof(c->disk_mode), val);
        else if (!strcmp(key, "soft_state_interval"))
            c->soft_state_interval = parse_dur(val, U_HOUR);
        else if (!strcmp(key, "learn_exclude_ports"))
            set_str(c->learn_exclude_ports, sizeof(c->learn_exclude_ports), val);
        else if (!strcmp(key, "discover_exclude"))
            set_str(c->discover_exclude, sizeof(c->discover_exclude), val);
        else if (!strcmp(key, "lan_server_interfaces"))
            set_str(c->lan_server_interfaces, sizeof(c->lan_server_interfaces), val);
        else if (!strcmp(key, "dp_check_interval"))
            c->dp_check_interval = parse_dur(val, U_SEC);
        else if (!strcmp(key, "learn_min_op"))
            c->learn_min_op = (int)strtol(val, NULL, 0);
        else if (!strcmp(key, "learn_min_bytes"))
            c->learn_min_bytes = (int)strtol(val, NULL, 0);
        else if (!strcmp(key, "confirm_min_bytes"))
            c->confirm_min_bytes = (int)strtol(val, NULL, 0);
        else if (!strcmp(key, "learn_strict"))
            c->learn_strict = (int)strtol(val, NULL, 0);
        else if (!strcmp(key, "cdn_ranges_file"))
            set_str(c->cdn_ranges_file, sizeof(c->cdn_ranges_file), val);
        else if (!strcmp(key, "cdn_ranges_url"))
            set_str(c->cdn_ranges_url, sizeof(c->cdn_ranges_url), val);
        else if (!strcmp(key, "cdn_ranges_interval"))
            c->cdn_ranges_interval = parse_dur(val, U_SEC);
        else if (!strcmp(key, "cdn_prefix_learn"))
            c->cdn_prefix_learn = (int)strtol(val, NULL, 0);
        else if (!strcmp(key, "cdn_prefix_ttl"))
            c->cdn_prefix_ttl = parse_dur(val, U_SEC);
        else if (!strcmp(key, "cdn_prefix_max"))
            c->cdn_prefix_max = (int)strtol(val, NULL, 0);
        else if (!strcmp(key, "ipv6_block"))
            c->ipv6_block = (int)strtol(val, NULL, 0);
        else if (!strcmp(key, "quic_block"))
            c->quic_block = (int)strtol(val, NULL, 0);
        else if (!strcmp(key, "egress_type"))
            set_str(c->egress_type, sizeof(c->egress_type), val);
        else if (!strcmp(key, "tproxy_port"))
            c->tproxy_port = (int)strtol(val, NULL, 0);
        else if (!strcmp(key, "udp_relay"))
            c->udp_relay = (int)strtol(val, NULL, 0);
        else if (!strcmp(key, "udp_relay_port"))
            c->udp_relay_port = (int)strtol(val, NULL, 0);
        else if (!strcmp(key, "socks_addr"))
            set_str(c->socks_addr, sizeof(c->socks_addr), val);
        else if (!strcmp(key, "socks_port"))
            c->socks_port = (int)strtol(val, NULL, 0);
        else if (!strcmp(key, "web_enable"))
            c->web_enable = (int)strtol(val, NULL, 0);
        else if (!strcmp(key, "web_listen"))
            set_str(c->web_listen, sizeof(c->web_listen), val);
        else if (!strcmp(key, "web_port"))
            c->web_port = (int)strtol(val, NULL, 0);
        else if (!strcmp(key, "web_token"))
            set_str(c->web_token, sizeof(c->web_token), val);
    }

    fclose(fp);
    {
        static const int def_tbl[CFG_MAX_PROFILES] = { 201, 202, 203, 204 };
        static const unsigned long def_mark[CFG_MAX_PROFILES] = {
            0x40000000UL, 0x08000000UL, 0x04000000UL, 0x02000000UL
        };
        int pi, n = 0;
        for (pi = 0; pi < CFG_MAX_PROFILES; pi++) {
            if (!c->profile_name[pi][0])
                continue;
            if (!c->profile_table[pi])
                c->profile_table[pi] = def_tbl[pi];
            if (!c->profile_mark[pi])
                c->profile_mark[pi] = def_mark[pi];
            n++;
        }
        c->n_profiles = n;
    }
    parse_egress(c);
    return 0;
}

int config_save(const char *path, const susanin_config *c)
{
    FILE *fp = fopen(path, "w");
    int i;
    if (!fp)
        return -1;
    fprintf(fp, "# Susanin.Keenetic configuration (generated)\n");
    fprintf(fp, "# Формат: key=value. Длительности — числом БЕЗ букв, в единицах,\n");
    fprintf(fp, "# указанных в описании параметра (сек / мин / ч).\n");

    fprintf(fp, "\n# Интерфейс(ы) туннеля (egress), через запятую; несколько включают фейловер.\n");
    fprintf(fp, "egress_interface=%s\n", c->egress_interface);
    fprintf(fp, "# Адрес(а) туннеля по индексу с интерфейсами (источник для health-проб).\n");
    fprintf(fp, "egress_address=%s\n", c->egress_address);
    fprintf(fp, "# LAN-интерфейсы (ingress), через запятую.\n");
    fprintf(fp, "lan_interfaces=%s\n", c->lan_interfaces);
    fprintf(fp, "# LAN-подсети (CIDR), через запятую.\n");
    fprintf(fp, "lan_subnets=%s\n", c->lan_subnets);
    fprintf(fp, "# Номер таблицы маршрутизации для VPN (небольшой; ограничение busybox ip).\n");
    fprintf(fp, "routing_table=%d\n", c->routing_table);
    fprintf(fp, "# fwmark «test»-фазы (hex, 32 бита).\n");
    fprintf(fp, "mark_test=0x%lx\n", c->mark_test);
    fprintf(fp, "# fwmark «ok»-фазы — подтверждено, идёт через VPN (hex).\n");
    fprintf(fp, "mark_ok=0x%lx\n", c->mark_ok);
    fprintf(fp, "# Маска fwmark для правил (hex).\n");
    fprintf(fp, "mark_mask=0x%lx\n", c->mark_mask);
    fprintf(fp, "# Стартовый приоритет ip rule.\n");
    fprintf(fp, "ip_rule_priority_start=%d\n", c->ip_rule_priority_start);
    fprintf(fp, "# Интервал «быстрой» фазы детекта, сек.\n");
    fprintf(fp, "fast_interval=%d\n", out_dur(c->fast_interval, U_SEC));
    fprintf(fp, "# Интервал «мягкой» фазы детекта (потоки с ответами), сек.\n");
    fprintf(fp, "soft_interval=%d\n", out_dur(c->soft_interval, U_SEC));
    fprintf(fp, "# Интервал фазы подтверждения (judge), сек.\n");
    fprintf(fp, "judge_interval=%d\n", out_dur(c->judge_interval, U_SEC));
    fprintf(fp, "# Интервал health-проб туннеля, сек.\n");
    fprintf(fp, "health_interval=%d\n", out_dur(c->health_interval, U_SEC));
    fprintf(fp, "# «Быстрый» детект: SYN без ответа до реакции (1 = быстрее, больше ложных).\n");
    fprintf(fp, "fast_syn_min_op=%d\n", c->fast_syn_min_op);
    fprintf(fp, "# TTL выученных ok-адресов, сек; 0 = никогда не истекает (наборы растут).\n");
    fprintf(fp, "ok_ttl=%d\n", out_dur(c->ok_ttl, U_SEC));
    fprintf(fp, "# Обновлять ok-адрес, если до истечения меньше заданного, ч.\n");
    fprintf(fp, "ok_refresh_below=%d\n", out_dur(c->ok_refresh_below, U_HOUR));
    fprintf(fp, "# Лимит записей ok-кэша на протокол; 0 = без лимита.\n");
    fprintf(fp, "ok_max_entries=%d\n", c->ok_max_entries);
    fprintf(fp, "# Сколько подряд сбоев по адресу нужно для снятия из ok.\n");
    fprintf(fp, "ok_evict_misses=%d\n", c->ok_evict_misses);
    fprintf(fp, "# Лимит новых переводов в VPN в минуту; 0 = без лимита.\n");
    fprintf(fp, "promo_per_min=%d\n", c->promo_per_min);
    fprintf(fp, "# TTL «test»-состояния (проба через VPN), мин.\n");
    fprintf(fp, "test_ttl=%d\n", out_dur(c->test_ttl, U_MIN));
    fprintf(fp, "# «Остывание» после снятия адреса из ok, мин.\n");
    fprintf(fp, "cooldown_ttl=%d\n", out_dur(c->cooldown_ttl, U_MIN));
    fprintf(fp, "# «Остывание» успешно подтверждённого адреса, сек.\n");
    fprintf(fp, "cooldown_ok_ttl=%d\n", out_dur(c->cooldown_ok_ttl, U_SEC));
    fprintf(fp, "# TTL «наблюдения» за подозрительным потоком, сек.\n");
    fprintf(fp, "watch_ttl=%d\n", out_dur(c->watch_ttl, U_SEC));
    fprintf(fp, "# Мин. время до повторной пробы «наблюдения», сек.\n");
    fprintf(fp, "watch_retry_below=%d\n", out_dur(c->watch_retry_below, U_SEC));
    fprintf(fp, "# Порог «туннель упал»: подряд неудачных health-проб.\n");
    fprintf(fp, "health_miss_debounce=%d\n", c->health_miss_debounce);
    fprintf(fp, "# Тип health-пробы: icmp | tcp (tcp — если egress не несёт ICMP: XRay/TUN).\n");
    fprintf(fp, "health_mode=%s\n", c->health_mode);
    fprintf(fp, "# Порт TCP-пробы (для health_mode=tcp).\n");
    fprintf(fp, "health_tcp_port=%d\n", c->health_tcp_port);
    fprintf(fp, "# Адреса health-проб через туннель, через запятую.\n");
    fprintf(fp, "health_probe=%s\n", c->health_probe);
    fprintf(fp, "# Файл списка «всегда через VPN».\n");
    fprintf(fp, "vpn_always_file=%s\n", c->vpn_always_file);
    fprintf(fp, "# Резолвер для списков; пусто = авто (роутер / LAN-мост).\n");
    fprintf(fp, "vpn_always_dns=%s\n", c->vpn_always_dns);
    fprintf(fp, "# Период обновления списка «всегда через VPN», сек.\n");
    fprintf(fp, "vpn_always_interval=%d\n", out_dur(c->vpn_always_interval, U_SEC));
    fprintf(fp, "# Файл списка «всегда напрямую».\n");
    fprintf(fp, "vpn_never_file=%s\n", c->vpn_never_file);
    fprintf(fp, "# Период обновления списка «всегда напрямую», сек.\n");
    fprintf(fp, "vpn_never_interval=%d\n", out_dur(c->vpn_never_interval, U_SEC));
    fprintf(fp, "# Уровень логов агента: quiet | error | warn | info | debug | trace.\n");
    fprintf(fp, "log_level=%s\n", c->log_level);
    fprintf(fp, "# Уровень логов Xray: debug | info | warning | none (читает xray-egress.sh).\n");
    fprintf(fp, "xray_loglevel=%s\n", c->xray_loglevel);
    fprintf(fp, "# Режим носителя: normal | soft (минимум записей на NAND/flash).\n");
    fprintf(fp, "disk_mode=%s\n", c->disk_mode);
    fprintf(fp, "# Период сохранения состояния в soft-режиме, ч; 0 = никогда.\n");
    fprintf(fp, "soft_state_interval=%d\n", out_dur(c->soft_state_interval, U_HOUR));
    fprintf(fp, "# Порты, исключённые из быстрого автообучения (скан-шум), через запятую.\n");
    fprintf(fp, "learn_exclude_ports=%s\n", c->learn_exclude_ports);
    fprintf(fp, "# Интерфейсы, которые НИКОГДА не берём как egress/LAN, через запятую.\n");
    fprintf(fp, "discover_exclude=%s\n", c->discover_exclude);
    fprintf(fp, "# Туннели-СЕРВЕРЫ, чьих клиентов тоже обрабатываем как LAN, через запятую.\n");
    fprintf(fp, "lan_server_interfaces=%s\n", c->lan_server_interfaces);
    fprintf(fp, "# Период сверки датаплейна (reconcile), сек; 0 = 15.\n");
    fprintf(fp, "dp_check_interval=%d\n", out_dur(c->dp_check_interval, U_SEC));
    fprintf(fp, "# L1: мин. пакетов к адресу для обучения.\n");
    fprintf(fp, "learn_min_op=%d\n", c->learn_min_op);
    fprintf(fp, "# L2: мин. байт «от нас» для обучения.\n");
    fprintf(fp, "learn_min_bytes=%d\n", c->learn_min_bytes);
    fprintf(fp, "# L4: мин. ответных байт для подтверждения.\n");
    fprintf(fp, "confirm_min_bytes=%d\n", c->confirm_min_bytes);
    fprintf(fp, "# Удвоить пороги обучения (строже): 0 | 1.\n");
    fprintf(fp, "learn_strict=%d\n", c->learn_strict);
    fprintf(fp, "# Файл диапазонов CDN (для агрегации по префиксу).\n");
    fprintf(fp, "cdn_ranges_file=%s\n", c->cdn_ranges_file);
    fprintf(fp, "# URL источника диапазонов CDN.\n");
    fprintf(fp, "cdn_ranges_url=%s\n", c->cdn_ranges_url);
    fprintf(fp, "# Период обновления диапазонов CDN, сек; 0 = не обновлять.\n");
    fprintf(fp, "cdn_ranges_interval=%d\n", out_dur(c->cdn_ranges_interval, U_SEC));
    fprintf(fp, "# Агрегация подтверждённого CDN-адреса по префиксу: 0 | 1.\n");
    fprintf(fp, "cdn_prefix_learn=%d\n", c->cdn_prefix_learn);
    fprintf(fp, "# TTL агрегированного CDN-префикса, сек.\n");
    fprintf(fp, "cdn_prefix_ttl=%d\n", out_dur(c->cdn_prefix_ttl, U_SEC));
    fprintf(fp, "# Не агрегировать шире этой маски (число бит).\n");
    fprintf(fp, "cdn_prefix_max=%d\n", c->cdn_prefix_max);
    fprintf(fp, "# Блокировать IPv6 из LAN (клиенты уходят на IPv4): 0 | 1.\n");
    fprintf(fp, "ipv6_block=%d\n", c->ipv6_block);
    fprintf(fp, "# Блокировать QUIC (UDP/443) из LAN: 0 | 1.\n");
    fprintf(fp, "quic_block=%d\n", c->quic_block);
    fprintf(fp, "# Встроенная веб-панель включена: 0 | 1.\n");
    fprintf(fp, "web_enable=%d\n", c->web_enable);
    fprintf(fp, "# Адрес веб-панели (LAN, не 0.0.0.0).\n");
    fprintf(fp, "web_listen=%s\n", c->web_listen);
    fprintf(fp, "# Порт веб-панели.\n");
    fprintf(fp, "web_port=%d\n", c->web_port);
    fprintf(fp, "# Токен доступа к веб-панели (пусто = без пароля).\n");
    fprintf(fp, "web_token=%s\n", c->web_token);
    fprintf(fp, "# Тип egress: interface (nwg*/wdtt*/tun*) | tproxy (XRay/REALITY).\n");
    fprintf(fp, "egress_type=%s\n", c->egress_type);
    fprintf(fp, "# Порт локального Xray (dokodemo-door redirect) для egress_type=tproxy.\n");
    fprintf(fp, "tproxy_port=%d\n", c->tproxy_port);
    fprintf(fp, "# UDP-релей (нужен только при egress_type=tproxy): 0 | 1.\n");
    fprintf(fp, "udp_relay=%d\n", c->udp_relay);
    fprintf(fp, "# Порт приёма UDP-релея (TPROXY).\n");
    fprintf(fp, "udp_relay_port=%d\n", c->udp_relay_port);
    fprintf(fp, "# Адрес Xray SOCKS (для UDP-релея).\n");
    fprintf(fp, "socks_addr=%s\n", c->socks_addr);
    fprintf(fp, "# Порт Xray SOCKS.\n");
    fprintf(fp, "socks_port=%d\n", c->socks_port);
    for (i = 0; i < CFG_MAX_PROFILES; i++) {
        if (!c->profile_name[i][0])
            continue;
        fprintf(fp, "# Профиль %d: имя (включает профиль), туннель, файл списка, таблица, fwmark.\n",
                i + 1);
        fprintf(fp, "profile%d_name=%s\n", i + 1, c->profile_name[i]);
        fprintf(fp, "profile%d_egress=%s\n", i + 1, c->profile_egress[i]);
        fprintf(fp, "profile%d_list=%s\n", i + 1, c->profile_list[i]);
        fprintf(fp, "profile%d_table=%d\n", i + 1, c->profile_table[i]);
        fprintf(fp, "profile%d_mark=0x%lx\n", i + 1, c->profile_mark[i]);
    }
    fclose(fp);
    return 0;
}

static int cfg_key_charset_ok(const char *k)
{
    if (!k || !*k)
        return 0;
    for (; *k; k++)
        if (!((*k >= 'a' && *k <= 'z') || (*k >= '0' && *k <= '9') || *k == '_'))
            return 0;
    return 1;
}

static int cfg_val_charset_ok(const char *v)
{
    if (!v)
        return 0;
    for (; *v; v++) {
        unsigned char c = (unsigned char)*v;
        if (c == '\n' || c == '\r' || c < 0x20 || c == 0x7f)
            return 0;
    }
    return 1;
}

int config_file_set(const char *path, const char *key, const char *val)
{
    FILE *in, *out;
    char line[1024], tmp[CFG_PATH_MAX + 8];
    size_t kl;
    int found = 0;

    if (!path || !key || !val)
        return -1;
    if (!cfg_key_charset_ok(key) || !cfg_val_charset_ok(val))
        return -1;

    in = fopen(path, "r");
    if (!in)
        return -1;
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    out = fopen(tmp, "w");
    if (!out) {
        fclose(in);
        return -1;
    }
    kl = strlen(key);
    while (fgets(line, sizeof(line), in)) {
        if (!strncmp(line, key, kl) && line[kl] == '=') {
            fprintf(out, "%s=%s\n", key, val);
            found = 1;
        } else {
            fputs(line, out);
        }
    }
    fclose(in);
    if (fclose(out) != 0) {
        remove(tmp);
        return -1;
    }
    /* Обновляем только существующий ключ: новых ключей через web не создаём. */
    if (!found) {
        remove(tmp);
        return -1;
    }
    if (rename(tmp, path) != 0) {
        remove(tmp);
        return -1;
    }
    return 0;
}

void config_print(const susanin_config *c)
{
    int i;
    printf("egress_interface=%s\n", c->egress_interface);
    printf("egress_address=%s\n", c->egress_address);
    printf("lan_interfaces=%s\n", c->lan_interfaces);
    printf("lan_subnets=%s\n", c->lan_subnets);
    printf("routing_table=%d\n", c->routing_table);
    printf("mark_test=0x%lx\n", c->mark_test);
    printf("mark_ok=0x%lx\n", c->mark_ok);
    printf("mark_mask=0x%lx\n", c->mark_mask);
    printf("ip_rule_priority_start=%d\n", c->ip_rule_priority_start);
    printf("fast_interval=%d\n", out_dur(c->fast_interval, U_SEC));
    printf("soft_interval=%d\n", out_dur(c->soft_interval, U_SEC));
    printf("judge_interval=%d\n", out_dur(c->judge_interval, U_SEC));
    printf("health_interval=%d\n", out_dur(c->health_interval, U_SEC));
    printf("fast_syn_min_op=%d\n", c->fast_syn_min_op);
    printf("ok_ttl=%d\n", out_dur(c->ok_ttl, U_SEC));
    printf("ok_refresh_below=%d\n", out_dur(c->ok_refresh_below, U_HOUR));
    printf("ok_max_entries=%d\n", c->ok_max_entries);
    printf("ok_evict_misses=%d\n", c->ok_evict_misses);
    printf("promo_per_min=%d\n", c->promo_per_min);
    printf("test_ttl=%d\n", out_dur(c->test_ttl, U_MIN));
    printf("cooldown_ttl=%d\n", out_dur(c->cooldown_ttl, U_MIN));
    printf("cooldown_ok_ttl=%d\n", out_dur(c->cooldown_ok_ttl, U_SEC));
    printf("watch_ttl=%d\n", out_dur(c->watch_ttl, U_SEC));
    printf("watch_retry_below=%d\n", out_dur(c->watch_retry_below, U_SEC));
    printf("health_miss_debounce=%d\n", c->health_miss_debounce);
    printf("health_mode=%s\n", c->health_mode);
    printf("health_tcp_port=%d\n", c->health_tcp_port);
    printf("health_probe=%s\n", c->health_probe);
    printf("vpn_always_file=%s\n", c->vpn_always_file);
    printf("vpn_always_dns=%s\n", c->vpn_always_dns);
    printf("vpn_always_interval=%d\n", out_dur(c->vpn_always_interval, U_SEC));
    printf("vpn_never_file=%s\n", c->vpn_never_file);
    printf("vpn_never_interval=%d\n", out_dur(c->vpn_never_interval, U_SEC));
    printf("log_level=%s\n", c->log_level);
    printf("xray_loglevel=%s\n", c->xray_loglevel);
    printf("disk_mode=%s\n", c->disk_mode);
    printf("soft_state_interval=%d\n", out_dur(c->soft_state_interval, U_HOUR));
    printf("learn_exclude_ports=%s\n", c->learn_exclude_ports);
    printf("discover_exclude=%s\n", c->discover_exclude);
    printf("lan_server_interfaces=%s\n", c->lan_server_interfaces);
    printf("dp_check_interval=%d\n", out_dur(c->dp_check_interval, U_SEC));
    printf("learn_min_op=%d\n", c->learn_min_op);
    printf("learn_min_bytes=%d\n", c->learn_min_bytes);
    printf("confirm_min_bytes=%d\n", c->confirm_min_bytes);
    printf("learn_strict=%d\n", c->learn_strict);
    printf("cdn_ranges_file=%s\n", c->cdn_ranges_file);
    printf("cdn_ranges_url=%s\n", c->cdn_ranges_url);
    printf("cdn_ranges_interval=%d\n", out_dur(c->cdn_ranges_interval, U_SEC));
    printf("cdn_prefix_learn=%d\n", c->cdn_prefix_learn);
    printf("cdn_prefix_ttl=%d\n", out_dur(c->cdn_prefix_ttl, U_SEC));
    printf("cdn_prefix_max=%d\n", c->cdn_prefix_max);
    printf("ipv6_block=%d\n", c->ipv6_block);
    printf("quic_block=%d\n", c->quic_block);
    printf("web_enable=%d\n", c->web_enable);
    printf("web_listen=%s\n", c->web_listen);
    printf("web_port=%d\n", c->web_port);
    printf("web_token=%s\n", c->web_token);
    printf("egress_type=%s\n", c->egress_type);
    printf("tproxy_port=%d\n", c->tproxy_port);
    printf("udp_relay=%d\n", c->udp_relay);
    printf("udp_relay_port=%d\n", c->udp_relay_port);
    printf("socks_addr=%s\n", c->socks_addr);
    printf("socks_port=%d\n", c->socks_port);
    for (i = 0; i < CFG_MAX_PROFILES; i++) {
        if (!c->profile_name[i][0])
            continue;
        printf("profile%d_name=%s\n", i + 1, c->profile_name[i]);
        printf("profile%d_egress=%s\n", i + 1, c->profile_egress[i]);
        printf("profile%d_list=%s\n", i + 1, c->profile_list[i]);
        printf("profile%d_table=%d\n", i + 1, c->profile_table[i]);
        printf("profile%d_mark=0x%lx\n", i + 1, c->profile_mark[i]);
    }
}
