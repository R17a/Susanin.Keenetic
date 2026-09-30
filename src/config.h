#ifndef SUSANIN_CONFIG_H
#define SUSANIN_CONFIG_H

#define CFG_MAX_LAN 8
#define CFG_PATH_MAX 256
#define CFG_MAX_EGRESS 4
#define CFG_MAX_PROFILES 4

typedef struct {
    char egress_interface[CFG_PATH_MAX];
    char egress_address[64];
    /* Parsed egress lists (comma-separated config, aligned by index).
     * egress_list[i] — interface, egress_addr[i] — its tunnel address. */
    char egress_list[CFG_MAX_EGRESS][64];
    char egress_addr[CFG_MAX_EGRESS][64];
    int n_egress;
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
    int ok_evict_misses;    /* сколько подряд «сбоев» до снятия из ok (гистерезис) */
    int promo_per_min;      /* лимит новых «проб» (перевод в VPN) в минуту; 0=без лимита */
    int ok_max_entries;     /* bounded GC: per-proto ok-cache limit (0=off) */
    int test_ttl;
    int cooldown_ttl;
    int cooldown_ok_ttl;
    int watch_ttl;
    int watch_retry_below;
    int health_miss_debounce;
    /* Health-проба туннеля: icmp (по умолчанию) | tcp. TCP нужен для egress,
     * которые не переносят ICMP (VLESS/XRay-туннель через TUN). */
    char health_mode[8];
    int health_tcp_port;    /* порт TCP-пробы (по умолчанию 443) */
    char health_probe[CFG_PATH_MAX];
    char vpn_always_file[CFG_PATH_MAX];
    char vpn_always_dns[CFG_PATH_MAX];
    int vpn_always_interval;
    char vpn_never_file[CFG_PATH_MAX];
    int vpn_never_interval;
    char log_level[16];
    char xray_loglevel[16]; /* уровень логов Xray (читает xray-egress.sh, не сам агент) */
    char disk_mode[8];      /* normal | soft: soft = минимум записей на диск */
    int soft_state_interval; /* soft: как часто сохранять состояние (сек; 0=никогда) */
    char learn_exclude_ports[CFG_PATH_MAX]; /* порты, которые не учим (скан-шум) */
    /* Интерфейсы, которые НИКОГДА не берём как egress/LAN (серверные туннели:
     * qWDTT wdtt0/wdttraw0, TUN/TAP и т.п.). Список через запятую. */
    char discover_exclude[CFG_PATH_MAX];
    /* Серверные туннели (qWDTT wdtt0/wdttraw0 и т.п.), которые, наоборот, нужно
     * обрабатывать как LAN: их клиенты должны идти через Susanin (интерфейс +
     * его IPv4-сеть добавляются к lan_interfaces/lan_subnets при discover). */
    char lan_server_interfaces[CFG_PATH_MAX];
    /* Период сверки датаплейна (reconcile), сек. Меньше — быстрее заметим снос
     * правил NDM; для tproxy это и есть «частая проверка правил». 0 = 15 c. */
    int dp_check_interval;
    /* L1–L6: пороги автообучения (защита от ложных заворотов). */
    int learn_min_op;        /* минимум пакетов к адресу до обучения (FAST/SOFT) */
    int learn_min_bytes;     /* минимум байт «от нас» до обучения */
    int confirm_min_bytes;   /* минимум ответных байт для judge->good */
    int learn_strict;        /* 1 = ещё строже (умножает пороги) */
    /* CDN-универсал (C1/C2): диапазоны CDN и агрегация по префиксу. */
    char cdn_ranges_file[CFG_PATH_MAX];
    char cdn_ranges_url[CFG_PATH_MAX];
    int cdn_ranges_interval; /* период авто-обновления, сек (0 = не обновлять) */
    int cdn_prefix_learn;    /* 1 = при CONFIRMED агрегировать префикс CDN в ok_net */
    int cdn_prefix_ttl;      /* TTL агрегированного префикса, сек */
    int cdn_prefix_max;      /* максимальная длина префикса для агрегации (напр. 24) */
    /* C3: политика IPv6 — 1 = блокировать IPv6 из LAN, чтобы весь трафик шёл
     * по IPv4 (иначе IPv6-трафик идёт мимо Susanin и может душиться). */
    int ipv6_block;
    /* QUIC (UDP 443): 1 = запретить из LAN, чтобы приложения шли по TCP.
     * UDP-релей для QUIC ненадёжен (крупные датаграммы/MTU), а TCP через
     * туннель работает стабильно; заодно уходит «зависание» на ожидании QUIC. */
    int quic_block;
    /* Встроенная веб-панель (мини-HTTP в самом агенте, режим `web`).
     * По умолчанию выключена. Слушает ТОЛЬКО LAN-адрес (не 0.0.0.0). */
    int web_enable;
    char web_listen[64];    /* LAN-адрес, напр. 192.168.1.1 */
    int web_port;
    char web_token[64];     /* токен; пусто = вход без пароля (только LAN) */
    /* Тип egress: interface (nwg/wdtt/tun) | tproxy | xray (перспектива).
     * Для R1 информативно + задел под XRay-egress (R2). */
    char egress_type[16];
    /* Для egress_type=tproxy: порт локального Xray (dokodemo-door, tproxy). */
    int tproxy_port;
    /* UDP-релей в демоне (egress через XRay): TPROXY-приём UDP + SOCKS5 UDP
     * ASSOCIATE к локальному Xray-socks. По умолчанию выключен. */
    int udp_relay;
    int udp_relay_port;
    char socks_addr[64];
    int socks_port;
    /* Профили маршрутизации (P1): статический список -> свой туннель.
     * Задаются повторяющимися ключами profileN_name/_egress/_list/_table/_mark
     * (N = 1..CFG_MAX_PROFILES). Нет ни одного profileN_name — профилей нет,
     * поведение как раньше. */
    int n_profiles;
    char profile_name[CFG_MAX_PROFILES][32];
    char profile_egress[CFG_MAX_PROFILES][64];
    char profile_list[CFG_MAX_PROFILES][CFG_PATH_MAX];
    int profile_table[CFG_MAX_PROFILES];
    unsigned long profile_mark[CFG_MAX_PROFILES];
} susanin_config;

void config_set_defaults(susanin_config *c);
int config_load(const char *path, susanin_config *c);
int config_save(const char *path, const susanin_config *c);
void config_print(const susanin_config *c);

/* Точечно обновить ОДИН существующий ключ в файле конфига (не создаёт новых
 * ключей): комментарии и остальные строки сохраняются, запись атомарная
 * (tmp+rename). Возврат 0 — ок; -1 — нет ключа/плохое значение/ошибка. */
int config_file_set(const char *path, const char *key, const char *val, int allow_create);

#endif
