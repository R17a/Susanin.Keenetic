#define _GNU_SOURCE
#include "config.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Единицы длительностей (в секундах). У каждого временного параметра своя
 * единица; в файле значение пишется числом БЕЗ суффикса, а единица указана
 * в описании параметра. */
#define U_SEC   1
#define U_MIN   60
#define U_HOUR  3600

/* Разбор длительности. Голое число трактуется в единицах параметра (unit —
 * сколько секунд в единице). Суффиксы s/m/h/d/w поддержаны для совместимости
 * со старыми конфигами (напр. cooldown_ttl=5m).
 *
 * Умножение — в long long с ограничением: `(int)(v * 604800)` на большом v
 * давало wrap-around вплоть до отрицательного значения, а для TTL отрицательный
 * путь кончается «не истекает». */
static int parse_dur(const char *s, int unit, int *overflow)
{
    char *end = NULL;
    long v;
    long long mul = unit;

    if (overflow)
        *overflow = 0;
    if (!s)
        return 0;
    errno = 0;
    v = strtol(s, &end, 10);
    if (end == s || v < 0)
        return 0;
    if (errno == ERANGE) {
        /* На 32-битном MIPS long==int: «99999999999» даёт LONG_MAX без v<0, и без
         * этой проверки переполнение зависело бы от разрядности сборки. */
        if (overflow)
            *overflow = 1;
        return 2147483647;
    }
    if (end && *end) {
        if (*end == 's') mul = 1;
        else if (*end == 'm') mul = 60;
        else if (*end == 'h') mul = 3600;
        else if (*end == 'd') mul = 86400;
        else if (*end == 'w') mul = 604800;
        else return 0;            /* суффикс не из нашего набора */
    }
    {
        long long r = (long long)v * mul;
        if (r > 2147483647LL) {
            if (overflow)
                *overflow = 1;
            r = 2147483647LL;
        }
        return (int)r;
    }
}

/* Обратное преобразование: секунды -> значение в единицах параметра. */
static int out_dur(int secs, int unit)
{
    if (unit <= 0)
        unit = 1;
    return secs / unit;
}

/* Точная запись длительности — в единице параметра, а если значение ей не
 * делится целочно, то суффиксом (parse_dur понимает s/m/h/d/w).
 *
 * Нужен потому, что целочисленное out_dur() на «test_ttl=45s» выдавал 0,
 * а 0 для TTL в state.c означает «не истекает»: одно сохранение конфига
 * молча превращало полторы минуты в бессрочность. Нуль сохраняем нулём —
 * иначе не выразить явный «0 = выключено» там, где он документирован. */
static void out_dur_exact(int secs, int unit, char *out, size_t n)
{
    if (secs <= 0) {
        snprintf(out, n, "0");
        return;
    }
    if (unit <= 1 || secs % unit == 0) {
        snprintf(out, n, "%d", secs / unit);
        return;
    }
    snprintf(out, n, "%ds", secs);
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

/* egress_interface/egress_address — списки через запятую (фейловер).
 * Значения выравниваются по индексу; один адрес допустим на все интерфейсы.
 * Не static: нужен и из ops_setup после смены ключа. */
void config_parse_egress(susanin_config *c)
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
    c->udp_min_op = 3;
    /* Улика гибели прямого пути (см. sf_note): 3 разных соединения на один
     * dst:port за 120 с -> заворачиваем в test без прямой пробы. 0 = выключить. */
    c->synfail_quorum = 3;
    c->synfail_window = 120;
    c->ok_ttl = 6 * 3600;
    c->ok_refresh_below = 3 * 3600;
    c->ok_max_entries = 4096;
    c->ok_evict_misses = 3;
    c->promo_per_min = 120;
    c->test_ttl = 60;
    c->cooldown_ttl = 5 * 60;
    c->ipset_batch = 1;
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
    c->vpn_refresh_budget_ms = 250;
    snprintf(c->log_level, sizeof(c->log_level), "%s", "info");
    snprintf(c->xray_loglevel, sizeof(c->xray_loglevel), "%s", "warning");
    snprintf(c->xray_gogc, sizeof(c->xray_gogc), "%s", "50");
    snprintf(c->xray_gomemlimit, sizeof(c->xray_gomemlimit), "%s", "64MiB");
    c->xray_watchdog = 1;
    /* Порог свободной памяти для запуска Xray (КБ): ниже порога старт
     * пропускается (защита от OOM-петли). По умолчанию 0 = ВЫКЛЮЧЕНО:
     * активный порог 12288 в 0.4.6 на 122 МБ роутере почти всегда блокировал
     * подъём Xray после падения (долгий fail-open DIRECT, «сайты грузятся
     * медленно»). Включать осознанно, напр. xray_min_mem_kb=6144. */
    c->xray_min_mem_kb = 0;
    /* Лог Xray перед запуском обрезаем до 2 МБ: при loglevel=debug он растёт
     * на мегабайты, а в tmpfs это отнятая у системы память. */
    c->xray_log_max_kb = 2048;
    snprintf(c->disk_mode, sizeof(c->disk_mode), "%s", "normal");
    c->soft_state_interval = 12 * 3600;   /* soft: сохранять состояние раз в 12 ч */
    /* Порты, которые не участвуют в автообучении (типовой скан-шум). */
    snprintf(c->learn_exclude_ports, sizeof(c->learn_exclude_ports), "%s",
             "22,23,53,135,137,138,139,445,500,554,853,1433,1723,3306,3389,4500,5432,5900,6379,7547,8567,9100,11211,27017");
    snprintf(c->discover_exclude, sizeof(c->discover_exclude), "%s",
             "wdtt0,wdttraw0,tun0,tap0");
    snprintf(c->lan_server_interfaces, sizeof(c->lan_server_interfaces), "%s", "");
    c->dp_check_interval = 15;
    c->learn_min_op = 10;
    c->learn_min_bytes = 2000;
    c->confirm_min_bytes = 512;
    c->learn_strict = 0;
    /* Пресет порогов не задан: значения — как выше (поведение не меняется). */
    snprintf(c->precision, sizeof(c->precision), "%s", "");
    /* Port-aware identity: по умолчанию выключено (поведение не меняется). */
    c->port_aware = 0;
    snprintf(c->cdn_ranges_file, sizeof(c->cdn_ranges_file), "%s",
             "/opt/susanin/etc/cdn_ranges.txt");
    snprintf(c->cdn_ranges_url, sizeof(c->cdn_ranges_url), "%s",
             "https://www.cloudflare.com/ips-v4");
    c->cdn_ranges_interval = 86400;
    c->cdn_prefix_learn = 1;
    c->cdn_prefix_ttl = 3600;
    c->aggregate_confirm = 2;
    c->frozen_net_enabled = 1;
    c->frozen_net_min_ips = 3;
    c->frozen_net_prefix = 24;
    c->frozen_net_ttl = 86400;
    c->test_net_enabled = 1;
    c->test_net_min_ips = 2;
    c->test_net_prefix = 24;
    c->test_net_window = 60;
    c->test_net_ttl = 600;
    c->ru_guard = 1;
    c->ru_guard_direct = 1;
    snprintf(c->ru_guard_tlds, sizeof(c->ru_guard_tlds), "%s",
             ".ru,.su,.рф,.xn--p1ai,.moscow,.xn--80adxhks,.tatar,.xn--80asehdb");
    c->tz[0] = '\0';
    c->cdn_prefix_max = 24;
    c->ipv6_block = 1;
    c->quic_block = 1;
    snprintf(c->mss_clamp, sizeof(c->mss_clamp), "%s", "0");
    c->mss_clamp_lan = 0;
    /* Встроенная веб-панель: по умолчанию выключена, адрес не задан. */
    c->web_enable = 0;
    snprintf(c->web_listen, sizeof(c->web_listen), "%s", "");
    c->web_port = 8087;
    snprintf(c->web_token, sizeof(c->web_token), "%s", "");
    /* W6: индикатор нового релиза в панели; GitHub опрашивается раз в 12 ч. */
    c->release_check = 1;
    c->release_check_interval = 43200;
    snprintf(c->egress_type, sizeof(c->egress_type), "%s", "interface");
    c->tproxy_port = 12345;
    c->udp_relay = 0;
    c->udp_relay_port = 1081;
    snprintf(c->socks_addr, sizeof(c->socks_addr), "%s", "127.0.0.1");
    c->socks_port = 1080;
    c->egress_failback = 1;
    c->egress_failback_debounce = 30;
    c->dns_sniff = 0;
    c->dns_sniff_ttl = 300;
    c->dns_hijack = 0;
    c->vpn_always_cdn_prefix = 0;
    c->pin_reassert = 1;
    c->kernel_offload = 0;
    c->kernel_offload_max = 24;
    /* P5: proxy_uid/proxy_egress по умолчанию выключены. */
    c->proxy_uid[0] = '\0';
    c->proxy_egress[0] = '\0';
    c->proxy_table = CFG_DEF_PROXY_TABLE;
    c->proxy_mark = CFG_DEF_PROXY_MARK;
    c->egress_race = 0;
    c->auto_direct = 1;
    c->direct_pref_ttl = 3600;
    c->media_enabled = 0;
    /* Медиа-порты по умолчанию — только видео/IPTV. 80/443 убраны: обычная
     * загрузка страницы под них подпадала, и два адреса уводили в VPN всю /24
     * хостинга. Кому нужно — задаёт явно. */
    snprintf(c->media_ports, sizeof(c->media_ports), "%s",
             "554,1935,8000,8001,8080,8443");
    c->media_min_bytes = 1048576;
    c->media_ratio = 8;
    c->media_min_rate = 150000;
    c->media_min_age = 12;
    c->media_ttl = 21600;
    c->media_prefix_max = 24;
    c->profile_failover = 1;
    c->n_profiles = 0;
    config_parse_egress(c);
}

static void set_str(char *dst, size_t n, const char *v)
{
    snprintf(dst, n, "%s", v ? v : "");
}

/* «Профили точности» (precision): пресет порогов автообучения. Значение пресета
 * применяется к полям, которых НЕТ в конфиге явно (см. биты PREC_* в config_load),
 * поэтому ключи в susanin.conf всегда сильнее. При config_save/config_print
 * пресет не «разворачивается» — в файл пишется только сам ключ precision. */
enum {
    PREC_FAST_SYN = 1,      /* fast_syn_min_op */
    PREC_EVICT = 2,         /* ok_evict_misses */
    PREC_LEARN_OP = 4,      /* learn_min_op */
    PREC_LEARN_BYTES = 8,   /* learn_min_bytes */
    PREC_CONFIRM = 16,      /* confirm_min_bytes */
    PREC_STRICT = 32        /* learn_strict */
};

/* Значение пресета известно? (strict | normal | aggressive | пусто) */
static int precision_known(const char *p)
{
    return !p[0] || !strcmp(p, "normal") || !strcmp(p, "strict") ||
           !strcmp(p, "aggressive");
}

static void apply_precision(susanin_config *c, unsigned seen)
{
    const char *p = c->precision;
    if (!p[0] || !strcmp(p, "normal"))
        return;
    if (!strcmp(p, "strict")) {
        if (!(seen & PREC_FAST_SYN))    c->fast_syn_min_op = 3;
        if (!(seen & PREC_EVICT))       c->ok_evict_misses = 5;
        if (!(seen & PREC_LEARN_OP))    c->learn_min_op = 14;
        if (!(seen & PREC_LEARN_BYTES)) c->learn_min_bytes = 3000;
        if (!(seen & PREC_CONFIRM))     c->confirm_min_bytes = 1024;
    } else if (!strcmp(p, "aggressive")) {
        if (!(seen & PREC_FAST_SYN))    c->fast_syn_min_op = 1;
        if (!(seen & PREC_EVICT))       c->ok_evict_misses = 2;
        if (!(seen & PREC_LEARN_OP))    c->learn_min_op = 8;
        if (!(seen & PREC_LEARN_BYTES)) c->learn_min_bytes = 1500;
        if (!(seen & PREC_CONFIRM))     c->confirm_min_bytes = 256;
    } else {
        /* Опечатка вроде precision=strong раньше молча ничего не делала:
         * теперь это видно и в stderr (уходит в лог), и в `config show`. */
        fprintf(stderr, "warning: unknown precision '%s' "
                        "(expected strict|normal|aggressive) — ignored\n", p);
    }
}

/* Разбор строки конфига на имя ключа и начало значения — ЕДИНЫЙ для чтения
 * (config_load), проверки наличия (cfg_line_key -> config_sync) и записи
 * (config_file_set). Пока три места делали это по-своему, «key = value»
 * терялся молча: load считал именем «key » (с пробелом) и ключ не узнавал,
 * sync считал его присутствующим и дефолт не дописывал, а set дописывал
 * вторую строку с тем же ключом — и кто победит, зависело от того, кто
 * читает: C берёт последнюю строку, datapath.sh — первую.
 * 0 = строка — ключ; *val указывает на значение (обрезать перевод строки
 * нужно вызывающему); комментарии и пустые строки дают -1. */
int config_line_split(const char *line, char *key, size_t kn, char **val)
{
    char *p = (char *)line;
    size_t i = 0;

    while (*p == ' ' || *p == '\t')
        p++;
    if (*p == '\0' || *p == '\n' || *p == '\r' || *p == '#')
        return -1;
    while (*p && *p != '=' && *p != ' ' && *p != '\t' && *p != '\n' &&
           *p != '\r' && i + 1 < kn) {
        char ch = *p++;
        if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_'))
            return -1;
        key[i++] = ch;
    }
    while (*p == ' ' || *p == '\t')
        p++;
    if (i == 0 || *p != '=')
        return -1;
    key[i] = '\0';
    p++;
    while (*p == ' ' || *p == '\t')
        p++;
    if (val)
        *val = p;
    return 0;
}

/* Запомнить имя ключа в ограниченный список: дедупликация по удержанным, за
 * границу не ходим никогда (прежняя версия именно так и читала чужую память),
 * а непоместившиеся считаются в отдельном счётчике, чтобы потерю было видно. */
static void cfg_note_name(char tab[][48], int *held, int *dropped, const char *key)
{
    int i;

    for (i = 0; i < *held; i++)
        if (!strcmp(tab[i], key))
            return;                       /* уже запомнено */
    if (*held < CFG_MAX_BAD_VALUES) {
        snprintf(tab[*held], 48, "%.47s", key);
        (*held)++;
    } else {
        (*dropped)++;
    }
}

/* Ключ со значением, которое разбор не принял: опечатка «interval=-5» и
 * осознанный «interval=0» иначе неразличимы — parse_dur() приводит минус к 0,
 * а для многих ключей 0 — законный сенсор. */
static void cfg_note_bad_value(susanin_config *c, const char *key)
{
    cfg_note_name(c->bad_values, &c->n_bad_values, &c->n_bad_dropped, key);
}

/* Ключ, которого агент не знает вовсе: строка вида «foris_ra=1» или опечатка
 * «ok_tll=6h» молча игнорируется, и до этой правки единственный способ её
 * заметить был — глазами сравнить файл со списком параметров. */
static void cfg_note_unknown_key(susanin_config *c, const char *key)
{
    cfg_note_name(c->unknown_keys, &c->n_unknown_keys, &c->n_unknown_dropped,
                  key);
}

/* Числовая форма значения. Проверяется ДО разбора, потому что прежний
 * `strtol(val, NULL, 0)` имел две неприятности:
 *   - «abc» превращалось в 0 молча, а 0 для немалого числа ключей — законный
 *     сенсор: опечатка становилась настройкой («ok_ttl=abc» = «не истекает»);
 *   - база 0 трактовала «0100» как восьмеричное 64 — в конфиге этого никто не
 *     ожидает.
 * Здесь: ведущий минус (регистрируется как отклонённое), явный префикс 0x,
 * иначе — только десятичные цифры, и хвост из букв не игнорируется, а
 * помечается. */
static int cfg_num_shape(susanin_config *c, const char *key, const char *val)
{
    const char *p = val;

    if (!*p)
        return 1;                       /* пусто = значение по умолчанию */
    if (*p == '-' || *p == '+') {
        cfg_note_bad_value(c, key);
        return 0;
    }
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        /* Шестнадцатеричная форма легальна и используется (маски fwmark,
         * метки профилей): прежняя проверка принимала только цифры и тем самым
         * объявляла «mark_mask=0xffff0000» мусором, обнуляя маску меток. */
        p += 2;
        if (!*p) {
            cfg_note_bad_value(c, key);     /* одинокий «0x» */
            return 0;
        }
        while ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') ||
               (*p >= 'A' && *p <= 'F'))
            p++;
    } else {
        if (!*p) {
            cfg_note_bad_value(c, key);
            return 0;
        }
        while (*p >= '0' && *p <= '9')
            p++;
    }
    if (*p)
        cfg_note_bad_value(c, key);     /* «5x», «12 сек» — прежний разбор молча
                                         * резал хвост и возвращал 5 и 12 */
    return !*p ? 1 : 0;
}

/* Длительность: то же, но суффикс s/m/h/d/w легален (он и раньше понимался). */
static int cfg_dur_shape(susanin_config *c, const char *key, const char *val)
{
    const char *p = val;

    if (!*p)
        return 1;
    if (*p == '-' || *p == '+') {
        cfg_note_bad_value(c, key);
        return 0;
    }
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        /* Для длительности шестнадцатеричной формы не существует: parse_dur
         * читает десятичное число и на «0x10» вернул бы 0, что означает
         * «не истекает». Молчать об этом нельзя. */
        cfg_note_bad_value(c, key);
        return 0;
    }
    if (!*p) {
        cfg_note_bad_value(c, key);
        return 0;
    }
    while (*p >= '0' && *p <= '9')
        p++;
    if (*p) {
        if (!(p[1] == '\0' && strchr("smhdw", *p)))
            cfg_note_bad_value(c, key);   /* «5хв», «10ms» и т.п. */
        else
            return 1;
    }
    return !*p ? 1 : 0;
}

static long cfg_num(susanin_config *c, const char *key, const char *val)
{
    char *end = NULL;
    long v;

    if (!cfg_num_shape(c, key, val))
        return 0;
    errno = 0;
    /* База по форме, а не 0: «0100» обязано означать 100. */
    v = strtol(val, &end,
               (val[0] == '0' && (val[1] == 'x' || val[1] == 'X')) ? 16 : 10);
    if (end == val)
        return 0;
    /* Поля конфига — int; значение вне диапазона дало бы wrap-around вплоть до
     * отрицательного, то есть ровно ту семантику, которую проверка конфига и
     * обещает не допускать. На 32-битном MIPS переполнение выглядит как
     * LONG_MAX, поэтому проверяем и ERANGE, а не только границы. */
    if (errno == ERANGE || v > 2147483647L || v < -2147483648L) {
        cfg_note_bad_value(c, key);
        return 0;
    }
    return v;
}

static unsigned long cfg_unum(susanin_config *c, const char *key, const char *val)
{
    char *end = NULL;
    unsigned long v;

    if (!cfg_num_shape(c, key, val))
        return 0;
    errno = 0;
    v = strtoul(val, &end,
                (val[0] == '0' && (val[1] == 'x' || val[1] == 'X')) ? 16 : 10);
    if (end == val)
        return 0;
    /* Переполнение: strtoul возвращает ULONG_MAX и ставит ERANGE. Для маски
     * fwmark значение «примерно бесконечность» хуже нуля, поэтому помечаем.
     * Дополнительно ограничиваем 32 битами: fwmark в Linux — u32, и на
     * 64-битной машине ERANGE не сработал бы вовсе (значение влезает в
     * unsigned long), тогда как на MIPS сработал — проверка не должна зависеть
     * от разрядности сборки. */
    if (errno == ERANGE || v > 0xffffffffUL) {
        cfg_note_bad_value(c, key);
        return 0;
    }
    return v;
}

static int cfg_dur(susanin_config *c, const char *key, const char *val, int unit)
{
    int ovf = 0, v;

    if (!cfg_dur_shape(c, key, val))
        return 0;
    v = parse_dur(val, unit, &ovf);
    if (ovf)
        cfg_note_bad_value(c, key);   /* значение заведомо больше любого TTL */
    return v;
}

int config_load(const char *path, susanin_config *c)
{
    FILE *fp;
    char line[512];
    unsigned seen = 0;      /* какие ключи группы порогов были в файле явно */

    config_set_defaults(c);
    if (!path)
        return 0;
    fp = fopen(path, "r");
    if (!fp)
        return -1;

    while (fgets(line, sizeof(line), fp)) {
        char key[64];
        char *val;

        if (config_line_split(line, key, sizeof(key), &val) != 0)
            continue;
        {
            char *q = val;
            while (*q && *q != '\n') q++;
            *q = '\0';
            while (q > val && (q[-1] == ' ' || q[-1] == '\t' || q[-1] == '\r'))
                *--q = '\0';
        }

        /* Отрицательное и неразобранное значение фиксирует сам разбор числа
         * (cfg_num_shape / cfg_dur_shape): отдельная проверка здесь раньше
         * удваивала запись для ключей, не попавших в удержанный список. */

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
                snprintf(pk, sizeof(pk), "profile%d_geo_url", pi);
                if (!strcmp(key, pk)) {
                    set_str(c->profile_geo_url[pi - 1], sizeof(c->profile_geo_url[pi - 1]), val);
                    handled = 1; break;
                }
                snprintf(pk, sizeof(pk), "profile%d_auto", pi);
                if (!strcmp(key, pk)) {
                    c->profile_auto[pi - 1] = (int)cfg_num(c, key, val);
                    handled = 1; break;
                }
                snprintf(pk, sizeof(pk), "profile%d_table", pi);
                if (!strcmp(key, pk)) {
                    c->profile_table[pi - 1] = (int)cfg_num(c, key, val);
                    handled = 1; break;
                }
                snprintf(pk, sizeof(pk), "profile%d_mark", pi);
                if (!strcmp(key, pk)) {
                    c->profile_mark[pi - 1] = cfg_unum(c, key, val);
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
            c->routing_table = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "mark_test"))
            c->mark_test = cfg_unum(c, key, val);
        else if (!strcmp(key, "mark_ok"))
            c->mark_ok = cfg_unum(c, key, val);
        else if (!strcmp(key, "mark_mask"))
            c->mark_mask = cfg_unum(c, key, val);
        else if (!strcmp(key, "ip_rule_priority_start"))
            c->ip_rule_priority_start = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "fast_interval"))
            c->fast_interval = cfg_dur(c, key, val, U_SEC);
        else if (!strcmp(key, "soft_interval"))
            c->soft_interval = cfg_dur(c, key, val, U_SEC);
        else if (!strcmp(key, "judge_interval"))
            c->judge_interval = cfg_dur(c, key, val, U_SEC);
        else if (!strcmp(key, "health_interval"))
            c->health_interval = cfg_dur(c, key, val, U_SEC);
        else if (!strcmp(key, "fast_syn_min_op")) {
            c->fast_syn_min_op = (int)cfg_num(c, key, val);
            seen |= PREC_FAST_SYN;
        }
        else if (!strcmp(key, "udp_min_op")) {
            c->udp_min_op = (int)cfg_num(c, key, val);
        }
        else if (!strcmp(key, "synfail_quorum"))
            c->synfail_quorum = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "synfail_window"))
            c->synfail_window = cfg_dur(c, key, val, U_SEC);
        else if (!strcmp(key, "ok_ttl"))
            c->ok_ttl = cfg_dur(c, key, val, U_SEC);
        else if (!strcmp(key, "ok_refresh_below"))
            c->ok_refresh_below = cfg_dur(c, key, val, U_HOUR);
        else if (!strcmp(key, "ok_max_entries"))
            c->ok_max_entries = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "ok_evict_misses")) {
            c->ok_evict_misses = (int)cfg_num(c, key, val);
            seen |= PREC_EVICT;
        }
        else if (!strcmp(key, "promo_per_min"))
            c->promo_per_min = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "test_ttl"))
            c->test_ttl = cfg_dur(c, key, val, U_MIN);
        else if (!strcmp(key, "ipset_batch"))
            c->ipset_batch = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "cooldown_ttl"))
            c->cooldown_ttl = cfg_dur(c, key, val, U_MIN);
        else if (!strcmp(key, "cooldown_ok_ttl"))
            c->cooldown_ok_ttl = cfg_dur(c, key, val, U_SEC);
        else if (!strcmp(key, "watch_ttl"))
            c->watch_ttl = cfg_dur(c, key, val, U_SEC);
        else if (!strcmp(key, "watch_retry_below"))
            c->watch_retry_below = cfg_dur(c, key, val, U_SEC);
        else if (!strcmp(key, "health_miss_debounce"))
            c->health_miss_debounce = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "health_mode"))
            set_str(c->health_mode, sizeof(c->health_mode), val);
        else if (!strcmp(key, "health_tcp_port"))
            c->health_tcp_port = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "health_probe"))
            set_str(c->health_probe, sizeof(c->health_probe), val);
        else if (!strcmp(key, "vpn_always_file"))
            set_str(c->vpn_always_file, sizeof(c->vpn_always_file), val);
        else if (!strcmp(key, "vpn_always_dns"))
            set_str(c->vpn_always_dns, sizeof(c->vpn_always_dns), val);
        else if (!strcmp(key, "vpn_always_interval"))
            c->vpn_always_interval = cfg_dur(c, key, val, U_SEC);
        else if (!strcmp(key, "vpn_never_file"))
            set_str(c->vpn_never_file, sizeof(c->vpn_never_file), val);
        else if (!strcmp(key, "vpn_never_interval"))
            c->vpn_never_interval = cfg_dur(c, key, val, U_SEC);
        else if (!strcmp(key, "vpn_refresh_budget_ms"))
            c->vpn_refresh_budget_ms = (int)cfg_num(c, key, val);
            else if (!strcmp(key, "log_level"))
                set_str(c->log_level, sizeof(c->log_level), val);
            else if (!strcmp(key, "xray_loglevel"))
                set_str(c->xray_loglevel, sizeof(c->xray_loglevel), val);
            else if (!strcmp(key, "xray_gogc"))
                set_str(c->xray_gogc, sizeof(c->xray_gogc), val);
            else if (!strcmp(key, "xray_gomemlimit"))
                set_str(c->xray_gomemlimit, sizeof(c->xray_gomemlimit), val);
            else if (!strcmp(key, "xray_watchdog"))
                c->xray_watchdog = (int)cfg_num(c, key, val);
            else if (!strcmp(key, "xray_min_mem_kb"))
                c->xray_min_mem_kb = (int)cfg_num(c, key, val);
            else if (!strcmp(key, "xray_log_max_kb"))
                c->xray_log_max_kb = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "disk_mode"))
            set_str(c->disk_mode, sizeof(c->disk_mode), val);
        else if (!strcmp(key, "soft_state_interval"))
            c->soft_state_interval = cfg_dur(c, key, val, U_HOUR);
        else if (!strcmp(key, "learn_exclude_ports"))
            set_str(c->learn_exclude_ports, sizeof(c->learn_exclude_ports), val);
        else if (!strcmp(key, "discover_exclude"))
            set_str(c->discover_exclude, sizeof(c->discover_exclude), val);
        else if (!strcmp(key, "lan_server_interfaces"))
            set_str(c->lan_server_interfaces, sizeof(c->lan_server_interfaces), val);
        else if (!strcmp(key, "dp_check_interval"))
            c->dp_check_interval = cfg_dur(c, key, val, U_SEC);
        else if (!strcmp(key, "learn_min_op")) {
            c->learn_min_op = (int)cfg_num(c, key, val);
            seen |= PREC_LEARN_OP;
        }
        else if (!strcmp(key, "learn_min_bytes")) {
            c->learn_min_bytes = (int)cfg_num(c, key, val);
            seen |= PREC_LEARN_BYTES;
        }
        else if (!strcmp(key, "confirm_min_bytes")) {
            c->confirm_min_bytes = (int)cfg_num(c, key, val);
            seen |= PREC_CONFIRM;
        }
        else if (!strcmp(key, "learn_strict")) {
            c->learn_strict = (int)cfg_num(c, key, val);
            seen |= PREC_STRICT;
        }
        else if (!strcmp(key, "port_aware"))
            c->port_aware = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "precision"))
            set_str(c->precision, sizeof(c->precision), val);
        else if (!strcmp(key, "cdn_ranges_file"))
            set_str(c->cdn_ranges_file, sizeof(c->cdn_ranges_file), val);
        else if (!strcmp(key, "cdn_ranges_url"))
            set_str(c->cdn_ranges_url, sizeof(c->cdn_ranges_url), val);
        else if (!strcmp(key, "cdn_ranges_interval"))
            c->cdn_ranges_interval = cfg_dur(c, key, val, U_SEC);
        else if (!strcmp(key, "cdn_prefix_learn"))
            c->cdn_prefix_learn = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "cdn_prefix_ttl"))
            c->cdn_prefix_ttl = cfg_dur(c, key, val, U_SEC);
        else if (!strcmp(key, "aggregate_confirm"))
            c->aggregate_confirm = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "frozen_net_enabled"))
            c->frozen_net_enabled = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "frozen_net_min_ips"))
            c->frozen_net_min_ips = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "frozen_net_prefix"))
            c->frozen_net_prefix = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "frozen_net_ttl"))
            c->frozen_net_ttl = cfg_dur(c, key, val, U_SEC);
        else if (!strcmp(key, "test_net_enabled"))
            c->test_net_enabled = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "test_net_min_ips"))
            c->test_net_min_ips = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "test_net_prefix"))
            c->test_net_prefix = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "test_net_window"))
            c->test_net_window = cfg_dur(c, key, val, U_SEC);
        else if (!strcmp(key, "test_net_ttl"))
            c->test_net_ttl = cfg_dur(c, key, val, U_SEC);
        else if (!strcmp(key, "ru_guard"))
            c->ru_guard = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "ru_guard_direct"))
            c->ru_guard_direct = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "ru_guard_tlds"))
            set_str(c->ru_guard_tlds, sizeof(c->ru_guard_tlds), val);
        else if (!strcmp(key, "tz"))
            set_str(c->tz, sizeof(c->tz), val);
        else if (!strcmp(key, "cdn_prefix_max"))
            c->cdn_prefix_max = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "ipv6_block"))
            c->ipv6_block = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "quic_block"))
            c->quic_block = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "mss_clamp"))
            set_str(c->mss_clamp, sizeof(c->mss_clamp), val);
        else if (!strcmp(key, "mss_clamp_lan"))
            c->mss_clamp_lan = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "egress_failback"))
            c->egress_failback = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "egress_failback_debounce"))
            c->egress_failback_debounce = cfg_dur(c, key, val, U_SEC);
        else if (!strcmp(key, "dns_sniff"))
            c->dns_sniff = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "dns_sniff_ttl"))
            c->dns_sniff_ttl = cfg_dur(c, key, val, U_SEC);
        else if (!strcmp(key, "dns_sniff_iface"))
            set_str(c->dns_sniff_iface, sizeof(c->dns_sniff_iface), val);
        else if (!strcmp(key, "dns_hijack"))
            c->dns_hijack = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "dns_hijack_target"))
            set_str(c->dns_hijack_target, sizeof(c->dns_hijack_target), val);
        else if (!strcmp(key, "vpn_always_cdn_prefix"))
            c->vpn_always_cdn_prefix = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "pin_reassert"))
            c->pin_reassert = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "kernel_offload"))
            c->kernel_offload = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "kernel_egress"))
            set_str(c->kernel_egress, sizeof(c->kernel_egress), val);
        else if (!strcmp(key, "kernel_offload_max"))
            c->kernel_offload_max = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "proxy_uid"))
            set_str(c->proxy_uid, sizeof(c->proxy_uid), val);
        else if (!strcmp(key, "proxy_egress"))
            set_str(c->proxy_egress, sizeof(c->proxy_egress), val);
        else if (!strcmp(key, "proxy_table")) {
            /* Обещание из config.h: 0 = значение по умолчанию. Нормализуем
             * сразу при разборе, чтобы И проверка готовности, и статус, и
             * datapath.sh видели одно и то же число. */
            int v = (int)cfg_num(c, key, val);
            c->proxy_table = v > 0 ? v : CFG_DEF_PROXY_TABLE;
        }
        else if (!strcmp(key, "proxy_mark")) {
            unsigned long v = cfg_unum(c, key, val);
            c->proxy_mark = v ? v : CFG_DEF_PROXY_MARK;
        }
        else if (!strcmp(key, "egress_race"))
            c->egress_race = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "auto_direct"))
            c->auto_direct = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "direct_pref_ttl"))
            c->direct_pref_ttl = cfg_dur(c, key, val, U_SEC);
        else if (!strcmp(key, "media_enabled"))
            c->media_enabled = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "media_ports"))
            set_str(c->media_ports, sizeof(c->media_ports), val);
        else if (!strcmp(key, "media_min_bytes"))
            c->media_min_bytes = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "media_ratio"))
            c->media_ratio = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "media_min_rate"))
            c->media_min_rate = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "media_min_age"))
            c->media_min_age = cfg_dur(c, key, val, U_SEC);
        else if (!strcmp(key, "media_ttl"))
            c->media_ttl = cfg_dur(c, key, val, U_SEC);
        else if (!strcmp(key, "media_prefix_max"))
            c->media_prefix_max = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "profile_failover"))
            c->profile_failover = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "egress_type"))
            set_str(c->egress_type, sizeof(c->egress_type), val);
        else if (!strcmp(key, "tproxy_port"))
            c->tproxy_port = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "udp_relay"))
            c->udp_relay = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "udp_relay_port"))
            c->udp_relay_port = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "socks_addr"))
            set_str(c->socks_addr, sizeof(c->socks_addr), val);
        else if (!strcmp(key, "socks_port"))
            c->socks_port = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "web_enable"))
            c->web_enable = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "web_listen"))
            set_str(c->web_listen, sizeof(c->web_listen), val);
        else if (!strcmp(key, "web_port"))
            c->web_port = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "web_token"))
            set_str(c->web_token, sizeof(c->web_token), val);
        else if (!strcmp(key, "release_check"))
            c->release_check = (int)cfg_num(c, key, val);
        else if (!strcmp(key, "release_check_interval"))
            c->release_check_interval = cfg_dur(c, key, val, U_SEC);
        else
            cfg_note_unknown_key(c, key);
    }

    fclose(fp);

    /* «Профили точности»: пресет применяется ПОСЛЕ разбора файла и только к тем
     * порогам, которых в файле не было (явные ключи сильнее пресета). */
    apply_precision(c, seen);

    /* P2: профили из profiles.d (один профиль = один файл .conf) дополняют
     * profileN_* из susanin.conf. Каталог: $SUSANIN_PROFILES_DIR или
     * /opt/susanin/etc/profiles.d. Ключи файла: name, egress, list, geo_url,
     * table, mark, auto. */
    {
        const char *pdir = getenv("SUSANIN_PROFILES_DIR");
        DIR *d;
        struct dirent *de;
        if (!pdir || !*pdir)
            pdir = "/opt/susanin/etc/profiles.d";
        d = opendir(pdir);
        if (d) {
            while ((de = readdir(d))) {
                char fp[CFG_PATH_MAX + 300];
                FILE *pf;
                char line[512];
                int slot = -1, i;
                size_t nl = strlen(de->d_name);
                if (de->d_name[0] == '.' || nl < 6 ||
                    strcmp(de->d_name + nl - 5, ".conf"))
                    continue;
                for (i = 0; i < CFG_MAX_PROFILES; i++)
                    if (!c->profile_name[i][0]) { slot = i; break; }
                if (slot < 0)
                    break;
                snprintf(fp, sizeof(fp), "%s/%s", pdir, de->d_name);
                pf = fopen(fp, "r");
                if (!pf)
                    continue;
                while (fgets(line, sizeof(line), pf)) {
                    char *p = line, *eq, *v, *q, *ke;
                    while (*p == ' ' || *p == '\t') p++;
                    if (*p == '#' || *p == '\n' || *p == '\0')
                        continue;
                    eq = strchr(p, '=');
                    if (!eq)
                        continue;
                    ke = eq;
                    while (ke > p && (ke[-1] == ' ' || ke[-1] == '\t'))
                        ke--;
                    *ke = '\0';
                    v = eq + 1;
                    while (*v == ' ' || *v == '\t')
                        v++;
                    q = v + strlen(v);
                    while (q > v && (q[-1] == '\n' || q[-1] == '\r' ||
                                     q[-1] == ' ' || q[-1] == '\t'))
                        *--q = '\0';
                    if (!strcmp(p, "name"))
                        set_str(c->profile_name[slot], sizeof(c->profile_name[slot]), v);
                    else if (!strcmp(p, "egress"))
                        set_str(c->profile_egress[slot], sizeof(c->profile_egress[slot]), v);
                    else if (!strcmp(p, "list"))
                        set_str(c->profile_list[slot], sizeof(c->profile_list[slot]), v);
                    else if (!strcmp(p, "geo_url"))
                        set_str(c->profile_geo_url[slot], sizeof(c->profile_geo_url[slot]), v);
                    else if (!strcmp(p, "table"))
                        c->profile_table[slot] = (int)cfg_num(c, "profile_table", v);
                    else if (!strcmp(p, "mark"))
                        c->profile_mark[slot] = cfg_unum(c, "profile_mark", v);
                    else if (!strcmp(p, "auto"))
                        c->profile_auto[slot] = (int)cfg_num(c, "profile_auto", v);
                }
                fclose(pf);
                if (!c->profile_name[slot][0]) {
                    size_t k;
                    for (k = 0; k + 1 < sizeof(c->profile_name[slot]) &&
                                de->d_name[k] && de->d_name[k] != '.'; k++)
                        c->profile_name[slot][k] = de->d_name[k];
                    c->profile_name[slot][k] = '\0';
                }
            }
            closedir(d);
        }
    }

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
    config_parse_egress(c);
    return 0;
}

int config_save(const char *path, const susanin_config *c)
{
    FILE *fp = fopen(path, "w");
    char dv[32];
    int i;
    if (!fp)
        return -1;
    fprintf(fp, "# Susanin.Keenetic configuration (generated)\n");
    fprintf(fp, "# Формат: key=value. Длительности — числом в единицах, указанных в\n");
    fprintf(fp, "# описании параметра (сек / мин / ч); если значение в эту единицу не\n");
    fprintf(fp, "# делится, оно записано с суффиксом (напр. 45s) — иначе округление\n");
    fprintf(fp, "# превратило бы «меньше минуты» в 0, а 0 для TTL значит «не истекает».\n");

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
    fprintf(fp, "# UDP: сколько неотвеченных пакетов в потоке нужно до заворота адреса\n");
    fprintf(fp, "# в VPN. Голосовые хендшейки (Discord) дают 3 пакета с нового порта и\n");
    fprintf(fp, "# сдаются — при большом значении адрес не успевает выучиться. 0 = 12.\n");
    fprintf(fp, "udp_min_op=%d\n", c->udp_min_op);
    fprintf(fp, "# Улика гибели прямого пути: сколько разных соединений на один\n");
    fprintf(fp, "# dst:port должны потерять SYN в окне synfail_window, чтобы уйти\n");
    fprintf(fp, "# в VPN без прямой пробы. Нужна потому, что проба — это connect()\n");
    fprintf(fp, "# с самого роутера, а умирает поток клиента; плюс проба ограничена\n");
    fprintf(fp, "# общим бюджетом и при фан-ауте не успевается. 0 = выключить.\n");
    fprintf(fp, "synfail_quorum=%d\n", c->synfail_quorum);
    fprintf(fp, "# Окно подсчёта погибших соединений, сек.\n");
    fprintf(fp, "synfail_window=%d\n", out_dur(c->synfail_window, U_SEC));
    fprintf(fp, "# TTL выученных ok-адресов, сек; 0 = никогда не истекает (наборы растут).\n");
    fprintf(fp, "ok_ttl=%d\n", out_dur(c->ok_ttl, U_SEC));
    fprintf(fp, "# Обновлять ok-адрес, если до истечения меньше заданного, ч.\n");
    out_dur_exact(c->ok_refresh_below, U_HOUR, dv, sizeof(dv));
    fprintf(fp, "ok_refresh_below=%s\n", dv);
    fprintf(fp, "# Лимит записей ok-кэша на протокол; 0 = без лимита.\n");
    fprintf(fp, "ok_max_entries=%d\n", c->ok_max_entries);
    fprintf(fp, "# Сколько подряд сбоев по адресу нужно для снятия из ok.\n");
    fprintf(fp, "ok_evict_misses=%d\n", c->ok_evict_misses);
    fprintf(fp, "# Лимит новых переводов в VPN в минуту; 0 = без лимита.\n");
    fprintf(fp, "promo_per_min=%d\n", c->promo_per_min);
    fprintf(fp, "# TTL «test»-состояния (проба через VPN), мин.\n");
    out_dur_exact(c->test_ttl, U_MIN, dv, sizeof(dv));
    fprintf(fp, "test_ttl=%s\n", dv);
    fprintf(fp, "# «Остывание» после снятия адреса из ok, мин.\n");
    out_dur_exact(c->cooldown_ttl, U_MIN, dv, sizeof(dv));
    fprintf(fp, "cooldown_ttl=%s\n", dv);
    fprintf(fp, "# Применять ipset-операции пачкой (`ipset restore`): 1 = да, 0 = поштучно.\n");
    fprintf(fp, "ipset_batch=%d\n", c->ipset_batch);
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
    fprintf(fp, "# Бюджет DNS-обновления списков за один проход, мс (0 = 4000).\n");
    fprintf(fp, "# Меньше — короче паузы главного цикла (важно для быстрой реакции\n");
    fprintf(fp, "# на голос/UDP), но списки обновляются за большее число проходов.\n");
    fprintf(fp, "vpn_refresh_budget_ms=%d\n", c->vpn_refresh_budget_ms);
    fprintf(fp, "# Уровень логов агента: quiet | error | warn | info | debug | trace.\n");
    fprintf(fp, "log_level=%s\n", c->log_level);
    fprintf(fp, "# Уровень логов Xray: debug | info | warning | none (читает xray-egress.sh).\n");
    fprintf(fp, "xray_loglevel=%s\n", c->xray_loglevel);
    fprintf(fp, "# GOGC Xray (память; меньше = агрессивнее GC).\n");
    fprintf(fp, "xray_gogc=%s\n", c->xray_gogc);
    fprintf(fp, "# GOMEMLIMIT Xray (мягкий лимит памяти, напр. 64MiB).\n");
    fprintf(fp, "xray_gomemlimit=%s\n", c->xray_gomemlimit);
    fprintf(fp, "# Watchdog Xray: 1 = агент сам поднимает упавший Xray (tproxy).\n");
    fprintf(fp, "xray_watchdog=%d\n", c->xray_watchdog);
    fprintf(fp, "# Порог свободной памяти для запуска Xray, КБ (0 = не проверять).\n");
    fprintf(fp, "xray_min_mem_kb=%d\n", c->xray_min_mem_kb);
    fprintf(fp, "# Обрезка xray.log перед запуском, КБ (0 = не обрезать).\n");
    fprintf(fp, "xray_log_max_kb=%d\n", c->xray_log_max_kb);
    fprintf(fp, "# Режим носителя: normal | soft (минимум записей на NAND/flash).\n");
    fprintf(fp, "disk_mode=%s\n", c->disk_mode);
    fprintf(fp, "# Период сохранения состояния в soft-режиме, ч; 0 = никогда.\n");
    out_dur_exact(c->soft_state_interval, U_HOUR, dv, sizeof(dv));
    fprintf(fp, "soft_state_interval=%s\n", dv);
    fprintf(fp, "# Порты, исключённые из быстрого автообучения (скан-шум), через запятую.\n");
    fprintf(fp, "learn_exclude_ports=%s\n", c->learn_exclude_ports);
    fprintf(fp, "# Интерфейсы, которые НИКОГДА не берём как egress/LAN, через запятую.\n");
    fprintf(fp, "discover_exclude=%s\n", c->discover_exclude);
    fprintf(fp, "# Туннели-СЕРВЕРЫ, чьих клиентов тоже обрабатываем как LAN, через запятую.\n");
    fprintf(fp, "lan_server_interfaces=%s\n", c->lan_server_interfaces);
    fprintf(fp, "# Период сверки датаплейна (reconcile), сек; 0 = 15.\n");
    fprintf(fp, "dp_check_interval=%d\n", out_dur(c->dp_check_interval, U_SEC));
    fprintf(fp, "# DNS-снифинг (домен->IP, зеркально, штатный DNS не трогаем): 0 | 1.\n");
    fprintf(fp, "dns_sniff=%d\n", c->dns_sniff);
    fprintf(fp, "# TTL записи домен->IP в снифинге, сек.\n");
    fprintf(fp, "dns_sniff_ttl=%d\n", out_dur(c->dns_sniff_ttl, U_SEC));
    fprintf(fp, "# Интерфейс захвата DNS; пусто = все lan_interfaces.\n");
    fprintf(fp, "dns_sniff_iface=%s\n", c->dns_sniff_iface);
    fprintf(fp, "# Заворачивать DNS клиентов СЕРВЕРНЫХ VPN (oc+/wdtt+ и\n");
    fprintf(fp, "# lan_server_interfaces) на резолвер роутера (DNAT 53). br0/br1 и\n");
    fprintf(fp, "# приватные адреса назначения не трогаются. 0 | 1.\n");
    fprintf(fp, "dns_hijack=%d\n", c->dns_hijack);
    fprintf(fp, "# Адрес резолвера для dns_hijack; пусто = LAN-адрес роутера:53.\n");
    fprintf(fp, "dns_hijack_target=%s\n", c->dns_hijack_target);
    fprintf(fp, "# Пинить CDN-префикс для адресов из vpn_always (ротация edge-ов): 0 | 1.\n");
    fprintf(fp, "vpn_always_cdn_prefix=%d\n", c->vpn_always_cdn_prefix);
    fprintf(fp, "# Периодически передобавлять пины списков (самолечение): 0 | 1.\n");
    fprintf(fp, "pin_reassert=%d\n", c->pin_reassert);
    fprintf(fp, "# N2: kernel-offload ok/CDN-адресов маршрутом через интерфейс: 0 | 1.\n");
    fprintf(fp, "kernel_offload=%d\n", c->kernel_offload);
    fprintf(fp, "# N2: интерфейс для offload (напр. nwg1); пусто = выключено.\n");
    fprintf(fp, "kernel_egress=%s\n", c->kernel_egress);
    fprintf(fp, "# N2: макс. длина префикса offload-маршрута (бит).\n");
    fprintf(fp, "kernel_offload_max=%d\n", c->kernel_offload_max);
    fprintf(fp, "# P5: uid процесса-прокси на роутере (MTProxy/Teleproxy); пусто = выкл.\n");
    fprintf(fp, "proxy_uid=%s\n", c->proxy_uid);
    fprintf(fp, "# P5: интерфейс для трафика proxy_uid (напр. nwg0); пусто = выкл.\n");
    fprintf(fp, "proxy_egress=%s\n", c->proxy_egress);
    fprintf(fp, "# P5: таблица маршрутизации для proxy_uid.\n");
    fprintf(fp, "proxy_table=%d\n", c->proxy_table);
    fprintf(fp, "# P5: метка для трафика proxy_uid (hex).\n");
    fprintf(fp, "proxy_mark=0x%lx\n", c->proxy_mark);
    fprintf(fp, "# N3: race-пробинг egress (выбор быстрейшего): 0 | 1.\n");
    fprintf(fp, "# Кандидаты — все интерфейсы из egress_interface.\n");
    fprintf(fp, "egress_race=%d\n", c->egress_race);
    fprintf(fp, "# D1: авто-возврат «в VPN хуже -> прямо» (мягкое прямо): 0 | 1.\n");
    fprintf(fp, "auto_direct=%d\n", c->auto_direct);
    fprintf(fp, "# D1: TTL мягкого «прямо», сек.\n");
    fprintf(fp, "direct_pref_ttl=%d\n", out_dur(c->direct_pref_ttl, U_SEC));
    fprintf(fp, "# M1: класс media (IPTV/видео) — детект по форме потока: 0 | 1.\n");
    fprintf(fp, "media_enabled=%d\n", c->media_enabled);
    fprintf(fp, "# M1: порты media через запятую.\n");
    fprintf(fp, "media_ports=%s\n", c->media_ports);
    fprintf(fp, "# M1: минимум принятых байт для media.\n");
    fprintf(fp, "media_min_bytes=%d\n", c->media_min_bytes);
    fprintf(fp, "# M1: rb >= ratio*ob.\n");
    fprintf(fp, "media_ratio=%d\n", c->media_ratio);
    fprintf(fp, "# M1: минимум Б/с (устойчиво).\n");
    fprintf(fp, "media_min_rate=%d\n", c->media_min_rate);
    fprintf(fp, "# M1: минимальный возраст потока, сек.\n");
    fprintf(fp, "media_min_age=%d\n", out_dur(c->media_min_age, U_SEC));
    fprintf(fp, "# M1: TTL media-префикса, сек.\n");
    fprintf(fp, "media_ttl=%d\n", out_dur(c->media_ttl, U_SEC));
    fprintf(fp, "# M1: макс. длина префикса агрегации (напр. 24).\n");
    fprintf(fp, "media_prefix_max=%d\n", c->media_prefix_max);
    fprintf(fp, "# P2: движок поддерживает default в table профиля на живом egress: 0 | 1.\n");
    fprintf(fp, "profile_failover=%d\n", c->profile_failover);
    fprintf(fp, "# L1: мин. пакетов к адресу для обучения.\n");
    fprintf(fp, "learn_min_op=%d\n", c->learn_min_op);
    fprintf(fp, "# L2: мин. байт «от нас» для обучения.\n");
    fprintf(fp, "learn_min_bytes=%d\n", c->learn_min_bytes);
    fprintf(fp, "# L4: мин. ответных байт для подтверждения.\n");
    fprintf(fp, "confirm_min_bytes=%d\n", c->confirm_min_bytes);
    fprintf(fp, "# Удвоить пороги обучения (строже): 0 | 1.\n");
    fprintf(fp, "learn_strict=%d\n", c->learn_strict);
    fprintf(fp, "# Пресет порогов обучения: strict | normal | aggressive (пусто = выкл).\n");
    fprintf(fp, "# Задаёт только значения по умолчанию: ключи выше, если они есть в\n");
    fprintf(fp, "# файле, пресет НЕ переопределяет.\n");
    fprintf(fp, "precision=%s\n", c->precision);
    fprintf(fp, "# Port-aware identity (экспериментально, по умолчанию 0): решения по паре\n");
    fprintf(fp, "# адрес+порт вместо адреса целиком. Требует наборов hash:ip,port.\n");
    fprintf(fp, "port_aware=%d\n", c->port_aware);
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
    fprintf(fp, "# Сколько РАЗНЫХ адресов подтвердить до агрегации префикса (>=1;\n");
    fprintf(fp, "# 1 = агрегировать по первому подтверждению).\n");
    fprintf(fp, "aggregate_confirm=%d\n", c->aggregate_confirm);
    fprintf(fp, "# Наследование заморозки ТСПУ на сеть (r4): N разных IP сети\n");
    fprintf(fp, "# подтверждены в VPN -> весь префикс идёт в VPN без дальнейших\n");
    fprintf(fp, "# проб (замораживают сети целиком: Hetzner/OVH/DO/Vultr...).\n");
    fprintf(fp, "frozen_net_enabled=%d\n", c->frozen_net_enabled);
    fprintf(fp, "# Сколько разных IP префикса подтвердить (>=1).\n");
    fprintf(fp, "frozen_net_min_ips=%d\n", c->frozen_net_min_ips);
    fprintf(fp, "# Длина префикса наследования (бит, 8..32).\n");
    fprintf(fp, "frozen_net_prefix=%d\n", c->frozen_net_prefix);
    fprintf(fp, "# TTL наследованного префикса, сек (продлевается при новых\n");
    fprintf(fp, "# подтверждениях сети; истёк — сеть снова учится по IP).\n");
    fprintf(fp, "frozen_net_ttl=%d\n", out_dur(c->frozen_net_ttl, U_SEC));
    fprintf(fp, "# Быстрая агрегация на фазе TEST: N разных IP одного префикса\n");
    fprintf(fp, "# в test за окно секунд -> префикс коротко пинится в susanin_ok_net\n");
    fprintf(fp, "# (фан-аут источника идёт в VPN сразу, не дожидаясь CONFIRMED\n");
    fprintf(fp, "# на каждый адрес); vpn_never приоритетнее. 0|1.\n");
    fprintf(fp, "test_net_enabled=%d\n", c->test_net_enabled);
    fprintf(fp, "# Сколько разных IP префикса нужно в test (>=1).\n");
    fprintf(fp, "test_net_min_ips=%d\n", c->test_net_min_ips);
    fprintf(fp, "# Длина префикса, бит (8..32).\n");
    fprintf(fp, "test_net_prefix=%d\n", c->test_net_prefix);
    fprintf(fp, "# Окно накопления серии, сек (серия остыла — счёт заново).\n");
    fprintf(fp, "test_net_window=%d\n", out_dur(c->test_net_window, U_SEC));
    fprintf(fp, "# TTL пина префикса, сек (короткий — ограничивает вред\n");
    fprintf(fp, "# ложного срабатывания).\n");
    fprintf(fp, "test_net_ttl=%d\n", out_dur(c->test_net_ttl, U_SEC));
    fprintf(fp, "# RU-guard (r5): российские домены НЕ заворачивать в VPN\n");
    fprintf(fp, "# автоматически — антифрод банков/OZON рвёт с чужого выхода.\n");
    fprintf(fp, "# Ручной vpn_always сильнее; работает при dns_sniff=1. 0|1.\n");
    fprintf(fp, "ru_guard=%d\n", c->ru_guard);
    fprintf(fp, "# 1 = RU-домены активно держать напрямую (пин в susanin_never,\n");
    fprintf(fp, "# снятие уже выученного VPN-пина); ручной vpn_always сильнее.\n");
    fprintf(fp, "ru_guard_direct=%d\n", c->ru_guard_direct);
    fprintf(fp, "# Суффиксы «российских» доменов через запятую.\n");
    fprintf(fp, "ru_guard_tlds=%s\n", c->ru_guard_tlds);
    fprintf(fp, "# Часовой пояс логов в POSIX-форме (Иркутск: IST-8, МСК: MSK-3).\n");
    fprintf(fp, "# Пусто = системный (на Entware обычно UTC). Влияет на время в логах\n");
    fprintf(fp, "# агента, панели и xray (init-скрипты экспортируют его в TZ).\n");
    fprintf(fp, "tz=%s\n", c->tz);
    fprintf(fp, "# Блокировать IPv6 из LAN (клиенты уходят на IPv4): 0 | 1.\n");
    fprintf(fp, "ipv6_block=%d\n", c->ipv6_block);
    fprintf(fp, "# Блокировать QUIC (UDP/443) из LAN: 0 | 1.\n");
    fprintf(fp, "quic_block=%d\n", c->quic_block);
    fprintf(fp, "# MSS для туннеля: 0 = выкл, число байт (напр. 1380) или pmtu.\n");
    fprintf(fp, "mss_clamp=%s\n", c->mss_clamp);
    fprintf(fp, "# 1 = MSS ко всему LAN-forward, 0 = только к VPN-потокам.\n");
    fprintf(fp, "mss_clamp_lan=%d\n", c->mss_clamp_lan);
    fprintf(fp, "# Встроенная веб-панель включена: 0 | 1.\n");
    fprintf(fp, "web_enable=%d\n", c->web_enable);
    fprintf(fp, "# Адрес веб-панели (LAN, не 0.0.0.0).\n");
    fprintf(fp, "web_listen=%s\n", c->web_listen);
    fprintf(fp, "# Порт веб-панели.\n");
    fprintf(fp, "web_port=%d\n", c->web_port);
    fprintf(fp, "# Токен доступа к веб-панели (пусто = без пароля).\n");
    fprintf(fp, "web_token=%s\n", c->web_token);
    fprintf(fp, "# W6: проверять новые релизы на GitHub и показывать «!» в шапке: 0 | 1.\n");
    fprintf(fp, "release_check=%d\n", c->release_check);
    fprintf(fp, "# W6: период проверки релизов, сек (по умолчанию 12 ч).\n");
    fprintf(fp, "release_check_interval=%d\n", out_dur(c->release_check_interval, U_SEC));
    fprintf(fp, "# Возврат на приоритетный (первый живой) egress после восстановления: 0 | 1.\n");
    fprintf(fp, "egress_failback=%d\n", c->egress_failback);
    fprintf(fp, "# Сколько секунд Master должен держать UP до возврата (антидребезг).\n");
    fprintf(fp, "egress_failback_debounce=%d\n", out_dur(c->egress_failback_debounce, U_SEC));
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
        if (c->profile_geo_url[i][0])
            fprintf(fp, "profile%d_geo_url=%s\n", i + 1, c->profile_geo_url[i]);
        fprintf(fp, "profile%d_table=%d\n", i + 1, c->profile_table[i]);
        fprintf(fp, "profile%d_mark=0x%lx\n", i + 1, c->profile_mark[i]);
        fprintf(fp, "profile%d_auto=%d\n", i + 1, c->profile_auto[i]);
    }
    /* Ошибка всплывает именно на fclose: буферы ещё не записаны на носитель.
     * Без проверки полный диск давал бы «успех», а setup уже успевал
     * обнулить рабочий конфиг (fopen "w") — то есть терял его молча. */
    /* fclose — безусловно: в записи «a || b || fclose()» короткое замыкание
     * оставляло дескриптор открытым ровно в том случае, ради которого проверка
     * и добавлена (диск полон, fflush падает). */
    {
        int werr = (fflush(fp) != 0) || ferror(fp);
        int cerr = (fclose(fp) != 0);

        if (werr || cerr)
            return -1;
    }
    return 0;
}

/* Имя ключа конфига: только [a-z0-9_]. Нужно и web-панели (что можно создать). */
int config_key_name_ok(const char *k)
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

/* allow_create=0 — правим только существующий ключ (общее правило: новых ключей
 * через web не создаём). allow_create=1 — разрешено ДОПИСАТЬ ключ, если его нет
 * (только для ключей из белого списка, напр. profileN_*). */
int config_file_set(const char *path, const char *key, const char *val, int allow_create)
{
    FILE *in, *out;
    char line[1024], tmp[CFG_PATH_MAX + 16];
    int found = 0, last_nl = 1, tfd;

    if (!path || !key || !val)
        return -1;
    if (!config_key_name_ok(key) || !cfg_val_charset_ok(val))
        return -1;

    in = fopen(path, "r");
    if (!in)
        return -1;
    /* Уникальное имя на вызов: фиксированный «path.tmp» давал гонку двух
     * одновременных config set (панель + CLI) — оба писали в один файл. */
    snprintf(tmp, sizeof(tmp), "%s.tmpXXXXXX", path);
    tfd = mkstemp(tmp);
    if (tfd < 0) {
        fclose(in);
        return -1;
    }
    out = fdopen(tfd, "w");
    if (!out) {
        close(tfd);
        remove(tmp);
        fclose(in);
        return -1;
    }
    while (fgets(line, sizeof(line), in)) {
        char k2[64], *v2;

        /* Сравнение тем же разбором, что и чтение: раньше строка вида
         * «key = value» здесь не узнавалась, и вместо правки появлялась
         * вторая строка с тем же ключом. Заодно запись нормализуется к
         * канонической форме «key=value». */
        if (config_line_split(line, k2, sizeof(k2), &v2) == 0 &&
            !strcmp(k2, key)) {
            fprintf(out, "%s=%s\n", key, val);
            found = 1;
            last_nl = 1;
        } else {
            fputs(line, out);
            last_nl = line[0] ? (line[strlen(line) - 1] == '\n') : last_nl;
        }
    }
    fclose(in);
    if (!found && allow_create) {
        if (!last_nl)
            fputc('\n', out);
        fprintf(out, "%s=%s\n", key, val);
        found = 1;
    }
    if (fclose(out) != 0) {
        remove(tmp);
        return -1;
    }
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

/* Строка вида "key=" — вернуть имя ключа. Реализовано тем же разбором, что и
 * чтение конфига (config_line_split): именно расхождение этих двух мест теряло
 * значения в форме «key = value». */
static int cfg_line_key(const char *line, char *out, size_t n)
{
    return config_line_split(line, out, n, NULL);
}

/* Ключи, которые задаёт пресет precision (см. apply_precision и биты PREC_*).
 * Дописывать их дефолтом нельзя: пресет применяется только к тем из них,
 * которых в файле нет, и появление явной строки молча отменило бы настройку. */
static int cfg_key_precision_managed(const char *k)
{
    static const char *const kp[] = {
        "fast_syn_min_op", "ok_evict_misses", "learn_min_op",
        "learn_min_bytes", "confirm_min_bytes", "learn_strict", NULL
    };
    int i;

    for (i = 0; kp[i]; i++)
        if (!strcmp(kp[i], k))
            return 1;
    return 0;
}

/* Дописать в конфиг отсутствующие ключи со значениями по умолчанию.
 *
 * Единственный источник истины — config_save(): он перечисляет все ключи, а
 * его значения совпадают с config_set_defaults(), потому что лежат в одном
 * файле. Рукописный перечень в update.sh от кода отстал (в нём не было
 * ru_guard*, tz, test_net_*, frozen_net_*, port_aware и др., а lan_interfaces,
 * lan_subnets и media_ports остались с прежними дефолтами) — поэтому
 * дописывание делает здесь агент, а не скрипт.
 *
 * Существующие строки не перезаписываются: значение пользователя важнее
 * дефолта. dry_run=1 — только напечатать то, что добавилось бы.
 * Возвращает число добавленных (напечатанных) ключей, -1 при ошибке.
 * skipped_preset (может быть NULL) получает число ключей, пропущенных из-за
 * активного пресета precision — их молча дописать нельзя (см. выше). */
int config_sync(const char *path, int dry_run, int *skipped_preset)
{
    susanin_config c;
    char gen[CFG_PATH_MAX + 16], line[1024], key[96];
    char *kname[512], *kline[512];
    char *have[512];
    FILE *f, *g, *out;
    int nhave = 0, nmiss = 0, i, found, prec_active;
    size_t tmpl;
    char tmp[CFG_PATH_MAX + 16];

    if (!path || !path[0])
        return -1;
    if (config_load(path, &c) != 0)
        config_set_defaults(&c);
    /* Пресет активен, только если он задан и не «normal» (normal = дефолты). */
    prec_active = (!strcmp(c.precision, "strict") ||
                   !strcmp(c.precision, "aggressive"));
    if (skipped_preset)
        *skipped_preset = 0;
    snprintf(gen, sizeof(gen), "%s.gen.tmp", path);
    if (config_save(gen, &c) != 0)
        return -1;

    f = fopen(path, "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            if (cfg_line_key(line, key, sizeof(key)) != 0)
                continue;
            if (nhave >= (int)(sizeof(have) / sizeof(have[0]))) {
                /* Без полного списка имеющихся ключей дописывание стало бы
                 * опасным: невидимые ключи получили бы дубли. Отказываемся. */
                fclose(f);
                for (i = 0; i < nhave; i++)
                    free(have[i]);
                remove(gen);
                return -1;
            }
            have[nhave] = strdup(key);
            if (have[nhave])
                nhave++;
        }
        fclose(f);
    }

    g = fopen(gen, "r");
    if (!g) {
        remove(gen);
        for (i = 0; i < nhave; i++)
            free(have[i]);
        return -1;
    }
    while (fgets(line, sizeof(line), g)) {
        if (cfg_line_key(line, key, sizeof(key)) != 0)
            continue;
        if (nmiss >= (int)(sizeof(kname) / sizeof(kname[0])))
            break;
        found = 0;
        for (i = 0; i < nhave; i++) {
            if (!strcmp(have[i], key)) {
                found = 1;
                break;
            }
        }
        if (found)
            continue;
        /* Ключи, которые задаёт пресет precision, дописывать нельзя: пресет
         * применяется только к тем из них, которых в файле НЕТ (см.
         * apply_precision), и появись они здесь — строгость у пользователя
         * пропала бы молча, ровно в момент обновления. */
        if (prec_active && cfg_key_precision_managed(key)) {
            if (skipped_preset)
                (*skipped_preset)++;
            continue;
        }
        /* один и тот же ключ в генераторе не повторяется, но на всякий случай
         * не добавляем дубль и в список недостающих */
        {
            int j, dup = 0;
            for (j = 0; j < nmiss; j++)
                if (!strcmp(kname[j], key)) { dup = 1; break; }
            if (dup)
                continue;
        }
        kname[nmiss] = strdup(key);
        kline[nmiss] = strdup(line);
        if (!kname[nmiss] || !kline[nmiss]) {
            /* не оставляем висячий указатель: nmiss не увеличивается, и
               освобождённый ниже по nmiss цикл его не увидит */
            free(kname[nmiss]);
            free(kline[nmiss]);
            break;
        }
        nmiss++;
    }
    fclose(g);
    remove(gen);
    for (i = 0; i < nhave; i++)
        free(have[i]);

    if (dry_run) {
        for (i = 0; i < nmiss; i++)
            fputs(kline[i], stdout);
        for (i = 0; i < nmiss; i++) {
            free(kname[i]);
            free(kline[i]);
        }
        return nmiss;
    }

    if (nmiss == 0)
        return 0;

    /* Отдельное имя временного файла: config_file_set() (его зовёт панель при
     * «config set») пишет в "%s.tmp". Один и тот же tmp на два writer — это
     * гонка, где rename победил бы одного из них. */
    snprintf(tmp, sizeof(tmp), "%s.sync.tmp", path);
    f = fopen(path, "r");
    out = fopen(tmp, "w");
    if (!f || !out) {
        if (f)
            fclose(f);
        if (out)
            fclose(out);
        remove(tmp);
        for (i = 0; i < nmiss; i++) {
            free(kname[i]);
            free(kline[i]);
        }
        return -1;
    }
    while (fgets(line, sizeof(line), f))
        fputs(line, out);
    fclose(f);
    fprintf(out, "\n# --- добавлены config sync: ключи, которых в файле не было ---\n");
    fprintf(out, "# Значения — действующие по умолчанию. Свои настройки здесь не менялись.\n");
    for (i = 0; i < nmiss; i++) {
        tmpl = strlen(kline[i]);
        if (!tmpl || kline[i][tmpl - 1] != '\n')
            fprintf(out, "%s\n", kline[i]);
        else
            fputs(kline[i], out);
    }
    if (fclose(out) != 0) {
        remove(tmp);
        for (i = 0; i < nmiss; i++) {
            free(kname[i]);
            free(kline[i]);
        }
        return -1;
    }
    if (rename(tmp, path) != 0) {
        remove(tmp);
        for (i = 0; i < nmiss; i++) {
            free(kname[i]);
            free(kline[i]);
        }
        return -1;
    }
    for (i = 0; i < nmiss; i++) {
        free(kname[i]);
        free(kline[i]);
    }
    return nmiss;
}

/* Проверка конфига на значения, которые код прочтёт иначе, чем задумано.
 *
 * Проверяем ТОЛЬКО то, где значение не «менее выгодно», а прочитано неверно:
 * отрицательные пороги уходят в беззнаковый контекст и превращаются в
 * гигантские (агрегация при этом молча выключается), нулевые периоды
 * превращают редкий скан в каждый проход, метка вне маски не различается
 * ядром вообще. Документированные сенсоры нуля
 * оцениваются по смыслу конкретного ключа: «выключено», «никогда» и «взять
 * действующий default» — три разных законных случая, единого правила для нуля
 * нет. Исключение сделано там, где нуля-сенсора нет и 0 обращает редкий скан в
 * каждый проход — только такой ноль и помечается. Иначе проверка стала бы
 * шумом, который оператор перестаёт читать.
 *
 * Возвращает число проблем; в out — по строке на проблему (что влезло).
 * Приложение к загрузке: движок повторяет проверку на старте и на Reload,
 * чтобы «значение прочтётся не так» было видно в логе, а не в поведении. */
int config_validate(const susanin_config *c, char *out, size_t n)
{
    size_t used = 0;
    int bad = 0, full = 0, i;
    /* Буфер обязан вместить самую длинную формулировку ниже: при 256 текст
     * обрезался бы посреди предложения, а число проблем от обрезки не
     * меняется — тест этого бы не поймал, поймал только компилятор. */
    char line[512];

    if (!c || !out || n == 0)
        return 0;
    out[0] = '\0';

#define CFGV(...) do {                                        \
        int _w = snprintf(line, sizeof(line), __VA_ARGS__);   \
        bad++;                                                \
        if (_w > 0 && !full) {                                \
            if (used + (size_t)_w + 1 >= n) {                 \
                full = 1;                                     \
                if (used + 1 < n)                             \
                    used += snprintf(out + used, n - used, "..."); \
            } else {                                          \
                used += snprintf(out + used, n - used, "%s\n", line); \
            }                                                 \
        }                                                     \
    } while (0)

    /* Первым делом — значений, которых в структуре уже нет: разбор отбросил их
     * и записал 0. Это не «странное число», а потерянное намерение оператора. */
    for (i = 0; i < c->n_bad_values && i < CFG_MAX_BAD_VALUES; i++)
        CFGV("%s: значение не разобрано (минус, буквы или вне диапазона) — "
             "в параметр записан 0, а 0 для этого ключа значит не то, что было "
             "написано в файле",
             c->bad_values[i]);
    if (c->n_bad_dropped > 0)
        CFGV("и ещё %d ключ(ей) с отклонённым значением не попали в список "
             "(вместе с перечисленными — %d)",
             c->n_bad_dropped, c->n_bad_values + c->n_bad_dropped);

    /* Ключи, которых агент не знает вовсе: строка лежит в файле, выглядит как
     * настройка и не действует ни на что. Опечатка в имени — самый частый
     * способ получить «я же выставил, а не работает». */
    for (i = 0; i < c->n_unknown_keys && i < CFG_MAX_BAD_VALUES; i++)
        CFGV("%s: ключ агентом не распознан, значение не применяется",
             c->unknown_keys[i]);
    if (c->n_unknown_dropped > 0)
        CFGV("и ещё %d нераспознанного ключа не показаны (список полон)",
             c->n_unknown_dropped);

    /* Периоды, где 0 НЕ является сенсором: они подставляются в сравнение как
     * есть, и `now - last >= 0` истинно всегда — то есть 0 означает «каждый
     * проход цикла», а не «выключено». Это единственный класс, где нуль
     * реально ломает поведение, и его мы и помечаем. */
    if (c->fast_interval < 1)
        CFGV("fast_interval=%d: не может быть меньше 1 с (полный скан conntrack каждый проход)",
             c->fast_interval);
    if (c->soft_interval < 1)
        CFGV("soft_interval=%d: меньше 1 с — смысла нет, только нагрузка", c->soft_interval);
    if (c->judge_interval < 1)
        CFGV("judge_interval=%d: меньше 1 с — только нагрузка", c->judge_interval);
    if (c->health_interval < 1)
        CFGV("health_interval=%d: меньше 1 с — пробы чаще, чем успевает ответить туннель",
             c->health_interval);

    /* А здесь 0 = «взять действующий default» (CFG_DEF_* в config.h), и та же
     * подстановка сделана в месте потребления — то есть ноль законен.
     * Отрицательное сюда не доходит: его отбрасывает разбор и регистрирует в
     * bad_values (первый блок), поэтому отдельная проверка «< 0» была бы
     * недостижимым кодом. */

    /* Маршрутизация и метки: здесь неверное значение не «хуже», а не работает. */
    if (c->routing_table < 1 || c->routing_table > 252)
        CFGV("routing_table=%d: для ip rule годятся 1..252 (253..255 зарезервированы ядром)",
             c->routing_table);
    if (c->ip_rule_priority_start < 1 || c->ip_rule_priority_start > 32767)
        CFGV("ip_rule_priority_start=%d: вне 1..32767 — правила встанут не туда и перекроют KeeneticOS",
             c->ip_rule_priority_start);
    if (c->mark_mask == 0)
        CFGV("mark_mask=0: маска нулевая — метки test/ok неразличимы, вся маршрутизация по метке падает");
    else {
        if (c->mark_test && (c->mark_test & ~c->mark_mask))
            CFGV("mark_test=0x%lx не входит в mark_mask=0x%lx", c->mark_test, c->mark_mask);
        if (c->mark_ok && (c->mark_ok & ~c->mark_mask))
            CFGV("mark_ok=0x%lx не входит в mark_mask=0x%lx", c->mark_ok, c->mark_mask);
        if (c->mark_test == c->mark_ok)
            CFGV("mark_test == mark_ok (0x%lx): фаза test и подтверждённые адреса неразличимы",
                 c->mark_ok);
    }

    /* P5 (прокси на роутере): метка не должна пересекаться с метками LAN —
     * иначе трафик прокси попадёт в правила, написанные для клиентов, и
     * наоборот. Таблица должна быть годна для ip rule. */
    if (c->proxy_uid[0] && c->proxy_egress[0]) {
        if (c->proxy_table < 1 || c->proxy_table > 252)
            CFGV("proxy_table=%d: для ip rule годятся 1..252", c->proxy_table);
        if (c->proxy_mark & (c->mark_ok | c->mark_test))
            CFGV("proxy_mark=0x%lx пересекается с mark_ok=0x%lx/mark_test=0x%lx — "
                 "трафик прокси и клиентов различить нельзя",
                 c->proxy_mark, c->mark_ok, c->mark_test);
    }

    /* Пороги учёта и media здесь НЕ проверяются на знак: cfg_num_shape/cfg_num
     * отбрасывают минус, буквы и значение вне int-диапазона ещё на разборе и
     * регистрируют имя в bad_values (первый блок выше). Проверка «< 0» здесь
     * была бы недостижимым кодом — ровно тот класс, который мы убираем. */

    /* Учёт погибших соединений. */
    if (c->synfail_quorum > CFG_SYNFAIL_QUORUM_MAX)
        CFGV("synfail_quorum=%d недостижим как «разных соединений»: клампим до %d",
             c->synfail_quorum, CFG_SYNFAIL_QUORUM_MAX);
    /* Порты. Разбор по способу подстановки, а не «нуль везде плох»:
     *   - tproxy_port и udp_relay_port уходят в сравнение и bind как есть,
     *     поэтому 0 там = сломанный порт (у релеев ещё и ephemeral-bind);
     *   - socks_port, web_port и health_tcp_port при 0 подменяются default-ом
     *     (CFG_DEF_* в config.h) — ноль законен, а вне диапазона уже нет. */
#define CFGV_PORT_STRICT(key, val, on) do {                       \
        if ((on) && ((val) < 1 || (val) > 65535))                 \
            CFGV("%s=%d: вне 1..65535", (key), (int)(val));      \
    } while (0)
#define CFGV_PORT_DEFAULT(key, val, def) do {                     \
        if ((val) != 0 && ((val) < 1 || (val) > 65535))           \
            CFGV("%s=%d: вне 1..65535 (0 = %d)", (key), (int)(val), (def)); \
    } while (0)
    CFGV_PORT_STRICT("tproxy_port", c->tproxy_port,
                     !strcmp(c->egress_type, "tproxy") || !strcmp(c->egress_type, "xray"));
    CFGV_PORT_STRICT("udp_relay_port", c->udp_relay_port, c->udp_relay == 1);
    CFGV_PORT_DEFAULT("socks_port", c->socks_port, CFG_DEF_SOCKS_PORT);
    CFGV_PORT_DEFAULT("web_port", c->web_port, CFG_DEF_WEB_PORT);
    CFGV_PORT_DEFAULT("health_tcp_port", c->health_tcp_port, CFG_DEF_HEALTH_TCP_PORT);

    /* Длины префиксов агрегации: код клампит их в 8..32, поэтому значение вне
     * диапазона — не поломка, а «будет применён другой предел»: о нём говорим,
     * но только у включённого механизма. */
#define CFGV_PREFIX(key, val, on) do {                            \
        if ((on) && ((val) < 8 || (val) > 32))                    \
            CFGV("%s=%d: длина префикса вне 8..32 — будет кламплена", (key), (int)(val)); \
    } while (0)
    CFGV_PREFIX("cdn_prefix_max", c->cdn_prefix_max, c->cdn_prefix_learn == 1);
    CFGV_PREFIX("frozen_net_prefix", c->frozen_net_prefix, c->frozen_net_enabled == 1);
    CFGV_PREFIX("test_net_prefix", c->test_net_prefix, c->test_net_enabled == 1);
    CFGV_PREFIX("media_prefix_max", c->media_prefix_max, c->media_enabled == 1);
    CFGV_PREFIX("kernel_offload_max", c->kernel_offload_max,
                c->kernel_offload == 1 && c->kernel_egress[0] != '\0');
    /* Окно и TTL списков: при 0 подставляется default, отрицательное не
     * доходит до сюда (отбрасывает разбор) — проверять нечего. */

    /* Ключ, который без egress-интерфейса означает «всё напрямую». */
    if (!strcmp(c->egress_type, "interface") && !c->egress_interface[0])
        CFGV("egress_type=interface без egress_interface: учение будет, маршрутизации — нет");

    for (i = 0; i < c->n_egress && i < CFG_MAX_EGRESS; i++)
        if (!c->egress_list[i][0])
            CFGV("egress %d: пустой интерфейс в списке", i + 1);

    /* Заметка о неполном выводе — не отдельная проблема, поэтому пишем её
     * напрямую, минуя CFGV (он увеличивает счётчик). */
    if (full && used + 2 < n)
        used += snprintf(out + used, n - used,
                         "часть проблем не поместилась: susanin-agent config check\n");

    return bad;
}

void config_print(const susanin_config *c)
{
    int i;
    char dv[32];
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
    printf("udp_min_op=%d\n", c->udp_min_op);
    printf("synfail_quorum=%d\n", c->synfail_quorum);
    printf("synfail_window=%d\n", out_dur(c->synfail_window, U_SEC));
    printf("ok_ttl=%d\n", out_dur(c->ok_ttl, U_SEC));
    out_dur_exact(c->ok_refresh_below, U_HOUR, dv, sizeof(dv));
    printf("ok_refresh_below=%s\n", dv);
    printf("ok_max_entries=%d\n", c->ok_max_entries);
    printf("ok_evict_misses=%d\n", c->ok_evict_misses);
    printf("promo_per_min=%d\n", c->promo_per_min);
    out_dur_exact(c->test_ttl, U_MIN, dv, sizeof(dv));
    printf("test_ttl=%s\n", dv);
    out_dur_exact(c->cooldown_ttl, U_MIN, dv, sizeof(dv));
    printf("cooldown_ttl=%s\n", dv);
    printf("ipset_batch=%d\n", c->ipset_batch);
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
    printf("vpn_refresh_budget_ms=%d\n", c->vpn_refresh_budget_ms);
    printf("log_level=%s\n", c->log_level);
    printf("xray_loglevel=%s\n", c->xray_loglevel);
    printf("xray_gogc=%s\n", c->xray_gogc);
    printf("xray_gomemlimit=%s\n", c->xray_gomemlimit);
    printf("xray_watchdog=%d\n", c->xray_watchdog);
    printf("xray_min_mem_kb=%d\n", c->xray_min_mem_kb);
    printf("xray_log_max_kb=%d\n", c->xray_log_max_kb);
    printf("disk_mode=%s\n", c->disk_mode);
    out_dur_exact(c->soft_state_interval, U_HOUR, dv, sizeof(dv));
    printf("soft_state_interval=%s\n", dv);
    printf("learn_exclude_ports=%s\n", c->learn_exclude_ports);
    printf("discover_exclude=%s\n", c->discover_exclude);
    printf("lan_server_interfaces=%s\n", c->lan_server_interfaces);
    printf("dp_check_interval=%d\n", out_dur(c->dp_check_interval, U_SEC));
    printf("dns_sniff=%d\n", c->dns_sniff);
    printf("dns_sniff_ttl=%d\n", out_dur(c->dns_sniff_ttl, U_SEC));
    printf("dns_sniff_iface=%s\n", c->dns_sniff_iface);
    printf("dns_hijack=%d\n", c->dns_hijack);
    printf("dns_hijack_target=%s\n", c->dns_hijack_target);
    printf("vpn_always_cdn_prefix=%d\n", c->vpn_always_cdn_prefix);
    printf("pin_reassert=%d\n", c->pin_reassert);
    printf("kernel_offload=%d\n", c->kernel_offload);
    printf("kernel_egress=%s\n", c->kernel_egress);
    printf("kernel_offload_max=%d\n", c->kernel_offload_max);
    printf("proxy_uid=%s\n", c->proxy_uid);
    printf("proxy_egress=%s\n", c->proxy_egress);
    printf("proxy_table=%d\n", c->proxy_table);
    printf("proxy_mark=0x%lx\n", c->proxy_mark);
    printf("egress_race=%d\n", c->egress_race);
    printf("auto_direct=%d\n", c->auto_direct);
    printf("direct_pref_ttl=%d\n", out_dur(c->direct_pref_ttl, U_SEC));
    printf("media_enabled=%d\n", c->media_enabled);
    printf("media_ports=%s\n", c->media_ports);
    printf("media_min_bytes=%d\n", c->media_min_bytes);
    printf("media_ratio=%d\n", c->media_ratio);
    printf("media_min_rate=%d\n", c->media_min_rate);
    printf("media_min_age=%d\n", out_dur(c->media_min_age, U_SEC));
    printf("media_ttl=%d\n", out_dur(c->media_ttl, U_SEC));
    printf("media_prefix_max=%d\n", c->media_prefix_max);
    printf("profile_failover=%d\n", c->profile_failover);
    printf("learn_min_op=%d\n", c->learn_min_op);
    printf("learn_min_bytes=%d\n", c->learn_min_bytes);
    printf("confirm_min_bytes=%d\n", c->confirm_min_bytes);
    printf("learn_strict=%d\n", c->learn_strict);
    /* Значение — сырое, пояснение отдельной строкой-комментарием. Вывод
     * `config show` копируют в susanin.conf, а прежняя приписка внутри значения
     * («precision=(выкл)») при обратной загрузке давала неизвестный пресет и
     * предупреждение на каждом старте. */
    printf("precision=%s\n", c->precision);
    if (!c->precision[0])
        printf("# precision не задан (строгие значения: strict|normal|aggressive)\n");
    else if (!precision_known(c->precision))
        printf("# ВНИМАНИЕ: пресет «%s» неизвестен — игнорируется\n", c->precision);
    else
        printf("# пресет применён только к порогам, которых нет в конфиге\n");
    printf("port_aware=%d%s\n", c->port_aware,
           c->port_aware ? "  (экспериментально: наборы hash:ip,port, решения по паре адрес+порт)" : "");
    printf("cdn_ranges_file=%s\n", c->cdn_ranges_file);
    printf("cdn_ranges_url=%s\n", c->cdn_ranges_url);
    printf("cdn_ranges_interval=%d\n", out_dur(c->cdn_ranges_interval, U_SEC));
    printf("cdn_prefix_learn=%d\n", c->cdn_prefix_learn);
    printf("cdn_prefix_ttl=%d\n", out_dur(c->cdn_prefix_ttl, U_SEC));
    printf("cdn_prefix_max=%d\n", c->cdn_prefix_max);
    printf("aggregate_confirm=%d\n", c->aggregate_confirm);
    printf("frozen_net_enabled=%d\n", c->frozen_net_enabled);
    printf("frozen_net_min_ips=%d\n", c->frozen_net_min_ips);
    printf("frozen_net_prefix=%d\n", c->frozen_net_prefix);
    printf("frozen_net_ttl=%d\n", out_dur(c->frozen_net_ttl, U_SEC));
    printf("test_net_enabled=%d\n", c->test_net_enabled);
    printf("test_net_min_ips=%d\n", c->test_net_min_ips);
    printf("test_net_prefix=%d\n", c->test_net_prefix);
    printf("test_net_window=%d\n", out_dur(c->test_net_window, U_SEC));
    printf("test_net_ttl=%d\n", out_dur(c->test_net_ttl, U_SEC));
    printf("ru_guard=%d\n", c->ru_guard);
    printf("ru_guard_direct=%d\n", c->ru_guard_direct);
    printf("ru_guard_tlds=%s\n", c->ru_guard_tlds);
    printf("tz=%s\n", c->tz);
    printf("ipv6_block=%d\n", c->ipv6_block);
    printf("quic_block=%d\n", c->quic_block);
    printf("mss_clamp=%s\n", c->mss_clamp);
    printf("mss_clamp_lan=%d\n", c->mss_clamp_lan);
    printf("web_enable=%d\n", c->web_enable);
    printf("web_listen=%s\n", c->web_listen);
    printf("web_port=%d\n", c->web_port);
    printf("web_token=%s\n", c->web_token);
    printf("release_check=%d\n", c->release_check);
    printf("release_check_interval=%d\n", out_dur(c->release_check_interval, U_SEC));
    printf("egress_failback=%d\n", c->egress_failback);
    printf("egress_failback_debounce=%d\n", out_dur(c->egress_failback_debounce, U_SEC));
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
        if (c->profile_geo_url[i][0])
            printf("profile%d_geo_url=%s\n", i + 1, c->profile_geo_url[i]);
        printf("profile%d_table=%d\n", i + 1, c->profile_table[i]);
        printf("profile%d_mark=0x%lx\n", i + 1, c->profile_mark[i]);
        printf("profile%d_auto=%d\n", i + 1, c->profile_auto[i]);
    }
}
