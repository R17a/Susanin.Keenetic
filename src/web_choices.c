/* Susanin.Keenetic — «известные системе» значения для веб-панели.
 *
 * GET /api/choices (см. web.c) отдаёт панели то, что уже есть на роутере:
 * сетевые интерфейсы с классификацией, IPv4-подсети, таблицы маршрутизации,
 * свободные fwmark, файлы списков профилей. Панель показывает их выпадающим
 * списком рядом с полем — вместо ручного ввода.
 *
 * Источники — только то, что доступно самому демону:
 *   - интерфейсы: перебор /sys/class/net;
 *   - адреса/префиксы: ioctl(SIOCGIFADDR/SIOCGIFNETMASK) — внешняя утилита
 *     `ip` НЕ обязательна (у агента PATH урезан, и её может не быть вовсе);
 *     `ip -4 -o addr show` используется лишь как дополнение, если найдётся;
 *   - таблицы/метки: susanin.conf; файлы списков: каталог профилей.
 *
 * Жёсткие правила этого файла:
 *   - никаких новых зависимостей (только POSIX/C11, как остальной агент);
 *   - отказ любого источника (нет каталога, нет прав, нет IPv4) — пустой
 *     массив и код 200, но НЕ ошибка и НЕ падение;
 *   - разбор отделён от системных вызовов, чтобы покрываться host-тестом. */

#define _GNU_SOURCE
#include "web_choices.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* --- аккуратная сборка JSON без snprintf-переполнений --------------- */

typedef struct {
    char *buf;
    size_t cap; /* включая место под '\0' */
    size_t len;
    int full;   /* что-то не поместилось — ответ отдавать нельзя */
} jbuf;

static void jc_init(jbuf *j, char *buf, size_t cap)
{
    j->buf = buf;
    j->cap = cap;
    j->len = 0;
    j->full = 0;
    if (cap)
        buf[0] = '\0';
}

static int jc_addn(jbuf *j, const char *s, size_t n)
{
    if (!j->cap || n >= j->cap - j->len) {
        j->full = 1;
        return 0;
    }
    memcpy(j->buf + j->len, s, n);
    j->len += n;
    j->buf[j->len] = '\0';
    return 1;
}

static int jc_add(jbuf *j, const char *s)
{
    return jc_addn(j, s, strlen(s));
}

static int jc_addf(jbuf *j, const char *fmt, ...)
{
    char tmp[256];
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof(tmp)) {
        j->full = 1;
        return 0;
    }
    return jc_addn(j, tmp, (size_t)n);
}

/* Строка в кавычках с JSON-экранированием: имена интерфейсов и пути приходят
 * из файловой системы, кавычка/бэкслеш/управляющий символ не должны ломать
 * ответ. Байты >0x7f отдаём как есть (имена у нас ASCII). */
static int jc_addq(jbuf *j, const char *s)
{
    if (!jc_add(j, "\""))
        return 0;
    for (; s && *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"':  if (!jc_add(j, "\\\"")) return 0; break;
        case '\\': if (!jc_add(j, "\\\\")) return 0; break;
        case '\n': if (!jc_add(j, "\\n")) return 0; break;
        case '\r': if (!jc_add(j, "\\r")) return 0; break;
        case '\t': if (!jc_add(j, "\\t")) return 0; break;
        default:
            if (c < 0x20) {
                if (!jc_addf(j, "\\u%04x", (unsigned)c))
                    return 0;
            } else if (!jc_addn(j, (const char *)&c, 1)) {
                return 0;
            }
            break;
        }
    }
    return jc_add(j, "\"");
}

/* --- мелкие утилиты -------------------------------------------------- */

static int is_ws(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v';
}

static void rtrim(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && is_ws(s[n - 1]))
        s[--n] = '\0';
}

static void ltrim_inplace(char **p)
{
    while (**p && is_ws(**p))
        (*p)++;
}

/* Следующий токен строки (разделители — пробельные). *p двигается за токен. */
static char *next_token(char **p)
{
    char *s, *e;
    while (**p && is_ws(**p))
        (*p)++;
    s = *p;
    if (!*s)
        return NULL;
    e = s;
    while (*e && !is_ws(*e))
        e++;
    if (*e) {
        *e = '\0';
        *p = e + 1;
    } else {
        *p = e;
    }
    return s;
}

/* Прочитать файл целиком (кап cap). Возврат: malloc-буфер или NULL. */
static char *read_all(const char *path, size_t cap)
{
    FILE *f;
    char *buf;
    size_t n;

    f = fopen(path, "rb");
    if (!f)
        return NULL;
    buf = malloc(cap + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    n = fread(buf, 1, cap, f);
    fclose(f);
    buf[n] = '\0';
    return buf;
}

static size_t fmt_mark(char *out, size_t outsz, unsigned long v)
{
    int n = snprintf(out, outsz, "0x%lx", v);
    if (n < 0)
        return 0;
    if ((size_t)n >= outsz)
        return outsz - 1;
    return (size_t)n;
}

/* --- классификация интерфейсов --------------------------------------- */

static int has_prefix(const char *name, const char *pfx)
{
    return strncmp(name, pfx, strlen(pfx)) == 0;
}

const char *choice_iface_kind(const char *name)
{
    /* «awg» — AmneziaWG (userspace amneziawg-go поднимает awg0/wg0): для панели
     * это такой же тоннель, иначе он попадал в группу «Физические» и терялся
     * среди eth/ra/lo. Ставим ДО «wg», чтобы правило читалось по порядку. */
    static const char *tun[] = { "nwg", "wdtt", "awg", "wg", "tun", "ppp" };
    size_t i;

    if (!name || !name[0])
        return "physical";
    for (i = 0; i < sizeof(tun) / sizeof(tun[0]); i++)
        if (has_prefix(name, tun[i]))
            return "tunnel";
    if (has_prefix(name, "br"))
        return "bridge";
    return "physical";
}

const char *choice_dev_kind(const char *name, const char *uevent)
{
    if (uevent && strstr(uevent, "DEVTYPE=bridge"))
        return "bridge";
    return choice_iface_kind(name);
}

/* --- разбор строк ---------------------------------------------------- */

/* Годится ли токен на роль имени интерфейса (eth0, br-lan, ppp1.1, nwg0). */
static int is_ifname(const char *s)
{
    size_t i;
    if (!s || !s[0] || strlen(s) > 31)
        return 0;
    if (strstr(s, "://"))
        return 0;                       /* "inet 1.2.3.4/24 dev https://…" */
    for (i = 0; s[i]; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
            return 0;
    }
    return 1;
}

/* Разбор одной строки `ip -4 -o addr show`.
 *
 * Реальный формат busybox/iproute2 — имя интерфейса стоит ПЕРЕД «\»-продолжением
 * строки (в обёрнутом виде встречается и слитно: «eth0\»), поэтому берём последний
 * токен перед «\», а не последний токен строки:
 *   2: eth0    inet 192.168.1.1/24 brd 192.168.1.255 scope global eth0\
 * Имя ищем по двум признакам, в порядке надёжности: (1) токен перед «\»
 * (основной случай), (2) отдельный токен dev («… dev NAME»).
 * Нет ни одного — строку пропускаем, а не выдумываем интерфейс. */
int choice_parse_dev(const char *line, char *subnet, size_t subsz,
                     char *dev, size_t devsz)
{
    char buf[512];
    char linecopy[512];
    char *p = buf;
    char *tok, *inet = NULL, *device = NULL, *slash;
    size_t ll;

    if (!line || !subsz || !devsz)
        return 0;
    subnet[0] = '\0';
    dev[0] = '\0';

    ll = strlen(line);
    if (ll >= sizeof(buf))
        return 0; /* строка не помещается — пропускаем, а не обрезаем */
    memcpy(buf, line, ll + 1);
    /* Копия до порчи токенов: в ней ищем токен перед «\» и токен dev. */
    memcpy(linecopy, line, ll + 1);

    {
        /* Имя интерфейса: последний токен перед первым «\». */
        char *bs = strchr(linecopy, '\\');
        if (bs) {
            char *r = bs;
            while (r > linecopy && (r[-1] == ' ' || r[-1] == '\t'))
                r--;
            *bs = '\0';
            while (r > linecopy && r[-1] != ' ' && r[-1] != '\t')
                r--;
            if (is_ifname(r))
                device = r;
        }
    }

    while ((tok = next_token(&p)) != NULL) {
        size_t tl = strlen(tok);
        /* Слитный «eth0\» читаем как имя интерфейса + продолжение строки. */
        while (tl > 0 && tok[tl - 1] == '\\')
            tok[--tl] = '\0';
        if (!tl)
            continue;                       /* токен-продолжение уже учтён */
        if (!strcmp(tok, "inet")) {
            /* Следующий токен — подсеть; имя интерфейса ищем дальше по строке. */
            inet = next_token(&p);
            continue;
        }
        if (!strcmp(tok, "dev")) {
            char *n = next_token(&p);
            if (n) {
                size_t nl = strlen(n);
                while (nl > 0 && n[nl - 1] == '\\')
                    n[--nl] = '\0';
            }
            if (n && is_ifname(n))
                device = n;
            continue;
        }
    }
    if (!inet)
        return 0;
    slash = strchr(inet, '/');
    if (!slash || !isdigit((unsigned char)slash[1]))
        return 0;
    if (!device)
        return 0;                           /* ни «\», ни dev NAME — пропускаем */
    if (strlen(inet) >= subsz || strlen(device) >= devsz)
        return 0;
    snprintf(subnet, subsz, "%s", inet);
    snprintf(dev, devsz, "%s", device);
    return 1;
}

/* Префикс из маски сети: число ведущих единичных бит (0..32).
 * Маска — в хостовом порядке (после ntohl): 0xffffff00 -> 24.
 * Неконтигуозную маску трактуем по ведущим битам — для реальных netmask
 * (0xffffffff, 0xffffff00, …) результат совпадает с «числом единиц». */
int choice_mask_prefix(unsigned long mask)
{
    int n = 0;
    unsigned long bit;

    mask &= 0xffffffffUL;
    for (bit = 0x80000000UL; bit != 0UL; bit >>= 1) {
        if (!(mask & bit))
            break;
        n++;
    }
    return n;
}

/* "A.B.C.D/len" в out. addr — в хостовом порядке, prefix 0..32.
 * Собираем вручную (без inet_ntop): зависимостей меньше, а формат — тот же
 * "адрес/префикс", что панель уже умеет. 0 — не поместилось/плохие аргументы. */
int choice_format_cidr(char *out, size_t outsz, unsigned long addr, int prefix)
{
    int n;

    if (!out || !outsz)
        return 0;
    out[0] = '\0';
    if (prefix < 0 || prefix > 32)
        return 0;
    n = snprintf(out, outsz, "%lu.%lu.%lu.%lu/%d",
                 (addr >> 24) & 0xffUL, (addr >> 16) & 0xffUL,
                 (addr >> 8) & 0xffUL, addr & 0xffUL, prefix);
    if (n < 0 || (size_t)n >= outsz) {
        out[0] = '\0';
        return 0;
    }
    return 1;
}

int choice_parse_conf_line(const char *line, char *key, size_t keysz,
                           char *val, size_t valsz)
{
    char buf[600];
    char *p, *eq;
    size_t ll, n;

    if (keysz)
        key[0] = '\0';
    if (valsz)
        val[0] = '\0';
    if (!line || !keysz || !valsz)
        return 0;
    ll = strlen(line);
    if (ll >= sizeof(buf))
        return 0;
    memcpy(buf, line, ll + 1);

    p = buf;
    ltrim_inplace(&p);
    if (!*p || *p == '#')
        return 0;
    eq = strchr(p, '=');
    if (!eq)
        return 0;
    *eq = '\0';
    rtrim(p);
    n = strlen(p);
    if (!n || n >= keysz)
        return 0;
    snprintf(key, keysz, "%s", p);

    p = eq + 1;
    ltrim_inplace(&p);
    rtrim(p);
    n = strlen(p);
    if (n >= valsz)
        return 0;
    snprintf(val, valsz, "%s", p);
    return 1;
}

int choice_looks_like_mark(const char *tok, unsigned long *out)
{
    char *end = NULL;
    unsigned long v;

    if (!tok || tok[0] != '0' || (tok[1] != 'x' && tok[1] != 'X'))
        return 0;
    if (!isxdigit((unsigned char)tok[2]))
        return 0;
    v = strtoul(tok + 2, &end, 16);
    if (!end || *end != '\0')
        return 0;
    if (out)
        *out = v;
    return 1;
}

int choice_mark_used(unsigned long mark, const unsigned long *used, size_t n)
{
    size_t i;
    if (!mark || !used)
        return 0;
    for (i = 0; i < n; i++)
        if (used[i] == mark)
            return 1;
    return 0;
}

int choice_mark_free_used(const unsigned long *used, size_t n)
{
    int k;
    for (k = 0; k < SUSANIN_MARK_STEP_COUNT; k++) {
        unsigned long m = SUSANIN_MARK_BASE + (unsigned long)k * SUSANIN_MARK_STEP;
        if (!choice_mark_used(m, used, n))
            return k;
    }
    return -1;
}

/* Метка уже в наборе used_marks (в строках вида "0x…"). */
static int mark_in_items(const choice_item *items, size_t n, unsigned long mark)
{
    size_t i;
    for (i = 0; i < n; i++) {
        unsigned long mv;
        if (choice_looks_like_mark(items[i].value, &mv) && mv == mark)
            return 1;
    }
    return 0;
}

/* "profileN_<field>=<value>" -> field/value. N — любое число. */
static int profile_conf_pair(const char *key, const char **fld)
{
    const char *p;
    if (strncmp(key, "profile", 7) != 0)
        return 0;
    p = key + 7;
    if (!isdigit((unsigned char)*p))
        return 0;
    while (isdigit((unsigned char)*p))
        p++;
    if (*p != '_')
        return 0;
    p++;
    if (!*p)
        return 0;
    *fld = p;
    return 1;
}

/* --- сбор из системы -------------------------------------------------- */

void choice_json_init(choice_set *cs)
{
    if (cs)
        memset(cs, 0, sizeof(*cs));
}

/* Добавить элемент в массив choice_item; тихо пропускаем при переполнении
 * и слишком длинных значениях. */
static void item_push(choice_item *arr, size_t *n, size_t max,
                      const char *field, const char *value)
{
    if (*n >= max)
        return;
    if (!field || strlen(field) >= sizeof(arr[0].field))
        return;
    if (!value || strlen(value) >= sizeof(arr[0].value))
        return;
    snprintf(arr[*n].field, sizeof(arr[0].field), "%s", field);
    snprintf(arr[*n].value, sizeof(arr[0].value), "%s", value);
    (*n)++;
}

void collect_ifaces(choice_set *cs, const char *netdir)
{
    DIR *d;
    struct dirent *de;

    if (!cs || !netdir)
        return;
    d = opendir(netdir);
    if (!d)
        return; /* нет /sys/class/net — пустой массив, не ошибка */

    while ((de = readdir(d)) != NULL) {
        char path[640];
        char op[64];
        const char *up;

        if (de->d_name[0] == '.')
            continue;
        if (cs->n_ifaces >= CHOICE_MAX_IFACES)
            break;

        up = "down";
        op[0] = '\0';
        if (snprintf(path, sizeof(path), "%s/%s/operstate", netdir, de->d_name) > 0) {
            FILE *f = fopen(path, "rb");
            if (f) {
                size_t got = fread(op, 1, sizeof(op) - 1, f);
                op[got] = '\0';
                fclose(f);
                rtrim(op);
                if (!strcmp(op, "up"))
                    up = "up";
            }
        }
        item_push(cs->ifaces, &cs->n_ifaces, CHOICE_MAX_IFACES,
                  de->d_name, up);
    }
    closedir(d);
}

/* IPv4-адрес и маска интерфейса через ioctl -> "A.B.C.D/len".
 * 1 — получилось. Интерфейс без IPv4 (ioctl не отработал или в ответе не
 * AF_INET) и loopback пропускаем. fd — сокет AF_INET/SOCK_DGRAM. */
static int iface_ipv4(int fd, const char *name, char *out, size_t outsz)
{
    struct ifreq ifr;
    struct sockaddr_in *sin;
    unsigned long addr, mask;
    int pfx;

    if (!name || !out || !outsz)
        return 0;
    out[0] = '\0';
    if (strlen(name) >= sizeof(ifr.ifr_name))
        return 0;                          /* имя не влезет в ifr_name */

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
    if (ioctl(fd, SIOCGIFADDR, &ifr) != 0)
        return 0;                          /* нет IPv4 на интерфейсе */
    sin = (struct sockaddr_in *)(void *)&ifr.ifr_addr;
    if (sin->sin_family != AF_INET)
        return 0;
    addr = (unsigned long)ntohl(sin->sin_addr.s_addr);
    if ((addr >> 24) == 127UL)
        return 0;                          /* loopback 127/8 не подсказываем */

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
    if (ioctl(fd, SIOCGIFNETMASK, &ifr) != 0)
        return 0;
    sin = (struct sockaddr_in *)(void *)&ifr.ifr_netmask;
    if (sin->sin_family != AF_INET)
        return 0;
    mask = (unsigned long)ntohl(sin->sin_addr.s_addr);
    if (mask == 0)
        return 0;                          /* маска не задана — подсказка бесполезна */

    pfx = choice_mask_prefix(mask);
    return choice_format_cidr(out, outsz, addr, pfx);
}

/* Подсеть (dev, cidr) уже собрана? Дедуп нужен, когда ioctl и `ip` дают одно
 * и то же. */
static int subnet_present(const choice_set *cs, const char *dev, const char *cidr)
{
    size_t i;
    for (i = 0; i < cs->n_subnets; i++)
        if (!strcmp(cs->subnets[i].field, dev) && !strcmp(cs->subnets[i].value, cidr))
            return 1;
    return 0;
}

/* Основной путь: адреса/префиксы через ioctl по интерфейсам из netdir. */
static void collect_subnets_ioctl(choice_set *cs, int fd, const char *netdir)
{
    DIR *d;
    struct dirent *de;

    if (!netdir)
        return;
    d = opendir(netdir);
    if (!d)
        return;                            /* нет /sys/class/net — не ошибка */
    while ((de = readdir(d)) != NULL) {
        char cidr[80];
        if (de->d_name[0] == '.')
            continue;
        if (cs->n_subnets >= CHOICE_MAX_SUBNETS)
            break;
        if (!iface_ipv4(fd, de->d_name, cidr, sizeof(cidr)))
            continue;
        item_push(cs->subnets, &cs->n_subnets, CHOICE_MAX_SUBNETS, de->d_name, cidr);
    }
    closedir(d);
}

/* Дополнение: `ip -4 -o addr show`, если утилита найдётся. Не обязательно —
 * без неё всё уже собрано через ioctl; stderr глушим, наличие проверяем
 * через `command -v` (иначе несуществующая утилита в некоторых оболочках
 * оставляет читателя popen() ждать вечно). */
static void collect_subnets_ip(choice_set *cs)
{
    FILE *p;
    char line[512];

    p = popen("command -v ip >/dev/null 2>&1 && ip -4 -o addr show 2>/dev/null", "r");
    if (!p)
        return;
    while (fgets(line, sizeof(line), p)) {
        char subnet[80], dev[64];
        if (cs->n_subnets >= CHOICE_MAX_SUBNETS)
            break;
        if (!choice_parse_dev(line, subnet, sizeof(subnet), dev, sizeof(dev)))
            continue;
        if (subnet_present(cs, dev, subnet))
            continue;                      /* уже собрано через ioctl */
        item_push(cs->subnets, &cs->n_subnets, CHOICE_MAX_SUBNETS, dev, subnet);
    }
    (void)pclose(p);
}

void collect_subnets(choice_set *cs, const char *netdir)
{
    int fd;

    if (!cs)
        return;

    /* Основной путь не зависит от внешних утилит: у демона PATH урезан
     * (Entware: нет /opt/sbin, /opt/bin), да и iproute2 может отсутствовать. */
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd >= 0) {
        collect_subnets_ioctl(cs, fd, netdir);
        close(fd);
    }

    /* Если `ip` всё-таки есть — добираем то, чего не видно через ioctl. */
    collect_subnets_ip(cs);
}

void collect_used(choice_set *cs, const char *conf_path, const susanin_config *cfg)
{
    int i;

    if (!cs)
        return;

    /* 1) Профили, разобранные конфигом: их таблица и метка заняты.
     * Перебираем ВСЕ 4 слота, а не n_profiles: config_load() заполняет
     * profile_table/profile_mark по индексу слота, а n_profiles считает
     * только профили с именем — при «дырке» (задан, скажем, лишь profile3)
     * разбор по n_profiles потерял бы занятую таблицу/метку слота 1. */
    if (cfg) {
        for (i = 0; i < CFG_MAX_PROFILES; i++) {
            if (!cfg->profile_name[i][0])
                continue;
            if (cfg->profile_table[i] > 0) {
                char num[16];
                snprintf(num, sizeof(num), "%d", cfg->profile_table[i]);
                item_push(cs->tables, &cs->n_tables, CHOICE_MAX_TABLES, num, num);
            }
            if (cfg->profile_mark[i] &&
                !mark_in_items(cs->used_marks, cs->n_used_marks, cfg->profile_mark[i])) {
                char m[32];
                fmt_mark(m, sizeof(m), cfg->profile_mark[i]);
                item_push(cs->used_marks, &cs->n_used_marks, CHOICE_MAX_USED_MARKS,
                          "profile_mark", m);
            }
        }
    }

    /* 2) Сырой текст конфига: profileN_table=/profileN_mark= мог быть задан
     * вручную и не попасть в разобранные профили (например, профиль ещё не
     * включён). Таблицу добираем пометкой used, метку — строкой для сравнения. */
    if (conf_path && conf_path[0]) {
        char *text = read_all(conf_path, CHOICE_MAX_FILE);
        if (text) {
            char *p = text;
            while (p && *p) {
                char *nl = strchr(p, '\n');
                char line[600];
                char key[64], val[64];
                size_t raw = nl ? (size_t)(nl - p) : strlen(p);

                if (raw < sizeof(line)) {
                    const char *fld = NULL;
                    memcpy(line, p, raw);
                    line[raw] = '\0';
                    if (choice_parse_conf_line(line, key, sizeof(key), val, sizeof(val)) &&
                        profile_conf_pair(key, &fld) && val[0]) {
                        if (!strcmp(fld, "table")) {
                            size_t k;
                            int seen = 0;
                            for (k = 0; k < cs->n_tables; k++)
                                if (!strcmp(cs->tables[k].field, val))
                                    seen = 1;
                            if (!seen)
                                item_push(cs->tables, &cs->n_tables, CHOICE_MAX_TABLES,
                                          val, val);
                        } else if (!strcmp(fld, "mark")) {
                            unsigned long mv;
                            if (choice_looks_like_mark(val, &mv) &&
                                !mark_in_items(cs->used_marks, cs->n_used_marks, mv)) {
                                char m[32];
                                fmt_mark(m, sizeof(m), mv);
                                item_push(cs->used_marks, &cs->n_used_marks,
                                          CHOICE_MAX_USED_MARKS, "profile_mark", m);
                            }
                        }
                    }
                }
                if (!nl)
                    break;
                p = nl + 1;
            }
            free(text);
        }
    }
}

void collect_list_files(choice_set *cs, const char *dir)
{
    DIR *d;
    struct dirent *de;

    if (!cs || !dir)
        return;
    d = opendir(dir);
    if (!d)
        return; /* каталога может не быть — пустой массив */

    while ((de = readdir(d)) != NULL) {
        const char *name = de->d_name;
        char path[700];
        size_t l;
        struct stat st;

        if (name[0] == '.')
            continue;
        if (cs->n_lists >= CHOICE_MAX_LISTS)
            break;
        l = strlen(name);
        if (l < 5 || strcmp(name + l - 4, ".txt") != 0)
            continue;
        if (snprintf(path, sizeof(path), "%s/%s", dir, name) < 0)
            continue;
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
            continue; /* только обычные файлы */
        item_push(cs->lists, &cs->n_lists, CHOICE_MAX_LISTS, name, path);
    }
    closedir(d);
}

const char *wc_list_dir(void)
{
    return SUSANIN_PROFILES_LIST_DIR;
}

/* --- JSON ------------------------------------------------------------- */

/* Классификация интерфейса: сначала uevent (DEVTYPE=bridge), потом по имени,
 * и последним признаком — наличие /sys/class/net/<if>/bridge. */
static const char *iface_kind_from_sys(const char *netdir, const char *name)
{
    char path[640];
    char uevent[1024];
    const char *kind;

    if (!netdir)
        return choice_iface_kind(name);

    uevent[0] = '\0';
    if (snprintf(path, sizeof(path), "%s/%s/uevent", netdir, name) > 0) {
        FILE *f = fopen(path, "rb");
        if (f) {
            size_t got = fread(uevent, 1, sizeof(uevent) - 1, f);
            uevent[got] = '\0';
            fclose(f);
        }
    }
    kind = choice_dev_kind(name, uevent[0] ? uevent : NULL);
    if (strcmp(kind, "bridge") != 0) {
        if (snprintf(path, sizeof(path), "%s/%s/bridge", netdir, name) > 0) {
            DIR *bd = opendir(path);
            if (bd) {
                closedir(bd);
                kind = "bridge";
            }
        }
    }
    return kind;
}

static void write_ifaces_json(jbuf *j, const choice_set *cs, const char *netdir)
{
    size_t i;

    jc_add(j, "\"ifaces\":[");
    /* Псевдо-egress: в tproxy-режиме канал задаётся не интерфейсом, а самим
     * Xray. Раньше в списке Web-панели его не было, и egress_interface=nwg0,tproxy
     * нельзя было выбрать иначе как руками. */
    jc_add(j, "{\"name\":\"tproxy\",\"kind\":\"tproxy\",\"up\":true},");
    for (i = 0; i < cs->n_ifaces; i++) {
        const char *kind = iface_kind_from_sys(netdir, cs->ifaces[i].field);
        if (i)
            jc_add(j, ",");
        jc_add(j, "{\"name\":");
        jc_addq(j, cs->ifaces[i].field);
        jc_add(j, ",\"kind\":");
        jc_addq(j, kind);
        jc_add(j, ",\"up\":");
        jc_add(j, !strcmp(cs->ifaces[i].value, "up") ? "true" : "false");
        jc_add(j, "}");
    }
    jc_add(j, "],");
}

static void write_subnets_json(jbuf *j, const choice_set *cs)
{
    size_t i;
    jc_add(j, "\"subnets\":[");
    for (i = 0; i < cs->n_subnets; i++) {
        if (i)
            jc_add(j, ",");
        jc_add(j, "{\"cidr\":");
        jc_addq(j, cs->subnets[i].value);
        jc_add(j, ",\"dev\":");
        jc_addq(j, cs->subnets[i].field);
        jc_add(j, "}");
    }
    jc_add(j, "],");
}

static void write_tables_json(jbuf *j, const choice_set *cs)
{
    int t;
    jc_add(j, "\"tables\":[");
    for (t = 200; t <= 210; t++) {
        char num[16];
        size_t k;
        int is_used = 0;
        snprintf(num, sizeof(num), "%d", t);
        for (k = 0; k < cs->n_tables; k++)
            if (!strcmp(cs->tables[k].field, num))
                is_used = 1;
        if (t > 200)
            jc_add(j, ",");
        jc_addf(j, "{\"id\":%d,\"used\":%s}", t, is_used ? "true" : "false");
    }
    jc_add(j, "],");
}

static void write_marks_json(jbuf *j, const choice_set *cs,
                             const unsigned long *used, size_t nused)
{
    size_t i;
    int k;

    jc_add(j, "\"used_marks\":[");
    for (i = 0; i < cs->n_used_marks; i++) {
        if (i)
            jc_add(j, ",");
        jc_addq(j, cs->used_marks[i].value);
    }
    jc_add(j, "],");

    jc_add(j, "\"marks\":[");
    for (k = 0; k < SUSANIN_MARK_STEP_COUNT; k++) {
        unsigned long mv = SUSANIN_MARK_BASE + (unsigned long)k * SUSANIN_MARK_STEP;
        char hex[32];
        if (k)
            jc_add(j, ",");
        fmt_mark(hex, sizeof(hex), mv);
        jc_add(j, "{\"value\":");
        jc_addq(j, hex);
        jc_add(j, ",\"used\":");
        jc_add(j, choice_mark_used(mv, used, nused) ? "true" : "false");
        jc_add(j, "}");
    }
    jc_add(j, "],");
}

static void write_lists_json(jbuf *j, const choice_set *cs, const char *listdir)
{
    size_t i;
    jc_add(j, "\"lists\":[");
    for (i = 0; i < cs->n_lists; i++) {
        if (i)
            jc_add(j, ",");
        jc_add(j, "{\"name\":");
        jc_addq(j, cs->lists[i].field);
        jc_add(j, ",\"path\":");
        jc_addq(j, cs->lists[i].value);
        jc_add(j, "}");
    }
    jc_add(j, "],");
    jc_add(j, "\"list_dir\":");
    jc_addq(j, listdir ? listdir : "");
}

size_t wc_write_json_src(const susanin_config *cfg, const char *conf_path,
                         const char *netdir, const char *listdir,
                         unsigned src, char *out, size_t outsz)
{
    choice_set *cs;
    jbuf j;
    unsigned long used[CHOICE_MAX_USED_MARKS];
    size_t nused = 0, i;

    if (!out || !outsz)
        return 0;
    out[0] = '\0';

    cs = malloc(sizeof(*cs));
    if (!cs)
        return 0;
    choice_json_init(cs);

    if (src & WC_SRC_IFACES)
        collect_ifaces(cs, netdir);
    if (src & WC_SRC_SUBNETS)
        collect_subnets(cs, netdir);
    if (src & WC_SRC_USED)
        collect_used(cs, conf_path, cfg);
    if (src & WC_SRC_LISTS)
        collect_list_files(cs, listdir);

    /* Итоговый набор занятых меток: разобранные профили (все 4 слота, как в
     * collect_used) + строки used_marks (уже нормализованы к виду "0x…"). */
    if (cfg) {
        int k;
        for (k = 0; k < CFG_MAX_PROFILES; k++)
            if (cfg->profile_name[k][0] && cfg->profile_mark[k] &&
                nused < CHOICE_MAX_USED_MARKS &&
                !choice_mark_used(cfg->profile_mark[k], used, nused))
                used[nused++] = cfg->profile_mark[k];
    }
    for (i = 0; i < cs->n_used_marks && nused < CHOICE_MAX_USED_MARKS; i++) {
        unsigned long mv;
        if (choice_looks_like_mark(cs->used_marks[i].value, &mv) &&
            !choice_mark_used(mv, used, nused))
            used[nused++] = mv;
    }

    jc_init(&j, out, outsz);
    jc_add(&j, "{");
    write_ifaces_json(&j, cs, netdir);
    write_subnets_json(&j, cs);
    write_tables_json(&j, cs);
    write_marks_json(&j, cs, used, nused);
    write_lists_json(&j, cs, listdir);
    jc_add(&j, ",\"free_mark_index\":");
    jc_addf(&j, "%d", choice_mark_free_used(used, nused));
    jc_add(&j, "}");

    free(cs);
    return j.full ? 0 : j.len;
}

size_t wc_write_json(const susanin_config *cfg, const char *conf_path,
                     const char *netdir, const char *listdir,
                     char *out, size_t outsz)
{
    return wc_write_json_src(cfg, conf_path, netdir, listdir, WC_SRC_ALL,
                             out, outsz);
}
