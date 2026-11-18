#define _GNU_SOURCE
#include "dns_sniff.h"
#include "classifier.h"
#include "entryparse.h"
#include "snisniff.h"
#include "backend.h"
#include "log.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define DNS_MAX_ENTRIES 2048
/* DNS_DOMAIN_MAX — в dns_sniff.h (нужен и классификатору). */

/* Источник пары «домен -> IP». SNI — самоутверждение клиента: LAN-хост может
 * послать любой servername, и по одному такому «приветствию» нельзя ни
 * запирать направление бессрочно, ни трогать чужие решения. Поэтому у
 * записей есть src, и ветки сильнее (бессрочный never-пин, снятие чужих
 * пинов, обрыв соединений) работают только для DNS-ответа. */
#define ESRC_DNS 1
#define ESRC_SNI 2

typedef struct {
    char domain[DNS_DOMAIN_MAX];
    char ip[16];
    time_t expire;
    unsigned char src;    /* ESRC_DNS / ESRC_SNI (SNI не понижает DNS до истечения) */
    int pinned;
    int pinned_never;
    /* Кэш вердиктов по спискам: reconcile каждые 10 с на каждую живую запись
     * выполнял до 5 полных проходов vpn_always/vpn_never (сотни зон) плюс
     * суффикс-проверку TLD. Вердикты пересчитываются только при смене
     * поколения списков (файлы перечитаны / TLD-набор изменён). */
    unsigned vgen;          /* поколение списков, на котором считали */
    signed char v_always;   /* -1 = не считали, 0/1 = вердикт */
    signed char v_soft;     /* 1 = запись в vpn_always с префиксом ? (мягкая) */
    signed char v_never;
    signed char v_ru;
} dns_entry;

static dns_entry g_tab[DNS_MAX_ENTRIES];

int dns_sniff_is_ru_domain(const susanin_config *cfg, const char *dom);
/* T4: слушаем ВСЕ LAN-интерфейсы (br0, br1, oc+ клиенты и т.п.), а не только
 * первый: DNS клиента OpenConnect (oc0) иначе не виден, и его адреса не
 * пинятся в vpn_always. Один сокет AF_PACKET на интерфейс. */
#define DNS_MAX_IFACES DNS_SNIFF_MAX_IFACES   /* лимит объявлен в заголовке */
static int g_fds[DNS_MAX_IFACES];
static char g_open[DNS_MAX_IFACES][64];   /* имена интерфейсов, к которым привязаны */
static int g_nfd = 0;
static int g_started = 0;
static const susanin_config *g_cfg = NULL;
static susanin_state *g_state = NULL;   /* для персиста пинов (может быть NULL) */

/* Кэш содержимого списка (vpn_always/vpn_never): файл перечитывается только при
 * смене mtime/размера, а не на каждую запись DNS-таблицы раз в 10 секунд. */
typedef struct {
    char path[256];
    long long mtime, size;
    char *data;              /* домены через '\n' */
} lcache;
static lcache lc[2];
/* Поколение списков: растёт при любом перечитывании vpn_always/vpn_never или
 * смене набора RU-TLD — кэш вердиктов записей при этом сбрасывается. */
static unsigned g_list_gen = 1;

static void reconcile_entry(const susanin_config *cfg, dns_entry *e, int i,
                            time_t now);
static int other_entry_matches(time_t now, int skip, int slot,
                               const susanin_config *cfg, const char *ip);

static unsigned long dns_hash(const char *s)
{
    unsigned long h = 5381;
    for (; *s; s++)
        h = ((h << 5) + h) ^ (unsigned char)tolower((unsigned char)*s);
    return h;
}

/* Счётчики пути «кадр -> запись в таблице» — по одному на шаг, чтобы сводка
 * показывала, ГДЕ именно всё умирает. Прежний одиночный «recv» рос до
 * проверок протокола, и «принято N пакетов, сохранено 0» нельзя было
 * прочитать как «ответов нет»: тот же результат давали и не-DNS-трафик, и
 * падающий разбор. Цепочка: frames -> udp53 (UDP с портом 53 с любой
 * стороны) -> queries/answers (по биту QR) -> parse_fail (обрезаны/битые) ->
 * stored; capped — отсев лимитом прохода. SNI считается отдельно: TCP-кадры
 * с ClientHello уходят из приёма раньше отбора UDP/53 и в DNS-шаги не
 * входят. Запросы/ответы дополнительно пишутся по интерфейсам захвата
 * (индексы параллельны g_fds, без аллокаций в пути): «кто видит ответы»
 * должен закрываться одной строкой сводки. */
static unsigned long g_c_frames, g_c_udp53, g_c_queries, g_c_answers;
static unsigned long g_c_parse_fail, g_c_stored, g_c_capped;
static unsigned long g_c_sni_seen, g_c_sni_named, g_c_sni_stored;
static unsigned long g_c_if_q[DNS_MAX_IFACES], g_c_if_a[DNS_MAX_IFACES];

/* 1 = пара домен+IP записана или обновлена, 0 = не записана. */
static int dns_store(const char *domain, const char *ip, int ttl, int src)
{
    time_t now = time(NULL);
    unsigned long h;
    int idx, reuse = -1;
    dns_entry *e;

    if (!domain[0] || !ip[0])
        return 0;
    h = dns_hash(domain) % DNS_MAX_ENTRIES;
    /* Домен ищем среди живых И истёкших записей: домен, который спрашивают
     * реже dns_sniff_ttl, раньше терял запись вместе с pinned-флагами, и
     * reconcile каждые dns_sniff_ttl секунд заново пинил его с логом. Теперь
     * та же пара домен+IP просто оживает; при смене IP флаги сбрасываются
     * (старый пин относится к прежнему адресу), и новый адрес пинится сразу. */
    for (idx = 0; idx < DNS_MAX_ENTRIES; idx++) {
        int s = (int)((h + (unsigned long)idx) % DNS_MAX_ENTRIES);
        e = &g_tab[s];
        if (!e->domain[0]) {
            if (reuse < 0) reuse = s;
            continue;
        }
        if (!strcasecmp(e->domain, domain)) {
            if (strcmp(e->ip, ip) != 0) {
                char old[16];

                snprintf(old, sizeof(old), "%s", e->ip);
                /* До сброса флагов снимаем пин СТАРОГО адреса. Иначе
                 * бессрочная запись (never pin идёт с timeout 0) остаётся в
                 * susanin_never навсегда: после ротации IP у CDN следующий
                 * владелец прежнего адреса уходил бы мимо VPN, и никто бы его
                 * обратно не вернул — флагов-то уже нет.
                 * Только для DNS-источника: SNI-притязание — слишком слабое
                 * основание трогать судьбу прежнего адреса, а пины,
                 * поставленные SNI-записью, и так ограничены TTL. */
                if (g_cfg && e->src == ESRC_DNS) {
                    if (e->pinned &&
                        !other_entry_matches(now, s, 0, g_cfg, old)) {
                        backend_ok_pin_del(g_cfg, old);
                        if (g_state) {
                            state_remove(st_ok(g_state, 0), old);
                            state_remove(st_ok(g_state, 1), old);
                        }
                    }
                    if (e->pinned_never &&
                        !other_entry_matches(now, s, 1, g_cfg, old)) {
                        backend_set_del(g_cfg, "susanin_never", old);
                        if (g_state)
                            state_remove(&g_state->never, old);
                        backend_ct_flush_ip(old);
                    }
                }
                snprintf(e->ip, sizeof(e->ip), "%s", ip);
                e->pinned = 0;
                e->pinned_never = 0;
            }
            /* DNS сильнее SNI: апгрейд разрешён, понижение — нет (пока
             * запись жива, факт реального A-ответа важнее позднего
             * самоутверждения). */
            if (src == ESRC_DNS)
                e->src = ESRC_DNS;
            e->expire = now + ttl;
            if (g_cfg)
                reconcile_entry(g_cfg, e, s, now);   /* мгновенный пин */
            if (src == ESRC_DNS)
                g_c_stored++;
            else
                g_c_sni_stored++;
            return 1;
        }
        if (e->expire <= now && reuse < 0)
            reuse = s;
    }
    if (reuse < 0) {
        /* Таблица полна живыми записями: новая пара отбрасывается. Молча —
         * нельзя, это ровно то, что видно только по счётчику. */
        return 0;
    }
    e = &g_tab[reuse];
    snprintf(e->domain, sizeof(e->domain), "%s", domain);
    snprintf(e->ip, sizeof(e->ip), "%s", ip);
    e->expire = now + ttl;
    e->src = (unsigned char)src;
    e->pinned = 0;
    e->pinned_never = 0;
    e->vgen = 0;                /* вердикты ещё не считали */
    e->v_always = -1;
    e->v_soft = -1;
    e->v_never = -1;
    e->v_ru = -1;
    if (g_cfg)
        reconcile_entry(g_cfg, e, reuse, now);       /* мгновенный пин */
    if (src == ESRC_DNS)
        g_c_stored++;
    else
        g_c_sni_stored++;
    return 1;
}

/* Разбор DNS-имени с поддержкой сжатия. nextoff — позиция после имени. */
static int dns_name(const uint8_t *p, int len, int off, char *out, unsigned outn,
                    int *nextoff)
{
    int jumps = 0, first = 1, o = off;
    unsigned outl = 0;
    *nextoff = off;
    if (outn)
        out[0] = '\0';
    while (o >= 0 && o < len) {
        uint8_t l = p[o];
        if ((l & 0xc0) == 0xc0) {
            int ptr;
            if (o + 1 >= len)
                return -1;
            ptr = ((l & 0x3f) << 8) | p[o + 1];
            if (ptr >= len)      /* указатель за пределы пакета — некорректный ответ */
                return -1;
            if (first) { *nextoff = o + 2; first = 0; }
            if (++jumps > 20)
                return -1;
            o = ptr;
            continue;
        }
        if (l == 0) {
            if (first)
                *nextoff = o + 1;
            break;
        }
        if (o + 1 + l > len)
            return -1;
        if (outl + (unsigned)l + 2 >= outn)
            return -1;
        if (outl)
            out[outl++] = '.';
        memcpy(out + outl, p + o + 1, (size_t)l);
        outl += (unsigned)l;
        o += 1 + l;
    }
    if (outn)
        out[outl] = '\0';
    return 0;
}

/* Разбор DNS-ОТВЕТА. Бит QR проверяет вызывающий — он же ведёт счётчики
 * queries/answers: раньше «не ответ» возвращался молча и был неотличим ни от
 * «это не DNS», ни от битого сообщения. Возврат: -1 = сообщение
 * битое/обрезанное, ни одна пара не извлечена; 0 = валидный ответ без
 * сохранённых пар (NXDOMAIN, только AAAA) — это не поломка разбора;
 * >0 = число сохранённых пар. */
static int dns_parse(const uint8_t *p, int len)
{
    int qd, an, off, i, ttlcap, stored = 0;
    char qname[DNS_DOMAIN_MAX];

    if (len < 12)
        return -1;                    /* заголовок не читается целиком */
    qd = (p[4] << 8) | p[5];
    an = (p[6] << 8) | p[7];
    if (qd < 1)
        return -1;                    /* вопроса нет — имя взять неоткуда */
    if (an < 1)
        return 0;                     /* честный ответ без записей */
    if (dns_name(p, len, 12, qname, sizeof(qname), &off) != 0)
        return -1;
    if (off + 4 > len)
        return -1;
    off += 4;                       /* qtype + qclass */

    ttlcap = (g_cfg && g_cfg->dns_sniff_ttl > 0) ? g_cfg->dns_sniff_ttl : CFG_DEF_DNS_SNIFF_TTL;
    for (i = 0; i < an && off + 10 <= len; i++) {
        int type, cls, rdlen, ttl;
        char aname[DNS_DOMAIN_MAX];
        int noff;
        if (dns_name(p, len, off, aname, sizeof(aname), &noff) != 0)
            return stored ? stored : -1;
        off = noff;
        if (off + 10 > len)
            return stored ? stored : -1;
        type = (p[off] << 8) | p[off + 1];
        cls = (p[off + 2] << 8) | p[off + 3];
        {
            /* Собрано в unsigned long: при старшем байте >= 0x80 запись вида
             * (p[off+4] << 24) переполняет signed int — это формально UB, а на
             * практике превращает огромный TTL в отрицательный. */
            unsigned long tu = ((unsigned long)p[off + 4] << 24) |
                               ((unsigned long)p[off + 5] << 16) |
                               ((unsigned long)p[off + 6] << 8) |
                               (unsigned long)p[off + 7];
            ttl = (tu > (unsigned long)INT_MAX) ? INT_MAX : (int)tu;
        }
        rdlen = (p[off + 8] << 8) | p[off + 9];
        off += 10;
        if (off + rdlen > len)
            return stored ? stored : -1;
        if (type == 1 && cls == 1 && rdlen == 4) {
            char ip[16];
            if (ttl <= 0 || ttl > ttlcap)
                ttl = ttlcap;
            snprintf(ip, sizeof(ip), "%u.%u.%u.%u",
                     p[off], p[off + 1], p[off + 2], p[off + 3]);
            /* Пиним ИМЯ, КОТОРОЕ СПРОСИЛ КЛИЕНТ, а не только владельца
             * A-записи. У CDN-хостов (EdgeOne, CloudFront, Fastly и т.п.)
             * ответ приходит как CNAME: aname — это каноническое имя
             * (*.eo.dnse3.com, *.cloudfront.net), и списки vpn_always/
             * vpn_never по нужному домену с ним не совпадают. Из-за этого
             * www.tencentcloud.com, api.deepseek.com и подобные не пинились
             * вообще, и решение по каждому адресу принимало автообучение
             * (CONFIRMED -> D1 -> soft-direct) — то есть маршрут «плавал»
             * от соединения к соединению. Каноническое имя тоже сохраняем:
             * если в списке указана сама CDN-зона, пин по ней должен работать. */
            if (qname[0])
                stored += dns_store(qname, ip, ttl, ESRC_DNS);
            if (aname[0] && strcasecmp(aname, qname) != 0)
                stored += dns_store(aname, ip, ttl, ESRC_DNS);
        }
        off += rdlen;
    }
    return stored;
}

/* Открыть сокет на конкретном интерфейсе. 0 = слушаем.
 *
 * Протокол — ETH_P_ALL, а не ETH_P_IP. Причина измерена на живом роутере:
 * ответ DNS, который роутер отдаёт клиенту (br0 Out / eth2.1 Out / eth2 Out),
 * у локально сгенерированного пакета идёт с skb->protocol, не выставленным в
 * ETH_P_IP, и сокет, привязанный к ETH_P_IP, такие кадры не получает вовсе —
 * видны только входящие запросы (br0 In). tcpdump, привязанный к ETH_P_ALL,
 * те же ответы видит. Поэтому слушаем всё, а нужное отбираем разбором. */
static int sniff_bind(const char *name)
{
    unsigned idx;
    int fd;
    struct sockaddr_ll sll;

    if (g_nfd >= DNS_MAX_IFACES)
        return -1;
    idx = if_nametoindex(name);
    if (idx == 0)
        return -1;                  /* интерфейса сейчас нет */
    fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
    if (fd < 0)
        return -1;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = (int)idx;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
        slogf(SL_WARN, "dns_sniff: не привязаться к %s — пропускаю", name);
        close(fd);
        return -1;
    }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    g_fds[g_nfd] = fd;
    snprintf(g_open[g_nfd], sizeof(g_open[0]), "%s", name);
    g_c_if_q[g_nfd] = g_c_if_a[g_nfd] = 0;   /* слот новый — счётчики с нуля */
    g_nfd++;
    slogf(SL_INFO, "dns_sniff: слушаю DNS на %s", name);
    return 0;
}

static int sniff_is_open(const char *name)
{
    int i;
    for (i = 0; i < g_nfd; i++)
        if (!strcmp(g_open[i], name))
            return 1;
    return 0;
}

/* Интерфейс, который только что отвалился, не пытаемся открыть заново на
 * каждом reconcile: иначе bind/close крутятся в цикле, а лог заполняется
 * строками «слушаю DNS на …». Пауза в пару минут, затем одна повторная
 * попытка — интерфейс мог вернуться (радио подняли, порт воткнули). */
#define SNIFF_COOL_SEC 120
static struct { char name[32]; time_t until; } g_cool[DNS_MAX_IFACES];

static int sniff_cooled(const char *name)
{
    int i;
    time_t now = time(NULL);
    for (i = 0; i < DNS_MAX_IFACES; i++)
        if (g_cool[i].name[0] && !strcmp(g_cool[i].name, name))
            return now < g_cool[i].until;
    return 0;
}

static void sniff_cool(const char *name)
{
    int i, slot = -1;

    for (i = 0; i < DNS_MAX_IFACES; i++) {
        if (!g_cool[i].name[0]) {
            if (slot < 0)
                slot = i;
            continue;
        }
        if (!strcmp(g_cool[i].name, name)) {
            slot = i;
            break;
        }
    }
    if (slot < 0)
        slot = 0;
    snprintf(g_cool[slot].name, sizeof(g_cool[0].name), "%.31s", name);
    g_cool[slot].until = time(NULL) + SNIFF_COOL_SEC;
}

/* Открыть один интерфейс из конфига. Мост раскрывать в порты не нужно:
 * с сокетом ETH_P_ALL ответ DNS виден и на самом br* (проверено tcpdump-ом:
 * «br0 Out IP 192.168.1.1.53 > клиент»), а порты/родители VLAN только давали
 * бы дубли и лишний объём. */
static int sniff_open_one(const char *name)
{
    if (sniff_cooled(name)) {
        slogf(SL_DEBUG, "dns_sniff: %s недавно отвалился — пропускаю", name);
        return 0;
    }
    if (sniff_is_open(name))
        return 1;
    if (if_nametoindex(name) == 0) {
        slogf(SL_DEBUG, "dns_sniff: %s сейчас нет — пропускаю", name);
        return 0;
    }
    return sniff_bind(name) == 0;
}

/* Раскрыть шаблон ("oc+", "wdtt*") по фактическим интерфейсам и открыть
 * недостающие. Клиент OpenConnect создаёт ocN только при подключении, поэтому
 * проверяем это периодически (в reconcile), а не только на старте. */
static void sniff_try_name(const char *name)
{
    if (strpbrk(name, "+*") != NULL) {
        char prefix[64];
        size_t n = strcspn(name, "+*");
        DIR *d;
        struct dirent *de;
        if (n >= sizeof(prefix))
            n = sizeof(prefix) - 1;
        memcpy(prefix, name, n);
        prefix[n] = '\0';
        d = opendir("/sys/class/net");
        if (!d)
            return;
        while ((de = readdir(d)) != NULL && g_nfd < DNS_MAX_IFACES) {
            if (de->d_name[0] == '.')
                continue;
            if (strncmp(de->d_name, prefix, n) != 0)
                continue;
            sniff_open_one(de->d_name);
        }
        closedir(d);
        return;
    }
    sniff_open_one(name);
}

/* Пройтись по списку интерфейсов из конфига и дооткрыть недостающие. */
static void sniff_sync(const susanin_config *cfg)
{
    char list[256];
    const char *p;

    if (cfg->dns_sniff_iface[0])
        snprintf(list, sizeof(list), "%s", cfg->dns_sniff_iface);
    else
        snprintf(list, sizeof(list), "%s", cfg->lan_interfaces);
    p = list;
    while (*p && g_nfd < DNS_MAX_IFACES) {
        char name[64];
        size_t l = 0;
        while (*p == ',' || *p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        while (*p && *p != ',' && *p != ' ' && *p != '\t' &&
               l < sizeof(name) - 1)
            name[l++] = *p++;
        name[l] = '\0';
        if (name[0])
            sniff_try_name(name);
    }
}

int dns_sniff_start(const susanin_config *cfg)
{
    if (g_started)
        return 0;
    /* Счётчики — с нуля: сводка должна описывать текущий запуск, а не
     * сумму с предыдущего (после stop/start смешивать их было бы нельзя). */
    g_c_frames = g_c_udp53 = g_c_queries = g_c_answers = 0;
    g_c_parse_fail = g_c_stored = g_c_capped = 0;
    g_c_sni_seen = g_c_sni_named = g_c_sni_stored = 0;
    memset(g_c_if_q, 0, sizeof(g_c_if_q));
    memset(g_c_if_a, 0, sizeof(g_c_if_a));
    g_cfg = cfg;
    g_nfd = 0;
    sniff_sync(cfg);
    if (g_nfd == 0) {
        slogf(SL_WARN, "dns_sniff: не привязаться ни к одному интерфейсу — выключено");
        return -1;
    }
    g_started = 1;
    return 0;
}

/* Применение dns_sniff=1/0 из Reload. Прежний вариант вызывал start один раз
 * при старте службы: включение снифера из панели отображалось в статусе как
 * «dns_sniff=1», сокеты при этом не открывались, и в логе не было ни строки
 * про то, что фича не работает. */
void dns_sniff_reload(const susanin_config *cfg)
{
    if (cfg->dns_sniff || cfg->sni_sniff) {
        if (!g_started) {
            if (dns_sniff_start(cfg) == 0)
                slogf(SL_INFO, "dns_sniff: включён reload-ом");
        }
    } else if (g_started) {
        dns_sniff_stop();
        slogf(SL_INFO, "dns_sniff: выключён reload-ом (сокеты закрыты)");
    }
}

/* Закрыть сокет и убрать его из массива (интерфейс исчез). */
static void sniff_drop(int f)
{
    int i;
    char gone[sizeof(g_open[0])];

    snprintf(gone, sizeof(gone), "%s", g_open[f]);
    if (g_fds[f] >= 0)
        close(g_fds[f]);
    for (i = f; i < g_nfd - 1; i++) {
        g_fds[i] = g_fds[i + 1];
        memcpy(g_open[i], g_open[i + 1], sizeof(g_open[0]));
        g_c_if_q[i] = g_c_if_q[i + 1];
        g_c_if_a[i] = g_c_if_a[i + 1];
    }
    g_nfd--;
    if (g_nfd >= 0 && g_nfd < DNS_MAX_IFACES) {
        g_fds[g_nfd] = -1;
        g_open[g_nfd][0] = '\0';
        g_c_if_q[g_nfd] = g_c_if_a[g_nfd] = 0;
    }
    if (gone[0])
        sniff_cool(gone);       /* не переоткрывать на каждом reconcile */
}

void dns_sniff_stop(void)
{
    int i;
    for (i = 0; i < g_nfd; i++)
        if (g_fds[i] >= 0)
            close(g_fds[i]);
    for (i = 0; i < DNS_MAX_IFACES; i++) {
        g_fds[i] = -1;
        g_open[i][0] = '\0';
    }
    g_nfd = 0;
    g_started = 0;
    for (i = 0; i < 2; i++) {          /* кэш списков — освобождаем */
        if (lc[i].data) {
            free(lc[i].data);
            lc[i].data = NULL;
        }
        lc[i].path[0] = '\0';
        lc[i].mtime = lc[i].size = 0;
    }
}

/* Один IP-пакет с LAN: если это ClientHello к 443, положить «домен -> IP»
 * в таблицу. Домены из TLS не зависят от DNS (работает и при DoH/DoT). */
static void sni_take_packet(const unsigned char *ip, size_t len)
{
    size_t ihl, doff;
    const unsigned char *tcp, *payload;
    unsigned dport;
    uint32_t dst4;
    size_t plen;
    char name[256], dst[16];

    if (len < 20 || (ip[0] >> 4) != 4)
        return;
    ihl = (size_t)(ip[0] & 0x0f) * 4;
    if (ihl < 20 || ihl + 20 > len || ip[9] != 6)
        return;
    if ((((unsigned)ip[6] << 8) | ip[7]) & 0x1fff)   /* осколки не собираем */
        return;
    tcp = ip + ihl;
    dport = ((unsigned)tcp[2] << 8) | tcp[3];
    if (dport != 443)
        return;
    doff = (size_t)(tcp[12] >> 4) * 4;
    if (doff < 20 || ihl + doff > len)
        return;
    payload = tcp + doff;
    plen = len - ihl - doff;
    if (plen < 9 || payload[0] != 0x16 || payload[5] != 0x01)
        return;
    g_c_sni_seen++;
    if (!sni_parse_client_hello(payload, plen, name, sizeof(name)))
        return;
    g_c_sni_named++;
    if (!inet_ntop(AF_INET, ip + 16, dst, sizeof(dst)))
        return;
    /* Приватные/петлевые/link-local/multicast назначения — не «имя из сети»:
     * LAN-принтер, роутер, соседний контейнер. Обучение такой фильтр уже
     * применяет (clf_is_private4), и SNI-наблюдение не должно быть слабее —
     * иначе самоутверждённое имя запинит внутренний адрес. */
    dst4 = ((uint32_t)ip[16] << 24) | ((uint32_t)ip[17] << 16) |
           ((uint32_t)ip[18] << 8) | (uint32_t)ip[19];
    if (clf_is_private4(dst4))
        return;
    dns_sniff_note_name(name, dst, 0);   /* g_c_sni_stored считает dns_store */
}

void dns_sniff_poll(void)
{
    uint8_t buf[2048];
    int f;

    if (!g_started || g_nfd <= 0)
        return;
    /* Пины, применённые сразу при DNS-ответе, копятся в один батч ipset:
     * без него каждый пин был бы отдельным fork'ом ipset. */
    backend_batch_begin();
    for (f = 0; f < g_nfd; ) {
        int guard = 0, dropped = 0;
        while (guard++ < 128) {
            ssize_t r = recv(g_fds[f], buf, sizeof(buf), 0);
            unsigned ihl, ulen;
            if (r == 0)
                break;
            if (r < 0) {
                /* ENODEV/EBADF — интерфейс правда исчез: закрываем сокет, чтобы
                 * не копить мёртвые fd; reconcile откроет заново, когда он
                 * появится (с паузой, см. sniff_cool). ENETDOWN — интерфейс
                 * есть, но лежит (радио без клиентов, порт без линка): сокет
                 * оставляем, иначе bind/close крутится каждые 10 с. */
                if (errno == ENODEV || errno == EBADF) {
                    sniff_drop(f);
                    dropped = 1;
                }
                break;
            }
            g_c_frames++;
            /* Кадр может прийти с 4-байтовым тегом VLAN (если интерфейс задан
             * VLAN-подынтерфейсом): сдвигаем начало разбора. */
            {
                const uint8_t *ip = buf;
                ssize_t n = r;
                unsigned udp_off;
                int ver;
                if (n >= 4 && ip[0] == 0x81 && ip[1] == 0x00) {
                    ip += 4;
                    n -= 4;
                }
                if (n < 20)
                    continue; /* ниже любого заголовка: разница frames-udp53 покажет */
                ver = ip[0] >> 4;
                if (ver == 6) {
                    /* IPv6: клиенты Keenetic получают DNS-сервер по RA и ходят
                     * на link-local адрес роутера, поэтому ответы резолвера
                     * приходят в IPv6 — без этой ветки сокет их видит, но
                     * разбор молча пропускал (и «ответов нет» врало). Заголовок
                     * IPv6 фиксированный (40 байт); расширения не разбираем:
                     * next-header не UDP — не наш кадр. Порты и длина — те же
                     * поля UDP, что и в IPv4, поэтому дальше разбор общий. */
                    if (n < 40 || ip[6] != 17)
                        continue;
                    udp_off = 40;
                } else if (ver == 4) {
                    ihl = (unsigned)(ip[0] & 0x0f) * 4;
                    if (ihl < 20 || (ssize_t)ihl + 8 > n)
                        continue;
                    if (ip[9] == 6) {
                        /* TCP: здесь только SNI. sni_take_packet ждёт IPv4. */
                        if (g_cfg && g_cfg->sni_sniff)
                            sni_take_packet(ip, (size_t)n);
                        continue;
                    }
                    if (ip[9] != 17)
                        continue; /* не UDP: видно как разница frames/udp53 */
                    udp_off = ihl;
                } else {
                    continue;
                }
                {
                    const uint8_t *udp = ip + udp_off;
                    const uint8_t *dns;
                    uint16_t sp = (uint16_t)((udp[0] << 8) | udp[1]);
                    uint16_t dp = (uint16_t)((udp[2] << 8) | udp[3]);
                    int dlen, rv;
                    if (sp != 53 && dp != 53)
                        continue;         /* UDP, но не DNS-порт (DoT/QUIC-шум) */
                    g_c_udp53++;
                    ulen = (unsigned)((udp[4] << 8) | udp[5]);
                    if (ulen < 8 || udp_off + ulen > (unsigned)n) {
                        g_c_parse_fail++;
                        continue;
                    }
                    dns = udp + 8;
                    dlen = (int)(ulen - 8);
                    if (dlen < 12) {
                        g_c_parse_fail++; /* заголовок DNS не читается целиком */
                        continue;
                    }
                    if (!(dns[2] & 0x80)) {
                        /* Запрос: пинить по нему нечего — адрес придёт с ответом.
                         * Но считать надо: «запросы видим, ответов нет» — отдельный
                         * диагноз, раньше он был неотличим от мусора. */
                        g_c_queries++;
                        g_c_if_q[f]++;
                        continue;
                    }
                    g_c_answers++;
                    g_c_if_a[f]++;
                    rv = dns_parse(dns, dlen);
                    if (rv < 0)
                        g_c_parse_fail++;
                }
            }
        }
        if (guard > 128)
            g_c_capped++;     /* приёмников больше, чем забираем за проход */
        if (!dropped)
            f++;
    }
    backend_batch_end();
}

static int zone_match(const char *domain, const char *zone_in)
{
    char zone[DNS_DOMAIN_MAX];
    size_t dl, zl;
    unsigned i;
    /* zone_in уже приведён к нижнему регистру при загрузке кэша списка —
     * tolower на каждую зону на каждую запись раньше стоил заметной доли
     * reconcile. */
    for (i = 0; zone_in[i] && i < sizeof(zone) - 1; i++)
        zone[i] = zone_in[i];
    zone[i] = '\0';
    if (zone[0] == '*') {
        const char *z = zone + 1;
        while (*z == '.')
            z++;
        memmove(zone, z, strlen(z) + 1);
    }
    dl = strlen(domain);
    zl = strlen(zone);
    if (zl == 0 || dl < zl)
        return 0;
    if (!strcasecmp(domain, zone))
        return 1;
    if (dl > zl && domain[dl - zl - 1] == '.' &&
        !strcasecmp(domain + dl - zl, zone))
        return 1;
    return 0;
}

static const char *list_cache(int slot, const char *file)
{
    lcache *c;
    struct stat sb;
    FILE *fp;
    char line[320];
    char *buf;
    size_t cap = 2048, len = 0;

    if (slot < 0 || slot > 1 || !file || !file[0])
        return NULL;
    c = &lc[slot];
    if (c->data && !strcmp(c->path, file) && stat(file, &sb) == 0 &&
        c->mtime == (long long)sb.st_mtime && c->size == (long long)sb.st_size)
        return c->data;
    if (c->data) {
        free(c->data);
        c->data = NULL;
    }
    c->path[0] = '\0';
    fp = fopen(file, "r");
    if (!fp)
        return NULL;
    buf = malloc(cap);
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    buf[0] = '\0';
    /* Единая грамматика списка для всех читателей: строку разбирает
     * entry_parse — тот же разбор, что у vpn_always/vpn_never. Раньше этот
     * кэш принимал всё, что не похоже на CIDR/IPv6, и расходился с
     * движком списков: "?domain" (мягкая запись) здесь работала, в
     * vpn_never — нет, "*domain" без точки совпадало здесь и отбрасывалось
     * там. Что entry_parse отверг — мусор и для сверки пинов. */
    while (fgets(line, sizeof(line), fp)) {
        char entry[288];
        char clean[256];
        int wild = 0, net = 0, soft = 0;
        size_t l;
        if (!entry_parse(line, clean, sizeof(clean), &wild, &net, &soft))
            continue;
        if (net)
            continue;               /* CIDR — не домен */
        if (soft && slot != 0)
            continue;               /* '?' осмысленна только в vpn_always */
        snprintf(entry, sizeof(entry), "%s%s%s",
                 soft ? "?" : "", wild ? "*." : "", clean);
        l = strlen(entry);
        if (len + l + 2 > cap) {
            char *nb;
            cap = (len + l + 2) * 2;
            nb = realloc(buf, cap);
            if (!nb)
                break;
            buf = nb;
        }
        memcpy(buf + len, entry, l);
        len += l;
        buf[len++] = '\n';
        buf[len] = '\0';
    }
    fclose(fp);
    c->data = buf;
    snprintf(c->path, sizeof(c->path), "%s", file);
    if (stat(file, &sb) == 0) {
        c->mtime = (long long)sb.st_mtime;
        c->size = (long long)sb.st_size;
    } else {
        c->mtime = 0;
        c->size = 0;
    }
    g_list_gen++;   /* список перечитан — кэш вердиктов записей недействителен */
    return c->data;
}

static int list_match(int slot, const char *file, const char *domain)
{
    const char *data, *p;
    char line[320];

    if (!file || !file[0])
        return 0;
    data = list_cache(slot, file);
    if (!data)
        return 0;
    p = data;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t l = nl ? (size_t)(nl - p) : strlen(p);
        if (l >= sizeof(line))
            l = sizeof(line) - 1;
        memcpy(line, p, l);
        line[l] = '\0';
        if (line[0] == '?') {
            if (zone_match(domain, line + 1))
                return 2;   /* мягкая запись: не пинить, guard не запирает */
        } else if (line[0] && zone_match(domain, line)) {
            return 1;
        }
        if (!nl)
            break;
        p = nl + 1;
    }
    return 0;
}

/* Мягкая запись (?domain) в vpn_always: RU-guard такую не запирает напрямую,
 * чтобы у домена остался VPN-фолбэк на случай деградации прямого пути. */
int dns_sniff_is_soft_domain(const susanin_config *cfg, const char *dom)
{
    if (!cfg || !dom || !dom[0])
        return 0;
    return list_match(0, cfg->vpn_always_file, dom) == 2;
}

/* Внешний источник имени (SNI из TLS ClientHello): кладём пару «домен -> IP»
 * в ту же таблицу, что и DNS-ответы, помечая источник как более слабый:
 * это самоутверждение клиента. Дальше всё работает единообразно: списки
 * пинятся сразу, ru_guard видит домен, в логе появляется «(домен)»;
 * бессрочный never-пин, снятие чужих пинов и обрыв соединений SNI не делает.
 * Возврат 1 = пара попала в таблицу. */
int dns_sniff_note_name(const char *domain, const char *ip, int ttl)
{
    if (!domain || !domain[0] || !ip || !ip[0])
        return 0;
    if (ttl <= 0)
        ttl = (g_cfg && g_cfg->dns_sniff_ttl > 0) ? g_cfg->dns_sniff_ttl : 300;
    return dns_store(domain, ip, ttl, ESRC_SNI);
}

void dns_sniff_set_state(susanin_state *st)
{
    g_state = st;
}

void dns_sniff_reset_pins(void)
{
    int i;
    /* Пины в ipset'ах сброшены (flush) — снимаем флаги, чтобы reconcile
     * применил их заново. Значения из state при этом уже восстановлены. */
    for (i = 0; i < DNS_MAX_ENTRIES; i++) {
        g_tab[i].pinned = 0;
        g_tab[i].pinned_never = 0;
    }
}

/* Другая живая запись с тем же IP всё ещё покрывается списком (slot 0=always,
 * 1=never) — тогда пин снимать нельзя, только сбросить флаг у нашей записи. */
static int other_entry_matches(time_t now, int skip, int slot,
                               const susanin_config *cfg, const char *ip)
{
    int i;
    for (i = 0; i < DNS_MAX_ENTRIES; i++) {
        dns_entry *e = &g_tab[i];
        if (i == skip || !e->domain[0] || e->expire <= now || strcmp(e->ip, ip) != 0)
            continue;
        if (slot == 0) {
            if (e->pinned && list_match(0, cfg->vpn_always_file, e->domain))
                return 1;
        } else {
            /* never-пин ставится и по ru_guard_direct (без vpn_never) — учитываем,
             * иначе при ротации общего CDN-IP снимали бы чужой RU-пин. */
            int ru = cfg->ru_guard && cfg->ru_guard_direct &&
                     dns_sniff_is_ru_domain(cfg, e->domain) &&
                     !list_match(0, cfg->vpn_always_file, e->domain);
            if (e->pinned_never &&
                (list_match(1, cfg->vpn_never_file, e->domain) || ru))
                return 1;
        }
    }
    return 0;
}

/* Вердикты записи по спискам — из кэша; пересчёт только при смене поколения
 * списков (файлы vpn_always/vpn_never перечитаны или изменён набор RU-TLD). */
static void entry_verdicts(const susanin_config *cfg, dns_entry *e)
{
    if (e->vgen == g_list_gen && e->v_always >= 0)
        return;
    {
        int m = list_match(0, cfg->vpn_always_file, e->domain);
        e->v_always = (signed char)(m != 0);
        e->v_soft = (signed char)(m == 2);
    }
    e->v_never = (signed char)list_match(1, cfg->vpn_never_file, e->domain);
    e->v_ru = (signed char)dns_sniff_is_ru_domain(cfg, e->domain);
    e->vgen = g_list_gen;
}

/* Применить решения по одной записи: вызывается и периодическим reconcile, и
 * сразу из dns_store (C1) — новый домен из списка уезжает в туннель/прямой
 * с первого соединения, а не через окно до 10 с. */
static void reconcile_entry(const susanin_config *cfg, dns_entry *e, int i,
                            time_t now)
{
    int va, ru_force;
    if (!cfg || !e->domain[0] || e->expire <= now)
        return;
    entry_verdicts(cfg, e);
    va = e->v_always && !e->v_soft;
    if (!e->pinned && va) {
        backend_ok_pin_add(cfg, e->ip, cfg->ok_ttl);
        e->pinned = 1;
        if (g_state) {                      /* переживёт re-provision/рестарт */
            /* Тот же срок, что и в ipset (ok_ttl), и только продление:
             * state_touch создаёт запись или продлевает существующую. */
            state_touch(st_ok(g_state, 0), e->ip, now, cfg->ok_ttl);
            state_touch(st_ok(g_state, 1), e->ip, now, cfg->ok_ttl);
        }
        slogf(SL_INFO, "dns-sniff: %s -> %s pinned (vpn_always)", e->domain, e->ip);
    }
    /* r7.8: RU-домены — активный direct (пин в never), а не только
     * «не учить»: IP .рф-сайта может совпадать с выученным VPN-адресом
     * чужого сервиса (общий CDN/хостинг) и уезжать в туннель вместе с
     * ним. Ручной vpn_always для конкретного домена сильнее guard'а. */
    ru_force = cfg->ru_guard && cfg->ru_guard_direct && e->v_ru && !va && !e->v_soft;
    if (!e->pinned_never && (e->v_never || ru_force)) {
        /* Бессрочный never — только когда за направлением стоит решение
         * оператора (vpn_never) и имя подтверждено DNS-ответом. SNI-пара по
         * ru_guard живёт ровно dns_sniff_ttl: клиент мог назвать что угодно. */
        int nttl = 0;
        if (e->src == ESRC_SNI && !e->v_never)
            nttl = cfg->dns_sniff_ttl > 0 ? cfg->dns_sniff_ttl : CFG_DEF_DNS_SNIFF_TTL;
        backend_set_add(cfg, "susanin_never", e->ip, nttl);
        e->pinned_never = 1;
        if (g_state)
            /* В ipset и в state — одинаковый срок (0 = бессрочно). */
            state_touch(&g_state->never, e->ip, now, nttl);
        /* Конфликт ok <-> never: адрес мог быть уже выучен в VPN — снимаем
         * и рвём его соединения, иначе «прямо» не заработает.
         * Обрыв (ct_flush) делает только DNS-подтверждённая запись: по
         * самоутверждённому имени рвать живые соединения соседа нельзя
         * (сам пин при этом TTL-ограничен и снимется сам). */
        if (g_state) {
            if (state_has(st_ok(g_state, 0), e->ip, now) ||
                state_has(st_ok(g_state, 1), e->ip, now) ||
                state_has(st_test(g_state, 0), e->ip, now) ||
                state_has(st_test(g_state, 1), e->ip, now)) {
                state_remove(st_ok(g_state, 0), e->ip);
                state_remove(st_ok(g_state, 1), e->ip);
                state_remove(st_test(g_state, 0), e->ip);
                state_remove(st_test(g_state, 1), e->ip);
                backend_ok_pin_del(cfg, e->ip);
                if (e->src != ESRC_SNI)
                    backend_ct_flush_ip(e->ip);
                slogf(SL_INFO, "dns-sniff: %s -> %s снят из VPN (конфликт с vpn_never)%s",
                      e->domain, e->ip, e->src == ESRC_SNI ? ", соединения не рву" : "");
            }
        }
        slogf(SL_INFO, "dns-sniff: %s -> %s (%s%s)", e->domain, e->ip,
              e->v_never ? "vpn_never" : "ru-guard",
              nttl > 0 ? ", SNI — только на TTL" : "");
    }
    /* Снятие пина, когда записи УЖЕ НЕТ в списке: раньше dns_sniff-пин
     * переживал удаление строки (never — бессрочно, always — до ok_ttl),
     * и пользователь не мог «отпустить» адрес правкой списка
     * Флаг сбрасываем в любом случае;
     * сам пин — только если его не держит другая живая запись. */
    if (e->pinned && !va) {
        e->pinned = 0;
        if (!other_entry_matches(now, i, 0, cfg, e->ip)) {
            backend_ok_pin_del(cfg, e->ip);
            if (g_state) {
                state_remove(st_ok(g_state, 0), e->ip);
                state_remove(st_ok(g_state, 1), e->ip);
            }
            slogf(SL_INFO, "dns-sniff: %s -> %s unpinned (нет в vpn_always)",
                  e->domain, e->ip);
        }
    }
    if (e->pinned_never && !e->v_never && !ru_force) {
        e->pinned_never = 0;
        if (!other_entry_matches(now, i, 1, cfg, e->ip)) {
            backend_set_del(cfg, "susanin_never", e->ip);
            if (g_state)
                state_remove(&g_state->never, e->ip);
            /* Обрыв соединений — действие уровня DNS-доверия (см. выше). */
            if (e->src != ESRC_SNI)
                backend_ct_flush_ip(e->ip);
            slogf(SL_INFO, "dns-sniff: %s -> %s unpinned (нет в vpn_never)",
                  e->domain, e->ip);
        }
    }
}

void dns_sniff_reconcile(const susanin_config *cfg)
{
    int i;
    time_t now = time(NULL);
    if (!g_started)
        return;
    /* Клиент OpenConnect создаёт ocN только при подключении, а шаблон "oc+"
     * нельзя привязать напрямую (if_nametoindex("oc+") == 0): дооткрываем
     * появившиеся интерфейсы здесь, не дожидаясь перезапуска агента. */
    sniff_sync(cfg);
    /* Пины этого прохода — одним батчем (ipset restore): без него каждый пин
     * это отдельный fork ipset, а с 0.4.6 dns_store пишет и qname, и CNAME —
     * записей вдвое больше. Вне batch буфер копит и nothing-операции — конец
     * обязан быть строго после begin. */
    backend_batch_begin();
    for (i = 0; i < DNS_MAX_ENTRIES; i++) {
        dns_entry *e = &g_tab[i];
        if (!e->domain[0] || e->expire <= now)
            continue;
        reconcile_entry(cfg, e, i, now);
    }
    backend_batch_end();
    /* r5.4: счётчик «RU в VPN» для панели (не чаще раза в минуту). */
    dns_sniff_ru_audit(cfg);
}

int dns_sniff_count(void)
{
    int i, n = 0;
    time_t now = time(NULL);
    for (i = 0; i < DNS_MAX_ENTRIES; i++)
        if (g_tab[i].domain[0] && g_tab[i].expire > now)
            n++;
    return n;
}

/* Сводка по пути «кадр -> запись»: имена счётчиков читаются без исходников,
 * а порядок = порядок шагов разбора. Как читать одну строку:
 *   frames=0                      — на захвате тишина (или дом молчит);
 *   frames растёт, udp53=0        — трафик есть, но не DNS/53: DoT/DoH/QUIC,
 *                                   TLS (см. sni_*), чужие порты или редкое
 *                                   «кадр не с IP-заголовка»;
 *   queries>0, answers=0          — запросы видим, ответов не видим
 *                                   (на тех же интерфейсах или вообще);
 *   answers>0, parse_fail>0       — ответы есть, но сообщения битые/обрезаны;
 *   answers>0, parse_fail=0,
 *   stored=0                      — ответы честные, но A-записей в них нет
 *                                   (AAAA/NXDOMAIN/DoH) — разбору ломаться
 *                                   не на чем;
 *   capped>0                      — приёмников больше, чем забираем за
 *                                   проход, сводка отстаёт от реальности.
 * Разбивка «(br0:140,br1:2)» при queries/answers — кто из интерфейсов видел;
 * ifs= — что вообще слушается в этот момент (появляются oc+ после подъёма
 * VPN). SNI-шаги свои: seen = разобран ClientHello, named = имя признано
 * доменом, stored = пара легла в таблицу (между named и stored стоит ещё
 * фильтр приватных адресов). */
static void stat_cat(char *out, size_t n, int *used, const char *fmt, ...)
{
    va_list ap;
    int w;

    if (*used < 0 || (size_t)*used >= n)
        return;               /* месту не хватило: строка остаётся обрезанной */
    va_start(ap, fmt);
    w = vsnprintf(out + *used, n - (size_t)*used, fmt, ap);
    va_end(ap);
    if (w < 0) {
        *used = -1;
        return;
    }
    *used += w;               /* может превысить n — это знак «обрезано» */
}

/* Разбивка счётчика по интерфейсам захвата: "(br0:140,br1:2)". Нулевые и
 * безымянные слоты не печатаются — пустая разбивка означает «никто не видел». */
static void stat_ifaces(char *out, size_t n, int *used, const unsigned long *cnt)
{
    int i, any = 0;
    for (i = 0; i < g_nfd && i < DNS_MAX_IFACES; i++) {
        if (!cnt[i] || !g_open[i][0])
            continue;
        stat_cat(out, n, used, any ? ",%s:%lu" : "(%s:%lu", g_open[i], cnt[i]);
        any = 1;
    }
    if (any)
        stat_cat(out, n, used, ")");
}

int dns_sniff_stats(char *out, size_t n)
{
    int i, used;

    if (!out || n == 0)
        return 0;
    out[0] = '\0';
    used = snprintf(out, n, "frames=%lu udp53=%lu queries=%lu",
                    g_c_frames, g_c_udp53, g_c_queries);
    if (used < 0) {
        out[0] = '\0';
        return 0;
    }
    stat_ifaces(out, n, &used, g_c_if_q);
    stat_cat(out, n, &used, " answers=%lu", g_c_answers);
    stat_ifaces(out, n, &used, g_c_if_a);
    stat_cat(out, n, &used,
             " parse_fail=%lu stored=%lu capped=%lu table=%d"
             " sni_seen=%lu sni_named=%lu sni_stored=%lu ifs=",
             g_c_parse_fail, g_c_stored, g_c_capped, dns_sniff_count(),
             g_c_sni_seen, g_c_sni_named, g_c_sni_stored);
    for (i = 0; i < g_nfd && i < DNS_MAX_IFACES; i++)
        stat_cat(out, n, &used, i ? ",%s" : "%s", g_open[i]);
    if (!g_nfd)
        stat_cat(out, n, &used, "-");
    return (int)(g_c_frames + g_c_stored + g_c_sni_stored);
}

/* Структурный срез для WARN-диагностики движка: разбирать сводку по
 * подстрокам нельзя — она форматируется для чтения человеком. */
void dns_sniff_get_counters(dns_sniff_counters *c)
{
    int i;

    if (!c)
        return;
    memset(c, 0, sizeof(*c));
    c->frames = g_c_frames;
    c->udp53 = g_c_udp53;
    c->queries = g_c_queries;
    c->answers = g_c_answers;
    c->parse_fail = g_c_parse_fail;
    c->stored = g_c_stored;
    c->capped = g_c_capped;
    c->niface = g_nfd;
    for (i = 0; i < g_nfd && i < DNS_SNIFF_MAX_IFACES; i++) {
        snprintf(c->name[i], sizeof(c->name[i]), "%.15s", g_open[i]);
        c->iface_queries[i] = g_c_if_q[i];
        c->iface_answers[i] = g_c_if_a[i];
    }
}

int dns_sniff_domain_of(const char *ip, char *domain_out, unsigned n)
{
    int i;
    time_t now = time(NULL);
    if (domain_out && n)
        domain_out[0] = '\0';
    if (!ip)
        return 0;
    for (i = 0; i < DNS_MAX_ENTRIES; i++) {
        dns_entry *e = &g_tab[i];
        if (e->domain[0] && e->expire > now && !strcmp(e->ip, ip)) {
            if (domain_out && n)
                snprintf(domain_out, n, "%s", e->domain);
            return 1;
        }
    }
    return 0;
}

/* --- r5: RU-домены -------------------------------------------------------- */

/* Суффикс-матчер TLD из cfg->ru_guard_tlds (".ru,.рф,.xn--p1ai,..."):
 * сравнение регистронезависимое, совпадение только по границе метки.
 * Список TLD разбирается один раз и кэшируется: прежняя версия копировала
 * строку конфига и strtok'ила её на каждый вызов (вызов — на каждую запись
 * reconcile и в классификаторе). При изменении набора увеличивается
 * поколение списков — кэш вердиктов dns_entry сбрасывается. */
int dns_sniff_is_ru_domain(const susanin_config *cfg, const char *dom)
{
    static char tld_src[256];
    static char tld[16][64];
    static int tld_n;
    size_t dl;
    int i;
    if (!cfg || !dom || !dom[0] || !cfg->ru_guard_tlds[0])
        return 0;
    if (strcmp(tld_src, cfg->ru_guard_tlds) != 0) {
        char buf[256], *save = NULL, *tok;
        snprintf(tld_src, sizeof(tld_src), "%s", cfg->ru_guard_tlds);
        snprintf(buf, sizeof(buf), "%s", cfg->ru_guard_tlds);
        tld_n = 0;
        for (tok = strtok_r(buf, ",", &save); tok && tld_n < 16;
             tok = strtok_r(NULL, ",", &save)) {
            size_t tl, k;
            while (*tok == ' ' || *tok == '\t')
                tok++;
            tl = strlen(tok);
            if (!tl || tl >= sizeof(tld[0]))
                continue;
            for (k = 0; k < tl; k++)    /* храним в нижнем регистре */
                tld[tld_n][k] = (char)tolower((unsigned char)tok[k]);
            tld[tld_n][tl] = '\0';
            tld_n++;
        }
        g_list_gen++;
    }
    dl = strlen(dom);
    for (i = 0; i < tld_n; i++) {
        size_t tl = strlen(tld[i]);
        size_t k;
        if (!tl || dl < tl)
            continue;
        for (k = 0; k < tl; k++)
            if (tolower((unsigned char)dom[dl - tl + k]) != tld[i][k])
                break;
        if (k == tl)
            return 1;
    }
    return 0;
}

/* r5.4: аудит «российское в VPN». Считаем RU-домены из сниффера, чей IP
 * сейчас в ok_tcp (VPN), пишем счётчик и список в файл для веб-процесса
 * (панель — отдельный процесс, память сниффера ему недоступна). Не чаще
 * раза в минуту; файл перезаписываем только при изменении содержимого. */
void dns_sniff_ru_audit(const susanin_config *cfg)
{
    static char last[512];
    static time_t last_run;
    char line[512], tmp[544];
    int i, cnt = 0, used = 0;
    time_t now = time(NULL);
    char seen[16][DNS_DOMAIN_MAX];
    if (!cfg || !g_state || now - last_run < 60)
        return;
    last_run = now;
    line[0] = '\0';
    for (i = 0; i < DNS_MAX_ENTRIES; i++) {
        dns_entry *e = &g_tab[i];
        char kf[64];
        int j, dup = 0;
        if (!e->domain[0] || e->expire <= now)
            continue;
        if (!dns_sniff_is_ru_domain(cfg, e->domain))
            continue;
        state_key(kf, sizeof(kf), e->ip, 0);
        if (!state_has(&g_state->ok_tcp, kf, now)) {
            state_key(kf, sizeof(kf), e->ip, 443);
            if (!state_has(&g_state->ok_tcp, kf, now))
                continue;
        }
        for (j = 0; j < cnt; j++)
            if (!strcmp(seen[j], e->domain)) { dup = 1; break; }
        if (dup || cnt >= 16)
            continue;
        snprintf(seen[cnt++], DNS_DOMAIN_MAX, "%.*s", DNS_DOMAIN_MAX - 1, e->domain);
    }
    used = snprintf(line, sizeof(line), "%d", cnt);
    for (i = 0; i < cnt && used < (int)sizeof(line) - DNS_DOMAIN_MAX - 1; i++)
        used += snprintf(line + used, sizeof(line) - used, " %s", seen[i]);
    if (!strcmp(line, last))
        return;
    snprintf(last, sizeof(last), "%s", line);
    snprintf(tmp, sizeof(tmp), "/opt/susanin/var/ru-in-vpn");
    {
        char wp[560];
        FILE *f;
        snprintf(wp, sizeof(wp), "%s.tmp", tmp);
        f = fopen(wp, "w");
        if (f) {
            fprintf(f, "%s\n", line);
            fclose(f);
            rename(wp, tmp);
        }
    }
}

/* Путь снимка для текущего режима носителя: в soft снимок идёт в tmpfs и
 * флешку не трогает (смысл режима — отсутствие записей на носитель), но
 * наблюдаемость сохраняется: журнала в soft нет вовсе. */
const char *dns_sniff_stats_path(const susanin_config *cfg)
{
    if (cfg && !strcmp(cfg->disk_mode, "soft"))
        return DNS_SNIFF_SOFT_STATS_FILE;
    return DNS_SNIFF_STATS_FILE;
}

/* Снимок счётчиков для ДРУГИХ процессов (панель, `susanin-agent status`,
 * `susanin-agent why`): сводка живёт в памяти движка, и CLI-процесс,
 * прочитавший dns_sniff_stats(), увидел бы нули — ровно та ошибка, которую
 * нельзя повторять. Пишется так же, как ru-in-vpn: только при изменении и
 * атомарно. Путь зависит от disk_mode (см. dns_sniff_stats_path): на носителе
 * только для чтения fopen просто не получится — status честно скажет
 * «снимка нет». */
void dns_sniff_stats_write(const susanin_config *cfg)
{
    static char last[512];
    const char *path;
    char line[512], wp[544];
    FILE *f;

    if (!cfg)
        return;
    /* Снимок нужен любому активному источнику имени: счётчики SNI иначе
     * не наблюдались бы вовсе. */
    if (!cfg->dns_sniff && !cfg->sni_sniff) {
        if (last[0])
            last[0] = '\0';       /* выключили — пусть файл остынет последним */
        return;
    }
    dns_sniff_stats(line, sizeof(line));
    if (!strcmp(line, last))
        return;
    snprintf(last, sizeof(last), "%s", line);
    path = dns_sniff_stats_path(cfg);
    snprintf(wp, sizeof(wp), "%s.tmp", path);
    f = fopen(wp, "w");
    if (!f)
        return;
    fprintf(f, "%s\n", line);
    fclose(f);
    rename(wp, path);
}
