/* Тест счётчиков dns_sniff: цепочка «кадр -> запись» должна быть измеряемой
 * по шагам (frames/udp53/queries/answers/parse_fail/stored/capped), а не по
 * одному «recv», который рос до проверок протокола. Сводка сверяется с
 * структурным срезом dns_sniff_get_counters().
 * dns_sniff.c включается в TU, чтобы задать g_fds/g_open/g_nfd/g_started
 * напрямую; кадровый ввод — через два socketpair(AF_UNIX, SOCK_SEQPACKET):
 * границы датаргам сохранены (как у AF_PACKET), два «интерфейса» t0/t1
 * дают проверку разбивки по интерфейсам; реальный сетевой стек и
 * привилегии не нужны. SEQPACKET обязателен: на SOCK_STREAM recv() склеил
 * бы кадры, и разбивка «битый ответ/обрезанный» проверялась бы на удачу.
 * SNI-ветка тоже исполняется: g_cfg — живой конфиг-стакабель с
 * dns_sniff=1/sni_sniff=1, пустые vpn_always_file/vpn_never_file и
 * ru_guard_tlds => reconcile_entry не ставит пинов, ipset/iptables не
 * дёргает — тест остаётся хостовым.
 * make test (хост-компилятор; в поставку не входит).
 */
#define _GNU_SOURCE
#include "dns_sniff.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>

static int failures = 0;
#define CHECK(cond, msg) do { if (cond) printf("ok  %s\n", msg); \
    else { printf("FAIL %s\n", msg); failures++; } } while (0)

/* Сверка отдельного счётчика сводки: после числа может быть только
 * «пробел/(()конец)» — strstr("answers=1") пропустил бы answers=12. */
static int cnt_is(const char *line, const char *key, unsigned long want)
{
    char pat[64];
    const char *p;
    unsigned long v;
    char *end;

    snprintf(pat, sizeof(pat), "%s=", key);
    p = strstr(line, pat);
    if (!p)
        return 0;
    p += strlen(pat);
    v = strtoul(p, &end, 10);
    if (v != want)
        return 0;
    return *end == '\0' || *end == ' ' || *end == '(';
}

/* DNS-ответ: 1 вопрос (example.com A) + 1 A-запись 93.184.216.34, ANNAME —
 * указатель 0xc00c (сжатие), как в реальных ответах роутера. */
static const uint8_t DNS_RESP[] = {
    0x12, 0x34, 0x81, 0x80,             /* id, flags: QR=1 RD RA */
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    7, 'e','x','a','m','p','l','e', 3, 'c','o','m', 0,
    0x00, 0x01, 0x00, 0x01,              /* qtype A, qclass IN */
    0xC0, 0x0C,                          /* ANNAME — указатель на qname */
    0x00, 0x01, 0x00, 0x01,              /* type A, class IN */
    0x00, 0x00, 0x00, 0x3C,              /* TTL 60 */
    0x00, 0x04,                          /* RDLEN 4 */
    93, 184, 216, 34
};
#define DNS_LEN ((int)sizeof(DNS_RESP))
#define DNS_OFF 28                        /* смещение DNS внутри build_ip */

/* IPv4 + UDP(src 53) + DNS_RESP. Возвращает длину кадра. */
static int build_ip(uint8_t *b, int dstport)
{
    int iplen = 20, udplen = 8 + DNS_LEN, total = iplen + udplen;
    memset(b, 0, (size_t)total);
    b[0] = 0x45;                        /* ver 4, ihl 20 */
    b[2] = (uint8_t)(total >> 8); b[3] = (uint8_t)(total & 0xff);
    b[8] = 64;                          /* ttl */
    b[9] = 17;                          /* proto UDP */
    b[12] = 192, b[13] = 0, b[14] = 2, b[15] = 1;   /* src */
    b[16] = 192, b[17] = 0, b[18] = 2, b[19] = 2;   /* dst */
    b[20] = 0; b[21] = 53;              /* sport 53 */
    b[22] = (uint8_t)(dstport >> 8); b[23] = (uint8_t)(dstport & 0xff);
    b[24] = (uint8_t)(udplen >> 8); b[25] = (uint8_t)(udplen & 0xff);
    memcpy(b + DNS_OFF, DNS_RESP, DNS_LEN);
    return total;
}

/* Тот же кадр, но с Ethernet-заголовком спереди: ровно то, что выдаёт
 * версию «L2 не срезан» — должна отлавливаться как «не IP», а не молча. */
static int build_ethernet_prefixed(uint8_t *b)
{
    int n;
    memset(b, 0, 14);
    b[12] = 0x08; b[13] = 0x00;          /* ethertype IPv4 */
    n = build_ip(b + 14, 5353);
    return n + 14;
}

/* TLS ClientHello с SNI=sni.example.net (тот же разбор, что в test_snisniff,
 * в компактном виде одного расширения). */
static int build_hello_body(uint8_t *hs, const char *sni)
{
    size_t nl = strlen(sni);
    size_t bl = 0, ext_pos, sn_pos, el;
    hs[bl++] = 0x03; hs[bl++] = 0x03;
    for (size_t i = 0; i < 32; i++)
        hs[bl++] = (uint8_t)i;
    hs[bl++] = 0;                        /* session_id_len */
    hs[bl++] = 0; hs[bl++] = 2; hs[bl++] = 0x13; hs[bl++] = 1;
    hs[bl++] = 1; hs[bl++] = 0;          /* compression */
    ext_pos = bl; bl += 2;
    sn_pos = bl; bl += 4;
    hs[bl++] = (uint8_t)((nl + 3) >> 8); hs[bl++] = (uint8_t)((nl + 3) & 0xff);
    hs[bl++] = 0;                        /* host_name */
    hs[bl++] = (uint8_t)(nl >> 8); hs[bl++] = (uint8_t)nl;
    memcpy(hs + bl, sni, nl); bl += nl;
    el = bl - sn_pos - 4;
    hs[sn_pos] = 0; hs[sn_pos + 1] = 0;
    hs[sn_pos + 2] = (uint8_t)(el >> 8); hs[sn_pos + 3] = (uint8_t)(el & 0xff);
    el = bl - ext_pos - 2;
    hs[ext_pos] = (uint8_t)(el >> 8); hs[ext_pos + 1] = (uint8_t)(el & 0xff);
    return (int)bl;
}

/* IPv4 + TCP(dport 443) + record(0x16)+ClientHello, dst — указанный. */
static int build_tls_to(uint8_t *b, uint8_t d0, uint8_t d1, uint8_t d2, uint8_t d3)
{
    uint8_t hs[512];
    int hbl = build_hello_body(hs, "sni.example.net");
    int rec = 9 + hbl;                   /* record header + handshake */
    int total = 20 + 20 + rec;
    memset(b, 0, (size_t)total);
    b[0] = 0x45;
    b[2] = (uint8_t)(total >> 8); b[3] = (uint8_t)(total & 0xff);
    b[8] = 64;
    b[9] = 6;                            /* proto TCP */
    b[12] = 198; b[13] = 51; b[14] = 100; b[15] = 7;   /* src (клиент LAN) */
    b[16] = d0; b[17] = d1; b[18] = d2; b[19] = d3;    /* dst (сервер) */
    b[20] = 0; b[21] = 44353 % 256;      /* sport произвольный */
    b[22] = 1; b[23] = 0xbb;             /* dport 443 */
    b[32] = (uint8_t)(5 << 4);           /* doff = 20 */
    b[40] = 0x16; b[41] = 0x03; b[42] = 0x01;
    b[43] = (uint8_t)((hbl + 4) >> 8); b[44] = (uint8_t)((hbl + 4) & 0xff);
    b[45] = 0x01;                        /* handshake: ClientHello */
    b[46] = (uint8_t)((hbl >> 16) & 0xff);
    b[47] = (uint8_t)((hbl >> 8) & 0xff);
    b[48] = (uint8_t)(hbl & 0xff);
    memcpy(b + 49, hs, (size_t)hbl);
    return total;
}

/* Кадр на «интерфейс» iface (0=t0, 1=t1) и один проход poll. */
static int Wfd[2];                        /* пишущие концы — вне g_fds */
static void feed(int iface, const uint8_t *frame, int len)
{
    ssize_t w = write(Wfd[iface], frame, (size_t)len);
    (void)w;
    dns_sniff_poll();
}

/* Без poll() — накопить пачку на одном интерфейсе (проверка лимита прохода). */
static void feed_now(int iface, const uint8_t *frame, int len)
{
    ssize_t w = write(Wfd[iface], frame, (size_t)len);
    (void)w;
}

int main(void)
{
    int spA[2], spB[2];
    uint8_t buf[2048];
    char dom[DNS_DOMAIN_MAX];
    char st[512];
    susanin_config cfg;

    slog_init("quiet");
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, spA) != 0 ||
        socketpair(AF_UNIX, SOCK_SEQPACKET, 0, spB) != 0) {
        printf("FAIL socketpair недоступен\n");
        return 1;
    }
    /* Мини-запуск без start(): старт трогал бы AF_PACKET и привилегии.
     * Читающие концы обязательно non-blocking: poll() рассчитан на AF_PACKET,
     * а на блокирующем сокете recv() встал бы навечно после последнего кадра
     * (тест бы «висел», а не падал). */
    {
        int fl = fcntl(spA[0], F_GETFL, 0);
        if (fl >= 0)
            fcntl(spA[0], F_SETFL, fl | O_NONBLOCK);
        fl = fcntl(spB[0], F_GETFL, 0);
        if (fl >= 0)
            fcntl(spB[0], F_SETFL, fl | O_NONBLOCK);
    }
    /* Живой конфиг, чтобы SNI-ветка poll() исполнялась (она под
     * g_cfg && g_cfg->sni_sniff). Пустые файлы списков и ru_guard_tlds
     * гарантируют: reconcile_entry пины не ставит, ipset/iptables не
     * дёргаются — тест остаётся хостовым. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.dns_sniff = 1;
    cfg.sni_sniff = 1;
    cfg.dns_sniff_ttl = 300;
    g_cfg = &cfg;
    g_nfd = 2;
    g_fds[0] = spA[0];
    g_fds[1] = spB[0];
    snprintf(g_open[0], sizeof(g_open[0]), "%s", "t0");
    snprintf(g_open[1], sizeof(g_open[1]), "%s", "t1");
    Wfd[0] = spA[1];
    Wfd[1] = spB[1];
    g_started = 1;

    printf("=== состояние «нет трафика» ===\n");
    dns_sniff_stats(st, sizeof(st));
    printf("     %s\n", st);
    CHECK(cnt_is(st, "frames", 0), "до первого кадра frames=0");
    CHECK(cnt_is(st, "udp53", 0) && cnt_is(st, "queries", 0) &&
          cnt_is(st, "answers", 0) && cnt_is(st, "parse_fail", 0) &&
          cnt_is(st, "stored", 0), "все DNS-шаги обнулены");
    CHECK(cnt_is(st, "sni_seen", 0), "SNI-счётчики видны в сводке");
    {
        static const char *NAMES[] = { "frames=", "udp53=", "queries=",
            "answers=", "parse_fail=", "stored=", "capped=", "table=",
            "sni_seen=", "sni_named=", "sni_stored=", "ifs=" };
        size_t k, miss = 0;
        for (k = 0; k < sizeof(NAMES) / sizeof(NAMES[0]); k++)
            if (!strstr(st, NAMES[k]))
                miss++;
        CHECK(miss == 0, "строка сводки содержит все имена счётчиков");
        CHECK(strstr(st, "ifs=t0,t1") != NULL, "ifs= перечисляет привязанные интерфейсы");
    }

    printf("=== ответ (0xc00c) на t0 ===\n");
    feed(0, buf, build_ip(buf, 5353));
    dns_sniff_stats(st, sizeof(st));
    printf("     %s\n", st);
    CHECK(cnt_is(st, "frames", 1), "кадр учтён в frames");
    CHECK(cnt_is(st, "udp53", 1), "UDP/53 учтён отдельно");
    CHECK(cnt_is(st, "answers", 1) && strstr(st, "answers=1(t0:1)") != NULL,
          "ответ учтён и привязан к t0");
    CHECK(cnt_is(st, "queries", 0), "запросов нет");
    CHECK(cnt_is(st, "parse_fail", 0), "разбор не падал");
    CHECK(cnt_is(st, "stored", 1), "пара домен+IP сохранена");
    CHECK(dns_sniff_domain_of("93.184.216.34", dom, sizeof(dom)) &&
          !strcasecmp(dom, "example.com"), "domain_of отдаёт имя");

    printf("=== запрос (QR=0) на t1 — не должен списываться в мусор ===\n");
    {
        int n = build_ip(buf, 5353);
        buf[DNS_OFF + 2] = 0x01; buf[DNS_OFF + 3] = 0x00;   /* QR=0 */
        feed(1, buf, n);
    }
    dns_sniff_stats(st, sizeof(st));
    printf("     %s\n", st);
    CHECK(cnt_is(st, "queries", 1) && strstr(st, "queries=1(t1:1)") != NULL,
          "запрос учтён как queries и привязан к t1");
    CHECK(cnt_is(st, "answers", 1), "answers не изменился");
    CHECK(cnt_is(st, "stored", 1), "запрос ничего не добавляет в таблицу");
    CHECK(cnt_is(st, "parse_fail", 0), "запрос — не parse_fail");

    printf("=== кадр UDP не 53-го порта ===\n");
    {
        int n = build_ip(buf, 5353);
        buf[20] = 0; buf[21] = 9;        /* sport 9 */
        buf[22] = 0; buf[23] = 9;        /* dport 9 */
        feed(0, buf, n);
    }
    dns_sniff_stats(st, sizeof(st));
    CHECK(cnt_is(st, "frames", 3), "frames вырос");
    CHECK(cnt_is(st, "udp53", 2), "udp53 НЕ вырос: кадр не DNS-порт");
    CHECK(cnt_is(st, "queries", 1) && cnt_is(st, "answers", 1),
          "в queries/answers не-53 не попал");

    printf("=== кадр с Ethernet-заголовком (версия «L2 не срезан») ===\n");
    feed(0, buf, build_ethernet_prefixed(buf));
    dns_sniff_stats(st, sizeof(st));
    CHECK(cnt_is(st, "frames", 4) && cnt_is(st, "udp53", 2),
          "не-IP виден как frames без прироста udp53");
    CHECK(cnt_is(st, "queries", 1) && cnt_is(st, "answers", 1) &&
          cnt_is(st, "parse_fail", 0),
          "и не просочился ни в DNS-шаги, ни в parse_fail");

    printf("=== обрезанный DNS (полезная нагрузка короче заголовка) ===\n");
    {
        int n = build_ip(buf, 5353);
        buf[24] = 0; buf[25] = 8 + 6;    /* ulen = 8+6: dlen 6 < 12 */
        feed(0, buf, n);
    }
    dns_sniff_stats(st, sizeof(st));
    printf("     %s\n", st);
    CHECK(cnt_is(st, "udp53", 3) && cnt_is(st, "parse_fail", 1),
          "обрезок учтён в parse_fail (udp53 вырос, QR не читался)");
    CHECK(cnt_is(st, "answers", 1) && cnt_is(st, "stored", 1),
          "в answers/stored обрезок не попал");

    printf("=== битый ответ (QR=1, имя за пределами кадра) ===\n");
    {
        int n = build_ip(buf, 5353);
        buf[DNS_OFF + 12] = 200;         /* метка qname длиннее пакета */
        feed(1, buf, n);
    }
    dns_sniff_stats(st, sizeof(st));
    printf("     %s\n", st);
    CHECK(cnt_is(st, "answers", 2), "ответ посчитан: он и есть ответ");
    CHECK(cnt_is(st, "parse_fail", 2), "и одновременно в parse_fail: разбор умер");
    CHECK(cnt_is(st, "stored", 1), "в таблицу не легло ничего нового");
    CHECK(strstr(st, "answers=2(t0:1,t1:1)") != NULL,
          "разбивка по интерфейсам считает и битый ответ");

    printf("=== TCP: ClientHello к публичному адресу (SNI-ветка) ===\n");
    feed(0, buf, build_tls_to(buf, 93, 184, 216, 99));
    dns_sniff_stats(st, sizeof(st));
    printf("     %s\n", st);
    CHECK(cnt_is(st, "sni_seen", 1), "ClientHello разобран (sni_seen=1)");
    CHECK(cnt_is(st, "sni_named", 1), "имя признано доменом");
    CHECK(cnt_is(st, "sni_stored", 1), "SNI-пара легла в таблицу");
    CHECK(cnt_is(st, "stored", 1), "DNS-счётчик stored не испорчен SNI-записями");
    CHECK(cnt_is(st, "udp53", 4), "TCP-кадр не стал udp53");
    CHECK(cnt_is(st, "queries", 1) && cnt_is(st, "answers", 2),
          "TCP-кадр не просочился в queries/answers");
    CHECK(dns_sniff_domain_of("93.184.216.99", dom, sizeof(dom)) &&
          !strcasecmp(dom, "sni.example.net"), "domain_of видит SNI-пару");

    printf("=== TCP: ClientHello к приватному адресу — фильтр ===\n");
    feed(0, buf, build_tls_to(buf, 10, 1, 2, 3));
    dns_sniff_stats(st, sizeof(st));
    CHECK(cnt_is(st, "sni_seen", 2), "разобран и учтён");
    CHECK(cnt_is(st, "sni_stored", 1),
          "в таблицу не попал: приватное/служебное назначение отброшено");

    printf("=== лимит прохода (capped) ===\n");
    {
        int n = build_ip(buf, 5353), k;
        for (k = 0; k < 130; k++)
            feed_now(0, buf, n);         /* 130 кадров копятся на t0 */
        dns_sniff_poll();                /* один проход заберёт 128 */
        dns_sniff_stats(st, sizeof(st));
        CHECK(cnt_is(st, "capped", 1), "проход упёрся в лимит — capped=1");
        CHECK(cnt_is(st, "frames", 8 + 128), "за проход взято ровно 128 кадров");
        dns_sniff_poll();                /* второй проход дочитывает хвост */
        dns_sniff_stats(st, sizeof(st));
        CHECK(cnt_is(st, "capped", 1), "capped не растёт на пустом приёме");
        CHECK(cnt_is(st, "frames", 138), "хвост дочитан");
    }

    printf("=== структурный срез для WARN ===\n");
    {
        dns_sniff_counters cn;
        dns_sniff_get_counters(&cn);
        CHECK(cn.frames == 138 && cn.udp53 == 134 && cn.queries == 1 &&
              cn.answers == 132 && cn.parse_fail == 2 && cn.stored == 131 &&
              cn.capped == 1,
              "dns_sniff_get_counters совпадает со сводкой");
        CHECK(cn.niface == 2 && !strcmp(cn.name[0], "t0") &&
              cn.iface_answers[0] == 131 && cn.iface_answers[1] == 1 &&
              cn.iface_queries[1] == 1,
              "разбивка по интерфейсам доступна без разбора строки");
    }

    dns_sniff_stop();
    close(Wfd[0]);
    close(Wfd[1]);
    printf("\n%s\n", failures ? "ЕСТЬ ОШИБКИ" : "ИТОГ: все проверки пройдены");
    return failures ? 1 : 0;
}
