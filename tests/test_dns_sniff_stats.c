/* Тест счётчиков dns_sniff: различает «пакеты не приходят», «кадр не с
 * IP-заголовка» и «разбираем, но не сохраняем». dns_sniff.c включается в TU,
 * чтобы задать g_fds/g_nfd/g_started напрямую; кадровый ввод — через
 * socketpair(AF_UNIX), реальный сетевой стек и привилегии не нужны.
 *
 * SNI-ветка тоже исполняется: g_cfg — живой конфиг-стакабель с
 * dns_sniff=1/sni_sniff=1, но пустые vpn_always_file/vpn_never_file и
 * ru_guard_tlds, поэтому reconcile_entry не ставит пинов и ipset/iptables
 * не дёргает — тест остаётся хостовым.
 * make test (хост-компилятор; в поставку не входит).
 */
#define _GNU_SOURCE
#include "dns_sniff.c"

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>

static int failures = 0;
#define CHECK(cond, msg) do { if (cond) printf("ok  %s\n", msg); \
    else { printf("FAIL %s\n", msg); failures++; } } while (0)

/* DNS-ответ: 1 вопрос (example.com A) + 1 A-запись 93.184.216.34, сжатие ANNAME. */
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

/* IPv4 + UDP(src 53) + DNS. Формат, который код ожидает в начале буфера. */
static int build_ip(uint8_t *b, int dstport)
{
    int iplen = 20, udplen = 8 + DNS_LEN, total = iplen + udplen;
    memset(b, 0, total);
    b[0] = 0x45;                        /* ver 4, ihl 20 */
    b[2] = (uint8_t)(total >> 8); b[3] = (uint8_t)(total & 0xff);
    b[8] = 64;                          /* ttl */
    b[9] = 17;                          /* proto UDP */
    b[12] = 192, b[13] = 0, b[14] = 2, b[15] = 1;   /* src */
    b[16] = 192, b[17] = 0, b[18] = 2, b[19] = 2;   /* dst */
    b[20] = 0; b[21] = 53;              /* sport 53 */
    b[22] = (uint8_t)(dstport >> 8); b[23] = (uint8_t)(dstport & 0xff);
    b[24] = (uint8_t)(udplen >> 8); b[25] = (uint8_t)(udplen & 0xff);
    memcpy(b + 28, DNS_RESP, DNS_LEN);
    return total;
}

/* Тот же кадр, но с Ethernet-заголовком спереди: ровно то, что ожидает
 * проверить версия H1 «L2 не срезан». */
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
    memset(b, 0, total);
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

static void feed(const uint8_t *frame, int len)
{
    ssize_t w = write(g_fds[1], frame, (size_t)len);
    (void)w;
    dns_sniff_poll();
}

int main(void)
{
    int sp[2];
    uint8_t buf[2048];
    char dom[DNS_DOMAIN_MAX];
    char st[384];
    susanin_config cfg;

    slog_init("quiet");
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) {
        printf("FAIL socketpair недоступен\n");
        return 1;
    }
    /* Мини-запуск без start(): старт трогал бы AF_PACKET и привилегии.
     * Читающий конец обязательно non-blocking: poll() рассчитан на AF_PACKET,
     * а на блокирующем сокете recv() встал бы навечно после последнего кадра
     * (тест бы «висел», а не падал). */
    {
        int fl = fcntl(sp[0], F_GETFL, 0);
        if (fl >= 0)
            fcntl(sp[0], F_SETFL, fl | O_NONBLOCK);
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
    g_nfd = 1;
    g_fds[0] = sp[0];
    g_fds[1] = sp[1];
    g_started = 1;

    printf("=== состояние «нет трафика» ===\n");
    dns_sniff_stats(st, sizeof(st));
    CHECK(strstr(st, "recv=0") != NULL, "до первого кадра recv=0");
    CHECK(strstr(st, "sni=0") != NULL, "SNI-счётчики видны в сводке");

    printf("=== обычный кадр (IP с начала) ===\n");
    feed(buf, build_ip(buf, 5353));
    dns_sniff_stats(st, sizeof(st));
    printf("     %s\n", st);
    CHECK(strstr(st, "recv=1") != NULL, "recv учтён");
    CHECK(strstr(st, "notudp=0") != NULL, "не UDP не помечен");
    CHECK(strstr(st, "stored=1") != NULL, "пара домен+IP сохранена");
    CHECK(dns_sniff_domain_of("93.184.216.34", dom, sizeof(dom)) &&
          !strcasecmp(dom, "example.com"), "domain_of отдаёт имя");

    printf("=== кадр с Ethernet-заголовком (версия H1) ===\n");
    feed(buf, build_ethernet_prefixed(buf));
    dns_sniff_stats(st, sizeof(st));
    printf("     %s\n", st);
    CHECK(strstr(st, "recv=2") != NULL, "второй кадр учтён как принятый");
    CHECK(strstr(st, "notudp=1") != NULL,
          "не-UDP отсчёт виден отдельным счётчиком (это и есть признак H1)");
    CHECK(strstr(st, "stored=1") != NULL, "и при этом новых DNS-записей нет");

    printf("=== кадр не 53-го порта ===\n");
    {
        int n = build_ip(buf, 5353);
        buf[20] = (uint8_t)(9 >> 8); buf[21] = 9;   /* sport 9 */
        buf[22] = 0; buf[23] = 9;                   /* dport 9 */
        feed(buf, n);
    }
    dns_sniff_stats(st, sizeof(st));
    CHECK(strstr(st, "notdns=1") != NULL, "не-DNS отсчёт отдельный (DoT/DoH-шум)");

    printf("=== запрос вместо ответа ===\n");
    {
        int n = build_ip(buf, 5353);
        buf[28 + 2] = 0x01; buf[28 + 3] = 0x00;     /* QR=0 */
        feed(buf, n);
    }
    dns_sniff_stats(st, sizeof(st));
    CHECK(strstr(st, "stored=1") != NULL, "запрос ничего не добавляет в таблицу");

    printf("=== TCP: ClientHello к публичному адресу (SNI-ветка) ===\n");
    feed(buf, build_tls_to(buf, 93, 184, 216, 99));
    dns_sniff_stats(st, sizeof(st));
    printf("     %s\n", st);
    CHECK(strstr(st, "sni=1") != NULL, "ClientHello разобран (sni=1)");
    CHECK(strstr(st, "sni_named=1") != NULL, "имя признано доменом");
    CHECK(strstr(st, "sni_stored=1") != NULL, "SNI-пара легла в таблицу");
    CHECK(strstr(st, "stored=1") != NULL,
          "DNS-счётчик stored не испорчен SNI-записями");
    CHECK(strstr(st, "notudp=1") != NULL,
          "TCP-кадр не попал в notudp (смысл «не UDP/53» — только про DNS)");
    CHECK(dns_sniff_domain_of("93.184.216.99", dom, sizeof(dom)) &&
          !strcasecmp(dom, "sni.example.net"), "domain_of видит SNI-пару");

    printf("=== TCP: ClientHello к приватному адресу — фильтр ===\n");
    feed(buf, build_tls_to(buf, 10, 1, 2, 3));
    dns_sniff_stats(st, sizeof(st));
    printf("     %s\n", st);
    CHECK(strstr(st, "sni=2") != NULL, "разобран и учтён");
    CHECK(strstr(st, "sni_stored=1") != NULL,
          "в таблицу не попал: приватное/служебное назначение отброшено");

    dns_sniff_stop();
    close(sp[0]);
    printf("\n%s\n", failures ? "ЕСТЬ ОШИБКИ" : "ИТОГ: все проверки пройдены");
    return failures ? 1 : 0;
}
