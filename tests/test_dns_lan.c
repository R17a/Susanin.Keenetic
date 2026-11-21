#define _GNU_SOURCE
/* Тест разбора DNS-запроса и TTL ответа для dns_lan (форвардер LAN -> туннель). */
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "log.h"

#include "dns_lan.c"

/* dns_lan.c при выключении на лету снимает DNAT через backend; в этом
 * host-тесте ipset/iptables нет — заглушка, проверяем только разбор и TTL. */
int backend_dns_lan_down(const susanin_config *c)
{
    (void)c;
    return 0;
}

static int failures = 0;
#define CHECK(c, m) do { if (c) printf("ok  %s\n", m); \
    else { printf("FAIL %s\n", m); failures++; } } while (0)

/* Запрос: header + "Example.COM" + A + IN */
static int make_query(unsigned char *b, unsigned id, const char *name,
                      unsigned type)
{
    static const unsigned char tail[] = { 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                                          3, 'c', 'o', 'm', 0 };
    int n;

    (void)name;
    memset(b, 0, 64);
    b[0] = (unsigned char)(id >> 8);
    b[1] = (unsigned char)(id & 0xff);
    b[2] = 0x01;                       /* RD */
    b[5] = 0x01;                       /* qdcount=1 */
    n = 12;
    memcpy(b + n, tail, sizeof(tail));  /* "example.com" */
    n += (int)sizeof(tail);
    b[n++] = (unsigned char)(type >> 8);
    b[n++] = (unsigned char)(type & 0xff);
    b[n++] = 0; b[n++] = 1;             /* IN */
    return n;
}

/* Ответ: тот же вопрос + один A с TTL */
static int make_answer(unsigned char *b, const unsigned char *q, int qlen, unsigned ttl)
{
    int n = qlen;
    memcpy(b, q, (size_t)qlen);
    b[2] = 0x81; b[3] = 0x80;          /* QR, RA */
    b[6] = 0; b[7] = 1;                /* ancount=1 */
    b[n++] = 0xc0; b[n++] = 0x0c;      /* указатель на имя вопроса */
    b[n++] = 0; b[n++] = 1;            /* A */
    b[n++] = 0; b[n++] = 1;            /* IN */
    b[n++] = (unsigned char)(ttl >> 24);
    b[n++] = (unsigned char)(ttl >> 16);
    b[n++] = (unsigned char)(ttl >> 8);
    b[n++] = (unsigned char)ttl;
    b[n++] = 0; b[n++] = 4;            /* rdlength */
    b[n++] = 1; b[n++] = 2; b[n++] = 3; b[n++] = 4;
    return n;
}

int main(void)
{
    unsigned char q[512], a[512];
    char key[264], name[256];
    unsigned qtype = 0;
    int qlen, alen;
    dl_entry *e;
    time_t now = time(NULL);

    printf("=== разбор вопроса ===\n");
    qlen = make_query(q, 0x1234, "Example.COM", 1);
    CHECK(dl_question(q, qlen, key, sizeof(key), &qtype, name, sizeof(name)) == 1,
          "вопрос разобран");
    CHECK(!strcmp(key, "example.com|1"), "ключ в нижнем регистре и с qtype");
    CHECK(qtype == 1, "qtype=A");
    CHECK(!strcmp(name, "example.com"), "имя без точки в конце");

    printf("=== TTL ответа ===\n");
    alen = make_answer(a, q, qlen, 120);
    CHECK(dl_ttl(a, alen) == 120, "TTL=120");
    alen = make_answer(a, q, qlen, 0);
    CHECK(dl_ttl(a, alen) == 1, "TTL=0 поднимается до 1 с");
    alen = make_answer(a, q, qlen, 999999);
    CHECK(dl_ttl(a, alen) == 3600, "огромный TTL ограничен 3600 с");

    printf("=== кэш ===\n");
    dl_stats_reset();
    memset(g_cache, 0, sizeof(g_cache));
    alen = make_answer(a, q, qlen, 60);
    dl_cache_put(key, a, alen, 60);
    e = dl_cache_get(key, now);
    CHECK(e != NULL && e->len == (unsigned short)alen, "запись найдена, длина совпала");
    CHECK(dl_cache_get("нет-такого|1", now) == NULL, "чужой ключ не находится");
    alen = make_answer(a, q, qlen, 1);
    dl_cache_put(key, a, alen, 1);
    CHECK(dl_cache_get(key, now + 5) == NULL, "просроченная запись не отдаётся");

    printf("\n%s\n", failures ? "ЕСТЬ ОШИБКИ" : "ИТОГ: все проверки пройдены");
    return failures ? 1 : 0;
}
