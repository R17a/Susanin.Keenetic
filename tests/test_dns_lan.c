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

int backend_dns_lan_up(const susanin_config *c)
{
    (void)c;
    return 0;
}

/* Форвардер регистрирует у backend точку «отдать время» на время ожидания
 * внешних процессов. В тесте ждать нечего — заглушка. */
void backend_set_yield_cb(void (*cb)(void))
{
    (void)cb;
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

/* Ответ: тот же вопрос + одна запись указанного типа с TTL.
 * Для A — адрес 1.2.3.4 (или 127.0.0.1 при subst=1), для остальных типов —
 * короткий rdata (так выглядит валидный ответ на запрос HTTPS/SVCB). */
static int make_answer_typed(unsigned char *b, const unsigned char *q, int qlen,
                             unsigned ttl, unsigned type, int subst)
{
    int n = qlen;
    memcpy(b, q, (size_t)qlen);
    b[2] = 0x81; b[3] = 0x80;          /* QR, RA */
    b[6] = 0; b[7] = 1;                /* ancount=1 */
    b[n++] = 0xc0; b[n++] = 0x0c;      /* указатель на имя вопроса */
    b[n++] = (unsigned char)(type >> 8);
    b[n++] = (unsigned char)(type & 0xff);
    b[n++] = 0; b[n++] = 1;            /* IN */
    b[n++] = (unsigned char)(ttl >> 24);
    b[n++] = (unsigned char)(ttl >> 16);
    b[n++] = (unsigned char)(ttl >> 8);
    b[n++] = (unsigned char)ttl;
    if (type == 1) {
        b[n++] = 0; b[n++] = 4;
        b[n++] = (unsigned char)(subst ? 127 : 1);
        b[n++] = (unsigned char)(subst ? 0 : 2);
        b[n++] = (unsigned char)(subst ? 0 : 3);
        b[n++] = (unsigned char)(subst ? 1 : 4);
    } else {
        b[n++] = 0; b[n++] = 3;        /* rdlength */
        b[n++] = 0; b[n++] = 1;        /* priority */
        b[n++] = 0;                    /* target "." */
    }
    return n;
}

/* Ответ: тот же вопрос + один A с TTL */
static int make_answer(unsigned char *b, const unsigned char *q, int qlen, unsigned ttl)
{
    return make_answer_typed(b, q, qlen, ttl, 1, 0);
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

    printf("=== приём ответа из туннеля ===\n");
    /* Ответ на A с настоящим адресом — годится. */
    qlen = make_query(q, 0x1234, "example.com", 1);
    alen = make_answer_typed(a, q, qlen, 60, 1, 0);
    CHECK(dl_tunnel_answer_ok(a, alen) == 1, "A с настоящим адресом принимается");
    /* Подмена 127.0.0.1 из туннеля — не годится. */
    alen = make_answer_typed(a, q, qlen, 60, 1, 1);
    CHECK(dl_tunnel_answer_ok(a, alen) == 0, "A с 127.0.0.1 отвергается");
    /* Ответ на запрос HTTPS/SVCB (тип 65) без A/AAAA — валидный NOERROR.
     * Раньше он считался провалом, и клиент получал SERVFAIL. */
    qlen = make_query(q, 0x1234, "example.com", 65);
    alen = make_answer_typed(a, q, qlen, 60, 65, 0);
    CHECK(dl_tunnel_answer_ok(a, alen) == 1, "ответ типа 65 принимается");
    /* NOERROR без записей (NODATA) — тоже валидный ответ. */
    alen = make_answer_typed(a, q, qlen, 60, 65, 0);
    a[7] = 0;                          /* ancount=0 */
    CHECK(dl_tunnel_answer_ok(a, alen) == 1, "NOERROR без записей принимается");
    /* SERVFAIL из туннеля по-прежнему провал. */
    alen = make_answer_typed(a, q, qlen, 60, 65, 0);
    a[3] = 0x82;                       /* rcode=2 */
    CHECK(dl_tunnel_answer_ok(a, alen) == 0, "SERVFAIL из туннеля отвергается");

    printf("\n%s\n", failures ? "ЕСТЬ ОШИБКИ" : "ИТОГ: все проверки пройдены");
    return failures ? 1 : 0;
}
