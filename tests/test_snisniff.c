/* Тесты SNI-парсера (src/snisniff.c): сборка ClientHello вручную и проверка
 * разбора. Сокеты и ipset не нужны — только байты. */
#include "snisniff.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(cond, msg) do { if (cond) printf("ok  %s\n", msg); \
    else { printf("FAIL %s\n", msg); failures++; } } while (0)

/* Собрать ClientHello с одним расширением SNI. Возврат — длина. */
static size_t build_hello(unsigned char *b, const char *sni, int hs_type,
                          int with_sni)
{
    size_t n = 0, hs, name_len = strlen(sni), ext_len = 0, i;
    unsigned char body[512];
    size_t bl = 0;

    /* handshake body: version, random, session_id, ciphers, compression, ext */
    body[bl++] = 0x03;
    body[bl++] = 0x03;
    for (i = 0; i < 32; i++)
        body[bl++] = (unsigned char)i;
    body[bl++] = 0;                         /* session_id_len */
    body[bl++] = 0x00; body[bl++] = 0x02;   /* cipher_suites_len */
    body[bl++] = 0x13; body[bl++] = 0x01;   /* TLS_AES_128_GCM_SHA256 */
    body[bl++] = 0x01; body[bl++] = 0x00;   /* compression */

    {
        size_t ext_pos = bl;
        bl += 2;                            /* ext_len placeholder */
        if (with_sni) {
            size_t sn_pos = bl;
            bl += 4;                        /* type+len placeholder */
            body[bl++] = (unsigned char)((name_len + 3) >> 8);
            body[bl++] = (unsigned char)((name_len + 3) & 0xff);
            body[bl++] = 0x00;              /* name_type = host_name */
            body[bl++] = (unsigned char)(name_len >> 8);
            body[bl++] = (unsigned char)(name_len & 0xff);
            memcpy(body + bl, sni, name_len);
            bl += name_len;
            ext_len = bl - sn_pos - 4;   /* длина расширения без заголовка */
            body[sn_pos] = 0x00; body[sn_pos + 1] = 0x00;   /* SNI */
            body[sn_pos + 2] = (unsigned char)(ext_len >> 8);
            body[sn_pos + 3] = (unsigned char)(ext_len & 0xff);
        }
        ext_len = bl - ext_pos - 2;
        body[ext_pos] = (unsigned char)(ext_len >> 8);
        body[ext_pos + 1] = (unsigned char)(ext_len & 0xff);
    }

    hs = bl;
    n = 0;
    b[n++] = 0x16;                          /* handshake record */
    b[n++] = 0x03;
    b[n++] = 0x01;
    b[n++] = (unsigned char)((hs + 4) >> 8);
    b[n++] = (unsigned char)((hs + 4) & 0xff);
    b[n++] = (unsigned char)hs_type;
    b[n++] = (unsigned char)(hs >> 16);
    b[n++] = (unsigned char)(hs >> 8);
    b[n++] = (unsigned char)hs;
    memcpy(b + n, body, bl);
    n += bl;
    return n;
}

int main(void)
{
    unsigned char b[1024];
    char out[256];
    size_t n;

    /* 1. Нормальный ClientHello с SNI. */
    n = build_hello(b, "example.com", 0x01, 1);
    CHECK(sni_parse_client_hello(b, n, out, sizeof(out)) == 1, "валидный: разобран");
    CHECK(!strcmp(out, "example.com"), "валидный: имя верное");

    /* 2. Верхний регистр приводится к нижнему. */
    n = build_hello(b, "MiXeD.Example.COM", 0x01, 1);
    CHECK(sni_parse_client_hello(b, n, out, sizeof(out)) == 1 &&
          !strcmp(out, "mixed.example.com"), "регистр: приведён к нижнему");

    /* 3. Без расширения SNI — имени нет. */
    n = build_hello(b, "", 0x01, 0);
    CHECK(sni_parse_client_hello(b, n, out, sizeof(out)) == 0, "без SNI: 0");

    /* 4. Не ClientHello (ServerHello). */
    n = build_hello(b, "example.com", 0x02, 1);
    CHECK(sni_parse_client_hello(b, n, out, sizeof(out)) == 0, "не ClientHello: 0");

    /* 5. Не TLS-запись. */
    n = build_hello(b, "example.com", 0x01, 1);
    b[0] = 0x17;                            /* application data */
    CHECK(sni_parse_client_hello(b, n, out, sizeof(out)) == 0, "не handshake: 0");

    /* 6. Обрезанный пакет (имя не влезло) — не угадываем. */
    n = build_hello(b, "example.com", 0x01, 1);
    CHECK(sni_parse_client_hello(b, n - 4, out, sizeof(out)) == 0, "обрезанный: 0");

    /* 7. Совсем короткий буфер. */
    CHECK(sni_parse_client_hello(b, 5, out, sizeof(out)) == 0, "короткий: 0");

    /* 8. Мусор в имени (пробел) — не отдаём как домен. */
    n = build_hello(b, "exa mple.com", 0x01, 1);
    CHECK(sni_parse_client_hello(b, n, out, sizeof(out)) == 0, "мусор в имени: 0");

    /* 9. NULL-безопасность. */
    CHECK(sni_parse_client_hello(NULL, 100, out, sizeof(out)) == 0, "NULL вход");
    CHECK(sni_parse_client_hello(b, 100, NULL, 100) == 0, "NULL выход");
    CHECK(sni_parse_client_hello(b, 100, out, 0) == 0, "нулевой размер");

    if (failures) {
        printf("FAILURES: %d\n", failures);
        return 1;
    }
    printf("all snisniff tests passed\n");
    return 0;
}
