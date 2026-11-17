/* Тесты SNI-парсера (src/snisniff.c): сборка ClientHello вручную и проверка
 * разбора. Сокеты и ipset не нужны — только байты.
 * Покрыто: границы TLS-записи (hs_len), валидность имени («..», ведущая/
 * замыкающая точка, длина), порядок и размеры расширений, и обязательная
 * проверка «не читаем за конец буфера»: каждый префикс кадра разбирается в
 * отдельном буфере ровно своего размера. */
#include "snisniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
#define CHECK(cond, msg) do { if (cond) printf("ok  %s\n", msg); \
    else { printf("FAIL %s\n", msg); failures++; } } while (0)

/* Собрать ClientHello.
 *  with_sni — класть расширение SNI; pre/prelen — произвольные расширения
 *  ПЕРЕД ним; hsl_delta — сдвиг объявленной длины handshake (меньше/больше
 *  фактической); hs_type — тип handshake-сообщения в record. */
static size_t build_full(unsigned char *b, const char *sni, int hs_type,
                         int with_sni, const unsigned char *pre, size_t prelen,
                         long hsl_delta)
{
    unsigned char body[1024];
    size_t bl = 0, ext_pos, n = 0;
    unsigned bl_total;
    size_t name_len = sni ? strlen(sni) : 0;

    body[bl++] = 0x03;
    body[bl++] = 0x03;
    for (size_t i = 0; i < 32; i++)
        body[bl++] = (unsigned char)i;
    body[bl++] = 0;                         /* session_id_len */
    body[bl++] = 0x00; body[bl++] = 0x02;   /* cipher_suites_len */
    body[bl++] = 0x13; body[bl++] = 0x01;   /* TLS_AES_128_GCM_SHA256 */
    body[bl++] = 0x01; body[bl++] = 0x00;   /* compression */

    ext_pos = bl;
    bl += 2;                                /* ext_len placeholder */
    if (pre && prelen) {
        memcpy(body + bl, pre, prelen);
        bl += prelen;
    }
    if (with_sni) {
        size_t sn_pos = bl;
        size_t el;
        bl += 4;                            /* type+len placeholder */
        body[bl++] = (unsigned char)((name_len + 3) >> 8);
        body[bl++] = (unsigned char)((name_len + 3) & 0xff);
        body[bl++] = 0x00;                  /* name_type = host_name */
        body[bl++] = (unsigned char)(name_len >> 8);
        body[bl++] = (unsigned char)(name_len & 0xff);
        if (name_len) {
            memcpy(body + bl, sni, name_len);
            bl += name_len;
        }
        el = bl - sn_pos - 4;               /* длина расширения без заголовка */
        body[sn_pos] = 0x00; body[sn_pos + 1] = 0x00;   /* SNI */
        body[sn_pos + 2] = (unsigned char)(el >> 8);
        body[sn_pos + 3] = (unsigned char)(el & 0xff);
    }
    {
        unsigned el = (unsigned)(bl - ext_pos - 2);
        body[ext_pos] = (unsigned char)(el >> 8);
        body[ext_pos + 1] = (unsigned char)(el & 0xff);
    }

    bl_total = (unsigned)bl;                /* фактический handshake body */
    n = 0;
    b[n++] = 0x16;                          /* handshake record */
    b[n++] = 0x03;
    b[n++] = 0x01;
    b[n++] = (unsigned char)((bl_total + 4) >> 8);
    b[n++] = (unsigned char)((bl_total + 4) & 0xff);
    b[n++] = (unsigned char)hs_type;
    {
        long decl = (long)bl_total + hsl_delta;   /* объявленная длина hs */
        if (decl < 0)
            decl = 0;
        b[n++] = (unsigned char)((decl >> 16) & 0xff);
        b[n++] = (unsigned char)((decl >> 8) & 0xff);
        b[n++] = (unsigned char)(decl & 0xff);
    }
    memcpy(b + n, body, bl);
    n += bl;
    return n;
}

static size_t build_hello(unsigned char *b, const char *sni, int hs_type,
                          int with_sni)
{
    return build_full(b, sni, hs_type, with_sni, NULL, 0, 0);
}

/* Имя заданной длины: метки по ~20 символов. */
static void mk_name(char *dst, size_t want)
{
    size_t i = 0, lab = 0;
    while (i < want - 1) {
        char c = (char)('a' + (i % 26));
        dst[i++] = c;
        lab++;
        if (lab == 20 && i < want - 1) {
            dst[i++] = '.';
            lab = 0;
        }
    }
    while (i < want)
        dst[i++] = 'z';
    dst[want] = '\0';
}

int main(void)
{
    unsigned char b[2048];
    char out[256], name[300];
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
    CHECK(out[0] == '\0', "при мусоре out обнулён (нет хвоста имени)");

    /* 9. NULL-безопасность. */
    CHECK(sni_parse_client_hello(NULL, 100, out, sizeof(out)) == 0, "NULL вход");
    CHECK(sni_parse_client_hello(b, 100, NULL, 100) == 0, "NULL выход");
    CHECK(sni_parse_client_hello(b, 100, out, 0) == 0, "нулевой размер");

    /* 10. hs_len МЕНЬШЕ фактической длины: разбор ограничен записью,
     *     имя за её концом — не имя. */
    n = build_full(b, "example.com", 0x01, 1, NULL, 0, -12);
    CHECK(sni_parse_client_hello(b, n, out, sizeof(out)) == 0,
          "hs_len меньше фактической: 0 (за запись не читаем)");

    /* 11. hs_len БОЛЬШЕ буфера: разбираем то, что дали, валидный кейс не
     *     ломается (это прежний clamp по len). */
    n = build_full(b, "example.com", 0x01, 1, NULL, 0, 500);
    CHECK(sni_parse_client_hello(b, n, out, sizeof(out)) == 1 &&
          !strcmp(out, "example.com"), "hs_len больше буфера: имя найдено");

    /* 12. Точки: «..», ведущая, замыкающая — самоутверждённое «похожее» имя
     *     в таблицу не попадает, раньше последняя срезалась молча. */
    n = build_hello(b, "a..b.com", 0x01, 1);
    CHECK(sni_parse_client_hello(b, n, out, sizeof(out)) == 0, "«..»: 0");
    n = build_hello(b, ".example.com", 0x01, 1);
    CHECK(sni_parse_client_hello(b, n, out, sizeof(out)) == 0, "ведущая точка: 0");
    n = build_hello(b, "example.com.", 0x01, 1);
    CHECK(sni_parse_client_hello(b, n, out, sizeof(out)) == 0, "замыкающая точка: 0");
    CHECK(out[0] == '\0', "отказ: out пуст");

    /* 13. Длины имён: 127/128 — валидны, 253 — предел, 254 — отказ. */
    mk_name(name, 127);
    n = build_hello(b, name, 0x01, 1);
    CHECK(sni_parse_client_hello(b, n, out, sizeof(out)) == 1 && !strcmp(out, name),
          "имя 127 символов: ок");
    mk_name(name, 128);
    n = build_hello(b, name, 0x01, 1);
    CHECK(sni_parse_client_hello(b, n, out, sizeof(out)) == 1 && !strcmp(out, name),
          "имя 128 символов: ок");
    mk_name(name, 253);
    n = build_hello(b, name, 0x01, 1);
    CHECK(sni_parse_client_hello(b, n, out, sizeof(out)) == 1, "имя 253: ок");
    mk_name(name, 254);
    n = build_hello(b, name, 0x01, 1);
    CHECK(sni_parse_client_hello(b, n, out, sizeof(out)) == 0, "имя 254: 0");

    /* 14. Имя не влезает в выходной буфер (rl >= n) — отказ, а не обрезок. */
    n = build_hello(b, "example.com", 0x01, 1);
    CHECK(sni_parse_client_hello(b, n, out, strlen("example.com")) == 0,
          "выход тесен (rl >= n): 0");

    /* 15. Расширения до SNI: GREASE-подобное (0x1a1a) и пустое (el=0) —
     *     парсер доходит до SNI, порядок расширений не важен. */
    {
        unsigned char pre[8];
        pre[0] = 0x1a; pre[1] = 0x1a;            /* GREASE */
        pre[2] = 0x00; pre[3] = 0x04;
        pre[4] = 0x1a; pre[5] = 0x1a; pre[6] = 0x1a; pre[7] = 0x1a;
        n = build_full(b, "example.com", 0x01, 1, pre, sizeof(pre), 0);
        CHECK(sni_parse_client_hello(b, n, out, sizeof(out)) == 1 &&
              !strcmp(out, "example.com"), "SNI не первым (GREASE перед ним): ок");
        {
            unsigned char pre0[4] = { 0x00, 0x0b, 0x00, 0x00 }; /* el = 0 */
            n = build_full(b, "example.com", 0x01, 1, pre0, sizeof(pre0), 0);
            CHECK(sni_parse_client_hello(b, n, out, sizeof(out)) == 1 &&
                  !strcmp(out, "example.com"), "расширение с el=0: пропущено, SNI найден");
        }
        /* SNI после нескольких расширений — парсер идёт по списку. */
        {
            unsigned char pre2[16];
            memcpy(pre2, pre, 8);
            pre2[8] = 0xff; pre2[9] = 0x01;      /* неизвестное, el=2 */
            pre2[10] = 0x00; pre2[11] = 0x02;
            pre2[12] = 0xaa; pre2[13] = 0xbb;
            n = build_full(b, "example.com", 0x01, 1, pre2, 14, 0);
            CHECK(sni_parse_client_hello(b, n, out, sizeof(out)) == 1,
                  "цепочка расширений до SNI: ок");
        }
    }

    /* 16. «Не читаем за конец буфера»: каждый префикс кадра длиной k
     *     разбирается в отдельном malloc-буфере ровно размера k — любой
     *     выход за границу поймает хотя бы обычный heap-check. Возврат —
     *     0 или полное корректное имя, падения быть не может. */
    n = build_hello(b, "example.com", 0x01, 1);
    {
        size_t k;
        int bad = 0;
        for (k = 0; k <= n; k++) {
            unsigned char *cut = malloc(k ? k : 1);
            int r;
            out[0] = '\0';
            memcpy(cut, b, k);
            r = sni_parse_client_hello(cut, k, out, sizeof(out));
            if (r != 0 && strcmp(out, "example.com") != 0)
                bad++;
            if (r != 0 && k < n)
                bad++;      /* полное имя на обрезанном кадре — читали лишнее */
            free(cut);
        }
        CHECK(bad == 0, "префиксы 0..n: без чтения за конец, только 0 или полное имя");
    }

    if (failures) {
        printf("FAILURES: %d\n", failures);
        return 1;
    }
    printf("all snisniff tests passed\n");
    return 0;
}
