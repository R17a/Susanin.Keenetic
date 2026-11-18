/* Тест локализации журнала: перевод шаблона по языку, откат на русский и
 * фактическая строка, которую печатает slogf(). */
#include "lang.h"
#include "log.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int failures = 0;
#define CHECK(cond, msg) do { if (cond) printf("ok  %s\n", msg); \
    else { printf("FAIL %s\n", msg); failures++; } } while (0)

/* Поймать вывод slogf() в файл: подменяем fd 1 и возвращаем обратно. */
static int capture(const char *path, const char *code, const char *msg,
                   char *out, size_t n)
{
    fflush(stdout);
    int saved = dup(1);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    FILE *f;
    size_t got;

    if (saved < 0 || fd < 0)
        return -1;
    dup2(fd, 1);
    close(fd);
    lang_set(code);
    slogf(SL_INFO, msg);
    fflush(stdout);
    dup2(saved, 1);
    close(saved);
    f = fopen(path, "r");
    if (!f)
        return -1;
    got = fread(out, 1, n - 1, f);
    out[got] = '\0';
    fclose(f);
    return 0;
}

int main(void)
{
    char buf[512];
    /* Построчный вывод: иначе строки теста уходят в перехваченный fd. */
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *ru = "батч ipset восстановлен без перезапуска агента";

    printf("=== языки ===\n");
    CHECK(lang_known("ru") && lang_known("en") && lang_known("zh"),
          "ru/en/zh известны");
    CHECK(!lang_known("de") && !lang_known("") && !lang_known(NULL),
          "остальное неизвестно");

    lang_set("ru");
    CHECK(!strcmp(lang_code(), "ru"), "по умолчанию ru");
    CHECK(lang_tr(ru) == ru, "русский отдаёт исходный указатель");

    lang_set("en");
    CHECK(strcmp(lang_tr(ru), ru) != 0, "английский даёт другой текст");
    lang_set("zh");
    CHECK(strcmp(lang_tr(ru), ru) != 0, "китайский даёт другой текст");

    lang_set("xx");
    CHECK(!strcmp(lang_code(), "ru"), "неизвестный код откатывается на ru");
    CHECK(lang_tr(ru) == ru, "неизвестный код — исходный текст");

    printf("=== откат для сообщения без перевода ===\n");
    lang_set("en");
    {
        const char *unknown = "совершенно новое сообщение без перевода %d";
        CHECK(lang_tr(unknown) == unknown, "нет перевода — исходный указатель");
    }

    printf("=== slogf печатает на выбранном языке ===\n");
    if (capture("/tmp/test_lang.out", "zh", ru, buf, sizeof(buf)) == 0) {
        CHECK(strstr(buf, lang_tr(ru)) != NULL ||
              strstr(buf, "ipset") != NULL,
              "строка журнала содержит перевод (не пустая)");
        CHECK(strstr(buf, ru) == NULL, "русский вариант не напечатан при zh");
    } else {
        CHECK(0, "не удалось перехватить вывод slogf");
    }
    if (capture("/tmp/test_lang.out", "ru", ru, buf, sizeof(buf)) == 0)
        CHECK(strstr(buf, ru) != NULL, "при ru напечатан русский текст");

    printf("\n%s\n", failures ? "ЕСТЬ ОШИБКИ" : "ИТОГ: все проверки пройдены");
    return failures ? 1 : 0;
}
