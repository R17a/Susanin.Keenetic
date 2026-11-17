/* Тесты разбора строк списков (src/entryparse.c): обычные записи, мягкие (?),
 * зоны (*.domain), CIDR, мусор. */
#include "entryparse.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(cond, msg) do { if (cond) printf("ok  %s\n", msg); \
    else { printf("FAIL %s\n", msg); failures++; } } while (0)

static int parse(const char *line, char *out, int *wild, int *net, int *soft)
{
    return entry_parse(line, out, 256, wild, net, soft);
}

int main(void)
{
    char out[256];
    int wild, net, soft;

    /* 1. Обычный домен. */
    wild = net = soft = -1;
    CHECK(parse("example.com", out, &wild, &net, &soft) == 1, "домен: разобран");
    CHECK(!strcmp(out, "example.com") && !wild && !net && !soft,
          "домен: имя, не зона, не сеть, не мягкая");

    /* 2. Мягкая запись. */
    CHECK(parse("?example.com", out, &wild, &net, &soft) == 1, "?домен: разобран");
    CHECK(!strcmp(out, "example.com") && soft == 1,
          "?домен: префикс снят, soft=1");

    /* 3. Мягкая зона. */
    CHECK(parse("?*.example.com", out, &wild, &net, &soft) == 1, "?*.: разобран");
    CHECK(!strcmp(out, "example.com") && wild == 1 && soft == 1,
          "?*. : зона + мягкая");

    /* 4. Зона без мягкости. */
    CHECK(parse("*.example.com", out, &wild, &net, &soft) == 1 &&
          wild == 1 && !soft && !strcmp(out, "example.com"),
          "*. : зона, не мягкая");

    /* 5. Адрес и сеть. */
    CHECK(parse("1.2.3.4", out, &wild, &net, &soft) == 1 &&
          !net && !strcmp(out, "1.2.3.4"), "IPv4");
    CHECK(parse("1.2.3.0/24", out, &wild, &net, &soft) == 1 &&
          net == 1 && !strcmp(out, "1.2.3.0/24"), "CIDR");
    CHECK(parse("?1.2.3.0/24", out, &wild, &net, &soft) == 1 &&
          net == 1 && soft == 1 && !strcmp(out, "1.2.3.0/24"), "?CIDR");
    CHECK(parse("1.2.3.5/24", out, &wild, &net, &soft) == 1 &&
          !strcmp(out, "1.2.3.0/24"), "CIDR: маска нормализует адрес");

    /* 6. Регистр и пробелы. */
    CHECK(parse("  ?EXAMPLE.COM  ", out, &wild, &net, &soft) == 1 &&
          !strcmp(out, "example.com") && soft == 1, "пробелы и регистр");

    /* 7. Мусор. */
    CHECK(parse("", out, &wild, &net, &soft) == 0, "пустая строка");
    CHECK(parse("# comment", out, &wild, &net, &soft) == 0, "комментарий");
    CHECK(parse("?", out, &wild, &net, &soft) == 0, "одинокий ?");
    CHECK(parse("?   ", out, &wild, &net, &soft) == 0, "? и пробелы");
    CHECK(parse("*", out, &wild, &net, &soft) == 0, "одинокая *");
    CHECK(parse("?*.", out, &wild, &net, &soft) == 0, "?*. без имени");
    CHECK(parse("exa mple.com", out, &wild, &net, &soft) == 0, "пробел в имени");
    CHECK(parse("1.2.3.4/33", out, &wild, &net, &soft) == 0, "CIDR: /33");
    CHECK(parse("1.2.3.4/abc", out, &wild, &net, &soft) == 0, "CIDR: не число");
    CHECK(parse("пример.рф", out, &wild, &net, &soft) == 0, "не-ASCII имя");
    /* Единая грамматика для всех читателей списка (движок и dns_sniff):
     * «? domain» — мусорная строка (пробел после «?» не допускается),
     * «*domain» без точки — тоже: wild пишется только как «*.domain». */
    CHECK(parse("? example.com", out, &wild, &net, &soft) == 0, "? с пробелом: мусор");
    CHECK(parse("?	example.com", out, &wild, &net, &soft) == 0, "? с табуляцией: мусор");
    CHECK(parse("*example.com", out, &wild, &net, &soft) == 0, "*domain без точки: мусор");

    /* 8. NULL-безопасность. */
    CHECK(entry_parse(NULL, out, 256, &wild, &net, &soft) == 0, "NULL строка");
    CHECK(entry_parse("example.com", NULL, 256, &wild, &net, &soft) == 0, "NULL буфер");
    CHECK(entry_parse("example.com", out, 0, &wild, &net, &soft) == 0, "нулевой размер");
    /* Необязательные выходные параметры могут быть NULL. */
    CHECK(entry_parse("?example.com", out, 256, NULL, NULL, NULL) == 1,
          "NULL-указатели на флаги допустимы");

    if (failures) {
        printf("FAILURES: %d\n", failures);
        return 1;
    }
    printf("all entryparse tests passed\n");
    return 0;
}
