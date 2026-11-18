/* Уровни записи журнала: имя из конфига -> что реально пишется.
 * Повод: уровень `warn` стоял по умолчанию и был в документации, но разбора
 * у него не было — строка проваливалась в ветку неизвестного значения и
 * включала INFO. Проверка фиксирует соответствие имён и порогу отсечения.
 * make test (хост; log.c не требует ни сети, ни файлов конфига). */
#define _GNU_SOURCE
#include "log.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(cond, msg) do { if (cond) printf("ok   %s\n", msg); \
    else { printf("FAIL %s\n", msg); failures++; } } while (0)

/* Имя -> ожидаемый уровень + проверка, что поток отсекается ровно там. */
static void expect(const char *name, int lvl, const char *what)
{
    char msg[128];
    slog_init(name);
    snprintf(msg, sizeof(msg), "log_level=%-7s -> %s", name, what);
    CHECK(slog_level() == lvl, msg);
}

int main(void)
{
    printf("=== соответствие имён уровней перечню в документации ===\n");
    expect("quiet", SL_QUIET, "тишина");
    expect("error", SL_ERROR, "только ошибки");
    expect("warn",  SL_WARN,  "ошибки и предупреждения");
    expect("info",  SL_INFO,  "события обучения");
    expect("debug", SL_DEBUG, "поштучный разбор");
    expect("trace", SL_TRACE, "всё");

    printf("\n=== warn: предупреждения пишутся, INFO — нет ===\n");
    slog_init("warn");
    CHECK(slog_enabled(SL_ERROR) == 1, "error проходит");
    CHECK(slog_enabled(SL_WARN)  == 1, "warn проходит");
    CHECK(slog_enabled(SL_INFO)  == 0, "info НЕ пишется");
    CHECK(slog_enabled(SL_DEBUG) == 0, "debug НЕ пишется");
    CHECK(slog_enabled(SL_TRACE) == 0, "trace НЕ пишется");

    printf("\n=== error: предупреждений тоже нет ===\n");
    slog_init("error");
    CHECK(slog_enabled(SL_ERROR) == 1, "error проходит");
    CHECK(slog_enabled(SL_WARN)  == 0, "warn НЕ пишется");

    printf("\n=== неизвестное имя: откат на info (и это видит config check) ===\n");
    slog_init("warrn");
    CHECK(slog_level() == SL_INFO, "опечатка не делает тише — включается info");

    printf("\n=== NULL не роняет и не меняет уровень ===\n");
    slog_init("quiet");
    slog_init(NULL);
    CHECK(slog_level() == SL_QUIET, "вызов без значения безопасен");

    printf("\n%s\n", failures ? "ЕСТЬ ОШИБКИ" : "все проверки пройдены");
    return failures ? 1 : 0;
}
