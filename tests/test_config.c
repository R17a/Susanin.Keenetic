/* Тесты пресета precision (apply_precision через config_load).
 * Хост-компилятор: make test. */
#define _GNU_SOURCE
#include "config.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int failures = 0;
#define CHECK(cond, msg) do { if (cond) printf("ok  %s\n", msg); \
    else { printf("FAIL %s\n", msg); failures++; } } while (0)

static const char *write_cfg(const char *text)
{
    static const char *path = "/tmp/susanin-test.conf";
    FILE *f = fopen(path, "wb");
    assert(f);
    fputs(text, f);
    fclose(f);
    return path;
}

int main(void)
{
    susanin_config cfg;

    printf("=== precision=strict (значения по умолчанию) ===\n");
    config_load(write_cfg("precision=strict\n"), &cfg);
    CHECK(cfg.fast_syn_min_op == 3, "fast_syn_min_op=3");
    CHECK(cfg.ok_evict_misses == 5, "ok_evict_misses=5");
    CHECK(cfg.learn_min_op == 14, "learn_min_op=14");
    CHECK(cfg.learn_min_bytes == 3000, "learn_min_bytes=3000");
    CHECK(cfg.confirm_min_bytes == 1024, "confirm_min_bytes=1024");
    CHECK(cfg.learn_strict == 0, "learn_strict не меняется пресетом");

    printf("=== precision=aggressive ===\n");
    config_load(write_cfg("precision=aggressive\n"), &cfg);
    CHECK(cfg.fast_syn_min_op == 1, "fast_syn_min_op=1");
    CHECK(cfg.ok_evict_misses == 2, "ok_evict_misses=2");
    CHECK(cfg.confirm_min_bytes == 256, "confirm_min_bytes=256");

    printf("=== явный ключ сильнее пресета ===\n");
    config_load(write_cfg("precision=aggressive\nlearn_min_op=20\n"), &cfg);
    CHECK(cfg.learn_min_op == 20, "явный learn_min_op=20 сохранён");
    CHECK(cfg.fast_syn_min_op == 1, "остальные пороги из пресета");

    printf("=== normal/пусто/неизвестный ===\n");
    config_load(write_cfg("precision=normal\n"), &cfg);
    CHECK(cfg.fast_syn_min_op == 2, "normal: значения по умолчанию");
    config_load(write_cfg("precision=\n"), &cfg);
    CHECK(cfg.confirm_min_bytes == 512, "пустой пресет: значения по умолчанию");
    config_load(write_cfg("precision=strong\n"), &cfg);
    CHECK(cfg.fast_syn_min_op == 2 && cfg.confirm_min_bytes == 512,
          "неизвестный пресет игнорируется (и пишет warning в stderr)");

    remove("/tmp/susanin-test.conf");
    printf("\n%s\n", failures ? "ЕСТЬ ОШИБКИ" : "все проверки пройдены");
    return failures ? 1 : 0;
}
