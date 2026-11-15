/* Тесты config_sync: дописывать отсутствующие ключи, не трогая пользовательские,
 * не создавая дублей и будучи идемпотентным.
 * make test (хост-компилятор; в поставку не входит).
 */
#define _GNU_SOURCE
#include "config.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures = 0;
#define CHECK(cond, msg) do { if (cond) printf("ok  %s\n", msg); \
    else { printf("FAIL %s\n", msg); failures++; } } while (0)

#define PATH_ "/tmp/susanin_test_conf_sync.conf"

static void write_seed(void)
{
    FILE *f = fopen(PATH_, "w");
    /* Строка с пробелом перед '=' — config_load такие принимает, и sync не
     * должен из-за этого считать ключ отсутствующим (иначе дубль). */
    fputs("# Susanin.Keenetic runtime configuration.\n"
          "egress_type=tproxy\n"
          "ok_ttl=60\n"
          "lan_interfaces = br0, br1\n"
          "log_level=info\n", f);
    fclose(f);
}

static long filesize(void)
{
    FILE *f = fopen(PATH_, "r");
    long n = 0;
    if (!f)
        return -1;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fclose(f);
    return n;
}

/* Сколько раз ключ встречается как "key=" (с возможными пробелами) — ловит дубли. */
static int count_key(const char *key)
{
    FILE *f = fopen(PATH_, "r");
    char line[1024];
    int n = 0;
    if (!f)
        return -1;
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t')
            p++;
        if (strncmp(p, key, strlen(key)) == 0) {
            p += strlen(key);
            while (*p == ' ' || *p == '\t')
                p++;
            if (*p == '=')
                n++;
        }
    }
    fclose(f);
    return n;
}

static int value_of(const char *key, char *out, size_t n)
{
    FILE *f = fopen(PATH_, "r");
    char line[1024];
    int found = 0;
    if (!f)
        return 0;
    while (fgets(line, sizeof(line), f)) {
        char *p = line, *v;
        while (*p == ' ' || *p == '\t')
            p++;
        if (strncmp(p, key, strlen(key)) != 0)
            continue;
        p += strlen(key);
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p != '=')
            continue;
        p++;
        while (*p == ' ' || *p == '\t')
            p++;
        v = p;
        while (*v && *v != '\n' && *v != '\r')
            v++;
        *v = '\0';
        snprintf(out, n, "%s", p);
        found = 1;
    }
    fclose(f);
    return found;
}

int main(void)
{
    susanin_config cfg;
    long sz0, sz1;
    int n, n2;
    char v[128];

    slog_init("quiet");

    write_seed();
    sz0 = filesize();

    printf("=== dry-run не трогает файл ===\n");
    n = config_sync(PATH_, 1);
    CHECK(n > 0, "dry-run сообщает о недостающих ключах");
    CHECK(filesize() == sz0, "dry-run не изменил файл");

    printf("=== sync дописывает ===\n");
    n2 = config_sync(PATH_, 0);
    CHECK(n2 == n, "число добавленных совпадает с dry-run");
    CHECK(filesize() > sz0, "файл вырос");

    printf("=== пользовательские значения сохранены ===\n");
    CHECK(count_key("egress_type") == 1, "egress_type не задублирован");
    CHECK(value_of("egress_type", v, sizeof(v)) && !strcmp(v, "tproxy"),
          "egress_type=tproxy сохранён");
    CHECK(count_key("ok_ttl") == 1, "ok_ttl не задублирован");
    CHECK(value_of("ok_ttl", v, sizeof(v)) && !strcmp(v, "60"),
          "ok_ttl=60 (своё) не перезаписан дефолтом");
    /* Ключ, записанный с пробелами: обязан остаться одним. */
    CHECK(count_key("lan_interfaces") == 1,
          "ключ с пробелами вокруг '=' не получил дубль");
    CHECK(value_of("lan_interfaces", v, sizeof(v)) && !strcmp(v, "br0, br1"),
          "значение lan_interfaces сохранено как было");

    printf("=== недостающий ключ появился с действующим дефолтом ===\n");
    CHECK(count_key("synfail_quorum") == 1, "synfail_quorum дописан ровно один раз");
    CHECK(config_load(PATH_, &cfg) == 0, "результат читается");
    CHECK(cfg.synfail_quorum == 3, "synfail_quorum = дефолт 3");
    CHECK(cfg.synfail_window == 120, "synfail_window = дефолт 120");
    CHECK(cfg.ok_ttl == 60, "прочитанный ok_ttl = пользовательские 60");
    CHECK(!strcmp(cfg.egress_type, "tproxy"), "прочитанный egress_type = tproxy");

    printf("=== идемпотентность ===\n");
    sz1 = filesize();
    CHECK(config_sync(PATH_, 0) == 0, "второй sync ничего не добавляет");
    CHECK(filesize() == sz1, "файл не изменился при повторе");

    printf("=== отсутствующий файл: не создаём молча ===\n");
    remove(PATH_);
    CHECK(config_sync(PATH_, 0) < 0 || filesize() < 0,
          "без файла sync не пишет новый конфиг");

    remove(PATH_);
    printf("\n%s\n", failures ? "ЕСТЬ ОШИБКИ" : "ИТОГ: все проверки пройдены");
    return failures ? 1 : 0;
}
