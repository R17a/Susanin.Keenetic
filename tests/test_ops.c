/* Тесты rule_fwmark_present() (проверка `ip rule` с маской и без неё).
 * Хост-компилятор: make test. Фейковый `ip` печатает строки из $FAKE_RULE. */
#define _GNU_SOURCE
#include "ops.c"
#include "ops.h"

#include <assert.h>
#include <sys/stat.h>

static int failures = 0;
#define CHECK(cond, msg) do { if (cond) printf("ok  %s\n", msg); \
    else { printf("FAIL %s\n", msg); failures++; } } while (0)

static void write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    assert(f);
    fputs(text, f);
    fclose(f);
}

static void make_fake_ip(const char *path)
{
    FILE *f = fopen(path, "wb");
    assert(f);
    fputs("#!/bin/sh\ncat \"$FAKE_RULE\"\n", f);
    fclose(f);
    chmod(path, 0755);
}

int main(void)
{
    const char *fakip = "/tmp/susanin-fake-ip";
    const char *rules = "/tmp/susanin-fake-rule.txt";

    make_fake_ip(fakip);
    putenv((char *)"FAKE_RULE=/tmp/susanin-fake-rule.txt");

    printf("=== rule_fwmark_present ===\n");
    write_file(rules, "2000:\tfrom all fwmark 0x20000000/0x30000000 lookup 100\n"
                      "2001:\tfrom all fwmark 0x10000000/0x30000000 lookup 100\n");
    CHECK(rule_fwmark_present(fakip, 0x20000000UL, 0x30000000UL, 100) == 1,
          "правило с маской (как ставит datapath.sh) найдено");
    CHECK(rule_fwmark_present(fakip, 0x10000000UL, 0x30000000UL, 100) == 1,
          "test-правило с маской найдено");

    write_file(rules, "2000:\tfrom all fwmark 0x20000000 lookup 100\n");
    CHECK(rule_fwmark_present(fakip, 0x20000000UL, 0x30000000UL, 100) == 1,
          "старая форма без маски тоже засчитывается");

    write_file(rules, "2000:\tfrom all fwmark 0x20000000/0x00ff0000 lookup 100\n");
    CHECK(rule_fwmark_present(fakip, 0x20000000UL, 0x30000000UL, 100) == 0,
          "чужая маска не засчитывается");
    write_file(rules, "2000:\tfrom all fwmark 0x20000000/0x30000000 lookup 200\n");
    CHECK(rule_fwmark_present(fakip, 0x20000000UL, 0x30000000UL, 100) == 0,
          "чужая таблица не засчитывается");
    write_file(rules, "100:\tfrom all fwmark 0xffffa00/0xffffffff lookup 4096\n");
    CHECK(rule_fwmark_present(fakip, 0x20000000UL, 0x30000000UL, 100) == 0,
          "политика Keenetic (0xffffaXX) не засчитывается");

    write_file(rules, "2002:\tfrom all fwmark 0x1 lookup 100\n");
    CHECK(rule_fwmark_present(fakip, 0x1UL, 0xffffffffUL, 100) == 1,
          "tproxy fwmark 0x1 (без маски) найден");
    write_file(rules, "2002:\tfrom all fwmark 0x1/0xffffffff lookup 100\n");
    CHECK(rule_fwmark_present(fakip, 0x1UL, 0xffffffffUL, 100) == 1,
          "tproxy fwmark 0x1/0xffffffff найден");

    remove(fakip);
    remove(rules);
    printf("\n%s\n", failures ? "ЕСТЬ ОШИБКИ" : "все проверки пройдены");
    return failures ? 1 : 0;
}
