/* Тест мягкой записи (?) в vpn_always: перечитывание файла и дедуп.
 * vpn_always.c включается в TU — file_load/doms_reconcile остаются static,
 * а на хосте вызываются без сети: сами функции только читают файл и
 * согласуют массив доменов (резолв/ipset в этом пути не дёргаются).
 *
 * Честно о покрытии: снятие IP-пинов при «жёсткая -> мягкая» делает шаг
 * desired внутри va_refresh (он зовёт backend_*), здесь проверено только
 * применение soft-флага к живой записи и сброс срока при обратном переходе —
 * то, из-за чего правка файла раньше не действовала до рестарта.
 */
#define _GNU_SOURCE
#include "vpn_always.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures = 0;
#define CHECK(cond, msg) do { if (cond) printf("ok  %s\n", msg); \
    else { printf("FAIL %s\n", msg); failures++; } } while (0)

static char list_path[64];

static void write_lines(const char *a, const char *b)
{
    FILE *f = fopen(list_path, "w");
    if (!f) {
        printf("FAIL: не создать тестовый список\n");
        exit(1);
    }
    fprintf(f, "%s\n", a);
    if (b && b[0])
        fprintf(f, "%s\n", b);
    fclose(f);
}

/* Перечитать файл и прогнать doms_reconcile — ровно тот путь, который
 * va_refresh делает при изменении файла. */
static int reload_into(vpn_always *v)
{
    char (*names)[256] = calloc(VA_MAXDOM, sizeof(*names));
    int *wilds = calloc(VA_MAXDOM, sizeof(*wilds));
    int *softs = calloc(VA_MAXDOM, sizeof(*softs));
    int n = -1;
    if (names && wilds && softs) {
        n = file_load(list_path, names, wilds, softs, VA_MAXDOM);
        if (n >= 0)
            doms_reconcile(v, names, wilds, softs, n);
    }
    free(names);
    free(wilds);
    free(softs);
    return n;
}

int main(void)
{
    vpn_always *v;
    va_dom *d;
    char names[8][256];
    int wilds[8], softs[8], n;
    FILE *f;

    snprintf(list_path, sizeof(list_path), "/tmp/susanin-va-soft.XXXXXX");
    {
        int fd = mkstemp(list_path);
        if (fd < 0) {
            printf("FAIL: mkstemp\n");
            return 1;
        }
        close(fd);
    }
    v = va_new();
    if (!v) {
        printf("FAIL: нет памяти\n");
        return 1;
    }

    /* 1. (А1) Файл был «a.com», стал «?a.com»: перечитывание обязано
     *    применить мягкость к ЖИВОЙ записи (прежний doms_reconcile копировал
     *    старую структуру и терял new soft до рестарта демона). */
    write_lines("a.com", NULL);
    CHECK(reload_into(v) == 1, "reconcile: жёсткая запись загружена");
    d = dom_find(v, "a.com", 0);
    CHECK(d && d->soft == 0, "reconcile: soft=0");
    write_lines("?a.com", NULL);
    CHECK(reload_into(v) == 1, "reconcile: перечитывание прошло");
    d = dom_find(v, "a.com", 0);
    CHECK(d && d->soft == 1, "(A1) domain -> ?domain применяется без рестарта");

    /* Обратный переход «?a.com» -> «a.com»: снова жёстко и срок сброшен
     * (резолв в ближайшем проходе, а не после next_try мягкой эры). */
    if (d)
        d->next_try = 1234567890;
    write_lines("a.com", NULL);
    reload_into(v);
    d = dom_find(v, "a.com", 0);
    CHECK(d && d->soft == 0 && d->next_try == 0,
          "(A1) ?domain -> domain: жёстко и резолвим заново");

    /* 2. (А2) Дедуп: name+wild+soft — один ключ; конфликт мягкой и жёсткой
     *    записей одной зоны решается в пользу жёсткой при любом порядке. */
    n = file_load((write_lines("b.com", "?b.com"), list_path),
                  names, wilds, softs, 8);
    CHECK(n == 1 && softs[0] == 0, "(A2) b.com + ?b.com: одна жёсткая запись");
    n = file_load((write_lines("?c.com", "c.com"), list_path),
                  names, wilds, softs, 8);
    CHECK(n == 1 && softs[0] == 0, "(A2) ?c.com + c.com: жёсткая переопределяет");
    n = file_load((write_lines("d.com", "d.com"), list_path),
                  names, wilds, softs, 8);
    CHECK(n == 1, "(A2) полный дубликат схлопнут");
    n = file_load((write_lines("*.e.com", "?*.e.com"), list_path),
                  names, wilds, softs, 8);
    CHECK(n == 1 && wilds[0] == 1 && softs[0] == 0,
          "(A2) *.e.com + ?*.e.com: одна жёсткая зона");
    n = file_load((write_lines("f.com", "?g.com"), list_path),
                  names, wilds, softs, 8);
    CHECK(n == 2 && softs[0] == 0 && softs[1] == 1,
          "(A2) разные домены не дедупятся");

    /* 3. Единая грамматика (А4): «? x» и «*x» в файл-лидере не проходят. */
    n = file_load((write_lines("? h.com", "*i.com"), list_path),
                  names, wilds, softs, 8);
    CHECK(n == 0, "(A4) «? h.com» и «*i.com» — мусор, не записи");

    va_free(v);
    f = NULL; (void)f;
    unlink(list_path);
    if (failures) {
        printf("FAILURES: %d\n", failures);
        return 1;
    }
    printf("all va_soft tests passed\n");
    return 0;
}
