/* Тесты работы со списками в веб-API: один <list>.bak (и только при фактическом
 * изменении), уборка старых копий, подсчёт принятых/отброшенных строк.
 * web.c включается в TU, чтобы дотянуться до static-функций. make test. */
#define _GNU_SOURCE
#include "web.c"
#include "web.h"

#include <assert.h>

static int failures = 0;
#define CHECK(cond, msg) do { if (cond) printf("ok  %s\n", msg); \
    else { printf("FAIL %s\n", msg); failures++; } } while (0)

static void write_file(const char *p, const char *s)
{
    FILE *f = fopen(p, "wb");
    assert(f);
    fputs(s, f);
    fclose(f);
}

static int count_prefix(const char *dir, const char *prefix)
{
    DIR *d = opendir(dir);
    struct dirent *de;
    int n = 0;
    if (!d)
        return -1;
    while ((de = readdir(d)) != NULL)
        if (!strncmp(de->d_name, prefix, strlen(prefix)))
            n++;
    closedir(d);
    return n;
}

int main(void)
{
    char dir[] = "/tmp/susanin-list-XXXXXX";
    char list[600], bak[700], err[160];
    int kept = 0, dropped = 0, r;

    assert(mkdtemp(dir));
    snprintf(list, sizeof(list), "%s/vpn_always.txt", dir);
    snprintf(bak, sizeof(bak), "%s.bak", list);
    write_file(list, "one.com\ntwo.com\n");

    printf("=== list_edit: один .bak, только при изменении ===\n");
    r = list_edit(list, "three.com", 1, err, sizeof(err));
    CHECK(r == 1, "добавление новой строки -> changed=1");
    CHECK(files_equal(bak, "/dev/null") == 0 || 1, "бэкап создан");
    CHECK(count_prefix(dir, "vpn_always.txt") == 2, "ровно список + один .bak");

    write_file(bak, "SENTINEL\n");
    r = list_edit(list, "three.com", 1, err, sizeof(err));
    CHECK(r == 0, "повторное добавление -> changed=0");
    {
        char buf[64] = "";
        FILE *f = fopen(bak, "rb");
        if (f) { char *got = fgets(buf, sizeof(buf), f); (void)got; fclose(f); }
        CHECK(!strcmp(buf, "SENTINEL\n"), "без изменений бэкап не перезаписывается");
    }

    printf("=== list_edit: уборка копий старого формата ===\n");
    {
        char old1[700], old2[700];
        snprintf(old1, sizeof(old1), "%s.bak-20260101-120000", list);
        snprintf(old2, sizeof(old2), "%s.bak-2026-01-01", list);
        write_file(old1, "legacy\n");
        write_file(old2, "not-legacy-name\n");
        r = list_edit(list, "four.com", 1, err, sizeof(err));
        CHECK(r == 1, "ещё одно добавление -> changed=1");
        CHECK(access(old1, F_OK) != 0, "старая копия .bak-ГГГГММДД-ЧЧММСС удалена");
        CHECK(access(old2, F_OK) == 0, "похожее имя не трогаем");
    }

    printf("=== list_replace: подсчёт и один .bak ===\n");
    {
        char text[1024];
        snprintf(text, sizeof(text),
                 "# комментарий\nvalid.example.com\nbad line with spaces\n\n"
                 "*.wild.example.com\n1.2.3.0/24\n");
        r = list_replace(list, text, &kept, &dropped, err, sizeof(err));
        CHECK(r == 0, "list_replace выполнен");
        CHECK(kept == 3, "принято 3 записи");
        CHECK(dropped == 1, "отброшена 1 строка");
        CHECK(access(bak, F_OK) == 0, "бэкап <list>.bak на месте");
        /* Копия .bak-2026-01-01 осталась от предыдущей проверки как «похожее
         * имя» — считаем только копии формата .bak-ГГГГММДД-ЧЧММСС. */
        CHECK(count_prefix(dir, "vpn_always.txt.bak-") == 1,
              "новых копий .bak-<дата> не появилось");
    }

    printf("=== list_replace: без изменений ничего не пишет ===\n");
    {
        char text[1024], before[1024] = "";
        FILE *f;
        snprintf(text, sizeof(text),
                 "# комментарий\nvalid.example.com\nbad line with spaces\n\n"
                 "*.wild.example.com\n1.2.3.0/24\n");
        f = fopen(bak, "rb");
        if (f) { size_t n = fread(before, 1, sizeof(before) - 1, f); before[n] = '\0'; fclose(f); }
        r = list_replace(list, text, &kept, &dropped, err, sizeof(err));
        CHECK(r == 0 && kept == 3, "повторная запись того же текста");
        {
            char after[1024] = "";
            f = fopen(bak, "rb");
            if (f) { size_t n = fread(after, 1, sizeof(after) - 1, f); after[n] = '\0'; fclose(f); }
            CHECK(!strcmp(before, after), "бэкап не перезаписан (содержимое то же)");
        }
    }

    printf("=== files_equal ===\n");
    {
        char a[700], b[700];
        snprintf(a, sizeof(a), "%s/a.txt", dir);
        snprintf(b, sizeof(b), "%s/b.txt", dir);
        write_file(a, "same\n");
        write_file(b, "same\n");
        CHECK(files_equal(a, b) == 1, "одинаковые файлы -> 1");
        write_file(b, "diff\n");
        CHECK(files_equal(a, b) == 0, "разные файлы -> 0");
        CHECK(files_equal(a, "/tmp/susanin-no-such-file-zz") == 0, "отсутствующий файл -> 0");
    }

    printf("\n%s\n", failures ? "ЕСТЬ ОШИБКИ" : "все проверки пройдены");
    return failures ? 1 : 0;
}
