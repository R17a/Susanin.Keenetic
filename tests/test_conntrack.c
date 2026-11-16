/* Тест парсера conntrack: гоняет conntrack_parse_line() по сэмплам из
 * testdata/nf_conntrack.samples и сверяет поля с ожидаемыми.
 *
 * Сборка/запуск: make test   (или вручную)
 *   cc -O2 -std=c11 -Wall -Wextra -Wpedantic -o tests/test_conntrack \
 *      tests/test_conntrack.c src/conntrack.c && ./tests/test_conntrack testdata/nf_conntrack.samples
 */
#include "conntrack.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

static int split_line(char *s)   /* обрезает перевод строки, возвращает длину */
{
    size_t l = strlen(s);
    while (l && (s[l - 1] == '\n' || s[l - 1] == '\r'))
        s[--l] = '\0';
    while (l && (s[l - 1] == ' ' || s[l - 1] == '\t'))
        s[--l] = '\0';
    return (int)l;
}

/* Приём записей сканом — для проверки обрезанных строк. */
static char g_seen[8][64];
static int g_seen_n;

static int collect_cb(void *ud, const ct_flow *f)
{
    (void)ud;
    if (g_seen_n < 8)
        snprintf(g_seen[g_seen_n], sizeof(g_seen[0]), "%s", f->dst);
    g_seen_n++;
    return 0;
}

int main(int argc, char **argv)
{
    FILE *fp;
    char line[4096];
    int n = 0, bad = 0;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <samples-file>\n", argv[0]);
        return 2;
    }
    fp = fopen(argv[1], "r");
    if (!fp) {
        fprintf(stderr, "cannot open %s\n", argv[1]);
        return 2;
    }
    while (fgets(line, sizeof(line), fp)) {
        char *p = line, *bar;
        char exp_state[32] = "-", exp_src[64] = "", exp_dst[64] = "";
        int rc_exp = 0, l4_exp = 0, fast_exp = 0;
        unsigned sport_exp = 0, dport_exp = 0;
        unsigned long op_exp = 0, ob_exp = 0, rp_exp = 0, rb_exp = 0, mark_exp = 0;
        ct_flow f;
        int rc;

        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '\0' || *p == '\n' || *p == '#')
            continue;
        if (split_line(p) == 0)
            continue;
        bar = strchr(p, '|');
        if (!bar) {
            printf("FAIL[%d] нет разделителя '|': %s\n", n + 1, p);
            bad++;
            continue;
        }
        *bar = '\0';
        split_line(p);   /* убираем хвостовые пробелы самой строки conntrack */
        if (sscanf(bar + 1, "%d %d %31s %63s %u %63s %u %lu %lu %lu %lu %lu %d",
                   &rc_exp, &l4_exp, exp_state, exp_src, &sport_exp, exp_dst,
                   &dport_exp, &op_exp, &ob_exp, &rp_exp, &rb_exp, &mark_exp,
                   &fast_exp) != 13) {
            printf("FAIL[%d] плохая ожидаемая часть: %s\n", n + 1, bar + 1);
            bad++;
            continue;
        }
        n++;
        rc = conntrack_parse_line(p, &f);
        if (rc != rc_exp) {
            printf("FAIL[%d] rc=%d, ожидалось %d: %s\n", n, rc, rc_exp, p);
            bad++;
            continue;
        }
        if (rc != 0) {
            printf("ok[%d] строка отброшена (как и ожидалось)\n", n);
            continue;
        }
        if (f.l4proto != l4_exp || f.sport != sport_exp || f.dport != dport_exp ||
            f.op != op_exp || f.ob != ob_exp || f.rp != rp_exp || f.rb != rb_exp ||
            f.ctmark != mark_exp || f.fastnat != fast_exp ||
            strcmp(f.src, exp_src) != 0 || strcmp(f.dst, exp_dst) != 0 ||
            (strcmp(exp_state, "-") != 0 && strcmp(f.tcp_state, exp_state) != 0) ||
            ((f.rp > 0) != (rp_exp > 0))) {
            printf("FAIL[%d] %s\n", n, p);
            printf("   получено: l4=%d proto=%s state=%s src=%s sport=%u dst=%s dport=%u"
                   " op=%lu ob=%lu rp=%lu rb=%lu mark=%lu fastnat=%d has_reply=%d\n",
                   f.l4proto, f.proto, f.tcp_state, f.src, f.sport, f.dst, f.dport,
                   f.op, f.ob, f.rp, f.rb, f.ctmark, f.fastnat, f.has_reply);
            bad++;
            continue;
        }
        printf("ok[%d] %s %s:%u -> %s:%u\n", n, f.proto, f.src, f.sport, f.dst, f.dport);
    }
    fclose(fp);
    printf("\n=== запись длиннее CT_LINE_MAX ===\n");
    {
        char p2l[160];
        const char *p2 = p2l;

        snprintf(p2l, sizeof(p2l), "/tmp/susanin-ct-trunc-%d.txt",
                 (int)getpid());
        unsigned long before = conntrack_overlong();
        FILE *w = fopen(p2, "w");
        int got, i;

        if (!w) {
            printf("SKIP: не удалось записать %s\n", p2);
        } else {
            /* 1) полностью корректная запись, но добитая до длины выше буфера:
             * src/dst в этом формате в середине/конце, поэтому обрезок
             * неразличим от «плохой строки» — его обязан пометить счётчик. */
            fputs("ipv4     2 tcp      6 431995 ESTABLISHED src=192.0.2.1 "
                  "dst=192.0.2.50 sport=51234 dport=443 packets=12 bytes=4096 "
                  "src=192.0.2.50 dst=192.0.2.1 sport=443 dport=51234 "
                  "packets=8 bytes=2048 [ASSURED] mark=0 use=1 ", w);
            for (i = 0; i < CT_LINE_MAX + 500; i++)
                fputc('x', w);
            fputs("\n", w);
            /* 2) обычная запись сразу после неё: если остаток длинной строки
             * не дочитан, следующим чтением мы взяли бы его середину. */
            fputs("ipv4     2 tcp      6 431995 ESTABLISHED src=192.0.2.2 "
                  "dst=192.0.2.51 sport=51235 dport=80 packets=12 bytes=4096 "
                  "src=192.0.2.51 dst=192.0.2.2 sport=80 dport=51235 "
                  "packets=8 bytes=2048 [ASSURED] mark=0 use=1\n", w);
            fclose(w);

            g_seen_n = 0;
            memset(g_seen, 0, sizeof(g_seen));
            got = conntrack_scan(p2, collect_cb, NULL);
            if (got == 1)
                printf("ok  разобрана ровно одна запись (обрезанная пропущена)\n");
            else {
                printf("FAIL  записей разобрано: %d, ожидалось 1\n", got);
                bad++;
            }
            if (conntrack_overlong() == before + 1)
                printf("ok  обрезанная запись учтена счётчиком\n");
            else {
                printf("FAIL  счётчик: +%lu, ожидалось +1\n",
                       conntrack_overlong() - before);
                bad++;
            }
            if (g_seen_n == 1 && !strcmp(g_seen[0], "192.0.2.51"))
                printf("ok  следующая запись прочитана целиком (остаток дочитан)\n");
            else {
                printf("FAIL  после обрезка принято %d записей, первая dst=%s\n",
                       g_seen_n, g_seen_n ? g_seen[0] : "-");
                bad++;
            }
            remove(p2);
        }
    }

    printf("\nстрок проверено: %d, ошибок: %d\n", n, bad);
    return bad ? 1 : 0;
}
