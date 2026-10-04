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
    printf("\nстрок проверено: %d, ошибок: %d\n", n, bad);
    return bad ? 1 : 0;
}
