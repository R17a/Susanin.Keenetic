#define _GNU_SOURCE
#include "conntrack.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Быстрый ручной разбор IPv4 dotted-quad (host order): адреса разбираются для
 * каждого потока на каждом сканировании, inet_pton заметно дороже. Возвращает
 * 0, если это не IPv4 (IPv6/мусор); 0.0.0.0 тоже даёт 0 — в потоках conntrack
 * такие адреса не встречаются, а «не разобрано» важнее отличить от нуля. */
uint32_t ct_parse4(const char *s)
{
    uint32_t a = 0;
    int i, oct, digits;
    if (!s || !*s)
        return 0;
    for (i = 0; i < 4; i++) {
        oct = 0;
        digits = 0;
        while (*s >= '0' && *s <= '9') {
            oct = oct * 10 + (*s - '0');
            if (oct > 255)
                return 0;
            if (++digits > 3)
                return 0;
            s++;
        }
        if (!digits)
            return 0;
        a = (a << 8) | (uint32_t)oct;
        if (i < 3) {
            if (*s != '.')
                return 0;
            s++;
        }
    }
    if (*s != '\0')
        return 0;
    return a;
}

int conntrack_parse_line_mut(char *buf, ct_flow *f)
{
    char *save = NULL;
    char *tok;
    int idx = 0;
    int seen_src = 0, seen_dst = 0, seen_sport = 0, seen_dport = 0;
    int seen_op = 0, seen_rp = 0;

    if (!buf || !f)
        return -1;
    memset(f, 0, sizeof(*f));

    /* Диспетчеризация по первому символу токена: скан разбирает тысячи строк
     * в секунду, а прежняя цепочка перебирала до 9 префиксов на каждый токен.
     * Порядок проверки «префиксы -> состояние TCP (позиция 5) -> FASTNAT»
     * сохранён один в один с исходным. */
    tok = strtok_r(buf, " \t", &save);
    while (tok) {
        int matched = 1;
        switch (tok[0]) {
        case 's':
            if (!strncmp(tok, "src=", 4)) {
                if (!seen_src++) snprintf(f->src, sizeof(f->src), "%s", tok + 4);
            } else if (!strncmp(tok, "sport=", 6)) {
                if (!seen_sport++) f->sport = (unsigned)strtoul(tok + 6, NULL, 10);
                else f->r_sport = (unsigned)strtoul(tok + 6, NULL, 10);
            } else matched = 0;
            break;
        case 'd':
            if (!strncmp(tok, "dst=", 4)) {
                if (!seen_dst++) snprintf(f->dst, sizeof(f->dst), "%s", tok + 4);
            } else if (!strncmp(tok, "dport=", 6)) {
                if (!seen_dport++) f->dport = (unsigned)strtoul(tok + 6, NULL, 10);
                else f->r_dport = (unsigned)strtoul(tok + 6, NULL, 10);
            } else matched = 0;
            break;
        case 'p':
            if (!strncmp(tok, "packets=", 8)) {
                if (!seen_op++) f->op = strtoul(tok + 8, NULL, 10);
                else f->rp = strtoul(tok + 8, NULL, 10);
            } else matched = 0;
            break;
        case 'b':
            if (!strncmp(tok, "bytes=", 6)) {
                if (!seen_rp++) f->ob = strtoul(tok + 6, NULL, 10);
                else f->rb = strtoul(tok + 6, NULL, 10);
            } else matched = 0;
            break;
        case 'm':
            if (!strncmp(tok, "mark=", 5)) {
                f->ctmark = strtoul(tok + 5, NULL, 0);
            } else matched = 0;
            break;
        case 't':
            if (!strcmp(tok, "tcp")) {
                snprintf(f->proto, sizeof(f->proto), "tcp");
                f->l4proto = 6;
            } else matched = 0;
            break;
        case 'u':
            if (!strcmp(tok, "udp")) {
                snprintf(f->proto, sizeof(f->proto), "udp");
                f->l4proto = 17;
            } else matched = 0;
            break;
        case 'i':
            if (!strcmp(tok, "icmp")) {
                snprintf(f->proto, sizeof(f->proto), "icmp");
                f->l4proto = 1;
            } else matched = 0;
            break;
        default:
            matched = 0;
            break;
        }
        if (!matched) {
            if (idx == 5 && f->l4proto == 6)
                snprintf(f->tcp_state, sizeof(f->tcp_state), "%s", tok);
            else if (strstr(tok, "FASTNAT"))
                f->fastnat = 1;
        }
        idx++;
        tok = strtok_r(NULL, " \t", &save);
    }

    f->has_reply = (f->rp > 0);
    if (f->proto[0] == '\0' || f->dst[0] == '\0' || f->src[0] == '\0')
        return -1;
    f->src4 = ct_parse4(f->src);
    f->dst4 = ct_parse4(f->dst);
    return 0;
}

int conntrack_parse_line(const char *line, ct_flow *f)
{
    char buf[2048];
    if (!line || !f)
        return -1;
    snprintf(buf, sizeof(buf), "%s", line);
    return conntrack_parse_line_mut(buf, f);
}

int conntrack_scan(const char *path, ct_cb cb, void *ud)
{
    FILE *fp;
    char line[4096];
    int n = 0;

    fp = fopen(path ? path : "/proc/net/nf_conntrack", "r");
    if (!fp)
        return -1;
    while (fgets(line, sizeof(line), fp)) {
        ct_flow f;
        /* In-place: line — наш изменяемый буфер, следующая fgets его
         * перезапишет. Копия строки на каждую запись conntrack не нужна. */
        if (conntrack_parse_line_mut(line, &f) == 0) {
            n++;
            if (cb && cb(ud, &f) != 0)
                break;
        }
    }
    fclose(fp);
    return n;
}
