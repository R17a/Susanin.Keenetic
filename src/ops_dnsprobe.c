#define _GNU_SOURCE
#include "ops.h"
#include "config.h"
#include "log.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* DNS-запрос напрямую в форвардер (или любой сервер): проверяет путь
 * «форвардер -> туннель», не задействуя DNAT и клиентов. */
static int q_put(unsigned char *b, int n, const char *name, unsigned type)
{
    const char *p = name;
    int i = 0;

    while (*p) {
        const char *dot = strchr(p, '.');
        int l = dot ? (int)(dot - p) : (int)strlen(p);
        if (l <= 0 || l > 63 || n + 1 + l + 5 > 512)
            return -1;
        b[n++] = (unsigned char)l;
        memcpy(b + n, p, (size_t)l);
        n += l;
        p = dot ? dot + 1 : p + (size_t)l;
        if (!dot)
            break;
        i++;
        if (i > 64)
            return -1;
    }
    b[n++] = 0;
    b[n++] = (unsigned char)(type >> 8);
    b[n++] = (unsigned char)(type & 0xff);
    b[n++] = 0; b[n++] = 1;
    return n;
}

/* Пропустить имя (с учётом сжатия). */
static int skip_name(const unsigned char *m, int len, int off)
{
    while (off < len) {
        if ((m[off] & 0xc0) == 0xc0)
            return off + 2;
        if (m[off] == 0)
            return off + 1;
        off += 1 + m[off];
    }
    return -1;
}

static int answer(const unsigned char *m, int len, int want_type, char *out, size_t on)
{
    int qd = (m[4] << 8) | m[5];
    int an = (m[6] << 8) | m[7];
    int off = 12, i, got = 0;
    char line[128];

    for (i = 0; i < qd; i++) {
        off = skip_name(m, len, off);
        if (off < 0 || off + 4 > len)
            return -1;
        off += 4;
    }
    for (i = 0; i < an && off < len; i++) {
        int type, rdlen;
        off = skip_name(m, len, off);
        if (off < 0 || off + 10 > len)
            return -1;
        type = (m[off] << 8) | m[off + 1];
        rdlen = (m[off + 8] << 8) | m[off + 9];
        off += 10;
        if (off + rdlen > len)
            return -1;
        if (type == want_type && ((want_type == 1 && rdlen == 4) ||
                                  (want_type == 28 && rdlen == 16))) {
            char ip[64];
            if (want_type == 1)
                inet_ntop(AF_INET, m + off, ip, sizeof(ip));
            else
                inet_ntop(AF_INET6, m + off, ip, sizeof(ip));
            snprintf(line, sizeof(line), "%s", ip);
            if (got)
                strncat(out, " ", on - strlen(out) - 1);
            strncat(out, line, on - strlen(out) - 1);
            got++;
        }
        off += rdlen;
    }
    return got;
}

int ops_dnsprobe(const susanin_config *cfg, const char *name, const char *server,
                 int port, int verbose)
{
    unsigned char q[512], resp[1500];
    struct sockaddr_in sa;
    unsigned id = (unsigned)((time(NULL) ^ (getpid() << 8)) & 0xffff);
    int n, rn, fd, a, aaaa;
    char ip4[512] = "", ip6[512] = "";
    const char *srv = server && server[0] ? server : "127.0.0.1";

    if (!name || !name[0]) {
        fprintf(stderr, "dnsprobe: укажите домен\n");
        return 2;
    }
    if (port <= 0)
        port = 5399;
    memset(q, 0, sizeof(q));
    q[0] = (unsigned char)(id >> 8);
    q[1] = (unsigned char)(id & 0xff);
    q[2] = 0x01;
    q[5] = 0x01;
    n = 12;
    n = q_put(q, n, name, 1);
    if (n < 0) {
        fprintf(stderr, "dnsprobe: имя не разобрано\n");
        return 2;
    }
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, srv, &sa.sin_addr) != 1) {
        fprintf(stderr, "dnsprobe: сервер '%s' — не IPv4\n", srv);
        return 2;
    }
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("dnsprobe: socket");
        return 2;
    }
    if (sendto(fd, q, (size_t)n, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("dnsprobe: sendto");
        close(fd);
        return 2;
    }
    {
        struct pollfd p = { fd, POLLIN, 0 };
        if (poll(&p, 1, 3000) != 1) {
            printf("dnsprobe %s via %s:%d — НЕТ ОТВЕТА за 3 с\n", name, srv, port);
            close(fd);
            return 1;
        }
    }
    rn = (int)recv(fd, resp, sizeof(resp), 0);
    close(fd);
    if (rn < 12) {
        printf("dnsprobe %s via %s:%d — короткий ответ (%d байт)\n", name, srv, port, rn);
        return 1;
    }
    printf("dnsprobe %s via %s:%d (rcode=%d, answers=%d)%s\n", name, srv, port,
           resp[3] & 0x0f, (resp[6] << 8) | resp[7],
           (cfg && cfg->dns_lan) ? "" : "  [dns_lan=0]");
    a = answer(resp, rn, 1, ip4, sizeof(ip4));
    aaaa = answer(resp, rn, 28, ip6, sizeof(ip6));
    if (a > 0)
        printf("  A    : %s\n", ip4);
    if (aaaa > 0)
        printf("  AAAA : %s\n", ip6);
    if (a <= 0 && aaaa <= 0) {
        printf("  записей A/AAAA нет\n");
        return 1;
    }
    (void)verbose;
    return 0;
}
