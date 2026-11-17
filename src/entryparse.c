#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "entryparse.h"

static int valid_cidr(const char *s, char *out, size_t n)
{
    char buf[48], *slash, *e;
    struct in_addr a;
    long pre;
    if (strlen(s) >= sizeof(buf))
        return 0;
    snprintf(buf, sizeof(buf), "%s", s);
    slash = strchr(buf, '/');
    if (!slash)
        return 0;
    *slash = '\0';
    if (inet_pton(AF_INET, buf, &a) != 1)
        return 0;
    errno = 0;
    pre = strtol(slash + 1, &e, 10);
    if (e == slash + 1 || *e != '\0' || errno != 0 || pre < 0 || pre > 32)
        return 0;
    {
        in_addr_t mask = pre == 0 ? 0u : (in_addr_t)(0xffffffffu << (32 - (int)pre));
        struct in_addr na;
        char nb[INET_ADDRSTRLEN];
        na.s_addr = htonl(ntohl(a.s_addr) & mask);
        if (!inet_ntop(AF_INET, &na, nb, sizeof(nb)))
            return 0;
        snprintf(out, n, "%s/%ld", nb, pre);
    }
    return 1;
}

static int valid_name(const char *s, char *out, size_t n, int *is_net)
{
    struct in_addr a;
    const char *p;
    size_t len = strlen(s);
    *is_net = 0;
    if (len == 0 || len >= n)
        return 0;
    if (inet_pton(AF_INET, s, &a) == 1) {
        snprintf(out, n, "%s", s);
        return 1;
    }
    if (strchr(s, '/')) {
        *is_net = 1;
        return valid_cidr(s, out, n);
    }
    if (len > 253)
        return 0;
    for (p = s; *p; p++) {
        char c = *p;
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '.' || c == '-'))
            return 0;
    }
    snprintf(out, n, "%s", s);
    return 1;
}

int entry_parse(const char *line, char *out, size_t n,
                int *is_wild, int *is_net, int *is_soft)
{
    char buf[320];
    char *p;
    size_t l;
    int soft = 0, wild = 0, net = 0;

    if (is_wild)
        *is_wild = 0;
    if (is_net)
        *is_net = 0;
    if (is_soft)
        *is_soft = 0;
    if (!line || !out || n == 0)
        return 0;
    snprintf(buf, sizeof(buf), "%s", line);
    l = strlen(buf);
    while (l > 0 && (buf[l - 1] == ' ' || buf[l - 1] == '\t' ||
                     buf[l - 1] == '\r' || buf[l - 1] == '\n'))
        buf[--l] = '\0';
    p = buf;
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p == '\0' || *p == '#')
        return 0;
    if (*p == '?') {
        soft = 1;
        p++;
        while (*p == ' ' || *p == '\t')
            p++;
    }
    if (p[0] == '*' && p[1] == '.') {
        wild = 1;
        p += 2;
    }
    {
        size_t i;
        for (i = 0; p[i]; i++)
            p[i] = (char)tolower((unsigned char)p[i]);
    }
    if (!valid_name(p, out, n, &net))
        return 0;
    /* Пустая запись после '?' или '*.' — мусор, а не запись. */
    if (out[0] == '\0' || (!net && !strcmp(out, ".")))
        return 0;
    if (is_wild)
        *is_wild = wild;
    if (is_net)
        *is_net = net;
    if (is_soft)
        *is_soft = soft;
    return 1;
}
