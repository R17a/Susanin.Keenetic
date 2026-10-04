#define _GNU_SOURCE
#include "health.h"
#include "log.h"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#ifndef SO_MARK
#define SO_MARK 36
#endif
#ifndef SO_BINDTODEVICE
#define SO_BINDTODEVICE 25
#endif

/* Привязать сокет к устройству (для независимой пробы конкретного egress). */
static void bind_dev(int fd, const char *dev)
{
    if (dev && dev[0])
        (void)setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev,
                         (socklen_t)(strlen(dev) + 1));
}

static uint16_t csum(const void *data, int len)
{
    const uint16_t *p = data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len == 1) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static int probe_one(const char *dst, const char *src, const char *dev,
                     unsigned long mark)
{
    int fd;
    struct sockaddr_in sin, to;
    struct icmphdr icmp;
    char packet[64];
    char rbuf[512];
    int n;
    uint16_t id = (uint16_t)(getpid() & 0xffff);
    struct timeval tv;

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0)
        return -1;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    if (inet_pton(AF_INET, src, &sin.sin_addr) != 1) { close(fd); return -1; }

    bind_dev(fd, dev);
    setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
    if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) != 0) { close(fd); return -1; }

    memset(&icmp, 0, sizeof(icmp));
    icmp.type = ICMP_ECHO;
    icmp.code = 0;
    icmp.checksum = 0;
    icmp.un.echo.id = htons(id);
    icmp.un.echo.sequence = htons(1);
    memset(packet, 0xa5, sizeof(packet));
    memcpy(packet, &icmp, sizeof(icmp));
    ((struct icmphdr *)packet)->checksum = csum(packet, sizeof(packet));

    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = 0;
    if (inet_pton(AF_INET, dst, &to.sin_addr) != 1) { close(fd); return -1; }

    if (sendto(fd, packet, sizeof(packet), 0, (struct sockaddr *)&to, sizeof(to)) < 0) {
        close(fd); return -1;
    }

    tv.tv_sec = 0;
    tv.tv_usec = 700000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    for (;;) {
        struct iphdr *ip;
        int iplen;
        struct icmphdr *r;
        n = recvfrom(fd, rbuf, sizeof(rbuf), 0, NULL, NULL);
        if (n < 0)
            break;
        ip = (struct iphdr *)rbuf;
        iplen = (int)(ip->ihl * 4);
        if (n < iplen + (int)sizeof(struct icmphdr))
            continue;
        r = (struct icmphdr *)(rbuf + iplen);
        if (r->type == ICMP_ECHOREPLY && ntohs(r->un.echo.id) == id)
            { close(fd); return 1; }
    }
    close(fd);
    return 0;
}

/* TCP-проба туннеля: подходит для egress без ICMP (VLESS/XRay через TUN).
 * Успех — установилось TCP-соединение (даже если сервер сразу закрыл). */
static int probe_tcp(const char *dst, int port, const char *src, const char *dev,
                     unsigned long mark)
{
    int fd, r;
    struct sockaddr_in to, sin;
    struct timeval tv;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    bind_dev(fd, dev);
    if (src && src[0]) {
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        if (inet_pton(AF_INET, src, &sin.sin_addr) == 1)
            (void)bind(fd, (struct sockaddr *)&sin, sizeof(sin));
    }
    setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, dst, &to.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    r = connect(fd, (struct sockaddr *)&to, sizeof(to));
    close(fd);
    return r == 0 ? 1 : 0;
}

int health_probe_dev(const susanin_config *c, const char *dev, const char *src,
                     int *ok, int *total)
{
    char buf[512], *save = NULL, *tok;
    char srcbuf[64];
    int o = 0, t = 0;
    const char *psrc = src;
    if (!psrc || !psrc[0]) {
        /* egress_address — список: берём первый адрес. */
        char *comma;
        snprintf(srcbuf, sizeof(srcbuf), "%s", c->egress_address);
        comma = strchr(srcbuf, ',');
        if (comma)
            *comma = '\0';
        psrc = srcbuf;
    }
    int tcp_mode = !strcmp(c->health_mode, "tcp");
    int tcp_port = c->health_tcp_port > 0 ? c->health_tcp_port : 443;
    if (ok) *ok = 0;
    if (total) *total = 0;
    snprintf(buf, sizeof(buf), "%s", c->health_probe);
    for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        int r;
        while (*tok == ' ') tok++;
        t++;
        if (tcp_mode)
            r = probe_tcp(tok, tcp_port, psrc, dev, c->mark_test);
        else
            r = probe_one(tok, psrc, dev, c->mark_test);
        if (r > 0) o++;
        else if (r < 0)
            slogf(SL_DEBUG, "health probe to %s failed (%d)", tok, r);
    }
    if (ok) *ok = o;
    if (total) *total = t;
    return 0;
}

int health_probe(const susanin_config *c, const char *src, int *ok, int *total)
{
    return health_probe_dev(c, NULL, src, ok, total);
}

/* Проба апстрима Xray через локальный SOCKS5 (режим tproxy): Xray отвечает
 * успехом только если сам смог подключиться к цели. 1 = ok. */
int health_probe_via_socks(const susanin_config *c, const char *dst, int port,
                           int timeout_ms)
{
    int fd, r;
    struct sockaddr_in sa;
    struct timeval tv;
    unsigned char req[16], rep[32];
    struct in_addr a;

    if (!dst || !dst[0] || port <= 0 || port > 65535)
        return 0;
    if (inet_pton(AF_INET, dst, &a) != 1)
        return 0;
    if (timeout_ms <= 0)
        timeout_ms = 3000;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return 0;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)(c->socks_port > 0 ? c->socks_port : 1080));
    if (inet_pton(AF_INET, c->socks_addr[0] ? c->socks_addr : "127.0.0.1",
                  &sa.sin_addr) != 1) {
        close(fd);
        return 0;
    }
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        /* Xray мог ещё биндить порт — короткая пауза и один повтор. */
        usleep(200 * 1000);
        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
            close(fd);
            return 0;
        }
    }
    req[0] = 0x05; req[1] = 0x01; req[2] = 0x00;          /* приветствие, no-auth */
    if (send(fd, req, 3, 0) != 3) { close(fd); return 0; }
    if (recv(fd, rep, 2, 0) != 2 || rep[0] != 0x05 || rep[1] != 0x00) {
        close(fd);
        return 0;
    }
    memset(req, 0, sizeof(req));
    req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x01;   /* CONNECT IPv4 */
    memcpy(req + 4, &a.s_addr, 4);
    req[8] = (unsigned char)((port >> 8) & 0xff);
    req[9] = (unsigned char)(port & 0xff);
    if (send(fd, req, 10, 0) != 10) { close(fd); return 0; }
    r = (int)recv(fd, rep, sizeof(rep), 0);
    close(fd);
    if (r < 2 || rep[0] != 0x05)
        return 0;
    return rep[1] == 0x00 ? 1 : 0;
}

/* Прямая проба dst:port (без egress/метки — идёт по main, т.е. напрямую).
 * 1 = соединение установилось. Нужна, чтобы не заворачивать адрес в VPN,
 * если прямой путь отвечает. */
int health_probe_tcp_direct(const char *dst, unsigned port, int timeout_ms)
{
    int fd, r;
    struct sockaddr_in to;
    struct timeval tv;

    if (!dst || !dst[0] || port == 0 || port > 65535)
        return 0;
    if (timeout_ms <= 0)
        timeout_ms = 1200;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return 0;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, dst, &to.sin_addr) != 1) {
        close(fd);
        return 0;
    }
    r = connect(fd, (struct sockaddr *)&to, sizeof(to));
    close(fd);
    return r == 0 ? 1 : 0;
}
