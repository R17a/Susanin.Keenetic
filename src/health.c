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

static uint16_t csum(const void *data, int len)
{
    const uint16_t *p = data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len == 1) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static int probe_one(const char *dst, const char *src, unsigned long mark)
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

int health_probe(const susanin_config *c, int *ok, int *total)
{
    char buf[512], *save = NULL, *tok;
    int o = 0, t = 0;
    if (ok) *ok = 0;
    if (total) *total = 0;
    snprintf(buf, sizeof(buf), "%s", c->health_probe);
    for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        int r;
        while (*tok == ' ') tok++;
        t++;
        r = probe_one(tok, c->egress_address, c->mark_test);
        if (r > 0) o++;
        else if (r < 0)
            slogf(SL_DEBUG, "health probe to %s failed (%d)", tok, r);
    }
    if (ok) *ok = o;
    if (total) *total = t;
    return 0;
}
