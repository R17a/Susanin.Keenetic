/* UDP-релей для egress через XRay (см. udp_relay.h).
 *
 * Зачем: iptables REDIRECT умеет только TCP, а XRay dokodemo-door UDP-tproxy
 * на 1.8.24 не читает исходный адрес ("unable to get destination"). Поэтому
 * помеченный Susanin.Keenetic'ом UDP заворачивается (mangle TPROXY) на локальный порт,
 * который слушает этот релей. Релей узнаёт исходный адрес назначения
 * (IP_ORIGDSTADDR), отправляет датаграммы через SOCKS5 UDP ASSOCIATE в Xray
 * (127.0.0.1:1080, udp:true) и возвращает ответы клиенту от имени сервиса.
 *
 * ВАЖНО: SOCKS5-ассоциация открывается НА КАЖДЫЙ поток (клиент:порт + сервер),
 * а не одна общая. Иначе ответы нельзя разложить: заголовок ответа SOCKS5
 * содержит только адрес сервера, и при нескольких клиентах/портах к одному
 * серверу (типовой DNS: разные исходные порты на 1.1.1.1:53) все ответы
 * уходили бы первому потоку, остальные висели бы в UNREPLIED. Своя ассоциация
 * на поток делает ответ однозначным. */

#define _GNU_SOURCE
#include "udp_relay.h"
#include "log.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT 19
#endif
#ifndef IP_RECVORIGDSTADDR
#define IP_RECVORIGDSTADDR 20
#endif
#ifndef IP_ORIGDSTADDR
#define IP_ORIGDSTADDR 20
#endif
#ifndef IP_FREEBIND
#define IP_FREEBIND 15
#endif

#define MAX_FLOWS 128
#define FLOW_TTL  180
#define ASSOC_TRIES 5

typedef struct {
    int used;
    struct sockaddr_in client;
    struct sockaddr_in server;      /* исходный dst (адрес сервиса) */
    struct sockaddr_in relay;       /* адрес socks-релея для этой ассоциации */
    int ctl_fd;                     /* TCP-контроль SOCKS5 (держать открытым) */
    int relay_fd;                   /* UDP-сокет ассоциации (на этот поток) */
    time_t last;
} flow_t;

/* Сокеты для ответов: привязаны к исходному адресу сервиса (IP:port), чтобы
 * ответ клиенту уходил ровно «от того, кому он слал» (иначе conntrack
 * отбрасывает: клиент ждёт 1.1.1.1:53, а мы бы отвечали :1081). Кэш общий —
 * один rsock на адрес сервиса, ответы разным клиентам идут через sendto. */
typedef struct {
    int used;
    int fd;
    struct sockaddr_in srv;
    time_t last;
} rsock_t;

static flow_t g_flow[MAX_FLOWS];
static rsock_t g_rs[MAX_FLOWS];
static char g_socks_host[64];
static int  g_socks_port = 1080;
static pid_t g_pid = 0;

static void flow_close(flow_t *f)
{
    if (f->ctl_fd >= 0)
        close(f->ctl_fd);
    if (f->relay_fd >= 0)
        close(f->relay_fd);
    f->ctl_fd = -1;
    f->relay_fd = -1;
    f->used = 0;
}

/* transparent-сокет, привязанный к адресу сервиса (для ответов клиенту). */
static int rsock_get(const struct sockaddr_in *srv)
{
    int i, free_i = -1, on = 1;
    time_t now = time(NULL);
    for (i = 0; i < MAX_FLOWS; i++) {
        if (!g_rs[i].used) {
            if (free_i < 0)
                free_i = i;
            continue;
        }
        if (g_rs[i].srv.sin_addr.s_addr == srv->sin_addr.s_addr &&
            g_rs[i].srv.sin_port == srv->sin_port) {
            g_rs[i].last = now;
            return g_rs[i].fd;
        }
        if (now - g_rs[i].last > FLOW_TTL) {
            close(g_rs[i].fd);
            g_rs[i].used = 0;
            if (free_i < 0)
                free_i = i;
        }
    }
    if (free_i < 0)
        return -1;
    {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in b = *srv;
        if (fd < 0)
            return -1;
        setsockopt(fd, IPPROTO_IP, IP_TRANSPARENT, &on, sizeof(on));
        setsockopt(fd, IPPROTO_IP, IP_FREEBIND, &on, sizeof(on));
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        if (bind(fd, (struct sockaddr *)&b, sizeof(b)) != 0) {
            slogf(SL_ERROR, "udp-relay: rsock bind %s:%u: %s",
                  inet_ntoa(srv->sin_addr), (unsigned)ntohs(srv->sin_port),
                  strerror(errno));
            close(fd);
            return -1;
        }
        g_rs[free_i].used = 1;
        g_rs[free_i].srv = *srv;
        g_rs[free_i].fd = fd;
        g_rs[free_i].last = now;
        return fd;
    }
}

/* SOCKS5 UDP ASSOCIATE. Возвращает control-fd (держать открытым) и адрес
 * релея в *relay. */
static int socks_associate(const char *host, int port, struct sockaddr_in *relay)
{
    int fd;
    struct sockaddr_in sa;
    unsigned char b[64];
    ssize_t n;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) { close(fd); return -1; }
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) { close(fd); return -1; }

    b[0] = 5; b[1] = 1; b[2] = 0;          /* VER, NMETHODS=1, noauth */
    if (write(fd, b, 3) != 3) { close(fd); return -1; }
    n = read(fd, b, 2);
    if (n != 2 || b[0] != 5 || b[1] != 0) { close(fd); return -1; }

    b[0] = 5; b[1] = 3; b[2] = 0; b[3] = 1; /* UDP ASSOCIATE, ATYP=IPv4 */
    memset(b + 4, 0, 4); b[8] = 0; b[9] = 0;
    if (write(fd, b, 10) != 10) { close(fd); return -1; }
    n = read(fd, b, 10);
    if (n < 10 || b[1] != 0 || b[3] != 1) { close(fd); return -1; }

    memset(relay, 0, sizeof(*relay));
    relay->sin_family = AF_INET;
    memcpy(&relay->sin_addr, b + 4, 4);
    memcpy(&relay->sin_port, b + 8, 2);
    if (relay->sin_addr.s_addr == 0)
        relay->sin_addr = sa.sin_addr;     /* бинд 0.0.0.0 → адрес socks */
    return fd;
}

static flow_t *flow_get(const struct sockaddr_in *server,
                        const struct sockaddr_in *client)
{
    int i, free_i = -1;
    time_t now = time(NULL);
    for (i = 0; i < MAX_FLOWS; i++) {
        if (!g_flow[i].used) {
            if (free_i < 0)
                free_i = i;
            continue;
        }
        if (g_flow[i].server.sin_addr.s_addr == server->sin_addr.s_addr &&
            g_flow[i].server.sin_port == server->sin_port &&
            g_flow[i].client.sin_addr.s_addr == client->sin_addr.s_addr &&
            g_flow[i].client.sin_port == client->sin_port) {
            g_flow[i].last = now;
            return &g_flow[i];
        }
    }
    if (free_i < 0)
        return NULL;
    {
        flow_t *f = &g_flow[free_i];
        struct sockaddr_in relay;
        int ctl = -1, tries, rfd;
        for (tries = 0; tries < ASSOC_TRIES; tries++) {
            ctl = socks_associate(g_socks_host, g_socks_port, &relay);
            if (ctl >= 0)
                break;
            sleep(1);
        }
        if (ctl < 0) {
            slogf(SL_ERROR, "udp-relay: SOCKS5 UDP ASSOCIATE к %s:%d не удался",
                  g_socks_host, g_socks_port);
            return NULL;
        }
        rfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (rfd < 0) {
            slogf(SL_ERROR, "udp-relay: relay socket: %s", strerror(errno));
            close(ctl);
            return NULL;
        }
        memset(f, 0, sizeof(*f));
        f->used = 1;
        f->client = *client;
        f->server = *server;
        f->relay = relay;
        f->ctl_fd = ctl;
        f->relay_fd = rfd;
        f->last = now;
        {
            char sb[32], cb[32];
            snprintf(sb, sizeof(sb), "%s:%u", inet_ntoa(server->sin_addr),
                     (unsigned)ntohs(server->sin_port));
            snprintf(cb, sizeof(cb), "%s:%u", inet_ntoa(client->sin_addr),
                     (unsigned)ntohs(client->sin_port));
            slogf(SL_INFO, "udp-relay: flow %s <- %s (ctl=%d udp=%d)",
                  sb, cb, ctl, rfd);
        }
        return f;
    }
}

static int udp_hdr(unsigned char *b, const struct sockaddr_in *dst)
{
    b[0] = 0; b[1] = 0; b[2] = 0; b[3] = 1;
    memcpy(b + 4, &dst->sin_addr, 4);
    memcpy(b + 8, &dst->sin_port, 2);
    return 10;
}

/* Длина SOCKS5-UDP-заголовка в ответе (RSV(2) FRAG(1) ATYP(1) ADDR PORT). */
static int socks_hdr_len(const unsigned char *b, ssize_t n)
{
    if (n < 4 || b[0] != 0 || b[1] != 0)
        return -1;
    switch (b[3]) {
        case 1: return 10;              /* IPv4 */
        case 4: return 22;              /* IPv6 */
        case 3:
            if (n < 5)
                return -1;
            return 4 + 1 + (int)b[4] + 2;
        default:
            return -1;
    }
}

static void relay_loop(int main_fd)
{
    unsigned char in[65536], out[66000];
    struct pollfd pfds[1 + MAX_FLOWS];
    int idx[1 + MAX_FLOWS];

    for (;;) {
        int nf = 1, i, r, j;
        time_t now = time(NULL);

        for (i = 0; i < MAX_FLOWS; i++)
            if (g_flow[i].used && now - g_flow[i].last > FLOW_TTL)
                flow_close(&g_flow[i]);

        pfds[0].fd = main_fd; pfds[0].events = POLLIN; pfds[0].revents = 0;
        for (i = 0; i < MAX_FLOWS; i++) {
            if (g_flow[i].used) {
                pfds[nf].fd = g_flow[i].relay_fd;
                pfds[nf].events = POLLIN;
                pfds[nf].revents = 0;
                idx[nf] = i;
                nf++;
            }
        }

        r = poll(pfds, (nfds_t)nf, 5000);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        if (pfds[0].revents & POLLIN) {
            struct sockaddr_in client, orig;
            struct iovec iov;
            struct msghdr mh;
            char cbuf[CMSG_SPACE(sizeof(struct sockaddr_in)) + 64];
            ssize_t n;
            int have = 0, hl;
            struct cmsghdr *cm;
            flow_t *f;

            memset(&client, 0, sizeof(client));
            memset(&orig, 0, sizeof(orig));
            iov.iov_base = in;
            iov.iov_len = sizeof(in);
            memset(&mh, 0, sizeof(mh));
            mh.msg_name = &client;
            mh.msg_namelen = sizeof(client);
            mh.msg_iov = &iov;
            mh.msg_iovlen = 1;
            mh.msg_control = cbuf;
            mh.msg_controllen = sizeof(cbuf);

            n = recvmsg(main_fd, &mh, 0);
            if (n <= 0)
                continue;
            for (cm = CMSG_FIRSTHDR(&mh); cm; cm = CMSG_NXTHDR(&mh, cm)) {
                if (cm->cmsg_level == IPPROTO_IP && cm->cmsg_type == IP_ORIGDSTADDR) {
                    memcpy(&orig, CMSG_DATA(cm), sizeof(orig));
                    have = 1;
                }
            }
            if (!have) {
                slogf(SL_ERROR, "udp-relay: нет IP_ORIGDSTADDR (ядро/опция?)");
                continue;
            }
            f = flow_get(&orig, &client);
            if (!f)
                continue;
            hl = udp_hdr(out, &orig);
            if ((size_t)hl + (size_t)n > sizeof(out))
                continue;
            memcpy(out + hl, in, (size_t)n);
            if (sendto(f->relay_fd, out, (size_t)hl + (size_t)n, 0,
                       (struct sockaddr *)&f->relay, sizeof(f->relay)) < 0)
                slogf(SL_ERROR, "udp-relay: send->socks: %s", strerror(errno));
        }

        for (j = 1; j < nf; j++) {
            flow_t *f;
            struct sockaddr_in from;
            socklen_t fl = sizeof(from);
            ssize_t n;
            int hl, rfd;

            if (!(pfds[j].revents & POLLIN))
                continue;
            f = &g_flow[idx[j]];
            if (!f->used)
                continue;
            n = recvfrom(f->relay_fd, in, sizeof(in), 0,
                         (struct sockaddr *)&from, &fl);
            if (n <= 0)
                continue;
            hl = socks_hdr_len(in, n);
            if (hl < 0 || hl > n) {
                slogf(SL_ERROR, "udp-relay: bad socks reply (n=%d atyp=%d)",
                      (int)n, n > 3 ? (int)in[3] : -1);
                continue;
            }
            /* Источник ответа всегда берём из потока (f->server), а не из
             * заголовка SOCKS, чтобы клиент видел ответ от того же адреса,
             * куда слал (иначе ядро/клиент отбросит). */
            rfd = rsock_get(&f->server);
            if (rfd < 0)
                continue;
            if (sendto(rfd, in + hl, (size_t)n - (size_t)hl, 0,
                       (struct sockaddr *)&f->client, sizeof(f->client)) < 0)
                slogf(SL_ERROR, "udp-relay: reply->client: %s", strerror(errno));
            f->last = time(NULL);
        }
    }
}

int udp_relay_start(const susanin_config *cfg)
{
    int main_fd, on = 1, i;
    struct sockaddr_in b;
    pid_t pid;

    if (!cfg->udp_relay)
        return 0;
    if (g_pid > 0)
        return (int)g_pid;

    snprintf(g_socks_host, sizeof(g_socks_host), "%s",
             cfg->socks_addr[0] ? cfg->socks_addr : "127.0.0.1");
    g_socks_port = cfg->socks_port > 0 ? cfg->socks_port : 1080;
    for (i = 0; i < MAX_FLOWS; i++) {
        g_flow[i].ctl_fd = -1;
        g_flow[i].relay_fd = -1;
    }

    main_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (main_fd < 0) {
        slogf(SL_ERROR, "udp-relay: socket: %s", strerror(errno));
        return 0;
    }
    setsockopt(main_fd, IPPROTO_IP, IP_TRANSPARENT, &on, sizeof(on));
    setsockopt(main_fd, IPPROTO_IP, IP_RECVORIGDSTADDR, &on, sizeof(on));
    setsockopt(main_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    memset(&b, 0, sizeof(b));
    b.sin_family = AF_INET;
    b.sin_port = htons((uint16_t)cfg->udp_relay_port);
    if (bind(main_fd, (struct sockaddr *)&b, sizeof(b)) != 0) {
        slogf(SL_ERROR, "udp-relay: bind :%d: %s", cfg->udp_relay_port,
              strerror(errno));
        close(main_fd);
        return 0;
    }

    pid = fork();
    if (pid < 0) {
        slogf(SL_ERROR, "udp-relay: fork: %s", strerror(errno));
        close(main_fd);
        return 0;
    }
    if (pid == 0) {
        /* дочерний процесс: свои обработчики сигналов — по умолчанию */
        signal(SIGTERM, SIG_DFL);
        signal(SIGINT, SIG_DFL);
        signal(SIGHUP, SIG_DFL);
        slogf(SL_INFO, "udp-relay: started :%d -> socks %s:%d",
              cfg->udp_relay_port, g_socks_host, g_socks_port);
        relay_loop(main_fd);
        _exit(0);
    }
    close(main_fd);
    g_pid = pid;
    return (int)pid;
}

void udp_relay_stop(void)
{
    if (g_pid > 0) {
        kill(g_pid, SIGTERM);
        waitpid(g_pid, NULL, 0);
        g_pid = 0;
        slogf(SL_INFO, "udp-relay: stopped");
    }
}
