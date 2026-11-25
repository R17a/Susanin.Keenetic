/* ay_client.c — клиент закрытого транспорта Susanin.Keenetic.AY.
 *
 * Устройство: отдельный поток держит UDP-сокет до сервера и tun-интерфейс.
 * Пакеты, попавшие в tun (маршрут VPN-таблицы указывает на него), уходят в
 * сокет; ответы из сокета пишутся обратно в tun, и ядро само раздаёт их по
 * маршрутам (LAN, локальные сокеты). Никакого userspace-форвардинга потоков —
 * только пакеты, поэтому TCP/UDP/ICMP обрабатываются одинаково.
 *
 * Реклама адресов: сервер AY ищет сессию по внутреннему адресу из HELLO,
 * поэтому LAN-трафик перед tun проходит SNAT в ay_tun_ip (правило ставит
 * datapath.sh при SUSANIN_AY=1). Без SNAT обратные пакеты не находят сессию.
 *
 * Состояние для панели: /opt/susanin/var/ay.desired (хочет ли оператор) и
 * /opt/susanin/var/ay.status (что происходит). Веб-процесс отдельный, поэтому
 * общение только через файлы + SIGHUP, как у остальных модулей.
 */
#define _GNU_SOURCE 1

#include "ay_client.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/if_tun.h>
#endif

#include "ay_transport.h"
#include "log.h"

#ifndef SO_MARK
#define SO_MARK 36
#endif

#define AY_VAR_DIR      "/opt/susanin/var"
#define AY_HELLO_RETRY  1000   /* мс между HELLO до первого ACK            */
#define AY_HELLO_SLOW   3000   /* мс между HELLO после 10 неудач           */
#define AY_SILENCE_MS   15000  /* столько тишины от сервера = перезаход    */
#define AY_APPLY_RETRY  15     /* сек между повторными попытками подъёма   */

typedef struct {
    pthread_mutex_t mu;
    int             running;        /* поток запущен и ещё не присоединён      */
    int             alive;          /* цикл потока жив (сбрасывает сам поток)  */
    pthread_t       th;
    volatile int    stop;           /* просьба потоку завершиться            */
    int             tun_fd;         /* принадлежит потоку, закрывает он       */
    char            state[16];      /* stopped|disabled|offline|connecting|connected */
    char            error[160];
    char            server[128];
    char            iface[16];
    int             mtu;
    int             configured;     /* заданы server+key                    */
    int             desired;        /* 1 = оператор нажал «Подключиться»     */
    time_t          since;          /* смена состояния (wall clock)         */
    long long       last_rx;        /* монотонные отметки для таймеров      */
    long long       last_ping;
    long long       last_hello;
    int             attempts;
    uint64_t        tx_dgrams, rx_dgrams, tx_bytes, rx_bytes;
    /* Снимок конфига, с которым работает поток (меняется только на остановленном). */
    char            c_server[128], c_key[128], c_tun_ip[32];
    int             c_port, c_mtu, c_keepalive;
    unsigned long   c_mark;
    uint32_t        c_inner;        /* сетевой порядок                       */
    struct sockaddr_in peer;
    time_t          last_apply;
    time_t          last_publish;
    char            last_json[1024];
} ay_global;

static ay_global g = {
    .mu = PTHREAD_MUTEX_INITIALIZER,
    .tun_fd = -1
};

static long long mono_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void json_escape(char *dst, size_t cap, const char *src)
{
    size_t o = 0;

    if (cap == 0)
        return;
    for (; src != NULL && *src; src++) {
        unsigned char c = (unsigned char)*src;

        if (o + 7 >= cap)
            break;
        if (c == '"' || c == '\\') {
            dst[o++] = '\\';
            dst[o++] = (char)c;
        } else if (c == '\n') {
            dst[o++] = '\\';
            dst[o++] = 'n';
        } else if (c < 0x20) {
            o += (size_t)snprintf(dst + o, cap - o, "\\u%04x", c);
        } else {
            dst[o++] = (char)c;
        }
    }
    dst[o] = '\0';
}

static void set_state_locked(const char *state, const char *error)
{
    if (strcmp(g.state, state) != 0) {
        snprintf(g.state, sizeof(g.state), "%s", state);
        g.since = time(NULL);
    }
    if (error != NULL)
        snprintf(g.error, sizeof(g.error), "%s", error);
}

static void set_state(const char *state, const char *error)
{
    pthread_mutex_lock(&g.mu);
    set_state_locked(state, error);
    pthread_mutex_unlock(&g.mu);
}

static void update_counters(ay_ctx *ctx, pthread_mutex_t *mu)
{
    uint64_t txd = 0, rxd = 0, txb = 0, rxb = 0;

    pthread_mutex_lock(mu);
    ay_transport_stats(ctx, &txd, &rxd, &txb, &rxb);
    pthread_mutex_unlock(mu);
    pthread_mutex_lock(&g.mu);
    g.tx_dgrams = txd;
    g.rx_dgrams = rxd;
    g.tx_bytes = txb;
    g.rx_bytes = rxb;
    pthread_mutex_unlock(&g.mu);
}

/* ─────────────────────────── состояние на диске ─────────────────────── */

static int read_desired(int *present)
{
    FILE *f = fopen(AY_DESIRED_PATH, "r");
    char buf[8];

    if (present != NULL)
        *present = 0;
    if (f == NULL)
        return -1;
    if (fgets(buf, sizeof buf, f) != NULL && present != NULL)
        *present = 1;
    fclose(f);
    if (present != NULL && *present)
        return buf[0] == '1' ? 1 : 0;
    return -1;
}

int ay_client_desired(const susanin_config *cfg)
{
    int present = 0;
    int v = read_desired(&present);

    if (present)
        return v;
    /* Явного решения оператора нет: тип egress=ay сам по себе означает
     * «подключаться при старте» (иначе после перезагрузки туннель молча не
     * поднялся бы, и весь VPN-трафик остался бы прямым). */
    return cfg != NULL && strcmp(cfg->egress_type, "ay") == 0;
}

static void write_status_file(const char *json)
{
    char tmp[128];
    FILE *f;

    pthread_mutex_lock(&g.mu);
    if (json != NULL && !strcmp(json, g.last_json)) {
        pthread_mutex_unlock(&g.mu);
        return;
    }
    if (json != NULL)
        snprintf(g.last_json, sizeof(g.last_json), "%s", json);
    pthread_mutex_unlock(&g.mu);

    if (json == NULL)
        return;
    snprintf(tmp, sizeof(tmp), "%s.tmp", AY_STATUS_PATH);
    f = fopen(tmp, "w");
    if (f == NULL)
        return;
    fprintf(f, "%s\n", json);
    if (fclose(f) != 0) {
        remove(tmp);
        return;
    }
    if (rename(tmp, AY_STATUS_PATH) != 0)
        remove(tmp);
}

static void publish_status(const susanin_config *cfg)
{
    char json[1024];
    time_t now = time(NULL);

    pthread_mutex_lock(&g.mu);
    if (now == g.last_publish && g.last_json[0]) {
        pthread_mutex_unlock(&g.mu);
        return;
    }
    g.last_publish = now;
    pthread_mutex_unlock(&g.mu);

    if (ay_client_status_json(cfg, json, sizeof json) == 0)
        write_status_file(json);
}

int ay_client_status_json(const susanin_config *cfg, char *buf, size_t cap)
{
    char eserver[160], eiface[48], eerr[320];
    int configured = 0, desired = 0, transport = ay_transport_available();

    if (buf == NULL || cap == 0)
        return -1;

    pthread_mutex_lock(&g.mu);

    /* До первого apply (например, веб-процесс) снимка ещё нет: отвечаем по
     * конфигу, чтобы панель не показывала пустоту. */
    if (g.state[0] == '\0') {
        configured = cfg != NULL && cfg->ay_server[0] && cfg->ay_key[0];
        desired = ay_client_desired(cfg);
        if (g.mtu == 0 && cfg != NULL)
            g.mtu = cfg->ay_mtu;
        set_state_locked(!transport ? "disabled"
                        : (!configured ? "disabled" : (!desired ? "stopped" : "offline")),
                        !transport ? "транспорт AY не входит в эту сборку"
                                   : (configured ? "" : "не заданы сервер и ключ"));
    } else {
        configured = g.configured;
        desired = g.desired;
    }

    json_escape(eserver, sizeof eserver, g.server[0] ? g.server : (cfg ? cfg->ay_server : ""));
    json_escape(eiface, sizeof eiface, g.iface[0] ? g.iface : ay_client_iface(cfg));
    json_escape(eerr, sizeof eerr, g.error);

    snprintf(buf, cap,
             "{\"state\":\"%s\",\"transport\":%d,\"configured\":%d,\"desired\":%d,"
             "\"server\":\"%s\",\"iface\":\"%s\",\"mtu\":%d,\"since\":%ld,"
             "\"tx_dgrams\":%llu,\"rx_dgrams\":%llu,\"tx_bytes\":%llu,\"rx_bytes\":%llu,"
             "\"error\":\"%s\"}",
             g.state[0] ? g.state : "disabled", transport, configured, desired,
             eserver, eiface, g.mtu, (long)g.since,
             (unsigned long long)g.tx_dgrams, (unsigned long long)g.rx_dgrams,
             (unsigned long long)g.tx_bytes, (unsigned long long)g.rx_bytes,
             eerr);

    pthread_mutex_unlock(&g.mu);
    return 0;
}

/* ─────────────────────────────── tun ─────────────────────────────────── */

static void try_create_tun_node(void)
{
    pid_t pid;

    if (access("/dev/net", F_OK) != 0)
        (void)mkdir("/dev/net", 0755);
    if (access("/dev/net/tun", F_OK) != 0)
        (void)mknod("/dev/net/tun", S_IFCHR | 0666, makedev(10, 200));

    pid = fork();
    if (pid == 0) {
        execl("/sbin/modprobe", "modprobe", "tun", (char *)NULL);
        execl("/usr/sbin/modprobe", "modprobe", "tun", (char *)NULL);
        _exit(127);
    }
    if (pid > 0)
        (void)waitpid(pid, NULL, 0);
}

static int parse_cidr(const char *cidr, struct in_addr *addr, struct in_addr *mask,
                      int *prefix)
{
    char buf[64];
    char *slash;
    int pfx = 24;
    unsigned long m;

    if (cidr == NULL || !cidr[0])
        return -1;
    snprintf(buf, sizeof buf, "%s", cidr);
    slash = strchr(buf, '/');
    if (slash != NULL) {
        *slash = '\0';
        pfx = atoi(slash + 1);
    }
    if (pfx < 0 || pfx > 32)
        return -1;
    if (inet_pton(AF_INET, buf, addr) != 1)
        return -1;
    m = pfx == 0 ? 0UL : (0xffffffffUL << (32 - pfx));
    mask->s_addr = htonl((uint32_t)m);
    if (prefix != NULL)
        *prefix = pfx;
    return 0;
}

static int tun_set_mtu(int fd, int mtu)
{
    int ctl;
    struct ifreq ifr;

    ctl = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctl < 0)
        return -1;
    memset(&ifr, 0, sizeof ifr);
    if (ioctl(fd, TUNGETIFF, &ifr) != 0) {
        close(ctl);
        return -1;
    }
    ifr.ifr_mtu = mtu;
    if (ioctl(ctl, SIOCSIFMTU, &ifr) != 0) {
        close(ctl);
        return -1;
    }
    close(ctl);
    return 0;
}

/* Создать и настроить tun. Ошибка — текст в err. */
static int tun_open(const char *ifname, int mtu, const struct in_addr *addr,
                    const struct in_addr *mask, char *err, size_t errsz)
{
    struct ifreq ifr;
    struct sockaddr_in sin;
    int fd, ctl, try;

    for (try = 0; try < 2; try++) {
        fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
        if (fd >= 0)
            break;
        if (try == 0)
            try_create_tun_node();
    }
    if (fd < 0) {
        snprintf(err, errsz, "нет /dev/net/tun: %s", strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof ifr);
    snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", ifname);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (ioctl(fd, TUNSETIFF, &ifr) != 0) {
        snprintf(err, errsz, "TUNSETIFF %s: %s", ifname, strerror(errno));
        close(fd);
        return -1;
    }

    ctl = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctl < 0) {
        snprintf(err, errsz, "socket для настройки tun: %s", strerror(errno));
        close(fd);
        return -1;
    }

    memset(&ifr, 0, sizeof ifr);
    snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", ifname);
    ifr.ifr_mtu = mtu;
    if (ioctl(ctl, SIOCSIFMTU, &ifr) != 0) {
        snprintf(err, errsz, "MTU %d на %s: %s", mtu, ifname, strerror(errno));
        close(ctl);
        close(fd);
        return -1;
    }

    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_addr = *addr;
    memset(&ifr, 0, sizeof ifr);
    snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", ifname);
    memcpy(&ifr.ifr_addr, &sin, sizeof sin);
    if (ioctl(ctl, SIOCSIFADDR, &ifr) != 0) {
        snprintf(err, errsz, "адрес %s на %s: %s", inet_ntoa(*addr), ifname,
                 strerror(errno));
        close(ctl);
        close(fd);
        return -1;
    }

    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_addr = *mask;
    memset(&ifr, 0, sizeof ifr);
    snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", ifname);
    memcpy(&ifr.ifr_netmask, &sin, sizeof sin);
    (void)ioctl(ctl, SIOCSIFNETMASK, &ifr);

    memset(&ifr, 0, sizeof ifr);
    snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", ifname);
    if (ioctl(ctl, SIOCGIFFLAGS, &ifr) == 0) {
        ifr.ifr_flags = (short)(ifr.ifr_flags | IFF_UP | IFF_RUNNING);
        (void)ioctl(ctl, SIOCSIFFLAGS, &ifr);
    }
    close(ctl);
    return fd;
}

/* ─────────────────────────── разрешение имени ────────────────────────── */

/* Разобрать «сервер» из панели/конфига: «1.2.3.4», «host.name» или
 * «host:port». Отдельного поля порта в панели нет, поэтому порт можно писать
 * прямо в адресе; иначе берётся ay_port. */
static int split_server_port(const char *srv, int def_port, char *host,
                             size_t hostcap, int *port)
{
    const char *colon;
    char *end;
    long p;

    if (srv == NULL || !srv[0] || hostcap == 0)
        return -1;
    colon = strrchr(srv, ':');
    if (colon != NULL && colon != srv) {
        p = strtol(colon + 1, &end, 10);
        if (*end == '\0' && p >= 1 && p <= 65535) {
            size_t n = (size_t)(colon - srv);

            if (n >= hostcap)
                n = hostcap - 1;
            memcpy(host, srv, n);
            host[n] = '\0';
            *port = (int)p;
            return 0;
        }
    }
    snprintf(host, hostcap, "%s", srv);
    *port = def_port;
    return 0;
}

static int resolve_server(const char *srv, int def_port, struct sockaddr_in *out,
                          char *err, size_t errsz)
{
    struct addrinfo hints, *res = NULL;
    struct in_addr numeric;
    char host[160];
    char portstr[16];
    int port = def_port;
    int rc;

    if (split_server_port(srv, def_port, host, sizeof host, &port) != 0 ||
        !host[0]) {
        snprintf(err, errsz, "пустой адрес сервера");
        return -1;
    }
    memset(out, 0, sizeof *out);
    out->sin_family = AF_INET;
    out->sin_port = htons((uint16_t)port);
    /* Чаще всего сервер задан адресом. Тогда не трогаем NSS: у статически
     * слинкованного агента getaddrinfo для имени требует glibc-NSS модулей,
     * которых на роутере может не быть. */
    if (inet_pton(AF_INET, host, &numeric) == 1) {
        out->sin_addr = numeric;
        return 0;
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_ADDRCONFIG;
    snprintf(portstr, sizeof portstr, "%d", port);
    rc = getaddrinfo(host, portstr, &hints, &res);
    if (rc != 0 || res == NULL) {
        snprintf(err, errsz, "не удалось разрешить %s: %s", host,
                 rc != 0 ? gai_strerror(rc) : "нет адреса");
        if (res != NULL)
            freeaddrinfo(res);
        return -1;
    }
    memcpy(out, res->ai_addr, sizeof *out);
    freeaddrinfo(res);
    return 0;
}

/* ────────────────────────────── поток ───────────────────────────────── */

typedef struct {
    ay_ctx *ctx;
    int ufd;
    int tfd;
    pthread_mutex_t *crypto_mu;
} ay_tx_ctx;

/* TX-поток: читает tun и отправляет запечатанные пакеты в UDP. RX и таймеры
 * остаются в ay_worker; crypto-контекст общий, поэтому все вызовы
 * ay_transport_* идут под crypto_mu. */
static void *ay_tx_thread(void *arg)
{
    ay_tx_ctx *t = arg;
    unsigned char buf[1600], dg[AY_MAX_DGRAM];

    while (!g.stop) {
        struct pollfd p;
        int pr;

        p.fd = t->tfd;
        p.events = POLLIN;
        p.revents = 0;
        pr = poll(&p, 1, 200);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (pr == 0) {
            update_counters(t->ctx, t->crypto_mu);
            continue;
        }
        if (p.revents & POLLIN) {
            int k;

            for (k = 0; k < 32; k++) {
                ssize_t r = read(t->tfd, buf, sizeof buf);
                size_t n = 0;
                int connected, rc;

                if (r <= 0) {
                    if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
                        errno != EINTR)
                        slogf(SL_DEBUG, "ay: чтение tun: %s", strerror(errno));
                    break;
                }
                pthread_mutex_lock(&g.mu);
                connected = strcmp(g.state, "connected") == 0;
                pthread_mutex_unlock(&g.mu);
                if (!connected)
                    continue;
                pthread_mutex_lock(t->crypto_mu);
                rc = ay_transport_seal_ip(t->ctx, buf, (size_t)r, dg,
                                          sizeof dg, &n);
                pthread_mutex_unlock(t->crypto_mu);
                if (rc != AY_OK)
                    continue;
                (void)send(t->ufd, dg, n, 0);
            }
        }
        update_counters(t->ctx, t->crypto_mu);
    }
    return NULL;
}

static void *ay_worker(void *arg)
{
    ay_ctx ctx;
    unsigned char plain[AY_MAX_DGRAM], dg[AY_MAX_DGRAM];
    long long last_hello = 0, last_ping = 0, last_rx = 0;
    int attempts = 0, connected = 0, ctx_ok = 0;
    int ufd = -1, tfd = g.tun_fd;
    pthread_mutex_t crypto_mu = PTHREAD_MUTEX_INITIALIZER;
    ay_tx_ctx tx;
    pthread_t th_tx;
    int tx_started = 0;

    (void)arg;
#ifdef __linux__
    (void)pthread_setname_np(pthread_self(), "susanin-ay");
#endif

    if (ay_transport_init(&ctx, g.c_key, g.c_inner, (uint16_t)g.c_mtu) != AY_OK) {
        set_state("offline", "ключ или адрес туннеля не разбираются");
        goto out;
    }
    ctx_ok = 1;

    ufd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (ufd < 0) {
        set_state("offline", "не удалось открыть UDP-сокет");
        goto out;
    }
    if (g.c_mark != 0) {
        unsigned int mark = (unsigned int)g.c_mark;

        if (setsockopt(ufd, SOL_SOCKET, SO_MARK, &mark, sizeof mark) != 0)
            slogf(SL_WARN, "ay: SO_MARK не применён: %s", strerror(errno));
    }
    {
        int rc = 5 << 20;

#ifdef SO_RCVBUFFORCE
        if (setsockopt(ufd, SOL_SOCKET, SO_RCVBUFFORCE, &rc, sizeof rc) != 0)
#endif
            (void)setsockopt(ufd, SOL_SOCKET, SO_RCVBUF, &rc, sizeof rc);
    }
    if (connect(ufd, (struct sockaddr *)&g.peer, sizeof g.peer) != 0) {
        set_state("offline", "UDP-соединение с сервером не установлено");
        goto out;
    }

    slogf(SL_INFO, "ay: клиент запущен (сервер %s:%d, tun %s)", g.server, g.c_port,
          g.iface);

    tx.ctx = &ctx;
    tx.ufd = ufd;
    tx.tfd = tfd;
    tx.crypto_mu = &crypto_mu;

    pthread_mutex_lock(&g.mu);
    g.alive = 1;
    pthread_mutex_unlock(&g.mu);
    if (pthread_create(&th_tx, NULL, ay_tx_thread, &tx) != 0) {
        set_state("offline", "не удалось запустить TX-поток");
        goto out;
    }
    tx_started = 1;

    for (;;) {
        struct pollfd p;
        long long now;
        int pr;

        if (g.stop)
            break;
        now = mono_ms();

        if (!connected) {
            long long iv = attempts < 10 ? AY_HELLO_RETRY : AY_HELLO_SLOW;

            if (attempts == 0 || now - last_hello >= iv) {
                size_t n = 0;
                int rc;

                pthread_mutex_lock(&crypto_mu);
                if (attempts > 0)
                    (void)ay_transport_restart(&ctx);
                rc = ay_transport_hello(&ctx, dg, sizeof dg, &n);
                pthread_mutex_unlock(&crypto_mu);
                if (rc == AY_OK)
                    (void)send(ufd, dg, n, 0);
                attempts++;
                last_hello = now;
                if (attempts == 1)
                    set_state("connecting", "");
                else if (attempts == 10)
                    /* Десять секунд тишины — это уже не «ещё подключается»:
                     * причина почти всегда в адресе/порте/ключе. Состояние не
                     * меняем (клиент продолжает попытки), но текст показываем. */
                    set_state("connecting", "сервер не отвечает: адрес, порт и ключ");
            }
        } else {
            long long ka = (long long)g.c_keepalive * 1000;

            if (ka <= 0)
                ka = 5000;
            if (now - last_ping >= ka) {
                size_t n = 0;
                int rc;

                pthread_mutex_lock(&crypto_mu);
                rc = ay_transport_seal_ping(&ctx, dg, sizeof dg, &n);
                pthread_mutex_unlock(&crypto_mu);
                if (rc == AY_OK)
                    (void)send(ufd, dg, n, 0);
                last_ping = now;
            }
            if (now - last_rx > AY_SILENCE_MS) {
                slogf(SL_WARN, "ay: сервер молчит %d с — новый заход",
                      AY_SILENCE_MS / 1000);
                pthread_mutex_lock(&crypto_mu);
                (void)ay_transport_restart(&ctx);
                pthread_mutex_unlock(&crypto_mu);
                connected = 0;
                attempts = 0;
                last_hello = 0;
                last_ping = 0;
                set_state("connecting", "нет ответа сервера — переподключение");
            }
        }

        p.fd = ufd;
        p.events = POLLIN;
        p.revents = 0;
        pr = poll(&p, 1, 200);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            set_state("offline", "poll: ошибка сокета");
            break;
        }
        if (pr == 0) {
            update_counters(&ctx, &crypto_mu);
            continue;
        }

        if (p.revents & (POLLIN | POLLERR)) {
            /* Пачкой: на всплесках 1440p один recv на пакет не успевает
             * вычитывать 5-МБ буфер, и ядро дропает (RcvbufErrors). */
            struct mmsghdr mm[16];
            struct iovec iov[16];
            char rbuf[16][1600];
            int i, got;

            for (i = 0; i < 16; i++) {
                memset(&mm[i], 0, sizeof mm[i]);
                iov[i].iov_base = rbuf[i];
                iov[i].iov_len = sizeof rbuf[i];
                mm[i].msg_hdr.msg_iov = &iov[i];
                mm[i].msg_hdr.msg_iovlen = 1;
            }
            do {
                got = (int)recvmmsg(ufd, mm, 16, MSG_DONTWAIT, NULL);
                if (got <= 0)
                    break;
                for (i = 0; i < got; i++) {
                    size_t r = mm[i].msg_len;
                    int msg = 0;
                    size_t off = 0, plen = 0;
                    int rc;

                    if (r == 0)
                        continue;
                    pthread_mutex_lock(&crypto_mu);
                    rc = ay_transport_open(&ctx, (unsigned char *)rbuf[i], r,
                                           plain, sizeof plain, &msg, &off, &plen);
                    pthread_mutex_unlock(&crypto_mu);
                    if (rc != AY_OK)
                        continue;
                    last_rx = now;
                    if (msg == AY_MSG_HELLO_ACK) {
                        int ack_rc;

                        pthread_mutex_lock(&crypto_mu);
                        ack_rc = ay_transport_accept_ack(&ctx, plain + off, plen);
                        pthread_mutex_unlock(&crypto_mu);
                        if (ack_rc != AY_OK) {
                            slogf(SL_WARN, "ay: подтверждение сессии не принято — перезаход");
                            pthread_mutex_lock(&crypto_mu);
                            (void)ay_transport_restart(&ctx);
                            pthread_mutex_unlock(&crypto_mu);
                            connected = 0;
                            attempts = 0;
                            last_hello = 0;
                            set_state("connecting", "сервер не подтвердил ключ");
                            continue;
                        }
                        connected = 1;
                        attempts = 0;
                        last_rx = now;
                        last_ping = now;
                        {
                            uint16_t mtu;
                            uint32_t sid;

                            pthread_mutex_lock(&crypto_mu);
                            mtu = ay_transport_mtu(&ctx);
                            sid = ay_transport_session_id(&ctx);
                            pthread_mutex_unlock(&crypto_mu);
                            if (mtu > 0 && mtu < (uint16_t)g.mtu) {
                                if (tun_set_mtu(tfd, (int)mtu) == 0) {
                                    slogf(SL_INFO, "ay: MTU туннеля понижен до %u по ACK",
                                          (unsigned)mtu);
                                    pthread_mutex_lock(&g.mu);
                                    g.mtu = (int)mtu;
                                    pthread_mutex_unlock(&g.mu);
                                }
                            }
                            set_state("connected", "");
                            slogf(SL_INFO, "ay: сессия установлена (id %08x, сервер %s)",
                                  sid, g.server);
                        }
                    } else if (msg == AY_MSG_IP) {
                        if (plen > 0 && write(tfd, plain + off, plen) < 0) {
                            if (errno != EAGAIN && errno != EWOULDBLOCK)
                                slogf(SL_DEBUG, "ay: запись в tun: %s", strerror(errno));
                        }
                    }
                    /* PONG: last_rx уже обновлён выше. */
                }
            } while (got == 16);
        }
        update_counters(&ctx, &crypto_mu);
    }

out:
    g.stop = 1;                 /* TX-поток должен выйти, даже если main упал */
    if (tx_started)
        pthread_join(th_tx, NULL);
    if (ctx_ok)
        update_counters(&ctx, &crypto_mu);
    pthread_mutex_destroy(&crypto_mu);
    if (ufd >= 0)
        close(ufd);
    if (tfd >= 0)
        close(tfd);
    set_state("stopped", "");
    /* Поток мог выйти сам (ошибка poll/сокета): снимаем признак жизни, но
     * не «running» — поток ещё нужно присоединить (иначе утечка стека). */
    pthread_mutex_lock(&g.mu);
    g.alive = 0;
    pthread_mutex_unlock(&g.mu);
    return NULL;
}

/* ──────────────────────── управление клиентом ───────────────────────── */

static void stop_worker(void)
{
    if (!g.running)
        return;
    g.stop = 1;
    pthread_join(g.th, NULL);
    g.running = 0;
    g.alive = 0;
    g.tun_fd = -1;
    g.stop = 0;
}

const char *ay_client_iface(const susanin_config *cfg)
{
    if (cfg != NULL && cfg->ay_iface[0])
        return cfg->ay_iface;
    return "ay0";
}

int ay_client_running(void)
{
    int v;

    pthread_mutex_lock(&g.mu);
    v = g.running && g.alive;
    pthread_mutex_unlock(&g.mu);
    return v;
}

int ay_client_connected(void)
{
    int v;

    pthread_mutex_lock(&g.mu);
    v = strcmp(g.state, "connected") == 0;
    pthread_mutex_unlock(&g.mu);
    return v;
}

int ay_client_apply(const susanin_config *cfg)
{
    struct in_addr addr, mask;
    char err[320] = "";
    int configured, want, changed;
    int tfd;

    if (cfg == NULL)
        return -1;

    configured = cfg->ay_server[0] && cfg->ay_key[0];
    want = configured && ay_client_desired(cfg) && ay_transport_available();

    pthread_mutex_lock(&g.mu);
    g.last_apply = time(NULL);
    g.configured = configured;
    g.desired = ay_client_desired(cfg);
    pthread_mutex_unlock(&g.mu);

    if (!want) {
        stop_worker();
        set_state(!ay_transport_available() ? "disabled"
                  : (!configured ? "disabled" : "stopped"),
                  !ay_transport_available() ? "транспорт AY не входит в эту сборку"
                  : (!configured ? "не заданы сервер и ключ"
                                : "отключено оператором"));
        if (!cfg->ay_iface[0] || !g.iface[0])
            snprintf(g.iface, sizeof g.iface, "%s", ay_client_iface(cfg));
        publish_status(cfg);
        return 0;
    }

    changed = g.running &&
              (strcmp(g.c_server, cfg->ay_server) != 0 ||
               strcmp(g.c_key, cfg->ay_key) != 0 ||
               strcmp(g.c_tun_ip, cfg->ay_tun_ip) != 0 ||
               g.c_port != cfg->ay_port || g.c_mtu != cfg->ay_mtu ||
               g.c_keepalive != cfg->ay_keepalive || g.c_mark != cfg->ay_mark ||
               strcmp(g.iface, ay_client_iface(cfg)) != 0);
    if (g.running && !g.alive) {
        /* Поток вышел сам (ошибка сокета): сначала присоединяем его, потом
         * поднимаем заново — иначе «running» навсегда заблокировал бы старт. */
        slogf(SL_WARN, "ay: поток клиента завершился — перезапуск");
        stop_worker();
        changed = 0;
    }
    if (changed) {
        slogf(SL_INFO, "ay: настройки изменились — перезапуск клиента");
        stop_worker();
    }

    if (!g.running) {
        if (parse_cidr(cfg->ay_tun_ip, &addr, &mask, NULL) != 0) {
            set_state("offline", "ay_tun_ip: ожидается адрес/префикс");
            publish_status(cfg);
            return -1;
        }
        if (resolve_server(cfg->ay_server, cfg->ay_port, &g.peer, err, sizeof err) != 0) {
            set_state("offline", err);
            publish_status(cfg);
            return -1;
        }
        tfd = tun_open(ay_client_iface(cfg), cfg->ay_mtu, &addr, &mask,
                       err, sizeof err);
        if (tfd < 0) {
            set_state("offline", err);
            publish_status(cfg);
            return -1;
        }

        snprintf(g.server, sizeof g.server, "%s", cfg->ay_server);
        snprintf(g.iface, sizeof g.iface, "%s", ay_client_iface(cfg));
        snprintf(g.c_server, sizeof g.c_server, "%s", cfg->ay_server);
        snprintf(g.c_key, sizeof g.c_key, "%s", cfg->ay_key);
        snprintf(g.c_tun_ip, sizeof g.c_tun_ip, "%s", cfg->ay_tun_ip);
        g.c_port = cfg->ay_port;
        g.c_mtu = cfg->ay_mtu;
        g.c_keepalive = cfg->ay_keepalive;
        g.c_mark = cfg->ay_mark;
        g.c_inner = addr.s_addr;
        g.mtu = cfg->ay_mtu;
        g.tun_fd = tfd;
        g.stop = 0;

        {
            pthread_attr_t attr;
            int prc;

            pthread_attr_init(&attr);
            /* Потоку хватает десятков килобайт; 8 МБ стека на роутере —
             * это вычеркнутая из кэша память, которой и так мало. */
            (void)pthread_attr_setstacksize(&attr, 256 * 1024);
            g.running = 1;
            g.alive = 1;
            prc = pthread_create(&g.th, &attr, ay_worker, NULL);
            pthread_attr_destroy(&attr);
            if (prc != 0) {
                g.running = 0;
                g.alive = 0;
                g.tun_fd = -1;
                close(tfd);
                set_state("offline", "не удалось создать поток клиента");
                publish_status(cfg);
                return -1;
            }
        }
        set_state("connecting", "");
        slogf(SL_INFO, "ay: tun %s поднят, ждём подтверждения сессии", g.iface);
    }

    publish_status(cfg);
    return 0;
}

void ay_client_stop(void)
{
    if (!g.running)
        return;
    slogf(SL_INFO, "ay: остановка клиента");
    stop_worker();
}

void ay_client_tick(const susanin_config *cfg)
{
    int retry = 0;

    if (cfg == NULL)
        return;
    publish_status(cfg);

    pthread_mutex_lock(&g.mu);
    if ((!g.running || !g.alive) && g.desired && g.configured &&
        time(NULL) - g.last_apply >= AY_APPLY_RETRY)
        retry = 1;
    pthread_mutex_unlock(&g.mu);

    if (retry) {
        /* Подъём не удался (нет tun, имя не разрешилось, сервер ещё не
         * отвечает) — повторяем не чаще раза в AY_APPLY_RETRY секунд. */
        (void)ay_client_apply(cfg);
    }
}
