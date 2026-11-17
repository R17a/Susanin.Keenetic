#include <stdio.h>
#include <string.h>

#include "vpin.h"

static struct {
    char ip[16];
    unsigned short port;   /* порт подтверждающего потока: проба идёт туда;
                            * 0 = неизвестен (движок подставит запасной 443) */
    unsigned char udp;     /* протокол потока-улики; UDP в очередь не ставим */
    unsigned char nfails;  /* подряд идущие промахи пробы */
    int holdoff;           /* ранняя перепроверка после промаха, сек; 0 = обычно */
    int state;
    time_t at;
} q[VPIN_MAX];

static unsigned long n_bad, n_slow, n_back, n_skip;

/* Есть ли чем мерить качество туннеля (локальный SOCKS бывает только в
 * tproxy). В остальных режимах Q_VPN-записи бессмысленны: проверять можно
 * только «ожил ли прямой», и note кладёт их сразу в Q_DIRECT. */
static int tunnel_probe = 1;

static int slot_find(const char *ip)
{
    int i;
    for (i = 0; i < VPIN_MAX; i++)
        if (q[i].state != VPIN_FREE && strcmp(q[i].ip, ip) == 0)
            return i;
    return -1;
}

/* Свободный слот; если очередь полна — самый старый по отметке (там уже
 * нечего проверять: решение по нему принято давно). */
static int slot_take(void)
{
    int i, oldest = -1;
    for (i = 0; i < VPIN_MAX; i++) {
        if (q[i].state == VPIN_FREE)
            return i;
        if (oldest < 0 || q[i].at < q[oldest].at)
            oldest = i;
    }
    return oldest;
}

void vpin_note(const char *ip, unsigned short port, int udp, time_t now)
{
    int i;
    if (!ip || !ip[0] || strlen(ip) >= sizeof(q[0].ip))
        return;
    /* UDP-поток в очередь не идёт: проба аудита — TCP (SOCKS CONNECT /
     * connect()), живой UDP-сервис (QUIC/RTSP/RTP) на тот же порт по-TCP
     * может молчать, и «нет ответа» снимет рабочий пин, оборвав поток.
     * Решение по UDP-адресам оставляет только само обучение. */
    if (udp)
        return;
    i = slot_find(ip);
    if (i < 0) {
        i = slot_take();
        if (i < 0)
            return;
        snprintf(q[i].ip, sizeof(q[i].ip), "%s", ip);
    }
    /* Повторная улика — как новая: сначала снова нужна проверка туннеля,
     * порт и срок обновляются, счётчик промахов обнуляется. */
    q[i].port = port;
    q[i].udp = 0;
    q[i].nfails = 0;
    q[i].holdoff = 0;
    q[i].state = tunnel_probe ? VPIN_Q_VPN : VPIN_Q_DIRECT;
    q[i].at = now;
}

void vpin_set_tunnel_probe(int enabled, time_t now)
{
    int i;
    enabled = enabled ? 1 : 0;
    if (tunnel_probe == enabled)
        return;
    tunnel_probe = enabled;
    if (enabled)
        return;
    /* В режиме без туннельной пробы не должно оставаться due Q_VPN-записей:
     * их нечем проверять, они вечно висели бы в очереди и вытесняли
     * Q_DIRECT-проверки возврата на прямой путь. */
    for (i = 0; i < VPIN_MAX; i++)
        if (q[i].state == VPIN_Q_VPN) {
            q[i].state = VPIN_Q_DIRECT;
            q[i].nfails = 0;
            q[i].holdoff = 0;
            q[i].at = now;
        }
}

/* Срок ожидания слота: после промаха — holdoff, иначе обычный для состояния. */
static int slot_wait(const int i, int vpn_iv, int direct_iv)
{
    if (q[i].holdoff > 0)
        return q[i].holdoff;
    return q[i].state == VPIN_Q_VPN ? vpn_iv : direct_iv;
}

int vpin_due(time_t now, int vpn_iv, int direct_iv, int *out, int max)
{
    int cand[VPIN_MAX], nc = 0, i, n, k;

    if (!out || max <= 0)
        return 0;
    if (vpn_iv < 0)
        vpn_iv = 0;
    if (direct_iv < 0)
        direct_iv = 0;
    for (i = 0; i < VPIN_MAX; i++) {
        if (q[i].state == VPIN_FREE)
            continue;
        if (now - q[i].at >= slot_wait(i, vpn_iv, direct_iv))
            cand[nc++] = i;
    }
    /* Отдача по давности (самый старый at первым). Выбор по индексу слота
     * морил бы голодом адреса в «дальних» слотах: batch всегда забирала бы
     * голова массива. */
    for (n = 0; n < max && n < nc; n++) {
        int bi = n;
        for (k = n + 1; k < nc; k++)
            if (q[cand[k]].at < q[cand[bi]].at)
                bi = k;
        if (bi != n) {
            int t = cand[n];
            cand[n] = cand[bi];
            cand[bi] = t;
        }
        out[n] = cand[n];
    }
    return n;
}

int vpin_pending(void)
{
    int i, n = 0;
    for (i = 0; i < VPIN_MAX; i++)
        if (q[i].state != VPIN_FREE)
            n++;
    return n;
}

int vpin_pending_vpn(void)
{
    int i, n = 0;
    for (i = 0; i < VPIN_MAX; i++)
        if (q[i].state == VPIN_Q_VPN)
            n++;
    return n;
}

const char *vpin_ip(int idx)
{
    if (idx < 0 || idx >= VPIN_MAX || q[idx].state == VPIN_FREE)
        return NULL;
    return q[idx].ip;
}

int vpin_state(int idx)
{
    if (idx < 0 || idx >= VPIN_MAX)
        return VPIN_FREE;
    return q[idx].state;
}

unsigned short vpin_port(int idx)
{
    if (idx < 0 || idx >= VPIN_MAX || q[idx].state == VPIN_FREE)
        return 0;
    return q[idx].port;
}

int vpin_find(const char *ip, int state)
{
    int i;
    if (!ip)
        return -1;
    i = slot_find(ip);
    if (i < 0 || q[i].state != state)
        return -1;
    return i;
}

void vpin_set(int idx, int state, time_t now)
{
    if (idx < 0 || idx >= VPIN_MAX)
        return;
    if (state == VPIN_FREE) {
        memset(&q[idx], 0, sizeof(q[idx]));   /* state 0 = VPIN_FREE */
        return;
    }
    if (q[idx].state == VPIN_FREE)
        return;
    q[idx].state = state;
    q[idx].nfails = 0;
    q[idx].holdoff = 0;
    q[idx].at = now;
}

int vpin_fail(int idx, time_t now, int holdoff)
{
    if (idx < 0 || idx >= VPIN_MAX || q[idx].state == VPIN_FREE)
        return 0;
    if (q[idx].nfails < 255)
        q[idx].nfails++;
    q[idx].holdoff = holdoff > 0 ? holdoff : 0;
    q[idx].at = now;
    return (int)q[idx].nfails;
}

void vpin_free_idx(int idx)
{
    vpin_set(idx, VPIN_FREE, 0);
}

void vpin_bump(int what)
{
    if (what == 0)
        n_bad++;
    else if (what == 1)
        n_slow++;
    else if (what == 2)
        n_back++;
    else
        n_skip++;
}

void vpin_counters(unsigned long *bad, unsigned long *slow,
                   unsigned long *back, unsigned long *skip)
{
    if (bad)
        *bad = n_bad;
    if (slow)
        *slow = n_slow;
    if (back)
        *back = n_back;
    if (skip)
        *skip = n_skip;
}

int vpin_format(char *out, size_t n, int check, int interval)
{
    unsigned long bad = 0, slow = 0, back = 0, skip = 0;
    int i, used;

    if (!out || n == 0)
        return 0;
    vpin_counters(&bad, &slow, &back, &skip);
    used = snprintf(out, n,
                    "vpin: check=%d interval=%ds pending=%d/vpn=%d "
                    "bad=%lu slow=%lu back=%lu skip=%lu",
                    check, interval, vpin_pending(), vpin_pending_vpn(),
                    bad, slow, back, skip);
    if (used < 0 || (size_t)used >= n)
        return used < 0 ? 0 : (int)n - 1;
    /* Строки очереди — вторичны: если буфер кончился, обрываем их,
     * сводная первая строка обязана остаться целой. */
    for (i = 0; i < VPIN_MAX; i++) {
        char line[64];
        int m;
        if (q[i].state == VPIN_FREE)
            continue;
        m = snprintf(line, sizeof(line), "\nq %s %s %u", q[i].ip,
                     q[i].state == VPIN_Q_VPN ? "vpn" : "direct",
                     (unsigned)q[i].port);
        if (m <= 0 || used + m >= (int)n)
            break;
        memcpy(out + used, line, (size_t)m);
        used += m;
    }
    out[used] = '\0';
    return used;
}

void vpin_reset(void)
{
    memset(q, 0, sizeof(q));
    n_bad = n_slow = n_back = n_skip = 0;
    tunnel_probe = 1;
}
