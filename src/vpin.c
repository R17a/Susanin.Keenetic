#include <stdio.h>
#include <string.h>

#include "vpin.h"

static struct {
    char ip[16];
    int state;
    time_t at;
} q[VPIN_MAX];

static unsigned long n_bad, n_slow, n_back;

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

void vpin_note(const char *ip, time_t now)
{
    int i;
    if (!ip || !ip[0] || strlen(ip) >= sizeof(q[0].ip))
        return;
    i = slot_find(ip);
    if (i < 0) {
        i = slot_take();
        if (i < 0)
            return;
        snprintf(q[i].ip, sizeof(q[i].ip), "%s", ip);
    }
    q[i].state = VPIN_Q_VPN;
    q[i].at = now;
}

int vpin_due(time_t now, int vpn_iv, int direct_iv, int *out, int max)
{
    int i, n = 0;
    if (!out || max <= 0)
        return 0;
    if (vpn_iv < 0)
        vpn_iv = 0;
    if (direct_iv < 0)
        direct_iv = 0;
    for (i = 0; i < VPIN_MAX && n < max; i++) {
        if (q[i].state == VPIN_FREE)
            continue;
        if (q[i].state == VPIN_Q_VPN && now - q[i].at >= vpn_iv)
            out[n++] = i;
        else if (q[i].state == VPIN_Q_DIRECT && now - q[i].at >= direct_iv)
            out[n++] = i;
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

void vpin_set(int idx, int state, time_t now)
{
    if (idx < 0 || idx >= VPIN_MAX)
        return;
    if (state == VPIN_FREE) {
        q[idx].state = VPIN_FREE;
        q[idx].ip[0] = '\0';
        q[idx].at = 0;
        return;
    }
    if (q[idx].state == VPIN_FREE)
        return;
    q[idx].state = state;
    q[idx].at = now;
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
    else
        n_back++;
}

void vpin_counters(unsigned long *bad, unsigned long *slow, unsigned long *back)
{
    if (bad)
        *bad = n_bad;
    if (slow)
        *slow = n_slow;
    if (back)
        *back = n_back;
}

void vpin_reset(void)
{
    memset(q, 0, sizeof(q));
    n_bad = n_slow = n_back = 0;
}
