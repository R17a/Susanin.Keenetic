/* Тесты очереди аудита пинов (src/vpin.c): очередь, сроки, состояния, счётчики.
 * Сети и ipset не касается — только структура решений. */
#include "vpin.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(cond, msg) do { if (cond) printf("ok  %s\n", msg); \
    else { printf("FAIL %s\n", msg); failures++; } } while (0)

int main(void)
{
    int i, idx[8], n;
    const time_t t0 = 1000000;

    /* 1. Новый адрес встаёт в очередь как «проверить туннель», не раньше интервала. */
    vpin_reset();
    vpin_note("1.2.3.4", t0);
    CHECK(vpin_pending() == 1, "note: адрес в очереди");
    CHECK(vpin_pending_vpn() == 1, "note: состояние Q_VPN");
    n = vpin_due(t0 + 599, 600, 1200, idx, 8);
    CHECK(n == 0, "due: до интервала не проверяем");
    n = vpin_due(t0 + 600, 600, 1200, idx, 8);
    CHECK(n == 1 && vpin_state(idx[0]) == VPIN_Q_VPN, "due: через интервал — Q_VPN");

    /* 2. Повторный note для того же адреса не плодит дубликат, а сдвигает срок. */
    vpin_note("1.2.3.4", t0 + 100);
    CHECK(vpin_pending() == 1, "note: без дубликата");
    CHECK(vpin_due(t0 + 601, 600, 1200, idx, 8) == 0, "note: срок сдвинут");

    /* 3. Туннель хорош: адрес ждёт проверки «не ожил ли прямой». */
    vpin_set(0, VPIN_Q_DIRECT, t0 + 700);
    CHECK(vpin_state(0) == VPIN_Q_DIRECT, "set: Q_DIRECT");
    CHECK(vpin_due(t0 + 700 + 1199, 600, 1200, idx, 8) == 0, "due: direct раньше срока молчит");
    n = vpin_due(t0 + 700 + 1200, 600, 1200, idx, 8);
    CHECK(n == 1 && vpin_state(idx[0]) == VPIN_Q_DIRECT, "due: direct через два интервала");

    /* 4. Снятие из очереди. */
    vpin_free_idx(0);
    CHECK(vpin_pending() == 0, "free: очередь пуста");
    CHECK(vpin_ip(0) == NULL, "free: адрес не отдаётся");

    /* 5. Переполнение: 64 слота, лишние вытесняют самый старый, очередь не растёт. */
    vpin_reset();
    for (i = 0; i < VPIN_MAX; i++) {
        char ip[16];
        snprintf(ip, sizeof(ip), "10.0.0.%d", i + 1);
        vpin_note(ip, t0 + i);
    }
    CHECK(vpin_pending() == VPIN_MAX, "fill: очередь полна");
    vpin_note("10.9.9.9", t0 + 500);
    CHECK(vpin_pending() == VPIN_MAX, "fill: вытеснение, размер тот же");
    CHECK(vpin_ip(0) && strcmp(vpin_ip(0), "10.9.9.9") == 0, "fill: старейший вытеснен");

    /* 6. Счётчики решений. */
    vpin_reset();
    vpin_bump(0);
    vpin_bump(0);
    vpin_bump(1);
    vpin_bump(2);
    {
        unsigned long bad = 0, slow = 0, back = 0;
        vpin_counters(&bad, &slow, &back);
        CHECK(bad == 2 && slow == 1 && back == 1, "counters: bad/slow/back");
    }
    vpin_reset();
    {
        unsigned long bad = 0, slow = 0, back = 0;
        vpin_counters(&bad, &slow, &back);
        CHECK(bad == 0 && slow == 0 && back == 0 && vpin_pending() == 0,
              "reset: всё обнулено");
    }

    /* 7. Некорректные аргументы не ломают очередь. */
    vpin_note(NULL, t0);
    vpin_note("", t0);
    vpin_note("0123456789abcdef", t0);   /* длиннее слота */
    CHECK(vpin_pending() == 0, "note: мусор игнорируется");
    CHECK(vpin_due(t0, 0, 0, NULL, 8) == 0, "due: без буфера — 0");
    CHECK(vpin_due(t0, 0, 0, idx, 0) == 0, "due: max=0 — 0");

    if (failures) {
        printf("FAILURES: %d\n", failures);
        return 1;
    }
    printf("all vpin tests passed\n");
    return 0;
}
