/* Тесты очереди аудита пинов (src/vpin.c): очередь, сроки, состояния,
 * порт/протокол улики, счётчики, снимок. Сети и ipset не касается —
 * только структура решений.
 *
 * Честно о покрытии: логика vq_* в engine.c (fork пробы, pipe, разбор
 * "<ip> <state> <ok> <lat>", трёхсостояательная проба через SOCKS,
 * применение вердикта) здесь НЕ проверяется — она неотделима от процессов,
 * сокетов и бэкенда и живёт в главном цикле. Здесь покрыта очередь, на
 * которую эта логика опирается (включая «после одного промаха слот жив и
 * состояние не изменено» — сам пин снимает движок только при nfails>=2).
 */
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

    /* 1. Новый адрес встаёт в очередь как «проверить туннель», не раньше
     *    интервала; порт подтверждающего потока сохраняется. */
    vpin_reset();
    vpin_note("1.2.3.4", 8000, 0, t0);
    CHECK(vpin_pending() == 1, "note: адрес в очереди");
    CHECK(vpin_pending_vpn() == 1, "note: состояние Q_VPN");
    n = vpin_due(t0 + 599, 600, 1200, idx, 8);
    CHECK(n == 0, "due: до интервала не проверяем");
    n = vpin_due(t0 + 600, 600, 1200, idx, 8);
    CHECK(n == 1 && vpin_state(idx[0]) == VPIN_Q_VPN, "due: через интервал — Q_VPN");
    CHECK(vpin_port(idx[0]) == 8000, "port: сохранён порт улики (не 443)");

    /* 2. Повторный note для того же адреса: без дубликата, срок сдвинут,
     *    порт обновлён (улика с нового порта важнее старой). */
    vpin_note("1.2.3.4", 1935, 0, t0 + 100);
    CHECK(vpin_pending() == 1, "note: без дубликата");
    CHECK(vpin_due(t0 + 601, 600, 1200, idx, 8) == 0, "note: срок сдвинут");
    n = vpin_due(t0 + 700 + 600, 600, 1200, idx, 8);
    CHECK(n == 1 && vpin_port(idx[0]) == 1935, "note: порт обновлён");

    /* 3. UDP-потоки в очередь не попадают: TCP-проба аудита ничего про них
     *    не знает, «нет ответа» по TCP снимала бы живой UDP-пин. */
    vpin_reset();
    vpin_note("5.6.7.8", 443, 1, t0);
    CHECK(vpin_pending() == 0, "udp: в очередь не ставим");

    /* 4. Туннельная проба недоступна (режим не-tproxy): новые улики едут
     *    сразу в Q_DIRECT, а существующие Q_VPN переводятся при смене
     *    режима — иначе они вечно висели бы due и вытесняли Q_DIRECT. */
    vpin_reset();
    vpin_note("1.1.1.1", 443, 0, t0);
    CHECK(vpin_pending_vpn() == 1, "mode: tproxy — запись в Q_VPN");
    vpin_set_tunnel_probe(0, t0 + 10);
    CHECK(vpin_pending_vpn() == 0, "mode: смена режима — Q_VPN не осталось");
    CHECK(vpin_find("1.1.1.1", VPIN_Q_DIRECT) >= 0, "mode: старая запись стала Q_DIRECT");
    vpin_note("2.2.2.2", 443, 0, t0 + 20);
    CHECK(vpin_find("2.2.2.2", VPIN_Q_DIRECT) >= 0, "mode: новая улика сразу Q_DIRECT");
    vpin_set_tunnel_probe(1, t0 + 30);
    vpin_note("3.3.3.3", 443, 0, t0 + 30);
    CHECK(vpin_find("3.3.3.3", VPIN_Q_VPN) >= 0, "mode: обратно — новые в Q_VPN");

    /* 5. Промахи: после одного — слот жив, состояние не изменено (пин на
     *    месте); снятие решает движок при втором подряд. vpin_set (успех или
     *    «не чем мерить») сбрасывает счётчик. */
    vpin_reset();
    vpin_note("9.9.9.9", 443, 0, t0);
    i = vpin_find("9.9.9.9", VPIN_Q_VPN);
    CHECK(i >= 0, "nfails: слот найден");
    CHECK(vpin_fail(i, t0 + 600, 30) == 1, "nfails: первый промах");
    CHECK(vpin_state(i) == VPIN_Q_VPN && vpin_pending() == 1,
          "nfails: после одного промаха пин НЕ снят (слот жив, состояние то же)");
    n = vpin_due(t0 + 600 + 29, 600, 1200, idx, 8);
    CHECK(n == 0, "holdoff: раньше половины интервала не проверяем");
    n = vpin_due(t0 + 600 + 30, 600, 1200, idx, 8);
    CHECK(n == 1 && idx[0] == i, "holdoff: перепроверка через 30 с");
    CHECK(vpin_fail(i, t0 + 630, 30) == 2, "nfails: второй промах подряд");
    vpin_set(i, VPIN_Q_DIRECT, t0 + 700);
    CHECK(vpin_fail(i, t0 + 800, 0) == 1, "set: успех сбросил счётчик промахов");

    /* 6. Кап Q_DIRECT: счётчик доходит до 3 — на этом движок освобождает
     *    слот (адрес легитимно живёт только в VPN). */
    vpin_reset();
    vpin_note("8.8.8.8", 443, 0, t0);
    i = vpin_find("8.8.8.8", VPIN_Q_VPN);
    vpin_set(i, VPIN_Q_DIRECT, t0 + 10);
    CHECK(vpin_fail(i, t0 + 20, 0) == 1 && vpin_fail(i, t0 + 30, 0) == 2 &&
          vpin_fail(i, t0 + 40, 0) == 3, "cap: три промаха прямого досчитаны");

    /* 7. Обход due по давности (самый старый at первым), а не по индексу:
     *    слот 0 продлён позже — первым должен уйти слот 1. */
    vpin_reset();
    vpin_note("10.0.0.1", 443, 0, t0 + 100);   /* слот 0, самый свежий */
    vpin_note("10.0.0.2", 443, 0, t0);         /* слот 1, самый старый */
    vpin_note("10.0.0.3", 443, 0, t0 + 50);    /* слот 2, средний */
    n = vpin_due(t0 + 700, 600, 1200, idx, 3);
    CHECK(n == 3 && !strcmp(vpin_ip(idx[0]), "10.0.0.2") &&
          !strcmp(vpin_ip(idx[1]), "10.0.0.3") &&
          !strcmp(vpin_ip(idx[2]), "10.0.0.1"),
          "due: порядок по давности, не по индексу");

    /* 8. Переполнение: 64 слота, лишние вытесняют самый старый. */
    vpin_reset();
    for (i = 0; i < VPIN_MAX; i++) {
        char ip[16];
        snprintf(ip, sizeof(ip), "10.0.0.%d", i + 1);
        vpin_note(ip, 443, 0, t0 + i);
    }
    CHECK(vpin_pending() == VPIN_MAX, "fill: очередь полна");
    vpin_note("10.9.9.9", 443, 0, t0 + 500);
    CHECK(vpin_pending() == VPIN_MAX, "fill: вытеснение, размер тот же");
    CHECK(vpin_ip(0) && strcmp(vpin_ip(0), "10.9.9.9") == 0, "fill: старейший вытеснен");
    CHECK(vpin_find("10.0.0.1", VPIN_Q_VPN) == -1, "find: вытесненный адрес не найден");

    /* 9. vpin_find: вердикт чужого слота (смена адреса/состояния) — -1. */
    CHECK(vpin_find("10.9.9.9", VPIN_Q_VPN) == 0, "find: по адресу и состоянию");
    CHECK(vpin_find("10.9.9.9", VPIN_Q_DIRECT) == -1, "find: состояние не совпало — -1");
    CHECK(vpin_find("10.0.0.9", VPIN_Q_VPN) >= 0, "find: живой адрес найден");

    /* 10. Счётчики решений, включая skip. */
    vpin_reset();
    vpin_bump(0);
    vpin_bump(0);
    vpin_bump(1);
    vpin_bump(2);
    vpin_bump(3);
    {
        unsigned long bad = 0, slow = 0, back = 0, skip = 0;
        vpin_counters(&bad, &slow, &back, &skip);
        CHECK(bad == 2 && slow == 1 && back == 1 && skip == 1,
              "counters: bad/slow/back/skip");
    }
    vpin_reset();
    {
        unsigned long bad = 1, slow = 1, back = 1, skip = 1;
        vpin_counters(&bad, &slow, &back, &skip);
        CHECK(bad == 0 && slow == 0 && back == 0 && skip == 0 && vpin_pending() == 0,
              "reset: всё обнулено");
    }

    /* 11. Снимок для status/why: первая строка — сводка, далее очередь. */
    vpin_reset();
    vpin_note("77.77.77.77", 554, 0, t0);
    {
        char buf[512];
        vpin_bump(3);
        CHECK(vpin_format(buf, sizeof(buf), 1, 600) > 0, "format: построен");
        CHECK(strstr(buf, "vpin: check=1 interval=600s") == buf,
              "format: сводная строка первой");
        CHECK(strstr(buf, "pending=1/vpn=1") != NULL, "format: длина очереди видна");
        CHECK(strstr(buf, "skip=1") != NULL, "format: skip виден");
        CHECK(strstr(buf, "q 77.77.77.77 vpn 554") != NULL, "format: строка очереди");
    }

    /* 12. Некорректные аргументы не ломают очередь. */
    vpin_note(NULL, 443, 0, t0);
    vpin_note("", 443, 0, t0);
    vpin_note("0123456789abcdef", 443, 0, t0);   /* длиннее слота */
    CHECK(vpin_pending() == 1, "note: мусор игнорируется");
    CHECK(vpin_due(t0, 0, 0, NULL, 8) == 0, "due: без буфера — 0");
    CHECK(vpin_due(t0, 0, 0, idx, 0) == 0, "due: max=0 — 0");

    if (failures) {
        printf("FAILURES: %d\n", failures);
        return 1;
    }
    printf("all vpin tests passed\n");
    return 0;
}
