/* Тесты подтверждения stall-сигналов (DPI-STALL, TCP-CLOSE-EMPTY): «тишина
 * после рукопожатия» уводит адрес в VPN не с первого наблюдения, а после
 * серии окон детектора (stall_confirm). Счёт — по различным проходам, а не
 * по пакетам/параллельным потокам одного прохода (тот же принцип, что у
 * sf_note для SYN-кворума); свежая отметка «прямой путь отвечает» не даёт
 * решить по одному окну; здоровая передача снимает с наблюдения.
 * classifier.c включается в TU, чтобы дотянуться до static-функций.
 * Сеть/ipset не нужны: проверяются шлюзы ДО backend-вызовов.
 * make test (хост-компилятор; в поставку не входит).
 */
#define _GNU_SOURCE
#include "classifier.c"
#include "classifier.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(cond, msg) do { if (cond) printf("ok  %s\n", msg); \
    else { printf("FAIL %s\n", msg); failures++; } } while (0)

/* stall_hold с обнулённым буфером причины: так же его вызывает promote_test.
 * Возврат 1 — решение отложено (НЕ promoted), 0 — промоушен разрешён. */
static int hold(classifier_ctx *ctx, const char *kf, const char *dst,
                const char *reason, time_t now, char *lb)
{
    lb[0] = '\0';
    return stall_hold(ctx, kf, dst, reason, now, lb, 48);
}

int main(void)
{
    susanin_config cfg;
    susanin_state st;
    classifier_ctx ctx;
    char lb[48];
    time_t t0 = 1000000;

    config_set_defaults(&cfg);
    state_init(&st);
    ctx.cfg = &cfg;
    ctx.st = &st;

    printf("=== дефолты ===\n");
    CHECK(cfg.stall_confirm == 2, "stall_confirm по умолчанию 2");
    CHECK(cfg.watch_ttl == 8, "окно серии (watch_ttl) по умолчанию 8 с");

    printf("=== одно наблюдение — только постановка под наблюдение ===\n");
    CHECK(hold(&ctx, "203.0.113.10", "203.0.113.10", "DPI-STALL", t0, lb) == 1,
          "первое окно -> не promoted");
    CHECK(state_has(st_watch(&st, 0), "203.0.113.10", t0) == 1,
          "пара взята под наблюдение (st_watch, тот же ключ, что у FREEZE)");

    printf("=== повторное наблюдение в следующем окне — promoted ===\n");
    CHECK(hold(&ctx, "203.0.113.10", "203.0.113.10", "DPI-STALL", t0 + 1, lb) == 0,
          "второе окно подряд -> промоушен разрешён");
    CHECK(!strcmp(lb, "DPI-STALL-CONFIRMED"),
          "в причине видно, что решение после подтверждения серией");

    printf("=== stall_confirm=1: прежнее мгновенное поведение ===\n");
    cfg.stall_confirm = 1;
    CHECK(hold(&ctx, "203.0.113.12", "203.0.113.12", "DPI-STALL", t0, lb) == 0,
          "первое окно -> разрешено сразу");
    CHECK(lb[0] == '\0', "причина без суффикса: поведение как до правки");
    cfg.stall_confirm = 2;

    printf("=== свежая отметка «прямой жив»: одного окна мало ===\n");
    /* Прямой путь только что отвечал на пробе с роутера — тишина одного окна
     * не перевешивает: минимум два окна, даже в мгновенном режиме. */
    cfg.stall_confirm = 1;
    dok_add("203.0.113.13", t0, DOK_TTL_OK);
    CHECK(hold(&ctx, "203.0.113.13", "203.0.113.13", "TCP-CLOSE-EMPTY", t0, lb) == 1,
          "dok свежая + stall_confirm=1 -> одно наблюдение не решает");
    CHECK(hold(&ctx, "203.0.113.13", "203.0.113.13", "TCP-CLOSE-EMPTY", t0 + 1, lb) == 0,
          "второе окно подряд -> разрешено");
    cfg.stall_confirm = 2;

    printf("=== SYN-кворум на то же назначение снимает ожидание ===\n");
    /* Гибели SYN клиента — явное доказательство сломанного прямого пути:
     * серия не обязана дожидаться всех окон. */
    {
        char fl[SF_FLOWLEN];
        int i;
        for (i = 0; i < cfg.synfail_quorum; i++) {
            snprintf(fl, sizeof(fl), "192.168.1.50:%d", 40000 + i);
            sf_note(&cfg, "203.0.113.14", fl, t0);
        }
        CHECK(sf_quorum_seen(&cfg, "203.0.113.14", t0) == 1,
              "кворум набран (read-only взгляд на sf_tab)");
        CHECK(hold(&ctx, "203.0.113.14", "203.0.113.14", "DPI-STALL", t0, lb) == 0,
              "одно stall-наблюдение + SYN-кворум -> разрешено");
        CHECK(!strcmp(lb, "DPI-STALL+SYN-QUORUM"),
              "в причине видно, что сняло ожидание именно кворум");
    }

    printf("=== повторные потоки одного прохода счёт не накручивают ===\n");
    /* Разговорчивый клиент с несколькими параллельными соединениями виден
     * детектору в одном проходе несколько раз: окно — проход, а не поток. */
    CHECK(hold(&ctx, "203.0.113.15", "203.0.113.15", "DPI-STALL", t0, lb) == 1,
          "окно 1 -> держим");
    CHECK(hold(&ctx, "203.0.113.15", "203.0.113.15", "DPI-STALL", t0, lb) == 1,
          "тот же проход (та же метка времени) -> повтор не засчитан");
    CHECK(hold(&ctx, "203.0.113.15", "203.0.113.15", "DPI-STALL", t0, lb) == 1,
          "и ещё раз в том же проходе -> всё ещё одно окно");
    CHECK(hold(&ctx, "203.0.113.15", "203.0.113.15", "DPI-STALL", t0 + 1, lb) == 0,
          "следующий проход -> второе окно, разрешено");

    printf("=== здоровая передача снимает с наблюдения ===\n");
    /* Ответ пошёл — тишина была переходящей: серия не должна потом «дозреть»
     * из устаревших окон. */
    CHECK(hold(&ctx, "203.0.113.16", "203.0.113.16", "DPI-STALL", t0, lb) == 1,
          "окно 1 -> под наблюдением");
    stall_release(&ctx, "203.0.113.16");
    CHECK(state_has(st_watch(&st, 0), "203.0.113.16", t0) == 0,
          "watch-запись снята");
    CHECK(hold(&ctx, "203.0.113.16", "203.0.113.16", "DPI-STALL", t0 + 1, lb) == 1,
          "новое наблюдение начинает серию заново: одного окна снова мало");

    printf("=== серия не переживает долгое молчание ===\n");
    CHECK(hold(&ctx, "203.0.113.17", "203.0.113.17", "DPI-STALL", t0, lb) == 1,
          "окно 1");
    CHECK(hold(&ctx, "203.0.113.17", "203.0.113.17", "DPI-STALL",
                t0 + cfg.watch_ttl + 5, lb) == 1,
          "наблюдение позже watch_ttl -> серия начата заново, не «второе окно»");
    CHECK(hold(&ctx, "203.0.113.17", "203.0.113.17", "DPI-STALL",
                t0 + cfg.watch_ttl + 6, lb) == 0,
          "а два окна подряд после рестарта -> подтверждено");

    printf("=== stall_confirm=3: ждём три окна ===\n");
    cfg.stall_confirm = 3;
    CHECK(hold(&ctx, "203.0.113.18", "203.0.113.18", "TCP-CLOSE-EMPTY", t0, lb) == 1,
          "окно 1");
    CHECK(hold(&ctx, "203.0.113.18", "203.0.113.18", "TCP-CLOSE-EMPTY", t0 + 1, lb) == 1,
          "окно 2 -> ещё мало");
    CHECK(hold(&ctx, "203.0.113.18", "203.0.113.18", "TCP-CLOSE-EMPTY", t0 + 2, lb) == 0,
          "окно 3 -> разрешено");
    CHECK(!strcmp(lb, "TCP-CLOSE-EMPTY-CONFIRMED"), "причина с суффиксом серии");
    cfg.stall_confirm = 2;

    printf("=== stall_confirm=0 трактуется как мгновенный режим ===\n");
    cfg.stall_confirm = 0;
    CHECK(hold(&ctx, "203.0.113.19", "203.0.113.19", "DPI-STALL", t0, lb) == 0,
          "0 -> мгновенно (как 1), без свежей отметки «прямой жив»");

    state_free(&st);
    printf("\n%s\n", failures ? "ЕСТЬ ОШИБКИ" : "ИТОГ: все проверки пройдены");
    return failures ? 1 : 0;
}
