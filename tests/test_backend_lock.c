/* Тесты распознавания xtables-lock (ложное «data plane missing»).
 * make test (host-компилятор). */
#define _GNU_SOURCE
#include "backend.h"

#include <stdio.h>

static int failures = 0;
#define CHECK(cond, msg) do { if (cond) printf("ok  %s\n", msg); \
    else { printf("FAIL %s\n", msg); failures++; } } while (0)

int main(void)
{
    printf("=== код возврата iptables ===\n");
    CHECK(backend_xt_locked(BACKEND_XT_LOCK_RC, NULL) == 1,
          "rc=4 -> замок занят, проверку надо повторить");
    CHECK(backend_xt_locked(4, "") == 1, "rc=4 с пустым выводом");
    CHECK(backend_xt_locked(0, NULL) == 0, "rc=0 -> проверка валидна");
    CHECK(backend_xt_locked(1, NULL) == 0, "rc=1 -> не замок (правило/ошибка)");
    CHECK(backend_xt_locked(127, NULL) == 0, "rc=127 (нет iptables) -> не замок");
    CHECK(backend_xt_locked(-1, NULL) == 0, "fork/wait ошибка -> не замок");

    printf("=== текст в выводе ===\n");
    CHECK(backend_xt_locked(1, "Another app is currently holding the xtables lock.") == 1,
          "текст xtables lock ловится и при чужом rc");
    CHECK(backend_xt_locked(0, "iptables v1.8: xtables lock is not available") == 1,
          "текст ловится и при rc=0");
    CHECK(backend_xt_locked(0, "Chain SUSANIN (1 references)") == 0,
          "обычный вывод -S замком не считается");
    CHECK(backend_xt_locked(1, "No chain/target/match by that name.") == 0,
          "реальная ошибка (нет цепочки) замком не считается");

    printf("=== признак «пропало redirect-правило» ===\n");
    CHECK(backend_why_is_redirect("nat REDIRECT (TCP)") == 1,
          "REDIRECT -> помеченные потоки ушли напрямую, conntrack рвать");
    CHECK(backend_why_is_redirect("mangle TPROXY (UDP)") == 1, "TPROXY -> рвать");
    CHECK(backend_why_is_redirect("ip rule tproxy") == 1, "ip rule -> рвать");
    CHECK(backend_why_is_redirect("FORWARD ACCEPT (mark)") == 0,
          "FORWARD ACCEPT -> поток до Xray доходит, рвать нечего");
    CHECK(backend_why_is_redirect("route table") == 0, "маршрут -> не рвать");
    CHECK(backend_why_is_redirect("chain SUSANIN") == 0, "цепочка -> не рвать");
    CHECK(backend_why_is_redirect("") == 0, "пустая причина");
    CHECK(backend_why_is_redirect(NULL) == 0, "NULL");

    printf("\n%s\n", failures ? "ЕСТЬ ОШИБКИ" : "все проверки пройдены");
    return failures ? 1 : 0;
}
