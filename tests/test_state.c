/* Тесты состояния (этап 2 port-aware): ключи ip:port, независимость от старых
 * записей, сохранение/загрузка в старом формате файла. make test. */
#define _GNU_SOURCE
#include "state.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int failures = 0;
#define CHECK(cond, msg) do { if (cond) printf("ok  %s\n", msg); \
    else { printf("FAIL %s\n", msg); failures++; } } while (0)

int main(void)
{
    susanin_state s;
    char k[64], k2[64];
    const char *path = "/tmp/susanin-state-test.txt";
    time_t now = time(NULL);

    printf("=== state_key ===\n");
    state_key(k, sizeof(k), "1.2.3.4", 0);
    CHECK(!strcmp(k, "1.2.3.4"), "port=0 -> адрес как есть");
    state_key(k, sizeof(k), "1.2.3.4", 443);
    CHECK(!strcmp(k, "1.2.3.4:443"), "port=443 -> ip:port");
    state_key(k, sizeof(k), "2001:db8::1", 80);
    CHECK(!strcmp(k, "2001:db8::1:80"), "IPv6-строка + порт (как строка)");
    state_key(k, sizeof(k), "1.2.3.4", -1);
    CHECK(!strcmp(k, "1.2.3.4"), "отрицательный порт -> обычный ключ");

    printf("=== пары и адрес не путаются ===\n");
    state_init(&s);
    state_key(k, sizeof(k), "1.2.3.4", 443);
    state_add(&s.ok_tcp, k, now, 600, 0);
    CHECK(state_has(&s.ok_tcp, k, now) == 1, "пара найдена");
    state_key(k2, sizeof(k2), "1.2.3.4", 0);
    CHECK(state_has(&s.ok_tcp, k2, now) == 0, "тот же адрес БЕЗ порта не найден");
    state_key(k2, sizeof(k2), "1.2.3.4", 80);
    CHECK(state_has(&s.ok_tcp, k2, now) == 0, "другой порт не найден");
    CHECK(state_at(&s.ok_tcp, k, now) > now, "state_at по паре отдаёт expire");
    state_remove(&s.ok_tcp, k);
    CHECK(state_has(&s.ok_tcp, k, now) == 0, "remove по паре работает");

    printf("=== много порт-ключей одного адреса ===\n");
    {
        int p;
        for (p = 0; p < 5; p++) {
            state_key(k, sizeof(k), "10.0.0.1", 100 + p);
            state_add(&s.test_udp, k, now, 60, 0);
        }
        CHECK(s.test_udp.n == 5, "пять пар одного адреса хранятся отдельно");
        state_key(k, sizeof(k), "10.0.0.1", 102);
        state_remove(&s.test_udp, k);
        CHECK(s.test_udp.n == 4, "удаление одной пары не трогает остальные");
    }

    printf("=== save/load: пары и старые записи вместе ===\n");
    state_key(k, sizeof(k), "203.0.113.7", 8443);
    state_add(&s.ok_udp, k, now, 900, 0);
    state_add(&s.net, "198.51.100.0/24", now, 900, 0);      /* как старый формат */
    CHECK(state_save(path, &s) == 0, "state_save выполнен");
    {
        susanin_state l;
        state_init(&l);
        CHECK(state_load(path, &l) == 0, "state_load выполнен");
        state_key(k, sizeof(k), "203.0.113.7", 8443);
        CHECK(state_has(&l.ok_udp, k, now) == 1, "пара восстановлена");
        CHECK(state_has(&l.net, "198.51.100.0/24", now) == 1, "запись по адресу восстановлена");
        {
            FILE *f = fopen(path, "r");
            int pairs = 0;
            char line[256];
            while (f && fgets(line, sizeof(line), f))
                if (strstr(line, "203.0.113.7:8443"))
                    pairs++;
            if (f)
                fclose(f);
            CHECK(pairs == 1, "в файле ключ записан как ip:port");
        }
        state_free(&l);
    }

    printf("=== истечение по TTL (GC) не зависит от формата ключа ===\n");
    {
        susanin_state e;
        state_init(&e);
        state_key(k, sizeof(k), "192.0.2.1", 8080);
        state_add(&e.cooldown_tcp, k, now - 100, 10, 0);   /* уже истёк */
        state_key(k2, sizeof(k2), "192.0.2.1", 0);
        state_add(&e.cooldown_tcp, k2, now - 100, 10, 0);
        CHECK(e.cooldown_tcp.n == 2, "две записи добавлены");
        state_expire(&e.cooldown_tcp, now);
        CHECK(e.cooldown_tcp.n == 0, "GC удалил и пару, и обычную запись");
        state_free(&e);
    }

    state_free(&s);
    remove(path);
    printf("\n%s\n", failures ? "ЕСТЬ ОШИБКИ" : "все проверки пройдены");
    return failures ? 1 : 0;
}
