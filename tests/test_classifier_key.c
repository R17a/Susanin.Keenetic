/* Тесты ключей port-aware в классификаторе (этап 5): pair_key/flow_port.
 * classifier.c включается в TU, чтобы дотянуться до static-функций. make test. */
#define _GNU_SOURCE
#include "classifier.c"
#include "classifier.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(cond, msg) do { if (cond) printf("ok  %s\n", msg); \
    else { printf("FAIL %s\n", msg); failures++; } } while (0)

int main(void)
{
    susanin_config cfg;
    ct_flow f;
    char buf[64];
    const char *key;

    config_set_defaults(&cfg);
    memset(&f, 0, sizeof(f));
    snprintf(f.dst, sizeof(f.dst), "%s", "203.0.113.9");
    f.dport = 443;

    printf("=== port_aware=0: ключ — адрес ===\n");
    key = pair_key(buf, sizeof(buf), &cfg, &f);
    CHECK(!strcmp(key, "203.0.113.9"), "пара не используется");
    CHECK(flow_port(&cfg, &f) == 0, "порт для ipset = 0");

    printf("=== port_aware=1: ключ — пара, порт передаётся ===\n");
    cfg.port_aware = 1;
    key = pair_key(buf, sizeof(buf), &cfg, &f);
    CHECK(!strcmp(key, "203.0.113.9:443"), "ключ ip:port");
    CHECK(flow_port(&cfg, &f) == 443, "порт для ipset = dport");
    f.dport = 80;
    key = pair_key(buf, sizeof(buf), &cfg, &f);
    CHECK(!strcmp(key, "203.0.113.9:80"), "другой порт — другой ключ");

    printf("=== ключ состояния совпадает с разбором ===\n");
    {
        char ip[64];
        int port = -1;
        f.dport = 8443;
        key = pair_key(buf, sizeof(buf), &cfg, &f);
        state_key_split(key, ip, sizeof(ip), &port);
        CHECK(!strcmp(ip, "203.0.113.9") && port == 8443,
              "state_key/pair_key/state_key_split согласованы");
    }

    printf("=== clf_marked_direct: помечен, но REDIRECT не забрал ===\n");
    {
        ct_flow m;

        config_set_defaults(&cfg);
        memset(&m, 0, sizeof(m));
        m.l4proto = 6;
        m.has_reply = 1;
        m.ctmark = cfg.mark_ok;
        m.dport = 443;
        m.r_sport = 443;
        CHECK(clf_marked_direct(&cfg, &m) == 1,
              "reply-порт = dport -> шёл напрямую");
        m.r_sport = (unsigned)cfg.tproxy_port;
        CHECK(clf_marked_direct(&cfg, &m) == 0,
              "reply-порт = порт Xray -> шёл через REDIRECT");
        m.r_sport = 443;
        m.ctmark = 0;
        CHECK(clf_marked_direct(&cfg, &m) == 0, "без нашей метки -> не наш поток");
        m.ctmark = cfg.mark_ok;
        m.has_reply = 0;
        CHECK(clf_marked_direct(&cfg, &m) == 0, "ответа ещё не было -> не доказать");
        m.has_reply = 1;
        m.l4proto = 17;
        CHECK(clf_marked_direct(&cfg, &m) == 0, "UDP не проверяем: reply-порт не тот признак");
        m.l4proto = 6;
        m.dport = (unsigned)cfg.tproxy_port;
        m.r_sport = (unsigned)cfg.tproxy_port;
        CHECK(clf_marked_direct(&cfg, &m) == 0, "dport = порт Xray -> исключён");
    }

    printf("\n%s\n", failures ? "ЕСТЬ ОШИБКИ" : "все проверки пройдены");
    return failures ? 1 : 0;
}
