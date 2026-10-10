/* Тесты значения элемента ipset для port-aware (этап 3).
 * make test (host-компилятор). */
#define _GNU_SOURCE
#include "backend.h"
#include "config.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(cond, msg) do { if (cond) printf("ok  %s\n", msg); \
    else { printf("FAIL %s\n", msg); failures++; } } while (0)

int main(void)
{
    susanin_config cfg;
    char v[80];

    config_set_defaults(&cfg);

    printf("=== port_aware=0 (по умолчанию) ===\n");
    backend_ipset_value(&cfg, "1.2.3.4", 0, 0, v, sizeof(v));
    CHECK(!strcmp(v, "1.2.3.4"), "port=0 -> адрес");
    backend_ipset_value(&cfg, "1.2.3.4", 443, 0, v, sizeof(v));
    CHECK(!strcmp(v, "1.2.3.4"), "порт игнорируется, когда режим выключен");

    printf("=== port_aware=1 ===\n");
    cfg.port_aware = 1;
    backend_ipset_value(&cfg, "1.2.3.4", 443, 0, v, sizeof(v));
    CHECK(!strcmp(v, "1.2.3.4,tcp:443"), "TCP-пара -> ip,tcp:порт (протокол обязателен)");
    backend_ipset_value(&cfg, "1.2.3.4", 443, 1, v, sizeof(v));
    CHECK(!strcmp(v, "1.2.3.4,udp:443"), "UDP-пара -> ip,udp:порт (иначе пакет не совпадёт)");
    backend_ipset_value(&cfg, "1.2.3.4", 53, 1, v, sizeof(v));
    CHECK(!strcmp(v, "1.2.3.4,udp:53"), "UDP DNS-порт");
    backend_ipset_value(&cfg, "1.2.3.4", 0, 0, v, sizeof(v));
    CHECK(!strcmp(v, "1.2.3.4"), "port=0 в режиме пар -> адрес (net-наборы)");

    printf("=== защита буфера/пустых значений ===\n");
    backend_ipset_value(&cfg, "1.2.3.4", 65535, 0, v, 8);
    CHECK(strlen(v) < 8, "короткий буфер не переполняется");
    backend_ipset_value(NULL, "1.2.3.4", 443, 0, v, sizeof(v));
    CHECK(!strcmp(v, "1.2.3.4"), "NULL-конфиг -> адрес");
    backend_ipset_value(&cfg, NULL, 443, 0, v, sizeof(v));
    CHECK(v[0] == ',' || v[0] == '\0', "NULL-адрес не падает");

    printf("=== matcher «наш Xray» (back-end распознавание процесса) ===\n");
    CHECK(backend_is_our_xray_cmdline("xray run -config /opt/susanin/etc/xray-tproxy.json") == 1,
          "наш Xray распознан");
    CHECK(backend_is_our_xray_cmdline("truncate -s 0 /opt/susanin/etc/xray-tproxy.json") == 0,
          "подстрока run (truncate) не считается Xray");
    CHECK(backend_is_our_xray_cmdline("runtime-xray /opt/susanin/etc/xray-tproxy.json") == 0,
          "подстрока run (runtime) не считается Xray");
    CHECK(backend_is_our_xray_cmdline("/opt/susanin/bin/susanin-agent run") == 0,
          "сам агент не считается Xray");
    CHECK(backend_is_our_xray_cmdline("grep -q /opt/susanin/etc/xray-tproxy.json") == 0,
          "grep по нашему пути не считается Xray");
    CHECK(backend_is_our_xray_cmdline("vi /opt/susanin/etc/xray-tproxy.json") == 0,
          "открытый в редакторе конфиг не считается Xray");
    CHECK(backend_is_our_xray_cmdline("tail -f /opt/susanin/etc/xray-tproxy.json") == 0,
          "tail по конфигу не считается Xray");
    CHECK(backend_is_our_xray_cmdline("sh -c for d in /proc/*; do ... xray run -config /opt/susanin/etc/xray-tproxy.json ...") == 1,
          "shell-цикл совпал бы (поэтому kill делаем из C, а не sh -c)");

    printf("\n%s\n", failures ? "ЕСТЬ ОШИБКИ" : "все проверки пройдены");
    return failures ? 1 : 0;
}
