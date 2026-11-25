/* test_ay.c — AY в публичной сборке: заглушка транспорта и разбор конфига.
 *
 * Настоящий транспорт здесь не проверяется (его исходников в публичном дереве
 * нет). Задача теста — чтобы публичная сборка честно собиралась и чтобы ключи
 * ay_* разбирались, а egress_type=ay давал единственный egress-интерфейс.
 */
#include <stdio.h>
#include <string.h>

#include "ay_client.h"
#include "ay_transport.h"
#include "config.h"

static int g_fail;

#define CHECK(cond, what) do {                         \
    if (!(cond)) {                                     \
        g_fail++;                                      \
        printf("FAIL: %s (line %d)\n", (what), __LINE__); \
    }                                                  \
} while (0)

int main(void)
{
    susanin_config c;
    ay_ctx ctx;

    config_set_defaults(&c);
    CHECK(!strcmp(c.egress_type, "interface"), "egress_type по умолчанию");
    CHECK(c.ay_server[0] == '\0', "ay_server пуст по умолчанию");
    CHECK(c.ay_key[0] == '\0', "ay_key пуст по умолчанию");
    CHECK(c.ay_port == 5004, "ay_port=5004 (порт по умолчанию)");
    CHECK(!strcmp(c.ay_iface, "ay0"), "ay_iface=ay0");
    CHECK(!strcmp(c.ay_tun_ip, "10.23.0.2/24"), "ay_tun_ip по умолчанию");
    CHECK(c.ay_mtu == 1200, "ay_mtu=1200");
    CHECK(c.ay_keepalive == 5, "ay_keepalive=5");
    CHECK(c.ay_mark == 0x2UL, "ay_mark=0x2");

    /* type=ay: единственный egress — tun клиента, а не интерфейс системы. */
    snprintf(c.egress_type, sizeof c.egress_type, "%s", "ay");
    snprintf(c.ay_iface, sizeof c.ay_iface, "%s", "ay7");
    snprintf(c.ay_tun_ip, sizeof c.ay_tun_ip, "%s", "10.23.0.7/24");
    config_parse_egress(&c);
    CHECK(c.n_egress == 1, "один egress для ay");
    CHECK(!strcmp(c.egress_list[0], "ay7"), "egress = ay_iface");
    CHECK(!strcmp(c.egress_addr[0], "10.23.0.7"), "адрес без префикса");

    /* type=interface не смотрит на ay_iface. */
    snprintf(c.egress_type, sizeof c.egress_type, "%s", "interface");
    snprintf(c.egress_interface, sizeof c.egress_interface, "%s", "nwg0");
    config_parse_egress(&c);
    CHECK(c.n_egress == 1 && !strcmp(c.egress_list[0], "nwg0"),
          "interface-режим не подменяется AY");

    /* Публичная сборка: транспорт недоступен и честно об этом говорит. */
    CHECK(ay_transport_available() == 0, "без закрытой части AY недоступен");
    CHECK(ay_transport_init(&ctx, "secret", 0x0a170002u, 1200) == AY_ERR_UNAVAILABLE,
          "init заглушки");
    CHECK(ay_transport_connected(&ctx) == 0, "заглушка не подключена");

    printf("test_ay: %s\n", g_fail ? "ОШИБКИ" : "ok");
    return g_fail ? 1 : 0;
}
