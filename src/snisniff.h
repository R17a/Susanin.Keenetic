#ifndef SNISNIFF_H
#define SNISNIFF_H

#include <stddef.h>

#include "config.h"

/* Пассивный SNI-детект: имя сервера из TLS ClientHello.
 *
 * Зачем второй источник домена: dns_sniff видит только открытый DNS (порт 53).
 * Если клиент ходит через DoH/DoT, или DNS-ответ не попал в захват, агент видит
 * только IP — и все доменные правила (vpn_always/vpn_never, ru_guard, мягкие
 * записи ?domain, строка «(домен)» в логе обучения) слепнут. SNI едет в первом
 * пакете данных TCP/443 в открытом виде и не зависит от DNS вообще.
 *
 * Хранилище общее с dns_sniff («IP -> домен»), поэтому остальной код ничего не
 * замечает: он спрашивает dns_sniff_domain_of() и получает имя.
 */

/* Разобрать TLS ClientHello из полезной нагрузки TCP.
 * Возврат: 1 — имя найдено (out, нижний регистр), 0 — не ClientHello/нет SNI/битые
 * данные. Функция чистая (без сокетов и состояния) — её и тестируют. */
int sni_parse_client_hello(const unsigned char *p, size_t len, char *out, size_t n);

#endif
