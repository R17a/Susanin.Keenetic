#ifndef SUSANIN_DNS_LAN_H
#define SUSANIN_DNS_LAN_H

#include <stddef.h>

#include "config.h"

/* DNS-форвардер для клиентов LAN: запросы уходят в туннель через SOCKS5-UDP
 * Xray, с кэшем и fail-open на прямой запрос (см. src/dns_lan.c). */
int  dns_lan_start(const susanin_config *cfg);   /* 0 = слушаем */
void dns_lan_stop(void);
void dns_lan_reload(const susanin_config *cfg);
void dns_lan_poll(void);
int  dns_lan_active(void);
/* 1 = форвардер обслуживается своим потоком: движку нельзя ни опрашивать его
 * (dns_lan_poll), ни читать счётчики (dns_lan_stats) — это сделает поток. */
int  dns_lan_threaded(void);
/* Пиннинг по подмене (dns_lan_pin): подменённый домен получает настоящий адрес
 * из туннеля, заявки складывает форвардер (в поточном режиме — из своего
 * потока), применяет главный цикл через dns_lan_drain_pins. */
int  dns_lan_pins_pending(void);
int  dns_lan_drain_pins(char ips[][16], char names[][64], int max);
int  dns_lan_busy(void);   /* 1 = идёт обмен с туннелем, спать короче */
int  dns_lan_stats(char *out, size_t n);
/* Сколько запросов сейчас ждут ответа (0..DNS_LAN_PEND). В status печатается
 * реальное число: прежняя константа «pend=64» выглядела как полная очередь. */
int  dns_lan_pending(void);

/* Снимок для CLI: движок пишет строку в файл, `status`/`why` её читают. */
#define DNS_LAN_STATE_FILE      "/opt/susanin/var/dnslan.state"
#define DNS_LAN_SOFT_STATE_FILE "/tmp/susanin-dnslan.state"
const char *dns_lan_state_path(const susanin_config *cfg);
void dns_lan_write_snapshot(const susanin_config *cfg);

#endif
