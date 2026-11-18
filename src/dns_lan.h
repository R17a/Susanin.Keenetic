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
int  dns_lan_stats(char *out, size_t n);

/* Снимок для CLI: движок пишет строку в файл, `status`/`why` её читают. */
#define DNS_LAN_STATE_FILE      "/opt/susanin/var/dnslan.state"
#define DNS_LAN_SOFT_STATE_FILE "/tmp/susanin-dnslan.state"
const char *dns_lan_state_path(const susanin_config *cfg);
void dns_lan_write_snapshot(const susanin_config *cfg);

#endif
