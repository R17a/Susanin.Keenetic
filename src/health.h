#ifndef SUSANIN_HEALTH_H
#define SUSANIN_HEALTH_H

#include "config.h"

/* Returns 0 on success. *ok = number of probes that got a reply, *total = sent.
 * src — source address for the probes (tunnel address of the current egress);
 * if NULL/empty, cfg->egress_address is used. */
int health_probe(const susanin_config *c, const char *src, int *ok, int *total);

/* То же, но проба жёстко привязана к интерфейсу (SO_BINDTODEVICE). Нужно для
 * независимой проверки КАЖДОГО egress (master/slave failback): маршрут таблицы
 * 100 указывает на активный egress, поэтому без привязки к устройству проба
 * всегда уходила бы через активный. dev=NULL — обычное поведение. */
int health_probe_dev(const susanin_config *c, const char *dev, const char *src,
                     int *ok, int *total);

/* Прямая TCP-проба dst:port мимо наших правил (по main, без метки):
 * 1 = соединение установилось. */
int health_probe_tcp_direct(const char *dst, unsigned port, int timeout_ms);

/* Проба апстрима Xray через локальный SOCKS5 (режим tproxy): 1 = ok. */
int health_probe_via_socks(const susanin_config *c, const char *dst, int port,
                           int timeout_ms);

#endif
