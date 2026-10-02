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

#endif
