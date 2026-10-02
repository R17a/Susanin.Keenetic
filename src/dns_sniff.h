#ifndef SUSANIN_DNS_SNIFF_H
#define SUSANIN_DNS_SNIFF_H

#include "config.h"

/*
 * DNS-снифинг (P3 / N1): зеркально слушаем DNS-ответы LAN (AF_PACKET на
 * LAN-интерфейсе) и запоминаем связь домен -> IP. Штатный DNS роутера при этом
 * НЕ перехватываем и не меняем — только подглядываем уже идущие ответы.
 *
 * Назначение:
 *  - контекст для наблюдаемости: «почему этот IP в VPN» (какому домену он
 *    принадлежит);
 *  - точное покрытие поддоменов доменов из vpn_always/vpn_never до их
 *    собственного резолва (IP из ответа пинится сразу).
 *
 * По умолчанию выключено (dns_sniff=0).
 */

int  dns_sniff_start(const susanin_config *cfg);  /* 0 = ok, -1 = нет (лог) */
void dns_sniff_stop(void);
void dns_sniff_poll(void);                        /* забрать пакеты (nonblock) */

/* Периодически пинит IP из снифинга, если домен попал в vpn_always/vpn_never. */
void dns_sniff_reconcile(const susanin_config *cfg);

int  dns_sniff_count(void);
/* 1 = нашли домен для IP; domain_out заполняется (может быть ""). */
int  dns_sniff_domain_of(const char *ip, char *domain_out, unsigned n);

#endif
