#ifndef SUSANIN_UDP_RELAY_H
#define SUSANIN_UDP_RELAY_H

#include "config.h"

/* UDP-релей (egress через XRay): принимает помеченные UDP-пакеты через TPROXY
 * (IP_TRANSPARENT + IP_RECVORIGDSTADDR) и передаёт их через SOCKS5 UDP
 * ASSOCIATE к локальному Xray-socks (udp:true). Ответы возвращает клиенту
 * с исходного адреса сервиса. Запускается только при cfg->udp_relay=1.
 * Возврат: pid дочернего процесса (или 0, если не запущено/ошибка). */
int  udp_relay_start(const susanin_config *cfg);
void udp_relay_stop(void);

#endif
