/* ay_client.h — клиент закрытого транспорта Susanin.Keenetic.AY.
 *
 * Задача модуля: поднять tun-интерфейс (ay0), держать сессию с сервером AY и
 * гонять IPv4-пакеты между tun и UDP-сокетом. Крипто и кадрирование — за
 * закрытым транспортом (src/ay_transport.h), здесь только сеть, состояние и
 * наблюдаемость.
 */
#ifndef SUSANIN_AY_CLIENT_H
#define SUSANIN_AY_CLIENT_H

#include <stddef.h>

#include "config.h"

/* Применить настройки: поднять/остановить/пересоздать клиент.
 * Идемпотентно: вызывается на старте агента и на каждый SIGHUP.
 * 0 — состояние применено (в т.ч. «выключено»), <0 — ошибка (см. статус). */
int ay_client_apply(const susanin_config *cfg);

/* Остановить клиент и закрыть tun (вызывается при выходе агента). */
void ay_client_stop(void);

int ay_client_running(void);
int ay_client_connected(void);

/* Желание оператора: 1 — «Подключиться» (или egress_type=ay по умолчанию),
 * 0 — «Отключиться». Хранится в var/ay.desired. */
int ay_client_desired(const susanin_config *cfg);

/* Имя tun-интерфейса для этого конфига (никогда не NULL). */
const char *ay_client_iface(const susanin_config *cfg);

/* JSON состояния для панели (`/api/ay`) и `status`. 0 — ок. */
int ay_client_status_json(const susanin_config *cfg, char *buf, size_t cap);

/* Тик главного цикла: обновить снимок состояния и, если туннель отключён,
 * изредка повторять попытку подъёма (разрешение имени/создание tun). */
void ay_client_tick(const susanin_config *cfg);

/* Файл-состояние «Подключиться/Отключиться» (его пишет веб-процесс). */
#define AY_DESIRED_PATH "/opt/susanin/var/ay.desired"
/* Снимок состояния (его читает веб-процесс). */
#define AY_STATUS_PATH  "/opt/susanin/var/ay.status"

#endif /* SUSANIN_AY_CLIENT_H */
