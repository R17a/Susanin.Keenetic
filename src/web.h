#ifndef SUSANIN_WEB_H
#define SUSANIN_WEB_H

#include "config.h"

/* Встроенная веб-панель (W1): мини-HTTP-сервер в самом агенте.
 * Слушает только LAN-адрес, отдаёт статику из SUSANIN_WWW_ROOT и /api/status.
 * Возврат: 0 — ок (или Web выключен), иначе код ошибки. */
int web_run(const susanin_config *cfg);

#endif
