#ifndef SUSANIN_CDN_H
#define SUSANIN_CDN_H

#include "config.h"
#include <stddef.h>

/* C1/C2: диапазоны CDN (Cloudflare и т.п.) как данные.
 * Файл cdn_ranges_file — по одной сети в строке (a.b.c.d/len, # — комментарий).
 * Обновляется через cdn_ranges_url (wget/curl), если задан. */

/* Загрузить диапазоны из файла. Возвращает число сетей (0 — нет/пусто). */
int cdn_load(const susanin_config *c);

/* Если ip попадает в диапазон CDN — записать канонический CIDR в out и вернуть
 * 1. Префикс не шире cdn_prefix_max (защита от «завернуть весь /13 CDN»: по
 * умолчанию агрегируем /24 вокруг адреса). 0 — не CDN. */
int cdn_match(const susanin_config *c, const char *ip, char *out, size_t outsz);

/* Обновить файл диапазонов с cdn_ranges_url. 0 = успех (файл заменён и
 * перечитан), -1 = не удалось (старый файл остаётся в силе). */
int cdn_refresh(const susanin_config *c);

/* Сколько сетей загружено (для status/diagnose). */
int cdn_count(void);

#endif
