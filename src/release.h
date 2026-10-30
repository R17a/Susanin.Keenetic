#ifndef SUSANIN_RELEASE_H
#define SUSANIN_RELEASE_H

#include "config.h"

#include <stddef.h>
#include <time.h>

#define RELEASE_TAG_MAX 32
#define RELEASE_URL_MAX 256

/* Последний известный релиз GitHub. tag хранится без префикса «v»:
 * «0.4.2» — так его удобно сравнивать с SUSANIN_VERSION и отдавать в UI. */
typedef struct {
    char tag[RELEASE_TAG_MAX];
    char url[RELEASE_URL_MAX];
    time_t checked;
} release_info;

/* Загрузить кэш /opt/susanin/var/release.state (сеть не трогает). */
void release_init(const susanin_config *c);

/* Проверить GitHub, если кэш устарел. 0 — данные есть/обновлены,
 * -1 — проверка выключена или не удалась. */
int release_check_now(const susanin_config *c);

/* Текущее состояние (всегда валидный указатель, поля могут быть пустыми). */
const release_info *release_get(void);

/* Сравнение версий: <0 — a старее b, 0 — равны, >0 — a новее b.
 * Суффиксы -devN/.RCN/alpha/beta считаются СТАРШЕ того же релиза. */
int release_version_cmp(const char *a, const char *b);

/* Есть ли в известном релизе версия новее current. */
int release_update_available(const char *current);

/* Разбор ответа GitHub API (вынесен наружу ради host-теста). */
int release_parse_payload(const char *json, char *tag, size_t tagsz,
                          char *url, size_t urlsz);

#endif
