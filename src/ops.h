#ifndef SUSANIN_OPS_H
#define SUSANIN_OPS_H

#include "config.h"
#include <stddef.h>

int ops_setup(const susanin_config *cfg, const char *conf_path, int argc, char **argv);
int ops_status(const susanin_config *cfg, const char *conf_path);
int ops_apply(const susanin_config *cfg, const char *conf_path, int dry_run);
/* Сбросить адрес (IP или домен) из кэша/ipsets и conntrack — «забыть» для
 * повторного обучения. `forget <ip>` — синоним. */
int ops_reset(const susanin_config *cfg, const char *arg);
const char *ops_default_conf_path(void);

/* Read-only JSON snapshot for the built-in web panel (`/api/status`). */
int ops_status_json(const susanin_config *cfg, const char *conf_path, char *buf, size_t n);
/* Read-only JSON array of a list file's entries (comments/blank lines
 * skipped) for the web panel (`/api/list?name=vpn_always|vpn_never`). */
int ops_list_json(const susanin_config *cfg, const char *which, char *buf, size_t n);
/* JSON {"file":..,"params":{..},"token_set":bool} для веб-панели (`/api/config`).
 * Секрет web_token не отдаётся (значение пустое). */
int ops_config_json(const susanin_config *cfg, const char *conf_path, char *buf, size_t n);

#endif
