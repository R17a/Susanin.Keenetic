#ifndef SUSANIN_STATE_H
#define SUSANIN_STATE_H

#include <time.h>

typedef struct {
    char addr[64];
    time_t expire;
} state_entry;

typedef struct {
    state_entry *v;
    int n;
    int cap;
} state_set;

typedef struct {
    state_set test_tcp, ok_tcp, watch_tcp, cooldown_tcp;
    state_set test_udp, ok_udp, watch_udp, cooldown_udp;
    /* Не привязаны к протоколу: префиксы susanin_ok_net, «мягко-прямо»
     * susanin_direct и пины dns_sniff в susanin_never. Без персиста теряются
     * при re-provision/fail-open. */
    state_set net, direct, never;
} susanin_state;

void state_init(susanin_state *s);
void state_free(susanin_state *s);
void state_expire(state_set *st, time_t now);
int state_has(const state_set *st, const char *addr, time_t now);
int state_add(state_set *st, const char *addr, time_t now, int ttl, int refresh);
/* Создать запись или продлить существующую (см. пояснение в state.c). */
int state_touch(state_set *st, const char *addr, time_t now, int ttl);
int state_remove(state_set *st, const char *addr);
time_t state_at(const state_set *st, const char *addr, time_t now);

/* Ключ записи состояния: port<=0 — обычный адрес ("1.2.3.4"), port>0 — пара
 * ("1.2.3.4:443"). Используется в port-aware режиме (ключ ip:port); в обычном
 * режиме вызывается с port=0, и поведение прежнее. Строка адреса должна быть
 * не длиннее 58 символов (addr[64] в state_entry). */
void state_key(char *dst, size_t n, const char *addr, int port);
/* Обратное разложение ключа: "1.2.3.4:443" -> ip="1.2.3.4", *port=443; ключ без
 * порта -> ip=ключ, *port=0. Нужно тем, кто получает ключ из состояния и должен
 * обратиться к ipset (там пара записывается через запятую). */
void state_key_split(const char *key, char *ip, size_t ipn, int *port);

/* Persistence: persist test/ok/cooldown entries across daemon restarts. */
int state_save(const char *path, const susanin_state *s);
int state_load(const char *path, susanin_state *s);

#define st_test(st, udp) ((udp) ? &(st)->test_udp : &(st)->test_tcp)
#define st_ok(st, udp)   ((udp) ? &(st)->ok_udp   : &(st)->ok_tcp)
#define st_watch(st, udp)((udp) ? &(st)->watch_udp: &(st)->watch_tcp)
#define st_cool(st, udp) ((udp) ? &(st)->cooldown_udp : &(st)->cooldown_tcp)

#endif
