#ifndef SUSANIN_BACKEND_H
#define SUSANIN_BACKEND_H

#include "config.h"
#include "conntrack.h"
#include <stddef.h>
#include <time.h>

int backend_provision(const susanin_config *c);
int backend_teardown(const susanin_config *c);
int backend_ready(const susanin_config *c);

/* Отметка о ре-провижене датаплейна (NDM снёс наши правила — агент их вернул).
 * Пишет /opt/susanin/var/dp-reprov ("epoch reason"); читается в status/diagnose. */
void backend_mark_reprov(const char *reason);
int backend_read_reprov(long *when, char *reason, size_t reasonsz);

/* Слушает ли кто-нибудь TCP-порт на локальном адресе (для tproxy — Xray).
 * 1 = слушает (или проверить нельзя), 0 = нет. */
int backend_local_listen(int port);

/* Environment check for the data plane (tools + egress interface). Returns 0
 * or -1 with a reason in err. */
int backend_preflight(const susanin_config *c, char *err, size_t errsz);

/* Failover: switch the VPN table default route to another egress interface. */
int backend_set_egress(const susanin_config *c, const char *iface);
/* Drop conntrack entries carrying the VPN mark (after an egress switch). */
int backend_ct_flush_vpn(const susanin_config *c);
/* Drop conntrack entries to a single IP (after vpn_never pin changes). */
int backend_ct_flush_ip(const char *ip);
int backend_ipset_add(const susanin_config *c, int proto_udp, int phase_ok,
                      const char *ip, int ttl);
int backend_ipset_del(const susanin_config *c, int proto_udp, int phase_ok,
                      const char *ip);

/* Port-aware варианты (этап 3): при c->port_aware=1 и port>0 значение для ipset
 * формируется как "ip,port" (наборы hash:ip,port); иначе — обычный "ip".
 * Старые функции выше — обёртки с port=0 (поведение не меняется). */
int backend_ipset_add_port(const susanin_config *c, int proto_udp, int phase_ok,
                           const char *ip, int port, int ttl);
int backend_ipset_del_port(const susanin_config *c, int proto_udp, int phase_ok,
                           const char *ip, int port);
/* Значение элемента набора для ipset ("ip" или "ip,port"). Чистая функция —
 * вынесена наружу, чтобы её можно было покрыть host-тестом. */
void backend_ipset_value(const susanin_config *c, const char *ip, int port,
                         int proto_udp, char *out, size_t n);

/* Пины ПО АДРЕСУ (vpn_always, dns_sniff, снятие по vpn_never): в обычном режиме
 * это оба ok-набора (tcp/udp), в port-aware — адресный susanin_ok_net, который
 * матчится по dst (адрес целиком, без порта). Так пины продолжают работать,
 * когда ok/test стали парами hash:ip,port. */
int backend_ok_pin_add(const susanin_config *c, const char *ip, int ttl);
int backend_ok_pin_del(const susanin_config *c, const char *ip);

/* Наш ли это Xray по командной строке (argv, элементы разделены пробелами):
 * должны присутствовать И "xray", И "run", И путь к нашему конфигу.
 * Строгая проверка нужна, чтобы `vi xray-tproxy.json` или `grep -q <путь>` не
 * считались процессом Xray. Вынесено из engine.c ради host-теста. */
int backend_is_our_xray_cmdline(const char *cmdline);
int backend_ipset_flush(const susanin_config *c);

/* Forced CIDR ranges (vpn_always): hash:net susanin_ok_net, timeout ttl. */
int backend_net_add(const susanin_config *c, const char *cidr, int ttl);
int backend_net_del(const susanin_config *c, const char *cidr);

/* Generic named ipset entry ops (e.g. susanin_never). */
int backend_set_add(const susanin_config *c, const char *set, const char *val,
                    int ttl);
int backend_set_del(const susanin_config *c, const char *set, const char *val);
/* 0 = значение присутствует в наборе, !=0 — нет/ошибка. */
int backend_set_test(const susanin_config *c, const char *set, const char *val);
int backend_ct_delete(const ct_flow *f);

#endif
