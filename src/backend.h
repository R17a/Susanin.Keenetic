#ifndef SUSANIN_BACKEND_H
#define SUSANIN_BACKEND_H

#include "config.h"
#include "conntrack.h"
#include <time.h>

int backend_provision(const susanin_config *c);
int backend_teardown(const susanin_config *c);
int backend_ready(const susanin_config *c);
int backend_ipset_add(const susanin_config *c, int proto_udp, int phase_ok,
                      const char *ip, int ttl);
int backend_ipset_del(const susanin_config *c, int proto_udp, int phase_ok,
                      const char *ip);
int backend_ipset_flush(const susanin_config *c);
int backend_ct_delete(const ct_flow *f);

#endif
