#ifndef SUSANIN_CLASSIFIER_H
#define SUSANIN_CLASSIFIER_H

#include "config.h"
#include "conntrack.h"
#include "state.h"
#include <time.h>

typedef struct {
    const susanin_config *cfg;
    susanin_state *st;
} classifier_ctx;

void clr_fast(classifier_ctx *ctx, const ct_flow *flows, int n, time_t now);
void clr_soft(classifier_ctx *ctx, const ct_flow *flows, int n, time_t now);
void clr_judge(classifier_ctx *ctx, const ct_flow *flows, int n, time_t now);

/* Чистые фильтры обучения (без форков) — нужны движку в sweep_direct(). */
int clf_service_port(unsigned port);
int clf_port_excluded(const susanin_config *cfg, unsigned port);
int clf_is_private_dst(const char *dst);
/* Бинарные варианты для горячего пути: берут готовый u32 из ct_flow
 * (src4/dst4; 0 = адрес не IPv4) и кэш lan_subnets — без строкового разбора
 * и inet_pton на каждый поток в каждом проходе. */
int clf_from_lan4(const susanin_config *cfg, uint32_t src4);
int clf_is_private4(uint32_t a);
/* 1 = адрес ip входит в cidr ("a.b.c.d/len"). Нужен reset/forget, чтобы снять
 * покрывающий префикс из susanin_ok_net (/24 оставался). */
int clf_ip_in_cidr(const char *ip, const char *cidr);

#endif
