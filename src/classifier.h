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

#endif
