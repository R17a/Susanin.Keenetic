#ifndef SUSANIN_HEALTH_H
#define SUSANIN_HEALTH_H

#include "config.h"

/* Returns 0 on success. *ok = number of probes that got a reply, *total = sent. */
int health_probe(const susanin_config *c, int *ok, int *total);

#endif
