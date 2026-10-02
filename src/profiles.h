#ifndef SUSANIN_PROFILES_H
#define SUSANIN_PROFILES_H

#include "config.h"

/*
 * P2: профили маршрутизации — слой автообучения.
 *
 * Профиль (profileN_*) задаёт свой набор susanin_prof_<name>: адреса из
 * list/CIDR. Если у профиля profileN_auto=1, то при подтверждении адреса
 * классификатором (CONFIRMED) адрес, попадающий в диапазон профиля,
 * дополнительно пинится в набор профиля — так выученный адрес уходит в
 * туннель профиля, а не в общий.
 */
void profile_auto_learn(const susanin_config *cfg, const char *ip);

#endif
