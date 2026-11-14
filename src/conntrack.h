#ifndef SUSANIN_CONNTRACK_H
#define SUSANIN_CONNTRACK_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    int l4proto;        /* 6=tcp, 17=udp, 1=icmp */
    char proto[8];      /* "tcp"/"udp"/"icmp" */
    char src[64];
    char dst[64];
    unsigned sport;
    unsigned dport;
    unsigned r_sport;
    unsigned r_dport;
    char tcp_state[16]; /* for tcp: SYN_SENT/ESTABLISHED/... */
    unsigned long op;   /* orig packets */
    unsigned long ob;   /* orig bytes */
    unsigned long rp;   /* reply packets */
    unsigned long rb;   /* reply bytes */
    unsigned long ctmark;
    int has_reply;      /* reply direction saw packets */
    int fastnat;        /* [FASTNAT]/offloaded */
    /* IPv4-адреса в host byte order (0 = адрес не IPv4): бинарные фильтры
     * LAN/приватные в горячем пути вместо inet_pton на каждый поток. */
    uint32_t src4;
    uint32_t dst4;
} ct_flow;

typedef int (*ct_cb)(void *ud, const ct_flow *f);

int conntrack_parse_line(const char *line, ct_flow *f);
/* То же, но разбирает буфер на месте (strtok_r разделяет его на токены) —
 * для conntrack_scan, который читает строки в собственный изменяемый буфер. */
int conntrack_parse_line_mut(char *buf, ct_flow *f);
int conntrack_scan(const char *path, ct_cb cb, void *ud);
/* Быстрый ручной разбор IPv4 dotted-quad (host order); 0 = не IPv4. */
uint32_t ct_parse4(const char *s);

#endif
