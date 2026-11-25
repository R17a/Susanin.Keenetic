/* ay_transport_stub.c — заглушка закрытого транспорта AY.
 *
 * Используется, когда при сборке не передан AY_SRC с исходниками
 * Susanin.Keenetic.AY. Агент собирается и работает как обычно, но
 * egress_type=ay подключить нельзя: панель и журнал сообщают, что транспорт
 * не входит в эту сборку.
 */
#include "ay_transport.h"

int ay_transport_available(void)
{
    return 0;
}

int ay_transport_init(ay_ctx *c, const char *secret, uint32_t inner_ip, uint16_t mtu)
{
    (void)c;
    (void)secret;
    (void)inner_ip;
    (void)mtu;
    return AY_ERR_UNAVAILABLE;
}

int ay_transport_restart(ay_ctx *c)
{
    (void)c;
    return AY_ERR_UNAVAILABLE;
}

int ay_transport_hello(ay_ctx *c, unsigned char *out, size_t cap, size_t *out_len)
{
    (void)c;
    (void)out;
    (void)cap;
    (void)out_len;
    return AY_ERR_UNAVAILABLE;
}

int ay_transport_accept_ack(ay_ctx *c, const unsigned char *payload, size_t len)
{
    (void)c;
    (void)payload;
    (void)len;
    return AY_ERR_UNAVAILABLE;
}

int ay_transport_open(ay_ctx *c, const unsigned char *dgram, size_t dlen,
                      unsigned char *plain, size_t pcap, int *msg,
                      size_t *payload_off, size_t *payload_len)
{
    (void)c;
    (void)dgram;
    (void)dlen;
    (void)plain;
    (void)pcap;
    (void)msg;
    (void)payload_off;
    (void)payload_len;
    return AY_ERR_UNAVAILABLE;
}

int ay_transport_seal_ip(ay_ctx *c, const unsigned char *ip, size_t ip_len,
                         unsigned char *out, size_t cap, size_t *out_len)
{
    (void)c;
    (void)ip;
    (void)ip_len;
    (void)out;
    (void)cap;
    (void)out_len;
    return AY_ERR_UNAVAILABLE;
}

int ay_transport_seal_ping(ay_ctx *c, unsigned char *out, size_t cap, size_t *out_len)
{
    (void)c;
    (void)out;
    (void)cap;
    (void)out_len;
    return AY_ERR_UNAVAILABLE;
}

int ay_transport_connected(const ay_ctx *c)
{
    (void)c;
    return 0;
}

uint16_t ay_transport_mtu(const ay_ctx *c)
{
    (void)c;
    return 0;
}

uint32_t ay_transport_session_id(const ay_ctx *c)
{
    (void)c;
    return 0;
}

void ay_transport_stats(const ay_ctx *c, uint64_t *tx_dgrams, uint64_t *rx_dgrams,
                        uint64_t *tx_bytes, uint64_t *rx_bytes)
{
    (void)c;
    if (tx_dgrams) *tx_dgrams = 0;
    if (rx_dgrams) *rx_dgrams = 0;
    if (tx_bytes)  *tx_bytes = 0;
    if (rx_bytes)  *rx_bytes = 0;
}
