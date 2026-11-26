/* ay_transport.h — интерфейс закрытого транспорта AY.
 *
 * Реализация намеренно НЕ входит в публичное дерево Susanin.Keenetic:
 * исходники лежат в проекте Susanin.Keenetic.AY и подключаются при сборке
 * через AY_SRC (см. devtools/wsl-build.sh). Без них собирается заглушка
 * (src/ay_transport_stub.c), и egress_type=ay недоступен.
 *
 * Контекст непрозрачен: вызывающий код не знает ни раскладки пакета, ни
 * ключей. Всё состояние сессии (счётчики, окно повторов, ключ) — внутри.
 */
#ifndef SUSANIN_AY_TRANSPORT_H
#define SUSANIN_AY_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

#define AY_TRANSPORT_ABI   1
#define AY_CTX_SIZE      512   /* размер непрозрачного контекста, байт */
#define AY_MAX_DGRAM    1280   /* максимум датаграммы транспорта          */
#define AY_MAX_IP       1212   /* максимум вложенного IPv4-пакета         */

/* Типы входящих сообщений (возвращает ay_transport_open). */
#define AY_MSG_IP          1
#define AY_MSG_PING        2
#define AY_MSG_PONG        3
#define AY_MSG_HELLO_ACK   5

/* Коды возврата. */
#define AY_OK              0
#define AY_ERR_ARG        (-1)  /* неверный аргумент                       */
#define AY_ERR_UNAVAILABLE (-2) /* закрытый транспорт не собран            */
#define AY_ERR_SECRET     (-3)  /* секрет пуст/не разбирается              */
#define AY_ERR_FRAME      (-4)  /* не наш формат/чужой идентификатор/метка  */
#define AY_ERR_AUTH       (-5)  /* не сошёлся тег                          */
#define AY_ERR_SIZE       (-6)  /* размер вне габаритов                    */
#define AY_ERR_STATE      (-7)  /* действие невозможно в этом состоянии    */

/* Выравнивание: контекст приводится к внутренней структуре, поэтому
 * объединение с uint64_t обязательно. */
typedef union {
    unsigned char      raw[AY_CTX_SIZE];
    unsigned long long align;
} ay_ctx;

#ifdef __cplusplus
extern "C" {
#endif

/* 1 — настоящий транспорт собран, 0 — заглушка. */
int ay_transport_available(void);

/* Разобрать секрет (64 hex или парольная фраза), запомнить внутренний адрес
 * (в СЕТЕВОМ порядке байт, как htonl/INADDR) и MTU, но сессию ещё не
 * начинать. 0 или AY_ERR_*. */
int ay_transport_init(ay_ctx *c, const char *secret, uint32_t inner_ip, uint16_t mtu);

/* Новая попытка установления сессии: новый идентификатор, новая база времени,
 * новый ключ; окно приёма и счётчики направления сбрасываются. */
int ay_transport_restart(ay_ctx *c);

/* Первый пакет сессии (запрос). Пишет датаграмму в out. */
int ay_transport_hello(ay_ctx *c, unsigned char *out, size_t cap, size_t *out_len);

/* Проверить и принять подтверждение сессии (payload из ay_transport_open). */
int ay_transport_accept_ack(ay_ctx *c, const unsigned char *payload, size_t len);

/* Разобрать входящую датаграмму: проверка формата, окно повторов,
 * аутентификация и расшифровка в plain (буфер вызывающего).
 * payload_off/payload_len — полезная нагрузка внутри plain. */
int ay_transport_open(ay_ctx *c, const unsigned char *dgram, size_t dlen,
                      unsigned char *plain, size_t pcap, int *msg,
                      size_t *payload_off, size_t *payload_len);

/* Зашифровать исходящий IPv4-пакет (ip_len <= AY_MAX_IP). */
int ay_transport_seal_ip(ay_ctx *c, const unsigned char *ip, size_t ip_len,
                         unsigned char *out, size_t cap, size_t *out_len);

/* Зашифровать keepalive (в ответ сервер пришлёт AY_MSG_PONG). */
int ay_transport_seal_ping(ay_ctx *c, unsigned char *out, size_t cap,
                           size_t *out_len);

/* 1 — подтверждение сессии получено и ключ работает. */
int ay_transport_connected(const ay_ctx *c);

/* Согласованный MTU (после ACK — серверный, иначе свой). 0 — нет сессии. */
uint16_t ay_transport_mtu(const ay_ctx *c);

/* Идентификатор сессии — только для журнала/статуса. 0, если не начата. */
uint32_t ay_transport_session_id(const ay_ctx *c);

/* Счётчики (могут быть NULL). */
void ay_transport_stats(const ay_ctx *c, uint64_t *tx_dgrams, uint64_t *rx_dgrams,
                        uint64_t *tx_bytes, uint64_t *rx_bytes);

#ifdef __cplusplus
}
#endif

#endif /* SUSANIN_AY_TRANSPORT_H */
