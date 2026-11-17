#ifndef SUSANIN_DNS_SNIFF_H
#define SUSANIN_DNS_SNIFF_H

#include "config.h"
#include "state.h"

/*
 * DNS-снифинг (P3 / N1): зеркально слушаем DNS-ответы LAN (AF_PACKET на
 * LAN-интерфейсе) и запоминаем связь домен -> IP. Штатный DNS роутера при этом
 * НЕ перехватываем и не меняем — только подглядываем уже идущие ответы.
 *
 * Назначение:
 *  - контекст для наблюдаемости: «почему этот IP в VPN» (какому домену он
 *    принадлежит);
 *  - точное покрытие поддоменов доменов из vpn_always/vpn_never до их
 *    собственного резолва (IP из ответа пинится сразу).
 *
 * Оба ключа по умолчанию выключены: dns_sniff=0 и sni_sniff=0. SNI — второй
 * источник имени (из TLS ClientHello), но это самоутверждение клиента:
 * SNI-пара не получает бессрочных пинов, не снимает чужие решения и не рвёт
 * соединения (см. src/dns_sniff.c, ESRC_*). Контур обслуживания (reconcile,
 * сводка, снимок счётчиков) работает при любом включённом источнике.
 */

int  dns_sniff_start(const susanin_config *cfg);  /* 0 = ok, -1 = нет (лог) */
void dns_sniff_stop(void);
void dns_sniff_poll(void);                        /* забрать пакеты (nonblock) */

/* Применить значение dns_sniff из перечитанного конфига: start при включении,
 * stop при выключении. Без этого ключ, изменённый панелью, не действовал до
 * перезапуска службы, а статус показывал «dns_sniff=1». */
void dns_sniff_reload(const susanin_config *cfg);

/* Периодически пинит IP из снифинга, если домен попал в vpn_always/vpn_never. */
void dns_sniff_reconcile(const susanin_config *cfg);

/* Персист пинов: агент отдаёт своё state (пины переживают re-provision/рестарт). */
void dns_sniff_set_state(susanin_state *st);
/* Сбросить флаги «запинено» (после flush ipset'ов) — применятся заново. */
void dns_sniff_reset_pins(void);

int  dns_sniff_count(void);
/* Сводка счётчиков пути «кадр -> запись» (см. dns_sniff.c): без неё четыре
 * разных способа «не видеть домены» неразличимы. */
int  dns_sniff_stats(char *out, size_t n);
/* 1 = нашли домен для IP; domain_out заполняется (может быть ""). */
int  dns_sniff_domain_of(const char *ip, char *domain_out, unsigned n);

#define DNS_DOMAIN_MAX 128

/* Файл-снимок счётчиков снифинга: движок пишет, панель и CLI читают. Нужен
 * именно файл, потому что счётчики живут в памяти движка, а `status`/`why` —
 * отдельные процессы. */
#define DNS_SNIFF_STATS_FILE "/opt/susanin/var/dnssniff.state"

/* Записать снимок (см. dns_sniff.c): при disk_mode=soft не пишется. */
void dns_sniff_stats_write(const susanin_config *cfg);

/* r5.2: домен оканчивается на русский TLD из cfg->ru_guard_tlds
 * (регистронезависимо, punycode-варианты включаются в список). */
int  dns_sniff_is_ru_domain(const susanin_config *cfg, const char *dom);
/* 1, если домен записан в vpn_always с префиксом ? (мягкая запись). */
int  dns_sniff_is_soft_domain(const susanin_config *cfg, const char *dom);
/* Положить пару «домен -> IP» из внешнего источника (SNI). Возврат 1 =
 * запись попала в таблицу; источник помечается более слабым (ESRC_SNI). */
int  dns_sniff_note_name(const char *domain, const char *ip, int ttl);

/* r5.4: сколько RU-доменов сейчас сидит в VPN (ok_tcp) — пишет
 * /opt/susanin/var/ru-in-vpn для панели; вызывать из reconcile. */
void dns_sniff_ru_audit(const susanin_config *cfg);

#endif
