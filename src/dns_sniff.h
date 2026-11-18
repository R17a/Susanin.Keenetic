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
/* Сводка счётчиков пути «кадр -> запись» (см. dns_sniff.c): строка описывает
 * каждый шаг разбора (frames/udp53/queries/answers/parse_fail/stored/capped
 * + SNI), чтобы по ней было видно, ГДЕ именно всё умирает, а не только то,
 * что «до таблицы не доходит». */
int  dns_sniff_stats(char *out, size_t n);

/* Сокетов захвата — по одному на интерфейс из lan_interfaces (br0, br1, oc+). */
#define DNS_SNIFF_MAX_IFACES 8

/* Структурный срез тех же счётчиков — для решений (WARN-диагностика в
 * движке). Сводку выше разбирать по подстрокам нельзя: она для чтения
 * человеком, и формат — не контракт. */
typedef struct {
    unsigned long frames, udp53, queries, answers, parse_fail, stored, capped;
    int niface;                            /* сколько сокетов захвата открыто */
    char name[DNS_SNIFF_MAX_IFACES][16];   /* имя интерфейса слота ('' — нет) */
    unsigned long iface_queries[DNS_SNIFF_MAX_IFACES];
    unsigned long iface_answers[DNS_SNIFF_MAX_IFACES];
} dns_sniff_counters;
void dns_sniff_get_counters(dns_sniff_counters *c);
/* 1 = нашли домен для IP; domain_out заполняется (может быть ""). */
int  dns_sniff_domain_of(const char *ip, char *domain_out, unsigned n);

#define DNS_DOMAIN_MAX 128

/* Файл-снимок счётчиков снифинга: движок пишет, панель и CLI читают. Нужен
 * именно файл, потому что счётчики живут в памяти движка, а `status`/`why` —
 * отдельные процессы. В disk_mode=soft носитель не трогаем, поэтому снимок
 * уходит в tmpfs: журнала в soft нет, и это единственный канал наблюдаемости,
 * но и повода писать на флешку у него быть не должно. */
#define DNS_SNIFF_STATS_FILE "/opt/susanin/var/dnssniff.state"
#define DNS_SNIFF_SOFT_STATS_FILE "/tmp/susanin-dnssniff.state"

/* Путь снимка для текущего режима носителя (см. выше). */
const char *dns_sniff_stats_path(const susanin_config *cfg);

/* Записать снимок (см. dns_sniff.c). */
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
