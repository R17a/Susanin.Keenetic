/* Тесты логики 0.4.0.RC1:
 *  - media_quorum(): агрегировать «медиа» можно только после media_min_age и
 *    при скорости не ниже media_min_rate. Раньше пороги были объявлены, но не
 *    проверялись, и обычная загрузка страницы уводила в VPN всю /24 хостинга
 *    (общий /24 провайдера);
 *  - clf_ip_in_cidr(): по нему reset/forget снимает покрывающий префикс из
 *    susanin_ok_net (иначе «removed=0» и сайт остаётся в VPN).
 *
 * classifier.c включается в TU, чтобы дотянуться до static media_quorum().
 * Запуск: make test (хост-компилятор; в кросс-сборку не входит).
 */
#define _GNU_SOURCE
#include "classifier.c"
#include "classifier.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(cond, msg) do { if (cond) printf("ok  %s\n", msg); \
    else { printf("FAIL %s\n", msg); failures++; } } while (0)

static void mkflow(ct_flow *f, const char *dst, unsigned dport, unsigned long rb)
{
    memset(f, 0, sizeof(*f));
    snprintf(f->proto, sizeof(f->proto), "%s", "tcp");
    snprintf(f->src, sizeof(f->src), "%s", "192.168.1.50");
    snprintf(f->dst, sizeof(f->dst), "%s", dst);
    f->sport = 40000;
    f->dport = dport;
    f->l4proto = 6;
    f->rb = rb;
    f->ob = 1000;
}

int main(void)
{
    susanin_config cfg;
    ct_flow f;
    time_t t0 = 1000000;

    config_set_defaults(&cfg);

    printf("=== clf_ip_in_cidr ===\n");
    CHECK(clf_ip_in_cidr("194.67.72.31", "194.67.72.0/24") == 1, "адрес внутри /24");
    CHECK(clf_ip_in_cidr("194.67.73.31", "194.67.72.0/24") == 0, "адрес вне /24");
    CHECK(clf_ip_in_cidr("10.0.0.5", "0.0.0.0/0") == 1, "0.0.0.0/0 покрывает всё");
    CHECK(clf_ip_in_cidr("10.0.0.5", "10.0.0.5") == 0, "без префикса — не CIDR");
    CHECK(clf_ip_in_cidr("10.0.0.5", "мусор/24") == 0, "битый CIDR — не совпадает");

    printf("=== media_quorum: пороги выключены ===\n");
    cfg.media_min_age = 0;
    cfg.media_min_rate = 0;
    mkflow(&f, "203.0.113.10", 554, 1000000);
    CHECK(media_quorum(&cfg, &f, t0) == 1, "без порогов агрегация разрешена сразу");

    printf("=== media_quorum: возраст потока ===\n");
    cfg.media_min_age = 12;
    cfg.media_min_rate = 0;
    mkflow(&f, "203.0.113.11", 554, 1000000);
    CHECK(media_quorum(&cfg, &f, t0) == 0, "первый сэмпл — только кандидат");
    CHECK(media_quorum(&cfg, &f, t0 + 5) == 0, "5 с < media_min_age=12");
    CHECK(media_quorum(&cfg, &f, t0 + 13) == 1, "13 с >= media_min_age — можно");

    printf("=== media_quorum: скорость потока ===\n");
    cfg.media_min_age = 0;
    cfg.media_min_rate = 150000;
    mkflow(&f, "203.0.113.12", 554, 1000000);
    CHECK(media_quorum(&cfg, &f, t0) == 0, "первый сэмпл — только кандидат");
    CHECK(media_quorum(&cfg, &f, t0 + 4) == 0, "25 КБ/с < media_min_rate");
    f.rb += 800000;                       /* +800 КБ за 4 с = 200 КБ/с */
    CHECK(media_quorum(&cfg, &f, t0 + 8) == 1, "200 КБ/с >= media_min_rate");

    printf("=== media_quorum: возраст и скорость вместе ===\n");
    cfg.media_min_age = 3;
    cfg.media_min_rate = 1000;
    mkflow(&f, "203.0.113.13", 554, 5000);
    CHECK(media_quorum(&cfg, &f, t0) == 0, "кандидат");
    f.rb += 5000;
    CHECK(media_quorum(&cfg, &f, t0 + 4) == 1, "возраст и скорость подтверждены");

    printf("=== media_ports по умолчанию: без 80/443 ===\n");
    {
        susanin_config d;
        config_set_defaults(&d);
        CHECK(media_port(&d, 554) == 1, "554 (RTSP/IPTV) остаётся медиа-портом");
        CHECK(media_port(&d, 80) == 0, "80 больше не считается медиа");
        CHECK(media_port(&d, 443) == 0, "443 больше не считается медиа");
    }

    printf("\n%s (%d fail)\n", failures ? "FAILED" : "ALL OK", failures);
    return failures ? 1 : 0;
}
