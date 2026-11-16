/* Тесты пресета precision (apply_precision через config_load).
 * Хост-компилятор: make test. */
#define _GNU_SOURCE
#include "config.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int failures = 0;
#define CHECK(cond, msg) do { if (cond) printf("ok  %s\n", msg); \
    else { printf("FAIL %s\n", msg); failures++; } } while (0)

static const char *write_cfg(const char *text)
{
    static const char *path = "/tmp/susanin-test.conf";
    FILE *f = fopen(path, "wb");
    assert(f);
    fputs(text, f);
    fclose(f);
    return path;
}

int main(void)
{
    susanin_config cfg;

    printf("=== precision=strict (значения по умолчанию) ===\n");
    config_load(write_cfg("precision=strict\n"), &cfg);
    CHECK(cfg.fast_syn_min_op == 3, "fast_syn_min_op=3");
    CHECK(cfg.ok_evict_misses == 5, "ok_evict_misses=5");
    CHECK(cfg.learn_min_op == 14, "learn_min_op=14");
    CHECK(cfg.learn_min_bytes == 3000, "learn_min_bytes=3000");
    CHECK(cfg.confirm_min_bytes == 1024, "confirm_min_bytes=1024");
    CHECK(cfg.learn_strict == 0, "learn_strict не меняется пресетом");

    printf("=== precision=aggressive ===\n");
    config_load(write_cfg("precision=aggressive\n"), &cfg);
    CHECK(cfg.fast_syn_min_op == 1, "fast_syn_min_op=1");
    CHECK(cfg.ok_evict_misses == 2, "ok_evict_misses=2");
    CHECK(cfg.confirm_min_bytes == 256, "confirm_min_bytes=256");

    printf("=== явный ключ сильнее пресета ===\n");
    config_load(write_cfg("precision=aggressive\nlearn_min_op=20\n"), &cfg);
    CHECK(cfg.learn_min_op == 20, "явный learn_min_op=20 сохранён");
    CHECK(cfg.fast_syn_min_op == 1, "остальные пороги из пресета");

    printf("=== normal/пусто/неизвестный ===\n");
    config_load(write_cfg("precision=normal\n"), &cfg);
    CHECK(cfg.fast_syn_min_op == 2, "normal: значения по умолчанию");
    config_load(write_cfg("precision=\n"), &cfg);
    CHECK(cfg.confirm_min_bytes == 512, "пустой пресет: значения по умолчанию");
    config_load(write_cfg("precision=strong\n"), &cfg);
    CHECK(cfg.fast_syn_min_op == 2 && cfg.confirm_min_bytes == 512,
          "неизвестный пресет игнорируется (и пишет warning в stderr)");

    printf("=== W6: release_check ===\n");
    config_load(write_cfg(""), &cfg);
    CHECK(cfg.release_check == 1, "по умолчанию проверка релизов включена");
    CHECK(cfg.release_check_interval == 43200, "по умолчанию интервал 12 ч");
    config_load(write_cfg("release_check=0\nrelease_check_interval=3600\n"), &cfg);
    CHECK(cfg.release_check == 0, "release_check=0 разобран");
    CHECK(cfg.release_check_interval == 3600, "release_check_interval=3600 разобран");

    printf("=== config_validate ===\n");
    {
        char prob[2048];
        int n;

        /* Дефолтный конфиг обязан проходить проверку: иначе инструмент
         * шумит с первого запуска, и его перестают читать. */
        config_set_defaults(&cfg);
        n = config_validate(&cfg, prob, sizeof(prob));
        CHECK(n == 0, "конфиг по умолчанию — без замечаний");
        if (n)
            printf("     (лишнее: %s)", prob);

        config_load(write_cfg("media_min_bytes=-1\n"), &cfg);
        CHECK(config_validate(&cfg, prob, sizeof(prob)) > 0 &&
              strstr(prob, "media_min_bytes") != NULL,
              "отрицательный media_min_bytes помечен (в коде станет гигантским)");

        config_load(write_cfg("mark_mask=0\n"), &cfg);
        CHECK(config_validate(&cfg, prob, sizeof(prob)) > 0 &&
              strstr(prob, "mark_mask") != NULL,
              "mark_mask=0 помечен (метрики неразличимы)");

        config_load(write_cfg("mark_test=0x10000000\nmark_ok=0x10000000\n"), &cfg);
        CHECK(config_validate(&cfg, prob, sizeof(prob)) > 0 &&
              strstr(prob, "mark_test == mark_ok") != NULL,
              "одинаковые test/ok помечены");

        config_load(write_cfg("routing_table=255\n"), &cfg);
        CHECK(config_validate(&cfg, prob, sizeof(prob)) > 0 &&
              strstr(prob, "routing_table") != NULL,
              "routing_table=255 помечен (зарезервирован ядром)");

        config_load(write_cfg("synfail_quorum=16\n"), &cfg);
        CHECK(config_validate(&cfg, prob, sizeof(prob)) > 0 &&
              strstr(prob, "клампим") != NULL,
              "synfail_quorum выше кольца помечен с указанием предела");
        config_load(write_cfg("synfail_quorum=8\n"), &cfg);
        CHECK(config_validate(&cfg, prob, sizeof(prob)) == 0,
              "synfail_quorum=8 (равен кольцу) — не замечание");

        /* Сенсоры «0 = выключено / 0 = никогда» не считаются ошибкой — иначе
         * проверка превращается в шум, который оператор глушит. */
        config_load(write_cfg(
            "ok_ttl=0\npromo_per_min=0\nsoft_state_interval=0\n"
            "media_enabled=0\nmedia_prefix_max=99\n"
            "udp_relay=0\nudp_relay_port=0\nsocks_port=0\n"
            "web_enable=0\nweb_port=0\nhealth_mode=icmp\nhealth_tcp_port=0\n"
            "dns_sniff=0\ndns_sniff_ttl=0\nkernel_offload=0\nkernel_offload_max=1\n"
            "cdn_prefix_learn=0\ncdn_prefix_max=0\n"
            "frozen_net_enabled=0\nfrozen_net_prefix=99\n"
            "test_net_enabled=0\ntest_net_prefix=99\ntest_net_window=0\n"), &cfg);
        n = config_validate(&cfg, prob, sizeof(prob));
        CHECK(n == 0, "выключенные механизмы с нулевыми/безумными значениями — не замечания");
        if (n)
            printf("     (ложное: %s)", prob);

        /* Отрицательное значение порога всегда замечание, а не сенсор. */
        config_load(write_cfg("fast_interval=0\n"), &cfg);
        CHECK(config_validate(&cfg, prob, sizeof(prob)) > 0,
              "fast_interval=0 помечен (полный скан каждый проход)");

        /* Семантика нуля закрепляется тестом. Причина: 0 в этом конфиге значит
         * ТРИ разные вещи — «выключено», «никогда» и «взять действующий
         * default», — и для каждого ключа это решается в месте потребления.
         * Угадать нельзя, поэтому проверяем обе стороны списка, а не одно
         * общее правило. */
        {
            static const char *zero_ok[] = {
                "synfail_window=0\n",
                "test_net_enabled=1\ntest_net_window=0\n",
                "test_net_enabled=1\ntest_net_ttl=0\n",
                "dns_sniff=1\ndns_sniff_ttl=0\n",
                "vpn_always_interval=0\n",
                "vpn_never_interval=0\n",
                "dp_check_interval=0\n",
                "web_enable=1\nweb_port=0\n",
                "udp_relay=1\nsocks_port=0\n",
                "health_mode=tcp\nhealth_tcp_port=0\n",
                "soft_state_interval=0\n",
                "ok_ttl=0\n",
                "promo_per_min=0\n",
                NULL
            };
            static const char *zero_bad[] = {
                "fast_interval=0\n",
                "soft_interval=0\n",
                "judge_interval=0\n",
                "health_interval=0\n",
                "egress_type=tproxy\ntproxy_port=0\n",
                "udp_relay=1\nudp_relay_port=0\n",
                NULL
            };
            /* Те же ключи, что выше в zero_ok, но с отрицательным значением:
             * ноль законен, минус — нет. */
            static const char *neg_bad[] = {
                "synfail_window=-1\n",
                "test_net_enabled=1\ntest_net_window=-1\n",
                "dns_sniff=1\ndns_sniff_ttl=-1\n",
                "vpn_always_interval=-1\n",
                "vpn_never_interval=-1\n",
                "dp_check_interval=-1\n",
                "web_enable=1\nweb_port=-1\n",
                "health_mode=tcp\nhealth_tcp_port=-1\n",
                "udp_relay=1\nsocks_port=-1\n",
                NULL
            };
            int z;
            char msg[192];

            for (z = 0; zero_ok[z]; z++) {
                int got;
                config_load(write_cfg(zero_ok[z]), &cfg);
                got = config_validate(&cfg, prob, sizeof(prob));
                snprintf(msg, sizeof(msg), "законный ноль: %.60s", zero_ok[z]);
                CHECK(got == 0, msg);
                if (got)
                    printf("     (замечание: %s)", prob);
            }
            for (z = 0; zero_bad[z]; z++) {
                config_load(write_cfg(zero_bad[z]), &cfg);
                snprintf(msg, sizeof(msg), "ноль ломает поведение: %.60s", zero_bad[z]);
                CHECK(config_validate(&cfg, prob, sizeof(prob)) > 0, msg);
            }
            for (z = 0; neg_bad[z]; z++) {
                config_load(write_cfg(neg_bad[z]), &cfg);
                snprintf(msg, sizeof(msg), "отрицательное значение помечено: %.60s",
                         neg_bad[z]);
                CHECK(config_validate(&cfg, prob, sizeof(prob)) > 0, msg);
            }
        }

        /* Малый буфер: число проблем возвращается, текст не вылезает за границу. */
        {
            char tiny[32];
            config_load(write_cfg("mark_mask=0\nrouting_table=0\nfast_interval=0\n"), &cfg);
            n = config_validate(&cfg, tiny, sizeof(tiny));
            CHECK(n >= 3, "при малом буфере число проблем не теряется");
            CHECK(strlen(tiny) < sizeof(tiny), "вывод не переполнил буфер");
        }
    }

    remove("/tmp/susanin-test.conf");
    printf("\n%s\n", failures ? "ЕСТЬ ОШИБКИ" : "все проверки пройдены");
    return failures ? 1 : 0;
}
