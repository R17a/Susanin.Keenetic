/* Тесты пресета precision (apply_precision через config_load).
 * Хост-компилятор: make test. */
#define _GNU_SOURCE
#include "config.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Имя уникально на процесс: два параллельных `make test` не должны писать в один файл. */
static char tmp_name[160];
static void tmp_init(const char *fmt)
{
    snprintf(tmp_name, sizeof(tmp_name), fmt, (int)getpid());
}
static const char *tmp_path(void) { return tmp_name; }

static int failures = 0;
#define CHECK(cond, msg) do { if (cond) printf("ok  %s\n", msg); \
    else { printf("FAIL %s\n", msg); failures++; } } while (0)

static const char *write_cfg(const char *text)
{
    FILE *f = fopen(tmp_path(), "wb");
    assert(f);
    fputs(text, f);
    fclose(f);
    return tmp_path();
}

int main(void)
{
    susanin_config cfg;

    tmp_init("/tmp/susanin-test-%d.conf");

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

    printf("=== разбор строки: «key = value» и границы списка отклонённого ===\n");
    {
        static const char *many[] = {
            "fast_interval", "soft_interval", "judge_interval", "health_interval",
            "dp_check_interval", "vpn_always_interval", "vpn_never_interval",
            "synfail_window", "synfail_quorum", "ok_ttl", "ok_refresh_below",
            "ok_max_entries", "ok_evict_misses", "promo_per_min", "test_ttl",
            "cooldown_ttl", "cooldown_ok_ttl", "watch_ttl", "watch_retry_below",
            "health_miss_debounce", "health_tcp_port"
        };
        char big[4096];
        char prob[8192];
        FILE *f;
        int i, sz, n;

        /* Значение в форме «ключ = значение» обязано примениться. Прежний
         * разбор включал пробел в имя ключа, строка молча игнорировалась, а
         * config_sync считал такой ключ присутствующим — то есть настройка
         * терялась навсегда, и даже дефолт не дописывался. */
        config_load(write_cfg("lan_interfaces = br0, br1\n"), &cfg);
        CHECK(!strcmp(cfg.lan_interfaces, "br0, br1"),
              "«lan_interfaces = br0, br1» применено");
        config_load(write_cfg("  tz = IST-8  \n"), &cfg);
        CHECK(!strcmp(cfg.tz, "IST-8"), "пробелы с обеих сторон применены");
        /* Комментарий не должен читаться как ключ. */
        config_load(write_cfg("#ok_ttl=1\nok_ttl=120\n"), &cfg);
        CHECK(cfg.ok_ttl == 120, "закомментированный ключ не применяется");

        /* Правка такой строки не должна плодить второй ключ. */
        write_cfg("web_port = 8087\n");
        if (config_file_set(tmp_path(), "web_port", "9999", 1) == 0) {
            int lines = 0;
            char ln[512];
            config_load(tmp_path(), &cfg);
            CHECK(cfg.web_port == 9999, "config set изменил «web_port = 8087»");
            f = fopen(tmp_path(), "r");
            if (f) {
                while (fgets(ln, sizeof(ln), f))
                    if (strstr(ln, "web_port"))
                        lines++;
                fclose(f);
            }
            CHECK(lines == 1, "и не создала вторую строку с тем же ключом");
        } else {
            CHECK(0, "config set над «web_port = 8087»");
        }

        /* Больше CFG_MAX_BAD_VALUES отрицательных ключей: список обязан
         * остаться в границах (раньше счётчик рос, и цикл дедупликации читал
         * за массивом), а потеря не должна стать невидимой. */
        big[0] = '\0';
        sz = (int)sizeof(many) / (int)sizeof(many[0]);
        for (i = 0; i < sz; i++) {
            char one[96];
            snprintf(one, sizeof(one), "%s=-1\n", many[i]);
            strncat(big, one, sizeof(big) - strlen(big) - 1);
        }
        strncat(big, "fast_interval=-1\n", sizeof(big) - strlen(big) - 1); /* повтор */
        config_load(write_cfg(big), &cfg);
        CHECK(cfg.n_bad_values == CFG_MAX_BAD_VALUES,
              "список отклонённых ключей не вырос за границу");
        /* Потерянных ровно «различных ключей минус места в списке»: повтор уже
         * запомненного имени не должен увеличивать счётчик даже тогда, когда
         * список полон (имя ищется по удержанной части списка). */
        CHECK(cfg.n_bad_dropped == sz - CFG_MAX_BAD_VALUES,
              "потерянные имена посчитаны, повтор запомненного — не повторно");
        n = config_validate(&cfg, prob, sizeof(prob));
        CHECK(n > CFG_MAX_BAD_VALUES,
              "проверка сообщает и про потерянные имена, а не только про влезшие");
    }

    printf("=== round-trip длительностей (config_save -> config_load) ===\n");
    {
        susanin_config a, b;
        char p2[200];

        snprintf(p2, sizeof(p2), "%s.rt", tmp_path());
        config_set_defaults(&a);
        /* Минутные ключи: значение меньше минуты не должно превращаться в 0 —
         * для TTL это «не истекает», то есть сохранение конфига молча меняло
         * бы смысл с «45 секунд» на «бессрочно». */
        a.test_ttl = 45;
        a.cooldown_ttl = 90;
        a.ok_refresh_below = 5400;         /* 1,5 ч */
        CHECK(config_save(p2, &a) == 0, "config_save прошёл");
        memset(&b, 0, sizeof(b));
        CHECK(config_load(p2, &b) == 0, "сохранённый конфиг читается");
        CHECK(b.test_ttl == 45, "test_ttl=45s пережил сохранение (не стал 0)");
        CHECK(b.cooldown_ttl == 90, "cooldown_ttl=90s пережил сохранение");
        CHECK(b.ok_refresh_below == 5400, "ok_refresh_below=1,5ч пережил сохранение");
        CHECK(b.media_min_bytes == a.media_min_bytes, "обычные ключи без потерь");
        remove(p2);
    }

    printf("=== разбор значения: мусор и переполнение ===\n");
    {
        char prob[4096];

        /* «abc» для числового ключа раньше означало 0 молча. */
        config_load(write_cfg("ok_ttl=abc\n"), &cfg);
        CHECK(cfg.ok_ttl == 0, "не разобранное значение стало 0");
        CHECK(cfg.n_bad_values == 1 && !strcmp(cfg.bad_values[0], "ok_ttl"),
              "и зарегистрировано как отклонённое (а не потеряно)");
        CHECK(config_validate(&cfg, prob, sizeof(prob)) > 0,
              "проверка конфига об этом сообщает");

        /* «5x» — прежний разбор молча резал хвост и возвращал 5. */
        config_load(write_cfg("learn_min_op=5x\n"), &cfg);
        CHECK(cfg.n_bad_values >= 1, "мусорный суффикс помечен");

        /* Шестнадцатеричная форма с буквами: маски fwmark записываются именно
         * так. Проверка формы принимала только цифры и тем самым обнуляла
         * mark_mask — заявленная поддержка hex не работала. */
        config_load(write_cfg("mark_mask=0xffff0000\nmark_ok=0xdeadbeef\n"), &cfg);
        CHECK(cfg.mark_mask == 0xffff0000UL && cfg.mark_ok == 0xdeadbeefUL,
              "hex с буквами принят (mark_mask/mark_ok)");
        CHECK(cfg.n_bad_values == 0, "и не помечен как отклонённый");
        /* Для длительности hex-формы не существует: разбор вернул бы 0, а 0 =
         * «не истекает». Такое должно быть замечено, а не применено молча. */
        config_load(write_cfg("ok_ttl=0x10\n"), &cfg);
        CHECK(cfg.n_bad_values == 1 && !strcmp(cfg.bad_values[0], "ok_ttl"),
              "hex в длительности отклонён, а не стал «бессрочно»");
        /* Переполнение: на 32-битном MIPS strtoul возвращает ULONG_MAX. */
        config_load(write_cfg("mark_ok=0xffffffffffffffff\n"), &cfg);
        CHECK(cfg.n_bad_values == 1, "переполнение значения метки помечено");

        /* Ведущий ноль — это десятичная система, а не восьмеричная. */
        config_load(write_cfg("routing_table=0100\n"), &cfg);
        CHECK(cfg.routing_table == 100, "«0100» прочитано как 100, а не как 64");

        /* Гигантское значение не должно переполнять int. */
        config_load(write_cfg("ok_ttl=99999999999\n"), &cfg);
        CHECK(cfg.ok_ttl >= 0, "переполнение не стало отрицательным");
        CHECK(cfg.n_bad_values >= 1, "выход за диапазон зарегистрирован");

        /* Легальный суффикс не считается мусором. */
        config_load(write_cfg("cooldown_ttl=5m\nok_ttl=6h\n"), &cfg);
        CHECK(cfg.cooldown_ttl == 300 && cfg.ok_ttl == 21600,
              "s/m/h/d/w по-прежнему понятны");
        CHECK(cfg.n_bad_values == 0, "и не помечаются как ошибка");

        /* Ключ, которого агент не знает: строка в файле выглядит настройкой и
         * не действует ни на что. */
        config_load(write_cfg("ok_tll=6h\nforis_ra=1\nok_ttl=21600\n"), &cfg);
        CHECK(cfg.ok_ttl == 21600, "правильный ключ рядом с опечаткой применён");
        CHECK(cfg.n_unknown_keys == 2, "обе опечатки распознаны как неизвестные");
        CHECK(cfg.n_unknown_keys == 2 &&
              !strcmp(cfg.unknown_keys[0], "ok_tll") &&
              !strcmp(cfg.unknown_keys[1], "foris_ra"),
              "имена сохранены для отчёта");
        CHECK(config_validate(&cfg, prob, sizeof(prob)) > 0 &&
              strstr(prob, "ok_tll") != NULL,
              "config check показывает нераспознанный ключ");
        /* Обычный конфиг не должен ничего такого выдавать. */
        config_load(write_cfg("ok_ttl=21600\ndns_sniff=1\nprecision=strict\n"), &cfg);
        CHECK(cfg.n_unknown_keys == 0 && cfg.n_bad_values == 0,
              "корректный конфиг — ни неизвестных, ни отклонённых ключей");
    }

    remove(tmp_path());
    printf("\n%s\n", failures ? "ЕСТЬ ОШИБКИ" : "все проверки пройдены");
    return failures ? 1 : 0;
}
