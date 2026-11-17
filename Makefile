CC ?= cc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Wpedantic
LDFLAGS ?=
PREFIX ?= /opt
BINDIR = $(PREFIX)/susanin/bin
CONFDIR = $(PREFIX)/susanin/etc
VARDIR = $(PREFIX)/susanin/var

SRCS = src/main.c src/config.c src/discover.c src/conntrack.c src/state.c \
       src/backend.c src/classifier.c src/health.c src/engine.c src/log.c src/ops.c \
       src/vpn_always.c src/vpn_never.c src/web.c src/web_choices.c \
       src/udp_relay.c src/cdn.c src/dns_sniff.c src/profiles.c src/release.c src/vpin.c src/entryparse.c src/snisniff.c
OBJS = $(SRCS:.c=.o)

TARGET = susanin-agent
TESTS = tests/test_conntrack tests/test_config tests/test_ops tests/test_web_list tests/test_web_choices tests/test_state tests/test_backend_value tests/test_backend_lock tests/test_classifier_key tests/test_classifier_media tests/test_classifier_synfail tests/test_config_sync tests/test_dns_sniff_stats tests/test_socks_timeout tests/test_web_token tests/test_release tests/test_vpin tests/test_entryparse tests/test_snisniff
SAMPLES = testdata/nf_conntrack.samples
# Объекты для тестов, которые включают .c-файл в свой TU (тогда его .o линковать нельзя).
TEST_OBJS = $(filter-out src/main.o,$(OBJS))

.PHONY: all clean install test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Все объектники зависят от всех заголовков src/. Без этого правка структуры в
# config.h (новые поля меняют смещения) пересобирает только изменённый .c, а
# остальные остаются со СТАРОЙ раскладкой — линкуется бинарник с разными layout
# в одном процессе. На хосте это выглядит как чудесно падающий тест, на роутере
# — как чтение чужих полей. Раньше зависимость ставили точечно (web_choices.h);
# теперь общая, включая тестовые сборки, которые линкуют те же объектники.
HDRS = $(wildcard src/*.h)
$(OBJS): $(HDRS)
# Тестовые бинари — тоже: они линкуют те же объектники и включают те же
# заголовки, а правило выше покрывает только src/*.o. Без этого, например,
# test_release мог остаться собранным со старым version.h.
$(TESTS): $(HDRS)

# Тесты (хост-компилятор; в кросс-сборку и поставку не входят).
# `all` в зависимостях обязателен: test-installer-sync.sh запускает сам
# `susanin-agent` (config check/sync), и без этого шага он молча проверял бы
# бинарник, оставшийся от прошлой сборки, — зелёный результат при изменённом
# исходнике.
test: all $(TESTS)
	./tests/test_conntrack $(SAMPLES)
	./tests/test_config
	./tests/test_ops
	./tests/test_web_list
	./tests/test_web_choices
	./tests/test_state
	./tests/test_backend_value
	./tests/test_backend_lock
	./tests/test_classifier_key
	./tests/test_classifier_media
	./tests/test_classifier_synfail
	./tests/test_config_sync
	./tests/test_dns_sniff_stats
	./tests/test_socks_timeout
	./tests/test_web_token
	./tests/test_release
	./tests/test_vpin
	./tests/test_entryparse
	./tests/test_snisniff
	sh tests/test-egress-failover.sh
	sh tests/test-installer-sync.sh
	sh tests/test-cfg-spaces.sh

tests/test_state: tests/test_state.c src/state.c src/state.h
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_state.c src/state.c

# Очередь аудита пинов: чистый модуль без сети/ipset — линкуем только его.
tests/test_vpin: tests/test_vpin.c src/vpin.c src/vpin.h
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_vpin.c src/vpin.c

# Разбор строк списков (префикс ? и зоны *.domain) — чистый модуль.
tests/test_entryparse: tests/test_entryparse.c src/entryparse.c src/entryparse.h
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_entryparse.c src/entryparse.c

# SNI-парсер ClientHello: чистый разбор полезной нагрузки, без сокетов.
tests/test_snisniff: tests/test_snisniff.c src/snisniff.c src/snisniff.h
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_snisniff.c src/snisniff.c

# test_web_token включает src/web.c (static token_eq/header_value/cookie_value):
# .o web исключаем, а web_choices.o линкуем (его вызывают функции web.c).
tests/test_web_token: tests/test_web_token.c src/web.c src/web_choices.c $(TEST_OBJS)
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_web_token.c \
		$(filter-out src/web.o,$(TEST_OBJS))

tests/test_backend_value: tests/test_backend_value.c src/backend.c $(TEST_OBJS)
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_backend_value.c $(TEST_OBJS)

# Распознавание xtables-lock (ложное «data plane missing»): нужен backend.o.
tests/test_backend_lock: tests/test_backend_lock.c src/backend.c $(TEST_OBJS)
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_backend_lock.c $(TEST_OBJS)

# test_classifier_key включает src/classifier.c: его .o из линковки исключаем.
tests/test_classifier_key: tests/test_classifier_key.c src/classifier.c $(TEST_OBJS)
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_classifier_key.c $(filter-out src/classifier.o,$(TEST_OBJS))

# test_classifier_media тоже включает src/classifier.c (static media_quorum /
# media_port / ip_in_cidr) — .o классификатора исключаем, как выше.
tests/test_classifier_media: tests/test_classifier_media.c src/classifier.c src/classifier.h $(TEST_OBJS)
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_classifier_media.c $(filter-out src/classifier.o,$(TEST_OBJS))

# Улика гибели прямого пути: sf_note — static, поэтому classifier.c включается в TU.
tests/test_classifier_synfail: tests/test_classifier_synfail.c src/classifier.c src/classifier.h $(TEST_OBJS)
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_classifier_synfail.c $(filter-out src/classifier.o,$(TEST_OBJS))

# config sync работает с файлом: config.c + log.c (slogf вызывается из config.c).
tests/test_config_sync: tests/test_config_sync.c src/config.c src/config.h src/log.c src/log.h
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_config_sync.c src/config.c src/log.c

# Счётчики снифинга: dns_sniff.c включается в TU (static-глобалы g_fds/g_started),
# поэтому его .o из линковки исключаем; в TU нет ни ipset, ни iptables (g_cfg=NULL).
tests/test_dns_sniff_stats: tests/test_dns_sniff_stats.c src/dns_sniff.c src/dns_sniff.h $(TEST_OBJS)
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_dns_sniff_stats.c $(filter-out src/dns_sniff.o,$(TEST_OBJS))

# Таймауты SOCKS: udp_relay.c включается в TU (static socks_associate), его .o
# из линковки исключаем.
tests/test_socks_timeout: tests/test_socks_timeout.c src/udp_relay.c src/udp_relay.h $(TEST_OBJS)
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_socks_timeout.c $(filter-out src/udp_relay.o,$(TEST_OBJS))

tests/test_conntrack: tests/test_conntrack.c src/conntrack.c src/conntrack.h
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_conntrack.c src/conntrack.c

tests/test_config: tests/test_config.c src/config.c src/config.h
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_config.c src/config.c

# W6: чистые функции разбора GitHub/сравнения версий; log.c нужен из-за slogf.
tests/test_release: tests/test_release.c src/release.c src/log.c
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_release.c src/release.c src/log.c

# test_ops включает src/ops.c, test_web_list — src/web.c: их .o из линковки
# исключаем, иначе дубли символов. src/web_choices.o, наоборот, ЛИНКУЕМ:
# web.c, включённый в TU теста, вызывает wc_list_dir()/wc_write_json().
tests/test_ops: tests/test_ops.c src/ops.c $(TEST_OBJS)
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_ops.c $(filter-out src/ops.o,$(TEST_OBJS))

tests/test_web_list: tests/test_web_list.c src/web.c src/web_choices.c $(TEST_OBJS)
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_web_list.c \
		$(filter-out src/web.o,$(TEST_OBJS))

# test_web_choices включает src/web_choices.c: из линковки его .o исключаем.
tests/test_web_choices: tests/test_web_choices.c src/web_choices.c src/web_choices.h
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_web_choices.c

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(CONFDIR) $(DESTDIR)$(VARDIR)
	install -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

clean:
	rm -f $(TARGET) $(OBJS) $(TESTS)
