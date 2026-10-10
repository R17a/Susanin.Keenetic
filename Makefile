CC ?= cc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Wpedantic
LDFLAGS ?=
PREFIX ?= /opt
BINDIR = $(PREFIX)/susanin/bin
CONFDIR = $(PREFIX)/susanin/etc
VARDIR = $(PREFIX)/susanin/var

SRCS = src/main.c src/config.c src/discover.c src/conntrack.c src/state.c \
       src/backend.c src/classifier.c src/health.c src/engine.c src/log.c src/ops.c \
       src/vpn_always.c src/vpn_never.c src/web.c src/udp_relay.c src/cdn.c \
       src/dns_sniff.c src/profiles.c
OBJS = $(SRCS:.c=.o)

TARGET = susanin-agent
TESTS = tests/test_conntrack tests/test_config tests/test_ops tests/test_web_list tests/test_state tests/test_backend_value tests/test_classifier_key
SAMPLES = testdata/nf_conntrack.samples
# Объекты для тестов, которые включают .c-файл в свой TU (тогда его .o линковать нельзя).
TEST_OBJS = $(filter-out src/main.o,$(OBJS))

.PHONY: all clean install test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Тесты (хост-компилятор; в кросс-сборку и поставку не входят).
test: $(TESTS)
	./tests/test_conntrack $(SAMPLES)
	./tests/test_config
	./tests/test_ops
	./tests/test_web_list
	./tests/test_state
	./tests/test_backend_value
	./tests/test_classifier_key

tests/test_state: tests/test_state.c src/state.c src/state.h
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_state.c src/state.c

tests/test_backend_value: tests/test_backend_value.c src/backend.c $(TEST_OBJS)
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_backend_value.c $(TEST_OBJS)

# test_classifier_key включает src/classifier.c: его .o из линковки исключаем.
tests/test_classifier_key: tests/test_classifier_key.c src/classifier.c $(TEST_OBJS)
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_classifier_key.c $(filter-out src/classifier.o,$(TEST_OBJS))

tests/test_conntrack: tests/test_conntrack.c src/conntrack.c src/conntrack.h
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_conntrack.c src/conntrack.c

tests/test_config: tests/test_config.c src/config.c src/config.h
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_config.c src/config.c

# test_ops включает src/ops.c, test_web_list — src/web.c: их .o исключаем из линковки.
tests/test_ops: tests/test_ops.c src/ops.c $(TEST_OBJS)
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_ops.c $(filter-out src/ops.o,$(TEST_OBJS))

tests/test_web_list: tests/test_web_list.c src/web.c $(TEST_OBJS)
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_web_list.c $(filter-out src/web.o,$(TEST_OBJS))

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(CONFDIR) $(DESTDIR)$(VARDIR)
	install -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

clean:
	rm -f $(TARGET) $(OBJS) $(TESTS)
