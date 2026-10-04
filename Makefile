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
TESTBIN = tests/test_conntrack
SAMPLES = testdata/nf_conntrack.samples

.PHONY: all clean install test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Тесты парсера conntrack (хост-компилятор; в кросс-сборку не входят).
test: $(TESTBIN)
	./$(TESTBIN) $(SAMPLES)

$(TESTBIN): tests/test_conntrack.c src/conntrack.c src/conntrack.h
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_conntrack.c src/conntrack.c

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(CONFDIR) $(DESTDIR)$(VARDIR)
	install -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

clean:
	rm -f $(TARGET) $(OBJS) $(TESTBIN)
