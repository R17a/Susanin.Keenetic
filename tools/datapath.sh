#!/bin/sh
# datapath.sh — Susanin.Keenetic data plane (iptables + ipset) on/off + manual words.
#
# Учитываем ТОЛЬКО свои биты метки (mark_mask, по умолчанию 0x30000000): guard
# "не помечено", CONNMARK restore и ip rule используют маску, поэтому метки
# сторонних подсистем (qWDTT/NDM, 0xffffaXX и т.п.) нам не мешают и не затираются.
#
# POSIX sh (busybox ash compatible).

set -eu

PREFIX=/opt
find_bin() { for b in /opt/sbin /opt/bin /usr/sbin /usr/bin; do [ -x "$b/$1" ] && { echo "$b/$1"; return; }; done; command -v "$1" 2>/dev/null || true; }
IPT=$(find_bin iptables); IPSET=$(find_bin ipset); IPCMD=$(find_bin ip)
IP6T=$(find_bin ip6tables)
# Все вызовы iptables — через `-w`: ждать xtables-lock, а не падать
# ("Another app is currently holding the xtables lock" при параллели с NDM).
ipt() { "$IPT" -w "$@"; }
MODPROBE=$(find_bin modprobe); INSMOD=$(find_bin insmod)
KVER=$(uname -r 2>/dev/null || echo "")
KDIR="/lib/modules/$KVER"
[ -n "$IPT" ] || { echo "iptables not found" >&2; exit 2; }
[ -n "$IPSET" ] || { echo "ipset not found" >&2; exit 2; }
[ -n "$IPCMD" ] || { echo "ip not found" >&2; exit 2; }

EGRESS=${SUSANIN_EGRESS:-nwg0}
TABLE=${SUSANIN_TABLE:-100}
MARK_OK=${SUSANIN_MARK_OK:-0x20000000}
MARK_TEST=${SUSANIN_MARK_TEST:-0x10000000}
# Наши биты метки (как в susanin.conf mark_mask). Всё, что вне маски (метки
# qWDTT/NDM), нас не касается и НЕ мешает маркировке.
MARK_MASK=${SUSANIN_MARK_MASK:-0x30000000}
# Для TPROXY-mark нужен полный охват битов (там значение 0x1).
TPMASK=0xffffffff
PRI_OK=${SUSANIN_PRI_OK:-2000}
PRI_TEST=${SUSANIN_PRI_TEST:-2001}
LAN=${SUSANIN_LAN:-"br0 br1"}
LAN=$(printf '%s' "$LAN" | tr ',' ' ')
TTL_TEST=${SUSANIN_TTL_TEST:-60}
TTL_OK=${SUSANIN_TTL_OK:-21600}
DISK_MODE=${SUSANIN_DISK_MODE:-normal}
TPROXY_PORT=${SUSANIN_TPROXY_PORT:-0}
TPROXY_MARK=0x1
UDP_RELAY_PORT=${SUSANIN_UDP_RELAY_PORT:-0}
# C3: блокировать IPv6 из LAN (весь трафик клиентов — по IPv4, под Susanin).
IPV6_BLOCK=${SUSANIN_IPV6_BLOCK:-0}
# QUIC (UDP 443) из LAN: 1 = запретить, чтобы приложения шли по TCP.
QUIC_BLOCK=${SUSANIN_QUIC_BLOCK:-0}
# N2: kernel-offload — адреса susanin_ok_net уводить маршрутом через НАСТОЯЩИЙ
# интерфейс (KERNEL_EGRESS), минуя userspace tproxy (быстрее на слабом CPU).
# Работает только в tproxy-режиме и только при заданном KERNEL_EGRESS.
KERNEL_OFFLOAD=${SUSANIN_KERNEL_OFFLOAD:-0}
KERNEL_EGRESS=${SUSANIN_KERNEL_EGRESS:-}
KERNEL_TABLE=${SUSANIN_KERNEL_TABLE:-210}
KERNEL_MARK=0x00800000
# MSS/PMTU для туннеля/CDN: "0"=выкл, число байт или "pmtu".
MSS_CLAMP=${SUSANIN_MSS_CLAMP:-0}
MSS_CLAMP_LAN=${SUSANIN_MSS_CLAMP_LAN:-0}
# T3: DNS клиентов серверных VPN (oc+/wdtt+) -> резолвер роутера (DNAT 53).
# Нужно, когда клиент шлёт DNS на 8.8.8.8, а сервер не форсирует DNS в туннель.
DNS_HIJACK=${SUSANIN_DNS_HIJACK:-0}
DNS_HIJACK_TARGET=${SUSANIN_DNS_HIJACK_TARGET:-}
# P5: сторонний прокси на роутере (Teleproxy/MTProxy). Трафик процесса с uid
# PROXY_UID метится в mangle OUTPUT и уходит в PROXY_EGRESS по своей таблице.
# Пустые значения = выключено.
PROXY_UID=${SUSANIN_PROXY_UID:-}
PROXY_EGRESS=${SUSANIN_PROXY_EGRESS:-}
PROXY_TABLE=${SUSANIN_PROXY_TABLE:-110}
PROXY_MARK=${SUSANIN_PROXY_MARK:-0x01000000}
# iptables печатает метку без ведущих нулей (0x1000000) — для grep приводим
# к каноническому виду.
PROXY_MARK_HEX=$(printf '0x%x' "$((PROXY_MARK))")
PRI_PROXY=${SUSANIN_PRI_PROXY:-$((PRI_OK + 3))}

# Ручной запуск (не из демона): значения берём из конфига; из демона всё
# приходит через окружение (backend.c) — поведение не меняется.
CONF_FILE=${SUSANIN_CONF:-/opt/susanin/etc/susanin.conf}
cfg_val() { # cfg_val <ключ> [значение по умолчанию]
    _v=""
    if [ -r "$CONF_FILE" ]; then
        _v=$(awk -F= -v k="$1" '$1==k {sub(/^[^=]*=/,""); print; exit}' "$CONF_FILE" 2>/dev/null || true)
    fi
    if [ -n "$_v" ]; then printf '%s' "$_v"; else printf '%s' "${2:-}"; fi
}
[ -n "${SUSANIN_EGRESS:-}" ]         || EGRESS=$(cfg_val egress_interface "$EGRESS")
# egress_interface может быть списком (фейловер) — дальше нужен один интерфейс.
EGRESS=$(printf '%s' "$EGRESS" | sed 's/,.*//' | tr -d ' \t')
[ -n "${SUSANIN_TABLE:-}" ]          || TABLE=$(cfg_val routing_table "$TABLE")
[ -n "${SUSANIN_LAN:-}" ]            || LAN=$(cfg_val lan_interfaces "br0 br1")
LAN=$(printf '%s' "$LAN" | tr ',' ' ')
[ -n "${SUSANIN_MARK_OK:-}" ]        || MARK_OK=$(cfg_val mark_ok "$MARK_OK")
[ -n "${SUSANIN_MARK_TEST:-}" ]      || MARK_TEST=$(cfg_val mark_test "$MARK_TEST")
[ -n "${SUSANIN_MARK_MASK:-}" ]      || MARK_MASK=$(cfg_val mark_mask "$MARK_MASK")
[ -n "${SUSANIN_DISK_MODE:-}" ]      || DISK_MODE=$(cfg_val disk_mode "$DISK_MODE")
[ -n "${SUSANIN_IPV6_BLOCK:-}" ]     || IPV6_BLOCK=$(cfg_val ipv6_block "$IPV6_BLOCK")
[ -n "${SUSANIN_QUIC_BLOCK:-}" ]     || QUIC_BLOCK=$(cfg_val quic_block "$QUIC_BLOCK")
[ -n "${SUSANIN_KERNEL_OFFLOAD:-}" ] || KERNEL_OFFLOAD=$(cfg_val kernel_offload "$KERNEL_OFFLOAD")
[ -n "${SUSANIN_KERNEL_EGRESS:-}" ]  || KERNEL_EGRESS=$(cfg_val kernel_egress "$KERNEL_EGRESS")
[ -n "${SUSANIN_MSS_CLAMP:-}" ]      || MSS_CLAMP=$(cfg_val mss_clamp "$MSS_CLAMP")
[ -n "${SUSANIN_MSS_CLAMP_LAN:-}" ]  || MSS_CLAMP_LAN=$(cfg_val mss_clamp_lan "$MSS_CLAMP_LAN")
[ -n "${SUSANIN_DNS_HIJACK:-}" ]     || DNS_HIJACK=$(cfg_val dns_hijack "$DNS_HIJACK")
[ -n "${SUSANIN_DNS_HIJACK_TARGET:-}" ] || DNS_HIJACK_TARGET=$(cfg_val dns_hijack_target "$DNS_HIJACK_TARGET")
[ -n "${SUSANIN_PROXY_UID:-}" ]      || PROXY_UID=$(cfg_val proxy_uid "")
[ -n "${SUSANIN_PROXY_EGRESS:-}" ]   || PROXY_EGRESS=$(cfg_val proxy_egress "")
[ -n "${SUSANIN_PROXY_TABLE:-}" ]    || PROXY_TABLE=$(cfg_val proxy_table "$PROXY_TABLE")
[ -n "${SUSANIN_PROXY_MARK:-}" ]     || PROXY_MARK=$(cfg_val proxy_mark "$PROXY_MARK")
# Порты демон выставляет только когда режим включён — повторяем ту же логику.
if [ -z "${SUSANIN_TPROXY_PORT:-}" ]; then
    if [ "$(cfg_val egress_type interface)" = "tproxy" ]; then
        TPROXY_PORT=$(cfg_val tproxy_port "$TPROXY_PORT")
    fi
fi
if [ -z "${SUSANIN_UDP_RELAY_PORT:-}" ]; then
    if [ "$(cfg_val udp_relay 0)" = "1" ]; then
        UDP_RELAY_PORT=$(cfg_val udp_relay_port "$UDP_RELAY_PORT")
    fi
fi

CHAIN=SUSANIN
SETS="susanin_ok_tcp susanin_ok_udp susanin_test_tcp susanin_test_udp"
NETSET=susanin_ok_net
NEVERSET=susanin_never
# Мягкое «прямо» (DIRECT_PREF, D1): RETURN как never, но с TTL и управляется
# агентом (авто-возврат). Отдельный набор, чтобы не трогать жёсткий never.
DIRECTSET=susanin_direct
# Port-aware identity (экспериментально, по умолчанию ВЫКЛ): решения по паре
# адрес+порт. Тогда ok/test — наборы hash:ip,port, правила матчат dst,dst, а
# add/del принимают порт. Наборы ok_net/never/direct остаются по адресу.
PORT_AWARE=${SUSANIN_PORT_AWARE:-0}
case "$PORT_AWARE" in 1|true|yes|on) PORT_AWARE=1 ;; *) PORT_AWARE=0 ;; esac

say() { echo "[susanin] $*"; }
load_mod() {
    _m="$1"
    [ -n "$MODPROBE" ] && "$MODPROBE" "$_m" >/dev/null 2>&1 && return 0
    [ -n "$INSMOD" ] && [ -f "$KDIR/$_m.ko" ] && "$INSMOD" "$KDIR/$_m.ko" >/dev/null 2>&1 && return 0
    return 1
}
ensure_mod() { load_mod "$1" || true; }

mangle() { "ipt" -t mangle -D "$@" >/dev/null 2>&1 || true; "ipt" -t mangle -A "$@"; }
iprule() { "$IPCMD" rule del "$@" >/dev/null 2>&1 || true; "$IPCMD" rule add "$@"; }
# ip rule для НАШИХ меток: добавляем с маской (чтобы не зависеть от чужих битов),
# при этом удаляем и старую запись без маски, если была.
iprule_fw() { # <mark> <prio>
    "$IPCMD" rule del fwmark "$1" priority "$2" lookup "$TABLE" >/dev/null 2>&1 || true
    "$IPCMD" rule del fwmark "$1/$MARK_MASK" priority "$2" lookup "$TABLE" >/dev/null 2>&1 || true
    "$IPCMD" rule add fwmark "$1/$MARK_MASK" priority "$2" lookup "$TABLE"
}

set_exists() { "$IPSET" list "$1" >/dev/null 2>&1; }

# Бэкап состояния netfilter ПЕРЕД правками — ОДИН фиксированный каталог
# var/datapath.bak, файлы перезаписываются. Раньше каталоги множились
# (datapath-<дата> + архивы в var/archive) и забивали носитель — от этого отказались:
# смысл бэкапа только в «состоянии до наших изменений», история не нужна.
# Если правила не изменились с прошлого раза — не пишем ничего (нет износа флеша),
# поэтому прежний лимит «не чаще раза в час» больше не нужен.
BK_DIR="$PREFIX/susanin/var/datapath.bak"

bk_cleanup_legacy() {
    # Одноразовая уборка старого множащегося формата: каталоги datapath-<дата>,
    # архивы var/archive/datapath-*.tar.gz и маркер .last-backup. Фиксированный
    # datapath.bak под шаблон datapath-[0-9]* не попадает; в archive трогаем
    # только НАШИ файлы (каталог удаляем лишь если опустел).
    for _d in "$PREFIX/susanin/var"/datapath-[0-9]*; do
        [ -e "$_d" ] && rm -rf "$_d" 2>/dev/null || true
    done
    for _a in "$PREFIX/susanin/var/archive"/datapath-*.tar.gz; do
        [ -e "$_a" ] && rm -f "$_a" 2>/dev/null || true
    done
    rmdir "$PREFIX/susanin/var/archive" 2>/dev/null || true
    rm -f "$PREFIX/susanin/var/.last-backup" 2>/dev/null || true
}

bk_file() { # bk_file <имя> <команда...>
    _n="$1"; shift
    _f="$BK_DIR/$_n"; _t="$BK_DIR/.$_n.tmp"
    "$@" > "$_t" 2>/dev/null || true
    if [ -f "$_f" ] && cmp -s "$_t" "$_f" 2>/dev/null; then
        rm -f "$_t"
        return 0
    fi
    mv -f "$_t" "$_f" 2>/dev/null || rm -f "$_t"
    BK_CHANGED=1
}

backup() {
    if [ "$DISK_MODE" = "soft" ]; then
        say "disk_mode=soft: backup skipped"
        return 0
    fi
    mkdir -p "$BK_DIR" || return 0
    bk_cleanup_legacy
    BK_CHANGED=0
    bk_file mangle.txt   "ipt" -t mangle -S
    bk_file nat.txt      "ipt" -t nat -S
    bk_file ip-rule.txt  "$IPCMD" rule show
    bk_file ip-route.txt "$IPCMD" route show table all
    if [ "$BK_CHANGED" = "1" ]; then
        say "backup: $BK_DIR"
    fi
    return 0
}

set_type_ok() { # set_type_ok <набор> <ожидаемый тип>
    "$IPSET" list -t "$1" 2>/dev/null | grep -q "Type: $2"
}

ensure_sets() {
    # ВАЖНО: не `[ ] && присваивание` — при ложном условии под `set -e` это
    # завершает скрипт (проверено харнессом).
    if [ "$PORT_AWARE" = "1" ]; then
        _t=hash:ip,port
    else
        _t=hash:ip
    fi
    for s in $SETS; do
        if set_exists "$s"; then
            # Тип мог остаться от прошлой конфигурации (hash:ip <-> hash:ip,port):
            # пересоздаём, иначе add с портом/без порта будет падать.
            set_type_ok "$s" "$_t" || {
                say "ipset $s: тип не $_t — пересоздаю"
                "$IPSET" destroy "$s" 2>/dev/null || true
                "$IPSET" create "$s" "$_t" timeout 0
            }
        else
            "$IPSET" create "$s" "$_t" timeout 0
        fi
    done
    set_exists "$NETSET" || "$IPSET" create "$NETSET" hash:net timeout 0
    set_exists "$NEVERSET" || "$IPSET" create "$NEVERSET" hash:net timeout 0
    set_exists "$DIRECTSET" || "$IPSET" create "$DIRECTSET" hash:net timeout 0
    say "ipsets ready (port_aware=$PORT_AWARE)"
}

ensure_chain() {
    "ipt" -t mangle -S "$CHAIN" >/dev/null 2>&1 || "ipt" -t mangle -N "$CHAIN"
}

rule_priv() {
    for priv in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 \
                172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4; do
        for i in $LAN; do
            mangle "$CHAIN" -i "$i" -d "$priv" -j RETURN
        done
    done
}

rule_mark() {
    for i in $LAN; do
        # Клиенты OpenConnect (oc0, oc1… или шаблон oc+) приходят с меткой
        # Keenetic (0xffffaXX). Она пересекается с нашей маской, поэтому
        # правило «-m mark 0x0/MASK» для них не срабатывало и трафик уходил по
        # политике NDM вместо VPN. Для oc* выставляем наш CONNMARK без этой
        # предусловицы; restore-mark дальше аккуратно заменит только наши биты.
        _ocm=0
        case "$i" in oc*) _ocm=1 ;; esac
        # N2: ok_net -> kernel-offload (отдельная метка + ACCEPT, чтобы не уйти
        # в tproxy REDIRECT и не получить MARK_OK).
        if [ "$KERNEL_OFFLOAD" = "1" ] && [ -n "$KERNEL_EGRESS" ]; then
            mangle "$CHAIN" -i "$i" -m set --match-set "$NETSET" dst \
                -j MARK --set-xmark "$KERNEL_MARK/$KERNEL_MARK"
            mangle "$CHAIN" -i "$i" -m mark --mark "$KERNEL_MARK/$KERNEL_MARK" -j ACCEPT
        fi
        mangle "$CHAIN" -i "$i" -m set --match-set susanin_never dst -j RETURN
        # Мягкое «прямо» (D1): адрес, который пробовали в VPN, но там хуже —
        # принудительно прямо, с TTL (сам вернётся в обучение).
        mangle "$CHAIN" -i "$i" -m set --match-set "$DIRECTSET" dst -j RETURN
        # Порты, которые ВСЕГДА идут напрямую (не в VPN и не в udp-relay):
        #   53/853 — DNS / DNS-over-TLS (иначе ломается резолв);
        #   500/4500 — IPsec (IKE/NAT-T); 8567 — UDP-мессенджер Битрикс24.
        # RETURN стоит ДО правил наборов, поэтому действует, даже если адрес уже
        # выучен в susanin_ok_*/ok_net.
        for _p in 53 853 500 4500 8567; do
            for _t in tcp udp; do
                mangle "$CHAIN" -i "$i" -p "$_t" --dport "$_p" -j RETURN
                mangle "$CHAIN" -i "$i" -p "$_t" --sport "$_p" -j RETURN
            done
        done
        # Семантика матча по набору: обычно по адресу цели (dst), в port-aware
        # режиме — по адресу И порту цели (dst,dst).
        if [ "$PORT_AWARE" = "1" ]; then
            _ms=dst,dst
        else
            _ms=dst
        fi
        for p in tcp udp; do
            if [ "$_ocm" = "1" ]; then
                # oc*: без предусловицы по skb-метке (у клиентов уже стоит
                # метка Keenetic 0xffffaXX, см. комментарий выше).
                mangle "$CHAIN" -i "$i" -p "$p" -m conntrack --ctstate NEW \
                    -m set --match-set susanin_ok_${p} $_ms \
                    -j CONNMARK --set-xmark "$MARK_OK/$MARK_MASK"
                mangle "$CHAIN" -i "$i" -p "$p" -m conntrack --ctstate NEW \
                    -m set --match-set susanin_ok_net dst \
                    -j CONNMARK --set-xmark "$MARK_OK/$MARK_MASK"
                mangle "$CHAIN" -i "$i" -p "$p" -m conntrack --ctstate NEW \
                    -m set --match-set susanin_test_${p} $_ms \
                    -j CONNMARK --set-xmark "$MARK_TEST/$MARK_MASK"
            else
                mangle "$CHAIN" -i "$i" -p "$p" -m conntrack --ctstate NEW \
                    -m mark --mark "0x0/$MARK_MASK" \
                    -m set --match-set susanin_ok_${p} $_ms \
                    -j CONNMARK --set-xmark "$MARK_OK/$MARK_MASK"
                mangle "$CHAIN" -i "$i" -p "$p" -m conntrack --ctstate NEW \
                    -m mark --mark "0x0/$MARK_MASK" \
                    -m set --match-set susanin_ok_net dst \
                    -j CONNMARK --set-xmark "$MARK_OK/$MARK_MASK"
                mangle "$CHAIN" -i "$i" -p "$p" -m conntrack --ctstate NEW \
                    -m mark --mark "0x0/$MARK_MASK" \
                    -m set --match-set susanin_test_${p} $_ms \
                    -j CONNMARK --set-xmark "$MARK_TEST/$MARK_MASK"
            fi
        done
        mangle "$CHAIN" -i "$i" -j CONNMARK --restore-mark --nfmask "$MARK_MASK" --ctmask "$MARK_MASK"
        mangle "$CHAIN" -i "$i" -m mark --mark "$MARK_OK/$MARK_MASK" \
            -j MARK --set-xmark "$MARK_OK/$MARK_MASK"
        mangle "$CHAIN" -i "$i" -m mark --mark "$MARK_TEST/$MARK_MASK" \
            -j MARK --set-xmark "$MARK_TEST/$MARK_MASK"
    done
}

ensure_jump() {
    "ipt" -t mangle -D PREROUTING -j "$CHAIN" >/dev/null 2>&1 || true
    "ipt" -t mangle -A PREROUTING -j "$CHAIN"
}

ensure_table() {
    if [ "${TPROXY_PORT:-0}" -gt 0 ] 2>/dev/null; then
        iprule_fw_clean "$MARK_OK" "$PRI_OK"
        iprule_fw_clean "$MARK_TEST" "$PRI_TEST"
        "$IPCMD" rule del fwmark "$TPROXY_MARK" priority "$((PRI_OK + 2))" lookup "$TABLE" >/dev/null 2>&1 || true
        "$IPCMD" route del local default dev lo table "$TABLE" >/dev/null 2>&1 || true
        "$IPCMD" route del default dev "$EGRESS" table "$TABLE" >/dev/null 2>&1 || true
        redirect_rules
        udp_relay_rules
        if [ "$KERNEL_OFFLOAD" = "1" ] && [ -n "$KERNEL_EGRESS" ]; then
            "$IPCMD" rule del fwmark "$KERNEL_MARK/$KERNEL_MARK" lookup "$KERNEL_TABLE" >/dev/null 2>&1 || true
            "$IPCMD" route del default table "$KERNEL_TABLE" >/dev/null 2>&1 || true
            "$IPCMD" route add default dev "$KERNEL_EGRESS" table "$KERNEL_TABLE" 2>/dev/null || true
            "$IPCMD" rule add fwmark "$KERNEL_MARK/$KERNEL_MARK" lookup "$KERNEL_TABLE" 2>/dev/null || true
            say "kernel-offload: ok_net -> $KERNEL_EGRESS table=$KERNEL_TABLE"
        fi
        say "redirect ready (port=$TPROXY_PORT, udp_relay=$UDP_RELAY_PORT, mask=$MARK_MASK)"
    else
        "$IPCMD" route del default dev "$EGRESS" table "$TABLE" >/dev/null 2>&1 || true
        "$IPCMD" route add default dev "$EGRESS" table "$TABLE"
        iprule_fw "$MARK_OK" "$PRI_OK"
        iprule_fw "$MARK_TEST" "$PRI_TEST"
        say "table/ip-rule ready (table=$TABLE dev=$EGRESS mask=$MARK_MASK)"
    fi
}

# Снять наши ip rule (и со старой полной маской, и с mark_mask).
iprule_fw_clean() { # <mark> <prio>
    "$IPCMD" rule del fwmark "$1" priority "$2" lookup "$TABLE" >/dev/null 2>&1 || true
    "$IPCMD" rule del fwmark "$1/$MARK_MASK" priority "$2" lookup "$TABLE" >/dev/null 2>&1 || true
}

redirect_rules() {
    for m in "$MARK_OK" "$MARK_TEST"; do
        "ipt" -t nat -D PREROUTING -p tcp -m mark --mark "$m/$MARK_MASK" \
            -j REDIRECT --to-ports "$TPROXY_PORT" >/dev/null 2>&1 || true
        "ipt" -t nat -A PREROUTING -p tcp -m mark --mark "$m/$MARK_MASK" \
            -j REDIRECT --to-ports "$TPROXY_PORT"
    done
}

udp_relay_rules() {
    [ "${UDP_RELAY_PORT:-0}" -gt 0 ] 2>/dev/null || return 0
    ensure_mod nf_tproxy_ipv4
    ensure_mod xt_socket
    ensure_mod xt_TPROXY
    iprule fwmark "$TPROXY_MARK" priority "$((PRI_OK + 2))" lookup "$TABLE" 2>/dev/null || true
    "$IPCMD" route replace local default dev lo table "$TABLE" 2>/dev/null || true
    for m in "$MARK_OK" "$MARK_TEST"; do
        "ipt" -t mangle -D PREROUTING -p udp -m mark --mark "$m/$MARK_MASK" \
            -j TPROXY --on-port "$UDP_RELAY_PORT" --tproxy-mark "$TPROXY_MARK/$TPMASK" \
            >/dev/null 2>&1 || true
        if ! "ipt" -t mangle -A PREROUTING -p udp -m mark --mark "$m/$MARK_MASK" \
                -j TPROXY --on-port "$UDP_RELAY_PORT" --tproxy-mark "$TPROXY_MARK/$TPMASK" 2>/dev/null; then
            say "UDP relay: target TPROXY недоступен (нет модуля xt_TPROXY?) — UDP через XRay не пойдёт, TCP работает"
            return 0
        fi
    done
    say "udp-relay rules ready (port=$UDP_RELAY_PORT)"
}

tproxy_clean() {
    "ipt" -t nat -S PREROUTING 2>/dev/null | grep -- '-j REDIRECT --to-ports' | \
        grep -- '--mark 0x' | \
        while read -r line; do
            spec=$(printf '%s' "$line" | sed 's/^-A PREROUTING //')
            "ipt" -t nat -D PREROUTING $spec >/dev/null 2>&1 || true
        done || true
    "ipt" -t mangle -S PREROUTING 2>/dev/null | grep -- '-j TPROXY' | \
        while read -r line; do
            spec=$(printf '%s' "$line" | sed 's/^-A PREROUTING //')
            "ipt" -t mangle -D PREROUTING $spec >/dev/null 2>&1 || true
        done || true
    "$IPCMD" rule del fwmark "$TPROXY_MARK" priority "$((PRI_OK + 2))" lookup "$TABLE" >/dev/null 2>&1 || true
    "$IPCMD" route del local default dev lo table "$TABLE" >/dev/null 2>&1 || true
    "$IPCMD" rule del fwmark "$KERNEL_MARK/$KERNEL_MARK" lookup "$KERNEL_TABLE" >/dev/null 2>&1 || true
    "$IPCMD" route del default table "$KERNEL_TABLE" >/dev/null 2>&1 || true
}

# C3: блокировка IPv6 из LAN, чтобы клиенты уходили на IPv4
ipv6_block_rules() {
    if [ -n "$IP6T" ]; then
        for i in $LAN; do
            "$IP6T" -w -t filter -D FORWARD -i "$i" -j REJECT >/dev/null 2>&1 || true
        done
    fi
    [ "$IPV6_BLOCK" = "1" ] || return 0
    if [ -z "$IP6T" ]; then
        say "ipv6_block=1, но ip6tables не найден — пропускаю"
        return 0
    fi
    for i in $LAN; do
        "$IP6T" -w -t filter -A FORWARD -i "$i" -j REJECT
    done
    say "ipv6_block=1: IPv6 из LAN заблокирован (клиенты — по IPv4)"
}

ipv6_block_clean() {
    [ -n "$IP6T" ] || return 0
    for i in $LAN; do
        "$IP6T" -w -t filter -D FORWARD -i "$i" -j REJECT >/dev/null 2>&1 || true
    done
}

# QUIC (UDP 443) из LAN: запретить, чтобы приложения шли по TCP (QUIC через
# UDP-релей ненадёжен). Правило ставим в mangle PREROUTING ПЕРЕД цепочкой
# SUSANIN — иначе помеченный QUIC успеет уйти в TPROXY/релей. DROP → приложение
# перестаёт ждать QUIC и уходит на TCP. Всегда снимаем свои прошлые правила,
# чтобы при quic_block=0 ничего не оставалось.
quic_block_rules() {
    for i in $LAN; do
        "ipt" -t mangle -D PREROUTING -p udp -i "$i" --dport 443 -j DROP >/dev/null 2>&1 || true
        # убрать и старый (ошибочный) вариант правила из filter FORWARD
        "ipt" -t filter -D FORWARD -p udp -i "$i" --dport 443 -j REJECT >/dev/null 2>&1 || true
    done
    [ "$QUIC_BLOCK" = "1" ] || return 0
    for i in $LAN; do
        "ipt" -t mangle -I PREROUTING 1 -p udp -i "$i" --dport 443 -j DROP
    done
    say "quic_block=1: QUIC (UDP 443) из LAN запрещён (приложения — по TCP)"
}

quic_block_clean() {
    for i in $LAN; do
        "ipt" -t mangle -D PREROUTING -p udp -i "$i" --dport 443 -j DROP >/dev/null 2>&1 || true
        "ipt" -t filter -D FORWARD -p udp -i "$i" --dport 443 -j REJECT >/dev/null 2>&1 || true
    done
}

# MSS/PMTU clamping. Свои правила держим в ОТДЕЛЬНОЙ цепочке SUSANIN_MSS и
# НИКОГДА не трогаем чужие TCPMSS-правила в FORWARD (например, штатный MSS-clamp
# Keenetic для PPPoE): их удаление ведёт к PMTU-блэкхолу — крупные пакеты не
# проходят, страницы грузятся частично/не открываются.
# По умолчанию (MSS_CLAMP=0) мы вообще ничего не добавляем и ничего не удаляем.
# mss_clamp_lan=1 — применять ко всему LAN-forward, иначе только к нашим
# помеченным (VPN) потокам.
MSS_CHAIN=SUSANIN_MSS

mss_clamp_clean() {
    "ipt" -t mangle -D FORWARD -j "$MSS_CHAIN" >/dev/null 2>&1 || true
    "ipt" -t mangle -F "$MSS_CHAIN" >/dev/null 2>&1 || true
    "ipt" -t mangle -X "$MSS_CHAIN" >/dev/null 2>&1 || true
}

mss_clamp_rules() {
    mss_clamp_clean
    case "$MSS_CLAMP" in ''|0) return 0;; esac
    if [ "$MSS_CLAMP" = "pmtu" ] || [ "$MSS_CLAMP" = "auto" ]; then
        _tgt="--clamp-mss-to-pmtu"; _desc="pmtu"
    else
        case "$MSS_CLAMP" in
            *[!0-9]*) say "mss_clamp: некорректное значение '$MSS_CLAMP' — пропускаю"; return 0;;
        esac
        _tgt="--set-mss $MSS_CLAMP"; _desc="$MSS_CLAMP"
    fi
    "ipt" -t mangle -N "$MSS_CHAIN" 2>/dev/null || true
    "ipt" -t mangle -F "$MSS_CHAIN" 2>/dev/null || true
    if [ "$MSS_CLAMP_LAN" = "1" ]; then
        for i in $LAN; do
            if ! "ipt" -t mangle -A "$MSS_CHAIN" -i "$i" -p tcp --tcp-flags SYN,RST SYN \
                    -j TCPMSS $_tgt 2>/dev/null; then
                say "mss_clamp: цель TCPMSS недоступна (модуль?) — пропускаю"
                mss_clamp_clean; return 0
            fi
        done
    else
        # Только помеченные (VPN) потоки. Клампим по CONNMARK, а не по skb-метке:
        # skb-метка ставится на входе из LAN, поэтому SYN-ACK с туннеля раньше не
        # клампился — а именно он задаёт размер отдачи клиента в туннель.
        # Плюс метки профилей (0x40000000/0x08000000/…): раньше профильный трафик
        # шёл вообще без клампа (метка профиля не входит в mark_mask).
        _mss_marks="$MARK_OK $MARK_TEST"
        _pi=1
        while [ "$_pi" -le 4 ]; do
            _pm=$(cfg_val "profile${_pi}_mark" "")
            if [ -z "$_pm" ]; then
                case "$_pi" in
                    1) _pm=0x40000000 ;; 2) _pm=0x08000000 ;;
                    3) _pm=0x04000000 ;; 4) _pm=0x02000000 ;;
                esac
            fi
            _mss_marks="$_mss_marks $_pm"
            _pi=$((_pi + 1))
        done
        _cm_ok=1
        for m in $_mss_marks; do
            case "$m" in
                "$MARK_OK"|"$MARK_TEST") _msk=$MARK_MASK ;;
                *) _msk=$m ;;
            esac
            if ! "ipt" -t mangle -A "$MSS_CHAIN" -p tcp --tcp-flags SYN,RST SYN \
                    -m connmark --mark "$m/$_msk" -j TCPMSS $_tgt 2>/dev/null; then
                _cm_ok=0
                break
            fi
        done
        if [ "$_cm_ok" = "0" ]; then
            # Ядро без xt_connmark — остаёмся на прежнем поведении (skb-метка).
            "ipt" -t mangle -F "$MSS_CHAIN" 2>/dev/null || true
            for m in "$MARK_OK" "$MARK_TEST"; do
                if ! "ipt" -t mangle -A "$MSS_CHAIN" -p tcp --tcp-flags SYN,RST SYN \
                        -m mark --mark "$m/$MARK_MASK" -j TCPMSS $_tgt 2>/dev/null; then
                    say "mss_clamp: цель TCPMSS недоступна (модуль?) — пропускаю"
                    mss_clamp_clean; return 0
                fi
            done
        fi
    fi
    if ! "ipt" -t mangle -A FORWARD -j "$MSS_CHAIN" 2>/dev/null; then
        say "mss_clamp: не удалось встроить цепочку $MSS_CHAIN — пропускаю"
        mss_clamp_clean; return 0
    fi
    say "mss_clamp=$_desc (lan=$MSS_CLAMP_LAN)"
}

# Профили: RETURN для адресов профилей в НАШЕЙ цепочке. datapath пересобирает
# SUSANIN (в т.ч. после пересборки netfilter силами NDM), поэтому правила
# профилей восстанавливаем и здесь — иначе профиль молча перестаёт срабатывать
# до следующего `profiles.sh up`. Наборы профилей узнаём по имени.
profiles_return_rules() {
    [ -n "$IPSET" ] || return 0
    _sets=$("$IPSET" list -n 2>/dev/null | grep '^susanin_prof_' || true)
    [ -n "$_sets" ] || return 0
    for _ps in $_sets; do
        "ipt" -t mangle -D "$CHAIN" -m set --match-set "$_ps" dst -j RETURN >/dev/null 2>&1 || true
        "ipt" -t mangle -I "$CHAIN" -m set --match-set "$_ps" dst -j RETURN >/dev/null 2>&1 || true
    done
}

# FORWARD: политика Keenetic по умолчанию DROP. Метка Susanin ставится в mangle
# PREROUTING, но клиенты серверных VPN (oc+, wdtt+) не имеют разрешения в
# интерфейс «Дополнительного подключения»: пакет умирает в filter/FORWARD, в
# conntrack поток есть, а в POSTROUTING на egress — 0 пакетов. Поэтому разрешаем
# ТОЛЬКО свои метки: трафик уже отфильтрован цепочкой SUSANIN, чужие правила и
# политики NDM не затрагиваются. В tproxy-режиме правило безвредно (трафик не
# форвардится, а уходит в локальный Xray), поэтому ставим его всегда — так после
# смены режима не остаётся «дыры».
_fwd_mark_list() {
    _fl="$MARK_OK/$MARK_MASK $MARK_TEST/$MARK_MASK"
    _pi=1
    while [ "$_pi" -le 4 ]; do
        _pm=$(cfg_val "profile${_pi}_mark" "")
        if [ -z "$_pm" ]; then
            case "$_pi" in
                1) _pm=0x40000000 ;; 2) _pm=0x08000000 ;;
                3) _pm=0x04000000 ;; 4) _pm=0x02000000 ;;
            esac
        fi
        _fl="$_fl $_pm/$_pm"
        _pi=$((_pi + 1))
    done
    if [ "$KERNEL_OFFLOAD" = "1" ] && [ -n "$KERNEL_EGRESS" ]; then
        _fl="$_fl $KERNEL_MARK/$KERNEL_MARK"
    fi
    printf '%s' "$_fl"
}

forward_accept_clean() {
    for _fm in $(_fwd_mark_list); do
        "ipt" -t filter -D FORWARD -m mark --mark "$_fm" -j ACCEPT >/dev/null 2>&1 || true
    done
}

forward_accept_rules() {
    forward_accept_clean
    for _fm in $(_fwd_mark_list); do
        if ! "ipt" -t filter -I FORWARD 1 -m mark --mark "$_fm" -j ACCEPT 2>/dev/null; then
            say "FORWARD ACCEPT для метки $_fm не добавлен (нет xt_mark?) — клиенты серверных VPN могут не ходить в туннель"
        fi
    done
}

# T3: DNS клиентов СЕРВЕРНЫХ VPN (oc+/wdtt+), а не всего LAN. Android/Chrome
# шлют DNS на 8.8.8.8, а Keenetic-сервер OpenConnect не форсирует «весь DNS в
# туннель» (X-CSTP-Tunnel-All-DNS: false) — запросы уходят наружу, режутся,
# клиент получает NXDOMAIN. ВАЖНО: br0/br1 не трогаем — иначе перехватим DNS
# у AdGuard Home/своего резолвера в другом сегменте. Правила ставим только на
# интерфейсы серверных VPN и только для НЕ-приватных адресов назначения.
_dns_hijack_dest() {
    _dst="$DNS_HIJACK_TARGET"
    if [ -z "$_dst" ]; then
        for _i in $LAN; do
            _a=$("$IPCMD" -4 -o addr show dev "$_i" 2>/dev/null | \
                 awk '$3 == "inet" { sub(/\/.*/, "", $4); print $4; exit }')
            [ -n "$_a" ] && { _dst="$_a:53"; break; }
        done
    fi
    case "$_dst" in
        ''|*:*) printf '%s' "$_dst" ;;
        *) printf '%s:53' "$_dst" ;;
    esac
}

# Интерфейсы серверных VPN — только те, что реально в lan_interfaces (иначе мы
# их трафик не метим, и перехват DNS был бы неожиданным). Существование
# интерфейса НЕ проверяем: клиент OpenConnect создаёт ocN только в момент
# подключения, а `-i oc+` — валидный шаблон и без единого oc*. Правило ставится
# заранее и начинает работать, когда клиент подключится.
# Сравниваем по префиксу имени, а не по подстроке: `vpn_ocean0` — не `oc*`.
_dns_hijack_ifaces() {
    _out=""
    _want_wdtt=0
    for _i in $(printf '%s' "$LAN" | tr ',' ' '); do
        case "$_i" in
            oc|oc+|oc[0-9]*)           _add=oc+ ;;
            wdtt0|wdtt+|wdtt[0-9]*)    _add=$_i; _want_wdtt=1 ;;
            wdttraw0|wdttraw[0-9]*)    _add=$_i; _want_wdtt=1 ;;
            *)                         continue ;;
        esac
        case " $_out " in
            *" $_add "*) ;;
            *) _out="$_out $_add" ;;
        esac
    done
    # qWDTT держит пару интерфейсов; если в LAN есть один — нужен и второй.
    if [ "$_want_wdtt" = "1" ]; then
        for _i in wdtt0 wdttraw0; do
            case " $_out " in
                *" $_i "*) ;;
                *) _out="$_out $_i" ;;
            esac
        done
    fi
    printf '%s' "$_out" | sed 's/^ *//'
}

# Метка наших правил: по ней ищем/удаляем и проверяем готовность датаплейна.
# iptables не допускает больше одного `-d` в правиле («multiple -d flags not
# allowed»), поэтому приватные сети исключаем отдельными RETURN-правилами ДО
# DNAT, а не тремя `! -d` в одном правиле.
DNS_HIJACK_COMMENT=susanin-dns
DNS_HIJACK_PRIVATE="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"

dns_hijack_clean() {
    "ipt" -t nat -S PREROUTING 2>/dev/null | grep -F -- "$DNS_HIJACK_COMMENT" | \
        while IFS= read -r _line; do
            _spec=$(printf '%s' "$_line" | sed 's/^-A PREROUTING //')
            "ipt" -t nat -D PREROUTING $_spec >/dev/null 2>&1 || true
        done || true
}

dns_hijack_rules() {
    dns_hijack_clean
    [ "$DNS_HIJACK" = "1" ] || return 0
    _dst=$(_dns_hijack_dest)
    if [ -z "$_dst" ]; then
        say "dns_hijack=1, но не определён адрес резолвера — пропускаю"
        return 0
    fi
    _ifaces=$(_dns_hijack_ifaces)
    if [ -z "$_ifaces" ]; then
        say "dns_hijack=1, но в lan_interfaces нет oc+/wdtt+ — пропускаю"
        return 0
    fi
    _n=0
    for _i in $_ifaces; do
        for _p in udp tcp; do
            # Ставим В НАЧАЛО PREROUTING (-I 1): у Keenetic в nat PREROUTING
            # могут быть свои ранние терминальные правила (jump/RETURN), из-за
            # которых DNAT в конце цепочки не сработал бы. Порядок вставки:
            # сначала DNAT, затем RETURN-исключения — каждый на позицию 1, в
            # итоге RETURN'ы оказываются выше DNAT.
            if "ipt" -t nat -I PREROUTING 1 -i "$_i" -p "$_p" --dport 53 \
                   -m comment --comment "$DNS_HIJACK_COMMENT" \
                   -j DNAT --to-destination "$_dst" 2>/dev/null; then
                _n=$((_n + 1))
            else
                say "dns_hijack: не удалось добавить $_p/53 для $_i (нет xt_comment?)"
                continue
            fi
            # Приватные адреса назначения (свой DNS/AdGuard в LAN) не трогаем:
            # RETURN срабатывает раньше DNAT.
            for _net in $DNS_HIJACK_PRIVATE; do
                "ipt" -t nat -I PREROUTING 1 -i "$_i" -p "$_p" --dport 53 \
                    -d "$_net" -m comment --comment "$DNS_HIJACK_COMMENT" \
                    -j RETURN >/dev/null 2>&1 || true
            done
        done
    done
    if [ "$_n" -eq 0 ]; then
        say "dns_hijack=1, но правила не добавлены — фича не работает (проверьте xt_comment/nat)"
        return 0
    fi
    say "dns_hijack: DNS клиентов ($_ifaces) -> $_dst (правил DNAT: $_n)"
}

# ══ P5: сторонний прокси на роутере (Teleproxy/MTProxy) ═══════════════════
# Исходящие соединения процесса с uid PROXY_UID уходят в PROXY_EGRESS
# (обычно nwg0) через отдельную таблицу, не задевая LAN-маршрутизацию:
#   1) mangle OUTPUT: -m owner --uid-owner UID -j MARK --set-xmark MARK/MARK
#   2) ip rule fwmark MARK/MARK -> lookup PROXY_TABLE
#   3) ip route default dev PROXY_EGRESS table PROXY_TABLE
# PROXY_TABLE должна быть выделенной (по умолчанию 110): при down она
# очищается целиком.
proxy_egress_rules() {
    [ -n "$PROXY_UID" ] || return 0
    if [ -z "$PROXY_EGRESS" ]; then
        say "proxy_uid=$PROXY_UID, но proxy_egress пуст — пропускаю"
        return 0
    fi
    if ! "$IPCMD" route replace default dev "$PROXY_EGRESS" table "$PROXY_TABLE" 2>/dev/null; then
        say "proxy_uid: маршрут через $PROXY_EGRESS в таблицу $PROXY_TABLE не добавлен (интерфейс поднят?)"
        return 0
    fi
    "$IPCMD" rule del fwmark "$PROXY_MARK/$PROXY_MARK" lookup "$PROXY_TABLE" >/dev/null 2>&1 || true
    if ! "$IPCMD" rule add fwmark "$PROXY_MARK/$PROXY_MARK" priority "$PRI_PROXY" lookup "$PROXY_TABLE" 2>/dev/null; then
        say "proxy_uid: ip rule fwmark $PROXY_MARK -> $PROXY_TABLE не добавлен"
        return 0
    fi
    proxy_egress_mark_clean
    if ! "ipt" -t mangle -A OUTPUT -m owner --uid-owner "$PROXY_UID" \
            -j MARK --set-xmark "$PROXY_MARK/$PROXY_MARK" 2>/dev/null; then
        say "proxy_uid: не удалось поставить метку по uid (нет xt_owner?)"
        return 0
    fi
    say "proxy egress: uid=$PROXY_UID -> $PROXY_EGRESS (table=$PROXY_TABLE mark=$PROXY_MARK prio=$PRI_PROXY)"
}

# Снять ТОЛЬКО свои правила метки в OUTPUT (по строке set-xmark).
proxy_egress_mark_clean() {
    "ipt" -t mangle -S OUTPUT 2>/dev/null | grep -F -- "--set-xmark $PROXY_MARK_HEX/$PROXY_MARK_HEX" | \
        while IFS= read -r _l; do
            _sp=$(printf '%s' "$_l" | sed 's/^-A OUTPUT //')
            "ipt" -t mangle -D OUTPUT $_sp >/dev/null 2>&1 || true
        done || true
}

proxy_egress_clean() {
    proxy_egress_mark_clean
    "$IPCMD" rule del fwmark "$PROXY_MARK/$PROXY_MARK" lookup "$PROXY_TABLE" >/dev/null 2>&1 || true
    "$IPCMD" route flush table "$PROXY_TABLE" >/dev/null 2>&1 || true
}

command_up() {
    backup
    ensure_sets
    ensure_chain
    rule_priv
    rule_mark
    profiles_return_rules
    ensure_jump
    ensure_table
    forward_accept_rules
    dns_hijack_rules
    ipv6_block_rules
    quic_block_rules
    mss_clamp_rules
    proxy_egress_rules
    say "data plane UP (table=$TABLE dev=$EGRESS mask=$MARK_MASK)"
}

command_down() {
    "ipt" -t mangle -D PREROUTING -j "$CHAIN" >/dev/null 2>&1 || true
    if "ipt" -t mangle -S "$CHAIN" >/dev/null 2>&1; then
        "ipt" -t mangle -F "$CHAIN" 2>/dev/null || true
        "ipt" -t mangle -X "$CHAIN" 2>/dev/null || true
    fi
    for s in $SETS; do set_exists "$s" && "$IPSET" destroy "$s" || true; done
    set_exists "$NETSET" && "$IPSET" destroy "$NETSET" || true
    set_exists "$NEVERSET" && "$IPSET" destroy "$NEVERSET" || true
    set_exists "$DIRECTSET" && "$IPSET" destroy "$DIRECTSET" || true
    iprule_fw_clean "$MARK_OK" "$PRI_OK"
    iprule_fw_clean "$MARK_TEST" "$PRI_TEST"
    "$IPCMD" rule del fwmark "$TPROXY_MARK" priority "$((PRI_OK + 2))" lookup "$TABLE" >/dev/null 2>&1 || true
    "$IPCMD" route del default dev "$EGRESS" table "$TABLE" >/dev/null 2>&1 || true
    "$IPCMD" route del local default dev lo table "$TABLE" >/dev/null 2>&1 || true
    "$IPCMD" route flush table "$TABLE" >/dev/null 2>&1 || true
    tproxy_clean || true
    forward_accept_clean || true
    dns_hijack_clean || true
    ipv6_block_clean || true
    quic_block_clean || true
    mss_clamp_clean || true
    # P5 (трафик стороннего прокси -> proxy_egress) НЕ снимаем здесь: он не
    # зависит от tproxy/Xray и должен переживать fail-open, когда Xray умер.
    # Снимается явно командой `datapath.sh p5-down` (susanin stop / down).
    say "data plane DOWN"
}

command_status() {
    if "ipt" -t mangle -S PREROUTING >/dev/null 2>&1 && "ipt" -t mangle -S PREROUTING | grep -q "$CHAIN"; then
        echo "jump: present"
    else
        echo "jump: MISSING"
    fi
    for s in $SETS; do
        if set_exists "$s"; then
            echo "$s = $("$IPSET" list "$s" 2>/dev/null | grep -cE '^[0-9]+\.' || true)"
        else
            echo "$s = (absent)"
        fi
    done
    if set_exists "$NETSET"; then
        echo "$NETSET = $("$IPSET" list "$NETSET" 2>/dev/null | grep -cE '^[0-9]+\.' || true)"
    else
        echo "$NETSET = (absent)"
    fi
    if set_exists "$NEVERSET"; then
        echo "$NEVERSET = $("$IPSET" list "$NEVERSET" 2>/dev/null | grep -cE '^[0-9]+\.' || true)"
    else
        echo "$NEVERSET = (absent)"
    fi
    if set_exists "$DIRECTSET"; then
        echo "$DIRECTSET = $("$IPSET" list "$DIRECTSET" 2>/dev/null | grep -cE '^[0-9]+\.' || true)"
    else
        echo "$DIRECTSET = (absent)"
    fi
    "$IPCMD" rule show | grep -E "lookup $TABLE" || echo "no ip rule for table $TABLE"
    _fa=0
    _fan=0
    if "ipt" -t filter -S FORWARD >/dev/null 2>&1; then
        for _fm in $(_fwd_mark_list); do
            _fan=$((_fan + 1))
            if "ipt" -t filter -S FORWARD 2>/dev/null | grep -q -- "-m mark --mark $_fm -j ACCEPT"; then
                _fa=$((_fa + 1))
            fi
        done
    fi
    echo "forward_accept: rules=$_fa/$_fan (метки ok/test/профили — нужны клиентам серверных VPN: oc+/wdtt+)"
    # Считаем только НАШИ правила (по comment-метке), а не любой DNAT 53.
    _dh=$("ipt" -t nat -S PREROUTING 2>/dev/null | grep -cF -- "$DNS_HIJACK_COMMENT" || true)
    if [ "$DNS_HIJACK" = "1" ]; then
        echo "dns_hijack: on (серверные VPN: $(_dns_hijack_ifaces) -> $(_dns_hijack_dest); наших правил=$_dh)"
    elif [ "${_dh:-0}" -gt 0 ] 2>/dev/null; then
        echo "dns_hijack: 0 в конфиге, но наши правила DNAT 53 остались ($_dh) — снимутся при следующем up/down"
    else
        echo "dns_hijack: off"
    fi
    if [ "${TPROXY_PORT:-0}" -gt 0 ] 2>/dev/null; then
        n=$("ipt" -t nat -S PREROUTING 2>/dev/null | grep -c 'REDIRECT --to-ports' || true)
        echo "redirect: port=$TPROXY_PORT rules=$n"
    fi
    if [ "${UDP_RELAY_PORT:-0}" -gt 0 ] 2>/dev/null; then
        u=$("ipt" -t mangle -S PREROUTING 2>/dev/null | grep -c "TPROXY --on-port $UDP_RELAY_PORT" || true)
        echo "udp-relay: port=$UDP_RELAY_PORT rules=$u"
    fi
    if [ "$IPV6_BLOCK" = "1" ]; then
        if [ -n "$IP6T" ]; then
            v6=$("$IP6T" -w -t filter -S FORWARD 2>/dev/null | grep -c -- '-j REJECT' || true)
            echo "ipv6_block: on (FORWARD REJECT rules=$v6)"
        else
            echo "ipv6_block: задан (=1), но ip6tables не найден — IPv6 из LAN не блокируется"
        fi
    fi
    if [ "$KERNEL_OFFLOAD" = "1" ] && [ -n "$KERNEL_EGRESS" ]; then
        ko=$("$IPCMD" rule show 2>/dev/null | grep -c "lookup $KERNEL_TABLE" || true)
        echo "kernel_offload: on ($KERNEL_EGRESS table=$KERNEL_TABLE rules=$ko)"
    fi
    if [ -n "$PROXY_UID" ] && [ -n "$PROXY_EGRESS" ]; then
        _pm=$("ipt" -t mangle -S OUTPUT 2>/dev/null | grep -cF -- "--set-xmark $PROXY_MARK_HEX/$PROXY_MARK_HEX" || true)
        _pr=$("$IPCMD" rule show 2>/dev/null | grep -c "lookup $PROXY_TABLE" || true)
        _prt=$("$IPCMD" route show table "$PROXY_TABLE" 2>/dev/null | grep -c '^default' || true)
        echo "proxy_egress: on (uid=$PROXY_UID -> $PROXY_EGRESS table=$PROXY_TABLE mark=$PROXY_MARK; mark_rules=$_pm ip_rule=$_pr default_route=$_prt)"
    elif [ -n "$PROXY_UID" ]; then
        echo "proxy_egress: proxy_uid задан, но proxy_egress пуст — выключено"
    else
        echo "proxy_egress: off"
    fi
    q=$("ipt" -t mangle -S PREROUTING 2>/dev/null | grep -c -- '-p udp .* --dport 443 -j DROP' || true)
    if [ "$QUIC_BLOCK" = "1" ]; then
        echo "quic_block: on (mangle PREROUTING DROP rules=$q; HTTP/3 из LAN идёт по TCP)"
    elif [ "${q:-0}" -gt 0 ] 2>/dev/null; then
        echo "quic_block: 0 в конфиге, но остались правила ($q) — снимутся при следующем up/down"
    else
        echo "quic_block: off (QUIC/HTTP/3 из LAN разрешён; в tproxy-режиме браузеры могут «висеть»)"
    fi
    if "ipt" -t mangle -L "$MSS_CHAIN" >/dev/null 2>&1; then
        if [ -n "$MSS_CLAMP" ] && [ "$MSS_CLAMP" != "0" ]; then
            echo "mss_clamp: on ($MSS_CLAMP, lan=$MSS_CLAMP_LAN, chain=$MSS_CHAIN)"
        else
            echo "mss_clamp: off, цепочка $MSS_CHAIN есть (своих правил нет)"
        fi
    elif [ -n "$MSS_CLAMP" ] && [ "$MSS_CLAMP" != "0" ]; then
        echo "mss_clamp: задан ($MSS_CLAMP), но цепочки $MSS_CHAIN нет"
    fi
}

command_egress() {
    iface="$1"
    [ -n "$iface" ] || { echo "usage: $0 egress <iface>" >&2; exit 2; }
    if [ "${TPROXY_PORT:-0}" -gt 0 ] 2>/dev/null; then
        say "tproxy mode: egress switch ignored (table=$TABLE stays local)"
        return 0
    fi
    "$IPCMD" route del default table "$TABLE" >/dev/null 2>&1 || true
    "$IPCMD" route add default dev "$iface" table "$TABLE"
    say "egress -> $iface (table=$TABLE)"
}

command_flush() {
    for s in $SETS; do set_exists "$s" && "$IPSET" flush "$s" || true; done
    set_exists "$NETSET" && "$IPSET" flush "$NETSET" || true
    set_exists "$NEVERSET" && "$IPSET" flush "$NEVERSET" || true
    say "sets flushed (fail-open / DIRECT)"
}

command_add() {
    # Допустимы обе формы: «add <ip> <tcp|udp> <test|ok>» и
    # «add <ip> <port> <tcp|udp> <test|ok>». Во второй форме порт используется
    # только при port_aware=1 (иначе игнорируется) — так агент может передавать
    # порт всегда, не зная о режиме.
    ip="$1"; p="$2"; ph="$3"
    case "${2:-}" in
        ''|*[!0-9]*) ;;                 # не число -> форма без порта
        *) ip="$1"; port="$2"; p="$3"; ph="$4" ;;
    esac
    case "$p" in tcp|udp) ;; *) echo "bad proto: $p" >&2; exit 2;; esac
    case "$ph" in test|ok) ;; *) echo "bad phase: $ph" >&2; exit 2;; esac
    ensure_sets
    ttl=$TTL_TEST; [ "$ph" = ok ] && ttl=$TTL_OK
    if [ "$PORT_AWARE" = "1" ]; then
        case "${port:-}" in
            ''|*[!0-9]*) echo "port_aware=1: нужен порт (add <ip> <port> <tcp|udp> <test|ok>)" >&2; exit 2 ;;
        esac
        # Протокол в элементе обязателен: в hash:ip,port элемент без него
        # считается TCP, и UDP-пакет с ним не совпадёт.
        "$IPSET" -exist add "susanin_${ph}_${p}" "$ip,$p:$port" timeout "$ttl"
        say "added $ip,$p:$port -> susanin_${ph}_${p} (timeout ${ttl}s)"
        return 0
    fi
    "$IPSET" -exist add "susanin_${ph}_${p}" "$ip" timeout "$ttl"
    say "added $ip -> susanin_${ph}_${p} (timeout ${ttl}s)"
}

command_del() {
    ip="$1"; p="$2"
    case "${2:-}" in
        ''|*[!0-9]*) ;;
        *) ip="$1"; port="$2"; p="$3" ;;
    esac
    case "$p" in tcp|udp) ;; *) echo "bad proto: $p" >&2; exit 2;; esac
    _val="$ip"
    if [ "$PORT_AWARE" = "1" ]; then
        case "${port:-}" in
            ''|*[!0-9]*) echo "port_aware=1: нужен порт (del <ip> <port> <tcp|udp>)" >&2; exit 2 ;;
        esac
        _val="$ip,$p:$port"
    fi
    for s in "susanin_test_${p}" "susanin_ok_${p}"; do
        set_exists "$s" && "$IPSET" -exist del "$s" "$_val" >/dev/null 2>&1 || true
    done
    say "deleted $_val ($p)"
}

case "${1:-}" in
    up) command_up ;;
    p5) proxy_egress_rules ;;
    p5-down) proxy_egress_clean ;;
    down) command_down ;;
    status) command_status ;;
    flush) command_flush ;;
    egress) command_egress "${2:-}" ;;
    add) command_add "${2:-}" "${3:-}" "${4:-}" "${5:-}" ;;
    del) command_del "${2:-}" "${3:-}" "${4:-}" ;;
    *)
        echo "usage: $0 {up|down|p5|p5-down|status|flush|egress <iface>|add <ip> [<port>] <tcp|udp> <test|ok>|del <ip> [<port>] <tcp|udp>}" >&2
        echo "  (порт обязателен при SUSANIN_PORT_AWARE=1; ok_net/never/direct всегда по адресу)" >&2
        exit 2 ;;
esac
