#!/bin/sh
# profiles.sh — статические профили маршрутизации (P1, экспериментально).
#
# Профиль = список (домены / IP / CIDR) -> свой egress-туннель.
# Задаётся в /opt/susanin/etc/susanin.conf повторяющимися ключами:
#   profile1_name=cdn
#   profile1_egress=nwg1
#   profile1_list=/opt/susanin/etc/profiles/cdn.txt
#   profile1_table=201          # опционально (по умолчанию 201..204)
#   profile1_mark=0x40000000    # опционально
# ... до profile4_*.
#
# Профили — отдельный слой поверх Susanin.Keenetic: своя цепочка SUSANIN_PROFILES в
# mangle PREROUTING (в конце, после SUSANIN), свои метки (0x40000000 и т.п.) и
# таблицы (201..204). Если профилей нет — ничего не делает.
#
# Usage: profiles.sh {up|down|status}
set -u

CONF="${SUSANIN_CONF:-/opt/susanin/etc/susanin.conf}"
SETPFX="susanin_prof_"
CHAIN="SUSANIN_PROFILES"
MAXP=4

cfg() { sed -n "s/^$1=[ \t]*//p" "$CONF" 2>/dev/null | head -n1; }
have() { command -v "$1" >/dev/null 2>&1; }
IPSET=$(have ipset && echo ipset || echo /opt/sbin/ipset)
IPT=$(have iptables && echo iptables || echo /opt/sbin/iptables)
IPB=$(have ip && echo ip || echo /opt/sbin/ip)

san() { printf '%s' "$1" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9_'; }
is_ip4()  { printf '%s' "$1" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; }
is_cidr() { printf '%s' "$1" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$'; }

resolv() { # domain -> IPv4
    nslookup "$1" 2>/dev/null | awk '
        /^Name:/ { f = 1; next }
        f && /^Address/ {
            for (i = 1; i <= NF; i++)
                if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { print $i; break }
        }'
}

prof_name() { cfg "profile$1_name"; }

fill_set() { # set listfile
    _s="$1"; _f="$2"
    [ -n "$_f" ] && [ -f "$_f" ] || return 0
    while IFS= read -r _raw; do
        _e=$(printf '%s' "$_raw" | sed 's/#.*//' | tr -d ' \t\r')
        [ -z "$_e" ] && continue
        if is_ip4 "$_e" || is_cidr "$_e"; then
            "$IPSET" add "$_s" "$_e" -exist 2>/dev/null || true
        else
            _d=$(printf '%s' "$_e" | sed 's/^\*\.//')
            for _ip in $(resolv "$_d"); do
                "$IPSET" add "$_s" "$_ip" -exist 2>/dev/null || true
            done
        fi
    done < "$_f"
}

count_profiles() {
    _n=0; _i=1
    while [ "$_i" -le "$MAXP" ]; do
        [ -n "$(prof_name "$_i")" ] && _n=$((_n + 1))
        _i=$((_i + 1))
    done
    echo "$_n"
}

up() {
    _n=$(count_profiles)
    if [ "$_n" -eq 0 ]; then
        echo "[profiles] профили не заданы"
        down >/dev/null 2>&1 || true
        return 0
    fi
    "$IPT" -t mangle -N "$CHAIN" 2>/dev/null || true
    "$IPT" -t mangle -F "$CHAIN" 2>/dev/null || true

    _i=1
    while [ "$_i" -le "$MAXP" ]; do
        _nm=$(prof_name "$_i")
        if [ -z "$_nm" ]; then _i=$((_i + 1)); continue; fi
        _eg=$(cfg "profile${_i}_egress")
        _lf=$(cfg "profile${_i}_list")
        _tb=$(cfg "profile${_i}_table"); [ -n "$_tb" ] || _tb=$((200 + _i))
        _mk=$(cfg "profile${_i}_mark");   [ -n "$_mk" ] || _mk=0x40000000
        _sn="$SETPFX$(san "$_nm")"

        "$IPSET" create "$_sn" hash:net timeout 0 -exist 2>/dev/null || true
        "$IPSET" flush "$_sn" 2>/dev/null || true
        fill_set "$_sn" "$_lf"

        if [ -n "$_eg" ] && [ -e "/sys/class/net/$_eg" ]; then
            "$IPB" route replace default dev "$_eg" table "$_tb" 2>/dev/null || true
            "$IPB" rule del fwmark "$_mk" lookup "$_tb" 2>/dev/null || true
            "$IPB" rule add fwmark "$_mk" lookup "$_tb" 2>/dev/null || true
        fi
        "$IPT" -t mangle -A "$CHAIN" -m set --match-set "$_sn" dst \
               -m mark --mark 0x0 -j MARK --set-mark "$_mk" 2>/dev/null || true
        _i=$((_i + 1))
    done

    "$IPT" -t mangle -C PREROUTING -j "$CHAIN" 2>/dev/null \
        || "$IPT" -t mangle -A PREROUTING -j "$CHAIN" 2>/dev/null || true
    echo "[profiles] up: $_n профил(ей)"
}

down() {
    "$IPT" -t mangle -D PREROUTING -j "$CHAIN" 2>/dev/null || true
    "$IPT" -t mangle -F "$CHAIN" 2>/dev/null || true
    "$IPT" -t mangle -X "$CHAIN" 2>/dev/null || true
    _i=1
    while [ "$_i" -le "$MAXP" ]; do
        _nm=$(prof_name "$_i")
        if [ -z "$_nm" ]; then _i=$((_i + 1)); continue; fi
        _tb=$(cfg "profile${_i}_table"); [ -n "$_tb" ] || _tb=$((200 + _i))
        _mk=$(cfg "profile${_i}_mark");   [ -n "$_mk" ] || _mk=0x40000000
        _sn="$SETPFX$(san "$_nm")"
        "$IPB" rule del fwmark "$_mk" lookup "$_tb" 2>/dev/null || true
        "$IPB" route flush table "$_tb" 2>/dev/null || true
        "$IPSET" destroy "$_sn" 2>/dev/null || true
        _i=$((_i + 1))
    done
    echo "[profiles] down"
}

status() {
    echo "chain $CHAIN: $("$IPT" -t mangle -S "$CHAIN" >/dev/null 2>&1 && echo ok || echo НЕТ)"
    _i=1
    while [ "$_i" -le "$MAXP" ]; do
        _nm=$(prof_name "$_i")
        if [ -z "$_nm" ]; then _i=$((_i + 1)); continue; fi
        _eg=$(cfg "profile${_i}_egress")
        _tb=$(cfg "profile${_i}_table"); [ -n "$_tb" ] || _tb=$((200 + _i))
        _mk=$(cfg "profile${_i}_mark");   [ -n "$_mk" ] || _mk=0x40000000
        _sn="$SETPFX$(san "$_nm")"
        _c=$("$IPSET" list "$_sn" 2>/dev/null | grep -cE '^[0-9]+\.')
        echo "  $_nm: egress=${_eg:-?} table=$_tb mark=$_mk set=$_sn entries=${_c:-0}"
    done
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    status) status ;;
    *) echo "usage: $0 {up|down|status}"; exit 2 ;;
esac
