#!/bin/sh
# profiles.sh — статические профили маршрутизации (P1, экспериментально).
#
# Профиль = список (домены / IP / CIDR) -> свой egress-туннель.
# Задаётся в /opt/susanin/etc/susanin.conf повторяющимися ключами:
#   profile1_name=cdn
#   profile1_egress=nwg1
#   profile1_egress=nwg0,nwg1   # можно списком — берётся первый живой
#   profile1_list=/opt/susanin/etc/profiles/cdn.txt
#   profile1_geo_url=https://... # P3: скачиваемый CIDR-список (кэш в var/profiles/)
#   profile1_table=201          # опционально (по умолчанию 201..204)
#   profile1_mark=0x40000000    # опционально
# ... до profile4_*.
#
# Профили — отдельный слой поверх Susanin.Keenetic: своя цепочка SUSANIN_PROFILES в
# mangle PREROUTING (в конце, после SUSANIN), свои метки (0x40000000 и т.п.) и
# таблицы (201..204). Если профилей нет — ничего не делает.
#
# Usage: profiles.sh {up|down|status|refresh}
#   refresh — перечитать файлы-списки и geo_url, не пересобирая правила.
set -u

CONF="${SUSANIN_CONF:-/opt/susanin/etc/susanin.conf}"
VARDIR="${SUSANIN_VAR:-/opt/susanin/var}"
SETPFX="susanin_prof_"
CHAIN="SUSANIN_PROFILES"
MAXP=4

cfg() { sed -n "s/^$1=[ \t]*//p" "$CONF" 2>/dev/null | head -n1; }
have() { command -v "$1" >/dev/null 2>&1; }

# P2: профили можно задавать и файлами profiles.d/<name>.conf (один профиль на
# файл). Собираем «слитый» конфиг profileN_* (susanin.conf + profiles.d), чтобы
# дальше работать единообразно. Ключи файла: name, egress, list, geo_url, table,
# mark, auto.
MERGED="${TMPDIR:-/tmp}/susanin-profiles.$$.conf"
CONF_ORIG="$CONF"
build_merged() {
    : > "$MERGED"
    grep -E '^profile[0-9]+_' "$CONF_ORIG" 2>/dev/null >> "$MERGED" || true
    PD_DIR="${SUSANIN_PROFILES_DIR:-/opt/susanin/etc/profiles.d}"
    if [ -d "$PD_DIR" ]; then
        _n=$(grep -cE '^profile[0-9]+_name=' "$MERGED" 2>/dev/null || true)
        case "$_n" in ''|*[!0-9]*) _n=0;; esac
        for _f in "$PD_DIR"/*.conf; do
            [ -f "$_f" ] || continue
            _n=$((_n + 1))
            [ "$_n" -gt "$MAXP" ] && break
            _nm=$(sed -n 's/^name=[ \t]*//p' "$_f" 2>/dev/null | head -n1)
            [ -n "$_nm" ] || _nm=$(basename "$_f" .conf)
            printf 'profile%d_name=%s\n' "$_n" "$_nm" >> "$MERGED"
            for _k in egress list geo_url table mark auto; do
                _v=$(sed -n "s/^${_k}=[ \t]*//p" "$_f" 2>/dev/null | head -n1)
                [ -n "$_v" ] && printf 'profile%d_%s=%s\n' "$_n" "$_k" "$_v" >> "$MERGED"
            done
        done
    fi
}
build_merged
CONF="$MERGED"
trap 'rm -f "$MERGED"' EXIT INT TERM

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

# P3: гео-базы — скачиваемый CIDR-список профиля (profileN_geo_url). Кэш
# хранится в var/profiles/<имя>.txt; при отсутствии сети используем прошлый кэш.
fetch_url() { # url outfile
    _u="$1"; _o="$2"
    [ -n "$_u" ] || return 1
    mkdir -p "$(dirname "$_o")" 2>/dev/null || true
    if command -v wget >/dev/null 2>&1; then
        wget -q -O "$_o.tmp" "$_u" 2>/dev/null && mv -f "$_o.tmp" "$_o" && return 0
    elif command -v curl >/dev/null 2>&1; then
        curl -fsS -o "$_o.tmp" "$_u" 2>/dev/null && mv -f "$_o.tmp" "$_o" && return 0
    fi
    rm -f "$_o.tmp" 2>/dev/null || true
    return 1
}

fill_geo() { # set url cachefile
    _s="$1"; _u="$2"; _o="$3"
    [ -n "$_u" ] || return 0
    if fetch_url "$_u" "$_o"; then
        fill_set "$_s" "$_o"
        echo "[profiles] geo: ${_u##*/} -> $_o"
    elif [ -f "$_o" ]; then
        fill_set "$_s" "$_o"
        echo "[profiles] geo: offline, использую кэш $_o"
    else
        echo "[profiles] geo: не скачать $_u и нет кэша"
    fi
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
        _egs=$(cfg "profile${_i}_egress")
        _eg=""
        for _e in $(printf '%s' "$_egs" | tr ',' ' '); do
            [ -e "/sys/class/net/$_e" ] && { _eg="$_e"; break; }
        done
        [ -n "$_eg" ] || _eg=$(printf '%s' "$_egs" | cut -d, -f1)
        _lf=$(cfg "profile${_i}_list")
        _tb=$(cfg "profile${_i}_table"); [ -n "$_tb" ] || _tb=$((200 + _i))
        _mk=$(cfg "profile${_i}_mark");   [ -n "$_mk" ] || _mk=0x40000000
        _sn="$SETPFX$(san "$_nm")"

        "$IPSET" create "$_sn" hash:net timeout 0 -exist 2>/dev/null || true
        "$IPSET" flush "$_sn" 2>/dev/null || true
        fill_set "$_sn" "$_lf"
        _gu=$(cfg "profile${_i}_geo_url")
        [ -n "$_gu" ] && fill_geo "$_sn" "$_gu" "$VARDIR/profiles/$(san "$_nm").txt"

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

# refresh — перечитать файлы-списки профилей (перерезолвить домены, подхватить
# новые IP/CIDR) без пересборки правил. Для geo/CDN-списков, обновляемых извне.
refresh() {
    _n=$(count_profiles)
    [ "$_n" -eq 0 ] && { echo "[profiles] профили не заданы"; return 0; }
    _i=1
    while [ "$_i" -le "$MAXP" ]; do
        _nm=$(prof_name "$_i")
        if [ -z "$_nm" ]; then _i=$((_i + 1)); continue; fi
        _lf=$(cfg "profile${_i}_list")
        _sn="$SETPFX$(san "$_nm")"
        "$IPSET" create "$_sn" hash:net timeout 0 -exist 2>/dev/null || true
        "$IPSET" flush "$_sn" 2>/dev/null || true
        fill_set "$_sn" "$_lf"
        _gu=$(cfg "profile${_i}_geo_url")
        [ -n "$_gu" ] && fill_geo "$_sn" "$_gu" "$VARDIR/profiles/$(san "$_nm").txt"
        echo "[profiles] refresh $_nm <- ${_lf:-?}"
        _i=$((_i + 1))
    done
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
    refresh) refresh ;;
    *) echo "usage: $0 {up|down|status|refresh}"; exit 2 ;;
esac
