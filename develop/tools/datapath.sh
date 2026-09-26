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
[ -n "ipt" ] || { echo "iptables not found" >&2; exit 2; }
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

CHAIN=SUSANIN
SETS="susanin_ok_tcp susanin_ok_udp susanin_test_tcp susanin_test_udp"
NETSET=susanin_ok_net
NEVERSET=susanin_never

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

backup() {
    if [ "$DISK_MODE" = "soft" ]; then
        say "disk_mode=soft: backup/archiving skipped"
        return 0
    fi
    mkdir -p "$PREFIX/susanin/var"
    _mark="$PREFIX/susanin/var/.last-backup"
    _now=$(date +%s)
    _last=$(cat "$_mark" 2>/dev/null || echo 0)
    case "$_last" in ''|*[!0-9]*) _last=0;; esac
    if [ $((_now - _last)) -lt "${BACKUP_MIN_INTERVAL:-3600}" ]; then
        return 0
    fi
    printf '%s\n' "$_now" > "$_mark" 2>/dev/null || true
    bk="$PREFIX/susanin/var/datapath-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$bk"
    "ipt" -t mangle -S > "$bk/mangle.txt" 2>/dev/null || true
    "ipt" -t nat -S > "$bk/nat.txt" 2>/dev/null || true
    "$IPCMD" rule show > "$bk/ip-rule.txt" 2>/dev/null || true
    "$IPCMD" route show table all > "$bk/ip-route.txt" 2>/dev/null || true
    say "backup: $bk"
    arc="$PREFIX/susanin/var/archive"
    mkdir -p "$arc"
    ls -1dt "$PREFIX/susanin/var"/datapath-* 2>/dev/null | tail -n +4 | \
        while read -r old; do
            base=$(basename "$old")
            if tar -czf "$arc/$base.tar.gz" -C "$(dirname "$old")" "$base" 2>/dev/null; then
                rm -rf "$old"
            fi
        done
    ls -1dt "$arc"/datapath-*.tar.gz 2>/dev/null | tail -n +6 | \
        while read -r x; do rm -f "$x"; done
}

ensure_sets() {
    for s in $SETS; do
        set_exists "$s" || "$IPSET" create "$s" hash:ip timeout 0
    done
    set_exists "$NETSET" || "$IPSET" create "$NETSET" hash:net timeout 0
    set_exists "$NEVERSET" || "$IPSET" create "$NEVERSET" hash:net timeout 0
    say "ipsets ready"
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
        mangle "$CHAIN" -i "$i" -m set --match-set susanin_never dst -j RETURN
        for p in tcp udp; do
            mangle "$CHAIN" -i "$i" -p "$p" -m conntrack --ctstate NEW \
                -m mark --mark "0x0/$MARK_MASK" \
                -m set --match-set susanin_ok_${p} dst \
                -j CONNMARK --set-xmark "$MARK_OK/$MARK_MASK"
            mangle "$CHAIN" -i "$i" -p "$p" -m conntrack --ctstate NEW \
                -m mark --mark "0x0/$MARK_MASK" \
                -m set --match-set susanin_ok_net dst \
                -j CONNMARK --set-xmark "$MARK_OK/$MARK_MASK"
            mangle "$CHAIN" -i "$i" -p "$p" -m conntrack --ctstate NEW \
                -m mark --mark "0x0/$MARK_MASK" \
                -m set --match-set susanin_test_${p} dst \
                -j CONNMARK --set-xmark "$MARK_TEST/$MARK_MASK"
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

command_up() {
    backup
    ensure_sets
    ensure_chain
    rule_priv
    rule_mark
    ensure_jump
    ensure_table
    ipv6_block_rules
    quic_block_rules
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
    iprule_fw_clean "$MARK_OK" "$PRI_OK"
    iprule_fw_clean "$MARK_TEST" "$PRI_TEST"
    "$IPCMD" rule del fwmark "$TPROXY_MARK" priority "$((PRI_OK + 2))" lookup "$TABLE" >/dev/null 2>&1 || true
    "$IPCMD" route del default dev "$EGRESS" table "$TABLE" >/dev/null 2>&1 || true
    "$IPCMD" route del local default dev lo table "$TABLE" >/dev/null 2>&1 || true
    "$IPCMD" route flush table "$TABLE" >/dev/null 2>&1 || true
    tproxy_clean || true
    ipv6_block_clean || true
    quic_block_clean || true
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
    "$IPCMD" rule show | grep -E "lookup $TABLE" || echo "no ip rule for table $TABLE"
    if [ "${TPROXY_PORT:-0}" -gt 0 ] 2>/dev/null; then
        n=$("ipt" -t nat -S PREROUTING 2>/dev/null | grep -c 'REDIRECT --to-ports' || true)
        echo "redirect: port=$TPROXY_PORT rules=$n"
    fi
    if [ "${UDP_RELAY_PORT:-0}" -gt 0 ] 2>/dev/null; then
        u=$("ipt" -t mangle -S PREROUTING 2>/dev/null | grep -c "TPROXY --on-port $UDP_RELAY_PORT" || true)
        echo "udp-relay: port=$UDP_RELAY_PORT rules=$u"
    fi
    if [ "$IPV6_BLOCK" = "1" ] && [ -n "$IP6T" ]; then
        v6=$("$IP6T" -w -t filter -S FORWARD 2>/dev/null | grep -c -- '-j REJECT' || true)
        echo "ipv6_block: on (FORWARD REJECT rules=$v6)"
    fi
    q=$("ipt" -t mangle -S PREROUTING 2>/dev/null | grep -c -- '-p udp .* --dport 443 -j DROP' || true)
    if [ "$QUIC_BLOCK" = "1" ]; then
        echo "quic_block: on (mangle PREROUTING DROP rules=$q)"
    elif [ "${q:-0}" -gt 0 ] 2>/dev/null; then
        echo "quic_block: off, но найдены остаточные правила ($q) — перезапустите susanin.sh"
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
    ip="$1"; p="$2"; ph="$3"
    case "$p" in tcp|udp) ;; *) echo "bad proto: $p" >&2; exit 2;; esac
    case "$ph" in test|ok) ;; *) echo "bad phase: $ph" >&2; exit 2;; esac
    ensure_sets
    ttl=$TTL_TEST; [ "$ph" = ok ] && ttl=$TTL_OK
    "$IPSET" -exist add "susanin_${ph}_${p}" "$ip" timeout "$ttl"
    say "added $ip -> susanin_${ph}_${p} (timeout ${ttl}s)"
}

command_del() {
    ip="$1"; p="$2"
    for s in "susanin_test_${p}" "susanin_ok_${p}"; do
        set_exists "$s" && "$IPSET" -exist del "$s" "$ip" >/dev/null 2>&1 || true
    done
    say "deleted $ip ($p)"
}

case "${1:-}" in
    up) command_up ;;
    down) command_down ;;
    status) command_status ;;
    flush) command_flush ;;
    egress) command_egress "${2:-}" ;;
    add) command_add "$2" "$3" "$4" ;;
    del) command_del "$2" "$3" ;;
    *)
        echo "usage: $0 {up|down|status|flush|egress <iface>|add <ip> <tcp|udp> <test|ok>|del <ip> <tcp|udp>}" >&2
        exit 2 ;;
esac
