#!/bin/sh
# datapath.sh — Susanin.Keenetic data plane (iptables + ipset) on/off + manual words.
#
# Implements the scheme resolved in docs/RECON.md section 9:
#   - chain SUSANIN added as the LAST jump in mangle PREROUTING (after NDM);
#   - guarded: only fully-unmarked (skb mark==0) new LAN connections are marked;
#   - own fwmarks -> routing table (default 100) via egress (nwg0);
#   - automatic NAT is done by NDM (_NDM_MASQ), so no explicit SNAT.
# Fail-open = flush the SUSANIN ipset sets (rules remain, sets empty -> DIRECT).
#
# POSIX sh (busybox ash compatible). Idempotent (delete-then-add). On `up` a
# netfilter backup (iptables-save / ip rule / ip route) is made first.
#
# Usage:
#   datapath.sh up                 # install rules, ipsets, table, ip rule
#   datapath.sh down               # remove everything SUSANIN-managed
#   datapath.sh status             # show jump presence + set sizes
#   datapath.sh add   <ip> tcp|udp test|ok
#   datapath.sh del   <ip> tcp|udp
#   datapath.sh flush              # empty the sets (fail-open / DIRECT)
#
# Overrides via env:
#   SUSANIN_EGRESS (nwg0), SUSANIN_TABLE (100),
#   SUSANIN_MARK_OK (0x20000000), SUSANIN_MARK_TEST (0x10000000),
#   SUSANIN_PRI_OK (2000), SUSANIN_PRI_TEST (2001), SUSANIN_LAN ("br0 br1")

set -eu

PREFIX=/opt
find_bin() { for b in /opt/sbin /opt/bin /usr/sbin /usr/bin; do [ -x "$b/$1" ] && { echo "$b/$1"; return; }; done; command -v "$1" 2>/dev/null || true; }
IPT=$(find_bin iptables); IPSET=$(find_bin ipset); IPCMD=$(find_bin ip)
[ -n "$IPT" ] || { echo "iptables not found" >&2; exit 2; }
[ -n "$IPSET" ] || { echo "ipset not found" >&2; exit 2; }
[ -n "$IPCMD" ] || { echo "ip not found" >&2; exit 2; }

EGRESS=${SUSANIN_EGRESS:-nwg0}
TABLE=${SUSANIN_TABLE:-100}
MARK_OK=${SUSANIN_MARK_OK:-0x20000000}
MARK_TEST=${SUSANIN_MARK_TEST:-0x10000000}
MASK=0xffffffff
PRI_OK=${SUSANIN_PRI_OK:-2000}
PRI_TEST=${SUSANIN_PRI_TEST:-2001}
LAN=${SUSANIN_LAN:-"br0 br1"}
LAN=$(printf '%s' "$LAN" | tr ',' ' ')
TTL_TEST=${SUSANIN_TTL_TEST:-60}
TTL_OK=${SUSANIN_TTL_OK:-21600}
DISK_MODE=${SUSANIN_DISK_MODE:-normal}
# tproxy-режим: если порт > 0, вместо маршрута в интерфейс завернуть помеченные
# пакеты в локальный tproxy-inbound Xray (dokodemo-door).
TPROXY_PORT=${SUSANIN_TPROXY_PORT:-0}
TPROXY_MARK=0x1
# UDP-релей в демоне: если порт > 0, помеченные UDP-пакеты заворачиваем через
# TPROXY на этот порт (демон делает SOCKS5 UDP ASSOCIATE к Xray socks).
UDP_RELAY_PORT=${SUSANIN_UDP_RELAY_PORT:-0}

CHAIN=SUSANIN
SETS="susanin_ok_tcp susanin_ok_udp susanin_test_tcp susanin_test_udp"
NETSET=susanin_ok_net
NEVERSET=susanin_never

say() { echo "[susanin] $*"; }

# Run iptables -t mangle with delete-first (idempotent). "$@" = full -A spec.
mangle() { "$IPT" -t mangle -D "$@" >/dev/null 2>&1 || true; "$IPT" -t mangle -A "$@"; }
# ip rule: delete-first then add.
iprule() { "$IPCMD" rule del "$@" >/dev/null 2>&1 || true; "$IPCMD" rule add "$@"; }

set_exists() { "$IPSET" list "$1" >/dev/null 2>&1; }

backup() {
    if [ "$DISK_MODE" = "soft" ]; then
        say "disk_mode=soft: backup/archiving skipped"
        return 0
    fi
    mkdir -p "$PREFIX/susanin/var"
    bk="$PREFIX/susanin/var/datapath-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$bk"
    "$IPT" -t mangle -S > "$bk/mangle.txt" 2>/dev/null || true
    "$IPT" -t nat -S > "$bk/nat.txt" 2>/dev/null || true
    "$IPCMD" rule show > "$bk/ip-rule.txt" 2>/dev/null || true
    "$IPCMD" route show table all > "$bk/ip-route.txt" 2>/dev/null || true
    say "backup: $bk"
    # keep the 3 most recent dirs; archive older ones (keep 5 archives)
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
    # CIDR (vpn_always) live in a hash:net set; matches any LAN proto.
    set_exists "$NETSET" || "$IPSET" create "$NETSET" hash:net timeout 0
    # always-direct list (vpn_never): hash:net holds IPs (/32) and CIDRs.
    set_exists "$NEVERSET" || "$IPSET" create "$NEVERSET" hash:net timeout 0
    say "ipsets ready"
}

ensure_chain() {
    "$IPT" -t mangle -S "$CHAIN" >/dev/null 2>&1 || "$IPT" -t mangle -N "$CHAIN"
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
        # never-VPN list: leave these destinations completely direct
        mangle "$CHAIN" -i "$i" -m set --match-set susanin_never dst -j RETURN
        for p in tcp udp; do
            mangle "$CHAIN" -i "$i" -p "$p" -m conntrack --ctstate NEW \
                -m mark --mark 0x0/0xffffffff \
                -m set --match-set susanin_ok_${p} dst \
                -j CONNMARK --set-xmark "$MARK_OK/$MASK"
            # forced CIDR ranges (vpn_always) -> VPN for both protocols
            mangle "$CHAIN" -i "$i" -p "$p" -m conntrack --ctstate NEW \
                -m mark --mark 0x0/0xffffffff \
                -m set --match-set susanin_ok_net dst \
                -j CONNMARK --set-xmark "$MARK_OK/$MASK"
            mangle "$CHAIN" -i "$i" -p "$p" -m conntrack --ctstate NEW \
                -m mark --mark 0x0/0xffffffff \
                -m set --match-set susanin_test_${p} dst \
                -j CONNMARK --set-xmark "$MARK_TEST/$MASK"
        done
        mangle "$CHAIN" -i "$i" -j CONNMARK --restore-mark --nfmask "$MASK" --ctmask "$MASK"
        mangle "$CHAIN" -i "$i" -m mark --mark "$MARK_OK/$MASK" \
            -j MARK --set-xmark "$MARK_OK/$MASK"
        mangle "$CHAIN" -i "$i" -m mark --mark "$MARK_TEST/$MASK" \
            -j MARK --set-xmark "$MARK_TEST/$MASK"
    done
}

ensure_jump() {
    "$IPT" -t mangle -D PREROUTING -j "$CHAIN" >/dev/null 2>&1 || true
    "$IPT" -t mangle -A PREROUTING -j "$CHAIN"
}

ensure_table() {
    if [ "${TPROXY_PORT:-0}" -gt 0 ] 2>/dev/null; then
        # REDIRECT (TCP): помеченные Susanin'ом пакеты -> локальный порт Xray.
        # Метка ставится в mangle PREROUTING (SUSANIN), а nat PREROUTING идёт
        # после mangle — поэтому тут мы видим метку и делаем REDIRECT.
        # ip rule/таблица 100 для этого не нужны — убираем возможные прежние.
        "$IPCMD" rule del fwmark "$MARK_OK" priority "$PRI_OK" lookup "$TABLE" >/dev/null 2>&1 || true
        "$IPCMD" rule del fwmark "$MARK_TEST" priority "$PRI_TEST" lookup "$TABLE" >/dev/null 2>&1 || true
        "$IPCMD" rule del fwmark "$TPROXY_MARK" priority "$((PRI_OK + 2))" lookup "$TABLE" >/dev/null 2>&1 || true
        "$IPCMD" route del local default dev lo table "$TABLE" >/dev/null 2>&1 || true
        "$IPCMD" route del default dev "$EGRESS" table "$TABLE" >/dev/null 2>&1 || true
        redirect_rules
        udp_relay_rules
        say "redirect ready (port=$TPROXY_PORT, udp_relay=$UDP_RELAY_PORT)"
    else
        "$IPCMD" route del default dev "$EGRESS" table "$TABLE" >/dev/null 2>&1 || true
        "$IPCMD" route add default dev "$EGRESS" table "$TABLE"
        iprule fwmark "$MARK_OK" priority "$PRI_OK" lookup "$TABLE"
        iprule fwmark "$MARK_TEST" priority "$PRI_TEST" lookup "$TABLE"
        say "table/ip-rule ready (table=$TABLE dev=$EGRESS)"
    fi
}

# REDIRECT-правила в nat PREROUTING: TCP, помеченный Susanin'ом, -> порт Xray.
redirect_rules() {
    for m in "$MARK_OK" "$MARK_TEST"; do
        "$IPT" -t nat -D PREROUTING -p tcp -m mark --mark "$m/$MASK" \
            -j REDIRECT --to-ports "$TPROXY_PORT" >/dev/null 2>&1 || true
        "$IPT" -t nat -A PREROUTING -p tcp -m mark --mark "$m/$MASK" \
            -j REDIRECT --to-ports "$TPROXY_PORT"
    done
}

# UDP-релей: помеченные UDP → TPROXY на порт демона (+ локальная доставка).
udp_relay_rules() {
    [ "${UDP_RELAY_PORT:-0}" -gt 0 ] 2>/dev/null || return 0
    iprule fwmark "$TPROXY_MARK" priority "$((PRI_OK + 2))" lookup "$TABLE" 2>/dev/null || true
    "$IPCMD" route replace local default dev lo table "$TABLE" 2>/dev/null || true
    for m in "$MARK_OK" "$MARK_TEST"; do
        "$IPT" -t mangle -D PREROUTING -p udp -m mark --mark "$m/$MASK" \
            -j TPROXY --on-port "$UDP_RELAY_PORT" --tproxy-mark "$TPROXY_MARK/$MASK" \
            >/dev/null 2>&1 || true
        "$IPT" -t mangle -A PREROUTING -p udp -m mark --mark "$m/$MASK" \
            -j TPROXY --on-port "$UDP_RELAY_PORT" --tproxy-mark "$TPROXY_MARK/$MASK"
    done
}

tproxy_clean() {
    # Наши REDIRECT-правила (mangle-метка -> nat REDIRECT --to-ports) снимаем ВСЕГДА,
    # независимо от env SUSANIN_TPROXY_PORT: `datapath.sh down` из shell идёт без env,
    # и раньше эти правила оставались «висеть» (без метки они инертны, но мусор).
    "$IPT" -t nat -S PREROUTING 2>/dev/null | grep -- '-j REDIRECT --to-ports' | \
        grep -- '--mark 0x' | \
        while read -r line; do
            spec=$(printf '%s' "$line" | sed 's/^-A PREROUTING //')
            "$IPT" -t nat -D PREROUTING $spec >/dev/null 2>&1 || true
        done || true
    # на случай прежних TPROXY-правил из ранних версий
    "$IPT" -t mangle -S PREROUTING 2>/dev/null | grep -- '-j TPROXY' | \
        while read -r line; do
            spec=$(printf '%s' "$line" | sed 's/^-A PREROUTING //')
            "$IPT" -t mangle -D PREROUTING $spec >/dev/null 2>&1 || true
        done || true
    "$IPCMD" rule del fwmark "$TPROXY_MARK" priority "$((PRI_OK + 2))" lookup "$TABLE" >/dev/null 2>&1 || true
    "$IPCMD" route del local default dev lo table "$TABLE" >/dev/null 2>&1 || true
}

command_up() {
    backup
    ensure_sets
    ensure_chain
    rule_priv
    rule_mark
    ensure_jump
    ensure_table
    say "data plane UP (table=$TABLE dev=$EGRESS)"
}

command_down() {
    # ВАЖНО: сначала снять jump и цепочку — чтобы трафик перестал метиться,
    # даже если дальнейшие шаги почему-то сорвутся. Это гарантирует возврат
    # обычного канала (иначе «оставшаяся» цепочка метит адреса, а таблица 100
    # уже пуста -> чёрная дыра -> нужен ребут).
    "$IPT" -t mangle -D PREROUTING -j "$CHAIN" >/dev/null 2>&1 || true
    if "$IPT" -t mangle -S "$CHAIN" >/dev/null 2>&1; then
        "$IPT" -t mangle -F "$CHAIN" 2>/dev/null || true
        "$IPT" -t mangle -X "$CHAIN" 2>/dev/null || true
    fi
    for s in $SETS; do set_exists "$s" && "$IPSET" destroy "$s" || true; done
    set_exists "$NETSET" && "$IPSET" destroy "$NETSET" || true
    set_exists "$NEVERSET" && "$IPSET" destroy "$NEVERSET" || true
    "$IPCMD" rule del fwmark "$MARK_OK" priority "$PRI_OK" lookup "$TABLE" >/dev/null 2>&1 || true
    "$IPCMD" rule del fwmark "$MARK_TEST" priority "$PRI_TEST" lookup "$TABLE" >/dev/null 2>&1 || true
    "$IPCMD" rule del fwmark "$TPROXY_MARK" priority "$((PRI_OK + 2))" lookup "$TABLE" >/dev/null 2>&1 || true
    "$IPCMD" route del default dev "$EGRESS" table "$TABLE" >/dev/null 2>&1 || true
    "$IPCMD" route del local default dev lo table "$TABLE" >/dev/null 2>&1 || true
    "$IPCMD" route flush table "$TABLE" >/dev/null 2>&1 || true
    tproxy_clean || true
    say "data plane DOWN"
}

command_status() {
    if "$IPT" -t mangle -S PREROUTING >/dev/null 2>&1 && "$IPT" -t mangle -S PREROUTING | grep -q "$CHAIN"; then
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
        n=$("$IPT" -t nat -S PREROUTING 2>/dev/null | grep -c 'REDIRECT --to-ports' || true)
        echo "redirect: port=$TPROXY_PORT rules=$n"
    fi
    if [ "${UDP_RELAY_PORT:-0}" -gt 0 ] 2>/dev/null; then
        u=$("$IPT" -t mangle -S PREROUTING 2>/dev/null | grep -c "TPROXY --on-port $UDP_RELAY_PORT" || true)
        echo "udp-relay: port=$UDP_RELAY_PORT rules=$u"
    fi
}

command_egress() {
    iface="$1"
    [ -n "$iface" ] || { echo "usage: $0 egress <iface>" >&2; exit 2; }
    if [ "${TPROXY_PORT:-0}" -gt 0 ] 2>/dev/null; then
        # В tproxy-режиме table $TABLE занята local-маршрутом для TPROXY;
        # менять её на default dev <iface> нельзя (сломает UDP-ветку).
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
