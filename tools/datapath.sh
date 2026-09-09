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

CHAIN=SUSANIN
SETS="susanin_ok_tcp susanin_ok_udp susanin_test_tcp susanin_test_udp"
NETSET=susanin_ok_net

say() { echo "[susanin] $*"; }

# Run iptables -t mangle with delete-first (idempotent). "$@" = full -A spec.
mangle() { "$IPT" -t mangle -D "$@" >/dev/null 2>&1 || true; "$IPT" -t mangle -A "$@"; }
# ip rule: delete-first then add.
iprule() { "$IPCMD" rule del "$@" >/dev/null 2>&1 || true; "$IPCMD" rule add "$@"; }

set_exists() { "$IPSET" list "$1" >/dev/null 2>&1; }

backup() {
    mkdir -p "$PREFIX/susanin/var"
    bk="$PREFIX/susanin/var/datapath-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$bk"
    "$IPT" -t mangle -S > "$bk/mangle.txt" 2>/dev/null || true
    "$IPT" -t nat -S > "$bk/nat.txt" 2>/dev/null || true
    "$IPCMD" rule show > "$bk/ip-rule.txt" 2>/dev/null || true
    "$IPCMD" route show table all > "$bk/ip-route.txt" 2>/dev/null || true
    say "backup: $bk"
}

ensure_sets() {
    for s in $SETS; do
        set_exists "$s" || "$IPSET" create "$s" hash:ip timeout 0
    done
    # CIDR (vpn_always) live in a hash:net set; matches any LAN proto.
    set_exists "$NETSET" || "$IPSET" create "$NETSET" hash:net timeout 0
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
    "$IPCMD" route del default dev "$EGRESS" table "$TABLE" >/dev/null 2>&1 || true
    "$IPCMD" route add default dev "$EGRESS" table "$TABLE"
    iprule fwmark "$MARK_OK" priority "$PRI_OK" lookup "$TABLE"
    iprule fwmark "$MARK_TEST" priority "$PRI_TEST" lookup "$TABLE"
    say "table/ip-rule ready (table=$TABLE dev=$EGRESS)"
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
    "$IPT" -t mangle -D PREROUTING -j "$CHAIN" >/dev/null 2>&1 || true
    if "$IPT" -t mangle -S "$CHAIN" >/dev/null 2>&1; then
        "$IPT" -t mangle -F "$CHAIN"; "$IPT" -t mangle -X "$CHAIN" || true
    fi
    for s in $SETS; do set_exists "$s" && "$IPSET" destroy "$s" || true; done
    set_exists "$NETSET" && "$IPSET" destroy "$NETSET" || true
    "$IPCMD" rule del fwmark "$MARK_OK" priority "$PRI_OK" lookup "$TABLE" >/dev/null 2>&1 || true
    "$IPCMD" rule del fwmark "$MARK_TEST" priority "$PRI_TEST" lookup "$TABLE" >/dev/null 2>&1 || true
    "$IPCMD" route del default dev "$EGRESS" table "$TABLE" >/dev/null 2>&1 || true
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
            echo "$s = $("$IPSET" list "$s" 2>/dev/null | grep -c '^[0-9]\.' || true)"
        else
            echo "$s = (absent)"
        fi
    done
    if set_exists "$NETSET"; then
        echo "$NETSET = $("$IPSET" list "$NETSET" 2>/dev/null | grep -cE '^[0-9]+\.' || true)"
    else
        echo "$NETSET = (absent)"
    fi
    "$IPCMD" rule show | grep -E "lookup $TABLE" || echo "no ip rule for table $TABLE"
}

command_flush() {
    for s in $SETS; do set_exists "$s" && "$IPSET" flush "$s" || true; done
    set_exists "$NETSET" && "$IPSET" flush "$NETSET" || true
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
    add) command_add "$2" "$3" "$4" ;;
    del) command_del "$2" "$3" ;;
    *)
        echo "usage: $0 {up|down|status|flush|add <ip> <tcp|udp> <test|ok>|del <ip> <tcp|udp>}" >&2
        exit 2 ;;
esac
