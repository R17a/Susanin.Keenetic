#!/bin/sh
# owrt-report.sh — collect OpenWRT diagnostics for Susanin.Keenetic bug reports.
#
# Usage:
#   wget -qO- https://raw.githubusercontent.com/R17a/Susanin.Keenetic/openwrt/tools/owrt-report.sh | sh
#   sh tools/owrt-report.sh [--out FILE]
#
# Prints the report and saves it to /tmp/susanin-report.txt (override with --out).
# Run it while the problem is reproducible. The report contains IP addresses.
set -u

OUT=/tmp/susanin-report.txt
while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift ;;
        -h|--help) echo "usage: $0 [--out FILE]"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
    shift
done

A=/usr/bin/susanin-agent
INIT=/etc/init.d/susanin
LOG=/var/lib/susanin/susanin.log

sec() { echo; echo "===== $* ====="; }
run() { echo "----- $* -----"; "$@" 2>&1; }

{
    sec SYSTEM
    [ -f /etc/openwrt_release ] && cat /etc/openwrt_release 2>&1
    uname -a
    echo "date: $(date 2>/dev/null)"
    echo "arch: $(uname -m)"

    sec AGENT
    if [ -x "$A" ]; then
        run "$A" version
        run "$A" status
        run "$A" config show
        run "$A" discover
        run "$A" diag errors
    else
        echo "susanin-agent not found at $A"
    fi
    if [ -x "$INIT" ]; then
        run "$INIT" status
    else
        echo "$INIT not found"
    fi
    echo "----- log (last 150) -----"
    tail -n 150 "$LOG" 2>&1

    sec "DATA PLANE"
    echo "----- ip rule -----"
    ip rule show 2>&1
    echo "----- route table 100 -----"
    ip route show table 100 2>&1
    echo "----- ipsets (address count) -----"
    for s in susanin_ok_tcp susanin_ok_udp susanin_test_tcp susanin_test_udp susanin_ok_net susanin_never; do
        printf "%s = " "$s"
        ipset list "$s" 2>/dev/null | grep -cE '^[0-9]+\.'
    done
    echo "----- iptables -t mangle -S SUSANIN -----"
    iptables -t mangle -S SUSANIN 2>&1 | head -60
    echo "----- conntrack VPN mark=536870912 (first 5) -----"
    grep -m5 'mark=536870912' /proc/net/nf_conntrack 2>&1

    sec "INTERFACES / MTU"
    ip link show 2>/dev/null | grep -E '^[0-9]+:'
    for i in $(ls /sys/class/net 2>/dev/null); do
        case "$i" in
            wg*|nwg*|amnezia*|awg*)
                printf "%s mtu: " "$i"; cat "/sys/class/net/$i/mtu" 2>/dev/null ;;
        esac
    done
    if [ -f /var/run/ocserv/ocserv.conf ]; then
        echo "----- ocserv mtu/mss -----"
        grep -iE 'mtu|mss' /var/run/ocserv/ocserv.conf 2>&1
    fi

    echo
    echo "===== END — send this output ====="
} > "$OUT" 2>&1

cat "$OUT"
echo
echo "[susanin] report saved: $OUT"
