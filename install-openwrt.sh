#!/bin/sh
# Susanin installer for OpenWRT.
#
# Run from an extracted package (susanin-agent, datapath.sh, susanin next to it):
#   sh install-openwrt.sh [--egress IF] [--lan IF,IF] [--subnets CIDR,CIDR]
#                         [--yes] [--force] [--no-start]
# POSIX sh (busybox ash compatible).
#
# Layout (platform=openwrt, see src/platform.c):
#   bin   /usr/bin        etc /etc/susanin
#   var   /var/lib/susanin  tools /usr/lib/susanin
set -eu

BINDIR=/usr/bin
ETCDIR=/etc/susanin
VARDIR=/var/lib/susanin
TOOLSDIR=/usr/lib/susanin
INITD=/etc/init.d

EGRESS=""
LAN=""
SUBNETS=""
YES=0
FORCE=0
NO_START=0

say() { echo "[susanin] $*"; }
die() { echo "[susanin] ERROR: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --egress) EGRESS="$2"; shift ;;
        --lan) LAN="$2"; shift ;;
        --subnets) SUBNETS="$2"; shift ;;
        --yes|-y) YES=1 ;;
        --force) FORCE=1 ;;
        --no-start) NO_START=1 ;;
        -h|--help)
            echo "usage: $0 [--egress IF] [--lan IF,IF] [--subnets CIDR,CIDR] [--yes] [--force] [--no-start]"
            exit 0 ;;
        *) die "unknown arg: $1" ;;
    esac
    shift
done

[ "$(id -u 2>/dev/null || echo 1)" = "0" ] || die "run as root"

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[ -f "$DIR/susanin-agent" ] || die "susanin-agent not found next to this script"

# --- dependencies -----------------------------------------------------------
miss=""
for t in ipset conntrack; do
    command -v "$t" >/dev/null 2>&1 || miss="$miss $t"
done
command -v iptables >/dev/null 2>&1 || miss="$miss iptables"
[ -n "$miss" ] && {
    say "WARNING: missing tools:$miss"
    say "  opkg update && opkg install ipset conntrack-tools iptables-legacy ip-full"
    say "  (kmods: kmod-ipset kmod-ipt-conntrack kmod-ipt-connmark kmod-ipt-tcp-mss)"
}

if ! iptables -t mangle -S >/dev/null 2>&1; then
    say "WARNING: 'iptables -t mangle' failed — OpenWRT 22.03+ ships nftables (fw4)."
    say "  This build expects iptables-legacy; install it or use a legacy-based image."
fi

# --- detect egress (WireGuard/AmneziaWG) ------------------------------------
if [ -z "$EGRESS" ]; then
    for i in $(ls /sys/class/net 2>/dev/null); do
        case "$i" in wg*|nwg*|amnezia*|awg*) EGRESS="$i"; break ;; esac
    done
fi
[ -n "$EGRESS" ] || EGRESS=wg0
say "egress: $EGRESS"

# --- detect LAN -------------------------------------------------------------
if [ -z "$LAN" ]; then
    if [ -d /sys/class/net/br-lan ]; then LAN=br-lan; else LAN=br0; fi
fi
say "lan: $LAN"

# --- detect LAN subnet (raw addr/prefix; ip_in_cidr masks both sides) --------
if [ -z "$SUBNETS" ]; then
    for i in $(printf '%s' "$LAN" | tr ',' ' '); do
        _cidr=$(ip -4 addr show dev "$i" 2>/dev/null | \
                sed -n 's/ *inet \([0-9.]*\/[0-9]*\).*/\1/p' | head -n1)
        [ -n "$_cidr" ] && SUBNETS="${SUBNETS:+$SUBNETS,}$_cidr"
    done
    [ -n "$SUBNETS" ] || SUBNETS=192.168.1.0/24
fi
say "subnets: $SUBNETS"

# --- confirm ----------------------------------------------------------------
if [ "$YES" -ne 1 ] && [ -r /dev/tty ]; then
    printf "[susanin] Install?\n  bin:     %s\n  etc:     %s\n  var:     %s\n  egress:  %s\n  lan:     %s\n  subnets: %s\nProceed? [y/N]: " \
        "$BINDIR" "$ETCDIR" "$VARDIR" "$EGRESS" "$LAN" "$SUBNETS" >&2
    read _ok < /dev/tty || _ok=n
    case "$_ok" in y|Y|yes|YES) ;; *) die "aborted" ;; esac
fi

# --- install files ----------------------------------------------------------
mkdir -p "$BINDIR" "$ETCDIR" "$VARDIR" "$TOOLSDIR" "$INITD"
cp "$DIR/susanin-agent" "$BINDIR/susanin-agent"
chmod 0755 "$BINDIR/susanin-agent"
if [ -f "$DIR/datapath.sh" ]; then
    cp "$DIR/datapath.sh" "$TOOLSDIR/datapath.sh"
    chmod 0755 "$TOOLSDIR/datapath.sh"
fi
if [ -f "$DIR/susanin" ]; then
    cp "$DIR/susanin" "$INITD/susanin"
    chmod 0755 "$INITD/susanin"
fi

# --- config -----------------------------------------------------------------
if [ ! -f "$ETCDIR/susanin.conf" ] || [ "$FORCE" -eq 1 ]; then
    if [ -f "$DIR/config.example.conf" ]; then
        cp "$DIR/config.example.conf" "$ETCDIR/susanin.conf"
    else
        : > "$ETCDIR/susanin.conf"
    fi
    sed -i "s|^egress_interface=.*|egress_interface=$EGRESS|" "$ETCDIR/susanin.conf" 2>/dev/null || true
    sed -i "s|^lan_interfaces=.*|lan_interfaces=$LAN|" "$ETCDIR/susanin.conf" 2>/dev/null || true
    sed -i "s|^lan_subnets=.*|lan_subnets=$SUBNETS|" "$ETCDIR/susanin.conf" 2>/dev/null || true
    say "config written: $ETCDIR/susanin.conf"
else
    say "config kept: $ETCDIR/susanin.conf"
fi

for f in vpn_always.txt vpn_never.txt; do
    if [ ! -f "$ETCDIR/$f" ] && [ -f "$DIR/$f" ]; then
        cp "$DIR/$f" "$ETCDIR/$f"
        say "list installed: $ETCDIR/$f"
    fi
done

if [ "$NO_START" -eq 1 ]; then
    say "installed (not started): $INITD/susanin enable && $INITD/susanin start"
    exit 0
fi

"$INITD/susanin" enable
"$INITD/susanin" start
say "installed and started"
say "check: $INITD/susanin status ; log: $VARDIR/susanin.log"
