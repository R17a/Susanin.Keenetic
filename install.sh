#!/bin/sh
# Susanin.Keenetic installer.
# Online (default): downloads the per-arch archive from GitHub Releases.
#   curl -fsSL https://raw.githubusercontent.com/R17a/Susanin.Keenetic/main/install.sh \
#     | sh -s -- [--arch mipsel] [--version vX.Y.Z] [--yes]
# Offline/local: run from an extracted archive (susanin-agent is next to this script):
#   sh install.sh [--yes]
# POSIX sh (busybox ash compatible).
set -eu

REPO="R17a/Susanin.Keenetic"
PREFIX=/opt/susanin
INITD=/opt/etc/init.d
ARCH=""
VERSION="latest"
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
        --arch) ARCH="$2"; shift ;;
        --version) VERSION="$2"; shift ;;
        --egress) EGRESS="$2"; shift ;;
        --lan) LAN="$2"; shift ;;
        --subnets) SUBNETS="$2"; shift ;;
        --prefix) PREFIX="$2"; shift ;;
        --yes|-y) YES=1 ;;
        --force) FORCE=1 ;;
        --no-start) NO_START=1 ;;
        -h|--help)
            echo "usage: $0 [--arch mipsel|mips|aarch64|armv7|x86_64] [--version latest|vX.Y.Z]"
            echo "          [--egress IF] [--lan IF,IF] [--subnets CIDR,CIDR] [--prefix DIR]"
            echo "          [--yes] [--force] [--no-start]"
            exit 0 ;;
        *) die "unknown arg: $1" ;;
    esac
    shift
done

if [ -z "$ARCH" ]; then
    _m=$(uname -m 2>/dev/null || echo unknown)
    case "$_m" in
        mips|mipsel) ARCH=mipsel ;;
        mips64) ARCH=mips64el ;;
        aarch64|arm64) ARCH=aarch64 ;;
        armv7l|armv7|armhf) ARCH=armv7 ;;
        x86_64|amd64) ARCH=x86_64 ;;
        *) die "cannot detect arch (uname -m=$_m); pass --arch" ;;
    esac
fi

DIR0=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -f "$DIR0/susanin-agent" ] || [ -n "$(ls "$DIR0"/susanin-agent.* 2>/dev/null)" ]; then
    DIR=$DIR0
    say "local package: $DIR"
else
    if command -v curl >/dev/null 2>&1; then
        fetch() { curl -fsSL "$1" -o "$2"; }
    elif command -v wget >/dev/null 2>&1; then
        fetch() { wget -qO "$2" "$1"; }
    else
        die "need curl or wget (Entware: opkg update && opkg install ca-certificates; optionally 'opkg install curl')"
    fi
    if [ "$VERSION" = latest ]; then
        BASE="https://github.com/$REPO/releases/latest/download"
    else
        BASE="https://github.com/$REPO/releases/download/$VERSION"
    fi
    ASSET="susanin-keenetic-deploy-$ARCH.tar.gz"
    say "arch=$ARCH version=$VERSION"
    TMP=$(mktemp -d /tmp/susanin-inst.XXXXXX)
    trap 'rm -rf "$TMP"' EXIT INT TERM
    say "downloading $BASE/$ASSET"
    fetch "$BASE/$ASSET" "$TMP/pkg.tar.gz" \
        || die "download failed (check --arch/--version or release assets): $BASE/$ASSET
     hint: opkg update && opkg install ca-certificates"
    tar -xzf "$TMP/pkg.tar.gz" -C "$TMP" || die "bad archive $ASSET"
    DIR=$TMP
fi

if [ -f "$DIR/susanin-agent" ]; then
    BINFILE=susanin-agent
else
    BINFILE=$(basename "$(ls "$DIR"/susanin-agent.* 2>/dev/null | head -1)")
fi
[ -n "${BINFILE:-}" ] && [ -f "$DIR/$BINFILE" ] || die "susanin-agent binary not found in $DIR"
say "binary: $BINFILE"

ifaces() { awk -F: '{print $1}' /proc/net/dev | tr -d ' ' | grep -v '^$'; }
addr_of() { ip addr show "$1" 2>/dev/null | awk '/inet /{print $2}' | head -1; }

pick() {
    _what="$1"; shift
    _n=0
    for _i in "$@"; do _n=$((_n + 1)); echo "  $_n) $_i" >&2; done
    if [ -r /dev/tty ]; then
        printf "%s [1-%d]: " "$_what" "$_n" >&2
        read _sel < /dev/tty || _sel=1
    else
        die "ambiguous $_what; pass flag explicitly (no tty)"
    fi
    _n=0
    for _i in "$@"; do _n=$((_n + 1)); [ "$_n" = "$_sel" ] && { echo "$_i"; return; }; done
    echo "$1"
}

default_devs() {
    ip route show table all 2>/dev/null \
      | awk '/default/ {for (i = 1; i <= NF; i++) if ($i == "dev") print $(i + 1)}' \
      | sort -u
}

if [ -z "$EGRESS" ]; then
    CAND=$(ifaces | grep -E '^(nwg|wg[0-9]*|amnezia|ovpn)' || true)
    if [ -z "$CAND" ]; then
        CAND=$(ifaces | grep -E '^(tun[0-9]+|tap[0-9]+)$' || true)
    fi
    CN=$(printf '%s\n' "$CAND" | grep -c . || true)
    if [ "$CN" = 1 ]; then
        EGRESS="$CAND"
    elif [ "$CN" -gt 1 ]; then
        DEF=$(default_devs)
        for c in $CAND; do
            if printf '%s\n' "$DEF" | grep -qx "$c"; then EGRESS="$c"; break; fi
        done
        [ -n "$EGRESS" ] || EGRESS=$(printf '%s\n' "$CAND" | grep -E '^(nwg|wg)' | head -1)
        [ -n "$EGRESS" ] || EGRESS=$(printf '%s\n' "$CAND" | head -1)
        say "selected egress=$EGRESS (candidates: $(printf '%s ' $CAND)); use --egress to override"
    elif ifaces | grep -qx nwg0; then
        EGRESS=nwg0
    else
        say "no VPN interface auto-detected; select manually"
        EGRESS=$(pick "select egress (VPN)" $(ifaces | grep -Ev '^(lo|ppp|tunl)' || true))
    fi
fi
say "egress=$EGRESS addr=$(addr_of "$EGRESS")"

lan_from_routes() {
    ip route show 2>/dev/null | awk '
        /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/ && $0 !~ /default/ {
            for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); break }
        }' | sort -u
}

if [ -z "$LAN" ]; then
    LANBR=$(lan_from_routes | grep '^br' || true)
    if [ -n "$LANBR" ]; then
        LAN=$(printf '%s\n' "$LANBR" | awk 'NR==1{s=$0;next}{s=s","$0}END{print s}')
    else
        LAN=$(lan_from_routes | grep -Ev '^(ppp|nwg|wg|tun|tap|eth)' \
              | awk 'NR==1{s=$0;next}{s=s","$0}END{print s}')
    fi
    [ -n "$LAN" ] || LAN="br0"
fi
if [ -z "$SUBNETS" ]; then
    for i in $(printf '%s' "$LAN" | tr ',' ' '); do
        p=$(ip route show 2>/dev/null | awk -v d="$i" '$0 ~ ("dev " d " ") && $1 ~ /\// {print $1; exit}')
        [ -n "$p" ] && SUBNETS="${SUBNETS:+$SUBNETS,}$p"
    done
fi
say "lan=$LAN subnets=${SUBNETS:-n/a}"

if [ "$YES" -ne 1 ] && [ -r /dev/tty ]; then
    printf "[susanin] Install to %s ?\n  egress:  %s\n  lan:     %s\n  subnets: %s\nProceed? [y/N]: " \
        "$PREFIX" "$EGRESS" "$LAN" "${SUBNETS:-n/a}" >&2
    read _ok < /dev/tty || _ok=n
    case "$_ok" in y|Y|yes|YES) ;; *) die "aborted" ;; esac
fi

mkdir -p "$PREFIX/bin" "$PREFIX/tools" "$PREFIX/etc" "$PREFIX/var" "$INITD"
cp "$DIR/$BINFILE" "$PREFIX/bin/susanin-agent"
for f in datapath.sh susanin.sh update.sh uninstall.sh install.sh; do
    [ -f "$DIR/$f" ] && cp "$DIR/$f" "$PREFIX/tools/$f"
done
chmod +x "$PREFIX/bin/susanin-agent" "$PREFIX/tools/"*.sh 2>/dev/null || true

if [ ! -f "$PREFIX/etc/susanin.conf" ] || [ "$FORCE" = 1 ]; then
    [ -f "$DIR/config.example.conf" ] && cp "$DIR/config.example.conf" "$PREFIX/etc/susanin.conf"
    sed -i "s|^egress_interface=.*|egress_interface=$EGRESS|" "$PREFIX/etc/susanin.conf" 2>/dev/null || true
    sed -i "s|^lan_interfaces=.*|lan_interfaces=$LAN|" "$PREFIX/etc/susanin.conf" 2>/dev/null || true
    [ -n "$SUBNETS" ] && sed -i "s|^lan_subnets=.*|lan_subnets=$SUBNETS|" "$PREFIX/etc/susanin.conf" 2>/dev/null || true
    EA=$(addr_of "$EGRESS")
    [ -n "$EA" ] && sed -i "s|^egress_address=.*|egress_address=${EA%%/*}|" "$PREFIX/etc/susanin.conf" 2>/dev/null || true
    say "config written: $PREFIX/etc/susanin.conf"
else
    say "config kept: $PREFIX/etc/susanin.conf"
fi
if [ ! -f "$PREFIX/etc/vpn_always.txt" ] && [ -f "$DIR/vpn_always.txt" ]; then
    cp "$DIR/vpn_always.txt" "$PREFIX/etc/vpn_always.txt"
    say "vpn_always list installed: $PREFIX/etc/vpn_always.txt"
else
    say "vpn_always list kept (not overwritten)"
fi

if [ -f "$DIR/S94susanin" ]; then
    cp "$DIR/S94susanin" "$INITD/S94susanin"
    chmod +x "$INITD/S94susanin"
fi

if [ "$NO_START" -ne 1 ]; then
    if ps 2>/dev/null | grep '[s]usanin-agent' >/dev/null 2>&1; then
        sh "$PREFIX/tools/susanin.sh" restart || true
    else
        sh "$PREFIX/tools/susanin.sh" start || true
    fi
fi
say "installed to $PREFIX (run: sh $PREFIX/tools/susanin.sh status)"
