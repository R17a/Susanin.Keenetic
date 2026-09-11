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
        die "need curl or wget"
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
        || die "download failed (check --arch/--version or release assets): $BASE/$ASSET"
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

if [ -z "$EGRESS" ]; then
    CAND=$(ifaces | grep -E '^(nwg|wg[0-9]|tun|tap|ovpn|amnezia)' || true)
    CN=$(printf '%s\n' "$CAND" | grep -c . || true)
    if [ "$CN" = 1 ]; then
        EGRESS="$CAND"
    elif [ "$CN" -gt 1 ]; then
        say "several VPN interfaces found:"
        EGRESS=$(pick "select egress (VPN)" $CAND)
    else
        say "no VPN interface auto-detected; candidates:"
        EGRESS=$(pick "select egress (VPN)" $(ifaces | grep -Ev '^(lo|ppp)' || true))
    fi
fi
say "egress=$EGRESS addr=$(addr_of "$EGRESS")"

if [ -z "$LAN" ]; then
    for i in $(ifaces); do
        [ "$i" = "$EGRESS" ] && continue
        a=$(addr_of "$i" || true)
        case "$a" in
            10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*)
                LAN="${LAN:+$LAN,}$i" ;;
        esac
    done
    [ -n "$LAN" ] || LAN="br0"
fi
if [ -z "$SUBNETS" ]; then
    for i in $(printf '%s' "$LAN" | tr ',' ' '); do
        a=$(addr_of "$i")
        [ -n "$a" ] && SUBNETS="${SUBNETS:+$SUBNETS,}$a"
    done
fi
say "lan=$LAN subnets=${SUBNETS:-n/a}"

if [ "$YES" -ne 1 ] && [ -r /dev/tty ]; then
    printf "[susanin] install to %s with egress=%s lan=%s ? [y/N]: " \
        "$PREFIX" "$EGRESS" "$LAN" >&2
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
    sh "$PREFIX/tools/susanin.sh" start || true
fi
say "installed to $PREFIX (run: sh $PREFIX/tools/susanin.sh status)"
