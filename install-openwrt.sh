#!/bin/sh
# Susanin installer for OpenWRT (Keenetic/Netcraze on OpenWRT).
#
# Online (default): detects the CPU architecture, resolves the newest OpenWRT
# release and installs it:
#   wget -qO- https://raw.githubusercontent.com/R17a/Susanin.Keenetic/openwrt/install-openwrt.sh | sh -s -- --yes
#   # or, from a saved copy:
#   wget -O /tmp/install-openwrt.sh https://raw.githubusercontent.com/R17a/Susanin.Keenetic/openwrt/install-openwrt.sh
#   sh /tmp/install-openwrt.sh --yes
#
# Offline/local: run from an extracted archive (susanin-agent next to this file):
#   sh install-openwrt.sh [--yes]
#
# Options:
#   --arch LABEL      force arch asset (mipsel_24kc | aarch64_cortex-a53)
#   --version TAG     pin version (openwrt-vX.Y.Z or vX.Y.Z)
#   --egress IF       VPN egress interface (e.g. wg0)
#   --lan IF[,IF]     LAN interface(s) (e.g. br-lan)
#   --subnets CIDR,.. LAN subnets
#   --deps            install required packages via opkg before installing
#   --yes|-y          skip confirmation prompts
#   --force           overwrite existing config
#   --no-start        install but do not enable/start the service
#
# Layout (platform=openwrt, see src/platform.c):
#   bin /usr/bin   etc /etc/susanin   var /var/lib/susanin   tools /usr/lib/susanin
set -eu

REPO="R17a/Susanin.Keenetic"
DEFAULT_TAG="openwrt-v0.3.8"

BINDIR=/usr/bin
ETCDIR=/etc/susanin
VARDIR=/var/lib/susanin
TOOLSDIR=/usr/lib/susanin
INITD=/etc/init.d

ARCH_LABEL=""
VERSION=""
EGRESS=""
LAN=""
SUBNETS=""
YES=0
FORCE=0
NO_START=0
DEPS=0

say() { echo "[susanin] $*"; }
die() { echo "[susanin] ERROR: $*" >&2; exit 1; }

usage() {
    cat <<EOF
usage: $0 [--arch LABEL] [--version TAG] [--egress IF] [--lan IF,IF]
          [--subnets CIDR,CIDR] [--deps] [--yes] [--force] [--no-start]
  --arch     mipsel_24kc | aarch64_cortex-a53 (default: autodetect)
  --version  openwrt-vX.Y.Z | vX.Y.Z (default: newest OpenWRT release)
  --deps     opkg install ipset conntrack-tools iptables-legacy ip-full + kmods
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --arch) ARCH_LABEL="$2"; shift ;;
        --version) VERSION="$2"; shift ;;
        --egress) EGRESS="$2"; shift ;;
        --lan) LAN="$2"; shift ;;
        --subnets) SUBNETS="$2"; shift ;;
        --deps) DEPS=1 ;;
        --yes|-y) YES=1 ;;
        --force) FORCE=1 ;;
        --no-start) NO_START=1 ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown arg: $1" ;;
    esac
    shift
done

[ "$(id -u 2>/dev/null || echo 1)" = "0" ] || die "run as root"

# --- fetch helpers ----------------------------------------------------------
if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL "$1" -o "$2"; }
    fetch_stdout() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -qO "$2" "$1"; }
    fetch_stdout() { wget -qO- "$1"; }
elif command -v uclient-fetch >/dev/null 2>&1; then
    fetch() { uclient-fetch -q -O "$2" "$1"; }
    fetch_stdout() { uclient-fetch -q -O- "$1"; }
else
    fetch() { return 1; }
    fetch_stdout() { return 1; }
    say "WARNING: no curl/wget/uclient-fetch (opkg install ca-bundle curl)"
fi

detect_arch() {
    [ -n "$ARCH_LABEL" ] && return 0
    m=$(uname -m 2>/dev/null || echo unknown)
    case "$m" in
        mipsel*) ARCH_LABEL=mipsel_24kc ;;
        aarch64) ARCH_LABEL=aarch64_cortex-a53 ;;
        *) die "unsupported arch '$m'; pass --arch mipsel_24kc|aarch64_cortex-a53" ;;
    esac
}

resolve_version() {
    if [ -n "$VERSION" ]; then
        case "$VERSION" in
            openwrt-*) echo "$VERSION" ;;
            *) echo "openwrt-$VERSION" ;;
        esac
        return 0
    fi
    tag=$(fetch_stdout "https://api.github.com/repos/$REPO/releases?per_page=30" 2>/dev/null | \
          grep -o '"tag_name": *"openwrt-v[^"]*"' | head -n1 | \
          sed 's/.*"\(openwrt-v[^"]*\)".*/\1/') || true
    if [ -n "${tag:-}" ]; then
        echo "$tag"
    else
        echo "$DEFAULT_TAG"
    fi
}

install_deps() {
    say "installing dependencies via opkg"
    opkg update || true
    opkg install ipset conntrack-tools iptables-legacy ip-full ca-bundle \
        kmod-ipset kmod-ipt-conntrack kmod-ipt-connmark kmod-ipt-tcp-mss || true
}

DIR0=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd 2>/dev/null || echo .)

if [ -f "$DIR0/susanin-agent" ]; then
    DIR=$DIR0
    say "local package: $DIR"
else
    [ -n "$ARCH_LABEL" ] || detect_arch
    if [ -z "$VERSION" ]; then VERSION=$(resolve_version); fi
    ASSET="susanin-openwrt-$ARCH_LABEL.tar.gz"
    BASE="https://github.com/$REPO/releases/download/$VERSION"
    say "arch=$ARCH_LABEL version=$VERSION"
    TMP=$(mktemp -d /tmp/susanin-owrt.XXXXXX)
    trap 'rm -rf "$TMP"' EXIT INT TERM
    say "downloading $BASE/$ASSET"
    fetch "$BASE/$ASSET" "$TMP/pkg.tar.gz" || die "download failed: $BASE/$ASSET
     hint: opkg update && opkg install ca-bundle"
    tar -xzf "$TMP/pkg.tar.gz" -C "$TMP" || die "bad archive $ASSET"
    DIR=$TMP
fi

# --- dependencies / data plane sanity ---------------------------------------
[ "$DEPS" -eq 1 ] && install_deps

miss=""
for t in ipset conntrack iptables; do
    command -v "$t" >/dev/null 2>&1 || miss="$miss $t"
done
if [ -n "$miss" ]; then
    say "WARNING: missing tools:$miss"
    say "  opkg update && opkg install ipset conntrack-tools iptables-legacy ip-full ca-bundle"
    say "  kmods: kmod-ipset kmod-ipt-conntrack kmod-ipt-connmark kmod-ipt-tcp-mss"
    say "  (or re-run with --deps)"
fi
if ! iptables -t mangle -S >/dev/null 2>&1; then
    say "WARNING: 'iptables -t mangle' failed — OpenWRT 22.03+ ships nftables (fw4)."
    say "  Install iptables-legacy (this build uses legacy iptables)."
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
if [ -f "$DIR/owrt-report.sh" ]; then
    cp "$DIR/owrt-report.sh" "$TOOLSDIR/owrt-report.sh"
    chmod 0755 "$TOOLSDIR/owrt-report.sh"
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
say "check: $INITD/susanin status ; $BINDIR/susanin-agent status ; log: $VARDIR/susanin.log"
