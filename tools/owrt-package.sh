#!/bin/sh
# owrt-package.sh — stage and pack one OpenWRT deploy archive.
#
# Usage: tools/owrt-package.sh <agent-binary> <arch-label>
# Result: deploy-openwrt/susanin-openwrt-<arch-label>.tar.gz
#
# Archive layout (what install-openwrt.sh expects next to it):
#   susanin-agent      datapath.sh      susanin (procd init)
#   install-openwrt.sh config.example.conf vpn_always.txt vpn_never.txt
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SRC=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

BIN=${1:-}
ARCH=${2:-}
if [ -z "$BIN" ] || [ -z "$ARCH" ]; then
    echo "usage: $0 <agent-binary> <arch-label>" >&2
    exit 2
fi
[ -f "$BIN" ] || { echo "no binary: $BIN" >&2; exit 1; }

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT INT TERM

cp "$BIN" "$STAGE/susanin-agent"
cp "$SRC/tools/datapath.sh" "$STAGE/datapath.sh"
cp "$SRC/tools/owrt-report.sh" "$STAGE/owrt-report.sh"
cp "$SRC/tools/diagnose.sh" "$STAGE/diagnose.sh"
cp "$SRC/init/openwrt/susanin" "$STAGE/susanin"
cp "$SRC/install-openwrt.sh" "$STAGE/install-openwrt.sh"
cp "$SRC/config.example.conf" "$STAGE/config.example.conf"
cp "$SRC/vpn_always.txt" "$STAGE/vpn_always.txt"
cp "$SRC/vpn_never.txt" "$STAGE/vpn_never.txt"
[ -f "$SRC/DEPLOY.md" ] && cp "$SRC/DEPLOY.md" "$STAGE/DEPLOY.md" || true

mkdir -p "$SRC/deploy-openwrt"
OUT="$SRC/deploy-openwrt/susanin-openwrt-$ARCH.tar.gz"
tar -czf "$OUT" -C "$STAGE" .
chmod 0644 "$OUT"
echo "packed: $OUT"
