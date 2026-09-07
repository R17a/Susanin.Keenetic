#!/bin/sh
# wsl-build.sh — run inside WSL (as root) to cross-compile susanin-agent for MIPS.
# The project folder is taken from the location of this script, so the script is
# portable (no absolute local paths).
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SRC=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
DEST="/root/Susanin.Keenetic"

[ -d "$SRC" ] || { echo "source not found: $SRC" >&2; exit 1; }

rm -rf "$DEST"
cp -r "$SRC" "$DEST"
cd "$DEST"

make clean >/dev/null 2>&1 || true
make CC=mipsel-linux-gnu-gcc \
     CFLAGS="-O2 -std=c11 -Wall -Wextra -Wpedantic -static" \
     LDFLAGS="-static"

echo "=== artifact ==="
file susanin-agent
mipsel-linux-gnu-readelf -h susanin-agent 2>/dev/null | grep -iE 'Class|Data|Machine' || true

mkdir -p "$SRC/build"
cp susanin-agent "$SRC/build/susanin-agent.mipsel"
cp -f config.example.conf "$SRC/build/susanin.conf.example"
echo "=== delivered ==="
ls -l "$SRC/build/"
