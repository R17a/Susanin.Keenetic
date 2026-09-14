#!/bin/sh
# sdk-build.sh — build susanin-agent with an OpenWRT SDK (musl) for one target.
#
# Run on a Linux host (WSL/container/VM) with wget.
#
# Usage:
#   tools/sdk-build.sh <release> <target>/<subtarget>
#   tools/sdk-build.sh 24.10.8 ramips/mt7621
#
# Env:
#   SDK_DIR  already-extracted SDK root (skips the download)
#   CACHE    download/extract cache (default /tmp/susanin-sdk)
#
# Result: build/susanin-agent.openwrt-<subtarget> (static, platform=openwrt)
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SRC=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

REL=${1:-}
TS=${2:-}
if [ -z "$REL" ] || [ -z "$TS" ]; then
    echo "usage: $0 <release> <target>/<subtarget>" >&2
    echo "  e.g. $0 24.10.8 ramips/mt7621" >&2
    exit 2
fi
TARGET=${TS%%/*}
SUB=${TS#*/}
if [ "$TARGET" = "$TS" ]; then
    echo "target must be <target>/<subtarget>" >&2
    exit 2
fi

CACHE=${CACHE:-/tmp/susanin-sdk}
mkdir -p "$CACHE"

if [ -z "${SDK_DIR:-}" ]; then
    BASE="https://downloads.openwrt.org/releases/$REL/targets/$TARGET/$SUB"
    echo "== resolving SDK for $REL $TARGET/$SUB =="
    name=$(wget -qO- "$BASE/" | \
        grep -oE "openwrt-sdk-${REL}-${TARGET}-${SUB}_[^\"]*musl[^\"]*Linux-x86_64\.tar\.[a-z]+" | \
        head -n1)
    if [ -z "$name" ]; then
        echo "SDK not found at $BASE" >&2
        exit 1
    fi
    tar="$CACHE/$name"
    if [ ! -f "$tar" ]; then
        echo "== downloading $name =="
        wget -O "$tar" "$BASE/$name"
    else
        echo "== cached: $tar =="
    fi
    echo "== extracting =="
    rm -rf "$CACHE/sdk"
    mkdir -p "$CACHE/sdk"
    case "$name" in
        *.tar.zst) TAROPT="--zstd" ;;
        *)         TAROPT="" ;;
    esac
    tar $TAROPT -xf "$tar" -C "$CACHE/sdk" --strip-components=1
    SDK_DIR="$CACHE/sdk"
fi

CC=$(ls "$SDK_DIR"/staging_dir/toolchain-*/bin/*-openwrt-linux-musl*-gcc 2>/dev/null | head -n1)
if [ -z "$CC" ]; then
    echo "no musl cross-gcc found in $SDK_DIR/staging_dir" >&2
    exit 1
fi
echo "== cc: $CC =="

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM
tar -C "$SRC" --exclude=.git --exclude=build --exclude=deploy -cf - . | \
    tar -C "$WORK" -xf -

export STAGING_DIR="$SDK_DIR/staging_dir"
( cd "$WORK" && { make clean >/dev/null 2>&1 || true; } && \
  make CC="$CC" PLATFORM=openwrt \
       CFLAGS="-O2 -std=c11 -Wall -Wextra -Wpedantic -static" \
       LDFLAGS="-static" )

OUT="$SRC/build/susanin-agent.openwrt-$TARGET-$SUB"
mkdir -p "$SRC/build"
cp "$WORK/susanin-agent" "$OUT"
chmod 0755 "$OUT"
command -v file >/dev/null 2>&1 && file "$OUT" || true
echo "== done: $OUT =="
