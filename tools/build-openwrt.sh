#!/bin/sh
# build-openwrt.sh — build and pack OpenWRT deploy archives for every entry in
# tools/owrt-targets.txt (one representative target per CPU architecture; the
# produced binaries are static musl, so they run on every device of that arch).
#
# Usage: tools/build-openwrt.sh [--strict]
#   --strict  exit non-zero if any target failed (default: continue and report)
#
# Requirements: wget, tar with zstd, make, POSIX shell. Run on Linux (WSL/CI).
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SRC=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
LIST="$SCRIPT_DIR/owrt-targets.txt"
STRICT=0
[ "${1:-}" = "--strict" ] && STRICT=1

[ -f "$LIST" ] || { echo "missing $LIST" >&2; exit 1; }

rc=0
failed=""
while read -r rel target arch; do
    case "${rel:-}" in
        ''|'#'*) continue ;;
    esac
    [ -n "${arch:-}" ] || continue
    echo "=== $arch  ($target, $rel) ==="
    if sh "$SCRIPT_DIR/sdk-build.sh" "$rel" "$target"; then
        t=${target%%/*}
        s=${target#*/}
        if ! sh "$SCRIPT_DIR/owrt-package.sh" "$SRC/build/susanin-agent.openwrt-$t-$s" "$arch"; then
            echo "!!! package failed: $arch" >&2
            rc=1
            failed="$failed $arch"
        fi
    else
        echo "!!! build failed: $arch ($target)" >&2
        rc=1
        failed="$failed $arch"
    fi
done < "$LIST"

echo "=============================================="
if [ "$rc" -eq 0 ]; then
    echo "all targets built"
else
    echo "failures:$failed"
fi
ls -1 "$SRC/deploy-openwrt" 2>/dev/null || true
[ "$STRICT" -eq 1 ] && exit "$rc"
exit 0
