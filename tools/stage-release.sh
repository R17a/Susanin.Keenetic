#!/bin/sh
# stage-release.sh — подготовить каталог для tar-архива релиза (CI) по единому
# списку поставки packaging/manifest.txt. Раскладка архива — «плоская», как у
# прежних релизов: скрипты и init в корне, статика в www/, доки в docs/.
#
# Usage: sh tools/stage-release.sh --out STAGE --bin susanin-agent
set -eu

SRC=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
MAN="$SRC/packaging/manifest.txt"
OUT=""
BIN="susanin-agent"

die() { echo "stage-release: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --bin) BIN="$2"; shift 2 ;;
        -h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "неизвестный параметр: $1" ;;
    esac
done

[ -n "$OUT" ] || die "нужен --out DIR"
[ -f "$SRC/$BIN" ] || die "нет бинарника $SRC/$BIN"
[ -f "$MAN" ] || die "нет $MAN"

mkdir -p "$OUT/www" "$OUT/docs"
cp "$SRC/$BIN" "$OUT/susanin-agent"
chmod 755 "$OUT/susanin-agent"

grep -vE '^[[:space:]]*(#|$)' "$MAN" | while read -r cls src; do
    [ -n "${src:-}" ] || continue
    if [ ! -e "$SRC/$src" ]; then
        die "в манифесте $src, но файла нет (чистый чекаут? проверьте packaging/manifest.txt)"
    fi
    case "$cls" in
        tool|init)  cp "$SRC/$src" "$OUT/$(basename "$src")" ;;
        doc)        cp "$SRC/$src" "$OUT/docs/$(basename "$src")" ;;
        share)      cp "$SRC/$src" "$OUT/$(basename "$src")" ;;
        ayserver)   cp -r "$SRC/$src" "$OUT/ay-server" ;;
        ndmhook)    cp "$SRC/$src" "$OUT/$(basename "$src")" ;;
        cfg)        cp "$SRC/$src" "$OUT/config.example.conf" ;;
        www)        cp -r "$SRC/$src/." "$OUT/www/" ;;
        root)       cp "$SRC/$src" "$OUT/$(basename "$src")" ;;
        *)          die "неизвестный класс '$cls' в манифесте" ;;
    esac
done

# init-скрипты должны быть исполняемыми (в архиве они ставятся в /opt/etc/init.d)
for f in "$OUT"/S9*; do [ -f "$f" ] && chmod 755 "$f"; done
for f in "$OUT"/*.sh; do [ -f "$f" ] && chmod 755 "$f"; done

echo "stage-release: готово ($(find "$OUT" -type f | wc -l) файлов) в $OUT"
