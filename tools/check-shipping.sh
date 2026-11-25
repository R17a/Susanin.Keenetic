#!/bin/sh
# check-shipping.sh — единый список поставки (packaging/manifest.txt) против
# фактического содержимого пакетов. Проверяет:
#   1) все файлы из манифеста существуют в репозитории;
#   2) каждый файл из tools/ — либо в манифесте, либо в packaging/dev-only.txt;
#   2b) каждый файл из init/entware/ — тоже;
#   3) если задан .ipk — в нём есть всё из манифеста и нет dev-only-скриптов.
#
# Usage:
#   sh tools/check-shipping.sh                 # только (1) и (2)
#   sh tools/check-shipping.sh --ipk dist/x.ipk
set -u

SRC=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
MAN="$SRC/packaging/manifest.txt"
DEVONLY="$SRC/packaging/dev-only.txt"
IPK=""
CHK_IPK=0

while [ $# -gt 0 ]; do
    case "$1" in
        --ipk) IPK="$2"; CHK_IPK=1; shift 2 ;;
        -h|--help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "check-shipping: неизвестный параметр: $1" >&2; exit 2 ;;
    esac
done

[ -f "$MAN" ] || { echo "check-shipping: нет $MAN" >&2; exit 1; }
BAD=0
note() { echo "  $*"; }
fail() { echo "  FAIL: $*"; BAD=1; }

echo "== 1. манифест: файлы на месте =="
LIST=$(mktemp 2>/dev/null || echo /tmp/susanin-man.$$)
grep -vE '^[[:space:]]*(#|$)' "$MAN" > "$LIST"
while read -r cls src; do
    [ -n "${src:-}" ] || continue
    case "$cls" in
        tool|init|doc|share|cfg|www|ayserver|ndmhook|root) ;;
        *) fail "неизвестный класс '$cls' у '$src'"; continue ;;
    esac
    if [ ! -e "$SRC/$src" ]; then
        fail "в манифесте '$src', но файла нет"
    fi
done < "$LIST"
note "проверено записей: $(wc -l < "$LIST")"

echo "== 2. tools/: каждый файл либо поставляется, либо dev-only =="
for f in "$SRC"/tools/*; do
    [ -f "$f" ] || continue
    b=$(basename "$f")
    if grep -qE "^tool[[:space:]]+tools/${b}$" "$LIST"; then continue; fi
    if [ -f "$DEVONLY" ] && grep -qE "^tools/${b}[[:space:]]" "$DEVONLY"; then continue; fi
    fail "tools/$b не учтён ни в manifest.txt, ни в dev-only.txt"
done
note "dev-only: $([ -f "$DEVONLY" ] && grep -cE '^(tools|init)/' "$DEVONLY" || echo 0) запис(ей)"

echo "== 2b. init/entware/: каждый файл либо поставляется, либо dev-only =="
for f in "$SRC"/init/entware/*; do
    [ -f "$f" ] || continue
    b=$(basename "$f")
    if grep -qE "^init[[:space:]]+init/entware/${b}$" "$LIST"; then continue; fi
    if [ -f "$DEVONLY" ] && grep -qE "^init/entware/${b}[[:space:]]" "$DEVONLY"; then continue; fi
    fail "init/entware/$b не учтён ни в manifest.txt, ни в dev-only.txt"
done

echo "== 3. .ipk =="
if [ "$CHK_IPK" = 1 ]; then
    [ -n "$IPK" ] && [ -f "$IPK" ] || { IPK=$(ls -1 "$SRC"/dist/*.ipk 2>/dev/null | head -1); }
    if [ -z "${IPK:-}" ] || [ ! -f "${IPK:-}" ]; then
        fail "нет .ipk (укажите --ipk FILE)"
    else
        T=$(mktemp -d)
        # .ipk бывает двух видов: gzip(tar) с ./data.tar.gz (как в фиде Entware)
        # или классический ar-архив с членом data.tar.gz. Поддерживаем оба.
        if tar -xzOf "$IPK" ./data.tar.gz > "$T/data.tar.gz" 2>/dev/null && \
           gzip -t "$T/data.tar.gz" 2>/dev/null; then
            :
        elif ar p "$IPK" data.tar.gz > "$T/data.tar.gz" 2>/dev/null && \
             gzip -t "$T/data.tar.gz" 2>/dev/null; then
            :
        else
            fail "не читается $IPK (ни tar-, ни ar-формат)"
        fi
        ( cd "$T" && tar -xzf data.tar.gz 2>/dev/null )
        while read -r cls src; do
            [ -n "${src:-}" ] || continue
            case "$cls" in
                tool)  p="opt/susanin/tools/$(basename "$src")" ;;
                init)  p="opt/etc/init.d/$(basename "$src")" ;;
                doc)   p="opt/susanin/docs/$(basename "$src")" ;;
                share) p="opt/susanin/share/$(basename "$src")" ;;
                cfg)   p="opt/susanin/share/susanin.conf.example" ;;
                www)   p="opt/susanin/www/index.html" ;;
                ayserver) p="opt/susanin/ay-server" ;;
                ndmhook) p="opt/etc/ndm/netfilter.d/$(basename "$src")" ;;
                root)  continue ;;
                *) continue ;;
            esac
            [ -e "$T/$p" ] || fail "в .ipk нет $p ($(basename "$IPK"))"
        done < "$LIST"
        # dev-only скрипты не должны попадать в пакет
        if [ -f "$DEVONLY" ]; then
            while read -r b _rest; do
                case "$b" in ''|'#'*) continue ;; esac
                [ -e "$T/opt/susanin/tools/$b" ] && fail "dev-only $b попал в .ipk"
            done < "$DEVONLY"
        fi
        note "проверен $(basename "$IPK")"
        rm -rf "$T"
    fi
fi

rm -f "$LIST"
echo
if [ "$BAD" = 0 ]; then
    echo "check-shipping: всё сходится"
else
    echo "check-shipping: ЕСТЬ РАСХОЖДЕНИЯ"
fi
exit "$BAD"
