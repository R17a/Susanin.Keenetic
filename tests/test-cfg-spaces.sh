#!/bin/sh
# Проверка: susanin.conf читается одной грамматикой.
#
# Повод: агент после единого разбора строки принимает «ключ = значение»,
# а shell-читатели того же файла (web_enable, tz, xray_*, egress_type,
# disk_mode) требовали «ключ=значение» без пробелов. Для оператора это
# означало «настроил — не работает»: агент считал панель включённой, а
# S95susanin-web её не запускал.
#
# Два уровня: статический страж (ни один поставляемый файл не читает конфиг
# нетерпимым паттерном) и функциональная проверка двух решений, которые
# можно вырезать из скрипта и вызвать.
#
# make test (хост; в поставку не входит).

set -u
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
bad=0

ok() { echo "ok   $1"; }
fail() { echo "FAIL $1"; bad=$((bad + 1)); }

FILES="install.sh tools/susanin.sh tools/datapath.sh tools/diagnose.sh tools/update.sh tools/xray-egress.sh init/entware/S93xray-tproxy init/entware/S94susanin init/entware/S95susanin-web"

echo "=== 1. ни один читатель не требует «ключ=значение» без пробелов ==="
for f in $FILES; do
    p="$ROOT/$f"
    [ -f "$p" ] || continue
    # нетерпимый вид: s/^<ключ или $1>=//p  (без [[:space:]] после ^ и вокруг =)
    hits=$(grep -nE "s/\^\\\$?[a-zA-Z_0-9]+=\[/p|s/\^\\\$?[a-zA-Z_0-9]+=//p" "$p" 2>/dev/null || true)
    if [ -n "$hits" ]; then
        echo "$hits" | sed 's/^/     /'
        fail "$f: читает конфиг нетерпимо"
    fi
done
[ "$bad" = "0" ] && ok "все поставляемые читатели толерантны к пробелам"

echo
echo "=== 2. живое решение susanin.sh (функции взяты из самого скрипта) ==="
P=$(mktemp -d "${TMPDIR:-/tmp}/susanin-spaces.XXXXXX") || exit 1
CONF="$P/susanin.conf"
_fn=$(mktemp "$P/fn.XXXXXX")
sed -n '/^web_enabled()/,/^}/p;/^disk_mode_of()/,/^}/p' "$ROOT/tools/susanin.sh" > "$_fn"
# shellcheck disable=SC1090
. "$_fn"

check() {  # check <описание> <команда>
    _d=$1; shift
    if ( eval "$*" ); then ok "$_d"; else fail "$_d"; fi
}

printf 'web_enable = 1\n' > "$CONF"
check "«web_enable = 1» включает панель" 'web_enabled'
printf 'web_enable=1\n' > "$CONF"
check "«web_enable=1» по-прежнему включает" 'web_enabled'
printf 'web_enable = 0\n' > "$CONF"
if web_enabled; then fail "«web_enable = 0» не должен включать"; else ok "«web_enable = 0» не включает"; fi
printf '# web_enable = 1\nweb_enable = 0\n' > "$CONF"
if web_enabled; then fail "закомментированное значение прочитано"; else ok "комментарий не считается значением"; fi
printf 'tz = Europe/Moscow\ndisk_mode = soft\n' > "$CONF"
check "«disk_mode = soft» прочитан" '[ "$(disk_mode_of)" = "soft" ]'

echo
echo "=== 3. совпадение с агентом на той же форме ==="
printf 'disk_mode = soft\nweb_enable = 1\n' > "$CONF"
_c=$(SUSANIN_CONF="$CONF" "$ROOT/susanin-agent" config show 2>/dev/null | sed -n 's/^disk_mode=//p')
if [ "$_c" = "soft" ]; then
    ok "агент и shell дают один и тот же ответ на «disk_mode = soft»"
else
    fail "агент дал [$_c], ожидалось soft"
fi

rm -rf "$P"
echo
if [ "$bad" = "0" ]; then
    echo "ИТОГ: все проверки пройдены"
    exit 0
fi
echo "ЕСТЬ ОШИБКИ: $bad"
exit 1
