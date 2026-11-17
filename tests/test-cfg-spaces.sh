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

FILES=""
if [ -f "$ROOT/packaging/manifest.txt" ]; then
    # Список = всё, что уезжает в пакет (классы tool/init/cfg/share/www/root;
    # каталоги разворачиваются в *.sh), плюс скрипты opkg. Пути,
    # которых нет в репозитории, пропускаются без падения.
    while read -r _cls _path _rest; do
        case "$_cls" in tool|init|cfg|share|www|root) ;; *) continue ;; esac
        [ -n "$_path" ] || continue
        if [ -d "$ROOT/$_path" ]; then
            for _g in $(find "$ROOT/$_path" -type f -name '*.sh' | sed "s|^$ROOT/||"); do
                FILES="$FILES $_g"
            done
        elif [ -f "$ROOT/$_path" ]; then
            FILES="$FILES $_path"
        fi
    done < "$ROOT/packaging/manifest.txt"
fi
FILES="$FILES opkg/postinst opkg/prerm opkg/postrm"

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

echo "=== 1b. хвост значения срезается читателем (как в config_load) ==="
for f in $FILES; do
    p="$ROOT/$f"
    [ -f "$p" ] || continue
    hits=$(grep -nE 's/\^\[\[:space:\]\]\*(\$?[a-zA-Z_0-9]+)\[\[:space:\]\]\*=\[\[:space:\]\]\*//p' "$p" 2>/dev/null || true)
    if [ -n "$hits" ]; then
        echo "$hits" | sed 's/^/     /'
        fail "$f: читатель возвращает значение с хвостовыми пробелами"
    fi
done
ok "ни один читатель не оставляет хвост у значения"

echo "=== 1c. якорь ключа susanin.conf всегда с толерантностью к пробелам ==="
# Строка «касается» susanin.conf (или файла списков профилей, который агент
# разбирает той же грамматикой), если в ней есть путь конфига или переменная
# конфига. Такой якорь обязан допускать пробелы вокруг '=' (форма агента):
# «ключ = значение» не должен ни молча перечитываться дублем при записи, ни
# теряться при проверке. Строки-комментарии не проверяем — они ничего не
# читают и не пишут.
bad2=0
SCOPE='susanin\.conf|\$[{]?CONF|\$MERGED|\$_f'
# a) после якоря идёт ключ без ведущего «[[:space:]]*» (в т.ч. в группе «^(...»)
# b) '=' приклеен к ключу без «[[:space:]]*» (s|^KEY=, '^KEY=')
LEAD_RE='\^([[:alnum:]_$]|\([[:alnum:]_$])'
EQ_RE='\^[^\\"%=]*[[:alnum:]_$})]='
for f in $FILES; do
    p="$ROOT/$f"
    [ -f "$p" ] || continue
    hits=$(grep -nE "$LEAD_RE|$EQ_RE" "$p" 2>/dev/null | grep -E "$SCOPE" | grep -vE '^[0-9]+:[[:space:]]*#' || true)
    if [ -n "$hits" ]; then
        echo "$hits" | sed 's/^/     /'
        echo "FAIL $f: нетерпимый якорь ключа susanin.conf"
        bad2=$((bad2 + 1))
    fi
done
if [ "$bad2" = "0" ]; then ok "все якоря ключей susanin.conf толерантны к пробелам"; fi

echo "=== 1d. читатель значения: хвост срезан, взята ПОСЛЕДНЯЯ строка ==="
# Дубль ключа: агент берёт последнюю строку. Значит читатель обязан
# а) срезать хвост пробелов/tab/CR (форма с «[^[:space:]]» внутри) и
# б) отдавать tail, а не head — иначе читатели расходятся с агентом и друг
# с другом.
bad3=0
for f in $FILES; do
    p="$ROOT/$f"
    [ -f "$p" ] || continue
    readers=$(grep -nE "sed -n .*(s[\|/]|\^)" "$p" 2>/dev/null | grep -E "$SCOPE" | grep -vE '^[0-9]+:[[:space:]]*#' || true)
    [ -n "$readers" ] || continue
    hits=$(printf '%s\n' "$readers" | grep -vF '[^[:space:]]' || true)
    hheads=$(grep -nE 'sed -n .*\|[[:space:]]*head' "$p" 2>/dev/null | grep -E "$SCOPE" | grep -vE '^[0-9]+:[[:space:]]*#' || true)
    [ -n "$hheads" ] && hits="$hits
$hheads"
    hits=$(printf '%s\n' "$hits" | grep -v '^$' | sort -u || true)
    if [ -n "$hits" ]; then
        echo "$hits" | sed 's/^/     /'
        echo "FAIL $f: читатель susanin.conf оставляет хвост или берёт head вместо tail"
        bad3=$((bad3 + 1))
    fi
done
if [ "$bad3" = "0" ]; then ok "читатели susanin.conf режут хвост и берут последнюю строку"; fi

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
echo "=== 2b. хвостовые пробелы значения (агент их срезает — и shell обязан) ==="
printf 'disk_mode=soft   \n' > "$CONF"
check "«disk_mode=soft   » читается как soft" '[ "$(disk_mode_of)" = "soft" ]'
printf 'disk_mode=soft\t\n' > "$CONF"
check "табуляция в хвосте не мешает" '[ "$(disk_mode_of)" = "soft" ]'
printf 'web_enable = 1\t \n' > "$CONF"
check "«web_enable = 1 » с хвостом включает панель" 'web_enabled'
printf 'disk_mode=\n' > "$CONF"
check "пустое значение остаётся пустым" '[ -z "$(disk_mode_of)" ]'

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
if [ "$bad" = "0" ] && [ "$bad2" = "0" ] && [ "$bad3" = "0" ]; then
    echo "ИТОГ: все проверки пройдены"
    exit 0
fi
echo "ЕСТЬ ОШИБКИ: $((bad + bad2 + bad3))"
exit 1
