#!/bin/sh
# Проверка миграции конфига в install.sh/update.sh. Скрипт берёт НАСТОЯЩИЕ
# блоки из поставляемых файлов (между маркерами) и выполняет их с подставным
# PREFIX — иначе тестировалась бы моя интерпретация, а не код, который
# реально запускается при установке.
#
# Запуск: make test   (нужен собранный хост-бинарник ./susanin-agent)
set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BIN="$ROOT/susanin-agent"
say() { echo "[test] $*"; }
fail=0

[ -x "$BIN" ] || { echo "FAIL: нет $BIN (сначала make)"; exit 1; }

run_block() { # run_block <файл> — вырезает участок MIGRATION-BEGIN..END
    _f="$1"
    _blk=$(mktemp "${TMPDIR:-/tmp}/susanin-block.XXXXXX" 2>/dev/null) || return 1
    sed -n '/# --- MIGRATION-BEGIN/,/# --- MIGRATION-END/p' "$_f" \
        | sed '1d;$d' > "$_blk" || { rm -f "$_blk"; return 1; }
    if [ ! -s "$_blk" ]; then
        echo "FAIL: в $_f нет участка MIGRATION-BEGIN/END"
        rm -f "$_blk"; return 1
    fi
    # shellcheck disable=SC1091
    . "$_blk"
    _rc=$?
    rm -f "$_blk"
    return $_rc
}

check() { # check <условие-текст> <описание>
    if eval "$1"; then echo "ok   $2"; else echo "FAIL $2"; fail=$((fail + 1)); fi
}

P=$(mktemp -d "${TMPDIR:-/tmp}/susanin-inst.XXXXXX") || exit 1
mkdir -p "$P/bin" "$P/etc"
cp "$BIN" "$P/bin/susanin-agent"

# Легаси-конфиг: мало ключей, один в форме «key = value», прежний дефолт
# promo_per_min, disk_mode отсутствует.
cat > "$P/etc/susanin.conf" <<'EOF'
# old config
egress_type=tproxy
lan_interfaces = br0, br1
promo_per_min=30
EOF

PREFIX="$P"
export PREFIX

echo "=== install.sh: дописывание ключей ==="
if run_block "$ROOT/install.sh"; then
    check '[ "$(grep -c "^synfail_quorum=" "$P/etc/susanin.conf")" = 1 ]' \
          "новый ключ дописан из действующего дефолта"
    check '[ "$(grep -c "^ru_guard=" "$P/etc/susanin.conf")" = 1 ]' \
          "ключи, которых не было в рукописном списке, тоже дописаны"
    check '[ "$(sed -n "s/^promo_per_min=//p" "$P/etc/susanin.conf")" = 120 ]' \
          "promo_per_min 30 -> 120 (миграция прежнего дефолта)"
    # Дубль ловится по любой форме записи: «key=», «key =», с отступом.
    check '[ "$(grep -Ec "^[[:space:]]*lan_interfaces[[:space:]]*=" "$P/etc/susanin.conf")" = 1 ]' \
          "ключ с пробелами не получил дубля"
    check '[ "$(SUSANIN_CONF="$P/etc/susanin.conf" "$ROOT/susanin-agent" config show \
                  | sed -n "s/^lan_interfaces=//p")" = "br0, br1" ]' \
          "и его значение реально читается после миграции"
    check '[ "$(grep -c "^media_ports=80," "$P/etc/susanin.conf")" = 0 ]' \
          "опасный media_ports 80/443 из рукописного списка больше не пишется"
    check '[ "$("$ROOT/susanin-agent" config show >/dev/null 2>&1; echo $?)" = 0 ]' \
          "после миграции конфиг читается"
else
    echo "FAIL: блок install.sh не выполнился"; fail=$((fail + 1))
fi

echo "=== install.sh: disk_mode не затирает выбор оператора ==="
# Сценарий: пользователь поставил normal, повторный запуск без --disk-mode
# (авто-определение говорит soft) не должен его менять.
DISK_MODE=soft
DISK_MODE_SET=0
grep -q '^disk_mode=' "$P/etc/susanin.conf" || echo "disk_mode=normal" >> "$P/etc/susanin.conf"
DM_BLOCK=$(sed -n '/# disk_mode: явный --disk-mode применяется всегда/,/^fi$/p' "$ROOT/install.sh")
if [ -n "$DM_BLOCK" ]; then
    eval "$DM_BLOCK" >/dev/null 2>&1
    check '[ "$(sed -n "s/^disk_mode=//p" "$P/etc/susanin.conf" | tail -n1)" = normal ]' \
          "авто-режим не перезаписал явный normal"
    DISK_MODE_SET=1
    eval "$DM_BLOCK" >/dev/null 2>&1
    check '[ "$(sed -n "s/^disk_mode=//p" "$P/etc/susanin.conf" | tail -n1)" = soft ]' \
          "--disk-mode по-прежнему применяется (явная команда важнее)"
else
    echo "FAIL: блок disk_mode не найден в install.sh"; fail=$((fail + 1))
fi

echo "=== update.sh: тот же механизм, другой сценарий ==="
cat > "$P/etc/susanin.conf" <<'EOF'
egress_type=interface
routing_table=100
EOF
if run_block "$ROOT/tools/update.sh"; then
    check '[ "$(grep -c "^synfail_window=" "$P/etc/susanin.conf")" = 1 ]' \
          "update.sh дописывает недостающие ключи через агента"
    check '[ "$(grep -c "^ok_ttl=" "$P/etc/susanin.conf")" = 1 ]' \
          "и не дублирует существующие"
else
    echo "FAIL: блок update.sh не извлечён"; fail=$((fail + 1))
fi

echo "=== config show: вывод пригоден для обратного чтения ==="
# Вывод показывают людям, но копируют в susanin.conf. Значит он обязан
# перечитываться без замечаний и быть устойчивым к повторному прогону
# (показал -> прочитал -> показал то же).
"$BIN" config show > "$P/show1.conf" 2>/dev/null
check '[ "$(SUSANIN_CONF="$P/show1.conf" "$BIN" config check >/dev/null 2>&1; echo $?)" = 0 ]' \
      "вывод config show проходит config check без замечаний"
SUSANIN_CONF="$P/show1.conf" "$BIN" config show > "$P/show2.conf" 2>/dev/null
check 'cmp -s "$P/show1.conf" "$P/show2.conf"' \
      "вторичный прогон идентичен первому (нет приписок, съедающих значение)"
check '[ "$(grep -c "precision=(выкл)" "$P/show1.conf")" = 0 ]' \
      "служебные пояснения не попадают в значения"

echo "=== susanin.sh: disk_mode=soft => лог не ведётся ==="
# Функции берутся из настоящего скрипта запуска: проверяем его решение, а не
# свою пересказанную версию.
_fn=$(mktemp "${TMPDIR:-/tmp}/susanin-fns.XXXXXX" 2>/dev/null) || _fn=""
if [ -n "$_fn" ]; then
    sed -n '/^disk_mode_of()/,/^}/p;/^log_dest()/,/^}/p' "$ROOT/tools/susanin.sh" > "$_fn"
    # shellcheck disable=SC1091
    . "$_fn"
    CONF="$P/mode.conf"
    LOG="$P/susanin.log"

    printf 'disk_mode=soft\n' > "$CONF"
    check '[ "$(log_dest "$LOG")" = "/dev/null" ]' "soft: вывод идёт в /dev/null"
    check '[ "$(disk_mode_of)" = "soft" ]' "soft: режим прочитан"

    printf 'disk_mode = normal\n' > "$CONF"
    check '[ "$(log_dest "$LOG")" = "$LOG" ]' "normal: вывод идёт в файл лога"
    check '[ "$(disk_mode_of)" = "normal" ]' "форма «key = value» прочитана (пробелы)"

    printf 'disk_mode=normal\ndisk_mode=soft\n' > "$CONF"
    check '[ "$(log_dest "$LOG")" = "/dev/null" ]' \
          "при двух строках побеждает последняя (как в config_load)"
    printf 'disk_mode=soft\n# disk_mode=normal\n' > "$CONF"
    check '[ "$(log_dest "$LOG")" = "/dev/null" ]' \
          "закомментированное значение не меняет решения"
    rm -f "$_fn"
else
    echo "FAIL: mktemp недоступен"; fail=$((fail + 1))
fi

echo "=== merge списков: тест вынесен в tests/test-list-merge.sh ==="
# Он не требует ни бинарника, ни сети, ни ipset, но прогоняется отсюда, чтобы
# `make test` гарантированно его запускал (файлы merge_list общие: install.sh,
# tools/update.sh, opkg/postinst).
if [ -f "$ROOT/tests/test-list-merge.sh" ]; then
    if sh "$ROOT/tests/test-list-merge.sh"; then
        echo "ok   merge_list: всё сходится"
    else
        echo "FAIL merge_list: есть ошибки (см. вывод выше)"
        fail=$((fail + 1))
    fi
else
    echo "FAIL: нет $ROOT/tests/test-list-merge.sh"
    fail=$((fail + 1))
fi

rm -rf "$P"
echo
if [ "$fail" = 0 ]; then echo "ИТОГ: все проверки пройдены"; else echo "ЕСТЬ ОШИБКИ ($fail)"; fi
exit $((fail ? 1 : 0))
