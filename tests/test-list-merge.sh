#!/bin/sh
# Проверка merge_list() — слияния списков vpn_always/vpn_never при установке и
# обновлении пакета. Функция вырезается ИЗ НАСТОЯЩИХ файлов (install.sh,
# tools/update.sh, opkg/postinst) и выполняется здесь, поэтому тестируется код
# поставки, а не его пересказ. Сеть, ipset и бинарник не нужны.
#
# Главное: запись опознаётся по имени без префикса мягкости '?', то есть
# «?домен» пользователя и «домен» из поставки — одна и та же запись. Буквально
# сравнивая строки, merge дописывал к мягкой записи жёсткого двойника, побеждала
# первая встретившаяся строка, и смягчение молча отменялось.
#
# Запуск: sh tests/test-list-merge.sh
set -u
LC_ALL=C
export LC_ALL

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fail=0
# say() нужен вырезанным merge_list() из install.sh/update.sh (в postinst echo).
say() { echo "  (merge) $*"; }

check() { # check <условие-текст> <описание>
    if eval "$1"; then echo "ok   $2"; else echo "FAIL $2"; fail=$((fail + 1)); fi
}

P=$(mktemp -d "${TMPDIR:-/tmp}/susanin-merge.XXXXXX") || exit 1
BLK="$P/blk.sh"; UF="$P/user.txt"; PF="$P/pkg.txt"
trap 'rm -rf "$P"' EXIT INT TERM

# Содержательные строки файла (без комментариев и пробелов), отсортированные.
entries() { sed 's/#.*//' "$1" | tr -d ' \t\r' | grep -v '^$' | sort; }

expect_entries() { # expect_entries <описание> <ожидаемые записи через пробел>
    printf '%s\n' "$2" | tr ' ' '\n' | grep -v '^[[:space:]]*$' | sort > "$P/exp"
    entries "$UF" > "$P/got"
    check '[ "$(cat "$P/exp")" = "$(cat "$P/got")" ]' "$1"
}

load_fn() { # load_fn <файл-источник> — в оболочке появляется merge_list()
    if ! sed -n '/^merge_list()/,/^}/p' "$1" > "$BLK" || [ ! -s "$BLK" ]; then
        echo "FAIL: не вырезан merge_list из $1"
        fail=$((fail + 1))
        return 1
    fi
    # shellcheck disable=SC1090
    . "$BLK"
}

run_scenarios() { # run_scenarios <метка> <файл-источник merge_list>
    # ВАЖНО: имена переменных не должны пересекаться с внутренними переменными
    # вырезанной merge_list (_uf/_pf/_label/_u/_p/_lbl/...), иначе она их затрёт.
    impl_lbl="$1"
    echo "=== $impl_lbl ==="
    load_fn "$2" || return 1

    # 1. Мягкая запись пользователя + жёсткая из поставки: двойника нет.
    printf '?x.example.ru\n' > "$UF"
    printf 'x.example.ru\n' > "$PF"
    merge_list "$UF" "$PF" vpn_always >/dev/null
    check '! grep -qxF "x.example.ru" "$UF"' "$impl_lbl: к ?x.example.ru не дописан жёсткий двойник"
    expect_entries "$impl_lbl: файл содержит только мягкую запись" "?x.example.ru"
    check 'grep -qxF "?x.example.ru" "$UF"' "$impl_lbl: форма мягкой строки не изменена"

    # 2. Обратный случай: пользователь жёстко, поставка мягко.
    printf 'x.example.ru\n' > "$UF"
    printf '?x.example.ru\n' > "$PF"
    merge_list "$UF" "$PF" vpn_always >/dev/null
    expect_entries "$impl_lbl: жёсткая строка пользователя не стала мягкой" "x.example.ru"

    # 3. Зоны: ?*.domain и *.domain — одна запись (в обе стороны).
    printf '?*.d.ru\n' > "$UF"
    printf '*.d.ru\n' > "$PF"
    merge_list "$UF" "$PF" vpn_always >/dev/null
    expect_entries "$impl_lbl: мягкая зона ?*.d.ru без жёсткого двойника" "?*.d.ru"
    printf '*.d.ru\n' > "$UF"
    printf '?*.d.ru\n' > "$PF"
    merge_list "$UF" "$PF" vpn_always >/dev/null
    expect_entries "$impl_lbl: жёсткая зона *.d.ru не переписана в мягкую" "*.d.ru"

    # 4. Домен и зона — РАЗНЫЕ записи: wildcard из поставки обязан доехать.
    printf '?x.ru\n' > "$UF"
    printf '*.x.ru\n' > "$PF"
    merge_list "$UF" "$PF" vpn_always >/dev/null
    expect_entries "$impl_lbl: *.x.ru — отдельная запись, она дописана" "*.x.ru ?x.ru"

    # 5. Штатный merge: отсутствующие записи дописываются, существующие целы.
    printf 'keep.ru\n' > "$UF"
    printf 'keep.ru\nnew.ru\n192.0.2.0/24\n' > "$PF"
    merge_list "$UF" "$PF" vpn_always >/dev/null
    expect_entries "$impl_lbl: новые строки из поставки дописаны" "keep.ru new.ru 192.0.2.0/24"
    check 'grep -qE "susanin-update:|добавлено при обновлении" "$UF"' \
          "$impl_lbl: дописанный блок помечен маркером"

    # 6. Нормализация: хвостовой комментарий и пробелы не мешают опознать запись.
    printf '?y.example.ru   # мягко  \n' > "$UF"
    printf 'y.example.ru\n' > "$PF"
    merge_list "$UF" "$PF" vpn_always >/dev/null
    expect_entries "$impl_lbl: запись с комментарием опознана" "?y.example.ru"
    check 'grep -qxF "?y.example.ru   # мягко  " "$UF"' \
          "$impl_lbl: исходная строка пользователя не переписана"

    # 7. Идемпотентность: повторный прогон не меняет файл вовсе.
    printf '?z.ru\n' > "$UF"
    printf 'z.ru\nw.ru\n' > "$PF"
    merge_list "$UF" "$PF" vpn_always >/dev/null
    cp "$UF" "$UF.pass1"
    merge_list "$UF" "$PF" vpn_always >/dev/null
    check 'cmp -s "$UF" "$UF.pass1"' "$impl_lbl: повторный merge ничего не дописал"
    expect_entries "$impl_lbl: после двух прогонов — мягкая z.ru и новая w.ru" "?z.ru w.ru"

    # 8. Закомментированная у пользователя запись возвращается из поставки
    #    (прежнее поведение merge сохраняется: комментарий = записи нет).
    printf '# x.example.ru\n' > "$UF"
    printf 'x.example.ru\n' > "$PF"
    merge_list "$UF" "$PF" vpn_always >/dev/null
    expect_entries "$impl_lbl: закомментированная запись дописана из поставки" "x.example.ru"

    # 9. Пустой файл пользователя и несуществующий файл пакета — без ошибок.
    : > "$UF"
    merge_list "$UF" "$PF" vpn_always >/dev/null
    merge_list "$UF" "$P/нет-такого-файла.txt" vpn_always >/dev/null
    check '[ -f "$UF" ]' "$impl_lbl: пустой список и отсутствующий пакет не валят merge"

    return 0
}

run_scenarios "install.sh" "$ROOT/install.sh"
run_scenarios "tools/update.sh" "$ROOT/tools/update.sh"
run_scenarios "opkg/postinst" "$ROOT/opkg/postinst"

echo
if [ "$fail" = 0 ]; then
    echo "ИТОГ: merge списков — все проверки пройдены"
else
    echo "ЕСТЬ ОШИБКИ ($fail)"
fi
exit $((fail ? 1 : 0))
