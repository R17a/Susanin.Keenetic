#!/bin/sh
# Susanin.Keenetic update: replace binary/tools, keep config and state.
# Списки vpn_always.txt / vpn_never.txt НЕ перезаписываются: существующие строки
# сохраняются, новые строки из пакета ДОПОЛНЯЮТСЯ (идемпотентно).
#   sh update.sh [--arch mipsel] [--version latest|vX.Y.Z] [--prefix /opt/susanin]
#                 [--keep-lists]   # не дополнять vpn_always.txt/vpn_never.txt
set -eu

REPO="R17a/Susanin.Keenetic"
PREFIX=/opt/susanin
ARCH=""
VERSION="latest"
# 0 — дополнять списки из сборки (по умолчанию), 1 — не трогать vpn_always/vpn_never.
KEEP_LISTS=0

say() { echo "[susanin] $*"; }
die() { echo "[susanin] ERROR: $*" >&2; exit 1; }

# Дополнить существующий список новыми строками из пакета. Ничего не удаляем и
# не перезаписываем: добавляем только те «чистые» строки (домены/IP/CIDR), которых
# ещё нет. Идемпотентно: повторный запуск ничего не меняет.
merge_list() { # merge_list <user_file> <package_file> <label>
    _uf="$1"; _pf="$2"; _label="$3"
    [ -f "$_uf" ] && [ -f "$_pf" ] || return 0
    _tmp=$(mktemp 2>/dev/null) || _tmp="/tmp/susanin-merge.$$"
    sed 's/#.*//' "$_uf" | tr -d ' \t\r' | grep -v '^$' | sort -u > "$_tmp" || true
    _added=0
    while IFS= read -r _line; do
        _e=$(printf '%s' "$_line" | sed 's/#.*//' | tr -d ' \t\r')
        if [ -z "$_e" ]; then
            continue
        fi
        if grep -qxF "$_e" "$_tmp"; then
            continue
        fi
        if [ "$_added" -eq 0 ]; then
            if ! grep -qF 'susanin-update:' "$_uf"; then
                printf '\n# susanin-update: added missing default entries\n' >> "$_uf"
            fi
        fi
        printf '%s\n' "$_e" >> "$_uf"
        printf '%s\n' "$_e" >> "$_tmp"
        _added=$((_added + 1))
    done < "$_pf"
    rm -f "$_tmp"
    if [ "$_added" -gt 0 ]; then
        say "$_label: добавлено новых строк: $_added"
    fi
    return 0
}

# Файл списка в пакете: релизный архив «плоский», dev-архив — с папками
# (etc/), поэтому ищем в нескольких местах.
pkg_file() { # pkg_file <имя> -> путь или ничего
    for _c in "$DIR/$1" "$DIR/etc/$1" "$DIR/../$1" "$DIR/../etc/$1"; do
        if [ -f "$_c" ]; then
            printf '%s\n' "$_c"
            return 0
        fi
    done
    return 1
}

while [ $# -gt 0 ]; do
    case "$1" in
        --arch) ARCH="$2"; shift ;;
        --version) VERSION="$2"; shift ;;
        v[0-9]*) VERSION="$1" ;;
        [0-9]*) VERSION="v$1" ;;
        --prefix) PREFIX="$2"; shift ;;
        --keep-lists|--no-lists) KEEP_LISTS=1 ;;
        --lists) KEEP_LISTS=0 ;;
        -h|--help) echo "usage: $0 [--arch ARCH] [--version latest|vX.Y.Z] [--prefix DIR] [--keep-lists]"; exit 0 ;;
        *) die "unknown arg: $1" ;;
    esac
    shift
done

if [ -z "$ARCH" ]; then
    # Архитектуру берём из Entware (авторитетен для userland/ABI): ядро (uname -m)
    # ненадёжно — не различает endianness MIPS и путается при 64-битном ядре с
    # 32-битным userland. uname -m оставлен только запасным вариантом.
    _a=""
    if [ -r /opt/etc/entware_release ]; then
        _a=$(awk -F= '$1=="arch"{gsub(/["[:space:]]/,"",$2); print $2; exit}' /opt/etc/entware_release 2>/dev/null)
    fi
    if [ -z "$_a" ] && command -v opkg >/dev/null 2>&1; then
        _a=$(opkg print-architecture 2>/dev/null | awk '$1=="arch" && $2!="all"{print $2; exit}')
    fi
    _a=$(printf '%s' "$_a" | sed 's/-k[0-9.][0-9.]*$//')
    case "$_a" in
        mipsel*|mipselsf*) ARCH=mipsel ;;
        mips64el*|mips64*) ARCH=mips64el ;;
        mips*|mipssf*)     ARCH=mips ;;
        aarch64*|arm64*)   ARCH=aarch64 ;;
        armv7*|armv7l*|armhf*) ARCH=armv7 ;;
        x86_64*|amd64*|x86-64*)    ARCH=x86_64 ;;
    esac
    if [ -z "$ARCH" ]; then
        _m=$(uname -m 2>/dev/null || echo unknown)
        case "$_m" in
            mips|mipsel) ARCH=mipsel ;;
            aarch64|arm64) ARCH=aarch64 ;;
            armv7l|armv7|armhf) ARCH=armv7 ;;
            x86_64|amd64) ARCH=x86_64 ;;
            *) die "cannot detect arch; pass --arch" ;;
        esac
    fi
fi

# r7.2: fallback через локальный SOCKS (только tproxy + живой socks-in 1080).
CONF_FOR_FETCH="$PREFIX/etc/susanin.conf"
# r7.2: локальный SOCKS доступен? Только tproxy-конфиг и слушающийся socks-in
# (127.0.0.1:1080 = 0x0438, состояние LISTEN 0A в /proc/net/tcp).
susanin_socks_avail() {
    _et=$(sed -n 's/^egress_type=//p' "$CONF_FOR_FETCH" 2>/dev/null | head -n1)
    [ "$_et" = "tproxy" ] || return 1
    awk '$2 ~ /:0438$/ && $4 == "0A" { f=1 } END { exit !f }' /proc/net/tcp 2>/dev/null
}

if command -v curl >/dev/null 2>&1; then
    fetch() {
        curl -fsSL --connect-timeout 6 --max-time 240 "$1" -o "$2" && return 0
        if susanin_socks_avail; then
            say "прямая загрузка не удалась — проба через локальный туннель (SOCKS)"
            curl -fsSL --connect-timeout 6 --max-time 300 -x socks5h://127.0.0.1:1080 "$1" -o "$2" && return 0
        fi
        return 1
    }
elif command -v wget >/dev/null 2>&1; then
    fetch() {
        wget -q -T 30 -O "$2" "$1" && return 0
        if susanin_socks_avail; then
            say "прямая загрузка не удалась — проба через локальный туннель (SOCKS)"
            wget -q -T 60 --tries=2 -e use_proxy=yes -e https_proxy=127.0.0.1:1080 -O "$2" "$1" && return 0
        fi
        return 1
    }
else
    die "need curl or wget (Entware: opkg update && opkg install ca-certificates)"
fi

OLD="unknown"
[ -x "$PREFIX/bin/susanin-agent" ] && OLD=$("$PREFIX/bin/susanin-agent" version 2>/dev/null || echo unknown)
say "installed version: $OLD -> target: $VERSION ($ARCH)"

if [ "$VERSION" = latest ]; then
    BASE="https://github.com/$REPO/releases/latest/download"
else
    BASE="https://github.com/$REPO/releases/download/$VERSION"
fi
# Только те архитектуры, для которых CI собирает бинарник
# (.github/workflows/release.yml). Проверка до загрузки, чтобы не показывать
# «скачивание не удалось» там, где сборки для этой платформы просто нет.
case "$ARCH" in
    mipsel|mips|aarch64|armv7|x86_64) : ;;
    *) die "для архитектуры '$ARCH' готовых сборок нет (есть: mipsel, mips, aarch64, armv7, x86_64); обновите вручную: sh tools/update.sh --arch mipsel" ;;
esac
ASSET="susanin-keenetic-deploy-$ARCH.tar.gz"
TMP=$(mktemp -d /tmp/susanin-upd.XXXXXX)

# Службу останавливаем ТОЛЬКО после успешной загрузки и проверки пакета — прямо
# перед заменой файлов (ниже). Иначе при недоступном GitHub (или битом архиве)
# рабочий Susanin оставался выключенным, хотя обновление не состоялось.
# STOPPED=1 = мы сами остановили работавшую службу; если дальше что-то сорвётся,
# cleanup вернёт её в строй.
STOPPED=0
cleanup() {
    if [ "$STOPPED" = "1" ]; then
        STOPPED=0
        [ -x "$PREFIX/tools/susanin.sh" ] \
            && sh "$PREFIX/tools/susanin.sh" start >/dev/null 2>&1 || true
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

say "downloading $BASE/$ASSET"
fetch "$BASE/$ASSET" "$TMP/pkg.tar.gz" || die "download failed: $BASE/$ASSET
     hint: opkg update && opkg install ca-certificates"
tar -xzf "$TMP/pkg.tar.gz" -C "$TMP" || die "bad archive"
PKG=$(find "$TMP" -maxdepth 2 -name 'susanin-agent' -type f 2>/dev/null | head -1)
[ -n "$PKG" ] || PKG=$(find "$TMP" -maxdepth 2 -name 'susanin-agent.*' -type f 2>/dev/null | head -1)
[ -n "$PKG" ] || die "binary not found in package"
DIR=$(dirname "$PKG")
if [ -f "$DIR/susanin-agent" ]; then
    BINFILE=susanin-agent
else
    BINFILE=$(basename "$PKG")
fi

mkdir -p "$PREFIX/bin" "$PREFIX/tools" "$PREFIX/var/backup"
STAMP=$(date +%Y%m%d-%H%M%S)
[ -f "$PREFIX/etc/susanin.conf" ] && cp "$PREFIX/etc/susanin.conf" "$PREFIX/var/backup/susanin.conf.$STAMP"
[ -f "$PREFIX/var/susanin.state" ] && cp "$PREFIX/var/susanin.state" "$PREFIX/var/backup/susanin.state.$STAMP"

# --- остановка службы: только теперь, перед установкой файлов -----------------
# Пакет уже скачан, распакован и проверен, поэтому сетевой сбой больше не может
# оставить систему без работающего Susanin. Останавливаем, только если служба
# реально работает, — иначе нечего возвращать в строй при сбое.
WAS_RUNNING=0
_pid=$(cat "$PREFIX/var/susanin-agent.pid" 2>/dev/null || true)
if [ -n "${_pid:-}" ] && kill -0 "$_pid" 2>/dev/null; then
    WAS_RUNNING=1
elif ps | grep 'susanin-agent run' | grep -v grep >/dev/null 2>&1; then
    WAS_RUNNING=1
fi
if [ -x "$PREFIX/tools/susanin.sh" ]; then
    [ "$WAS_RUNNING" = "1" ] && STOPPED=1
    sh "$PREFIX/tools/susanin.sh" stop || true
fi

cp "$DIR/$BINFILE" "$PREFIX/bin/susanin-agent.new"
mv "$PREFIX/bin/susanin-agent.new" "$PREFIX/bin/susanin-agent"
chmod +x "$PREFIX/bin/susanin-agent"
# Копируем все скрипты из пакета (не жёстким списком): так новые файлы,
# добавленные в релизе, не теряются при обновлении старым update.sh.
for f in "$DIR"/*.sh; do
    [ -f "$f" ] || continue
    cp "$f" "$PREFIX/tools/"
done
chmod +x "$PREFIX/tools/"*.sh 2>/dev/null || true

# Документация обновляется вместе с пакетом (см. install.sh).
if [ -n "${DIR:-}" ] && [ -d "$DIR/docs" ]; then
    mkdir -p "$PREFIX/docs"
    cp -r "$DIR/docs/." "$PREFIX/docs/" 2>/dev/null || true
fi

# Статика веб-панели: без этого правки www/ НЕ доезжали до установленных систем
# через `susanin update` (копировались только *.sh, docs/ и бинарник).
if [ -n "${DIR:-}" ] && [ -d "$DIR/www" ]; then
    mkdir -p "$PREFIX/www"
    cp -r "$DIR/www/." "$PREFIX/www/" 2>/dev/null || true
    say "веб-панель обновлена: $PREFIX/www"
fi

# init-скрипты: раньше `susanin update` их вообще не обновлял (только .ipk).
# Раскладка архива бывает «плоской» и с каталогами — ищем оба вида.
# S95xray-guard (был в 0.4.6) из поставки исключён — ниже только вычистка.
for _pair in "S93xray-tproxy:S93xray-tproxy" \
             "S94susanin:S94susanin" "S95susanin-web:S95susanin-web"; do
    _name=${_pair%%:*}
    _src=""
    for _cand in "$DIR/$_name" "$DIR/init/$_name" "$DIR/init/entware/$_name" \
                 "$DIR/etc/init.d/$_name"; do
        [ -f "$_cand" ] && { _src="$_cand"; break; }
    done
    [ -n "$_src" ] || continue
    if [ -d /opt/etc/init.d ] && cp "$_src" "/opt/etc/init.d/$_name" 2>/dev/null; then
        chmod +x "/opt/etc/init.d/$_name" 2>/dev/null || true
        say "init: /opt/etc/init.d/$_name обновлён"
    fi
done
# Вычистка сторожа Xray после 0.4.6: он конфликтует с агентом (поднимает Xray
# при остановленном агенте и не останавливается при удалении пакета).
if [ -f /opt/etc/init.d/S95xray-guard ]; then
    /opt/etc/init.d/S95xray-guard stop >/dev/null 2>&1 || true
    rm -f /opt/etc/init.d/S95xray-guard /opt/var/run/xray-guard.pid 2>/dev/null || true
    say "init: S95xray-guard остановлен и удалён (больше не поставляется)"
fi

# Короткий вызов `susanin …`: симлинк в /opt/bin (не трогаем чужой файл с этим именем).
if [ -d /opt/bin ] && [ ! -e /opt/bin/susanin ]; then
    ln -s "$PREFIX/tools/susanin.sh" /opt/bin/susanin 2>/dev/null \
        && say "короткий вызов: susanin {status|check|diagnose|report|...}" \
        || say "симлинк /opt/bin/susanin создать не удалось (не критично)"
fi

# Дополнить существующие списки новыми строками из пакета (идемпотентно).
# Существующие строки не трогаем: пользовательские правки сохраняются.
# Если файла списка нет вовсе — ставим его из пакета.
# Флаг запуска --keep-lists (он же --no-lists) выключает операцию целиком:
# оба файла остаются ровно такими, какие они есть.
if [ "$KEEP_LISTS" = "1" ]; then
    say "--keep-lists: списки vpn_always/vpn_never не трогаем"
else
    for _l in vpn_always vpn_never; do
        if _pf=$(pkg_file "$_l.txt"); then
            if [ ! -f "$PREFIX/etc/$_l.txt" ]; then
                cp "$_pf" "$PREFIX/etc/$_l.txt"
                say "$_l list installed: $PREFIX/etc/$_l.txt"
            else
                merge_list "$PREFIX/etc/$_l.txt" "$_pf" "$_l"
            fi
        fi
    done
fi

# Одноразовая уборка накопленных бэкапов списков старого формата
# (<список>.bak-ГГГГММДД-ЧЧММСС) — теперь бэкап один: <список>.bak.
rm -f "$PREFIX/etc/vpn_always.txt".bak-[0-9]* \
      "$PREFIX/etc/vpn_never.txt".bak-[0-9]* 2>/dev/null || true

# --- MIGRATION-BEGIN (тест tests/test-installer-sync.sh вырезает этот участок;
# --- границы менять только вместе с тестом) -----------------------------------
# Дописать отсутствующие дефолтные ключи (старый конфиг мог их не содержать).
# Перечень ключей и их значения берёт сам агент (`config sync`): рукописный
# список в этом скрипте неминуемо отстаёт от кода — в нём не было ru_guard*,
# tz, test_net_*, frozen_net_*, port_aware, ipset_batch, proxy_* и др., а
# lan_interfaces, lan_subnets и media_ports остались с прежними дефолтами, так
# что обновлённый роутер получал устаревшие настройки молча. Существующие
# строки не перезаписываются: значение пользователя важнее дефолта.
if [ -f "$PREFIX/etc/susanin.conf" ]; then
    # Путь конфига передаём явно: у агента он по умолчанию /opt/susanin, а
    # обновление может идти в другой --prefix — иначе sync правил бы не тот
    # файл, что обновляется. Временное имя уникально: две сессии обновления не
    # должны затирать вывод друг друга.
    _sync_out=$(mktemp "${TMPDIR:-/tmp}/susanin-sync.XXXXXX" 2>/dev/null || echo "")
    if [ -n "$_sync_out" ] &&
       SUSANIN_CONF="$PREFIX/etc/susanin.conf" \
           "$PREFIX/bin/susanin-agent" config sync >"$_sync_out" 2>/dev/null; then
        say "конфиг: $(tr '\n' ' ' < "$_sync_out" 2>/dev/null)"
    else
        say "ВНИМАНИЕ: config sync не выполнился (старый бинарник?) —" \
            "отсутствующие ключи не дописаны, проверьте susanin.conf вручную"
    fi
    [ -n "$_sync_out" ] && rm -f "$_sync_out"

    # Миграция значений по умолчанию (0.4.0): promo_per_min 30 -> 120.
    # Меняем только прежний дефолт; своё значение пользователя не трогаем.
    # Форма с пробелами («promo_per_min = 30») читается агентом как обычный
    # ключ, поэтому и миграция должна её видеть.
    _pp=$(sed -n 's/^[[:space:]]*promo_per_min[[:space:]]*=[[:space:]]*//p' \
              "$PREFIX/etc/susanin.conf" 2>/dev/null | tail -n1)
    if [ "$_pp" = "30" ]; then
        sed -i 's|^[[:space:]]*promo_per_min[[:space:]]*=.*|promo_per_min=120|' \
            "$PREFIX/etc/susanin.conf" 2>/dev/null \
            && say "promo_per_min: 30 -> 120 (новый дефолт)"
    fi
fi

# --- MIGRATION-END -------------------------------------------------------------

# Данные CDN (cdn_ranges.txt): ставим, если файла ещё нет; существующий не трогаем.
if [ -f "$DIR/cdn_ranges.txt" ] && [ ! -f "$PREFIX/etc/cdn_ranges.txt" ]; then
    cp "$DIR/cdn_ranges.txt" "$PREFIX/etc/cdn_ranges.txt"
    say "CDN ranges installed: $PREFIX/etc/cdn_ranges.txt"
fi

if [ -x "$PREFIX/tools/susanin.sh" ]; then
    sh "$PREFIX/tools/susanin.sh" start || true
    STOPPED=0
fi
NEW=$("$PREFIX/bin/susanin-agent" version 2>/dev/null || echo unknown)
say "updated: $OLD -> $NEW (config/state preserved)"
