#!/bin/sh
# Susanin.Keenetic — универсальный установщик (bootstrap) для Keenetic + Entware.
#
# Зачем он нужен: на роутерах со старым BusyBox `tar` не умеет `--exclude`, и
# инструкция «распаковать с исключениями» (xray, чужие бинарники) там падает.
# Этот скрипт ничего не исключает флагами, а распаковывает ровно нужные файлы:
#
#   * сам определяет платформу: архитектуру (Entware → opkg → ELF-endianness →
#     uname -m), версию ядра, версию BusyBox, наличие curl/wget/sha256sum;
#   * сам выбирает рабочий способ выборочной распаковки: tar по списку файлов
#     (работает и там, где нет --exclude), затем `gzip -dc | tar` (если у tar нет
#     -z), затем GNU tar из Entware (/opt/bin/tar);
#   * полную распаковку НЕ делает: она пишет на носитель ~5 МБ (весь пакет) вместо
#     нужен из архива один бинарник. Если выборочная распаковка невозможна —
#     останавливается и предлагает `opkg install tar` (GNU tar) либо явный флаг
#     `--allow-full-unpack`;
#   * делает то же, для чего в инструкции стоял `--exclude`: на носитель
#     распаковывается только бинарник под это ядро/архитектуру. Сам архив при этом
#     скачивается целиком (tar не умеет брать из HTTP-архива отдельные файлы) —
#     экономия именно на распаковке;
#   * бинарников Xray в архиве нет вовсе (29 МБ + 28 МБ, нужны только для
#     egress_type=tproxy): их скачивает `--with-xray` и сразу ставит в
#     /opt/sbin/xray, сверяя sha256 по xray/SHA256SUMS из пакета;
#   * запускает install.sh из пакета и передаёт ему ваши флаги.
#
# Быстрый старт (тестовая ветка develop), без сохранения файла:
#   cd /opt/tmp
#   wget -qO- https://raw.githubusercontent.com/R17a/Susanin.Keenetic/develop/bootstrap.sh | sh -s -- --yes
#
# То же с сохранением файла (удобно перезапускать и смотреть `--check`):
#   cd /opt/tmp && rm -f susanin-install.sh && \
#   wget -O susanin-install.sh https://raw.githubusercontent.com/R17a/Susanin.Keenetic/develop/bootstrap.sh && \
#   sh susanin-install.sh --yes
#
# Последний релиз (архив под свою архитектуру, качается с GitHub Releases):
#   sh susanin-install.sh --channel stable --yes
#
# Уже скачанный архив (без интернета):
#   sh susanin-install.sh --file /opt/tmp/susanin-keenetic-0.4.0-dev.tar.gz --yes
#
# Только показать, что определено (ничего не качает и не ставит):
#   sh susanin-install.sh --check
#
# Скрипт можно запускать и из уже распакованного пакета (лежит рядом с
# install.sh) — тогда он просто вызовет install.sh из него.
#
# POSIX sh (BusyBox ash совместимо).
set -eu

REPO="R17a/Susanin.Keenetic"
BRANCH="develop"
CHANNEL="dev"
VERSION="latest"
DEV_FILE="susanin-keenetic-0.4.0-dev.tar.gz"
URL=""
FILE=""
ARCH=""
ARCH_SRC=""
WITH_XRAY=0
FULL_UNPACK=0
VERIFY=0
KEEP=0
DRYRUN=0
CHECKONLY=0
INSTALL_ARGS=""
TMP_OVERRIDE="${SUSANIN_TMPDIR:-}"
WORK=""
PKG_ROOT=""
ARCH_RAW=""
ENDIAN=""
KREL=""
KMACH=""
BBVER=""
SUPPORTED_ARCH="mipsel mips aarch64 armv7 x86_64"

say()  { echo "[susanin] $*"; }
warn() { echo "[susanin] ВНИМАНИЕ: $*" >&2; }
die()  { echo "[susanin] ОШИБКА: $*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Использование: sh bootstrap.sh [опции своего установщика] [опции install.sh]

Опции установщика:
  --channel dev|stable   dev (по умолчанию) — универсальный архив из ветки
                         develop; stable — последний GitHub Release (архив под
                         вашу архитектуру).
  --version latest|vX.Y.Z  версия для --channel stable.
  --branch ВЕТКА         ветка GitHub для --channel dev (по умолчанию develop).
  --dev-file ИМЯ.tar.gz  имя файла dev-архива. Обычно не нужно: имя одно и то же
                         для всех dev-сборок — susanin-keenetic-0.4.0-dev.tar.gz.
  --url URL              скачать архив по своему адресу.
  --file ПУТЬ            использовать уже скачанный архив (без интернета).
  --arch ARCH            mipsel|mips|aarch64|armv7|x86_64 (иначе — автоопределение).
  --with-xray            скачать Xray-core под вашу архитектуру (~29 МБ) и
                         поставить в /opt/sbin/xray: в архив он не входит.
                         Дополнительно передаёт install.sh --with-xray-tproxy,
                         чтобы положить шаблон tproxy-конфига.
  --allow-full-unpack    разрешить полную распаковку архива, если выборочная
                         невозможна. ВНИМАНИЕ: пишет на носитель ~5 МБ вместо
                         ~1,5 МБ; по умолчанию выключено (нужен один бинарник).
  --check                показать платформу и выйти (ничего не качать).
  --dry-run              скачать и распаковать, но не устанавливать.
  --verify               строгая проверка SHA256 по SHA256SUMS из пакета
                         (без флага несовпадение — только предупреждение).
  --keep                 не удалять временный каталог после установки.
  --tmp DIR              каталог для скачивания/распаковки (по умолчанию
                         /opt/tmp, затем /opt/var/tmp, затем /tmp). С `--tmp /tmp`
                         архив и распаковка идут в RAM: флеш не пишется, но нужно
                         ~30 МБ свободной памяти.
  -h, --help             эта справка.

Опции, которые передаются в install.sh:
  --yes|-y, --force, --no-start, --deps, --with-xray-tproxy,
  --egress IF, --lan IF[,IF], --subnets CIDR[,CIDR],
  --prefix DIR, --disk-mode normal|soft

Дополнительные пакеты Entware (если ставите впервые):
  opkg update && opkg install ca-certificates ipset iptables conntrack
EOF
}

# --- аргументы ---------------------------------------------------------------
need_val() { # need_val <$#> <имя опции>
    [ "$1" -ge 2 ] || die "опция $2 требует значение (см. --help)"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --channel) need_val $# "$1"; CHANNEL="$2"; shift ;;
        --version) need_val $# "$1"; VERSION="$2"; INSTALL_ARGS="$INSTALL_ARGS --version $2"; shift ;;
        --branch) need_val $# "$1"; BRANCH="$2"; shift ;;
        --dev-file) need_val $# "$1"; DEV_FILE="$2"; shift ;;
        --url) need_val $# "$1"; URL="$2"; shift ;;
        --file) need_val $# "$1"; FILE="$2"; shift ;;
        --arch) need_val $# "$1"; ARCH="$2"; INSTALL_ARGS="$INSTALL_ARGS --arch $2"; shift ;;
        --tmp) need_val $# "$1"; TMP_OVERRIDE="$2"; shift ;;
        --with-xray) WITH_XRAY=1; INSTALL_ARGS="$INSTALL_ARGS --with-xray-tproxy" ;;
        --allow-full-unpack|--full-unpack) FULL_UNPACK=1 ;;
        --check|--print-platform) CHECKONLY=1 ;;
        --dry-run) DRYRUN=1 ;;
        --verify) VERIFY=1 ;;
        --keep) KEEP=1 ;;
        --yes|-y) INSTALL_ARGS="$INSTALL_ARGS --yes" ;;
        --force) INSTALL_ARGS="$INSTALL_ARGS --force" ;;
        --no-start) INSTALL_ARGS="$INSTALL_ARGS --no-start" ;;
        --deps) INSTALL_ARGS="$INSTALL_ARGS --deps" ;;
        --with-xray-tproxy) INSTALL_ARGS="$INSTALL_ARGS --with-xray-tproxy" ;;
        --egress|--lan|--subnets|--prefix|--disk-mode)
            need_val $# "$1"; INSTALL_ARGS="$INSTALL_ARGS $1 $2"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "неизвестная опция: $1 (см. --help)" ;;
    esac
    shift
done

case "$CHANNEL" in
    dev|develop) CHANNEL=dev ;;
    stable|release) CHANNEL=stable ;;
    *) die "неверный --channel: $CHANNEL (dev|stable)" ;;
esac

# --- определение платформы ---------------------------------------------------
# Endianness по ELF-заголовку: байт 5 (EI_DATA): 1 — little, 2 — big.
# Нужен только для MIPS: uname -m там пишет «mips» и для mipsel, и для mips.
elf_endian() { # elf_endian <файл> -> little|big|пусто
    _f="$1"
    [ -f "$_f" ] || return 1
    _b=""
    if command -v od >/dev/null 2>&1; then
        _b=$(dd if="$_f" bs=1 skip=5 count=1 2>/dev/null | od -An -tu1 2>/dev/null | tr -d ' \t\n' || true)
    fi
    if [ -z "$_b" ] && command -v hexdump >/dev/null 2>&1; then
        _b=$(hexdump -s 5 -n 1 -e '1/1 "%u"' "$_f" 2>/dev/null | tr -d ' \t\n' || true)
    fi
    case "$_b" in
        1) printf 'little' ;;
        2) printf 'big' ;;
        *) return 1 ;;
    esac
}

probe_endian() { # определяем по userland-бинарям (Entware важнее системных)
    for _f in /opt/bin/opkg /opt/bin/opkg-cl /opt/bin/busybox /bin/busybox /bin/sh; do
        _e=$(elf_endian "$_f" 2>/dev/null || true)
        if [ -n "$_e" ]; then printf '%s' "$_e"; return 0; fi
    done
    return 1
}

# Сырое имя архитектуры Entware: entware_release -> opkg.conf -> opkg print-architecture.
entware_arch() {
    _a=""
    if [ -r /opt/etc/entware_release ]; then
        _a=$(awk -F= '$1=="arch"{gsub(/["[:space:]]/,"",$2); print $2; exit}' /opt/etc/entware_release 2>/dev/null || true)
    fi
    if [ -z "$_a" ] && [ -r /opt/etc/opkg.conf ]; then
        # src/gz entware https://bin.entware.net/mipselsf-k3.4 -> mipselsf-k3.4
        _a=$(awk '/^[[:space:]]*src/ {print $NF}' /opt/etc/opkg.conf 2>/dev/null \
             | sed 's|/*$||' | awk -F/ '{print $NF}' | grep -v '^$' | head -n1 || true)
    fi
    if [ -z "$_a" ] && command -v opkg >/dev/null 2>&1; then
        _a=$(opkg print-architecture 2>/dev/null | awk '$1=="arch" && $2!="all"{print $2; exit}' || true)
    fi
    printf '%s' "$_a"
}

# Нормализация: mipselsf-k3.4 -> mipsel, armv7sf-k2.6 -> armv7, aarch64-3.10 -> aarch64.
arch_norm() {
    _a=$(printf '%s' "$1" | tr 'A-Z' 'a-z' | sed 's/-k[0-9][0-9.]*$//; s/_[0-9][0-9.]*$//')
    case "$_a" in
        mipsel*|mipselsf*|mipsel_kn*) printf 'mipsel' ;;
        mips64el*|mips64*)            printf 'mips64el' ;;
        mips*|mipssf*)                printf 'mips' ;;
        aarch64*|arm64*|armv8*)       printf 'aarch64' ;;
        armv7*|armhf*)                printf 'armv7' ;;
        x86_64*|x86-64*|amd64*)       printf 'x86_64' ;;
        *) : ;;
    esac
}

detect_arch() {
    _ent=$(entware_arch)
    ARCH_RAW="$_ent"
    _n=$(arch_norm "$_ent")
    if [ "$_n" = mips64el ]; then
        die "Entware собран под mips64el (64-битный MIPS): в сборке такого
     бинарника нет (есть: $SUPPORTED_ARCH) — нужна отдельная сборка под mips64el"
    fi
    case "$_n" in
        mipsel|mips|aarch64|armv7|x86_64)
            ARCH="$_n"; ARCH_SRC="Entware ($_ent)"; return 0 ;;
    esac
    _m=$(printf '%s' "$KMACH" | tr 'A-Z' 'a-z')
    case "$_m" in
        aarch64|arm64)  ARCH=aarch64; ARCH_SRC="uname -m ($KMACH)"; return 0 ;;
        armv7l|armv7|armhf) ARCH=armv7; ARCH_SRC="uname -m ($KMACH)"; return 0 ;;
        x86_64|amd64)   ARCH=x86_64;  ARCH_SRC="uname -m ($KMACH)"; return 0 ;;
        mips|mipsel|mips64)
            ENDIAN=$(probe_endian || true)
            case "$ENDIAN" in
                little) ARCH=mipsel ;;
                big)    ARCH=mips ;;
            esac
            if [ -n "$ARCH" ]; then
                ARCH_SRC="uname -m ($KMACH) + ELF-endianness ($ENDIAN)"
                return 0
            fi
            # Без ELF-проб: на Keenetic+Entware это почти всегда mipsel.
            ARCH=mipsel
            ARCH_SRC="предположение для MIPS (endianness не определён)"
            warn "endianness MIPS определить не удалось — считаю mipsel; если роутер mips (big-endian), запустите с --arch mips"
            return 0 ;;
    esac
    if [ -n "$_n" ]; then
        ARCH="$_n"; ARCH_SRC="Entware ($_ent)"; return 0
    fi
    return 1
}

ask_arch() {
    [ -r /dev/tty ] || return 1
    {
        echo "[susanin] не удалось определить архитектуру."
        echo "[susanin] uname -m=$KMACH, ядро=$KREL, Entware arch='${ARCH_RAW:-нет данных}'"
        echo "  1) mipsel    (Keenetic: почти все модели на MIPS)"
        echo "  2) mips      (MIPS big-endian)"
        echo "  3) aarch64   (ARM 64-bit: Keenetic Giga/Titan и новые)"
        echo "  4) armv7     (ARM 32-bit)"
        echo "  5) x86_64    (PC/VM)"
    } >&2
    printf "[susanin] выберите архитектуру [1-5]: " >&2
    read _sel < /dev/tty || _sel=""
    case "$_sel" in
        1) ARCH=mipsel; ARCH_SRC="выбрана вручную" ;;
        2) ARCH=mips; ARCH_SRC="выбрана вручную" ;;
        3) ARCH=aarch64; ARCH_SRC="выбрана вручную" ;;
        4) ARCH=armv7; ARCH_SRC="выбрана вручную" ;;
        5) ARCH=x86_64; ARCH_SRC="выбрана вручную" ;;
        *) return 1 ;;
    esac
    return 0
}

probe_tools() {
    FETCHER=""
    if command -v curl >/dev/null 2>&1; then FETCHER=curl
    elif command -v wget >/dev/null 2>&1; then FETCHER=wget
    fi
    if command -v sha256sum >/dev/null 2>&1; then HAVE_SHA=1; else HAVE_SHA=0; fi
    if command -v df >/dev/null 2>&1; then HAVE_DF=1; else HAVE_DF=0; fi
    HAVE_TAR_EXCLUDE=0
    if tar --exclude='susanin-nonexistent' -cf /dev/null /dev/null >/dev/null 2>&1; then
        HAVE_TAR_EXCLUDE=1
    fi
    HAVE_TAR_GZIP=0
    if tar -czf /dev/null /dev/null >/dev/null 2>&1; then HAVE_TAR_GZIP=1; fi
}

detect_platform() {
    KREL=$(uname -r 2>/dev/null || true)
    KMACH=$(uname -m 2>/dev/null || true)
    BBVER=$( (busybox 2>&1 || true) | sed -n '1s/.*BusyBox v\([0-9][^ ,)]*\).*/\1/p' )
    [ -n "$BBVER" ] || BBVER="неизвестно"
    if [ -n "$ARCH" ]; then
        ARCH_SRC="задана вручную (--arch)"
    elif ! detect_arch; then
        if ! ask_arch; then
            die "не удалось определить архитектуру — запустите с --arch mipsel|mips|aarch64|armv7|x86_64"
        fi
    fi
    case " $SUPPORTED_ARCH " in
        *" $ARCH "*) : ;;
        *) warn "в сборке нет бинарника под arch=$ARCH (есть: $SUPPORTED_ARCH)" ;;
    esac
    probe_tools
}

print_platform() {
    say "=== платформа роутера ==="
    say "архитектура : $ARCH   (источник: $ARCH_SRC)"
    say "ядро        : ${KREL:-неизвестно}   (uname -m: ${KMACH:-?})"
    say "BusyBox     : $BBVER"
    if [ -n "$ARCH_RAW" ]; then say "Entware     : $ARCH_RAW"; fi
    if [ -n "$ENDIAN" ]; then say "ELF endian  : $ENDIAN"; fi
    if [ -z "$FETCHER" ]; then
        say "загрузка    : нет ни curl, ни wget (opkg install wget)"
    else
        say "загрузка    : $FETCHER"
    fi
    if [ "$HAVE_TAR_GZIP" -eq 1 ]; then say "tar -z      : есть"; else say "tar -z      : нет (будет gzip -dc | tar)"; fi
    if [ "$HAVE_TAR_EXCLUDE" -eq 1 ]; then
        say "tar --exclude: есть (не нужен: распаковываем по списку файлов)"
    else
        say "tar --exclude: НЕТ — это и есть причина старых инструкций; здесь он не нужен"
    fi
    if [ "$HAVE_SHA" -eq 1 ]; then say "sha256sum   : есть"; else say "sha256sum   : нет (проверка SHA256 будет пропущена)"; fi
    case " $SUPPORTED_ARCH " in
        *" $ARCH "*) : ;;
        *) say "внимание    : для $ARCH бинарника в сборке нет (есть: $SUPPORTED_ARCH)" ;;
    esac
}

# --- скачивание --------------------------------------------------------------
fetch() { # fetch <url> <файл>
    _u="$1"; _o="$2"; _n=0
    if [ -z "$FETCHER" ]; then
        die "нужен curl или wget (Entware: opkg update && opkg install ca-certificates wget)"
    fi
    while [ "$_n" -lt 3 ]; do
        _n=$((_n + 1))
        rm -f "$_o"
        if [ "$FETCHER" = curl ]; then
            if curl -fL --connect-timeout 20 -o "$_o" "$_u"; then return 0; fi
        else
            if wget -O "$_o" "$_u"; then return 0; fi
        fi
        if [ "$_n" -lt 3 ]; then
            say "повтор загрузки ($_n/3): $_u"
            sleep 2
        fi
    done
    # Второй инструмент, если первый не смог (бывает с сертификатами/редиректами).
    if [ "$FETCHER" = curl ] && command -v wget >/dev/null 2>&1; then
        if wget -O "$_o" "$_u"; then return 0; fi
    elif [ "$FETCHER" = wget ] && command -v curl >/dev/null 2>&1; then
        if curl -fL --connect-timeout 20 -o "$_o" "$_u"; then return 0; fi
    fi
    rm -f "$_o"
    return 1
}

download_archive() {
    if [ -n "$URL" ]; then
        say "скачиваю: $URL"
        fetch "$URL" "$WORK/pkg.tar.gz" || die "не удалось скачать архив: $URL"
        return 0
    fi
    if [ "$CHANNEL" = stable ]; then
        if [ "$VERSION" = latest ]; then
            _base="https://github.com/$REPO/releases/latest/download"
        else
            _base="https://github.com/$REPO/releases/download/$VERSION"
        fi
        _asset="susanin-keenetic-deploy-$ARCH.tar.gz"
        say "скачиваю: $_base/$_asset"
        fetch "$_base/$_asset" "$WORK/pkg.tar.gz" \
            || die "не удалось скачать $_asset из $_base
     подсказка: opkg update && opkg install ca-certificates
     или укажите версию: --version vX.Y.Z"
        return 0
    fi
    # Имя dev-архива специально всегда одно и то же (susanin-keenetic-0.4.0-dev.tar.gz):
    # его не нужно переписывать в скриптах и инструкциях при смене сборки.
    _base="https://raw.githubusercontent.com/$REPO/$BRANCH/develop"
    say "скачиваю: $_base/$DEV_FILE"
    fetch "$_base/$DEV_FILE" "$WORK/pkg.tar.gz" || die "не удалось скачать $_base/$DEV_FILE
     подсказка: opkg update && opkg install ca-certificates
     проверьте ветку (--branch) и имя файла (--dev-file)
     или укажите свой адрес архива: --url <адрес>"
}

# --- распаковка --------------------------------------------------------------
# Ключевая идея: не пользоваться --exclude (его нет в старых BusyBox), а взять
# список файлов из архива и распаковать только нужные.
make_workdir() {
    for _d in "$TMP_OVERRIDE" /opt/tmp /opt/var/tmp "${TMPDIR:-}" /tmp; do
        [ -n "$_d" ] || continue
        mkdir -p "$_d" 2>/dev/null || true
        [ -d "$_d" ] || continue
        [ -w "$_d" ] || continue
        if mkdir -p "$_d/susanin-inst.$$" 2>/dev/null; then
            WORK=$(CDPATH= cd -- "$_d/susanin-inst.$$" && pwd)
            say "рабочий каталог: $WORK"
            return 0
        fi
    done
    _w=$(mktemp -d 2>/dev/null) || _w=""
    if [ -n "$_w" ] && [ -d "$_w" ]; then
        WORK=$(CDPATH= cd -- "$_w" && pwd)
        say "рабочий каталог: $WORK"
        return 0
    fi
    die "не удалось создать временный каталог (проверьте место в /opt/tmp)"
}

archive_list() { # archive_list <архив> <куда>
    _arc="$1"; _out="$2"
    if tar -tf "$_arc" > "$_out" 2>/dev/null && [ -s "$_out" ]; then return 0; fi
    if command -v gzip >/dev/null 2>&1; then
        if gzip -dc "$_arc" 2>/dev/null | tar -t > "$_out" 2>/dev/null && [ -s "$_out" ]; then return 0; fi
    fi
    rm -f "$_out"
    return 1
}

XRAY_ARCH=""
pick_xray_arch() {
    case "$ARCH" in
        mipsel|mips) XRAY_ARCH=mipsel ;;
        aarch64)     XRAY_ARCH=aarch64 ;;
        *)           XRAY_ARCH="" ;;
    esac
}

keep_member() { # keep_member <имя в архиве> — 0 = распаковывать
    case "$1" in
        */bin/susanin-agent.*|bin/susanin-agent.*)
            case "$1" in
                */bin/susanin-agent."$ARCH"|bin/susanin-agent."$ARCH") return 0 ;;
                *) return 1 ;;
            esac ;;
        */xray/xray.*|xray/xray.*)
            [ "$WITH_XRAY" -eq 1 ] || return 1
            [ -n "$XRAY_ARCH" ] || return 1
            case "$1" in
                */xray/xray."$XRAY_ARCH"|xray/xray."$XRAY_ARCH") return 0 ;;
                *) return 1 ;;
            esac ;;
    esac
    return 0
}

build_keep_list() { # build_keep_list <полный список> <список для распаковки>
    while IFS= read -r _m; do
        [ -n "$_m" ] || continue
        # Каталоги в список НЕ кладём: GNU tar, получив имя каталога, вычитывает
        # архив целиком (распаковывает поддерево), а остальные имена после этого
        # считает ненайденными → код возврата 2. Файлы же tar создаёт вместе с
        # недостающими каталогами сам.
        case "$_m" in */) continue ;; esac
        if keep_member "$_m"; then printf '%s\n' "$_m"; fi
    done < "$1" > "$2"
}

tar_info() { # короткая версия tar — для сообщений об ошибке
    _v=$(tar --version 2>/dev/null | head -n1 || true)
    if [ -z "$_v" ]; then
        if [ -n "${BBVER:-}" ] && [ "$BBVER" != "неизвестно" ]; then
            _v="BusyBox v$BBVER"
        else
            _v="tar"
        fi
    fi
    printf '%s' "$_v"
}

extract_selective() { # extract_selective <архив> <куда> <список файлов> [tar]
    _arc="$1"; _dst="$2"; _keep="$3"; _tar="${4:-tar}"
    _args=$(tr '\n' ' ' < "$_keep")
    [ -n "$_args" ] || return 1
    # 1) tar с явным списком файлов: работает и там, где нет --exclude.
    if ( cd "$_dst" && "$_tar" -xzf "$_arc" $_args ) 2>/dev/null; then return 0; fi
    # 2) tar без поддержки -z: распаковываем gzip сами и подаём поток на stdin.
    if command -v gzip >/dev/null 2>&1; then
        if ( cd "$_dst" && gzip -dc "$_arc" | "$_tar" -x $_args ) 2>/dev/null; then return 0; fi
    fi
    # 3) tar мог вернуть ненулевой код, но нужное уже распаковано (особенности
    #    BusyBox/GNU tar: лишние предупреждения, «not found» на часть имён).
    #    Проверяем результат по файлу, а не по коду возврата.
    if [ -f "$_dst/susanin-agent" ]; then
        warn "tar вернул ошибку, но бинарник распакован — продолжаю"
        return 0
    fi
    if find "$_dst" -maxdepth 3 -type f -name "susanin-agent.$ARCH" 2>/dev/null | grep -q .; then
        warn "tar вернул ошибку, но бинарник распакован — продолжаю"
        return 0
    fi
    return 1
}

extract_full() { # extract_full <архив> <куда>
    _arc="$1"; _dst="$2"
    if ( cd "$_dst" && tar -xzf "$_arc" ) 2>/dev/null; then return 0; fi
    if command -v gzip >/dev/null 2>&1; then
        if ( cd "$_dst" && gzip -dc "$_arc" | tar -x ) 2>/dev/null; then return 0; fi
    fi
    return 1
}

prune_pkg() { # prune_pkg <корень пакета> — удалить чужие бинарники агента и Xray
    _root="$1"
    for _f in "$_root"/bin/susanin-agent.*; do
        [ -e "$_f" ] || continue
        case "$_f" in
            *"/susanin-agent.$ARCH") : ;;
            *) say "удаляю чужой бинарник: $(basename "$_f")"; rm -f "$_f" ;;
        esac
    done
    if [ "$WITH_XRAY" -eq 1 ] && [ -n "$XRAY_ARCH" ]; then
        for _f in "$_root"/xray/xray.*; do
            [ -e "$_f" ] || continue
            case "$_f" in
                *"/xray.$XRAY_ARCH") : ;;
                *) rm -f "$_f" ;;
            esac
        done
    else
        for _f in "$_root"/xray/xray.*; do
            if [ -e "$_f" ]; then rm -f "$_f"; fi
        done
    fi
    return 0
}

find_pkg_root() { # find_pkg_root <каталог распаковки>
    for _p in "$1"/*/install.sh "$1"/install.sh; do
        if [ -f "$_p" ]; then dirname "$_p"; return 0; fi
    done
    return 1
}

free_kb() { # свободное место в КБ (пусто, если df не смог)
    df -k "$1" 2>/dev/null | awk 'NR>1 {print $4; exit}'
}

verify_pkg() { # verify_pkg <корень пакета>
    _root="$1"
    if [ ! -f "$_root/SHA256SUMS" ]; then
        say "SHA256SUMS в пакете нет — проверка целостности пропущена"
        return 0
    fi
    if [ "$HAVE_SHA" -ne 1 ]; then
        say "sha256sum недоступен — проверка целостности пропущена"
        return 0
    fi
    _vf="$WORK/sha256.filtered"
    : > "$_vf"
    while IFS= read -r _line; do
        case "$_line" in ''|'#'*) continue ;; esac
        _f=$(printf '%s' "$_line" | awk '{print $NF}')
        case "$_f" in ./*) : ;; *) _f="./$_f" ;; esac
        if [ -f "$_root/$_f" ]; then printf '%s\n' "$_line" >> "$_vf"; fi
    done < "$_root/SHA256SUMS"
    if [ ! -s "$_vf" ]; then
        say "проверять нечего (файлы из SHA256SUMS в пакете не найдены)"
        return 0
    fi
    if ( cd "$_root" && sha256sum -c "$_vf" >/dev/null 2>&1 ); then
        say "SHA256: распакованные файлы совпали с SHA256SUMS"
        return 0
    fi
    if [ "$VERIFY" -eq 1 ]; then
        die "SHA256 не совпал (архив повреждён или SHA256SUMS в пакете устарел).
     повторите без --verify, чтобы установить как есть"
    fi
    warn "SHA256 не совпал у части файлов. Для свежей dev-сборки это бывает из-за
       устаревшего SHA256SUMS в архиве; если хотите строго — запустите с --verify"
    return 0
}

prepare_package() { # prepare_package <архив> -> PKG_ROOT
    _arc="$1"
    [ -f "$_arc" ] || die "архив не найден: $_arc"
    # Абсолютный путь: распаковка идёт из подкаталога (cd), относительный путь сломается.
    case "$_arc" in
        /*) : ;;
        *) _arc="$(pwd)/$_arc" ;;
    esac
    _dst="$WORK/pkg"
    mkdir -p "$_dst"
    _arc_b=$(wc -c < "$_arc" 2>/dev/null | tr -d ' \t' || true)
    case "${_arc_b:-}" in ''|*[!0-9]*) _arc_b=0 ;; esac

    _done=0
    _tar_used=""
    if archive_list "$_arc" "$WORK/list.all"; then
        _all=$(grep -c . "$WORK/list.all" 2>/dev/null || true)
        build_keep_list "$WORK/list.all" "$WORK/list.keep"
        _keep=$(grep -c . "$WORK/list.keep" 2>/dev/null || true)
        case "${_all:-}" in ''|*[!0-9]*) _all=0 ;; esac
        case "${_keep:-}" in ''|*[!0-9]*) _keep=0 ;; esac
        say "распаковка: по списку файлов ($_keep из $_all; чужие бинарники и Xray не распаковываем)"
        if extract_selective "$_arc" "$_dst" "$WORK/list.keep"; then
            _done=1; _tar_used=tar
        fi
        # Если системный tar не умеет список файлов, пробуем GNU tar из Entware.
        if [ "$_done" -ne 1 ] && [ -x /opt/bin/tar ]; then
            if [ "$(command -v tar 2>/dev/null || true)" != /opt/bin/tar ]; then
                say "пробую GNU tar из Entware: /opt/bin/tar"
                if extract_selective "$_arc" "$_dst" "$WORK/list.keep" /opt/bin/tar; then
                    _done=1; _tar_used=/opt/bin/tar
                fi
            fi
        fi
    else
        say "tar не смог прочитать список файлов архива"
    fi

    if [ "$_done" -ne 1 ]; then
        # Полную распаковку не делаем по умолчанию: она пишет на носитель ~5 МБ
        # (все архитектуры и документация) вместо ~1,5 МБ, а нужен один бинарник.
        if [ "$FULL_UNPACK" -ne 1 ]; then
            die "не удалось распаковать архив выборочно ($(tar_info)).
     Полную распаковку я не делаю специально — она пишет ~5 МБ вместо ~1,5 МБ.
     Что можно сделать:
       1) разрешить полную распаковку явно (запишет ~5 МБ на носитель):
            sh bootstrap.sh --allow-full-unpack <ваши флаги>
       2) либо распаковать архив на компьютере и скопировать на роутер только
          bin/susanin-agent.<arch> и файлы пакета (см. DEPLOY.md)
     Пришлите, пожалуйста, вывод этой команды в тему/issue — разберёмся:
            sh bootstrap.sh --check; tar --version; tar -tvf <архив> | head -20"
        fi
        warn "полная распаковка по вашему запросу (--allow-full-unpack): ~5 МБ записи на носитель"
        _need=$(( _arc_b / 1024 * 3 ))
        if [ "$HAVE_DF" -eq 1 ] && [ "$_need" -gt 0 ]; then
            _free=$(free_kb "$WORK" || true)
            case "${_free:-}" in
                ''|*[!0-9]*) : ;;
                *) if [ "$_free" -lt "$_need" ]; then
                       warn "в $WORK свободно ${_free}K, для полной распаковки нужно ~${_need}K"
                   fi ;;
            esac
        fi
        extract_full "$_arc" "$_dst" || die "не удалось распаковать архив ($_arc)
     подсказка: проверьте, что файл докачан целиком (--file) и есть место в /opt/tmp"
        _prune=1
    else
        _prune=0
        if [ "$_tar_used" = /opt/bin/tar ]; then
            say "распаковано через /opt/bin/tar (GNU tar из Entware)"
        fi
    fi

    PKG_ROOT=$(find_pkg_root "$_dst" || true)
    [ -n "$PKG_ROOT" ] || die "в архиве не найден install.sh — это не пакет Susanin.Keenetic?"
    if [ "$_prune" -eq 1 ]; then prune_pkg "$PKG_ROOT"; fi

    if [ ! -f "$PKG_ROOT/bin/susanin-agent.$ARCH" ] \
       && [ ! -f "$PKG_ROOT/bin/susanin-agent" ] \
       && [ ! -f "$PKG_ROOT/susanin-agent" ]; then
        _have=""
        for _b in "$PKG_ROOT"/bin/susanin-agent.*; do
            if [ -e "$_b" ]; then _have="$_have $(basename "$_b")"; fi
        done
        die "в архиве нет бинарника под arch=$ARCH (есть:${_have:- нет})
     укажите архитектуру вручную: --arch mipsel|mips|aarch64|armv7|x86_64"
    fi
    say "пакет распакован: $PKG_ROOT"
}

# --- Xray (только по флагу --with-xray) --------------------------------------
# В архив бинарники Xray не входят (29 МБ + 28 МБ; нужны только для
# egress_type=tproxy), поэтому при --with-xray скачиваем нужный из репозитория и
# ставим в /opt/sbin/xray. Сверяем с xray/SHA256SUMS из пакета, если он есть.
download_xray() {
    [ "$WITH_XRAY" -eq 1 ] || return 0
    if [ -z "$XRAY_ARCH" ]; then
        warn "для arch=$ARCH бинарника Xray в репозитории нет (есть mipsel и aarch64) —
       положите рабочий Xray вручную: /opt/sbin/xray"
        return 0
    fi
    if [ -x /opt/sbin/xray ]; then
        say "xray уже установлен (/opt/sbin/xray) — не перезаписываю"
        return 0
    fi
    _tmp=0
    _file="$PKG_ROOT/xray/xray.$XRAY_ARCH"
    if [ -f "$_file" ]; then
        # Старый архив, где Xray ещё лежал внутри пакета.
        say "Xray найден в пакете: $_file"
    else
        _dir="$WORK"
        if [ -z "$_dir" ] || [ ! -d "$_dir" ]; then _dir=/tmp; fi
        _file="$_dir/xray.$XRAY_ARCH"
        _tmp=1
        _url="https://raw.githubusercontent.com/$REPO/$BRANCH/develop/xray/xray.$XRAY_ARCH"
        say "скачиваю Xray ($XRAY_ARCH): $_url"
        if ! fetch "$_url" "$_file"; then
            warn "не удалось скачать Xray — скачайте вручную и положите в /opt/sbin/xray
       (адреса и суммы — в xray/README.txt и xray/SHA256SUMS пакета)"
            return 0
        fi
    fi
    _sums="$PKG_ROOT/xray/SHA256SUMS"
    if [ -f "$_sums" ] && command -v sha256sum >/dev/null 2>&1; then
        _want=$(awk -v f="xray.$XRAY_ARCH" '$2==f {print $1; exit}' "$_sums" 2>/dev/null || true)
        _got=$(sha256sum "$_file" 2>/dev/null | awk '{print $1}' || true)
        if [ -n "$_want" ] && [ "$_want" != "$_got" ]; then
            if [ "$VERIFY" -eq 1 ]; then
                die "SHA256 Xray не совпал: ожидалось $_want, получено ${_got:-?}"
            fi
            warn "SHA256 Xray не совпал с xray/SHA256SUMS (ожидалось $_want) — ставлю как есть"
        elif [ -n "$_want" ]; then
            say "SHA256 Xray: OK"
        fi
    fi
    mkdir -p /opt/sbin 2>/dev/null || true
    if cp "$_file" /opt/sbin/xray 2>/dev/null && chmod +x /opt/sbin/xray 2>/dev/null; then
        say "xray установлен: /opt/sbin/xray"
        if [ "$_tmp" -eq 1 ]; then rm -f "$_file" 2>/dev/null || true; fi
    else
        warn "не удалось положить Xray в /opt/sbin/xray — файл: $_file"
    fi
    return 0
}

# --- работа ------------------------------------------------------------------
detect_platform
if [ "$CHECKONLY" -eq 1 ]; then
    print_platform
    exit 0
fi

say "платформа: arch=$ARCH ($ARCH_SRC), ядро=${KREL:-?} ($KMACH), BusyBox=$BBVER, загрузка=${FETCHER:-нет}"
pick_xray_arch
case " $SUPPORTED_ARCH " in
    *" $ARCH "*) : ;;
    *) warn "для arch=$ARCH в сборке нет бинарника — установка, скорее всего, не пройдёт" ;;
esac

# Флаги install.sh дополняем своей архитектурой: чтобы там выбрался тот же бинарник.
case " $INSTALL_ARGS " in
    *" --arch "*) : ;;
    *) INSTALL_ARGS="$INSTALL_ARGS --arch $ARCH" ;;
esac

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd || printf '.')

cleanup() {
    if [ -n "$WORK" ] && [ -d "$WORK" ]; then
        if [ "$KEEP" -eq 1 ]; then
            say "временный каталог сохранён: $WORK"
        else
            rm -rf "$WORK"
        fi
    fi
    return 0
}

if [ -z "$FILE" ] && [ -z "$URL" ] && [ -f "$SELF_DIR/install.sh" ] \
   && { [ -f "$SELF_DIR/susanin-agent" ] || [ -f "$SELF_DIR/bin/susanin-agent" ] \
        || [ -f "$SELF_DIR/bin/susanin-agent.$ARCH" ]; }; then
    PKG_ROOT="$SELF_DIR"
    say "пакет уже распакован рядом со скриптом: $PKG_ROOT"
else
    make_workdir
    trap 'cleanup' 0
    if [ -n "$FILE" ]; then
        ARC="$FILE"
        say "использую архив: $ARC"
    else
        download_archive
        ARC="$WORK/pkg.tar.gz"
        _sz=$(wc -c < "$ARC" 2>/dev/null | tr -d ' \t' || true)
        case "${_sz:-}" in ''|*[!0-9]*) _sz=0 ;; esac
        if [ "$_sz" -lt 20000 ]; then
            die "скачанный файл слишком мал ($_sz байт) — похоже, это не архив
     подсказка: проверьте адрес/ветку: --url, --branch, --dev-file"
        fi
    fi
    prepare_package "$ARC"
    verify_pkg "$PKG_ROOT"
fi

say "архитектура: $ARCH ($ARCH_SRC)"
if [ "$DRYRUN" -eq 1 ]; then
    say "режим --dry-run: установку не запускаю. Пакет: $PKG_ROOT"
    if [ "$WITH_XRAY" -eq 1 ]; then
        say "с --with-xray был бы скачан Xray ($XRAY_ARCH) и положен в /opt/sbin/xray"
    fi
    say "запустить установку: cd $PKG_ROOT && sh install.sh $INSTALL_ARGS"
    exit 0
fi

download_xray

say "запускаю установщик пакета: sh install.sh$INSTALL_ARGS"
if ( cd "$PKG_ROOT" && sh ./install.sh $INSTALL_ARGS ); then
    say "готово. Проверка: sh /opt/susanin/tools/susanin.sh status"
else
    die "install.sh завершился с ошибкой (см. сообщения выше)"
fi
