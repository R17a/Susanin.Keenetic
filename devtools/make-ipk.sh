#!/bin/sh
# make-ipk.sh — собрать .ipk-пакеты для Entware (0.4.0).
#
# .ipk — это gzip(tar) с членами ./debian-binary, ./data.tar.gz, ./control.tar.gz
# (именно так упакованы пакеты в фиде Entware; классический ar-вариант
# Keenetic-овский opkg не принимает: «Malformed package file»).
# Пакет ставится в /opt (Entware): /opt/susanin/... и /opt/etc/init.d/...
#
# Использование:
#   sh devtools/make-ipk.sh [--bin DIR] [--out DIR] [--version X] [arch…]
#   sh devtools/make-ipk.sh --bin build --out dist --version 0.4.0
#   sh devtools/make-ipk.sh --bin build --out dist --one mipsel /path/susanin-agent
#
# Без --one собирает все архитектуры, для которых есть <bin>/susanin-agent.<arch>.
# Требует: tar, gzip (есть в WSL/Ubuntu и в Entware).
#
# Имена: susanin-keenetic_<version>_<opkg-arch>.ipk
set -eu

SRC=$(cd "$(dirname "$0")/.." && pwd)   # корень репозитория
BINDIR="$SRC/build"
OUT="$SRC/dist"
VER=""
ONE=""
ONE_BIN=""
ARCHS=""

die() { echo "make-ipk: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --bin)     BINDIR="$2"; shift 2 ;;
        --out)     OUT="$2"; shift 2 ;;
        --version) VER="$2"; shift 2 ;;
        --one)     ONE="$2"; ONE_BIN="${3:-}"; shift 2; [ -n "$ONE_BIN" ] && shift ;;
        -h|--help)
            sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*) die "неизвестный параметр: $1" ;;
        *)  ARCHS="$ARCHS $1"; shift ;;
    esac
done

command -v tar >/dev/null 2>&1 || die "нет 'tar'"
command -v gzip >/dev/null 2>&1 || die "нет 'gzip'"

# Целевая архитектура сборки -> архитектура entware/opkg.
opkg_arch() {
    case "$1" in
        mipsel)  echo mipsel-3.4 ;;
        mips)    echo mips-3.4 ;;
        aarch64) echo aarch64-3.10 ;;
        armv7)   echo armv7sf-k3.2 ;;
        x86_64)  echo x86-64 ;;
        *)       echo "$1" ;;
    esac
}

# Версия: из src/version.h, если не задана.
if [ -z "$VER" ]; then
    VER=$(sed -n 's/.*SUSANIN_VERSION "\(.*\)".*/\1/p' "$SRC/src/version.h" | head -1)
fi
[ -n "$VER" ] || die "не удалось определить версию (--version)"

mkdir -p "$OUT"
# Абсолютный путь: сборка .ipk идёт из временного каталога (cd в subshell),
# поэтому относительный --out там бы не нашёлся.
OUT=$(cd "$OUT" && pwd)

# ---- один пакет ------------------------------------------------------------
build_one() { # build_one <target-arch> <binary>
    _t="$1"; _bin="$2"
    _oa=$(opkg_arch "$_t")
    [ -f "$_bin" ] || die "нет бинарника: $_bin"

    _work=$(mktemp -d 2>/dev/null || echo "/tmp/mkipk.$$")
    _data="$_work/data"
    _ctrl="$_work/control"
    mkdir -p "$_data/opt/susanin/bin" "$_data/opt/susanin/tools" \
             "$_data/opt/susanin/share" "$_data/opt/susanin/www" \
             "$_data/opt/susanin/docs" "$_data/opt/etc/init.d" \
             "$_data/opt/etc/ndm/netfilter.d" "$_ctrl"

    # Библиотека приложения
    cp "$_bin" "$_data/opt/susanin/bin/susanin-agent"
    chmod 755 "$_data/opt/susanin/bin/susanin-agent"

    # Единый список поставки (тот же, что у CI-архива): packaging/manifest.txt.
    # Читаем через redirect (не pipe): иначе ошибка ниже не выйдет из функции.
    # Отсутствующий в манифесте файл — это ОШИБКА, а не «молча пропустить».
    while read -r _cls _src; do
        case "${_cls:-}" in ''|'#'*) continue ;; esac
        [ -n "${_src:-}" ] || continue
        if [ ! -e "$SRC/$_src" ]; then
            echo "make-ipk: в манифесте $_src, но файла нет (проверьте packaging/manifest.txt)" >&2
            rm -rf "$_work"
            return 1
        fi
        case "$_cls" in
            tool)   cp "$SRC/$_src" "$_data/opt/susanin/tools/" ;;
            init)   cp "$SRC/$_src" "$_data/opt/etc/init.d/$(basename "$_src")" ;;
            doc)    cp "$SRC/$_src" "$_data/opt/susanin/docs/$(basename "$_src")" ;;
            share)  cp "$SRC/$_src" "$_data/opt/susanin/share/$(basename "$_src")" ;;
            cfg)    cp "$SRC/$_src" "$_data/opt/susanin/share/susanin.conf.example" ;;
            www)    cp -r "$SRC/$_src/." "$_data/opt/susanin/www/" ;;
            ayserver) cp -r "$SRC/$_src" "$_data/opt/susanin/ay-server" ;;
            ndmhook) cp "$SRC/$_src" "$_data/opt/etc/ndm/netfilter.d/$(basename "$_src")" ;;
            root)   : ;;   # install.sh/bootstrap.sh нужны tar-архиву, не .ipk
            *)
                echo "make-ipk: неизвестный класс '$_cls' в манифесте" >&2
                rm -rf "$_work"
                return 1 ;;
        esac
    done < "$SRC/packaging/manifest.txt"
    find "$_data/opt/etc/init.d" -type f -exec chmod 755 {} \; 2>/dev/null || true
    find "$_data/opt/susanin/tools" -type f -name '*.sh' -exec chmod 755 {} \; 2>/dev/null || true
    find "$_data/opt/susanin/ay-server" -type f -name '*.sh' -exec chmod 755 {} \; 2>/dev/null || true
    find "$_data/opt/etc/ndm/netfilter.d" -type f -exec chmod 755 {} \; 2>/dev/null || true

    # control + скрипты сопровождения
    _size=$(du -sk "$_data" 2>/dev/null | awk '{print $1}')
    [ -n "${_size:-}" ] || _size=0
    sed -e "s|{{VER}}|$VER|g" -e "s|{{ARCH}}|$_oa|g" -e "s|{{SIZE}}|$_size|g" \
        "$SRC/packaging/opkg/control.template" > "$_ctrl/control"
    for s in postinst prerm postrm; do
        [ -f "$SRC/packaging/opkg/$s" ] && cp "$SRC/packaging/opkg/$s" "$_ctrl/$s"
    done
    chmod 755 "$_ctrl/postinst" "$_ctrl/prerm" "$_ctrl/postrm" 2>/dev/null || true

    # Сборка .ipk. Формат — как у пакетов Entware (bin.entware.net): это
    # gzip(tar) с членами ./debian-binary, ./data.tar.gz, ./control.tar.gz.
    # Классический ar-.ipk (debian-binary + control.tar.gz + data.tar.gz)
    # Keenetic-овский opkg отвергает: «Malformed package file».
    printf '2.0\n' > "$_work/debian-binary"
    ( cd "$_ctrl" && tar -czf "$_work/control.tar.gz" ./control ./postinst ./prerm ./postrm 2>/dev/null \
        || tar -czf "$_work/control.tar.gz" ./control )
    ( cd "$_data" && tar -czf "$_work/data.tar.gz" ./opt )
    _out="$OUT/susanin-keenetic_${VER}_${_oa}.ipk"
    ( cd "$_work" && tar -czf "$_out" ./debian-binary ./data.tar.gz ./control.tar.gz )
    echo "make-ipk: $_out ($(du -h "$_out" | awk '{print $1}'))"
    rm -rf "$_work"
}

if [ -n "$ONE" ]; then
    [ -n "$ONE_BIN" ] || die "--one требует путь к бинарнику"
    build_one "$ONE" "$ONE_BIN"
    # SHA256SUMS рядом с пакетом: по нему проверяют загрузку (и CI, и вручную).
    ( cd "$OUT" && sha256sum ./*.ipk > SHA256SUMS 2>/dev/null ) || true
    exit 0
fi

[ -n "$ARCHS" ] || ARCHS="mipsel mips aarch64 armv7 x86_64"
_n=0
for a in $ARCHS; do
    b="$BINDIR/susanin-agent.$a"
    if [ ! -f "$b" ]; then
        echo "make-ipk: пропускаю $a (нет $b)" >&2
        continue
    fi
    build_one "$a" "$b"
    _n=$((_n + 1))
done
[ "$_n" -gt 0 ] || die "не собрано ни одного пакета (укажите --bin DIR)"
# SHA256SUMS рядом с пакетами (имена без каталогов, как в релизе).
( cd "$OUT" && sha256sum ./*.ipk > SHA256SUMS 2>/dev/null ) || true
echo "make-ipk: готово, $_n пакет(ов) в $OUT (+SHA256SUMS)"
