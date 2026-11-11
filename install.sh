#!/bin/sh
# Susanin.Keenetic installer.
# Online (default): downloads the per-arch archive from GitHub Releases.
#   curl -fsSL https://raw.githubusercontent.com/R17a/Susanin.Keenetic/main/install.sh \
#     | sh -s -- [--arch mipsel] [--version vX.Y.Z] [--yes]
# Пакетом Entware (.ipk) из релиза, с автоопределением архитектуры:
#   curl -fsSL https://raw.githubusercontent.com/R17a/Susanin.Keenetic/main/install.sh \
#     | sh -s -- --ipk [--version vX.Y.Z] [--yes]
# Offline/local: run from an extracted archive (susanin-agent is next to this script):
#   sh install.sh [--yes]
# Prompts accept short answers: "y" or "yes". Use --yes|-y to skip all prompts.
# POSIX sh (busybox ash compatible).
set -eu

REPO="R17a/Susanin.Keenetic"
# Ветка, откуда берётся Xray (xray/). Обычно main; переопределяется
# SUSANIN_BRANCH для своих форков/зеркал.
BRANCH="${SUSANIN_BRANCH:-main}"
PREFIX=/opt/susanin
INITD=/opt/etc/init.d
ARCH=""
VERSION="latest"
EGRESS=""
LAN=""
SUBNETS=""
# Интерфейсы-серверы, которые не берём как egress/LAN (qWDTT и т.п.).
DISCOVER_EXCLUDE="${DISCOVER_EXCLUDE:-wdtt0,wdttraw0,tun0,tap0}"
EXCL_RE=$(printf '%s' "$DISCOVER_EXCLUDE" | tr ',' '|' | tr -d ' \t')
YES=0
FORCE=0
NO_START=0
# 1 = не трогать существующие vpn_always.txt/vpn_never.txt (флаг --keep-lists).
KEEP_LISTS=0
DISK_MODE=""
DEPS=0
XRAYTUN=0
USE_IPK=0
IPK_LOCAL=""     # --ipk-file: уже скачанный .ipk на устройстве (без релиза)
WITH_OC=0        # --with-oc: добавить oc+ (только осознанно, не по умолчанию)
PROXY_UID=""     # --proxy-uid: uid процесса-прокси на роутере (P5)
PROXY_EGRESS=""  # --proxy-egress: интерфейс туннеля для его трафика (P5)

say() { echo "[susanin] $*"; }
die() { echo "[susanin] ERROR: $*" >&2; exit 1; }

# Скачивание: curl или wget-ssl (у BusyBox-wget нет HTTPS).
pick_fetch() {
    if command -v curl >/dev/null 2>&1; then
        fetch() { curl -fsSL "$1" -o "$2"; }
    elif command -v wget >/dev/null 2>&1; then
        fetch() { wget -qO "$2" "$1"; }
    else
        die "need curl or wget-ssl (Entware: opkg update && opkg install ca-certificates wget-ssl; либо 'opkg install curl')"
    fi
}

# --- VLESS/REALITY: Xray + шаблон tproxy-конфига ------------------------------
# Вызывается по --with-xray-tproxy (или bootstrap --with-xray) в ЛЮБОМ режиме
# установки (tar-архив и .ipk). Бинарников Xray нет в поставке, поэтому при
# отсутствии /opt/sbin/xray скачиваем нужный из репозитория (xray/) и
# сверяем sha256 по xray/SHA256SUMS. Если сети нет — просто подсказываем.
xray_setup() {
    [ "$XRAYTUN" -eq 1 ] || return 0
    say "XRay-egress (tproxy): проверяю инструменты ..."
    if [ -x /opt/sbin/xray ]; then
        say "xray: есть (/opt/sbin/xray)"
    else
        case "$ARCH" in
            mipsel|mips) _xa=mipsel ;;
            aarch64)     _xa=aarch64 ;;
            *)           _xa="" ;;
        esac
        if [ -z "$_xa" ]; then
            say "xray: для arch=$ARCH готового бинарника в репозитории нет (есть mipsel и aarch64) — положите рабочий Xray в /opt/sbin/xray и chmod +x"
        else
            pick_fetch
            mkdir -p /opt/sbin /opt/tmp 2>/dev/null || true
            _xbase="https://raw.githubusercontent.com/$REPO/$BRANCH/xray"
            _xfile="/opt/tmp/xray.$_xa"
            say "скачиваю Xray ($_xa): $_xbase/xray.$_xa"
            if fetch "$_xbase/xray.$_xa" "$_xfile"; then
                if fetch "$_xbase/SHA256SUMS" /opt/tmp/xray.SHA256SUMS 2>/dev/null && \
                   command -v sha256sum >/dev/null 2>&1; then
                    _want=$(awk -v f="xray.$_xa" '$2==f {print $1; exit}' /opt/tmp/xray.SHA256SUMS 2>/dev/null || true)
                    _got=$(sha256sum "$_xfile" | awk '{print $1}' || true)
                    if [ -n "$_want" ] && [ "$_want" != "$_got" ]; then
                        rm -f "$_xfile" /opt/tmp/xray.SHA256SUMS
                        say "xray: SHA256 НЕ совпал — скачивание отменено, поставьте Xray вручную"
                        _xfile=""
                    else
                        [ -n "$_want" ] && say "xray: SHA256 OK"
                    fi
                fi
                if [ -n "${_xfile:-}" ] && [ -f "$_xfile" ]; then
                    if cp "$_xfile" /opt/sbin/xray && chmod +x /opt/sbin/xray; then
                        say "xray установлен: /opt/sbin/xray"
                    else
                        say "xray: не удалось положить в /opt/sbin/xray (файл: $_xfile)"
                    fi
                    rm -f "$_xfile"
                fi
            elif [ ! -x "$PREFIX/bin/xray" ]; then
                say "xray: скачать не удалось — положите рабочий Xray в /opt/sbin/xray и chmod +x"
            fi
        fi
    fi
    # Шаблон конфига: ищем и в пакете (.ipk: share/), и в распакованном архиве.
    _xtp=""
    for _c in "$PREFIX/share/xray-tproxy.json.example" \
              "${DIR:-}/xray-tproxy.json.example" \
              "${DIR:-}/xray/xray-tproxy.json.example" \
              "${DIR0:-}/xray-tproxy.json.example"; do
        [ -n "$_c" ] && [ -f "$_c" ] && { _xtp="$_c"; break; }
    done
    if [ -n "$_xtp" ]; then
        mkdir -p "$PREFIX/etc" 2>/dev/null || true
        cp "$_xtp" "$PREFIX/etc/xray-tproxy.json.example" 2>/dev/null || true
        say "шаблон: $PREFIX/etc/xray-tproxy.json.example (подставьте SERVER/UUID/SNI/PBK/SID)"
    fi
    say "в susanin.conf: egress_type=tproxy, tproxy_port=12345"
    say "включить/проверить: sh $PREFIX/tools/xray-egress.sh enable | status | test <ip>"
}

# Detect whether /opt lives on a removable flash (USB/SD) or on the router's
# internal memory (NAND/UBIFS/overlay). Internal -> soft disk mode (minimal writes).
detect_disk_mode() {
    dev=""; fst=""; mnt=""
    if command -v findmnt >/dev/null 2>&1; then
        mnt=$(findmnt -n -o TARGET --target /opt 2>/dev/null | head -n1)
        fst=$(findmnt -n -o FSTYPE --target /opt 2>/dev/null | head -n1)
        dev=$(findmnt -n -o SOURCE --target /opt 2>/dev/null | head -n1)
    fi
    if [ -z "$mnt" ] && [ -r /proc/mounts ]; then
        line=$(grep -E ' /opt ' /proc/mounts 2>/dev/null | head -n1)
        if [ -n "$line" ]; then
            dev=$(printf '%s' "$line" | awk '{print $1}')
            fst=$(printf '%s' "$line" | awk '{print $3}')
            mnt=/opt
        fi
    fi
    # /opt — не отдельная точка монтирования => часть rootfs (внутренняя память).
    if [ "$mnt" != "/opt" ]; then
        echo soft; return
    fi
    case "$fst" in
        ubifs|squashfs|jffs2|overlay|ramfs|tmpfs) echo soft; return ;;
    esac
    case "$dev" in
        *mtdblock*|*ubiblock*|*overlay*|*rootfs*|/storage*) echo soft; return ;;
        /dev/sd*|/dev/mmcblk*|/dev/nvme*|/dev/usb*) echo normal; return ;;
    esac
    # Не смогли определить носитель — безопаснее мягкий режим.
    echo soft
}

while [ $# -gt 0 ]; do
    case "$1" in
        --arch) ARCH="$2"; shift ;;
        --version) VERSION="$2"; shift ;;
        --egress) EGRESS="$2"; shift ;;
        --lan) LAN="$2"; shift ;;
        --subnets) SUBNETS="$2"; shift ;;
        --prefix) PREFIX="$2"; shift ;;
        --disk-mode) DISK_MODE="$2"; shift ;;
        --deps) DEPS=1 ;;
        --ipk) USE_IPK=1 ;;
        # Локальный .ipk (без релиза/интернета): --ipk-file /opt/tmp/x.ipk
        --ipk-file) IPK_LOCAL="$2"; USE_IPK=1; shift ;;
        --with-xray-tproxy) XRAYTUN=1 ;;
        --with-oc) WITH_OC=1 ;;
        --proxy-uid) PROXY_UID="$2"; shift ;;
        --proxy-egress) PROXY_EGRESS="$2"; shift ;;
        --yes|-y) YES=1 ;;
        --force) FORCE=1 ;;
        --no-start) NO_START=1 ;;
        --keep-lists|--no-lists) KEEP_LISTS=1 ;;
        -h|--help)
            echo "usage: $0 [--arch mipsel|mips|aarch64|armv7|x86_64] [--version latest|vX.Y.Z]"
            echo "          [--ipk] [--egress IF] [--lan IF,IF] [--subnets CIDR,CIDR] [--prefix DIR]"
            echo "          [--disk-mode normal|soft] [--deps] [--with-xray-tproxy] [--with-oc]"
            echo "          [--yes] [--force] [--no-start]"
            echo
            echo "  --ipk        ставить пакетом Entware (.ipk) из релиза вместо tar-архива:"
            echo "               архитектура определяется сама, файл скачивается в /opt/tmp,"
            echo "               затем выполняется opkg install (конфиг и списки сохраняются)."
            echo "  --ipk-file F ставить уже скачанный .ipk с устройства (без релиза/интернета):"
            echo "               sh install.sh --ipk-file /opt/tmp/susanin-keenetic_*.ipk --yes"
            echo "  --disk-mode  normal (USB/SD) | soft (internal flash; no logs/state/backups)."
            echo "               Default: autodetect by /opt mount."
            echo "  --deps       доустановить недостающие пакеты через opkg без вопроса"
            echo "  --with-xray-tproxy  проверить Xray и положить шаблон tproxy-конфига"
            echo "  --with-oc    добавить 'oc+' (клиенты OpenConnect-сервера) в lan_interfaces."
            echo "               По умолчанию НЕ добавляется: сервер есть не у всех."
            echo "  --proxy-uid U  включить P5: трафик процесса с uid U (MTProxy/Teleproxy)"
            echo "               уходит в туннель. Пользователь создаётся автоматически."
            echo "  --proxy-egress IF  интерфейс туннеля для трафика прокси (по умолчанию nwg0)."
            echo
            echo "  Prompts: answer 'y' (or 'yes'); --yes|-y skips all prompts."
            exit 0 ;;
        *) die "unknown arg: $1" ;;
    esac
    shift
done

# --- зависимости (Entware) ---------------------------------------------------
need=""
for t in ipset conntrack iptables; do
    command -v "$t" >/dev/null 2>&1 || need="$need $t"
done
[ -f /opt/etc/ssl/certs/ca-certificates.crt ] || need="$need ca-certificates"
# wget-ssl: у BusyBox-wget нет HTTPS, а установщик качает архив по https.
if ! command -v curl >/dev/null 2>&1; then
    if ! wget --help 2>&1 | grep -q -- '--no-check-certificate'; then
        need="$need wget-ssl"
    fi
fi
need=$(printf '%s' "$need" | sed 's/^ *//')
if [ -n "$need" ]; then
    say "не хватает пакетов:$need"
    install_them=0
    if [ "$DEPS" -eq 1 ]; then
        install_them=1
    elif [ "$YES" -ne 1 ] && [ -r /dev/tty ]; then
        printf "[susanin] Доустановить через opkg? [y/N]: " >&2
        read _ok < /dev/tty || _ok=n
        case "$_ok" in y|Y|yes|YES) install_them=1 ;; esac
    fi
    if [ "$install_them" -eq 1 ]; then
        say "opkg update && opkg install $need"
        opkg update || true
        opkg install $need || true
    else
        say "пропускаю. Установите вручную: opkg update && opkg install $need"
    fi
fi

# --- определение платформы ---------------------------------------------------
# Архитектуру берём из Entware (авторитетен для userland/ABI): ядро (uname -m)
# ненадёжно — не различает endianness MIPS и путается при 64-битном ядре с
# 32-битным userland.
# Порядок источников: entware_release -> opkg.conf (фид) -> opkg print-architecture
# -> uname -m + endianness ELF-заголовка.
ARCH_SRC=""

elf_endian() { # little|big|пусто — байт 5 ELF-заголовка (EI_DATA: 1=LSB, 2=MSB)
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

probe_endian() { # endianness по userland-бинарям (Entware важнее системных)
    for _f in /opt/bin/opkg /opt/bin/opkg-cl /opt/bin/busybox /bin/busybox /bin/sh; do
        _e=$(elf_endian "$_f" 2>/dev/null || true)
        if [ -n "$_e" ]; then printf '%s' "$_e"; return 0; fi
    done
    return 1
}

entware_arch() { # сырое имя архитектуры Entware (напр. mipselsf-k3.4)
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

arch_norm() { # mipselsf-k3.4 -> mipsel, armv7sf-k2.6 -> armv7, aarch64-3.10 -> aarch64
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

detect_arch() { # печатает "arch|источник" (источник — для строки platform:)
    _ent=$(entware_arch)
    _n=$(arch_norm "$_ent")
    case "$_n" in
        mipsel|mips|aarch64|armv7|x86_64|mips64el)
            printf '%s|Entware (%s)\n' "$_n" "$_ent"; return 0 ;;
    esac
    _m=$(uname -m 2>/dev/null | tr 'A-Z' 'a-z' || true)
    case "$_m" in
        aarch64|arm64)      printf 'aarch64|uname -m (%s)\n' "$_m"; return 0 ;;
        armv7l|armv7|armhf) printf 'armv7|uname -m (%s)\n' "$_m"; return 0 ;;
        x86_64|amd64)       printf 'x86_64|uname -m (%s)\n' "$_m"; return 0 ;;
        mips|mipsel|mips64)
            _e=$(probe_endian || true)
            case "$_e" in
                little) printf 'mipsel|uname -m (%s) + ELF-endianness (%s)\n' "$_m" "$_e"; return 0 ;;
                big)    printf 'mips|uname -m (%s) + ELF-endianness (%s)\n' "$_m" "$_e"; return 0 ;;
            esac
            # Endianness определить не удалось: на Keenetic+Entware это почти всегда mipsel.
            printf 'mipsel|предположение для MIPS (endianness не определён)\n'; return 0 ;;
    esac
    return 1
}

if [ -z "$ARCH" ]; then
    # detect_arch вызывается в подоболочке — источник возвращаем в самом выводе,
    # иначе в логе получалось «arch=mipsel ()».
    _det=$(detect_arch || true)
    if [ -z "$_det" ]; then
        _m=$(uname -m 2>/dev/null || echo unknown)
        die "cannot detect arch (uname -m=$_m); pass --arch mipsel|mips|aarch64|armv7|x86_64"
    fi
    ARCH=${_det%%|*}
    ARCH_SRC=${_det#*|}
else
    ARCH_SRC="--arch"
fi
KREL=$(uname -r 2>/dev/null || true)
KMACH=$(uname -m 2>/dev/null || true)
BBVER=$( (busybox 2>&1 || true) | sed -n '1s/.*BusyBox v\([0-9][^ ,)]*\).*/\1/p' )
say "platform: arch=$ARCH ($ARCH_SRC), kernel=${KREL:-?} ($KMACH), busybox=${BBVER:-?}"

# Откуда качать: GitHub Releases (по умолчанию) либо свой зеркальный каталог —
# SUSANIN_BASE_URL (например, локальный сервер или собственный фид). С зеркалом
# указывайте --version: имя .ipk/архива содержит версию.
if [ "$VERSION" = latest ]; then
    BASE="${SUSANIN_BASE_URL:-https://github.com/$REPO/releases/latest/download}"
else
    BASE="${SUSANIN_BASE_URL:-https://github.com/$REPO/releases/download/$VERSION}"
fi

# --- режим .ipk: ставим штатный пакет Entware из релиза -----------------------
# Зачем: tar-архив раскладывает файлы «руками», а .ipk ставится обычным opkg —
# появляется учёт пакета, `opkg remove` снимает службу/init/правила, а конфиг,
# списки, состояние и профили при обновлении не перезаписываются.
if [ "$USE_IPK" -eq 1 ]; then
    command -v opkg >/dev/null 2>&1 \
        || die "нет opkg — это не Entware? Установка без --ipk использует tar-архив"
    case "$ARCH" in
        mipsel)  OA=mipsel-3.4 ;;
        mips)    OA=mips-3.4 ;;
        aarch64) OA=aarch64-3.10 ;;
        armv7)   OA=armv7sf-k3.2 ;;
        x86_64)  OA=x86-64 ;;
        *) die "для архитектуры '$ARCH' нет .ipk (есть: mipsel, mips, aarch64, armv7, x86_64)" ;;
    esac
    pick_fetch
    if [ -n "$IPK_LOCAL" ]; then
        # Файл уже на устройстве: ни релиз, ни интернет не нужны.
        [ -f "$IPK_LOCAL" ] || die "нет файла: $IPK_LOCAL (--ipk-file)"
        IPK_FILE="$IPK_LOCAL"
        _sums_dir=$(dirname "$IPK_FILE")
        say "ipk (локальный файл): $IPK_FILE"
    else
        mkdir -p /opt/tmp
        _sums_dir=/opt/tmp
        _url=""
        IPK_FILE=""
        # (1) Релиз GitHub. Для latest имя ассета содержит версию — берём URL из
        # API (без jq); для явной версии URL собираем сами.
        if [ "$VERSION" = latest ]; then
            _api=$(mktemp 2>/dev/null) || _api=/tmp/susanin-api.$$
            if fetch "https://api.github.com/repos/$REPO/releases/latest" "$_api" 2>/dev/null; then
                _url=$(sed -n 's/.*"browser_download_url":[[:space:]]*"\([^"]*\)".*/\1/p' "$_api" \
                       | grep -F "_${OA}.ipk" | head -n1 || true)
            fi
            rm -f "$_api"
        else
            _url="$BASE/susanin-keenetic_${VERSION#v}_${OA}.ipk"
        fi
        if [ -n "$_url" ]; then
            say "ipk (релиз): $(basename "$_url")"
            if fetch "$_url" "/opt/tmp/$(basename "$_url")" 2>/dev/null; then
                IPK_FILE="/opt/tmp/$(basename "$_url")"
                fetch "$BASE/SHA256SUMS" "$_sums_dir/SHA256SUMS" 2>/dev/null || true
            else
                rm -f "/opt/tmp/$(basename "$_url")"
                [ "$VERSION" != latest ] && say "в релизе $VERSION нет пакета для $OA"
            fi
        fi
        # (2) Резервного источника больше нет: dev-каталог develop/ipk/ удалён,
        # .ipk публикуются только в Release.
        if [ -z "$IPK_FILE" ]; then
            rm -f "$_sums_dir/SHA256SUMS"
            die "нет .ipk для $OA в релизе
     что делать:
       * поставить tar-архивом:               sh install.sh --yes
       * поставить свой файл:                 sh install.sh --ipk-file /opt/tmp/<файл>.ipk
       * если релиз уже есть:                 sh install.sh --ipk --version vX.Y.Z"
        fi
    fi
    # --- проверка файла ДО установки -----------------------------------------
    # 1) Формат. Пакеты Entware — это gzip(tar) с ./debian-binary, ./data.tar.gz,
    #    ./control.tar.gz; старые сборки встречались и как ar-архив ("!<arch>").
    #    Если пришла HTML-страница или файл обрезан (кончилось место в /opt) —
    #    opkg сказал бы невнятное "Malformed package file", поэтому проверяем сами.
    _ibase=$(basename "$IPK_FILE")
    if [ ! -s "$IPK_FILE" ]; then
        die "пакет пустой: $IPK_FILE (место в /opt? проверьте df -h /opt)"
    fi
    if [ "$(head -c 7 "$IPK_FILE" 2>/dev/null)" != "!<arch" ]; then
        if ! gzip -t "$IPK_FILE" >/dev/null 2>&1; then
            _size=$(wc -c < "$IPK_FILE" | tr -d ' ')
            die "это не .ipk (нет ни ar-, ни gzip-заголовка; размер $_size б): $IPK_FILE
     обычно значит, что файл скачался не полностью или вместо файла пришла
     страница ошибки. Проверьте место (df -h /opt) и повторите."
        fi
    fi
    # 2) SHA256 по SHA256SUMS (строки вида "<hash>  ./имя" или "<hash>  имя").
    _sums="$_sums_dir/SHA256SUMS"
    _want=""
    [ -f "$_sums" ] && _want=$(awk -v b="$_ibase" \
        '$2==b || $2=="./"b {print $1; exit}' "$_sums" 2>/dev/null || true)
    if [ -n "$_want" ] && command -v sha256sum >/dev/null 2>&1; then
        _got=$(sha256sum "$IPK_FILE" | awk '{print $1}')
        if [ "$_want" != "$_got" ]; then
            _size=$(wc -c < "$IPK_FILE" | tr -d ' ')
            die "SHA256 не совпал — файл повреждён (размер $_size б, ожидалось ${_want%?}…)
     вероятная причина: не хватило места в /opt/tmp (df -h /opt) или скачивание
     оборвалось. Освободите место и повторите; можно проверить так:
       wget -O /opt/tmp/x.ipk $_ibase   # и сравнить sha256sum с $_sums"
        fi
        say "SHA256: ok"
    else
        say "SHA256: пропущено (нет SHA256SUMS/sha256sum)"
    fi
    [ -n "$IPK_LOCAL" ] || rm -f "$_sums"
    # Если в системе уже стоит ровно эта версия — opkg скажет «up to date» и НЕ
    # распакует пересобранные файлы (частый случай, когда пакет пересобрали без
    # смены номера: остаются старые бинарник/скрипты/www). Тогда ставим с
    # --force-reinstall сами, без просьбы добавить --force.
    _newver=$(basename "$IPK_FILE")
    _newver=${_newver#susanin-keenetic_}
    _newver=${_newver%_"$OA".ipk}
    _curver=$(opkg list-installed 2>/dev/null | awk '$1 == "susanin-keenetic" { print $3; exit }')
    [ -n "$_curver" ] || _curver=$(opkg status susanin-keenetic 2>/dev/null \
        | sed -n 's/^Version: //p' | head -n1)
    if [ "$FORCE" -eq 1 ]; then
        :
    elif [ -n "$_newver" ] && [ "$_newver" = "$_curver" ]; then
        say "версия $_curver уже установлена — переустанавливаю с --force-reinstall (чтобы применить пересобранные файлы)"
        FORCE=1
    fi
    if [ "$FORCE" -eq 1 ]; then
        say "opkg install --force-reinstall --force-downgrade $IPK_FILE"
        opkg install --force-reinstall --force-downgrade "$IPK_FILE" \
            || die "opkg install не удался"
    else
        # Версии: opkg считает 0.4.0 МЕНЬШЕ 0.4.0.RC1.Hotfix (короткая строка
        # идёт раньше суффикса) и отказывается ставить: «Not downgrading
        # package susanin-keenetic ...». Поэтому явно разрешаем понижение —
        # для обычного обновления флаг безвреден.
        say "opkg install --force-downgrade $IPK_FILE"
        opkg install --force-downgrade "$IPK_FILE" \
            || die "opkg install не удался (если пакет уже стоит: добавьте --force)
     «Not downgrading» = установленная версия нумерно выше (например,
     0.4.0.RC1.Hotfix): поставьте вручную:
       opkg install --force-downgrade $IPK_FILE
     «Malformed package file» = файл пакета повреждён/недокачан: проверьте
     sha256sum $IPK_FILE и df -h /opt, затем повторите."
    fi
    # opkg может напечатать «Not downgrading …» и всё равно выйти с кодом 0.
    # Поэтому проверяем, что в базе действительно стоит нужная версия.
    _inst=$(opkg list-installed 2>/dev/null | awk '$1 == "susanin-keenetic" { print $3; exit }')
    if [ -n "$_newver" ] && [ "$_inst" != "$_newver" ]; then
        die "opkg НЕ установил $_newver (в системе: ${_inst:-нет})
     «Not downgrading» = установленная версия нумерно выше (0.4.0 < 0.4.0.RC1.Hotfix):
       opkg install --force-downgrade $IPK_FILE
     либо обновиться архивом: sh /opt/susanin/tools/susanin.sh update v0.4.0"
    fi
    say "установлено: $_inst"
    say "готово. Проверка: susanin status && susanin diagnose"
    say "конфиг: $PREFIX/etc/susanin.conf — проверьте egress_interface и lan_interfaces"
    # VLESS/REALITY по желанию: --with-xray-tproxy (Xray скачивается отдельно,
    # в пакет не входит).
    xray_setup
    exit 0
fi

DIR0=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -f "$DIR0/susanin-agent" ] || [ -f "$DIR0/bin/susanin-agent" ] \
   || [ -n "$(ls "$DIR0"/susanin-agent.* "$DIR0"/bin/susanin-agent.* 2>/dev/null)" ]; then
    DIR=$DIR0
    say "local package: $DIR"
else
    pick_fetch
    ASSET="susanin-keenetic-deploy-$ARCH.tar.gz"
    say "arch=$ARCH version=$VERSION"
    TMP=$(mktemp -d /tmp/susanin-inst.XXXXXX)
    trap 'rm -rf "$TMP"' EXIT INT TERM
    say "downloading $BASE/$ASSET"
    fetch "$BASE/$ASSET" "$TMP/pkg.tar.gz" \
        || die "download failed (check --arch/--version or release assets): $BASE/$ASSET
     hint: opkg update && opkg install ca-certificates wget-ssl"
    tar -xzf "$TMP/pkg.tar.gz" -C "$TMP" || die "bad archive $ASSET"
    DIR=$TMP
fi

# Раскладка пакета: либо все файлы рядом с install.sh, либо по подпапкам
# (bin/, tools/, etc/, init/, www/). Ищем в обоих вариантах.
find_file() { # find_file <name> -> path
    for _d in "$DIR" "$DIR/bin" "$DIR/tools" "$DIR/etc" "$DIR/init" "$DIR/www"; do
        [ -e "$_d/$1" ] && { printf '%s\n' "$_d/$1"; return 0; }
    done
    return 1
}

if [ -f "$DIR/susanin-agent" ]; then
    BINFILE=susanin-agent
elif [ -f "$DIR/bin/susanin-agent.$ARCH" ]; then
    # Один каталог может содержать бинари под несколько архитектур: берём свою.
    BINFILE="bin/susanin-agent.$ARCH"
elif [ -f "$DIR/susanin-agent.$ARCH" ]; then
    BINFILE="susanin-agent.$ARCH"
elif [ -f "$DIR/bin/susanin-agent" ]; then
    BINFILE=bin/susanin-agent
else
    # Бинарника под нашу архитектуру нет. Ставить «первый попавшийся» нельзя:
    # так на mips64el/неизвестной арх. можно было получить чужой бинарник
    # (напр. aarch64). Разрешаем только случай «в пакете ровно один бинарник»,
    # и в этом случае предупреждаем.
    _cand=""
    _n=0
    for _b in "$DIR"/susanin-agent.*; do
        [ -f "$_b" ] || continue
        _n=$((_n + 1)); _cand="$_cand susanin-agent.${_b##*susanin-agent.}"
    done
    for _b in "$DIR"/bin/susanin-agent.*; do
        [ -f "$_b" ] || continue
        _n=$((_n + 1)); _cand="$_cand bin/susanin-agent.${_b##*susanin-agent.}"
    done
    if [ "$_n" -eq 1 ]; then
        BINFILE=$(printf '%s' "$_cand" | sed 's/^ *//')
        say "ВНИМАНИЕ: бинарника под arch=$ARCH в пакете нет; единственный бинарник — $BINFILE, ставлю его"
    elif [ "$_n" -gt 1 ]; then
        die "бинарника под arch=$ARCH в пакете нет; есть:$_cand
     укажите архитектуру вручную: --arch mipsel|mips|aarch64|armv7|x86_64"
    fi
fi
[ -n "${BINFILE:-}" ] && [ -f "$DIR/$BINFILE" ] || die "susanin-agent binary not found in $DIR (arch=$ARCH)"
say "binary: $BINFILE"

ifaces() { awk -F: '{print $1}' /proc/net/dev | tr -d ' ' | grep -v '^$'; }
addr_of() { ip addr show "$1" 2>/dev/null | awk '/inet /{print $2}' | head -1; }

pick() {
    _what="$1"; shift
    _n=0
    for _i in "$@"; do _n=$((_n + 1)); echo "  $_n) $_i" >&2; done
    if [ -r /dev/tty ]; then
        printf "%s [1-%d]: " "$_what" "$_n" >&2
        read _sel < /dev/tty || _sel=1
    else
        die "ambiguous $_what; pass flag explicitly (no tty)"
    fi
    _n=0
    for _i in "$@"; do _n=$((_n + 1)); [ "$_n" = "$_sel" ] && { echo "$_i"; return; }; done
    echo "$1"
}

default_devs() {
    ip route show table all 2>/dev/null \
      | awk '/default/ {for (i = 1; i <= NF; i++) if ($i == "dev") print $(i + 1)}' \
      | sort -u
}

if [ -z "$EGRESS" ]; then
    CAND=$(ifaces | grep -E '^(nwg|wg[0-9]*|amnezia|ovpn)' | grep -Ev "^($EXCL_RE)" || true)
    if [ -z "$CAND" ]; then
        CAND=$(ifaces | grep -E '^(tun[0-9]+|tap[0-9]+)$' | grep -Ev "^($EXCL_RE)" || true)
    fi
    CN=$(printf '%s\n' "$CAND" | grep -c . || true)
    if [ "$CN" = 1 ]; then
        EGRESS="$CAND"
    elif [ "$CN" -gt 1 ]; then
        DEF=$(default_devs)
        for c in $CAND; do
            if printf '%s\n' "$DEF" | grep -qx "$c"; then EGRESS="$c"; break; fi
        done
        [ -n "$EGRESS" ] || EGRESS=$(printf '%s\n' "$CAND" | grep -E '^(nwg|wg)' | head -1)
        [ -n "$EGRESS" ] || EGRESS=$(printf '%s\n' "$CAND" | head -1)
        say "selected egress=$EGRESS (candidates: $(printf '%s ' $CAND)); use --egress to override"
    elif ifaces | grep -qx nwg0; then
        EGRESS=nwg0
    else
        say "no VPN interface auto-detected; select manually"
        EGRESS=$(pick "select egress (VPN)" $(ifaces | grep -Ev "^(lo|ppp|tunl|$EXCL_RE)" || true))
    fi
fi
say "egress=$EGRESS addr=$(addr_of "$EGRESS")"

lan_from_routes() {
    ip route show 2>/dev/null | awk '
        /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/ && $0 !~ /default/ {
            for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); break }
        }' | sort -u
}

if [ -z "$LAN" ]; then
    LANBR=$(lan_from_routes | grep '^br' || true)
    if [ -n "$LANBR" ]; then
        LAN=$(printf '%s\n' "$LANBR" | awk 'NR==1{s=$0;next}{s=s","$0}END{print s}')
    else
        LAN=$(lan_from_routes | grep -Ev "^(ppp|nwg|wg|tun|tap|eth|$EXCL_RE)" \
              | awk 'NR==1{s=$0;next}{s=s","$0}END{print s}')
    fi
    [ -n "$LAN" ] || LAN="br0"
fi
if [ -z "$SUBNETS" ]; then
    for i in $(printf '%s' "$LAN" | tr ',' ' '); do
        p=$(ip route show 2>/dev/null | awk -v d="$i" '$0 ~ ("dev " d " ") && $1 ~ /\// {print $1; exit}')
        [ -n "$p" ] && SUBNETS="${SUBNETS:+$SUBNETS,}$p"
    done
fi
if [ -z "$SUBNETS" ]; then
    # Не смогли определить (нестандартная раскладка/нет connected-маршрутов):
    # не оставляем примеры из config.example.conf, а предупреждаем.
    SUBNETS="192.168.1.0/24"
    say "lan_subnets: определить не удалось — использую $SUBNETS (проверьте и поправьте при необходимости)"
fi

# OpenConnect (ocserv): клиенты выходят через tun-интерфейсы oc0, oc1, … Один oc0
# брать нельзя: tun создаётся по требованию и выпадает из lan_interfaces после
# `rescan` с отключённым клиентом (регрессия 2026-10-14: «часть сайтов висит,
# а status зелёный»). Поэтому — шаблон 'oc+' в КОНЕЦ списка.
oc_srv=0
[ -f /var/run/ocserv/ocserv.conf ] && oc_srv=1
command -v iptables >/dev/null 2>&1 && iptables -t mangle -S _NDM_OCSRVVPN_MARK >/dev/null 2>&1 && oc_srv=1
command -v ipset >/dev/null 2>&1 && ipset list -n _NDM_SRV_OCSRVVPN >/dev/null 2>&1 && oc_srv=1
if [ "$oc_srv" = 1 ]; then
    case ",$LAN," in
        *",oc+"*|*",oc0"*)
            say "OpenConnect: клиенты уже в lan_interfaces" ;;
        *)
            # OpenConnect есть не у всех: без явного --with-oc НЕ добавляем, даже
            # с --yes. Раньше --yes молча добавлял oc+ всем, у кого включён
            # ocserver, и это ломало чужие установки.
            add_oc=0
            if [ "$WITH_OC" -eq 1 ]; then
                add_oc=1
            elif [ "$YES" -eq 0 ] && [ -r /dev/tty ]; then
                printf "[susanin] OpenConnect server detected. Add its clients (oc+) to routing? [y/N, или флаг --with-oc]: " >&2
                read _oc < /dev/tty || _oc=n
                case "$_oc" in y|Y|yes|YES) add_oc=1 ;; esac
            else
                say "OpenConnect обнаружен, но не добавлен (нужен явный --with-oc)"
            fi
            if [ "$add_oc" -eq 1 ]; then
                oc_net=$(sed -n 's/^ipv4-network=//p' /var/run/ocserv/ocserv.conf 2>/dev/null | head -1)
                if [ -z "$oc_net" ]; then
                    for _i in $(ifaces); do
                        case "$_i" in
                            oc[0-9]*)
                                _oc_addr=$(addr_of "$_i")
                                [ -n "$_oc_addr" ] && oc_net=$(printf '%s' "$_oc_addr" | \
                                    awk -F'[./]' '{print $1"."$2"."$3".0/24"}')
                                break ;;
                        esac
                    done
                fi
                LAN="${LAN:+$LAN,}oc+"
                [ -n "$oc_net" ] && SUBNETS="${SUBNETS:+$SUBNETS,}$oc_net"
                say "OpenConnect added: iface=oc+ subnet=${oc_net:-n/a}"
            fi ;;
    esac
fi
say "lan=$LAN subnets=${SUBNETS:-n/a}"

if [ -z "$DISK_MODE" ]; then
    DISK_MODE=$(detect_disk_mode)
fi
case "$DISK_MODE" in
    normal) say "disk mode: normal (flash/USB)" ;;
    soft)   say "disk mode: soft (внутренняя память: логи/state/бэкапы отключены)" ;;
    *)      die "bad --disk-mode: $DISK_MODE (normal|soft)" ;;
esac

if [ "$YES" -ne 1 ] && [ -r /dev/tty ]; then
    printf "[susanin] Install to %s ?\n  egress:  %s\n  lan:     %s\n  subnets: %s\n  disk:    %s\nProceed? [y/N]: " \
        "$PREFIX" "$EGRESS" "$LAN" "${SUBNETS:-n/a}" "$DISK_MODE" >&2
    read _ok < /dev/tty || _ok=n
    case "$_ok" in y|Y|yes|YES) ;; *) die "aborted" ;; esac
fi

mkdir -p "$PREFIX/bin" "$PREFIX/tools" "$PREFIX/etc" "$PREFIX/etc/profiles" "$PREFIX/var" "$INITD"
cp "$DIR/$BINFILE" "$PREFIX/bin/susanin-agent"
for f in datapath.sh susanin.sh update.sh uninstall.sh install.sh report.sh diagnose.sh profiles.sh xray-egress.sh; do
    _src=$(find_file "$f") || _src=""
    [ -n "$_src" ] && cp "$_src" "$PREFIX/tools/$f"
done
chmod +x "$PREFIX/bin/susanin-agent" "$PREFIX/tools/"*.sh 2>/dev/null || true

# Объединить два списка через запятую без дублей (используется при --force,
# чтобы не затереть уже заданные интерфейсы/подсети).
merge_csv() {
    printf '%s,%s\n' "$1" "$2" | tr ',' '\n' | sed 's/^[ \t]*//; s/[ \t]*$//' | \
        grep -v '^$' | awk '!seen[$0]++' | awk 'NR==1{s=$0;next}{s=s","$0}END{print s}'
}

_cfg_val() { # значение ключа из уже установленного конфига
    sed -n "s/^$1=[ \t]*//p" "$PREFIX/etc/susanin.conf" 2>/dev/null | head -1
}

if [ ! -f "$PREFIX/etc/susanin.conf" ]; then
    _cfg=$(find_file config.example.conf) || _cfg=""
    [ -n "$_cfg" ] && cp "$_cfg" "$PREFIX/etc/susanin.conf"
    say "config created: $PREFIX/etc/susanin.conf"
fi
if [ ! -f "$PREFIX/etc/susanin.conf" ] || [ "$FORCE" = 1 ]; then
    if [ "$FORCE" = 1 ]; then
        # --force не затирает lan_*: объединяем автоопределённое с текущим.
        _old_lan=$(_cfg_val lan_interfaces)
        _old_sub=$(_cfg_val lan_subnets)
        [ -n "$_old_lan" ] && LAN=$(merge_csv "$_old_lan" "$LAN")
        [ -n "$_old_sub" ] && SUBNETS=$(merge_csv "$_old_sub" "$SUBNETS")
    fi
    sed -i "s|^egress_interface=.*|egress_interface=$EGRESS|" "$PREFIX/etc/susanin.conf" 2>/dev/null || true
    sed -i "s|^lan_interfaces=.*|lan_interfaces=$LAN|" "$PREFIX/etc/susanin.conf" 2>/dev/null || true
    sed -i "s|^lan_subnets=.*|lan_subnets=$SUBNETS|" "$PREFIX/etc/susanin.conf" 2>/dev/null || true
    EA=$(addr_of "$EGRESS")
    [ -n "$EA" ] && sed -i "s|^egress_address=.*|egress_address=${EA%%/*}|" "$PREFIX/etc/susanin.conf" 2>/dev/null || true
    say "config written: $PREFIX/etc/susanin.conf"
else
    say "config kept: $PREFIX/etc/susanin.conf"
fi

# disk_mode применяем всегда (в т.ч. когда конфиг уже существовал).
if [ -f "$PREFIX/etc/susanin.conf" ]; then
    if grep -q '^disk_mode=' "$PREFIX/etc/susanin.conf" 2>/dev/null; then
        sed -i "s|^disk_mode=.*|disk_mode=$DISK_MODE|" "$PREFIX/etc/susanin.conf" 2>/dev/null || true
    else
        echo "disk_mode=$DISK_MODE" >> "$PREFIX/etc/susanin.conf"
    fi
    say "disk_mode=$DISK_MODE -> $PREFIX/etc/susanin.conf"
fi

# --- P5: сторонний прокси на роутере (Teleproxy/MTProxy) --------------------
# Настройка включается флагами --proxy-uid/--proxy-egress. Перед созданием
# пользователя проверяем, что ядро умеет матч по uid (xt_owner): иначе правило
# молча не встанет и трафик прокси уйдёт мимо туннеля.
proxy_set_key() { # proxy_set_key <key> <value>
    if grep -q "^$1=" "$PREFIX/etc/susanin.conf" 2>/dev/null; then
        sed -i "s|^$1=.*|$1=$2|" "$PREFIX/etc/susanin.conf" 2>/dev/null || true
    else
        echo "$1=$2" >> "$PREFIX/etc/susanin.conf"
    fi
}

if [ -n "$PROXY_UID" ]; then
    say "proxy_uid=$PROXY_UID: проверяю поддержку матча по uid"
    if ! command -v iptables >/dev/null 2>&1; then
        die "нет iptables — proxy_uid не настроить"
    fi
    # -C возвращает 0 (правило есть) или 1 (правила нет) — оба означают, что
    # модуль xt_owner доступен. 2 и выше — ошибка разбора/отсутствие модуля.
    iptables -w -t mangle -C OUTPUT -m owner --uid-owner 0 -j RETURN >/dev/null 2>&1
    _rc=$?
    if [ "$_rc" -gt 1 ]; then
        say "ВНИМАНИЕ: ядро не поддерживает -m owner (xt_owner) — метка по uid не встанет"
        say "          проверьте: iptables -t mangle -C OUTPUT -m owner --uid-owner 0 -j RETURN"
    else
        say "xt_owner: OK"
    fi

    if [ -z "$PROXY_EGRESS" ]; then
        PROXY_EGRESS=nwg0
        say "proxy_egress не задан — беру по умолчанию $PROXY_EGRESS"
    fi
    if command -v ip >/dev/null 2>&1 && ! ip link show "$PROXY_EGRESS" >/dev/null 2>&1; then
        say "ВНИМАНИЕ: интерфейса $PROXY_EGRESS сейчас нет (туннель выключен?)"
        say "          метка и ip rule будут созданы, маршрут появится при поднятии туннеля"
    fi

    if id -u "$PROXY_UID" >/dev/null 2>&1; then
        say "пользователь $PROXY_UID уже есть"
    else
        say "создаю пользователя $PROXY_UID"
        adduser -S -D -H -s /sbin/nologin "$PROXY_UID" >/dev/null 2>&1 || \
            useradd -r -s /sbin/nologin "$PROXY_UID" >/dev/null 2>&1 || true
        if id -u "$PROXY_UID" >/dev/null 2>&1; then
            say "пользователь создан: uid=$(id -u "$PROXY_UID")"
        else
            say "ВНИМАНИЕ: создать пользователя не удалось — создайте вручную и повторите"
        fi
    fi

    proxy_set_key proxy_uid "$PROXY_UID"
    proxy_set_key proxy_egress "$PROXY_EGRESS"
    grep -q '^proxy_table=' "$PREFIX/etc/susanin.conf" 2>/dev/null || \
        echo "proxy_table=110" >> "$PREFIX/etc/susanin.conf"
    grep -q '^proxy_mark=' "$PREFIX/etc/susanin.conf" 2>/dev/null || \
        echo "proxy_mark=0x01000000" >> "$PREFIX/etc/susanin.conf"
    say "P5 включён: uid=$PROXY_UID -> $PROXY_EGRESS (table=110, mark=0x01000000)"
    say "не забудьте: прокси должен запускаться от этого пользователя (user=$PROXY_UID)"
fi
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

# vpn_always/vpn_never: --keep-lists не трогает существующие файлы вовсе.
if [ "$KEEP_LISTS" = "1" ]; then
    say "--keep-lists: списки vpn_always/vpn_never не трогаем"
fi
_va=$(find_file vpn_always.txt) || _va=""
if [ ! -f "$PREFIX/etc/vpn_always.txt" ] && [ -n "$_va" ]; then
    cp "$_va" "$PREFIX/etc/vpn_always.txt"
    say "vpn_always list installed: $PREFIX/etc/vpn_always.txt"
else
    say "vpn_always list kept (not overwritten; may be merged with new entries)"
    if [ -n "$_va" ] && [ "$KEEP_LISTS" != "1" ]; then
        merge_list "$PREFIX/etc/vpn_always.txt" "$_va" "vpn_always"
    fi
fi
_vn=$(find_file vpn_never.txt) || _vn=""
if [ ! -f "$PREFIX/etc/vpn_never.txt" ] && [ -n "$_vn" ]; then
    cp "$_vn" "$PREFIX/etc/vpn_never.txt"
    say "vpn_never list installed: $PREFIX/etc/vpn_never.txt"
else
    say "vpn_never list kept (not overwritten; may be merged with new entries)"
    if [ -n "$_vn" ] && [ "$KEEP_LISTS" != "1" ]; then
        merge_list "$PREFIX/etc/vpn_never.txt" "$_vn" "vpn_never"
    fi
fi
# Одноразовая уборка накопленных бэкапов списков старого формата
# (<список>.bak-ГГГГММДД-ЧЧММСС): правки через панель плодили десятки копий.
# Теперь бэкап один — <список>.bak (перезаписывается).
rm -f "$PREFIX/etc/vpn_always.txt".bak-[0-9]* \
      "$PREFIX/etc/vpn_never.txt".bak-[0-9]* 2>/dev/null || true
_cdn=$(find_file cdn_ranges.txt) || _cdn=""
if [ ! -f "$PREFIX/etc/cdn_ranges.txt" ] && [ -n "$_cdn" ]; then
    cp "$_cdn" "$PREFIX/etc/cdn_ranges.txt"
    say "CDN ranges installed: $PREFIX/etc/cdn_ranges.txt"
else
    say "CDN ranges kept (not overwritten; auto-updates from cdn_ranges_url)"
fi

# Дописать отсутствующие дефолтные ключи: старый susanin.conf мог их не
# содержать, и тогда `sed 's|^key=.*|...|'` молча ничего не делал (web_*,
# egress_type, tproxy_port и т.п.). Ничего не перезаписываем — только добавляем.
ensure_key() { # ensure_key <file> <key> <default>
    _f="$1"; _k="$2"; _d="$3"
    [ -f "$_f" ] || return 0
    grep -q "^${_k}=" "$_f" 2>/dev/null || printf '%s=%s\n' "$_k" "$_d" >> "$_f"
}
if [ -f "$PREFIX/etc/susanin.conf" ]; then
    ensure_key "$PREFIX/etc/susanin.conf" web_enable 0
    ensure_key "$PREFIX/etc/susanin.conf" web_listen ""
    ensure_key "$PREFIX/etc/susanin.conf" web_port 8087
    ensure_key "$PREFIX/etc/susanin.conf" web_token ""
    ensure_key "$PREFIX/etc/susanin.conf" egress_type interface
    ensure_key "$PREFIX/etc/susanin.conf" tproxy_port 12345
    ensure_key "$PREFIX/etc/susanin.conf" discover_exclude "wdtt0,wdttraw0,tun0,tap0"
    ensure_key "$PREFIX/etc/susanin.conf" fast_syn_min_op 2
    ensure_key "$PREFIX/etc/susanin.conf" ok_max_entries 4096
    ensure_key "$PREFIX/etc/susanin.conf" ok_evict_misses 3
    ensure_key "$PREFIX/etc/susanin.conf" promo_per_min 120
    ensure_key "$PREFIX/etc/susanin.conf" soft_state_interval 12
    ensure_key "$PREFIX/etc/susanin.conf" learn_exclude_ports "22,23,53,135,137,138,139,445,500,554,853,1433,1723,3306,3389,4500,5432,5900,6379,7547,8567,9100,11211,27017"
    ensure_key "$PREFIX/etc/susanin.conf" vpn_always_file /opt/susanin/etc/vpn_always.txt
    ensure_key "$PREFIX/etc/susanin.conf" vpn_always_dns ""
    ensure_key "$PREFIX/etc/susanin.conf" vpn_always_interval 300
    ensure_key "$PREFIX/etc/susanin.conf" vpn_never_file /opt/susanin/etc/vpn_never.txt
    ensure_key "$PREFIX/etc/susanin.conf" vpn_never_interval 300
    ensure_key "$PREFIX/etc/susanin.conf" lan_server_interfaces ""
    ensure_key "$PREFIX/etc/susanin.conf" dp_check_interval 15
    ensure_key "$PREFIX/etc/susanin.conf" learn_min_op 10
    ensure_key "$PREFIX/etc/susanin.conf" learn_min_bytes 2000
    ensure_key "$PREFIX/etc/susanin.conf" confirm_min_bytes 512
    ensure_key "$PREFIX/etc/susanin.conf" learn_strict 0
    # Пресет порогов (strict|normal|aggressive); пусто = выключен.
    ensure_key "$PREFIX/etc/susanin.conf" precision ""
    ensure_key "$PREFIX/etc/susanin.conf" cdn_ranges_file /opt/susanin/etc/cdn_ranges.txt
    ensure_key "$PREFIX/etc/susanin.conf" cdn_ranges_url https://www.cloudflare.com/ips-v4
    ensure_key "$PREFIX/etc/susanin.conf" cdn_ranges_interval 86400
    ensure_key "$PREFIX/etc/susanin.conf" cdn_prefix_learn 1
    ensure_key "$PREFIX/etc/susanin.conf" cdn_prefix_ttl 3600
    ensure_key "$PREFIX/etc/susanin.conf" cdn_prefix_max 24
    ensure_key "$PREFIX/etc/susanin.conf" aggregate_confirm 2
    ensure_key "$PREFIX/etc/susanin.conf" ipv6_block 1
    ensure_key "$PREFIX/etc/susanin.conf" quic_block 1
    ensure_key "$PREFIX/etc/susanin.conf" health_mode icmp
    ensure_key "$PREFIX/etc/susanin.conf" health_tcp_port 443
    # Остальные ключи, которые есть в веб-панели — чтобы поля не показывались
    # как «нет в файле». Существующие значения НЕ меняются (ensure_key только
    # дописывает отсутствующую строку).
    ensure_key "$PREFIX/etc/susanin.conf" egress_interface nwg0
    ensure_key "$PREFIX/etc/susanin.conf" egress_address 10.8.1.1
    ensure_key "$PREFIX/etc/susanin.conf" lan_interfaces br0
    ensure_key "$PREFIX/etc/susanin.conf" lan_subnets ""
    ensure_key "$PREFIX/etc/susanin.conf" routing_table 100
    ensure_key "$PREFIX/etc/susanin.conf" mark_test 0x10000000
    ensure_key "$PREFIX/etc/susanin.conf" mark_ok 0x20000000
    ensure_key "$PREFIX/etc/susanin.conf" mark_mask 0x30000000
    ensure_key "$PREFIX/etc/susanin.conf" ip_rule_priority_start 2000
    ensure_key "$PREFIX/etc/susanin.conf" fast_interval 1
    ensure_key "$PREFIX/etc/susanin.conf" soft_interval 1
    ensure_key "$PREFIX/etc/susanin.conf" judge_interval 1
    ensure_key "$PREFIX/etc/susanin.conf" health_interval 5
    ensure_key "$PREFIX/etc/susanin.conf" ok_ttl 21600
    ensure_key "$PREFIX/etc/susanin.conf" ok_refresh_below 3
    ensure_key "$PREFIX/etc/susanin.conf" test_ttl 1
    ensure_key "$PREFIX/etc/susanin.conf" cooldown_ttl 5
    ensure_key "$PREFIX/etc/susanin.conf" cooldown_ok_ttl 30
    ensure_key "$PREFIX/etc/susanin.conf" watch_ttl 8
    ensure_key "$PREFIX/etc/susanin.conf" watch_retry_below 4
    ensure_key "$PREFIX/etc/susanin.conf" health_probe "1.1.1.1,8.8.8.8"
    ensure_key "$PREFIX/etc/susanin.conf" udp_relay 0
    ensure_key "$PREFIX/etc/susanin.conf" udp_relay_port 1081
    ensure_key "$PREFIX/etc/susanin.conf" socks_addr 127.0.0.1
    ensure_key "$PREFIX/etc/susanin.conf" socks_port 1080
    ensure_key "$PREFIX/etc/susanin.conf" log_level info
    ensure_key "$PREFIX/etc/susanin.conf" xray_loglevel warning
    # 0.4.0-dev5: failback/watchdog/offload/dns-sniff/pin_reassert.
    ensure_key "$PREFIX/etc/susanin.conf" egress_failback 1
    ensure_key "$PREFIX/etc/susanin.conf" egress_failback_debounce 30
    ensure_key "$PREFIX/etc/susanin.conf" egress_race 0
    ensure_key "$PREFIX/etc/susanin.conf" xray_gogc 50
    ensure_key "$PREFIX/etc/susanin.conf" xray_gomemlimit 64MiB
    ensure_key "$PREFIX/etc/susanin.conf" xray_watchdog 1
    ensure_key "$PREFIX/etc/susanin.conf" kernel_offload 0
    ensure_key "$PREFIX/etc/susanin.conf" kernel_egress ""
    ensure_key "$PREFIX/etc/susanin.conf" kernel_offload_max 24
    ensure_key "$PREFIX/etc/susanin.conf" dns_sniff 0
    ensure_key "$PREFIX/etc/susanin.conf" dns_sniff_ttl 300
    ensure_key "$PREFIX/etc/susanin.conf" dns_sniff_iface ""
    ensure_key "$PREFIX/etc/susanin.conf" dns_hijack 0
    ensure_key "$PREFIX/etc/susanin.conf" dns_hijack_target ""
    ensure_key "$PREFIX/etc/susanin.conf" vpn_always_cdn_prefix 0
    ensure_key "$PREFIX/etc/susanin.conf" pin_reassert 1
    ensure_key "$PREFIX/etc/susanin.conf" auto_direct 1
    ensure_key "$PREFIX/etc/susanin.conf" direct_pref_ttl 3600
    ensure_key "$PREFIX/etc/susanin.conf" media_enabled 0
    ensure_key "$PREFIX/etc/susanin.conf" media_ports "80,443,554,1935,8080,8443"
    ensure_key "$PREFIX/etc/susanin.conf" media_min_bytes 1048576
    ensure_key "$PREFIX/etc/susanin.conf" media_ratio 8
    ensure_key "$PREFIX/etc/susanin.conf" media_min_rate 150000
    ensure_key "$PREFIX/etc/susanin.conf" media_min_age 12
    ensure_key "$PREFIX/etc/susanin.conf" media_ttl 21600
    ensure_key "$PREFIX/etc/susanin.conf" media_prefix_max 24
    ensure_key "$PREFIX/etc/susanin.conf" mss_clamp 0
    ensure_key "$PREFIX/etc/susanin.conf" mss_clamp_lan 0
    ensure_key "$PREFIX/etc/susanin.conf" profile_failover 1
fi

# --- миграция значений по умолчанию (0.4.0) ----------------------------------
# promo_per_min: дефолт поднят 30 -> 120 (обучение быстрее). Меняем только если
# в конфиге стоит прежний дефолт — своё значение пользователя не трогаем.
if [ -f "$PREFIX/etc/susanin.conf" ]; then
    _pp=$(sed -n 's/^promo_per_min=//p' "$PREFIX/etc/susanin.conf" 2>/dev/null | tail -n1)
    if [ "$_pp" = "30" ]; then
        sed -i 's/^promo_per_min=.*/promo_per_min=120/' "$PREFIX/etc/susanin.conf" 2>/dev/null \
            && say "promo_per_min: 30 -> 120 (новый дефолт)"
    fi
fi

# Каталоги профилей маршрутизации: profiles (списки) и profiles.d (секции).
mkdir -p "$PREFIX/etc/profiles" "$PREFIX/etc/profiles.d" 2>/dev/null || true

_s94=$(find_file S94susanin) || _s94=""
if [ -n "$_s94" ]; then
    cp "$_s94" "$INITD/S94susanin"
    chmod +x "$INITD/S94susanin"
fi
_s93=$(find_file S93xray-tproxy) || _s93=""
if [ -n "$_s93" ]; then
    cp "$_s93" "$INITD/S93xray-tproxy"
    chmod +x "$INITD/S93xray-tproxy"
fi

# Веб-панель: статика и (при наличии в пакете) init-сервис.
mkdir -p "$PREFIX/www"
if [ -d "$DIR/www" ]; then
    cp -r "$DIR/www/." "$PREFIX/www/" 2>/dev/null || true
    say "web assets installed: $PREFIX/www"
fi
# Документация — в /opt/susanin/docs (в поставке лежит в docs/), чтобы её было
# где найти на устройстве: TESTBUILD, TROUBLESHOOTING, USER_GUIDE, DEPLOY, XRAY.
if [ -d "$DIR/docs" ]; then
    mkdir -p "$PREFIX/docs"
    cp -r "$DIR/docs/." "$PREFIX/docs/" 2>/dev/null || true
    say "docs installed: $PREFIX/docs (TESTBUILD, TROUBLESHOOTING, USER_GUIDE)"
fi

_s95=$(find_file S95susanin-web) || _s95=""
if [ -n "$_s95" ]; then
    cp "$_s95" "$INITD/S95susanin-web"
    chmod +x "$INITD/S95susanin-web"
fi

# Сторож единственности Xray (0.4.6): страховка от накопления процессов
# `xray run`, когда watchdog поднимает второй экземпляр на медленном старте.
_s95g=$(find_file S95xray-guard) || _s95g=""
if [ -n "$_s95g" ]; then
    cp "$_s95g" "$INITD/S95xray-guard"
    chmod +x "$INITD/S95xray-guard"
fi

# Короткий вызов: `susanin status` вместо длинного пути. /opt/bin есть в PATH у
# Entware; если имя уже занято (не нашим симлинком) — не трогаем.
if [ -d /opt/bin ]; then
    chmod +x "$PREFIX/tools/susanin.sh" 2>/dev/null || true
    if [ -L /opt/bin/susanin ]; then
        say "короткий вызов уже настроен: /opt/bin/susanin -> $(readlink /opt/bin/susanin 2>/dev/null)"
    elif [ -e /opt/bin/susanin ]; then
        say "/opt/bin/susanin занят другим файлом — симлинк не создаю"
    elif ln -s "$PREFIX/tools/susanin.sh" /opt/bin/susanin 2>/dev/null; then
        say "короткий вызов: susanin {status|check|diagnose|report|restart|...}"
    else
        say "симлинк /opt/bin/susanin создать не удалось (не критично)"
    fi
fi

# Если оставшийся/выбранный конфиг в tproxy-режиме — поднять Xray ДО старта
# агента, иначе агент не станет поднимать tproxy-правила (fail-open -> DIRECT).
if grep -q '^egress_type=tproxy' "$PREFIX/etc/susanin.conf" 2>/dev/null; then
    if [ -x /opt/sbin/xray ] && [ -f "$PREFIX/etc/xray-tproxy.json" ]; then
        # restart (не start): чтобы применился свежий уровень логов Xray и конфиг,
        # даже если Xray уже был запущен с прошлых тестов.
        [ -x "$INITD/S93xray-tproxy" ] && sh "$INITD/S93xray-tproxy" restart >/dev/null 2>&1 || true
        say "tproxy: Xray поднят перед стартом агента"
    else
        say "ВНИМАНИЕ: egress_type=tproxy, но нет /opt/sbin/xray или $PREFIX/etc/xray-tproxy.json"
        say "         пока Xray не готов, агент оставит трафик в DIRECT (fail-open)"
    fi
fi

if [ "$NO_START" -ne 1 ]; then
    if ps 2>/dev/null | grep '[s]usanin-agent' >/dev/null 2>&1; then
        sh "$PREFIX/tools/susanin.sh" restart || true
    else
        sh "$PREFIX/tools/susanin.sh" start || true
    fi
    # web — ОТДЕЛЬНЫЙ процесс: `restart` демона его не трогает (чтобы /api/restart
    # не ронял панель). После подмены бинаря его нужно перезапустить принудительно,
    # иначе панель продолжит работать СТАРЫМ кодом из памяти.
    sh "$PREFIX/tools/susanin.sh" web restart || true
    # Сторож Xray — после агента и Xray, чтобы он сразу увидел один процесс.
    [ -x "$INITD/S95xray-guard" ] && sh "$INITD/S95xray-guard" start >/dev/null 2>&1 || true
fi
say "installed to $PREFIX (run: sh $PREFIX/tools/susanin.sh status)"

# XRay-egress (tproxy): скачать Xray (если нет), положить шаблон конфига и
# подсказать ключи. Одна и та же логика для tar-архива и .ipk.
xray_setup
