#!/bin/sh
# Susanin.Keenetic installer.
# Online (default): downloads the per-arch archive from GitHub Releases.
#   curl -fsSL https://raw.githubusercontent.com/R17a/Susanin.Keenetic/main/install.sh \
#     | sh -s -- [--arch mipsel] [--version vX.Y.Z] [--yes]
# Offline/local: run from an extracted archive (susanin-agent is next to this script):
#   sh install.sh [--yes]
# Prompts accept short answers: "y" or "yes". Use --yes|-y to skip all prompts.
# POSIX sh (busybox ash compatible).
set -eu

REPO="R17a/Susanin.Keenetic"
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
DISK_MODE=""
DEPS=0
XRAYTUN=0

say() { echo "[susanin] $*"; }
die() { echo "[susanin] ERROR: $*" >&2; exit 1; }

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
        --with-xray-tproxy) XRAYTUN=1 ;;
        --yes|-y) YES=1 ;;
        --force) FORCE=1 ;;
        --no-start) NO_START=1 ;;
        -h|--help)
            echo "usage: $0 [--arch mipsel|mips|aarch64|armv7|x86_64] [--version latest|vX.Y.Z]"
            echo "          [--egress IF] [--lan IF,IF] [--subnets CIDR,CIDR] [--prefix DIR]"
            echo "          [--disk-mode normal|soft] [--deps] [--with-xray-tproxy]"
            echo "          [--yes] [--force] [--no-start]"
            echo
            echo "  --disk-mode  normal (USB/SD) | soft (internal flash; no logs/state/backups)."
            echo "               Default: autodetect by /opt mount."
            echo "  --deps       доустановить недостающие пакеты через opkg без вопроса"
            echo "  --with-xray-tproxy  проверить Xray и положить шаблон tproxy-конфига"
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
        say "opkg update && opkg install$need"
        opkg update || true
        opkg install $need || true
    else
        say "пропускаю. Установите вручную: opkg update && opkg install$need"
    fi
fi

if [ -z "$ARCH" ]; then
    _m=$(uname -m 2>/dev/null || echo unknown)
    case "$_m" in
        mips|mipsel) ARCH=mipsel ;;
        mips64) ARCH=mips64el ;;
        aarch64|arm64) ARCH=aarch64 ;;
        armv7l|armv7|armhf) ARCH=armv7 ;;
        x86_64|amd64) ARCH=x86_64 ;;
        *) die "cannot detect arch (uname -m=$_m); pass --arch" ;;
    esac
fi

DIR0=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -f "$DIR0/susanin-agent" ] || [ -f "$DIR0/bin/susanin-agent" ] \
   || [ -n "$(ls "$DIR0"/susanin-agent.* "$DIR0"/bin/susanin-agent.* 2>/dev/null)" ]; then
    DIR=$DIR0
    say "local package: $DIR"
else
    if command -v curl >/dev/null 2>&1; then
        fetch() { curl -fsSL "$1" -o "$2"; }
    elif command -v wget >/dev/null 2>&1; then
        fetch() { wget -qO "$2" "$1"; }
    else
        die "need curl or wget (Entware: opkg update && opkg install ca-certificates; optionally 'opkg install curl')"
    fi
    if [ "$VERSION" = latest ]; then
        BASE="https://github.com/$REPO/releases/latest/download"
    else
        BASE="https://github.com/$REPO/releases/download/$VERSION"
    fi
    ASSET="susanin-keenetic-deploy-$ARCH.tar.gz"
    say "arch=$ARCH version=$VERSION"
    TMP=$(mktemp -d /tmp/susanin-inst.XXXXXX)
    trap 'rm -rf "$TMP"' EXIT INT TERM
    say "downloading $BASE/$ASSET"
    fetch "$BASE/$ASSET" "$TMP/pkg.tar.gz" \
        || die "download failed (check --arch/--version or release assets): $BASE/$ASSET
     hint: opkg update && opkg install ca-certificates"
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
elif [ -f "$DIR/bin/susanin-agent" ]; then
    BINFILE=bin/susanin-agent
elif [ -f "$DIR/susanin-agent.$ARCH" ]; then
    # Один каталог может содержать бинари под несколько архитектур: берём свою.
    BINFILE="susanin-agent.$ARCH"
elif [ -f "$DIR/bin/susanin-agent.$ARCH" ]; then
    BINFILE="bin/susanin-agent.$ARCH"
else
    BINFILE=$(ls "$DIR"/susanin-agent.* "$DIR"/bin/susanin-agent.* 2>/dev/null | head -1)
fi
[ -n "${BINFILE:-}" ] && [ -f "$DIR/$BINFILE" ] || die "susanin-agent binary not found in $DIR"
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

# OpenConnect (ocserv) server, if present, can be routed through Susanin too.
oc_if=""
for i in $(ifaces); do
    case "$i" in oc[0-9]*) oc_if=$i ;; esac
done
if [ -z "$oc_if" ]; then
    dev=$(sed -n 's/^device=//p' /var/run/ocserv/ocserv.conf 2>/dev/null | head -1)
    if [ -n "$dev" ] && ifaces | grep -qx "${dev}0"; then
        oc_if="${dev}0"
    elif ps 2>/dev/null | grep -q '[o]cserv'; then
        [ -n "$dev" ] && oc_if="${dev}0" || oc_if=oc0
    fi
fi
if [ -n "$oc_if" ]; then
    case ",$LAN," in
        *",$oc_if,"*) : ;;
        *)
            add_oc=0
            if [ "$YES" -eq 1 ]; then
                add_oc=1
            elif [ -r /dev/tty ]; then
                printf "[susanin] OpenConnect server detected (%s). Add it to Susanin routing? [y/N]: " "$oc_if" >&2
                read _oc < /dev/tty || _oc=n
                case "$_oc" in y|Y|yes|YES) add_oc=1 ;; esac
            fi
            if [ "$add_oc" -eq 1 ]; then
                oc_addr=$(sed -n 's/^ipv4-network=//p' /var/run/ocserv/ocserv.conf 2>/dev/null | head -1)
                [ -n "$oc_addr" ] || oc_addr=$(addr_of "$oc_if")
                oc_net=$(printf '%s' "$oc_addr" | awk -F'[./]' '{print $1"."$2"."$3".0/24"}')
                LAN="${LAN:+$LAN,}$oc_if"
                SUBNETS="${SUBNETS:+$SUBNETS,}$oc_net"
                say "OpenConnect added: iface=$oc_if subnet=$oc_net"
            fi
            ;;
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

if [ ! -f "$PREFIX/etc/susanin.conf" ] || [ "$FORCE" = 1 ]; then
    _cfg=$(find_file config.example.conf) || _cfg=""
    [ -n "$_cfg" ] && cp "$_cfg" "$PREFIX/etc/susanin.conf"
    sed -i "s|^egress_interface=.*|egress_interface=$EGRESS|" "$PREFIX/etc/susanin.conf" 2>/dev/null || true
    sed -i "s|^lan_interfaces=.*|lan_interfaces=$LAN|" "$PREFIX/etc/susanin.conf" 2>/dev/null || true
    [ -n "$SUBNETS" ] && sed -i "s|^lan_subnets=.*|lan_subnets=$SUBNETS|" "$PREFIX/etc/susanin.conf" 2>/dev/null || true
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

_va=$(find_file vpn_always.txt) || _va=""
if [ ! -f "$PREFIX/etc/vpn_always.txt" ] && [ -n "$_va" ]; then
    cp "$_va" "$PREFIX/etc/vpn_always.txt"
    say "vpn_always list installed: $PREFIX/etc/vpn_always.txt"
else
    say "vpn_always list kept (not overwritten)"
fi
_vn=$(find_file vpn_never.txt) || _vn=""
if [ ! -f "$PREFIX/etc/vpn_never.txt" ] && [ -n "$_vn" ]; then
    cp "$_vn" "$PREFIX/etc/vpn_never.txt"
    say "vpn_never list installed: $PREFIX/etc/vpn_never.txt"
else
    say "vpn_never list kept (not overwritten)"
    if [ -n "$_vn" ]; then
        merge_list "$PREFIX/etc/vpn_never.txt" "$_vn" "vpn_never"
    fi
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
    ensure_key "$PREFIX/etc/susanin.conf" health_mode icmp
    ensure_key "$PREFIX/etc/susanin.conf" health_tcp_port 443
fi

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
_s95=$(find_file S95susanin-web) || _s95=""
if [ -n "$_s95" ]; then
    cp "$_s95" "$INITD/S95susanin-web"
    chmod +x "$INITD/S95susanin-web"
fi

# Если оставшийся/выбранный конфиг в tproxy-режиме — поднять Xray ДО старта
# агента, иначе агент не станет поднимать tproxy-правила (fail-open -> DIRECT).
if grep -q '^egress_type=tproxy' "$PREFIX/etc/susanin.conf" 2>/dev/null; then
    if [ -x /opt/sbin/xray ] && [ -f "$PREFIX/etc/xray-tproxy.json" ]; then
        [ -x "$INITD/S93xray-tproxy" ] && sh "$INITD/S93xray-tproxy" start >/dev/null 2>&1 || true
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
fi
say "installed to $PREFIX (run: sh $PREFIX/tools/susanin.sh status)"

# XRay-egress (tproxy): проверяет Xray и кладёт шаблон tproxy-конфига.
if [ "$XRAYTUN" -eq 1 ]; then
    say "XRay-egress (tproxy): проверяю инструменты ..."
    if [ -x /opt/sbin/xray ]; then
        say "xray: есть (/opt/sbin/xray)"
    else
        say "xray: НЕТ — положите рабочий бинарь Xray (напр. 1.8.24 softfloat) в /opt/sbin/xray и chmod +x"
    fi
    _xtp=$(find_file xray-tproxy.json.example) || _xtp=""
    if [ -n "$_xtp" ]; then
        cp "$_xtp" "$PREFIX/etc/xray-tproxy.json.example"
    fi
    # Бинарь Xray из комплекта (xray/xray.<arch>), если ещё не установлен.
    XB="$DIR/xray/xray.$ARCH"
    if [ -x "$XB" ] && [ ! -x /opt/sbin/xray ]; then
        cp "$XB" /opt/sbin/xray && chmod +x /opt/sbin/xray \
            && say "xray установлен из комплекта: /opt/sbin/xray"
    elif [ -x "$XB" ]; then
        say "xray уже есть (/opt/sbin/xray) — из комплекта не ставлю"
    fi
    say "шаблон: $PREFIX/etc/xray-tproxy.json.example (подставьте SERVER/UUID/SNI/PBK/SID)"
    say "в susanin.conf: egress_type=tproxy, tproxy_port=12345"
fi
