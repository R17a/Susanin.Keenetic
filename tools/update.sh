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

if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -qO "$2" "$1"; }
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

# Дописать отсутствующие дефолтные ключи (старый конфиг мог их не содержать).
# Новые ключи добавляются со значениями по умолчанию; существующие не трогаем.
if [ -f "$PREFIX/etc/susanin.conf" ]; then
    for kv in web_enable=0 web_listen= web_port=8087 web_token= \
              egress_type=interface tproxy_port=12345 \
              discover_exclude=wdtt0,wdttraw0,tun0,tap0 \
              fast_syn_min_op=2 ok_max_entries=4096 ok_evict_misses=3 promo_per_min=120 \
              soft_state_interval=12 \
              egress_interface=nwg0 egress_address=10.8.1.1 lan_interfaces=br0 lan_subnets= \
              routing_table=100 mark_test=0x10000000 mark_ok=0x20000000 mark_mask=0x30000000 \
              ip_rule_priority_start=2000 fast_interval=1 soft_interval=1 judge_interval=1 \
              health_interval=5 ok_ttl=21600 ok_refresh_below=3 test_ttl=1 cooldown_ttl=5 \
              cooldown_ok_ttl=30 watch_ttl=8 watch_retry_below=4 health_probe=1.1.1.1,8.8.8.8 \
              udp_relay=0 udp_relay_port=1081 socks_addr=127.0.0.1 socks_port=1080 \
              log_level=info xray_loglevel=warning \
              learn_exclude_ports=22,23,53,135,137,138,139,445,500,554,853,1433,1723,3306,3389,4500,5432,5900,6379,7547,8567,9100,11211,27017 \
              vpn_always_file=/opt/susanin/etc/vpn_always.txt vpn_always_dns= \
              vpn_always_interval=300 \
              vpn_never_file=/opt/susanin/etc/vpn_never.txt vpn_never_interval=300 \
              lan_server_interfaces= dp_check_interval=15 \
              learn_min_op=10 learn_min_bytes=2000 confirm_min_bytes=512 learn_strict=0 \
              precision= \
              cdn_ranges_file=/opt/susanin/etc/cdn_ranges.txt \
              cdn_ranges_url=https://www.cloudflare.com/ips-v4 \
              cdn_ranges_interval=86400 cdn_prefix_learn=1 cdn_prefix_ttl=3600 \
              cdn_prefix_max=24 aggregate_confirm=2 ipv6_block=1 \
              quic_block=1 \
              egress_failback=1 egress_failback_debounce=30 egress_race=0 \
              xray_gogc=50 xray_gomemlimit=64MiB xray_watchdog=1 \
              kernel_offload=0 kernel_egress= kernel_offload_max=24 \
              dns_sniff=0 dns_sniff_ttl=300 dns_sniff_iface= pin_reassert=1 \
              dns_hijack=0 dns_hijack_target= vpn_always_cdn_prefix=0 \
              mss_clamp=0 mss_clamp_lan=0 profile_failover=1 \
              auto_direct=1 direct_pref_ttl=3600 \
              media_enabled=0 media_ports=80,443,554,1935,8080,8443 media_min_bytes=1048576 \
              media_ratio=8 media_min_rate=150000 media_min_age=12 media_ttl=21600 media_prefix_max=24 \
              health_mode=icmp health_tcp_port=443; do
        k=${kv%%=*}; d=${kv#*=}
        grep -q "^${k}=" "$PREFIX/etc/susanin.conf" 2>/dev/null \
            || printf '%s=%s\n' "$k" "$d" >> "$PREFIX/etc/susanin.conf"
    done

    # Миграция значений по умолчанию (0.4.0): promo_per_min 30 -> 120.
    # Меняем только прежний дефолт; своё значение пользователя не трогаем.
    _pp=$(sed -n 's/^promo_per_min=//p' "$PREFIX/etc/susanin.conf" 2>/dev/null | tail -n1)
    if [ "$_pp" = "30" ]; then
        sed -i 's/^promo_per_min=.*/promo_per_min=120/' "$PREFIX/etc/susanin.conf" 2>/dev/null \
            && say "promo_per_min: 30 -> 120 (новый дефолт)"
    fi
fi

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
