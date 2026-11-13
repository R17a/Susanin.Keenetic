#!/bin/sh
# profiles.sh — статические профили маршрутизации (P1, экспериментально).
#
# Профиль = список (домены / IP / CIDR) -> свой egress-туннель.
# Задаётся в /opt/susanin/etc/susanin.conf повторяющимися ключами:
#   profile1_name=cdn
#   profile1_egress=nwg1
#   profile1_egress=nwg0,nwg1   # можно списком — берётся первый живой
#   profile1_list=/opt/susanin/etc/profiles/cdn.txt
#   profile1_geo_url=https://... # P3: скачиваемый CIDR-список (кэш в var/profiles/)
#   profile1_table=201          # опционально (по умолчанию 201..204)
#   profile1_mark=0x40000000    # опционально
# ... до profile4_*.
#
# Профили — отдельный слой поверх Susanin.Keenetic: своя цепочка SUSANIN_PROFILES в
# mangle PREROUTING (в конце, после SUSANIN), свои метки (0x40000000 и т.п.) и
# таблицы (201..204). Если профилей нет — ничего не делает.
#
# Usage: profiles.sh {up|down|status|refresh}
#   refresh — перечитать файлы-списки и geo_url, не пересобирая правила.
set -u

CONF="${SUSANIN_CONF:-/opt/susanin/etc/susanin.conf}"
VARDIR="${SUSANIN_VAR:-/opt/susanin/var}"
SETPFX="susanin_prof_"
CHAIN="SUSANIN_PROFILES"
MAXP=4

cfg() { sed -n "s/^$1=[ \t]*//p" "$CONF" 2>/dev/null | head -n1; }
have() { command -v "$1" >/dev/null 2>&1; }

# P2: профили можно задавать и файлами profiles.d/<name>.conf (один профиль на
# файл). Собираем «слитый» конфиг profileN_* (susanin.conf + profiles.d), чтобы
# дальше работать единообразно. Ключи файла: name, egress, list, geo_url, table,
# mark, auto.
MERGED="${TMPDIR:-/tmp}/susanin-profiles.$$.conf"
CONF_ORIG="$CONF"
build_merged() {
    : > "$MERGED"
    grep -E '^profile[0-9]+_' "$CONF_ORIG" 2>/dev/null >> "$MERGED" || true
    PD_DIR="${SUSANIN_PROFILES_DIR:-/opt/susanin/etc/profiles.d}"
    if [ -d "$PD_DIR" ]; then
        _n=$(grep -cE '^profile[0-9]+_name=' "$MERGED" 2>/dev/null || true)
        case "$_n" in ''|*[!0-9]*) _n=0;; esac
        for _f in "$PD_DIR"/*.conf; do
            [ -f "$_f" ] || continue
            _n=$((_n + 1))
            [ "$_n" -gt "$MAXP" ] && break
            _nm=$(sed -n 's/^name=[ \t]*//p' "$_f" 2>/dev/null | head -n1)
            [ -n "$_nm" ] || _nm=$(basename "$_f" .conf)
            printf 'profile%d_name=%s\n' "$_n" "$_nm" >> "$MERGED"
            for _k in egress list geo_url table mark auto; do
                _v=$(sed -n "s/^${_k}=[ \t]*//p" "$_f" 2>/dev/null | head -n1)
                [ -n "$_v" ] && printf 'profile%d_%s=%s\n' "$_n" "$_k" "$_v" >> "$MERGED"
            done
        done
    fi
}
build_merged
CONF="$MERGED"
trap 'rm -f "$MERGED"' EXIT INT TERM

have() { command -v "$1" >/dev/null 2>&1; }
IPSET=$(have ipset && echo ipset || echo /opt/sbin/ipset)
IPT=$(have iptables && echo iptables || echo /opt/sbin/iptables)
IPB=$(have ip && echo ip || echo /opt/sbin/ip)

san() { printf '%s' "$1" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9_'; }
is_ip4()  { printf '%s' "$1" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; }
is_cidr() { printf '%s' "$1" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$'; }

# Наши биты метки основной схемы (susanin.conf mark_mask) и её цепочка: профиль
# должен стоять ВЫШЕ неё, иначе адрес, который основная схема уже выучила или
# держит в vpn_always, профиль не заберёт никогда.
MARK_MASK=$(cfg mark_mask); [ -n "$MARK_MASK" ] || MARK_MASK=0x30000000
MAIN_CHAIN=SUSANIN

# Дефолтные метки профилей — РАЗНЫЕ по индексу, как обещает README
# (0x40000000, 0x08000000, 0x04000000, 0x02000000). Раньше всем профилям
# ставилась одна и та же метка, и при 2+ профилях правила дрались за неё.
default_mark() {
    case "$1" in
        1) printf '0x40000000' ;;
        2) printf '0x08000000' ;;
        3) printf '0x04000000' ;;
        4) printf '0x02000000' ;;
        *) printf '0x40000000' ;;
    esac
}

prof_mark() { # <index> -> метка профиля (конфиг или дефолт по индексу)
    _pm=$(cfg "profile$1_mark")
    [ -n "$_pm" ] || _pm=$(default_mark "$1")
    printf '%s' "$_pm"
}

# RETURN для адресов профиля в основной цепочке: иначе SUSANIN метит их раньше
# (и с маской 0x30000000, куда бит профиля не входит) и профиль не срабатывает.
del_prof_return() { # <set>
    while "$IPT" -t mangle -D "$MAIN_CHAIN" -m set --match-set "$1" dst -j RETURN 2>/dev/null; do :; done
}
add_prof_return() { # <set>
    "$IPT" -t mangle -S "$MAIN_CHAIN" >/dev/null 2>&1 || return 0
    del_prof_return "$1"
    "$IPT" -t mangle -I "$MAIN_CHAIN" -m set --match-set "$1" dst -j RETURN 2>/dev/null || true
}

resolv() { # domain -> IPv4
    nslookup "$1" 2>/dev/null | awk '
        /^Name:/ { f = 1; next }
        f && /^Address/ {
            for (i = 1; i <= NF; i++)
                if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { print $i; break }
        }'
}

prof_name() { cfg "profile$1_name"; }

# Сколько адресов реально в наборе профиля (не «сколько строк в файле»).
set_count() { "$IPSET" list "$1" 2>/dev/null | grep -cE '^[0-9]+\.'; }

fill_set() { # set listfile
    _s="$1"; _f="$2"
    [ -n "$_f" ] && [ -f "$_f" ] || return 0
    # `|| [ -n "$_raw" ]` — иначе ПОСЛЕДНЯЯ строка файла без перевода строки в
    # конце теряется: read при EOF без разделителя возвращает не-ноль (значение
    # при этом уже присвоено) и тело цикла не выполняется. С одним доменом в
    # файле это давало пустой набор и молча неработающий профиль.
    while IFS= read -r _raw || [ -n "$_raw" ]; do
        _e=$(printf '%s' "$_raw" | sed 's/#.*//' | tr -d ' \t\r')
        [ -z "$_e" ] && continue
        if is_ip4 "$_e" || is_cidr "$_e"; then
            "$IPSET" add "$_s" "$_e" -exist 2>/dev/null || true
        else
            _d=$(printf '%s' "$_e" | sed 's/^\*\.//')
            for _ip in $(resolv "$_d"); do
                "$IPSET" add "$_s" "$_ip" -exist 2>/dev/null || true
            done
        fi
    done < "$_f"
}

# P3: гео-базы — скачиваемый CIDR-список профиля (profileN_geo_url). Кэш
# хранится в var/profiles/<имя>.txt; при отсутствии сети используем прошлый кэш.
fetch_url() { # url outfile
    _u="$1"; _o="$2"
    [ -n "$_u" ] || return 1
    mkdir -p "$(dirname "$_o")" 2>/dev/null || true
    if command -v wget >/dev/null 2>&1; then
        wget -q -O "$_o.tmp" "$_u" 2>/dev/null && mv -f "$_o.tmp" "$_o" && return 0
    elif command -v curl >/dev/null 2>&1; then
        curl -fsS -o "$_o.tmp" "$_u" 2>/dev/null && mv -f "$_o.tmp" "$_o" && return 0
    fi
    rm -f "$_o.tmp" 2>/dev/null || true
    return 1
}

fill_geo() { # set url cachefile
    _s="$1"; _u="$2"; _o="$3"
    [ -n "$_u" ] || return 0
    if fetch_url "$_u" "$_o"; then
        fill_set "$_s" "$_o"
        echo "[profiles] geo: ${_u##*/} -> $_o"
    elif [ -f "$_o" ]; then
        fill_set "$_s" "$_o"
        echo "[profiles] geo: offline, использую кэш $_o"
    else
        echo "[profiles] geo: не скачать $_u и нет кэша"
    fi
}

count_profiles() {
    _n=0; _i=1
    while [ "$_i" -le "$MAXP" ]; do
        [ -n "$(prof_name "$_i")" ] && _n=$((_n + 1))
        _i=$((_i + 1))
    done
    echo "$_n"
}

up() {
    _n=$(count_profiles)
    if [ "$_n" -eq 0 ]; then
        echo "[profiles] профили не заданы"
        down >/dev/null 2>&1 || true
        return 0
    fi
    "$IPT" -t mangle -N "$CHAIN" 2>/dev/null || true
    "$IPT" -t mangle -F "$CHAIN" 2>/dev/null || true

    _i=1
    while [ "$_i" -le "$MAXP" ]; do
        _nm=$(prof_name "$_i")
        if [ -z "$_nm" ]; then _i=$((_i + 1)); continue; fi
        _egs=$(cfg "profile${_i}_egress")
        _eg=""
        for _e in $(printf '%s' "$_egs" | tr ',' ' '); do
            [ -e "/sys/class/net/$_e" ] && { _eg="$_e"; break; }
        done
        [ -n "$_eg" ] || _eg=$(printf '%s' "$_egs" | cut -d, -f1)
        _lf=$(cfg "profile${_i}_list")
        _tb=$(cfg "profile${_i}_table"); [ -n "$_tb" ] || _tb=$((200 + _i))
        _mk=$(prof_mark "$_i")
        _sn="$SETPFX$(san "$_nm")"

        "$IPSET" create "$_sn" hash:net timeout 0 -exist 2>/dev/null || true
        "$IPSET" flush "$_sn" 2>/dev/null || true
        fill_set "$_sn" "$_lf"
        _gu=$(cfg "profile${_i}_geo_url")
        [ -n "$_gu" ] && fill_geo "$_sn" "$_gu" "$VARDIR/profiles/$(san "$_nm").txt"

        _cnt=$(set_count "$_sn")
        if [ "${_cnt:-0}" -eq 0 ]; then
            echo "[profiles] $_nm: набор пуст (0 адресов) — профиль ни на что не сработает (пустой список / не резолвится домен / в файле нет перевода строки в конце)"
        fi

        if [ -n "$_eg" ] && [ -e "/sys/class/net/$_eg" ]; then
            "$IPB" route replace default dev "$_eg" table "$_tb" 2>/dev/null || true
            "$IPB" rule del fwmark "$_mk" lookup "$_tb" 2>/dev/null || true
            "$IPB" rule add fwmark "$_mk" lookup "$_tb" 2>/dev/null || true
            # Метку ставим ТОЛЬКО когда есть и живой интерфейс, и правило, и
            # маршрут в таблице. Иначе помеченный пакет уйдёт по чужой политике
            # (например, на основной VPN Keenetic) — именно так выглядел баг
            # «профиль есть, а трафик идёт через основной интерфейс».
            if "$IPB" rule show 2>/dev/null | grep -q "fwmark $_mk lookup $_tb" &&
               "$IPB" route show table "$_tb" 2>/dev/null | grep -q '^default'; then
                "$IPT" -t mangle -A "$CHAIN" -m set --match-set "$_sn" dst \
                       -m mark --mark 0x0 -j MARK --set-mark "$_mk" 2>/dev/null || true
                # CONNMARK: чтобы движок видел поток «своим» (ctmark != 0) и не
                # учил адрес профиля в основную схему. Без этого профильный поток
                # выглядел неразмеченным и уходил в автообучение (двух встречных
                # механизмов на один адрес). Маска — сам бит профиля: биты
                # основной схемы (mark_mask) не трогаем.
                "$IPT" -t mangle -A "$CHAIN" -m set --match-set "$_sn" dst \
                       -j CONNMARK --set-xmark "$_mk/$_mk" 2>/dev/null || true
                # И RETURN в основной цепочке: профиль должен выигрывать у
                # выученных адресов/vpn_always (главная причина «профиль
                # поднят, а не работает»).
                add_prof_return "$_sn"
            else
                echo "[profiles] $_nm: нет правила/маршрута для mark $_mk table $_tb — профиль пропущен"
            fi
        else
            echo "[profiles] $_nm: egress '${_eg:-не задан}' не найден — профиль пропущен (метка не ставится)"
        fi
        _i=$((_i + 1))
    done

    # Профили должны стоять ПЕРВЫМИ в PREROUTING: основная цепочка SUSANIN
    # метит адрес раньше и забирает поток. Старый хвостовой jump снимаем, чтобы
    # не было двух одинаковых.
    "$IPT" -t mangle -D PREROUTING -j "$CHAIN" 2>/dev/null || true
    "$IPT" -t mangle -I PREROUTING 1 -j "$CHAIN" 2>/dev/null \
        || "$IPT" -t mangle -A PREROUTING -j "$CHAIN" 2>/dev/null || true
    echo "[profiles] up: $_n профил(ей)"
}

# refresh — перечитать файлы-списки профилей (перерезолвить домены, подхватить
# новые IP/CIDR) без пересборки правил. Для geo/CDN-списков, обновляемых извне.
refresh() {
    _n=$(count_profiles)
    [ "$_n" -eq 0 ] && { echo "[profiles] профили не заданы"; return 0; }
    _i=1
    while [ "$_i" -le "$MAXP" ]; do
        _nm=$(prof_name "$_i")
        if [ -z "$_nm" ]; then _i=$((_i + 1)); continue; fi
        _lf=$(cfg "profile${_i}_list")
        _sn="$SETPFX$(san "$_nm")"
        "$IPSET" create "$_sn" hash:net timeout 0 -exist 2>/dev/null || true
        "$IPSET" flush "$_sn" 2>/dev/null || true
        fill_set "$_sn" "$_lf"
        _gu=$(cfg "profile${_i}_geo_url")
        [ -n "$_gu" ] && fill_geo "$_sn" "$_gu" "$VARDIR/profiles/$(san "$_nm").txt"
        _cnt=$(set_count "$_sn")
        if [ "${_cnt:-0}" -eq 0 ]; then
            echo "[profiles] $_nm: набор пуст (0 адресов) — профиль ни на что не сработает (пустой список / не резолвится домен / в файле нет перевода строки в конце)"
        fi
        echo "[profiles] refresh $_nm <- ${_lf:-?} (адресов: ${_cnt:-0})"
        _i=$((_i + 1))
    done
}

down() {
    "$IPT" -t mangle -D PREROUTING -j "$CHAIN" 2>/dev/null || true
    "$IPT" -t mangle -F "$CHAIN" 2>/dev/null || true
    "$IPT" -t mangle -X "$CHAIN" 2>/dev/null || true
    _i=1
    while [ "$_i" -le "$MAXP" ]; do
        _nm=$(prof_name "$_i")
        if [ -z "$_nm" ]; then _i=$((_i + 1)); continue; fi
        _tb=$(cfg "profile${_i}_table"); [ -n "$_tb" ] || _tb=$((200 + _i))
        _mk=$(prof_mark "$_i")
        _sn="$SETPFX$(san "$_nm")"
        del_prof_return "$_sn"
        "$IPB" rule del fwmark "$_mk" lookup "$_tb" 2>/dev/null || true
        "$IPB" route flush table "$_tb" 2>/dev/null || true
        "$IPSET" destroy "$_sn" 2>/dev/null || true
        _i=$((_i + 1))
    done
    echo "[profiles] down"
}

status() {
    echo "chain $CHAIN: $("$IPT" -t mangle -S "$CHAIN" >/dev/null 2>&1 && echo ok || echo НЕТ)"
    _pos=$("$IPT" -t mangle -S PREROUTING 2>/dev/null | grep -n -- "-j $CHAIN" | head -n1 | cut -d: -f1)
    echo "jump в PREROUTING: ${_pos:-нет} (должен быть первым: профиль выигрывает у основной схемы)"
    _marks=""
    _i=1
    while [ "$_i" -le "$MAXP" ]; do
        _nm=$(prof_name "$_i")
        # ВАЖНО: счётчик увеличивается на КАЖДОЙ итерации. Раньше при заданном
        # профиле цикл не двигался и status печатал одну и ту же строку без конца.
        _i=$((_i + 1))
        [ -n "$_nm" ] || continue
        _pv=$((_i - 1))
        _eg=$(cfg "profile${_pv}_egress")
        _tb=$(cfg "profile${_pv}_table"); [ -n "$_tb" ] || _tb=$((200 + _pv))
        _mk=$(prof_mark "$_pv")
        _mk_user=$(cfg "profile${_pv}_mark")
        _sn="$SETPFX$(san "$_nm")"
        case " $_marks " in
            *" $_mk "*) _mdup=1 ;;
            *) _mdup=0 ;;
        esac
        _marks="$_marks $_mk"
        _c=$(set_count "$_sn")
        _live=""
        for _e in $(printf '%s' "$_eg" | tr ',' ' '); do
            [ -e "/sys/class/net/$_e" ] && { _live="$_e"; break; }
        done
        if [ -n "$_live" ]; then _egs="egress=${_eg:-?} (живой: $_live)"; else _egs="egress=${_eg:-?} (НЕТ живого интерфейса!)"; fi
        _rule=$("$IPB" rule show 2>/dev/null | grep -c "fwmark $_mk lookup $_tb")
        _rt=$("$IPB" route show table "$_tb" 2>/dev/null | grep -c '^default')
        _mr=$("$IPT" -t mangle -S "$CHAIN" 2>/dev/null | grep -c -- "--match-set $_sn dst")
        echo "  $_nm: $_egs table=$_tb mark=$_mk$([ -n "$_mk_user" ] && echo " (из конфига)" || echo " (дефолт по индексу)") set=$_sn entries=${_c:-0}"
        [ "$_mdup" = "1" ] && echo "      ВНИМАНИЕ: метка $_mk уже занята другим профилем — при 2+ профилях задайте profileN_mark явно (0x40000000/0x08000000/0x04000000/0x02000000)."
        _ret=$("$IPT" -t mangle -S "$MAIN_CHAIN" 2>/dev/null | grep -c -- "--match-set $_sn dst -j RETURN")
        echo "      RETURN в $MAIN_CHAIN: $([ "${_ret:-0}" -gt 0 ] && echo есть || echo НЕТ)"
        echo "      ip rule=$([ "${_rule:-0}" -gt 0 ] && echo есть || echo НЕТ), default в таблице=$([ "${_rt:-0}" -gt 0 ] && echo есть || echo НЕТ), правило mark=$([ "${_mr:-0}" -gt 0 ] && echo есть || echo НЕТ)"
        # entries=0 при «есть/есть/есть» — самая обманчивая картина: правила и
        # маршрут на месте, а метка не встанет ни на один пакет.
        if [ "${_c:-0}" -eq 0 ]; then
            echo "      ВНИМАНИЕ: набор пуст (0 адресов) — профиль не сработает. Проверьте файл списка, резолв доменов и перевод строки в конце файла."
        fi
        # Профиль ставит МЕТКУ ПАКЕТА (не connmark), поэтому в
        # /proc/net/nf_conntrack её не видно — единственный признак «профиль
        # реально срабатывал» это счётчик пакетов на правиле mark.
        _pk=$("$IPT" -t mangle -vnL "$CHAIN" 2>/dev/null | awk -v s="$_sn" '$0 ~ s { print $1; exit }')
        _pk=${_pk:-0}
        if [ "$_pk" = "0" ]; then
            echo "      пакетов помечено: 0 — профиль ещё ни разу не сработал (адрес из списка не совпал ни с одним потоком)"
        else
            echo "      пакетов помечено: $_pk"
        fi
    done
    # Метки профилей могут совпасть с чужой политикой (Keenetic и т.п.) — покажем все
    # правила с нашими метками, чтобы это было видно в отчёте.
    _pfx=$("$IPB" rule show 2>/dev/null | grep -c 'fwmark 0x4')
    [ "${_pfx:-0}" -gt 1 ] && echo "  внимание: правил с метками 0x4… — $_pfx (проверьте, нет ли конфликта с политиками Keenetic)"
    return 0
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    status) status ;;
    refresh) refresh ;;
    *) echo "usage: $0 {up|down|status|refresh}"; exit 2 ;;
esac
