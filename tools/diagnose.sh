#!/bin/sh
# diagnose.sh — диагностика Susanin.Keenetic.
#
# Когда что-то работает не так — запустите этот скрипт: он проверит окружение,
# настройки, правила и списки, а в конце выдаст РЕКОМЕНДАЦИИ.
#
# Запуск:
#   sh /opt/susanin/tools/diagnose.sh [--etc DIR] [--dns IP]
#
# Для отправки полного отчёта (логи и состояние) используйте report.sh.
# POSIX sh (busybox ash compatible).
set -u

ETCDIR=""
DNS=""
while [ $# -gt 0 ]; do
    case "$1" in
        --etc) ETCDIR="$2"; shift ;;
        --dns) DNS="$2"; shift ;;
        -h|--help) echo "usage: $0 [--etc DIR] [--dns IP]"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
    shift
done

if [ -z "$ETCDIR" ]; then
    if [ -d /opt/susanin/etc ]; then
        ETCDIR=/opt/susanin/etc
    elif [ -d /etc/susanin ]; then
        ETCDIR=/etc/susanin
    else
        ETCDIR=/opt/susanin/etc
    fi
fi
CONF="$ETCDIR/susanin.conf"

cfg() { # cfg <key> — значение из susanin.conf (или пусто)
    [ -f "$CONF" ] || return 0
    sed -n "s/^$1=[ \t]*//p" "$CONF" | head -n1
}

RECS=""
rec() { RECS="${RECS}
  - $*"; }
sec() { echo; echo "== $* =="; }

# ------------------------------------------------------------------ окружение
sec "Окружение"
A=/opt/susanin/bin/susanin-agent
if [ ! -x "$A" ]; then
    A=$(command -v susanin-agent 2>/dev/null || true)
fi
if [ -n "$A" ] && [ -x "$A" ]; then
    echo "agent: $("$A" version 2>/dev/null)"
else
    echo "agent: НЕ НАЙДЕН"
    rec "susanin-agent не найден — проверьте установку/обновление"
fi

for t in iptables ipset conntrack ip; do
    if command -v "$t" >/dev/null 2>&1; then
        echo "tool $t: ok"
    else
        echo "tool $t: НЕТ"
        rec "установите пакет: opkg update && opkg install $t"
    fi
done

# ------------------------------------------------------------------- конфиг
sec "Конфиг ($CONF)"
EGR=$(cfg egress_interface)
LAN=$(cfg lan_interfaces)
SUB=$(cfg lan_subnets)
TBL=$(cfg routing_table)
DM=$(cfg disk_mode)
DNS_CFG=$(cfg vpn_always_dns)
[ -n "$TBL" ] || TBL=100
echo "egress: ${EGR:-?}"
echo "lan: ${LAN:-?} / ${SUB:-?}"
echo "table: $TBL, disk_mode: ${DM:-?}, vpn_always_dns: ${DNS_CFG:-<auto>}"

if [ -n "$EGR" ]; then
    oldifs=$IFS; IFS=','
    for i in $EGR; do
        IFS=$oldifs
        i=$(printf '%s' "$i" | tr -d ' \t')
        if [ -e "/sys/class/net/$i" ]; then
            echo "egress $i: существует"
        else
            echo "egress $i: ОТСУТСТВУЕТ"
            rec "интерфейс '$i' отсутствует — исправьте egress_interface или поднимите VPN"
        fi
        IFS=','
    done
    IFS=$oldifs
fi

# ------------------------------------------------------------ правила (data plane)
sec "Правила"
if command -v iptables >/dev/null 2>&1; then
    if iptables -t mangle -S SUSANIN >/dev/null 2>&1; then
        echo "цепочка SUSANIN: ok"
    else
        echo "цепочка SUSANIN: НЕТ"
        rec "правила не созданы — проверьте ipset/iptables и egress, затем: susanin.sh restart"
    fi
fi
if command -v ip >/dev/null 2>&1; then
    if ip rule show 2>/dev/null | grep -q "lookup $TBL"; then
        echo "ip rule -> table $TBL: ok"
    else
        echo "ip rule -> table $TBL: НЕТ"
        rec "нет ip rule на таблицу $TBL — правила не применены"
    fi
    if ip route show table "$TBL" 2>/dev/null | grep -q '^default'; then
        echo "default в table $TBL: ok"
    else
        echo "default в table $TBL: НЕТ"
        rec "в таблице $TBL нет default-маршрута (проверьте egress/VPN)"
    fi
fi

# --------------------------------------------------------------------- списки
ips_of() {
    if [ -n "$DNS" ]; then
        nslookup "$1" "$DNS" 2>&1
    else
        nslookup "$1" 2>&1
    fi | awk '/^Name:/{f=1; next}
              f && /^Address/ {
                  for (i = 1; i <= NF; i++)
                      if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { print $i; break }
              }'
}
is_ip4()  { printf '%s' "$1" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; }
is_cidr() { printf '%s' "$1" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$'; }

check_list() {
    f="$1"; label="$2"
    if [ ! -f "$f" ]; then
        echo "$label: файла нет ($f)"
        return
    fi
    echo "$label ($f):"
    tot=0; ok=0; bad=0
    while IFS= read -r raw; do
        e=$(printf '%s' "$raw" | sed 's/#.*//' | tr -d ' \t\r')
        [ -z "$e" ] && continue
        tot=$((tot + 1))
        if is_ip4 "$e" || is_cidr "$e"; then
            ok=$((ok + 1))
            continue
        fi
        name=$(printf '%s' "$e" | sed 's/^\*\.//')
        ips=$(ips_of "$name")
        if [ -n "$ips" ]; then
            ok=$((ok + 1))
        else
            bad=$((bad + 1))
            echo "  проблема: $e — нет A / не резолвится"
            case "$e" in
                '*.'*) rec "$label: '$e' не резолвится — проверьте зону/резолвер" ;;
                *) rec "$label: у '$e' нет A на apex — укажите поддомены или '*.$name'" ;;
            esac
        fi
    done < "$f"
    echo "  итог: строк $tot, с адресами $ok, без адресов $bad"
}

sec "Списки"
check_list "$ETCDIR/vpn_always.txt" "vpn_always"
check_list "$ETCDIR/vpn_never.txt" "vpn_never"

if [ -f "$ETCDIR/vpn_always.txt" ] && [ -f "$ETCDIR/vpn_never.txt" ]; then
    conf=$(awk '
        { l = $0; sub(/#.*/, "", l); gsub(/[ \t\r]/, "", l);
          if (l == "") next;
          if (FNR == NR) { a[l] = 1; next }
          if (a[l]) print l }
    ' "$ETCDIR/vpn_always.txt" "$ETCDIR/vpn_never.txt")
    if [ -n "$conf" ]; then
        echo "  конфликты always/never (приоритет — «напрямую»):"
        printf '    %s\n' $conf
        rec "уберите дубли always/never: они конфликтуют (например, $(printf '%s' "$conf" | head -n1))"
    fi
fi

if [ -z "$DNS_CFG" ] && [ -z "$DNS" ]; then
    echo "  резолвер списка: auto (из resolv.conf)"
    rec "если много «нет A/не резолвится» — задайте vpn_always_dns (например, IP LAN-моста)"
fi

# ------------------------------------------------------------- рекомендации
sec "Рекомендации"
if [ -n "$RECS" ]; then
    printf '%s\n' "$RECS"
else
    echo "  проблем не найдено — настройки и правила в порядке"
fi
echo
echo "Для отправки отчёта с логами: sh /opt/susanin/tools/report.sh"
