#!/bin/sh
# check-lists.sh — проверка списков vpn_always / vpn_never: что реально пинится.
#
# Универсально: проходит по ВСЕМ строкам списков и по каждой показывает вердикт
# (адреса есть / нет A / не резолвится), плюс итог и конфликты always/never.
#
# Запуск:
#   sh /opt/susanin/tools/check-lists.sh [--etc DIR] [--dns IP]
#
# Резолвер: --dns IP, иначе vpn_always_dns из susanin.conf, иначе системный.
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

if [ -z "$DNS" ] && [ -f "$ETCDIR/susanin.conf" ]; then
    DNS=$(sed -n 's/^vpn_always_dns=[ \t]*\([0-9.]*\).*/\1/p' "$ETCDIR/susanin.conf" | head -n1)
fi

# Печатает IPv4-адреса для имени (по одному в строке).
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

check() {
    f="$1"; label="$2"
    if [ ! -f "$f" ]; then
        echo "== $label: файла нет ($f) =="
        return
    fi
    echo "== $label ($f) =="
    tot=0; ok=0; bad=0
    while IFS= read -r raw; do
        e=$(printf '%s' "$raw" | sed 's/#.*//' | tr -d ' \t\r')
        [ -z "$e" ] && continue
        tot=$((tot + 1))
        if is_ip4 "$e" || is_cidr "$e"; then
            ok=$((ok + 1))
            printf '  ok    %-44s (IP/CIDR)\n' "$e"
            continue
        fi
        name=$(printf '%s' "$e" | sed 's/^\*\.//')
        ips=$(ips_of "$name")
        if [ -n "$ips" ]; then
            ok=$((ok + 1))
            printf '  ok    %-44s %s\n' "$e" "$(printf '%s' "$ips" | tr '\n' ' ')"
        else
            bad=$((bad + 1))
            printf '  --    %-44s нет A / не резолвится (нужны поддомены или *.%s)\n' "$e" "$name"
        fi
    done < "$f"
    echo "  итог: строк $tot, с адресами $ok, без адресов $bad"
}

echo "check-lists: каталог $ETCDIR, резолвер ${DNS:-системный}"
check "$ETCDIR/vpn_always.txt" "vpn_always"
check "$ETCDIR/vpn_never.txt"  "vpn_never"

if [ -f "$ETCDIR/vpn_always.txt" ] && [ -f "$ETCDIR/vpn_never.txt" ]; then
    conf=$(awk '
        { l = $0; sub(/#.*/, "", l); gsub(/[ \t\r]/, "", l);
          if (l == "") next;
          if (FNR == NR) { a[l] = 1; next }
          if (a[l]) print l }
    ' "$ETCDIR/vpn_always.txt" "$ETCDIR/vpn_never.txt")
    if [ -n "$conf" ]; then
        echo "== конфликты always/never (приоритет — «напрямую»): =="
        printf '  %s\n' $conf
    fi
fi
