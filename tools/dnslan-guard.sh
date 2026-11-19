#!/bin/sh
# dnslan-guard.sh — сторож DNAT-правил `dns_lan`.
#
# Зачем: правила DNAT перенаправляют DNS клиентов LAN на порт форвардера,
# который живёт ВНУТРИ агента. Если агент умирает (сегфолт, OOM, kill -9),
# правила остаются, а слушателя на порту больше нет — и тогда DNS перестаёт
# работать у ВСЕХ клиентов LAN, хотя сам роутер исправен. Это единственный
# сценарий, в котором `dns_lan=1` опаснее, чем `dns_lan=0`: при живом роутере
# и мёртвом агенте теряется не «маршрутизация», а разрешение имён.
#
# Сторож запускается из datapath.sh вместе с правилами и раз в INTERVAL
# секунд проверяет, что порт форвардера кто-то слушает. Как только слушателя
# нет — снимает ТОЛЬКО цепь DNS (остальной датаплейн не трогает) и выходит:
# DNS клиентов возвращается на прямой путь (fail-open), маршрутизация остаётся
# в текущем состоянии.
#
# Не перезапускает агент: восстановление — `susanin restart` или панель.
#
# POSIX sh (busybox ash compatible).

PORT=${SUSANIN_DNS_LAN_PORT:-5399}
TOOLS=${SUSANIN_TOOLS:-/opt/susanin/tools}
CHAIN=SUSANIN_DNSLAN
PIDFILE=/opt/susanin/var/dnslan-guard.pid
NOTE=/opt/susanin/var/dnslan-guard.last
INTERVAL=${SUSANIN_DNSLAN_GUARD_INTERVAL:-5}

IPT=${SUSANIN_IPTABLES:-}
if [ -z "$IPT" ]; then
    for _b in /opt/sbin /opt/bin /usr/sbin /usr/bin; do
        [ -x "$_b/iptables" ] && { IPT="$_b/iptables"; break; }
    done
fi

note() {
    printf '%s\n' "$*" >>"$NOTE" 2>/dev/null || true
    command -v logger >/dev/null 2>&1 && logger -t susanin "$*" 2>/dev/null || true
}

# Кто-то слушает UDP-порт форвардера (состояние 07 в /proc/net/udp).
listening() {
    _hex=$(printf '%04X' "$PORT")
    awk -v p=":$_hex" '$2 ~ p"$" && $4 == "07" { f = 1 } END { exit(f ? 0 : 1) }' \
        /proc/net/udp 2>/dev/null
}

chain_present() {
    [ -n "$IPT" ] || return 1
    "$IPT" -w -t nat -S "$CHAIN" >/dev/null 2>&1
}

echo $$ >"$PIDFILE" 2>/dev/null || true
# Убираем pid-файл только если он всё ещё наш: иначе сторож, вышедший после
# restart, удалил бы pid-файл нового сторожа, и тот через тик решил бы, что его
# сняли.
cleanup() {
    [ "$(cat "$PIDFILE" 2>/dev/null)" = "$$" ] && rm -f "$PIDFILE"
    return 0
}
trap cleanup EXIT HUP INT TERM

while :; do
    sleep "$INTERVAL"
    # Нас заменил новый сторож (up после restart) или сняли pid-файл — выходим.
    [ "$(cat "$PIDFILE" 2>/dev/null)" = "$$" ] || exit 0
    listening && continue
    # Слушателя нет. Если цепи уже нет (stop/down снял правила) — тихо выходим.
    chain_present || exit 0
    if SUSANIN_DNSLAN_GUARD_PID=$$ sh "$TOOLS/datapath.sh" dns-lan-down >/dev/null 2>&1; then
        note "dns_lan: форвардер (udp/$PORT) не слушает — DNAT клиентов снят, DNS идёт напрямую (вернуть: susanin restart)"
    else
        note "dns_lan: форвардер (udp/$PORT) не слушает, снять DNAT не удалось ($TOOLS/datapath.sh) — нужен susanin restart"
    fi
    exit 0
done
