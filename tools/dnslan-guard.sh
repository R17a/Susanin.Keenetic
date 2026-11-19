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
AGENT_PID=/opt/susanin/var/susanin-agent.pid
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
socket_inode() {
    _hex=$(printf '%04X' "$PORT")
    awk -v p=":$_hex" '$2 ~ p"$" && $4 == "07" { print $10; exit }' \
        /proc/net/udp 2>/dev/null
}

# Слушает именно агент. Порт мог достаться процессу, унаследовавшему сокет
# (Xray запускается агентом через exec): форвардера в нём уже нет, но порт
# занят — и DNAT слал бы DNS клиентов в мёртвый сокет.
agent_holds_socket() {
    _ino=$(socket_inode)
    [ -n "$_ino" ] || return 1
    _ap=$(cat "$AGENT_PID" 2>/dev/null || true)
    [ -n "$_ap" ] || return 0
    kill -0 "$_ap" 2>/dev/null || return 0
    for _f in /proc/"$_ap"/fd/*; do
        [ "$(readlink "$_f" 2>/dev/null)" = "socket:[$_ino]" ] || continue
        return 0
    done
    return 1
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
    agent_holds_socket && continue
    # Слушателя нет (или порт держит не агент). Цепь уже снята — тихо выходим.
    chain_present || exit 0
    if [ -n "$(socket_inode)" ]; then
        _why="порт udp/$PORT занят не агентом (унаследован Xray?)"
    else
        _why="форвардер (udp/$PORT) не слушает"
    fi
    if SUSANIN_DNSLAN_GUARD_PID=$$ sh "$TOOLS/datapath.sh" dns-lan-down >/dev/null 2>&1; then
        note "dns_lan: $_why — DNAT клиентов снят, DNS идёт напрямую (вернуть: susanin restart)"
    else
        note "dns_lan: $_why, снять DNAT не удалось ($TOOLS/datapath.sh) — нужен susanin restart"
    fi
    exit 0
done
