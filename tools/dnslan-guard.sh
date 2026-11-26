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
# секунд проверяет, что порт форвардера слушает ИМЕННО агент и что он отвечает.
# Если агент мёртв или сокет достался наследнику (Xray и т.п.) — снимает ТОЛЬКО
# цепь DNS (остальной датаплейн не трогает): DNS клиентов возвращается на
# прямой путь (fail-open), маршрутизация остаётся как была. Затем пытается
# поднять агент (не чаще 3 раз в час).
#
# Состояние «сокета нет» проверяется CONFIRM тиков подряд: один пустой замер
# /proc/net/udp ловится, когда форвардер пересоздаёт сокет (смена upstream), и
# снимать из-за него DNAT у всех клиентов нельзя. Если агент после попытки
# подъёма жив (pid не сменился), правила возвращаются на место, а не остаются
# снятыми до ручного restart.
#
# Живой агент, который не ответил на пробу, DNAT не снимает: прямой путь в РФ
# для части домён хуже туннеля, а форвардер живёт в своём потоке и обычно
# восстанавливается сам. Такие случаи только пишутся в заметку.
#
# POSIX sh (busybox ash compatible).

PORT=${SUSANIN_DNS_LAN_PORT:-5399}
TOOLS=${SUSANIN_TOOLS:-/opt/susanin/tools}
CHAIN=SUSANIN_DNSLAN
PIDFILE=/opt/susanin/var/dnslan-guard.pid
AGENT_PID=/opt/susanin/var/susanin-agent.pid
AGENT_BIN=/opt/susanin/bin/susanin-agent
NOTE=/opt/susanin/var/dnslan-guard.last
INTERVAL=${SUSANIN_DNSLAN_GUARD_INTERVAL:-5}
# Сколько тиков подряд «сокета агента нет» нужно, чтобы снимать DNAT.
CONFIRM=${SUSANIN_DNSLAN_GUARD_CONFIRM:-3}

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
#
# Владелец ищется не только по pid из pid-файла: агент держит часть сокетов в
# дочерних процессах того же бинаря, и раньше такой сокет считался «чужим» —
# сторож снимал DNAT, хотя форвардер работал.
_ino_in_pid() { # <pid> <inode>
    for _f in /proc/"$1"/fd/*; do
        [ "$(readlink "$_f" 2>/dev/null)" = "socket:[$2]" ] && return 0
    done
    return 1
}

agent_holds_socket() {
    _ino=$(socket_inode)
    [ -n "$_ino" ] || return 1
    _ap=$(cat "$AGENT_PID" 2>/dev/null || true)
    if [ -n "$_ap" ] && kill -0 "$_ap" 2>/dev/null && _ino_in_pid "$_ap" "$_ino"; then
        return 0
    fi
    for _p in /proc/[0-9]*; do
        [ "$(readlink "$_p/exe" 2>/dev/null)" = "$AGENT_BIN" ] || continue
        _ino_in_pid "${_p#/proc/}" "$_ino" && return 0
    done
    return 1
}

chain_present() {
    [ -n "$IPT" ] || return 1
    "$IPT" -w -t nat -S "$CHAIN" >/dev/null 2>&1
}

# Поднять агент, если он умер не по команде stop/down. Ограничиваем число
# попыток, чтобы падение на старте не превратилось в бесконечный цикл.
# Возврат: 0 — агент поднят (правила поставит он сам), 1 — поднимать не стали
# или pid не сменился (агент был жив); тогда вызывающий решает про правила сам.
RESTARTS=/opt/susanin/var/dnslan-guard.restarts
maybe_restart() {
    _now=$(date +%s 2>/dev/null || echo 0)
    _old=$(cat "$AGENT_PID" 2>/dev/null || true)
    _n=0
    if [ -f "$RESTARTS" ]; then
        _n=$(awk -v t="$((_now - 3600))" '$1 + 0 > t' "$RESTARTS" 2>/dev/null | wc -l)
    fi
    if [ "$_n" -ge 3 ]; then
        note "dns_lan: агент не поднимаю — 3 перезапуска за час; нужен susanin start вручную"
        return 1
    fi
    printf '%s\n' "$_now" >>"$RESTARTS" 2>/dev/null || true
    if [ -x "$TOOLS/susanin.sh" ] && sh "$TOOLS/susanin.sh" start >/dev/null 2>&1; then
        _new=$(cat "$AGENT_PID" 2>/dev/null || true)
        if [ -n "$_new" ] && [ "$_new" != "$_old" ]; then
            note "dns_lan: агент перезапущен сторожем (pid ${_old:-?} -> $_new; правила датаплейна он поставит сам)"
            return 0
        fi
        note "dns_lan: start вызван, но pid не сменился (${_new:-?}) — агент уже работал"
        return 1
    fi
    note "dns_lan: перезапустить агент не удалось — нужен susanin start вручную"
    return 1
}

echo $$ >"$PIDFILE" 2>/dev/null || true
# Проверка ОТВЕТА, а не только сокета: агент может быть жив и держать порт,
# но не успевать отвечать (занят iptables/пересборкой). Три неудачи подряд
# (раз в PROBE_EVERY тиков) — повод записать в заметку. Две не годятся: один
# пропущенный тик агента давал ложное «мёртв».
PROBE_EVERY=${SUSANIN_DNSLAN_PROBE_EVERY:-12}
PROBE_FAIL_MAX=${SUSANIN_DNSLAN_PROBE_FAIL_MAX:-3}
probe_answers() {
    [ -x "$AGENT_BIN" ] || return 0
    "$AGENT_BIN" dnsprobe example.com 127.0.0.1 "$PORT" >/dev/null 2>&1
}
# Причина неудачи — в журнал: без неё «не отвечает» не отличить от таймаута,
# отказа upstream-а и занятого цикла.
probe_why() {
    "$AGENT_BIN" dnsprobe example.com 127.0.0.1 "$PORT" 2>&1 | tail -n1
}
# Убираем pid-файл только если он всё ещё наш: иначе сторож, вышедший после
# restart, удалил бы pid-файл нового сторожа, и тот через тик решил бы, что его
# сняли.
cleanup() {
    [ "$(cat "$PIDFILE" 2>/dev/null)" = "$$" ] && rm -f "$PIDFILE"
    return 0
}
trap cleanup EXIT HUP INT TERM

tick=0
pfail=0
miss=0

while :; do
    sleep "$INTERVAL"
    tick=$((tick + 1))
    # Нас заменил новый сторож (up после restart) или сняли pid-файл — выходим.
    [ "$(cat "$PIDFILE" 2>/dev/null)" = "$$" ] || exit 0
    if agent_holds_socket; then
        miss=0
        if [ $((tick % PROBE_EVERY)) -eq 0 ] && ! probe_answers; then
            pfail=$((pfail + 1))
            note "dns_lan: сокет udp/$PORT есть, но форвардер не отвечает (проба $pfail/$PROBE_FAIL_MAX: $(probe_why))"
            if [ "$pfail" -ge "$PROBE_FAIL_MAX" ]; then
                pfail=0
                note "dns_lan: форвардер не отвечает, но агент жив (pid $(cat "$AGENT_PID" 2>/dev/null || echo '?')) — DNAT не снимаю"
            fi
            continue
        fi
        pfail=0
        continue
    fi
    # Сокета агента нет. Один замер ничего не доказывает: форвардер пересоздаёт
    # сокет при смене upstream, и в щель между bind() и появлением в /proc/net/udp
    # сторож уже попадал — снимал DNAT у всех клиентов из-за пустого чтения.
    miss=$((miss + 1))
    if [ "$miss" -lt "$CONFIRM" ]; then
        continue
    fi
    miss=0
    # Слушателя нет или порт держит не агент — это и есть случай, от которого
    # сторож защищает (мёртвый агент + живые DNAT-правила). Цепь уже снята —
    # тихо выходим.
    chain_present || exit 0
    _ino=$(socket_inode)
    _ap=$(cat "$AGENT_PID" 2>/dev/null || true)
    if [ -n "$_ino" ]; then
        _why="порт udp/$PORT занят не агентом (inode $_ino, pid-файл ${_ap:-нет})"
    else
        _why="форвардер (udp/$PORT) не слушает"
    fi
    if SUSANIN_DNSLAN_GUARD_PID=$$ sh "$TOOLS/datapath.sh" dns-lan-down >/dev/null 2>&1; then
        note "dns_lan: $_why — DNAT клиентов снят, DNS идёт напрямую"
    else
        note "dns_lan: $_why, снять DNAT не удалось ($TOOLS/datapath.sh) — нужен susanin restart"
    fi
    maybe_restart && exit 0
    # Агент жив (перезапуск не понадобился) — правила возвращаем сами, иначе
    # DNS клиентов остаётся на прямом пути до ручного restart.
    if [ -z "$(socket_inode)" ]; then
        note "dns_lan: форвардер не слушает — DNAT не возвращаю (нужен susanin restart)"
        exit 0
    fi
    if SUSANIN_DNSLAN_GUARD_PID=$$ sh "$TOOLS/datapath.sh" dns-lan-up >/dev/null 2>&1; then
        note "dns_lan: правила DNAT возвращены (агент жив), сторож перезапущен"
    else
        note "dns_lan: вернуть правила не удалось — нужен susanin restart"
    fi
    exit 0
done
