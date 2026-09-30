#!/bin/sh
# susanin.sh — Susanin.Keenetic daemon control.
#
# Usage:
#   sh susanin.sh start          # start daemon in background (writes log)
#   sh susanin.sh stop           # graceful stop (SIGTERM, then KILL if needed)
#   sh susanin.sh restart        # restart
#   sh susanin.sh status         # daemon + data plane state
#   sh susanin.sh log [N]        # last N log lines (default 30)
#   sh susanin.sh install        # data plane setup (datapath up + setup)
#   sh susanin.sh update [ver]   # update binary/scripts (keeps config and state)
#   sh susanin.sh uninstall [--purge]
#   sh susanin.sh reload         # перечитать susanin.conf на лету (SIGHUP)
#   sh susanin.sh rescan [--force]  # заново найти LAN/VPN, обновить конфиг и перечитать
#                                   # (без --force ручной egress_interface не затирается)
#   sh susanin.sh web {start|stop|restart|status}  # веб-панель (отдельный процесс)
#   sh susanin.sh down           # remove data plane rules (daemon keeps running)
#   sh susanin.sh reset <ip|domain>  # сброс из кэша/ipsets/conntrack («забыть»)
#   sh susanin.sh forget <ip|domain> # синоним reset
#   sh susanin.sh add <ip> tcp|udp test|ok
#   sh susanin.sh del <ip> tcp|udp

set -eu

BIN=/opt/susanin/bin/susanin-agent
CONF=/opt/susanin/etc/susanin.conf
LOG=/opt/susanin/var/susanin.log
TOOLS=/opt/susanin/tools

# Пид-файл демона (пишет start_daemon) — основной признак; ps — запасной,
# чтобы не путать демон (run) с веб-панелью (web).
DAEMON_PID=/opt/susanin/var/susanin-agent.pid

is_running() {
    _p=$(cat "$DAEMON_PID" 2>/dev/null)
    if [ -n "${_p:-}" ] && kill -0 "$_p" 2>/dev/null; then
        return 0
    fi
    ps | grep 'susanin-agent run' | grep -v grep >/dev/null 2>&1
}

# Веб-панель — ОТДЕЛЬНЫЙ процесс (susanin-agent web). Держим её отдельно от
# демона: рестарт демона не должен ронять панель, иначе /api/restart убивает
# процесс, обслуживающий сам запрос, и панель «отваливается».
WEB_PID=/opt/susanin/var/susanin-web.pid
WEB_LOG=/opt/susanin/var/susanin-web.log

is_web_running() {
    [ -f "$WEB_PID" ] && kill -0 "$(cat "$WEB_PID" 2>/dev/null)" 2>/dev/null
}

web_enabled() {
    [ "$(sed -n 's/^web_enable=//p' "$CONF" 2>/dev/null | tail -n1)" = "1" ]
}

cmd_web_start() {
    web_enabled || return 0
    is_web_running && return 0
    mkdir -p /opt/susanin/var
    SUSANIN_CONF="$CONF" "$BIN" web >>"$WEB_LOG" 2>&1 </dev/null &
    echo $! > "$WEB_PID"
    echo "[susanin] web started (pid $(cat "$WEB_PID" 2>/dev/null))"
}

cmd_web_stop() {
    if [ -f "$WEB_PID" ]; then
        _p=$(cat "$WEB_PID" 2>/dev/null)
        [ -n "${_p:-}" ] && kill "$_p" 2>/dev/null || true
        rm -f "$WEB_PID"
        echo "[susanin] web stopped"
    fi
}

# Rotate log above 5 MiB; keep compressed archives susanin.log.1.gz .. .3.gz
rotate_log() {
    [ -f "$LOG" ] || return 0
    _sz=$(wc -c < "$LOG" 2>/dev/null || echo 0)
    [ "${_sz:-0}" -lt 5242880 ] && return 0
    rm -f "$LOG.3.gz"
    [ -f "$LOG.2.gz" ] && mv -f "$LOG.2.gz" "$LOG.3.gz"
    [ -f "$LOG.1.gz" ] && mv -f "$LOG.1.gz" "$LOG.2.gz"
    mv -f "$LOG" "$LOG.1"
    if command -v gzip >/dev/null 2>&1; then
        gzip -f "$LOG.1" 2>/dev/null || true
    else
        rm -f "$LOG.3.gz"
    fi
    echo "[susanin] log rotated (archives: $LOG.N.gz, keep 3)"
}

start_daemon() {
    if is_running; then
        echo "[susanin] already running"
        return 0
    fi
    mkdir -p /opt/susanin/var
    rotate_log
    (
        trap '' HUP
        SUSANIN_CONF="$CONF" SUSANIN_LOG="$LOG" exec "$BIN" run
    ) >>"$LOG" 2>&1 </dev/null &
    echo $! > /opt/susanin/var/susanin-agent.pid
    sleep 2
    if is_running; then
        echo "[susanin] started, log: $LOG"
    else
        echo "[susanin] failed to start, see log: $LOG" >&2
        tail -n 10 "$LOG" 2>/dev/null || true
        return 1
    fi
}

cmd_start() {
    start_daemon || return 1
    cmd_web_start
}

stop_daemon() {
    if ! is_running; then
        echo "[susanin] not running"
        return 0
    fi
    for p in $(cat "$DAEMON_PID" 2>/dev/null) $(ps | grep 'susanin-agent run' | grep -v grep | awk '{print $1}'); do
        kill -TERM "$p" 2>/dev/null || true
    done
    _i=0
    while [ "$_i" -lt 10 ] && is_running; do
        sleep 1
        _i=$((_i + 1))
    done
    if is_running; then
        for p in $(cat "$DAEMON_PID" 2>/dev/null) $(ps | grep 'susanin-agent run' | grep -v grep | awk '{print $1}'); do
            kill -9 "$p" 2>/dev/null || true
        done
    fi
    rm -f "$DAEMON_PID"
    sleep 1
    echo "[susanin] stopped"
}

cmd_stop() {
    stop_daemon
    cmd_web_stop
}

cmd_restart() {
    # Демон перезапускаем, веб-панель НЕ трогаем (чтобы /api/restart не убивал
    # процесс, обслуживающий сам запрос); при необходимости поднимаем её.
    stop_daemon
    sleep 1
    start_daemon || return 1
    cmd_web_start
}

cmd_status() {
    if is_running; then
        echo "daemon: RUNNING"
    else
        echo "daemon: stopped"
    fi
    if is_web_running; then
        echo "web: RUNNING (pid $(cat "$WEB_PID" 2>/dev/null))"
    else
        echo "web: stopped"
    fi
    "$BIN" status
}

cmd_log() {
    n="${1:-30}"
    tail -n "$n" "$LOG" 2>/dev/null || echo "log is empty: $LOG"
}

cmd_reload() {
    pids=$(ps | grep 'susanin-agent run' | grep -v grep | awk '{print $1}')
    if [ -z "${pids:-}" ]; then
        echo "[susanin] not running" >&2
        return 1
    fi
    for p in $pids; do
        kill -HUP "$p" 2>/dev/null && echo "[susanin] reload signal sent (pid $p)"
    done
}

# rescan: заново определить текущие LAN/VPN из системы, обновить конфиг
# (egress_interface/egress_address/lan_interfaces/lan_subnets) и перечитать его.
cmd_rescan() {
    force=0
    [ "${1:-}" = "--force" ] && force=1
    echo "[susanin] re-scan network/VPN -> $CONF"
    d=$("$BIN" discover 2>/dev/null || true)
    [ -n "$d" ] || { echo "[susanin] discover failed" >&2; return 1; }
    printf '%s\n' "$d"
    # Обновляем ТОЛЬКО сетевые параметры (egress_* и lan_*). Остальные ключи
    # конфига не трогаем. Ручное значение egress_interface по умолчанию НЕ
    # затираем (интерфейс мог быть задан намеренно и сейчас просто не поднят,
    # напр. oc0 создаётся по требованию) — для принудительного авто-подбора
    # нужен флаг --force.
    _tmp="$CONF.rescan.$$"
    printf '%s\n' "$d" > "$_tmp"
    _changed=""
    _keep_egress=0
    while IFS='=' read -r k v; do
        case "$k" in
            egress_interface|egress_address|lan_interfaces|lan_subnets) ;;
            *) continue ;;
        esac
        [ -n "$v" ] || continue
        _cur=$(sed -n "s|^$k=||p" "$CONF" 2>/dev/null | head -n1)
        if [ "$k" = "egress_interface" ] && [ "$force" != "1" ] &&
           [ -n "$_cur" ] && [ "$_cur" != "$v" ]; then
            echo "[susanin]   egress_interface: оставляю '$_cur' (ручное значение; --force — переопределить)"
            _keep_egress=1
            continue
        fi
        if [ "$k" = "egress_address" ] && [ "$_keep_egress" = "1" ]; then
            continue
        fi
        [ "$_cur" = "$v" ] && continue
        if grep -q "^$k=" "$CONF" 2>/dev/null; then
            sed -i "s|^$k=.*|$k=$v|" "$CONF"
        else
            printf '%s=%s\n' "$k" "$v" >> "$CONF"
        fi
        echo "[susanin]   $k: ${_cur:-<нет>} -> $v"
        _changed="$_changed $k"
    done < "$_tmp"
    rm -f "$_tmp"
    if [ -z "$_changed" ]; then
        echo "[susanin] сетевые параметры без изменений"
    else
        echo "[susanin] обновлено:$_changed"
    fi
    cmd_reload || true
}

case "${1:-}" in
    start) cmd_start ;;
    stop) cmd_stop ;;
    restart) cmd_restart ;;
    web)
        case "${2:-status}" in
            start) cmd_web_start ;;
            stop) cmd_web_stop ;;
            restart) cmd_web_stop; sleep 1; cmd_web_start ;;
            status) if is_web_running; then echo "[susanin] web: RUNNING (pid $(cat "$WEB_PID" 2>/dev/null))"; else echo "[susanin] web: stopped"; fi ;;
            *) echo "usage: $0 web {start|stop|restart|status}" >&2; exit 2 ;;
        esac ;;
    status) cmd_status ;;
    reload) cmd_reload ;;
    rescan) cmd_rescan "${2:-}" ;;
    log) cmd_log "${2:-30}" ;;
    install) sh "$TOOLS/datapath.sh" up; "$BIN" setup ;;
    update) shift || true; sh "$TOOLS/update.sh" "$@" ;;
    uninstall) shift || true; sh "$TOOLS/uninstall.sh" "$@" ;;
    down) sh "$TOOLS/datapath.sh" down ;;
    reset|forget) "$BIN" reset "$2" ;;
    add) sh "$TOOLS/datapath.sh" add "$2" "$3" "$4" ;;
    del) sh "$TOOLS/datapath.sh" del "$2" "$3" ;;
    profiles) SUSANIN_CONF="$CONF" sh "$TOOLS/profiles.sh" "${2:-status}" ;;
    xray) shift; SUSANIN_CONF="$CONF" sh "$TOOLS/xray-egress.sh" "$@" ;;
    *)
        echo "usage: $0 {start|stop|restart|status|reload|rescan [--force]|web {start|stop|restart|status}|log [N]|install|update [ver]|uninstall [--purge]|down|reset <ip|domain>|forget <ip|domain>|add <ip> <tcp|udp> <test|ok>|del <ip> <tcp|udp>|profiles [up|down|status]|xray {run [ip]|stop|status|test <ip>|untest <ip>}}" >&2
        exit 2 ;;
esac
