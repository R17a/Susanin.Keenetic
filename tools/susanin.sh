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
#   sh susanin.sh down           # remove data plane rules (daemon keeps running)
#   sh susanin.sh add <ip> tcp|udp test|ok
#   sh susanin.sh del <ip> tcp|udp

set -eu

BIN=/opt/susanin/bin/susanin-agent
CONF=/opt/susanin/etc/susanin.conf
LOG=/opt/susanin/var/susanin.log
TOOLS=/opt/susanin/tools

is_running() {
    ps | grep susanin-agent | grep -v grep >/dev/null 2>&1
}

cmd_start() {
    if is_running; then
        echo "[susanin] already running"
        return 0
    fi
    mkdir -p /opt/susanin/var
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

cmd_stop() {
    if ! is_running; then
        echo "[susanin] not running"
        return 0
    fi
    for p in $(ps | grep susanin-agent | grep -v grep | awk '{print $1}'); do
        kill -TERM "$p" 2>/dev/null || true
    done
    _i=0
    while [ "$_i" -lt 10 ] && is_running; do
        sleep 1
        _i=$((_i + 1))
    done
    if is_running; then
        for p in $(ps | grep susanin-agent | grep -v grep | awk '{print $1}'); do
            kill -9 "$p" 2>/dev/null || true
        done
    fi
    sleep 1
    echo "[susanin] stopped"
}

cmd_status() {
    if is_running; then
        echo "daemon: RUNNING"
    else
        echo "daemon: stopped"
    fi
    "$BIN" status
}

cmd_log() {
    n="${1:-30}"
    tail -n "$n" "$LOG" 2>/dev/null || echo "log is empty: $LOG"
}

case "${1:-}" in
    start) cmd_start ;;
    stop) cmd_stop ;;
    restart) cmd_stop; sleep 1; cmd_start ;;
    status) cmd_status ;;
    log) cmd_log "${2:-30}" ;;
    install) sh "$TOOLS/datapath.sh" up; "$BIN" setup ;;
    update) shift || true; sh "$TOOLS/update.sh" "$@" ;;
    uninstall) shift || true; sh "$TOOLS/uninstall.sh" "$@" ;;
    down) sh "$TOOLS/datapath.sh" down ;;
    add) sh "$TOOLS/datapath.sh" add "$2" "$3" "$4" ;;
    del) sh "$TOOLS/datapath.sh" del "$2" "$3" ;;
    *)
        echo "usage: $0 {start|stop|restart|status|log [N]|install|update [ver]|uninstall [--purge]|down|add <ip> <tcp|udp> <test|ok>|del <ip> <tcp|udp>}" >&2
        exit 2 ;;
esac
