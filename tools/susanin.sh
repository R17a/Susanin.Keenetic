#!/bin/sh
# susanin.sh — управление демоном Susanin.Keenetic.
#
# Usage:
#   sh susanin.sh start          # запустить демон в фоне (лог пишется)
#   sh susanin.sh stop           # остановить демон
#   sh susanin.sh restart        # перезапустить
#   sh susanin.sh status         # состояние демона и дата-плейна
#   sh susanin.sh log            # последние 30 строк лога
#   sh susanin.sh log 100        # последние 100 строк лога
#   sh susanin.sh install        # настройка дата-плейна (setup + up)
#   sh susanin.sh down           # снять правила дата-плейна (без остановки демона)
#   sh susanin.sh add  <ip> tcp|udp test|ok   # вручную добавить IP в VPN
#   sh susanin.sh del  <ip> tcp|udp           # убрать IP

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
        echo "[susanin] уже запущен"
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
        echo "[susanin] запущен, лог: $LOG"
    else
        echo "[susanin] НЕ запустился, смотри лог: $LOG" >&2
        tail -n 10 "$LOG" 2>/dev/null || true
        return 1
    fi
}

cmd_stop() {
    if ! is_running; then
        echo "[susanin] и так не запущен"
        return 0
    fi
    for p in $(ps | grep susanin-agent | grep -v grep | awk '{print $1}'); do
        kill -9 "$p" 2>/dev/null || true
    done
    sleep 1
    echo "[susanin] остановлен"
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
    tail -n "$n" "$LOG" 2>/dev/null || echo "лог пуст: $LOG"
}

case "${1:-}" in
    start) cmd_start ;;
    stop) cmd_stop ;;
    restart) cmd_stop; sleep 1; cmd_start ;;
    status) cmd_status ;;
    log) cmd_log "${2:-30}" ;;
    install) sh "$TOOLS/datapath.sh" up; "$BIN" setup ;;
    down) sh "$TOOLS/datapath.sh" down ;;
    add) sh "$TOOLS/datapath.sh" add "$2" "$3" "$4" ;;
    del) sh "$TOOLS/datapath.sh" del "$2" "$3" ;;
    *)
        echo "usage: $0 {start|stop|restart|status|log [N]|install|down|add <ip> <tcp|udp> <test|ok>|del <ip> <tcp|udp>}" >&2
        exit 2 ;;
esac
