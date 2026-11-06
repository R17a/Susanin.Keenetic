#!/bin/sh
# xray-socks.sh — включить локальный SOCKS5-инбаунд Xray для сторонних сервисов
# (например MTProxy/Teleproxy), чтобы их трафик шёл по Reality, а не напрямую
# и не через WireGuard, который могут душить.
#
#   sh tools/xray-socks.sh status
#   sh tools/xray-socks.sh enable   [--port 1080]
#   sh tools/xray-socks.sh disable
#
# Правит /opt/susanin/etc/xray-tproxy.json (первый элемент "inbounds"),
# делает резервную копию .bak и перезапускает наш Xray.
set -eu

CFG=${XRAY_CFG:-/opt/susanin/etc/xray-tproxy.json}
INIT=${XRAY_INIT:-/opt/etc/init.d/S93xray-tproxy}
PORT=1080
TAG=socks-in

say() { echo "[xray-socks] $*"; }

case "${1:-status}" in
    enable)
        shift || true
        while [ $# -gt 0 ]; do
            case "$1" in
                --port) PORT="$2"; shift 2 ;;
                *) say "неизвестный аргумент: $1" >&2; exit 2 ;;
            esac
        done
        [ -f "$CFG" ] || { say "нет $CFG"; exit 1; }
        # В штатном конфиге Susanin socks-инбаунд уже есть (127.0.0.1:1080).
        # Проверяем по протоколу, а не по тегу: иначе добавляли второй с тем же
        # тегом и Xray падал с "existing tag found".
        if grep -q "\"protocol\"[[:space:]]*:[[:space:]]*\"socks\"" "$CFG" 2>/dev/null; then
            _p=$(grep -A2 "\"protocol\"[[:space:]]*:[[:space:]]*\"socks\"" "$CFG" | sed -n "s/.*\"port\"[[:space:]]*:[[:space:]]*\\([0-9]*\\).*/\\1/p" | head -1)
            say "SOCKS-инбаунд уже есть в конфиге (port=${_p:-?})"
            exit 0
        fi
        cp -f "$CFG" "$CFG.bak"
        # Вставляем первым элементом массива inbounds — так JSON остаётся валидным
        # независимо от содержимого остальных инбаундов.
        awk -v port="$PORT" -v tag="$TAG" '
            !done && match($0, /"inbounds"[[:space:]]*:[[:space:]]*\[/) {
                print
                printf "    {\"tag\":\"%s\",\"listen\":\"127.0.0.1\",\"port\":%d,\"protocol\":\"socks\",\"settings\":{\"auth\":\"noauth\",\"udp\":false}},\n", tag, port
                done = 1
                next
            }
            { print }
        ' "$CFG.bak" > "$CFG"
        say "добавлен socks-inbound 127.0.0.1:$PORT (резервная копия $CFG.bak)"
        if [ -x "$INIT" ]; then
            sh "$INIT" restart >/dev/null 2>&1 || true
            say "Xray перезапущен"
        fi
        ;;
    disable)
        [ -f "$CFG" ] || { say "нет $CFG"; exit 1; }
        grep -q "\"$TAG\"" "$CFG" 2>/dev/null || { say "SOCKS-инбаунда нет"; exit 0; }
        cp -f "$CFG" "$CFG.bak"
        grep -v "\"$TAG\"" "$CFG.bak" > "$CFG"
        say "socks-inbound удалён (резервная копия $CFG.bak)"
        if [ -x "$INIT" ]; then
            sh "$INIT" restart >/dev/null 2>&1 || true
        fi
        ;;
    status)
        if [ -f "$CFG" ] && grep -q "\"$TAG\"" "$CFG" 2>/dev/null; then
            say "socks-inbound: настроен"
        else
            say "socks-inbound: нет"
        fi
        if netstat -ltn 2>/dev/null | grep -q '127\.0\.0\.1:1080'; then
            say "127.0.0.1:1080: слушает"
        else
            say "127.0.0.1:1080: не слушает"
        fi
        ;;
    *)
        echo "usage: $0 {status|enable [--port N]|disable}" >&2
        exit 2 ;;
esac
