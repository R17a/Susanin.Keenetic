#!/bin/sh
# xray-egress.sh — безопасное включение/выключение XRay-egress для Susanin.
#
# XRay-клиент на роутере: inbound dokodemo-door (REDIRECT, TCP) для Susanin,
# плюс локальный socks (127.0.0.1:1080, udp:true) для UDP-релея демона.
# Сервер XRay (Reality) — на стороне VPS, тут не трогаем.
#
# Usage:
#   xray-egress.sh run [IP] [proto]  # БЕЗОПАСНЫЙ тест: очищает обученное, гасит
#                                    # vpn_always, поднимает Xray+Susanin и
#                                    # заворачивает ТОЛЬКО [IP] (proto: tcp|udp|both)
#   xray-egress.sh enable            # БОЕВОЙ режим: egress_type=tproxy + udp_relay,
#                                    # запуск Xray и рестарт агента (vpn_always НЕ гасим)
#   xray-egress.sh disable           # выключить боевой режим и вернуть всё в DIRECT
#   xray-egress.sh default           # ВЕРНУТЬ ВСЁ в обычный канал (direct):
#                                    # стоп всего, снятие правил, сброс conntrack,
#                                    # восстановление vpn_always
#   xray-egress.sh stop              # = default (синоним)
#   xray-egress.sh status
#   xray-egress.sh test <IP> [proto] # добавить адрес в test (tcp|udp|both)
#   xray-egress.sh untest <IP> [proto]
#
# POSIX sh (busybox ash compatible).
set -u

PREFIX=/opt/susanin
CONF=${SUSANIN_CONF:-$PREFIX/etc/susanin.conf}
XCFG=$PREFIX/etc/xray-tproxy.json
VA=$PREFIX/etc/vpn_always.txt
VABAK=$PREFIX/etc/vpn_always.txt.test-bak
INITD=/opt/etc/init.d
SH=$PREFIX/tools/susanin.sh
DP=$PREFIX/tools/datapath.sh

port=$(sed -n 's/^tproxy_port=//p' "$CONF" 2>/dev/null | tail -n1)
[ -n "$port" ] || port=12345
urp=$(sed -n 's/^udp_relay_port=//p' "$CONF" 2>/dev/null | tail -n1)
[ -n "$urp" ] || urp=1081
et=$(sed -n 's/^egress_type=//p' "$CONF" 2>/dev/null | tail -n1)
[ -n "$et" ] || et=interface

say() { echo "[xray-egress] $*"; }
xray_running()  { pidof xray >/dev/null 2>&1; }
agent_running() { pidof susanin-agent >/dev/null 2>&1; }
net_ok()        { nslookup ya.ru >/dev/null 2>&1; }

ensure_tproxy_cfg() {
    grep -q '^egress_type=' "$CONF" 2>/dev/null \
        && sed -i 's|^egress_type=.*|egress_type=tproxy|' "$CONF" \
        || echo 'egress_type=tproxy' >> "$CONF"
    grep -q '^tproxy_port=' "$CONF" 2>/dev/null \
        || echo "tproxy_port=$port" >> "$CONF"
    grep -q '^udp_relay=' "$CONF" 2>/dev/null \
        && sed -i 's|^udp_relay=.*|udp_relay=1|' "$CONF" \
        || echo 'udp_relay=1' >> "$CONF"
    grep -q '^udp_relay_port=' "$CONF" 2>/dev/null \
        || echo 'udp_relay_port=1081' >> "$CONF"
    grep -q '^socks_addr=' "$CONF" 2>/dev/null \
        || echo 'socks_addr=127.0.0.1' >> "$CONF"
    grep -q '^socks_port=' "$CONF" 2>/dev/null \
        || echo 'socks_port=1080' >> "$CONF"
    et=tproxy
}

start_xray() {
    [ -f "$XCFG" ] || { say "нет $XCFG — положите конфиг Xray"; return 1; }
    if xray_running; then
        if netstat -lnt 2>/dev/null | grep -q '127.0.0.1:1080'; then
            say "xray уже запущен (socks 1080 слушается)"; return 0
        fi
        say "xray запущен без socks 1080 — перезапускаю с $XCFG"
        for p in $(pidof xray); do kill -9 "$p" 2>/dev/null; done
        sleep 1
    fi
    if [ -x "$INITD/S93xray-tproxy" ]; then
        sh "$INITD/S93xray-tproxy" start
    else
        /opt/sbin/xray run -config "$XCFG" >>"$PREFIX/var/xray.log" 2>&1 &
    fi
}

stop_xray() {
    for p in $(pidof xray); do kill "$p" 2>/dev/null; done
    sleep 1
    for p in $(pidof xray); do kill -9 "$p" 2>/dev/null; done
}

clean_rules() {
    # Страховка: снять jump и цепочку SUSANIN ПРЯМО (чтобы метки прекратились,
    # даже если datapath down сорвётся).
    iptables -t mangle -D PREROUTING -j SUSANIN 2>/dev/null || true
    iptables -t mangle -F SUSANIN 2>/dev/null || true
    iptables -t mangle -X SUSANIN 2>/dev/null || true

    SUSANIN_TPROXY_PORT="$port" SUSANIN_UDP_RELAY_PORT="$urp" \
        sh "$DP" down >/dev/null 2>&1 || true
    # остатки TPROXY (mangle)
    iptables -t mangle -S PREROUTING 2>/dev/null | grep -- '-j TPROXY' | \
        while read -r l; do
            iptables -t mangle -D PREROUTING $(echo "$l" | sed 's/^-A PREROUTING //') 2>/dev/null || true
        done
    # тестовые правила для 1.1.1.1 / любые наши REDIRECT
    for ip in 1.1.1.1 8.8.8.8; do
        iptables -t nat -D PREROUTING -p tcp -d "$ip" -j REDIRECT --to-ports "$port" 2>/dev/null || true
        iptables -t mangle -D PREROUTING -p udp -d "$ip" -j TPROXY --on-port "$urp" --tproxy-mark 0x1/0xffffffff 2>/dev/null || true
    done
    ip route del local default dev lo table 100 2>/dev/null || true
    ip route flush table 100 2>/dev/null || true
    ip rule del fwmark 0x1 lookup 100 2>/dev/null || true
    # добить возможные сторонние прокси-демоны
    for p in $(pidof hev-socks5-tunnel) $(pidof badvpn-tun2socks) $(pidof sing-box); do
        kill -9 "$p" 2>/dev/null
    done
    # сбросить conntrack (чтобы «залипшие» метки/сессии не держали чёрную дыру)
    conntrack -F >/dev/null 2>&1 || true
}

# Полный возврат в обычный канал (direct).
reset_all() {
    agent_running && sh "$SH" stop >/dev/null 2>&1 || true
    for p in $(pidof susanin-agent); do kill -9 "$p" 2>/dev/null; done
    clean_rules
    stop_xray
    # восстановить vpn_always, если тест его «гасил»
    [ -f "$VABAK" ] && mv -f "$VABAK" "$VA" && say "vpn_always восстановлен"
    echo "--- default route ---"
    ip route show default 2>/dev/null || true
    if net_ok; then say "default: интернет OK, всё в DIRECT"; else
        say "default: сделано, но проверка DNS не прошла — смотри 'ip route show default'"
    fi
}

status() {
    say "egress_type=$et tproxy_port=$port udp_relay_port=$urp"
    if xray_running;  then say "xray: RUNNING";          else say "xray: stopped"; fi
    if agent_running; then say "susanin-agent: RUNNING"; else say "susanin-agent: stopped"; fi
    echo "--- слушатели ($port / 1080 / $urp) ---"
    netstat -lntu 2>/dev/null | grep -E ":$port |127.0.0.1:1080|:$urp " || echo "(нет)"
    echo "--- nat REDIRECT ---"
    iptables -t nat -S PREROUTING 2>/dev/null | grep "REDIRECT --to-ports $port" || echo "(нет)"
    echo "--- mangle TPROXY ---"
    iptables -t mangle -S PREROUTING 2>/dev/null | grep TPROXY || echo "(нет)"
}

add_test() { # IP proto
    case "${2:-tcp}" in
        both) sh "$SH" add "$1" tcp test; sh "$SH" add "$1" udp test ;;
        tcp|udp) sh "$SH" add "$1" "$2" test ;;
        *) echo "proto: tcp|udp|both"; exit 2 ;;
    esac
}
del_test() {
    case "${2:-tcp}" in
        both) sh "$SH" del "$1" tcp; sh "$SH" del "$1" udp ;;
        tcp|udp) sh "$SH" del "$1" "$2" ;;
        *) echo "proto: tcp|udp|both"; exit 2 ;;
    esac
}

case "${1:-}" in
    run)
        ensure_tproxy_cfg
        # БЕЗОПАСНЫЙ тест: чистим обученное и временно гасим vpn_always,
        # чтобы в туннель уходил ТОЛЬКО тестовый адрес.
        [ -f "$VABAK" ] || cp -a "$VA" "$VABAK" 2>/dev/null || true
        : > "$VA" 2>/dev/null || true
        agent_running && sh "$SH" flush >/dev/null 2>&1 || true

        start_xray
        i=0
        while [ "$i" -lt 15 ]; do
            netstat -lnt 2>/dev/null | grep -q '127.0.0.1:1080' && break
            sleep 1; i=$((i + 1))
        done
        netstat -lnt 2>/dev/null | grep -q '127.0.0.1:1080' \
            || say "ВНИМАНИЕ: Xray socks 1080 не поднялся"

        sh "$SH" restart || true
        sleep 3
        [ -n "${2:-}" ] && add_test "$2" "${3:-tcp}"

        # ПРОВЕРКА СВЯЗНОСТИ — если интернет пропал, откатываемся сразу.
        if ! net_ok; then
            say "НЕТ СВЯЗНОСТИ после старта — ОТКАТ (default)"
            reset_all
            exit 1
        fi
        status
        say "готово. Тестовый адрес завернут; остальное идёт напрямую."
        ;;
    default|stop)
        reset_all
        ;;
    enable)
        # БОЕВОЙ режим: egress_type=tproxy + udp_relay=1, БЕЗ гашения vpn_always.
        # Учимся/заворачиваем как обычно, но egress — XRay.
        ensure_tproxy_cfg
        [ -x /opt/sbin/xray ] || say "ВНИМАНИЕ: нет /opt/sbin/xray (положите бинарь Xray)"
        [ -f "$XCFG" ] || say "ВНИМАНИЕ: нет $XCFG (положите конфиг Xray)"
        start_xray
        sh "$SH" restart || true
        sleep 3
        if ! net_ok; then
            say "НЕТ СВЯЗНОСТИ после включения — ОТКАТ (default)"
            reset_all
            exit 1
        fi
        status
        say "tproxy ВКЛЮЧЁН: трафик ok/vpn_always идёт через XRay (TCP REDIRECT + UDP relay)."
        say "откат: sh $0 disable"
        ;;
    disable)
        reset_all
        [ -f "$INITD/S93xray-tproxy" ] && sh "$INITD/S93xray-tproxy" stop >/dev/null 2>&1 || true
        say "tproxy выключен, всё в DIRECT."
        say "чтобы не поднималось после перезагрузки: chmod -x $INITD/S93xray-tproxy (и уберите autostart S94susanin, если не нужен)."
        ;;
    status) status ;;
    test)   [ -n "${2:-}" ] || { echo "usage: $0 test <IP> [tcp|udp|both]"; exit 2; }; add_test "$2" "${3:-tcp}" ;;
    untest) [ -n "${2:-}" ] || { echo "usage: $0 untest <IP> [tcp|udp|both]"; exit 2; }; del_test "$2" "${3:-tcp}" ;;
    *) echo "usage: $0 {run [IP] [tcp|udp|both]|enable|disable|default|stop|status|test <IP> [proto]|untest <IP> [proto]}"; exit 2 ;;
esac
