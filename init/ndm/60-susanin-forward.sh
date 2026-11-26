#!/bin/sh
# 60-susanin-forward.sh — хук NDM: вернуть разрешение FORWARD по метке VPN
# и перехват DNS клиентов LAN.
#
# Зачем: NDM периодически пересобирает netfilter и снимает чужие правила из
# filter/FORWARD. Агент замечает пропажу быстрым контролем (раз в 5 с) и
# пересобирает датаплейн, но до этого трафик с меткой VPN упирается в политику
# DROP: на пересборку уходит 5–8 секунд, и это видно как «подвисание» видео
# или страницы. Хук вызывается самим NDM сразу после пересборки и возвращает
# одно правило за десятки миллисекунд.
#
# Вторая часть — nat-цепочка dns_lan: её NDM тоже сносит при каждой пересборке
# (раз в ~25 минут). Без неё DNS клиентов LAN уходит мимо туннеля, а агент
# замечает это только своим тиком. Перехват возвращается в фоне: iptables -w
# внутри datapath.sh ждёт тот же xtables-lock, и хук не должен задерживать
# пересборку NDM.
#
# Доступа сам по себе хук не даёт: метку ставит только агент и только пока
# живёт туннель. Если агент не запущен — хук молчит.
#
# POSIX sh (busybox ash compatible).

CONF=/opt/susanin/etc/susanin.conf
AGENT_PID=/opt/susanin/var/susanin-agent.pid
TOOLS=/opt/susanin/tools

[ -r "$CONF" ] || exit 0
_ap=$(cat "$AGENT_PID" 2>/dev/null || true)
[ -n "$_ap" ] || exit 0
kill -0 "$_ap" 2>/dev/null || exit 0

IPT=${SUSANIN_IPTABLES:-}
if [ -z "$IPT" ]; then
    for _b in /opt/sbin /opt/bin /usr/sbin /usr/bin; do
        [ -x "$_b/iptables" ] && { IPT="$_b/iptables"; break; }
    done
fi
[ -n "$IPT" ] || exit 0

# Те же значения, что читает агент; по умолчанию — как в config.c.
_ok=$(sed -n 's/^[[:space:]]*mark_ok[[:space:]]*=[[:space:]]*//p' "$CONF" 2>/dev/null | tail -n 1 | tr -d ' \r')
_mask=$(sed -n 's/^[[:space:]]*mark_mask[[:space:]]*=[[:space:]]*//p' "$CONF" 2>/dev/null | tail -n 1 | tr -d ' \r')
[ -n "$_ok" ] || _ok=0x20000000
[ -n "$_mask" ] || _mask=0x30000000

if ! "$IPT" -C FORWARD -m mark --mark "$_ok/$_mask" -j ACCEPT 2>/dev/null; then
    "$IPT" -A FORWARD -m mark --mark "$_ok/$_mask" -j ACCEPT 2>/dev/null || true
fi

# --- перехват DNS клиентов LAN -------------------------------------------
# Ставим только если он вообще включён и цепочки с прыжком нет: иначе каждый
# вызов хука дёргал бы datapath.sh впустую.
_dl=$(sed -n 's/^[[:space:]]*dns_lan[[:space:]]*=[[:space:]]*//p' "$CONF" 2>/dev/null | tail -n 1 | tr -d ' \r')
if [ "$_dl" = "1" ] && [ -x "$TOOLS/datapath.sh" ] &&
   ! "$IPT" -t nat -C PREROUTING -j SUSANIN_DNSLAN 2>/dev/null; then
    (
        _lock=/tmp/susanin-dnslan-hook.lock
        mkdir "$_lock" 2>/dev/null || exit 0
        trap 'rmdir "$_lock" 2>/dev/null' EXIT
        if command -v timeout >/dev/null 2>&1; then
            timeout 20 sh "$TOOLS/datapath.sh" dns-lan-up >/dev/null 2>&1 || true
        else
            sh "$TOOLS/datapath.sh" dns-lan-up >/dev/null 2>&1 || true
        fi
    ) </dev/null >/dev/null 2>&1 &
fi

exit 0
