#!/bin/sh
# 60-susanin-forward.sh — хук NDM: вернуть разрешение FORWARD по метке VPN.
#
# Зачем: NDM периодически пересобирает netfilter и снимает чужие правила из
# filter/FORWARD. Агент замечает пропажу быстрым контролем (раз в 5 с) и
# пересобирает датаплейн, но до этого трафик с меткой VPN упирается в политику
# DROP: на пересборку уходит 5–8 секунд, и это видно как «подвисание» видео
# или страницы. Хук вызывается самим NDM сразу после пересборки и возвращает
# одно правило за десятки миллисекунд.
#
# Доступа сам по себе хук не даёт: метку ставит только агент и только пока
# живёт туннель. Если агент не запущен — хук молчит.
#
# POSIX sh (busybox ash compatible).

CONF=/opt/susanin/etc/susanin.conf
AGENT_PID=/opt/susanin/var/susanin-agent.pid

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

"$IPT" -C FORWARD -m mark --mark "$_ok/$_mask" -j ACCEPT 2>/dev/null && exit 0
"$IPT" -A FORWARD -m mark --mark "$_ok/$_mask" -j ACCEPT 2>/dev/null || true
exit 0
