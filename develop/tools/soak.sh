#!/bin/sh
# soak.sh — длительный прогон Susanin.Keenetic с записью метрик.
#
# Зачем: найти утечки памяти, рост conntrack/наборов, деградацию за сутки-двое.
# Одна строка на сэмпл (key=value) — удобно грепать и строить график.
#
# Запуск (на роутере, можно в фоне):
#   sh /opt/susanin/tools/soak.sh              # интервал 60 c, /opt/susanin/var/soak.log
#   sh /opt/susanin/tools/soak.sh 300 /tmp/soak.log &
#   tail -f /opt/susanin/var/soak.log
# Остановка: Ctrl-C (или kill) — печатает сводку по памяти/росту.
#
# POSIX sh (busybox ash compatible).
set -u

PREFIX=${SUSANIN_PREFIX:-/opt/susanin}
INTERVAL=${1:-60}
OUT=${2:-$PREFIX/var/soak.log}
PIDF="$PREFIX/var/susanin-agent.pid"
LOG="$PREFIX/var/susanin.log"
SETS="susanin_ok_tcp susanin_ok_udp susanin_test_tcp susanin_test_udp susanin_ok_net susanin_never susanin_direct"

case "$INTERVAL" in ''|*[!0-9]*) INTERVAL=60 ;; esac
[ "$INTERVAL" -ge 1 ] || INTERVAL=1
mkdir -p "$(dirname "$OUT")" 2>/dev/null || true

rss_of() {  # rss_of <pid> -> КБ (0 если нет)
    [ -n "${1:-}" ] && [ -r "/proc/$1/status" ] || { echo 0; return; }
    awk '/^VmRSS:/{print $2; exit}' "/proc/$1/status" 2>/dev/null || echo 0
}
cpu_of() {  # cpu_of <pid> -> тики utime+stime (0 если нет)
    [ -n "${1:-}" ] && [ -r "/proc/$1/stat" ] || { echo 0; return; }
    awk '{print $14+$15}' "/proc/$1/stat" 2>/dev/null || echo 0
}
count_set() {  # count_set <имя ipset>
    command -v ipset >/dev/null 2>&1 || { echo 0; return; }
    ipset list "$1" 2>/dev/null | grep -cE '^[0-9]' || true
}

first=""
last=""
n=0

sample() {
    _pid=$(cat "$PIDF" 2>/dev/null || true)
    # Именно НАШ Xray (по cmdline с нашим конфигом): `pidof xray` в métriques
    # ловил бы и чужой процесс (XKeen), искажая RSS/CPU.
    _xpid=""
    if [ -r /opt/susanin/var/xray.pid ]; then
        _xp=$(cat /opt/susanin/var/xray.pid 2>/dev/null || true)
        case "$_xp" in ''|*[!0-9]*) _xp="" ;; esac
        if [ -n "$_xp" ] && [ -r "/proc/$_xp/cmdline" ] && \
           tr '\0' ' ' < "/proc/$_xp/cmdline" 2>/dev/null | grep -q 'xray-tproxy.json' && tr '\0' ' ' < "/proc/$_xp/cmdline" 2>/dev/null | grep -q -- '-config'; then
            _xpid="$_xp"
        fi
    fi
    if [ -z "$_xpid" ]; then
        for _d in /proc/[0-9]*; do
            [ -r "$_d/cmdline" ] || continue
            if tr '\0' ' ' < "$_d/cmdline" 2>/dev/null | grep -q 'xray-tproxy.json' && tr '\0' ' ' < "$_d/cmdline" 2>/dev/null | grep -q -- '-config'; then
                _xpid="${_d#/proc/}"
                break
            fi
        done
    fi
    _ts=$(date +%Y-%m-%dT%H:%M:%S 2>/dev/null || echo "?")
    _up=$(cut -d. -f1 /proc/uptime 2>/dev/null || echo 0)
    _load=$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null | tr ' ' '/' || echo "?")
    _ram=$(free -k 2>/dev/null | awk '$1=="Mem:"{print $4}' || echo 0)
    _arss=$(rss_of "$_pid"); _acpu=$(cpu_of "$_pid")
    _xrss=$(rss_of "$_xpid"); _xcpu=$(cpu_of "$_xpid")
    _ct=$(wc -l < /proc/net/nf_conntrack 2>/dev/null || echo 0)
    _logb=0; _loge=0
    if [ -r "$LOG" ]; then
        _logb=$(wc -c < "$LOG" 2>/dev/null || echo 0)
        _loge=$(grep -c 'ERR:' "$LOG" 2>/dev/null || echo 0)
    fi
    _free=$(df -k "$PREFIX" 2>/dev/null | awk 'NR>1{print $4; exit}' || echo 0)
    _sets=""
    for _s in $SETS; do
        _sets="$_sets $_s=$(count_set $_s)"
    done
    printf '%s uptime=%s load=%s ram_free_kb=%s agent_rss_kb=%s agent_cpu=%s xray_rss_kb=%s xray_cpu=%s ct=%s log_bytes=%s log_err=%s prefix_free_kb=%s%s\n' \
        "$_ts" "${_up:-0}" "${_load:-?}" "${_ram:-0}" "${_arss:-0}" "${_acpu:-0}" \
        "${_xrss:-0}" "${_xcpu:-0}" "${_ct:-0}" "${_logb:-0}" "${_loge:-0}" \
        "${_free:-0}" "$_sets"
}

summary() {
    [ -n "$first" ] && [ -n "$last" ] || return 0
    echo "--- сводка soak ($n сэмплов) ---" >&2
    _t1=$(printf '%s\n' "$first" | sed -n 's/ .*//p')
    _a1=$(printf '%s\n' "$first" | sed -n 's/.*agent_rss_kb=\([0-9]*\).*/\1/p')
    _a2=$(printf '%s\n' "$last"  | sed -n 's/.*agent_rss_kb=\([0-9]*\).*/\1/p')
    _x1=$(printf '%s\n' "$first" | sed -n 's/.*xray_rss_kb=\([0-9]*\).*/\1/p')
    _x2=$(printf '%s\n' "$last"  | sed -n 's/.*xray_rss_kb=\([0-9]*\).*/\1/p')
    _u1=$(printf '%s\n' "$first" | sed -n 's/.* uptime=\([0-9]*\).*/\1/p')
    _u2=$(printf '%s\n' "$last"  | sed -n 's/.* uptime=\([0-9]*\).*/\1/p')
    _el=$(( ${_u2:-0} - ${_u1:-0} ))
    [ "$_el" -gt 0 ] || _el=1
    echo "  начало: ${_t1:-?}, длительность: $((_el / 3600)) ч $(((_el % 3600) / 60)) мин" >&2
    echo "  susanin-agent RSS: ${_a1:-?} -> ${_a2:-?} КБ (≈ $(( (${_a2:-0} - ${_a1:-0}) * 3600 / _el )) КБ/ч)" >&2
    echo "  xray RSS:          ${_x1:-?} -> ${_x2:-?} КБ (≈ $(( (${_x2:-0} - ${_x1:-0}) * 3600 / _el )) КБ/ч)" >&2
    echo "  устойчивый рост RSS (>~1 МБ/сутки) = кандидат на утечку; приложите $OUT к issue" >&2
}

trap 'summary; exit 0' INT TERM

echo "# soak: интервал ${INTERVAL}c, файл $OUT" >&2
while :; do
    _line=$(sample)
    n=$((n + 1))
    [ -n "$first" ] || first="$_line"
    last="$_line"
    echo "$_line" >> "$OUT"
    if [ $((n % 10)) -eq 0 ]; then
        echo "# $n сэмплов, последняя: $_line" >&2
    fi
    sleep "$INTERVAL"
done
