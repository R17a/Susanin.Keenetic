#!/bin/sh
# diag-watch.sh — сборщик телеметрии Susanin.Keenetic + Teleproxy на роутере.
#
# Зачем: понять, растёт ли память (и у кого именно) и не крутится ли цикл
# репровижна датаплейна. Пишет одну строку на сэмпл, плюс периодически — топ
# процессов по RSS. Файл: /opt/susanin/var/diag-<дата>.log
#
#   sh tools/diag-watch.sh                 # 30 с, до Ctrl+C
#   INTERVAL=10 sh tools/diag-watch.sh     # каждые 10 с
#   COUNT=120 sh tools/diag-watch.sh       # 120 сэмплов и выход
#   OUT=/tmp/diag.log sh tools/diag-watch.sh
#
# Ничего не меняет в системе: только читает /proc, ipset, iptables, лог.
set -u

INTERVAL=${INTERVAL:-30}
COUNT=${COUNT:-0}                 # 0 = бесконечно
OUT=${OUT:-/opt/susanin/var/diag-$(date +%Y%m%d-%H%M%S).log}
LOG=${SUSANIN_LOG:-/opt/susanin/var/susanin.log}
TOPPROCS="ndm nginx xray susanin-agent teleproxy https_dns_proxy wind"

have() { command -v "$1" >/dev/null 2>&1; }

# Суммарный RSS процесса (с учётом потоков и нескольких экземпляров), КБ.
rss_of() {
    _sum=0
    for _pid in $(pidof "$1" 2>/dev/null); do
        _v=$(awk '/^VmRSS:/{print $2}' "/proc/$_pid/status" 2>/dev/null)
        [ -n "${_v:-}" ] && _sum=$((_sum + _v))
    done
    echo "$_sum"
}

meminfo() { # meminfo <Field>
    awk -v f="$1:" '$1==f{print $2}' /proc/meminfo 2>/dev/null
}

conntrack_count() {
    _c=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null)
    if [ -n "${_c:-}" ]; then echo "$_c"; else
        cat /proc/net/nf_conntrack 2>/dev/null | wc -l
    fi
}

sockstat_line() { # TCP: inuse N orphan N tw N alloc N mem N
    awk '/^TCP:/{print $3" "$4" "$5" "$6" "$7" "$8" "$9" "$10" "$11" "$12}' /proc/net/sockstat 2>/dev/null
}

ipset_sizes() {
    _out=""
    for _s in susanin_test_tcp susanin_test_udp susanin_ok_tcp susanin_ok_udp susanin_ok_net susanin_never; do
        if ipset list "$_s" >/dev/null 2>&1; then
            _n=$(ipset list "$_s" 2>/dev/null | grep -cE '^[0-9]+\.' || true)
            _out="$_out$_s=$_n;"
        fi
    done
    echo "${_out:-none}"
}

p5_state() {
    _rule=$(iptables -t mangle -S OUTPUT 2>/dev/null | grep -c 'uid-owner' || true)
    _pkts=$(iptables -t mangle -L OUTPUT -v -n 2>/dev/null | awk '/owner UID/{print $1}' | head -1)
    _rule5=$(ip rule show 2>/dev/null | grep -c 'lookup 110' || true)
    _route=$(ip route show table 110 2>/dev/null | grep -c 'default dev' || true)
    echo "rule=$_rule pkts=${_pkts:-0} iprule=$_rule5 route=$_route"
}

reprov_count() { # сколько раз в логе встречается слово re-provision
    [ -f "$LOG" ] || { echo 0; return; }
    grep -c 're-provision\|reprovision' "$LOG" 2>/dev/null || echo 0
}

xray_state() {
    if pidof xray >/dev/null 2>&1; then
        echo "up"; else echo "DOWN"; fi
}

nwg_state() {
    if ip link show nwg0 >/dev/null 2>&1 && ip link show nwg0 2>/dev/null | grep -q 'LOWER_UP'; then
        echo "up"; else echo "down"; fi
}

top_by_rss() {
    echo "  --- top RSS (KB) ---"
    for _p in $TOPPROCS; do
        _r=$(rss_of "$_p")
        [ "${_r:-0}" -gt 0 ] && echo "  $_p $_r"
    done | sort -k2 -nr | head -8
}

mkdir -p "$(dirname "$OUT")" 2>/dev/null || true

{
    echo "# diag-watch start $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "# susanin: $(susanin version 2>/dev/null || echo '?'), kernel: $(uname -r), arch: $(uname -m)"
    echo "# interval=${INTERVAL}s file=$OUT"
    echo "# columns: ts load mfree mavail slab sunreclaim ct tcp_inuse tcp_orphan tcp_tw xray nwg p5 reprov"
} >> "$OUT"

prev_reprov=$(reprov_count)
i=0
while :; do
    now=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    load=$(cut -d' ' -f1 /proc/loadavg 2>/dev/null)
    mfree=$(meminfo MemFree)
    mavail=$(meminfo MemAvailable)
    slab=$(meminfo Slab)
    sunrec=$(meminfo SUnreclaim)
    ct=$(conntrack_count)
    set -- $(sockstat_line)
    inuse=${1:-0}; orphan=${3:-0}; tw=${5:-0}
    xr=$(xray_state); nw=$(nwg_state); p5=$(p5_state)
    cur_reprov=$(reprov_count)
    drep=$((cur_reprov - prev_reprov))
    prev_reprov=$cur_reprov

    echo "$now load=$load mfree=$mfree mavail=$mavail slab=$slab sunreclaim=$sunrec ct=$ct tcp_inuse=$inuse tcp_orphan=$orphan tcp_tw=$tw xray=$xr nwg=$nw $p5 reprov_delta=$drep" >> "$OUT"

    # раз в 10 сэмплов — детали, раз в сэмпл при аномалии
    if [ $((i % 10)) -eq 0 ]; then
        {
            echo "  --- $(date -u '+%H:%M:%SZ') ---"
            echo "  ipset: $(ipset_sizes)"
            echo "  p5: $(p5_state)"
            echo "  egress: nwg0=$nw xray=$xr"
            top_by_rss
            echo "  log tail:"
            [ -f "$LOG" ] && tail -3 "$LOG" 2>/dev/null | sed 's/^/    /'
        } >> "$OUT"
    fi

    i=$((i + 1))
    [ "$COUNT" -gt 0 ] && [ "$i" -ge "$COUNT" ] && break
    sleep "$INTERVAL"
done

echo "# diag-watch done $(date -u '+%Y-%m-%dT%H:%M:%SZ') samples=$i" >> "$OUT"
echo "готово: $OUT ($i сэмплов)"
