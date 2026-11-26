#!/bin/sh
# egress-failover.sh — резервный egress через Xray (tproxy) для Susanin.Keenetic.
#
# Зачем отдельный скрипт. Штатный failover движка (egress_failback) выбирает
# живой egress среди ИНТЕРФЕЙСОВ. Переход «интерфейс (WireGuard/AmneziaWG) ->
# Xray» — это смена РЕЖИМА датаплейна (egress_type=interface <-> tproxy), а не
# выбор другого интерфейса: в tproxy трафик перехватывается REDIRECT-ом в
# nat PREROUTING, то есть раньше маршрутизации, и правила одного режима с
# правилами другого сосуществовать не могут. Поэтому переключение делает этот
# наблюдатель: меняет egress_type в susanin.conf и перезапускает агента
# (susanin.sh restart = datapath down + up, чистый переход).
#
# Схема работы:
#   * основной канал жив  -> egress_type=interface, egress_interface=<primary>,
#                            Xray остановлен (на слабом роутере это заметная
#                            экономия RAM/CPU);
#   * основной мёртв MISS проверок подряд -> поднимаем Xray, ЖДЁМ порт
#                            tproxy, и только потом переключаем режим;
#   * основной ожил RECOVER проверок подряд -> возвращаемся в interface,
#                            после чего гасим Xray (если keep_xray=0).
#
# Безопасность: если Xray не установлен/не поднялся, переключение в tproxy
# ОТМЕНЯЕТСЯ (иначе помеченный трафик уйдёт в чёрную дыру). В этом случае
# сохраняется штатное поведение движка — fail-open DIRECT.
#
# Использование:
#   egress-failover.sh run          цикл-наблюдатель (запускается из init.d)
#   egress-failover.sh once         одна проверка (для cron/отладки)
#   egress-failover.sh status       текущее состояние и последние строки лога
#   egress-failover.sh force-iface  принудительно вернуть основной канал
#   egress-failover.sh force-tproxy принудительно уйти на Xray
#
# Только для разработки: в поставку НЕ входит (см. devtools/README.md).
# Ставится вручную; init-скрипт — devtools/init/S96susanin-failover.
# Конфиг:    /opt/susanin/etc/failover.conf (необязателен; это ОТДЕЛЬНЫЙ файл,
#            чтобы ключи не терялись при `susanin-agent config set`/config_save).

PATH=/opt/sbin:/opt/bin:$PATH
export PATH

# Пути переопределяются окружением — это же имя SUSANIN_CONF использует
# datapath.sh, поэтому тестовый прогон не требует монтирования /opt/susanin.
CONF=${FAILOVER_CONF:-/opt/susanin/etc/failover.conf}
SCONF=${SUSANIN_CONF:-/opt/susanin/etc/susanin.conf}
VAR=${SUSANIN_VAR:-/opt/susanin/var}
STATE=$VAR/failover.state
LOG=$VAR/failover.log
SUSANIN_SH=${SUSANIN_SH:-/opt/susanin/tools/susanin.sh}
XRAY_BIN=${SUSANIN_XRAY_BIN:-/opt/sbin/xray}
XRAY_CFG=${SUSANIN_XRAY_CFG:-/opt/susanin/etc/xray-tproxy.json}
LOG_MAX=262144

# ------------------------------- значения по умолчанию ----------------------
ENABLE=1
PRIMARY=                 # пусто = первый интерфейс из egress_interface
PROBE="1.1.1.1 8.8.8.8"  # адреса для пробы ЧЕРЕЗ основной интерфейс
INTERVAL=10              # период проверки, с
MISS=3                   # неудач подряд -> уходим на Xray
RECOVER=6                # успехов подряд -> возвращаемся на основной
COOLDOWN=60              # пауза после переключения, с
BOOT_GRACE=60            # не трогать режим первые N секунд после старта, с
KEEP_XRAY=0              # 1 = не гасить Xray, когда основной канал работает
XRAY_INIT=/opt/etc/init.d/S93xray-tproxy
XRAY_WAIT=25             # сколько секунд ждать, пока Xray займёт порт tproxy
IFACE_CHECK=1            # 1 = «нет интерфейса» считается падением канала
                         # (на роутере); 0 = не проверять /sys/class/net
                         # (тесты, контейнеры, где нужного iface нет)

# --------------------------------- утилиты ----------------------------------
mkdir -p "$VAR" 2>/dev/null

log() {
    _line="$(date '+%Y-%m-%d %H:%M:%S') $*"
    if [ -f "$LOG" ] && [ "$(wc -c < "$LOG" 2>/dev/null || echo 0)" -gt "$LOG_MAX" ]; then
        mv -f "$LOG" "$LOG.1" 2>/dev/null || true
    fi
    printf '%s\n' "$_line" >> "$LOG" 2>/dev/null
    printf '%s\n' "$_line"
}

# cfg <ключ> <файл> [по умолчанию]: первое совпадение, кавычки снимаются.
cfg() {
    _k="$1"; _f="$2"; _d="${3:-}"
    _v=""
    [ -r "$_f" ] && _v=$(awk -F= -v k="$_k" '$1==k {sub(/^[^=]*=/,""); print; exit}' "$_f" 2>/dev/null)
    _v=$(printf '%s' "$_v" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    case "$_v" in
        \"*\") _v=$(printf '%s' "$_v" | sed 's/^"//; s/"$//') ;;
        \'*\') _v=$(printf '%s' "$_v" | sed "s/^'//; s/'$//") ;;
    esac
    if [ -n "$_v" ]; then printf '%s' "$_v"; else printf '%s' "$_d"; fi
}

load_conf() {
    [ -r "$CONF" ] || return 0
    ENABLE=$(cfg enable "$CONF" "$ENABLE")
    PRIMARY=$(cfg primary "$CONF" "$PRIMARY")
    PROBE=$(cfg probe "$CONF" "$PROBE")
    INTERVAL=$(cfg interval "$CONF" "$INTERVAL")
    MISS=$(cfg miss "$CONF" "$MISS")
    RECOVER=$(cfg recover "$CONF" "$RECOVER")
    COOLDOWN=$(cfg cooldown "$CONF" "$COOLDOWN")
    BOOT_GRACE=$(cfg boot_grace "$CONF" "$BOOT_GRACE")
    KEEP_XRAY=$(cfg keep_xray "$CONF" "$KEEP_XRAY")
    XRAY_INIT=$(cfg xray_init "$CONF" "$XRAY_INIT")
    XRAY_WAIT=$(cfg xray_wait "$CONF" "$XRAY_WAIT")
    IFACE_CHECK=$(cfg iface_check "$CONF" "$IFACE_CHECK")
    case "$ENABLE" in 1|true|yes|on) ENABLE=1 ;; *) ENABLE=0 ;; esac
    case "$KEEP_XRAY" in 1|true|yes|on) KEEP_XRAY=1 ;; *) KEEP_XRAY=0 ;; esac
    case "$IFACE_CHECK" in 0|false|no|off) IFACE_CHECK=0 ;; *) IFACE_CHECK=1 ;; esac
    for _n in INTERVAL MISS RECOVER COOLDOWN BOOT_GRACE XRAY_WAIT; do
        eval "_x=\$$_n"
        case "$_x" in ''|*[!0-9]*) eval "$_n=0" ;; esac
    done
    [ "$INTERVAL" -gt 0 ] 2>/dev/null || INTERVAL=10
    [ "$MISS" -gt 0 ] 2>/dev/null || MISS=3
    [ "$RECOVER" -gt 0 ] 2>/dev/null || RECOVER=6
    [ "$XRAY_WAIT" -gt 0 ] 2>/dev/null || XRAY_WAIT=25
}

# --- состояние (счётчики и время последнего переключения) ---
state_get() {
    _d="${2:-0}"
    _v=""
    [ -r "$STATE" ] && _v=$(awk -F= -v k="$1" '$1==k {print $2; exit}' "$STATE" 2>/dev/null)
    case "$_v" in ''|*[!0-9]*) _v="$_d" ;; esac
    printf '%s' "$_v"
}
state_set() {
    printf 'fails=%s\noks=%s\nlast_switch=%s\n' "$1" "$2" "$3" > "$STATE"
}

# --- конфиг Susanin.Keenetic ---
sconf_get() { cfg "$1" "$SCONF" "${2:-}"; }

sconf_set() { # sconf_set <ключ> <значение>
    _k="$1"; _v="$2"
    [ -f "$SCONF" ] || { log "нет $SCONF — не могу записать $_k"; return 1; }
    [ -f "$SCONF.failover-bak" ] || cp -f "$SCONF" "$SCONF.failover-bak" 2>/dev/null || true
    # Значение может содержать спецсимволы sed-замены (| \ & /) — экранируем.
    _v_esc=$(printf '%s' "$_v" | sed 's/[\\&|/]/\\&/g')
    if grep -q "^${_k}=" "$SCONF" 2>/dev/null; then
        sed -i "s|^${_k}=.*|${_k}=${_v_esc}|" "$SCONF" || return 1
    else
        printf '%s=%s\n' "$_k" "$_v" >> "$SCONF" || return 1
    fi
}

current_mode() { sconf_get egress_type "interface"; }

primary_if() {
    if [ -n "$PRIMARY" ]; then printf '%s' "$PRIMARY"; return 0; fi
    printf '%s' "$(sconf_get egress_interface "")" | sed 's/,.*//; s/^[[:space:]]*//; s/[[:space:]]*$//'
}

tproxy_port() {
    _p=$(sconf_get tproxy_port "")
    case "$_p" in ''|*[!0-9]*) _p=12345 ;; esac
    printf '%s' "$_p"
}

# Слушает ли кто-нибудь порт (по /proc/net/tcp*, без netstat/ss).
port_listen() {
    _hex=$(printf '%04X' "$1" 2>/dev/null) || return 1
    for _f in /proc/net/tcp /proc/net/tcp6; do
        [ -r "$_f" ] || continue
        if awk -v h=":$_hex" 'length($2) >= 5 && substr($2, length($2)-4) == h && $4 == "0A" { n++ } END { exit !(n > 0) }' "$_f" 2>/dev/null; then
            return 0
        fi
    done
    return 1
}

conntrack_flush_vpn() {
    command -v conntrack >/dev/null 2>&1 || return 0
    _ok=$(sconf_get mark_ok "0x20000000")
    _mask=$(sconf_get mark_mask "0x30000000")
    conntrack -D --mark "$_ok/$_mask" >/dev/null 2>&1 || true
}

xray_start() {
    [ -x "$XRAY_INIT" ] || { log "нет $XRAY_INIT — Xray не поднять"; return 1; }
    sh "$XRAY_INIT" start >/dev/null 2>&1
    return 0
}

xray_stop() {
    [ -x "$XRAY_INIT" ] || return 0
    sh "$XRAY_INIT" stop >/dev/null 2>&1
    return 0
}

# --- проба основного канала ---
# Только SO_BINDTODEVICE (-I <iface>): проба по адресу источника на Keenetic
# ушла бы по обычному маршруту (в интернет напрямую), а не в тоннель, и
# «мёртвый» канал выглядел бы живым.
probe_primary() {
    _if=$(primary_if)
    [ -n "$_if" ] || { log "не знаю основной интерфейс (egress_interface пуст)"; return 1; }
    # Наличие интерфейса проверяем, только если включён iface_check (на роутере
    # это полезный ранний признак «канал пропал»). В тестах и контейнерах нужного
    # интерфейса может не быть — там iface_check=0.
    if [ "$IFACE_CHECK" = "1" ] && [ -d /sys/class/net ] && \
       [ ! -d "/sys/class/net/$_if" ]; then
        return 1
    fi
    for _ip in $PROBE; do
        [ -n "$_ip" ] || continue
        if ping -I "$_if" -c 1 -W 2 -q "$_ip" >/dev/null 2>&1; then
            return 0
        fi
    done
    return 1
}

# --- переключения ---
restart_agent() {
    [ -x "$SUSANIN_SH" ] || { log "нет $SUSANIN_SH"; return 1; }
    sh "$SUSANIN_SH" restart >/dev/null 2>&1
    return 0
}

switch_to_tproxy() {
    _p=$(tproxy_port)
    if [ ! -x "$XRAY_BIN" ] || [ ! -f "$XRAY_CFG" ]; then
        log "ОТКАЗ: нет $XRAY_BIN или $XRAY_CFG — резервный канал через Xray недоступен"
        return 1
    fi
    log "основной канал мёртв -> поднимаю Xray и ухожу в tproxy"
    xray_start
    _i=0
    while [ "$_i" -lt "$XRAY_WAIT" ]; do
        port_listen "$_p" && break
        sleep 1
        _i=$((_i + 1))
    done
    if ! port_listen "$_p"; then
        log "ОТКАЗ: Xray не слушает :$_p — переключение отменено (иначе чёрная дыра)"
        return 1
    fi
    sconf_set egress_type tproxy || return 1
    restart_agent
    conntrack_flush_vpn
    log "режим tproxy активен (Xray :$_p)"
    return 0
}

switch_to_interface() {
    _if=$(primary_if)
    log "основной канал ($_if) восстановлен -> возвращаю egress_type=interface"
    sconf_set egress_type interface || return 1
    restart_agent
    conntrack_flush_vpn
    if [ "$KEEP_XRAY" = "1" ]; then
        log "режим interface активен (Xray оставлен запущенным, keep_xray=1)"
    else
        xray_stop
        log "режим interface активен, Xray остановлен"
    fi
    return 0
}

# --- один цикл проверки ---
tick() {
    _now=$(date +%s)
    _fails=$(state_get fails 0)
    _oks=$(state_get oks 0)
    _last=$(state_get last_switch 0)
    _mode=$(current_mode)

    if probe_primary; then
        _oks=$((_oks + 1))
        _fails=0
    else
        _fails=$((_fails + 1))
        _oks=0
    fi

    if [ $((_now - _last)) -lt "$COOLDOWN" ]; then
        state_set "$_fails" "$_oks" "$_last"
        return 0
    fi

    if [ "$_mode" != "tproxy" ] && [ "$_fails" -ge "$MISS" ]; then
        if switch_to_tproxy; then
            state_set 0 0 "$_now"
            return 0
        fi
        # Переключиться не удалось — не долбим Xray каждые 10 с.
        state_set "$_fails" 0 "$_now"
        return 0
    fi

    if [ "$_mode" = "tproxy" ] && [ "$_oks" -ge "$RECOVER" ]; then
        if switch_to_interface; then
            state_set 0 0 "$_now"
            return 0
        fi
        state_set 0 "$_oks" "$_now"
        return 0
    fi

    state_set "$_fails" "$_oks" "$_last"
    return 0
}

cmd_run() {
    load_conf
    if [ "$ENABLE" != "1" ]; then
        log "failover выключен (enable=0) — выхожу"
        return 0
    fi
    _boot=$(date +%s)
    log "наблюдатель запущен: основной=$(primary_if), проба='$PROBE', " \
        "интервал=${INTERVAL}s miss=$MISS recover=$RECOVER cooldown=${COOLDOWN}s"
    # sleep & wait: иначе TERM обрабатывается только после конца `sleep`, а
    # init-скрипт ждёт 5 с и добивает kill -9 (не успеваем записать лог/выйти
    # аккуратно). С `wait` трап срабатывает сразу.
    trap 'log "наблюдатель остановлен"; [ -n "${SLEEP_PID:-}" ] && kill "$SLEEP_PID" 2>/dev/null; exit 0' TERM INT
    while :; do
        load_conf
        [ "$ENABLE" = "1" ] || { log "failover выключен (enable=0) — выхожу"; return 0; }
        if [ $(( $(date +%s) - _boot )) -ge "$BOOT_GRACE" ]; then
            tick
        fi
        sleep "$INTERVAL" &
        SLEEP_PID=$!
        wait "$SLEEP_PID" 2>/dev/null || true
        SLEEP_PID=""
    done
}

cmd_status() {
    load_conf
    _if=$(primary_if)
    _mode=$(current_mode)
    _p=$(tproxy_port)
    echo "failover:     $([ "$ENABLE" = 1 ] && echo ENABLED || echo DISABLED)"
    echo "primary iface: $_if"
    echo "egress_type:  $_mode"
    echo "проба:        $PROBE (через $_if)"
    echo "пороги:       miss=$MISS recover=$RECOVER interval=${INTERVAL}s cooldown=${COOLDOWN}s"
    if [ -d "/sys/class/net/$_if" ]; then echo "iface:        UP"; else echo "iface:        ОТСУТСТВУЕТ"; fi
    if probe_primary; then echo "проба сейчас: OK (основной канал отвечает)"; else echo "проба сейчас: FAIL (основной канал не отвечает)"; fi
    if port_listen "$_p"; then echo "Xray :$_p:    LISTEN"; else echo "Xray :$_p:    не слушает"; fi
    if [ -r "$STATE" ]; then echo "счётчики:     $(tr '\n' ' ' < "$STATE")"; fi
    [ -r "$LOG" ] && { echo "--- $LOG (хвост) ---"; tail -n 10 "$LOG"; }
}

force() { # force <interface|tproxy>
    load_conf
    if [ "$1" = "tproxy" ]; then
        switch_to_tproxy && state_set 0 0 "$(date +%s)"
    else
        switch_to_interface && state_set 0 0 "$(date +%s)"
    fi
}

case "${1:-}" in
    run)          cmd_run ;;
    once)         load_conf; tick ;;
    status)       cmd_status ;;
    force-iface)  force interface ;;
    force-tproxy) force tproxy ;;
    *)
        cat <<EOF
Usage: $0 {run|once|status|force-iface|force-tproxy}

  run            цикл-наблюдатель (запускается из /opt/etc/init.d/S96susanin-failover)
  once           одна проверка (cron/отладка)
  status         состояние, проба и хвост лога
  force-iface    принудительно вернуть основной канал (интерфейс)
  force-tproxy   принудительно перевести трафик на Xray

Конфиг: $CONF
EOF
        exit 2 ;;
esac
