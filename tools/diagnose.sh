#!/bin/sh
# diagnose.sh — диагностика Susanin.Keenetic.
#
# Когда что-то работает не так — запустите этот скрипт: он проверит окружение,
# настройки, правила и списки, а в конце выдаст РЕКОМЕНДАЦИИ.
#
# Запуск:
#   sh /opt/susanin/tools/diagnose.sh [--etc DIR] [--dns IP]
#
# Для отправки полного отчёта (логи и состояние) используйте report.sh.
# POSIX sh (busybox ash compatible).
#
# ---------------------------------------------------------------------------
# Что проверяет и какие проблемы выявляет (по опыту проекта и разбору логов):
#
#  1) Окружение и версия
#     - нет susanin-agent (не установлен / неудачное обновление);
#     - нет пакетов iptables/ipset/conntrack/ip — правила не создаются вообще
#       (в логе это выглядело как «provisioning failed», пока не добавили
#       причину).
#  2) Конфиг
#     - egress_interface указывает на отсутствующий интерфейс (VPN удалён или
#       переименован) — демон «помнит» старое подключение, маршрут не встаёт;
#     - пустые lan_interfaces/lan_subnets — трафик LAN не анализируется;
#     - disk_mode=soft на флешке и наоборот (не критично, но полезно видеть);
#     - vpn_always_dns пусто (auto) — риск, что список резолвится через
#       подменяемый/неотвечающий DNS.
#  3) Правила (data plane)
#     - нет цепочки SUSANIN, нет ip rule на таблицу VPN, нет default в таблице —
#       трафик идёт мимо VPN (частый симптом «ничего не работает»);
#     - обнаружены правила политик Keenetic (fwmark 0xffffaXX) — клиенты,
#       привязанные к «Приоритетам подключений», Susanin.Keenetic не обрабатывает
#       (в логах это видно как mark=0xffffaXX в conntrack);
#     - наборы susanin_ok_* пусты — автообучение не работает.
#  4) Списки vpn_always / vpn_never
#     - домен без A-записей на apex — НЕ ошибка: для CDN это норма, демон сам
#       зондирует поддомены (resolve_dom: apex пуст → пробы susanin-XXXX.domain);
#       такие строки идут в отдельный счётчик «без A на apex», без списка
#       «проблем» и рекомендаций по каждой;
#     - одна и та же строка в обоих списках (конфликт; приоритет у «напрямую»).
#
# В конце печатается блок «Рекомендации» — что именно поправить.
# ---------------------------------------------------------------------------
set -u

# Прогресс показываем только в интерактивном терминале (stderr — tty), чтобы не
# засорять вывод при перенаправлении (например, в report.sh).
ttyst=0
[ -t 2 ] && ttyst=1

ETCDIR=""
DNS=""
while [ $# -gt 0 ]; do
    case "$1" in
        --etc) ETCDIR="$2"; shift ;;
        --dns) DNS="$2"; shift ;;
        -h|--help) echo "usage: $0 [--etc DIR] [--dns IP]"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
    shift
done

if [ -z "$ETCDIR" ]; then
    if [ -d /opt/susanin/etc ]; then
        ETCDIR=/opt/susanin/etc
    elif [ -d /etc/susanin ]; then
        ETCDIR=/etc/susanin
    else
        ETCDIR=/opt/susanin/etc
    fi
fi
CONF="$ETCDIR/susanin.conf"

cfg() { # cfg <key> — значение из susanin.conf (или пусто)
    [ -f "$CONF" ] || return 0
    sed -n "s/^$1=[ \t]*//p" "$CONF" | head -n1
}

RECS=""
rec() { RECS="${RECS}
  - $*"; }
sec() { echo; echo "== $* =="; }

# ------------------------------------------------------------------ окружение
sec "Окружение"
A=/opt/susanin/bin/susanin-agent
if [ ! -x "$A" ]; then
    A=$(command -v susanin-agent 2>/dev/null || true)
fi
if [ -n "$A" ] && [ -x "$A" ]; then
    echo "agent: $("$A" version 2>/dev/null)"
else
    echo "agent: НЕ НАЙДЕН"
            rec "Программа (susanin-agent) не найдена — проверьте установку или обновление."
fi

for t in iptables ipset conntrack ip; do
    if command -v "$t" >/dev/null 2>&1; then
        echo "tool $t: ok"
    else
        echo "tool $t: НЕТ"
        rec "Не хватает пакета '$t'. Установите: opkg update && opkg install $t"
    fi
done

# ------------------------------------------------------------------- конфиг
sec "Конфиг ($CONF)"
EGR=$(cfg egress_interface)
LAN=$(cfg lan_interfaces)
SUB=$(cfg lan_subnets)
TBL=$(cfg routing_table)
DM=$(cfg disk_mode)
DNS_CFG=$(cfg vpn_always_dns)
[ -n "$TBL" ] || TBL=100
echo "egress: ${EGR:-?}"
echo "lan: ${LAN:-?} / ${SUB:-?}"
echo "table: $TBL, disk_mode: ${DM:-?}, vpn_always_dns: ${DNS_CFG:-<auto>}"

# Наши метки (как в susanin.conf): по ним проверяются правила ip rule.
MT=$(cfg mark_test); [ -n "$MT" ] || MT=0x10000000
MO=$(cfg mark_ok);   [ -n "$MO" ] || MO=0x20000000
MM=$(cfg mark_mask); [ -n "$MM" ] || MM=0x30000000
echo "marks: test=$MT ok=$MO mask=$MM"

# WAN-IP нужен, чтобы отличить блокировку на стороне сайта (403 по IP) от
# проблем маршрутизации: см. TROUBLESHOOTING, «Сайт отдаёт 403/блок-страницу».
if command -v ip >/dev/null 2>&1; then
    WANIP=$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n1)
    [ -n "$WANIP" ] && echo "WAN-IP: $WANIP"
fi

if [ -n "$EGR" ]; then
    oldifs=$IFS; IFS=','
    for i in $EGR; do
        IFS=$oldifs
        i=$(printf '%s' "$i" | tr -d ' \t')
        case "$i" in
            tproxy|xray)
                # Кандидат-резерв через Xray (не интерфейс): проверяем порт.
                _tp=$(cfg tproxy_port); [ -n "$_tp" ] || _tp=12345
                if netstat -lnt 2>/dev/null | grep -q ":${_tp}[ \t]"; then
                    echo "egress $i: Xray слушает порт $_tp — кандидат доступен"
                else
                    echo "egress $i: Xray НЕ слушает порт $_tp — переключение в tproxy не произойдёт (fail-safe)"
                    rec "Кандидат '$i' в egress_interface: Xray не слушает tproxy_port=$_tp. Запустите /opt/etc/init.d/S93xray-tproxy start или уберите '$i' из списка."
                fi ;;
            *)
                if [ -e "/sys/class/net/$i" ]; then
                    echo "egress $i: существует"
                else
                    echo "egress $i: ОТСУТСТВУЕТ"
                    rec "VPN-интерфейс '$i' не найден. Включите VPN-подключение или укажите верное имя в egress_interface."
                fi ;;
        esac
        IFS=','
    done
    IFS=$oldifs
fi

# -------------------------------------------- возможности и память (0.4.0-dev5)
sec "Возможности и память (dev5)"
echo "egress pool: failback=$(cfg egress_failback) debounce=$(cfg egress_failback_debounce)s race=$(cfg egress_race)"
echo "dns_sniff=$(cfg dns_sniff) offload=$(cfg kernel_offload) kernel_egress=$(cfg kernel_egress) xray_watchdog=$(cfg xray_watchdog)"
echo "dns_hijack=$(cfg dns_hijack) target=$(cfg dns_hijack_target) always_cdn_prefix=$(cfg vpn_always_cdn_prefix)"
ET=$(cfg egress_type); [ -n "$ET" ] || ET=interface
if [ "$ET" = "tproxy" ]; then
    echo "tproxy: port=$(cfg tproxy_port) udp_relay=$(cfg udp_relay)"
    # Проверяем ИМЕННО наш Xray (по cmdline с нашим конфигом), а не любой процесс
    # с именем xray: чужой (XKeen) не должен выглядеть как наш (замечание ревью).
    XPID=""
    if [ -r /opt/susanin/var/xray.pid ]; then
        _xp=$(cat /opt/susanin/var/xray.pid 2>/dev/null || true)
        case "$_xp" in
            ''|*[!0-9]*) _xp="" ;;
        esac
        if [ -n "$_xp" ] && [ -r "/proc/$_xp/cmdline" ] && \
           tr '\0' ' ' < "/proc/$_xp/cmdline" 2>/dev/null | grep -q '/opt/susanin/etc/xray-tproxy.json'; then
            XPID="$_xp"
        fi
    fi
    if [ -z "$XPID" ]; then
        for _d in /proc/[0-9]*; do
            [ -r "$_d/cmdline" ] || continue
            if tr '\0' ' ' < "$_d/cmdline" 2>/dev/null | grep -q '/opt/susanin/etc/xray-tproxy.json'; then
                XPID="${_d#/proc/}"
                break
            fi
        done
    fi
    if [ -n "$XPID" ]; then
        echo "xray: RUNNING (pid=$XPID, наш конфиг)"
    else
        echo "xray: не запущен с нашим конфигом"
        if pidof xray >/dev/null 2>&1; then
            echo "xray: ВНИМАНИЕ — есть ЧУЖОЙ процесс xray ($(pidof xray | tr '\n' ' ')): порт $(cfg tproxy_port) может быть занят им"
            rec "Запущен чужой Xray (не с нашим конфигом). Susanin.Keenetic его не трогает; если он занял tproxy_port=$(cfg tproxy_port), смените tproxy_port или остановите чужой процесс сами."
        fi
        rec "egress_type=tproxy, но Xray не запущен — трафик идёт DIRECT. Поднимите: /opt/etc/init.d/S93xray-tproxy start (при xray_watchdog=1 агент поднимет сам)."
    fi
    QB=$(cfg quic_block)
    if [ "$QB" = "1" ]; then
        echo "quic_block: 1 (HTTP/3 из LAN -> TCP)"
    else
        echo "quic_block: ${QB:-<нет ключа>} — HTTP/3 (UDP 443) из LAN НЕ блокируется"
        rec "egress_type=tproxy, а quic_block не равен 1: QUIC помеченных адресов уходит в UDP-релей (Xray), браузер ждёт HTTP/3 и страница может грузиться бесконечно (частый симптом «сайт висит, а ping/curl работают»). Поставьте quic_block=1 в susanin.conf и перезапустите: sh /opt/susanin/tools/susanin.sh restart"
    fi
fi
if command -v free >/dev/null 2>&1; then
    echo "--- память ---"
    free 2>/dev/null | sed -n '1,3p'
    if [ -r /proc/swaps ] && [ ! -s /proc/swaps ]; then
        echo "swap: нет"
        rec "Нет swap, а RAM ~128 МБ: возможен OOM-killer. Для tproxy задайте xray_gomemlimit (напр. 64MiB) и xray_gogc (напр. 50). На USB-носителе можно swap-файл; на встроенной flash — только zram."
    fi
    _top=$(ps w 2>/dev/null | sort -k4 -rn 2>/dev/null | head -n4)
    [ -n "$_top" ] && { echo "--- топ по памяти ---"; echo "$_top"; }
fi
if command -v dmesg >/dev/null 2>&1; then
    _oom=$(dmesg 2>/dev/null | grep -iE 'killed process|out of memory' | tail -n3)
    if [ -n "$_oom" ]; then
        echo "--- OOM в dmesg ---"; echo "$_oom"
        rec "В dmesg есть OOM-killer. Ограничьте память Xray (xray_gomemlimit/xray_gogc) и/или добавьте swap/zram; включённый xray_watchdog поднимет упавший Xray."
    fi
fi

# Профили маршрутизации (P2): заданные профили, живой egress, набор.
_pn=0
for _i in 1 2 3 4; do
    _nm=$(cfg "profile${_i}_name")
    [ -n "$_nm" ] || continue
    _eg=$(cfg "profile${_i}_egress")
    _tb=$(cfg "profile${_i}_table"); [ -n "$_tb" ] || _tb=$((200 + _i))
    _au=$(cfg "profile${_i}_auto")
    _live=""
    if [ -n "$_eg" ]; then
        oldifs=$IFS; IFS=','
        for _e in $_eg; do
            IFS=$oldifs
            _e=$(printf '%s' "$_e" | tr -d ' \t')
            if [ -e "/sys/class/net/$_e" ]; then _live="$_e"; break; fi
            IFS=','
        done
        IFS=$oldifs
    fi
    echo "profile $_nm: egress=${_eg:-?} live=${_live:-НЕТ} table=$_tb auto=${_au:-0}"
    if [ -z "$_live" ]; then
        rec "Профиль '$_nm': ни один egress (${_eg:-?}) не существует — маршрут профиля не поднимется."
    fi
    _pn=$((_pn + 1))
done
if [ -d /opt/susanin/etc/profiles.d ]; then
    _pd=$(ls -1 /opt/susanin/etc/profiles.d/*.conf 2>/dev/null | wc -l)
    echo "profiles.d: $_pd файл(ов)"
fi
[ "$_pn" -eq 0 ] && echo "профили: не заданы"

# ------------------------------------------------------------ правила (data plane)
sec "Правила"
if command -v iptables >/dev/null 2>&1; then
    if iptables -t mangle -S SUSANIN >/dev/null 2>&1; then
        echo "цепочка SUSANIN: ok"
    else
        echo "цепочка SUSANIN: НЕТ"
        rec "Правила Susanin.Keenetic не созданы. Проверьте, что установлены ipset и iptables, затем: susanin.sh restart"
    fi
fi
if command -v ip >/dev/null 2>&1; then
    # rule_marks <mark> <mask> <table> — есть ли НАШЕ правило. Ядро печатает
    # «fwmark 0x20000000/0x30000000 lookup 100», но старые сборки ставили правило
    # без маски — принимаем обе формы (как src/ops.c: rule_fwmark_present()).
    rule_marks() {
        ip rule show 2>/dev/null | grep -Eq "fwmark $1(/$2)? .*lookup $3( |\$)"
    }
    for _m in "test:$MT" "ok:$MO"; do
        _nm=${_m%%:*}; _mk=${_m#*:}
        if rule_marks "$_mk" "$MM" "$TBL"; then
            echo "ip rule $_nm (fwmark $_mk/$MM) -> table $TBL: ok"
        else
            echo "ip rule $_nm (fwmark $_mk/$MM) -> table $TBL: НЕТ"
            rec "Нет правила ip rule для метки $_nm (fwmark $_mk/$MM) на таблицу $TBL — этот трафик идёт мимо VPN. Перезапустите: susanin.sh restart"
        fi
    done
    # Чужие правила на НАШЕЙ таблице: иначе диагностика пишет «ok» при том, что
    # наши правила сняты, а на таблицу смотрит кто-то другой.
    _foreign=$(ip rule show 2>/dev/null | grep "lookup $TBL" 2>/dev/null | \
               grep -v "fwmark $MT" | grep -v "fwmark $MO" | \
               grep -vE 'fwmark 0xffffa' | head -n3)
    if [ -n "$_foreign" ]; then
        echo "внимание: на таблице $TBL есть ЧУЖИЕ правила:"
        printf '  %s\n' "$_foreign"
        rec "На таблице $TBL найдены правила с другими метками (другое ПО или старая версия). Susanin.Keenetic их не создаёт; если они перехватывают трафик — уберите их сами или смените routing_table."
    fi
    if ip route show table "$TBL" 2>/dev/null | grep -q '^default'; then
        echo "default в table $TBL: ok"
    else
        echo "default в table $TBL: НЕТ"
        rec "В таблице $TBL нет маршрута по умолчанию — проверьте, что VPN-подключение включено."
    fi
    if ip rule show 2>/dev/null | grep -qE 'fwmark 0xffffa'; then
        echo "политики Keenetic (fwmark 0xffffaXX): есть"
        rec "У части устройств включён «Приоритет подключений» Keenetic. Для них маршрут выбирает Keenetic, а Susanin.Keenetic не участвует. Если устройство должно управляться Susanin.Keenetic — снимите у него политику (оставьте «по умолчанию»)."
    fi
fi
if command -v ipset >/dev/null 2>&1; then
    okc=$(ipset list susanin_ok_tcp 2>/dev/null | grep -cE '^[0-9]+\.')
    okn=$(ipset list susanin_ok_net 2>/dev/null | grep -cE '^[0-9]+\.')
    echo "наборы: ok_tcp=$okc, ok_net=$okn"
    if [ "${okc:-0}" -eq 0 ] && [ "${okn:-0}" -eq 0 ]; then
        rec "Список выученных адресов пуст — обучение не работает. Проверьте пакеты и правила и что через роутер идёт трафик."
    fi
fi

# --------------------------------------------------- port-aware (экспериментально)
PA=$(cfg port_aware)
if [ "$PA" = "1" ]; then
    echo "port_aware=1: наборы ok/test хранят ПАРЫ адрес+порт (матч dst,dst)"
    if command -v ipset >/dev/null 2>&1; then
        _pt=$(ipset list -t susanin_ok_tcp 2>/dev/null | sed -n 's/^Type: //p')
        echo "  тип susanin_ok_tcp: ${_pt:-<набора нет>}"
        case "$_pt" in
            hash:ip,port) ;;
            "") rec "port_aware=1, но набора susanin_ok_tcp нет: перезапустите 'sh /opt/susanin/tools/susanin.sh restart' — datapath создаст наборы нужного типа." ;;
            *)  rec "port_aware=1, но набор susanin_ok_tcp типа '$_pt' (ожидается hash:ip,port): перезапустите агент, datapath пересоздаст наборы при 'up'." ;;
        esac
    fi
    _pa_free=$(free -k 2>/dev/null | awk '$1=="Mem:"{print $4}')
    [ -n "${_pa_free:-}" ] && echo "  свободной памяти: $((_pa_free / 1024)) МБ"
    rec "port_aware=1 (экспериментально): пар в наборах больше, чем адресов — на слабом mipsel это заметнее по памяти. Смотрите RSS Xray/агента и OOM в dmesg; при нехватке памяти верните port_aware=0 и перезапустите агент (наборы пересоздадутся как hash:ip)."
fi

# --------------------------------------------------------------------- списки
ips_of() {
    if [ -n "$DNS" ]; then
        nslookup "$1" "$DNS" 2>&1
    else
        nslookup "$1" 2>&1
    fi | awk '/^Name:/{f=1; next}
              f && /^Address/ {
                  for (i = 1; i <= NF; i++)
                      if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { print $i; break }
              }'
}
is_ip4()  { printf '%s' "$1" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; }
is_cidr() { printf '%s' "$1" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$'; }

# Домен без A на apex — не ошибка: для CDN это норма (работают поддомены), а
# демон с 0.3.10 сам зондирует поддомены (resolve_dom: apex пуст → пробы
# susanin-XXXX.domain). Поэтому такие строки считаем отдельно и НЕ заваливаем
# пользователя списком «проблем». Реально нерезолвимые имена видны по нулевому
# числу адресов и упоминаются в сводке.
DNS_HIJ=0; DNS_HIJ_EX=""

check_list() {
    f="$1"; label="$2"
    if [ ! -f "$f" ]; then
        echo "$label: файла нет ($f)"
        return
    fi
    echo "$label ($f):"
    n_all=$(grep -vcE '^[[:space:]]*(#|$)' "$f" 2>/dev/null)
    [ -n "$n_all" ] || n_all=0
    if [ "$ttyst" = 1 ] && [ "$n_all" -gt 0 ]; then
        printf '  проверяю %s строк (DNS-запрос к каждому домену; может занять ~минуту, Ctrl+C — прервать)\n' \
               "$n_all" >&2
    fi
    tot=0; ok=0; zone=0; idx=0; hij=0; hijex=""
    zex=""
    # `|| [ -n "$raw" ]` — иначе последняя строка списка без перевода строки в
    # конце не проверяется: read при EOF без разделителя возвращает не-ноль,
    # хотя значение уже присвоено (та же ловушка, что была в tools/profiles.sh).
    while IFS= read -r raw || [ -n "$raw" ]; do
        e=$(printf '%s' "$raw" | sed 's/#.*//' | tr -d ' \t\r')
        [ -z "$e" ] && continue
        tot=$((tot + 1))
        idx=$((idx + 1))
        [ "$ttyst" = 1 ] && printf '\r  [%d/%d] %-45s' "$idx" "$n_all" "$e" >&2
        if is_ip4 "$e" || is_cidr "$e"; then
            ok=$((ok + 1))
            continue
        fi
        name=$(printf '%s' "$e" | sed 's/^\*\.//')
        # Резолвим один раз: и адреса, и признак подмены (127.0.0.1/::1).
        # Важно: смотрим только секцию ответа (после "Name:"), иначе адрес
        # самого резолвера в шапке даёт ложное срабатывание.
        if [ -n "$DNS" ]; then ans=$(nslookup "$name" "$DNS" 2>&1); else ans=$(nslookup "$name" 2>&1); fi
        ans=$(printf '%s\n' "$ans" | awk '/^Name:/{f=1} f')
        ips=$(printf '%s\n' "$ans" | awk '/^Address/ {
                 for (i = 1; i <= NF; i++)
                     if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { print $i; break } }')
        if printf '%s\n' "$ans" | grep -qE '(^|[^0-9])127\.0\.0\.1([^0-9]|$)|(^|[^0-9a-fA-F])::1([^0-9a-fA-F]|$)'; then
            hij=$((hij + 1))
            [ -z "$hijex" ] && hijex="$name"
        fi
        if [ -n "$ips" ]; then
            ok=$((ok + 1))
        else
            zone=$((zone + 1))
            [ -z "$zex" ] && zex="$name"
        fi
    done < "$f"
    [ "$ttyst" = 1 ] && printf '\r                                                                      \r' >&2
    echo "  итог: строк $tot, с адресами $ok, без A на apex $zone"
    if [ "$zone" -gt 0 ]; then
        echo "  без A на apex: $zone (для CDN это норма, демон проверит поддомены; напр. $zex)"
    fi
    if [ "$hij" -gt 0 ]; then
        echo "  ПОДМЕНА DNS (127.0.0.1/::1): $hij (напр. $hijex)"
        DNS_HIJ=$((DNS_HIJ + hij))
        [ -z "$DNS_HIJ_EX" ] && DNS_HIJ_EX="$hijex"
    fi
}

sec "Списки"
check_list "$ETCDIR/vpn_always.txt" "vpn_always"
check_list "$ETCDIR/vpn_never.txt" "vpn_never"

if [ -f "$ETCDIR/vpn_always.txt" ] && [ -f "$ETCDIR/vpn_never.txt" ]; then
    conf=$(awk '
        { l = $0; sub(/#.*/, "", l); gsub(/[ \t\r]/, "", l);
          if (l == "") next;
          if (FNR == NR) { a[l] = 1; next }
          if (a[l]) print l }
    ' "$ETCDIR/vpn_always.txt" "$ETCDIR/vpn_never.txt")
    if [ -n "$conf" ]; then
        echo "  конфликты always/never (приоритет — «напрямую»):"
        printf '    %s\n' $conf
        rec "Один и тот же адрес есть и в vpn_always, и в vpn_never — побеждает «напрямую». Уберите лишнюю строку: $(printf '%s' "$conf" | head -n1)"
    fi
fi

# Wildcard-зоны в vpn_never: пиннится только apex + типовые поддомены, поэтому
# «сайт открывается частично» — типичный симптом. Сверяем, сколько адресов реально
# в наборе, и напоминаем правило «для сервисов с несколькими хостами — явные имена».
if [ -f "$ETCDIR/vpn_never.txt" ]; then
    _zw=$(grep -vE '^[[:space:]]*(#|$)' "$ETCDIR/vpn_never.txt" 2>/dev/null | grep -c '^\*\.' || true)
    _nn=0
    if command -v ipset >/dev/null 2>&1; then
        _nn=$(ipset list susanin_never 2>/dev/null | grep -cE '^[0-9]+\.' || true)
    fi
    echo "vpn_never: wildcard-зон=${_zw:-0}, адресов в наборе susanin_never=${_nn:-0}"
    if [ "${_zw:-0}" -gt 0 ]; then
        rec "В vpn_never есть wildcard-зоны ($_zw): по зоне пиннятся apex и типовые поддомены (www/cdn/api/static/m + пробы), но у сервисов с несколькими хостами часть адресов может остаться вне набора — тогда «сайт открывается частично». Для таких сервисов указывайте явные имена, а не wildcard."
    fi
    if [ "${_zw:-0}" -gt 0 ] && [ "${_nn:-0}" -le "${_zw:-0}" ] && command -v ipset >/dev/null 2>&1; then
        rec "Набор susanin_never почти пуст при непустом списке: зоны не разрешились (DNS) либо правила не применены. Проверьте вывод выше и перезапустите: susanin.sh reload"
    fi
fi

# Подмена DNS (127.0.0.1/::1): домен не завернуть в VPN, пока резолвер не исправлен.
if [ "${DNS_HIJ:-0}" -gt 0 ]; then
    echo
    echo "!! DNS WARNING: ${DNS_HIJ} домен(ов) из списков резолвятся в 127.0.0.1/::1 (напр. ${DNS_HIJ_EX:-?})."
    echo "   Это подмена DNS (блок-лист). Пока так, эти адреса через VPN не пойдут."
    if ls /tmp/run/dotproxy-*.yml >/dev/null 2>&1 && \
       grep -lq 'GETDNS_TRANSPORT_TLS' /tmp/run/dotproxy-*.yml 2>/dev/null; then
        echo "   Обнаружен DNS-over-TLS (DoT, порт 853) — провайдеры часто его глушат."
    fi
    echo "   Почините DNS на роутере: выключите DoT и включите DoH (443) или обычный DNS (напр. 1.1.1.1)."
    rec "DNS подменяет адреса: ${DNS_HIJ} домен(ов) из списков дают 127.0.0.1/::1 (напр. ${DNS_HIJ_EX:-?}). Выключите DNS-over-TLS (порт 853 часто глушат) и включите DoH или обычный DNS (напр. 1.1.1.1)."
fi

if [ -z "$DNS_CFG" ] && [ -z "$DNS" ]; then
    echo "  DNS для списков: auto (системный, при 127.0.0.1 — адрес LAN-моста)"
fi

# r7.9: локальные подсети, не покрытые lan_subnets (гостевой SSID/mesh) —
# клиенты в них обрабатываться не будут; раньше это было видно только по
# «почему у меня ничего не работает» со стороны клиента.
SUBS=$(cfg lan_subnets)
_unc=$(ip -4 -o addr show 2>/dev/null | awk '{print $2" "$4}' | awk -v subs="$SUBS" '
BEGIN { n = split(subs, a, ","); m = 0;
        for (i = 1; i <= n; i++) {
            gsub(/[[:space:]]/, "", a[i]); if (a[i] == "") continue;
            split(a[i], p, "/");
            base[m] = p[1]; pre[m] = (p[2] == "" ? 32 : p[2] + 0); m++;
        } }
{
    iface = $1; cidr = $2; split(cidr, q, "/"); ip = q[1]; pl = q[2] + 0;
    if (ip ~ /^127\./ || ip ~ /^169\.254\./) next;
    split(ip, o, ".");
    v = o[1] * 16777216 + o[2] * 65536 + o[3] * 256 + o[4];
    hit = 0;
    for (i = 0; i < m; i++) {
        split(base[i], b, ".");
        bv = b[1] * 16777216 + b[2] * 65536 + b[3] * 256 + b[4];
        sz = 2 ^ (32 - pre[i]);
        if (v >= bv && v - bv < sz) { hit = 1; break }
    }
    if (!hit) printf "%s %s/%d\n", iface, base_str(cidr), pl
}
function base_str(c) { return c }
' 2>/dev/null)
if [ -n "$_unc" ]; then
    echo "Локальные подсети вне lan_subnets (их клиенты НЕ обрабатываются):"
    printf '%s\n' "$_unc" | while read _i _c; do
        echo "   $_i: $_c"
    done
    rec "Добавьте нужные подсети в lan_subnets (панель или: susanin-agent config set lan_subnets \"$SUBS,$(printf '%s' "$_unc" | head -n1 | awk '{print $2}')\"), затем susanin restart. Если подсеть — гостевая и намеренно изолирована, игнорируйте."
fi

# -------------------------------------------------- OpenConnect (серверный VPN)
# Регрессия: клиенты OpenConnect не обрабатывались, потому что `oc*`
# не было в lan_interfaces (tun создаётся по требованию клиента и теряется при
# «rescan» с отключённым телефоном). Диагностика обязана это показывать.
sec "OpenConnect (серверный VPN на этом роутере)"
OC_SRV=0
[ -f /var/run/ocserv/ocserv.conf ] && OC_SRV=1
if command -v iptables >/dev/null 2>&1; then
    iptables -t mangle -S _NDM_OCSRVVPN_MARK >/dev/null 2>&1 && OC_SRV=1
fi
if command -v ipset >/dev/null 2>&1; then
    ipset list -n _NDM_SRV_OCSRVVPN >/dev/null 2>&1 && OC_SRV=1
fi
if [ "$OC_SRV" = "1" ]; then
    echo "OpenConnect-сервер: обнаружен"
    case ",$LAN," in
        *oc*)
            echo "lan_interfaces: содержит oc* — клиенты обрабатываются" ;;
        *)
            echo "lan_interfaces: НЕТ ни одного oc*"
            rec "На роутере работает OpenConnect-сервер, а в lan_interfaces нет 'oc+': клиенты (телефон/ноутбук) не обрабатываются — часть сайтов висит, обычный интернет «тормозит». Добавьте 'oc+' В КОНЕЦ списка lan_interfaces и выполните: susanin.sh restart" ;;
    esac
    case ",$LAN," in
        *oc*) ;;
        *)
            if printf '%s' "$SUB" | grep -q '172\.16\.'; then
                rec "Полу-состояние: подсеть пула OpenConnect (172.16.x) есть в lan_subnets, но 'oc+' в lan_interfaces нет. Именно так теряется обработка клиентов после 'rescan' при отключённом телефоне; 'discover' с 0.4.0 возвращает 'oc+' сам (если сервер жив)."
            fi ;;
    esac
    if command -v iptables >/dev/null 2>&1; then
        _occ=$(iptables -t mangle -vnL SUSANIN 2>/dev/null | grep -c 'oc' || true)
        echo "правила с -i oc* в SUSANIN: ${_occ:-0}"
        if [ "${_occ:-0}" -eq 0 ]; then
            rec "В цепочке SUSANIN нет правил с -i oc* — трафик клиентов OpenConnect проходит мимо (счётчики не растут). Проверьте lan_interfaces и перезапустите агент."
        fi
        # T3: клиент шлёт DNS на 8.8.8.8? Тогда нужен dns_hijack, иначе NXDOMAIN.
        _dh=$(iptables -t nat -S PREROUTING 2>/dev/null | grep -cF -- 'susanin-dns' || true)
        echo "DNAT 53 для клиентов (dns_hijack): наших правил ${_dh:-0}"
        if [ "$(cfg dns_hijack)" = "1" ] && [ "${_dh:-0}" -eq 0 ]; then
            rec "dns_hijack=1, но правил DNAT 53 нет — выполните 'susanin.sh reload' (или restart). Правило ставится шаблоном oc+ заранее и работает, когда клиент подключится позже."
        elif [ "$(cfg dns_hijack)" != "1" ] && [ "${_dh:-0}" -eq 0 ]; then
            rec "Если на телефоне через OpenConnect «сайты не открываются» / DNS_PROBE_FINISHED_NXDOMAIN — включите dns_hijack=1 (DNS клиентов уйдёт на резолвер роутера; Android часто шлёт запросы на 8.8.8.8)."
        fi
    fi
else
    echo "OpenConnect-сервер: не обнаружен"
fi

# ------------------------------------------------------------------- qWDTT
sec "qWDTT (соседний туннель)"
QW=0
[ -e /sys/class/net/wdtt0 ] && QW=1
[ -e /sys/class/net/wdttraw0 ] && QW=1
[ -f /opt/etc/ndm/netfilter.d/60-qwdtt-netfilter.sh ] && QW=1
if command -v pidof >/dev/null 2>&1; then pidof qwdtt >/dev/null 2>&1 && QW=1; fi
if [ "$QW" = 1 ]; then
    echo "qWDTT: обнаружен"
    case ",$EGR," in
        *,wdtt0,*|*,wdttraw0,*)
            echo "egress: содержит wdtt*"
            rec "Уберите wdtt*/wdttraw* из egress_interface — это серверные туннели qWDTT, а не ваш VPN." ;;
    esac
    case ",$LAN," in
        *,wdtt0,*|*,wdttraw0,*)
            # Штатная фича lan_server_interfaces (LAN-серверы qWDTT как клиенты
            # Susanin) сама переносит wdtt* в lan_interfaces при rescan — ругаться
            # на это нельзя. Предупреждаем только про реальный риск: клиенты WDTT
            # одновременно под политикой Keenetic (двойной заворот).
            LSRV=$(cfg lan_server_interfaces)
            case ",$LSRV," in
                *,wdtt0,*|*,wdttraw0,*)
                    echo "lan_interfaces: содержит wdtt* (ожидаемо: lan_server_interfaces=$LSRV)"
                    if [ "$(cfg mss_clamp)" = "0" ] && [ "$(cfg mss_clamp_lan)" != "1" ]; then
                        rec "Клиенты qWDTT завернуты в Susanin (lan_server_interfaces), но mss_clamp выключен: вложенный туннель 1280-в-1280 упрётся в PMTU — поставьте mss_clamp=pmtu или mss_clamp_lan=1."
                    fi
                    NEV=$(ip route show table 4096 2>/dev/null | head -1)
                    [ -n "$NEV" ] && echo "policy-route 4096: $(echo "$NEV" | cut -c1-60) (проверьте, не перебивает ли политика Keenetic метку Susanin)" ;;
                *)
                    echo "lan_interfaces: содержит wdtt*"
                    rec "Уберите wdtt*/wdttraw* из lan_interfaces/lan_subnets — иначе Susanin.Keenetic начнёт обрабатывать клиентов qWDTT (двойной туннель). Если это нужно намеренно — задайте lan_server_interfaces=wdtt0,wdttraw0 и сделайте rescan." ;;
            esac ;;
    esac
    if command -v iptables >/dev/null 2>&1; then
        if iptables -t nat -S POSTROUTING 2>/dev/null | grep -qE '\-s 10\.(66|70)\.'; then
            echo "nat POSTROUTING: MASQUERADE qWDTT по источнику"
            rec "У qWDTT NAT «по источнику, без -o» (10.66.66.0/24, 10.70.66.0/16). Если egress_address Susanin.Keenetic попадает в эти сети — туннель сломается; разведите подсети."
        fi
    fi
    case "$(cfg egress_address)" in
        10.66.66.*|10.70.*)
            rec "egress_address Susanin.Keenetic пересекается с сетями qWDTT (10.66.66.0/24 / 10.70.66.0/16). Возьмите VPN-подсеть вне них (напр. 10.8.1.0/24)." ;;
    esac
else
    echo "qWDTT: не обнаружен"
fi

# ----------------------------------------------------------------------- Web
sec "Веб-панель"
WEB_EN=$(cfg web_enable)
WEB_LS=$(cfg web_listen)
WEB_PT=$(cfg web_port)
WEB_TK=$(cfg web_token)
if [ -n "$WEB_TK" ]; then _tk=set; else _tk=empty; fi
echo "web_enable=${WEB_EN:-0}, listen=${WEB_LS:-<не задан>}, port=${WEB_PT:-8087}, token=$_tk"
if [ "${WEB_EN:-0}" = "1" ]; then
    case "$WEB_LS" in
        ""|0.0.0.0)
            echo "web_listen: неверно"
            rec "Для веб-панели задайте web_listen=<LAN-адрес роутера> (напр. 192.168.1.1). Слушать 0.0.0.0 запрещено." ;;
        *)
            if command -v netstat >/dev/null 2>&1; then
                if netstat -lnt 2>/dev/null | grep -q ":${WEB_PT:-8087}[ \t]"; then
                    echo "port ${WEB_PT:-8087}: слушается"
                else
                    echo "port ${WEB_PT:-8087}: НЕ слушается"
                    rec "Сервис веб-панели не запущен. Проверьте: /opt/etc/init.d/S95susanin-web start и лог /opt/susanin/var/susanin-web.log."
                fi
            fi ;;
    esac
    [ -n "$WEB_TK" ] || rec "web_token пуст — панель без пароля (только LAN). Задайте токен."
    [ -d /opt/susanin/www ] || rec "Нет каталога /opt/susanin/www — переустановите/обновите пакет (в дистрибутив добавлен www/)."
    [ -x /opt/etc/init.d/S95susanin-web ] || rec "Нет init-скрипта /opt/etc/init.d/S95susanin-web — веб-панель не поднимется автоматически."
else
    echo "веб-панель выключена (web_enable=0)"
fi

# ------------------------------------------------- датаплейн / IPv6 / IPTV
# ----------------------------------------------------- health (по логу агента)
# Проба здоровья по каждому egress — самая частая причина «сайты не открываются,
# а VPN работает»: агент считает туннель мёртвым. Показываем последние переходы
# и предупреждения из лога (без чтения состояния демона).
sec "Health (по логу)"
HLOG=/opt/susanin/var/susanin.log
if [ -r "$HLOG" ]; then
    _hlast=$(grep -E 'egress [^ ]+ (UP|DOWN)|all egress DOWN|health:' "$HLOG" 2>/dev/null | tail -n 5)
    if [ -n "$_hlast" ]; then
        printf '%s\n' "$_hlast"
    else
        echo "переходов UP/DOWN в логе нет (всё стабильно)"
    fi
    if tail -n 200 "$HLOG" 2>/dev/null | grep -q 'all egress DOWN'; then
        if command -v ip >/dev/null 2>&1 && \
           ip route get 1.1.1.1 2>/dev/null | grep -q .; then
            rec "В логе есть «all egress DOWN», но прямой маршрут (WAN) работает. Проверьте ICMP до health_probe с egress вручную и посмотрите время простоя: с 0.4.0 агент дополнительно пробует TCP-пробу на health_tcp_port и пишет простой в лог раз в 5 минут. Если ICMP молчит, а ping/HTTPS через VPN идут — дело в залипшем NAT-состоянии на промежуточном сервере (см. TROUBLESHOOTING, «all egress DOWN»)."
        fi
    fi
else
    echo "лог $HLOG недоступен"
fi

sec "Датаплейн, IPv6 и IPTV"
REPROV=/opt/susanin/var/dp-reprov
if [ -f "$REPROV" ]; then
    echo "tproxy re-provision: $(cat "$REPROV" 2>/dev/null)"
else
    echo "tproxy re-provision: не было"
fi

if command -v ip >/dev/null 2>&1; then
    if ip -6 route show default 2>/dev/null | grep -q .; then
        echo "IPv6 default: есть ($(ip -6 route show default 2>/dev/null | head -n1))"
        rec "Есть глобальный IPv6, а Susanin.Keenetic работает только по IPv4: трафик к IPv6-адресам (у Cloudflare/CDN часто есть AAAA) идёт мимо и может душиться. Если сайт «то грузится, то нет» — отключите IPv6 у проблемного клиента (или в Keenetic) и проверьте."
    else
        echo "IPv6 default: нет (глобального IPv6-интернета нет — это норма)"
    fi

    # MTU/MSS: на PPPoE (MTU 1492) без зажатия MSS крупные пакеты не проходят →
    # сайты грузятся частично/не открываются. Проверяем WAN MTU и наличие clamp.
    _wan=$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')
    # MSS vs MTU: значение mss_clamp не должно превышать MTU egress минус 40
    # (20 IP + 20 TCP). Иначе на каждом соединении фрагментация/PMTU-пауза —
    # «страница открывается 1–2 с» через профильный туннель.
    _msscfg=$(cfg mss_clamp)
    _egfirst=$(printf '%s' "$EGR" | cut -d, -f1 | tr -d ' \t')
    case "$_msscfg" in
        ''|0|pmtu|auto) ;;
        *[!0-9]*) rec "mss_clamp='$_msscfg' — некорректное значение (ожидается число, 'pmtu' или 0)." ;;
        *)
            _emtu=""
            [ -n "$_egfirst" ] && _emtu=$(cat "/sys/class/net/$_egfirst/mtu" 2>/dev/null || true)
            [ -z "$_emtu" ] && [ -n "$_wan" ] && _emtu=$(cat "/sys/class/net/$_wan/mtu" 2>/dev/null || true)
            if [ -n "$_emtu" ]; then
                _limit=$((_emtu - 40))
                if [ "$_msscfg" -gt "$_limit" ]; then
                    rec "mss_clamp=$_msscfg больше предела для MTU $_emtu ($_limit = MTU-40): крупные пакеты будут фрагментироваться или теряться — страницы через туннель открываются долго. Поставьте mss_clamp=pmtu (или $_limit)."
                fi
            fi ;;
    esac
    if [ -n "$_wan" ] && [ -r "/sys/class/net/$_wan/mtu" ]; then
        _mtu=$(cat "/sys/class/net/$_wan/mtu" 2>/dev/null)
        _mss=0; iptables -t mangle -L SUSANIN_MSS >/dev/null 2>&1 && _mss=1
        _kclamp=$(iptables -t mangle -S FORWARD 2>/dev/null | grep -c -- '-j TCPMSS' || true)
        echo "WAN MTU ($_wan): ${_mtu:-?} ; MSS-clamp: susanin=$_mss, внешних TCPMSS=${_kclamp:-0}"
        if [ "${_mtu:-1500}" -lt 1500 ] 2>/dev/null && [ "$_mss" = "0" ] && [ "${_kclamp:-0}" -eq 0 ]; then
            rec "WAN MTU=$_mtu (<1500), а MSS-clamp нет: вероятен PMTU-блэкхол (крупные пакеты теряются, сайты грузятся частично). Включите mss_clamp=pmtu (или 1400) и mss_clamp_lan=1 в susanin.conf, либо «MSS clamping» в Keenetic."
        fi
    fi
fi

echo "IPTV/CDN (сайт за Cloudflare/Fastly и «то грузится, то нет»):"
echo "  - адреса провайдера НЕ кладите в vpn_never (это принудительный DIRECT);"
echo "  - поймать реальный хост: tcpdump -i br0 -n 'host <IP-приставки> and port 53' (LAN-DNS открыт);"
echo "  - проверка заворота: grep '<IP-приставки>' /proc/net/nf_conntrack | grep sport=12345"

# ------------------------------------------------------------- рекомендации
sec "Рекомендации"
if [ -n "$RECS" ]; then
    printf '%s\n' "$RECS"
else
    echo "  проблем не найдено — настройки и правила в порядке"
fi
echo
echo "Для отправки отчёта с логами: sh /opt/susanin/tools/report.sh"
