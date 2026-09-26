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

if [ -n "$EGR" ]; then
    oldifs=$IFS; IFS=','
    for i in $EGR; do
        IFS=$oldifs
        i=$(printf '%s' "$i" | tr -d ' \t')
        if [ -e "/sys/class/net/$i" ]; then
            echo "egress $i: существует"
        else
            echo "egress $i: ОТСУТСТВУЕТ"
            rec "VPN-интерфейс '$i' не найден. Включите VPN-подключение или укажите верное имя в egress_interface."
        fi
        IFS=','
    done
    IFS=$oldifs
fi

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
    if ip rule show 2>/dev/null | grep -q "lookup $TBL"; then
        echo "ip rule -> table $TBL: ok"
    else
        echo "ip rule -> table $TBL: НЕТ"
        rec "Нет правила ip rule на таблицу $TBL — трафик идёт мимо VPN. Перезапустите: susanin.sh restart"
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
    while IFS= read -r raw; do
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
            echo "lan_interfaces: содержит wdtt*"
            rec "Уберите wdtt*/wdttraw* из lan_interfaces/lan_subnets — иначе Susanin.Keenetic начнёт обрабатывать клиентов qWDTT (двойной туннель)." ;;
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
