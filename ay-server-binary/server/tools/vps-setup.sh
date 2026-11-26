#!/bin/sh
# vps-setup.sh — разовая настройка VPS под tunnel-server: ip_forward, NAT, MSS
# clamping, защита UDP-порта. Идемпотентна: повторный запуск не дублирует правила.
#
#   sh vps-setup.sh [tun-ip/prefix] [tun-iface] [udp-port]
#   по умолчанию: 10.23.0.1/24 tun10, порт — из tunnel-server.conf (5004);
#   внешний интерфейс берётся из default route.
#
# Что и почему:
#   * ip_forward=1 и rp_filter=0 — обратный путь пакетов туннеля иначе
#     убивается anti-spoofing'ом;
#   * MASQUERADE из туннеля в интернет — клиент выходит наружу с адресом VPS;
#   * TCPMSS --clamp-mss-to-pmtu — внутренний MTU туннеля (1200) меньше 1500,
#     без clamping тяжёлые TCP-сессии «тихо» встают;
#   * DROP для адресов провайдера/хостинга из туннеля — туннель не должен
#     становиться мостом в чужие L2/VPN-сети;
#   * rate-limit новых UDP-пакетов на порт туннеля — флуд не должен съедать CPU.
#
# ВАЖНО: правил, перенаправляющих собственный трафик VPS в туннель, здесь нет и
# быть не должно: UDP-порт туннеля обязан уходить наружу напрямую, иначе — петля.

set -eu

TUN_IP=${1:-10.23.0.1/24}
TUN_IF=${2:-tun10}
PORT=${3:-}

say() { printf '== %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "запускать от root"

# Порт туннеля: аргумент, затем конфиг, затем 5004.
if [ -z "$PORT" ] && [ -r /etc/susanin/tunnel-server.conf ]; then
    PORT=$(sed -n 's/^[[:space:]]*tunnel_port[[:space:]]*=[[:space:]]*//p' \
        /etc/susanin/tunnel-server.conf 2>/dev/null | tail -n 1 | tr -d ' \t\r')
fi
[ -n "$PORT" ] || PORT=5004
case "$PORT" in
    *[!0-9]*) die "некорректный UDP-порт: $PORT" ;;
esac
if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    die "UDP-порт вне 1..65535: $PORT"
fi

case "$TUN_IP" in
    */*) : ;;
    *) TUN_IP="$TUN_IP/24" ;;
esac
OCTET=${TUN_IP%%/*}
PLEN=${TUN_IP##*/}
[ "$PLEN" -ge 8 ] 2>/dev/null || die "prefix должен быть >= 8: $TUN_IP"
TUN_NET="${OCTET%.*}.0/$PLEN"

IFB=$(ip -4 route show default 2>/dev/null | awk '/default/ {print $5; exit}')
[ -n "${IFB:-}" ] || die "не найден default route (нет внешнего интерфейса?)"

IPT=iptables
command -v iptables >/dev/null 2>&1 || IPT=iptables-legacy
command -v "$IPT" >/dev/null 2>&1 || die "iptables не установлен"

say "внешний интерфейс: $IFB, туннель: $TUN_IF ($TUN_IP), сеть: $TUN_NET"

# --- sysctl ---------------------------------------------------------------
say "sysctl: ip_forward=1, rp_filter=0, UDP-буферы под RTT туннеля"
sysctl -qw net.ipv4.ip_forward=1 || warn "не удалось включить ip_forward"
sysctl -qw net.ipv4.conf.all.rp_filter=0 || true
if [ -w "/proc/sys/net/ipv4/conf/$TUN_IF/rp_filter" ]; then
    echo 0 > "/proc/sys/net/ipv4/conf/$TUN_IF/rp_filter"
fi
# UDP-буфер сокета туннеля. Дефолтные 208 КБ при RTT 100+ мс дают полосу
# ~2 МБ/с по BDP (208 КБ / 0.105 с): выше канал не разогнать, хотя он свободен.
# rmem — приём от клиента, wmem — отправка клиенту (для скачивания важнее wmem).
sysctl -qw net.core.rmem_max=4194304 || warn "не удалось поднять net.core.rmem_max"
sysctl -qw net.core.wmem_max=4194304 || warn "не удалось поднять net.core.wmem_max"
sysctl -qw net.core.rmem_default=1048576 || true
sysctl -qw net.core.wmem_default=1048576 || true
mkdir -p /etc/sysctl.d
cat > /etc/sysctl.d/90-susanin-tunnel.conf <<EOF
# Susanin tunnel server: форвардинг трафика клиентов туннеля
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 0
# UDP-буферы под RTT туннеля (дефолт 208 КБ ограничивал полосу ~2 МБ/с)
net.core.rmem_max = 4194304
net.core.wmem_max = 4194304
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
EOF

# --- правила ---------------------------------------------------------------
add_rule() {
    # $1 = таблица, остальные = цепочка и спецификация; без дублей
    tbl=$1; shift
    if $IPT -t "$tbl" -C "$@" 2>/dev/null; then
        say "есть: $IPT -t $tbl $*"
    else
        $IPT -t "$tbl" -A "$@" || warn "правило не принято: $IPT -t $tbl $*"
    fi
}

add_rule nat POSTROUTING -s "$TUN_NET" -o "$IFB" -j MASQUERADE
add_rule mangle FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --clamp-mss-to-pmtu
add_rule filter FORWARD -i "$TUN_IF" -o "$IFB" \
    -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
add_rule filter FORWARD -i "$TUN_IF" -o "$IFB" -j ACCEPT

# туннель не должен использоваться как мост во внутренние сети хостинга
for blk in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 \
           100.64.0.0/10 0.0.0.0/8 224.0.0.0/4 240.0.0.0/4; do
    add_rule filter FORWARD -i "$TUN_IF" -o "$IFB" -d "$blk" -j DROP
done

# служебные порты VPS не должны приходить из туннеля
add_rule filter INPUT -i "$TUN_IF" -p tcp -m multiport \
    --dports 22,25,135,137,138,139,445,3389 -j DROP
add_rule filter INPUT -i "$TUN_IF" -p udp -m multiport --dports 137,138 -j DROP

# rate limit на порт туннеля (если есть xt_recent; иначе пропускаем).
# Ставим идемпотентно: повторный install-vps.sh не должен плодить правила.
if $IPT -C INPUT -p udp --dport "$PORT" -m conntrack --ctstate NEW \
        -m recent --name tnl --set 2>/dev/null; then
    say "rate limit UDP/$PORT: правило уже есть"
elif $IPT -A INPUT -p udp --dport "$PORT" -m conntrack --ctstate NEW \
        -m recent --name tnl --set 2>/dev/null; then
    add_rule filter INPUT -p udp --dport "$PORT" -m recent --name tnl --update \
        --seconds 60 --hitcount 20000 -j DROP
    if $IPT -C INPUT -p udp --dport "$PORT" -m recent --name tnl --update \
            --seconds 60 --hitcount 20000 -j DROP 2>/dev/null; then
        say "rate limit UDP/$PORT включён (20000 пакетов/60 с на адрес)"
    else
        warn "rate limit: правило --set стоит, но DROP не принят (nf_tables/xt_recent?) — частота пакетов не ограничена"
    fi
else
    warn "модуль xt_recent недоступен — ограничение частоты пакетов не задано"
fi

# --- не блокируем исходящий UDP-порт (сам туннель) --------------------------
if $IPT -t filter -C OUTPUT -p udp --dport "$PORT" -j DROP 2>/dev/null; then
    warn "в OUTPUT стоит DROP udp/$PORT — туннель не заработает, удаляем"
    $IPT -t filter -D OUTPUT -p udp --dport "$PORT" -j DROP || true
fi

say "готово (порт туннеля: UDP/$PORT)"
echo "  ip_forward        = $(cat /proc/sys/net/ipv4/ip_forward)"
echo "  udp buffers       = rmem $(cat /proc/sys/net/core/rmem_max) / wmem $(cat /proc/sys/net/core/wmem_max)"
echo "  rules (nat):"
$IPT -t nat -L POSTROUTING -n -v --line-numbers 2>/dev/null | sed -n '1,12p'
echo "  rules (forward):"
$IPT -L FORWARD -n -v --line-numbers 2>/dev/null | sed -n '1,16p'
echo
echo "адрес $TUN_IP на $TUN_IF поднимает сам tunnel-server (--tun-ip/--mtu);"
echo "если интерфейс уже создан вручную: ip addr add $TUN_IP dev $TUN_IF && "
echo "ip link set $TUN_IF mtu 1200 up"
