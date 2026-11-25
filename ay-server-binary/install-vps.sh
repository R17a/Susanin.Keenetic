#!/bin/sh
# install-vps.sh — сервер туннеля Susanin.Keenetic.AY для Ubuntu (x86-64).
#
# Язык вывода: русский / English / 简体中文. Выбирается автоматически по
# LANG/LC_ALL, по умолчанию — English. Переопределить: AY_LANG=ru|en|zh.
#   AY_LANG=ru sudo -E sh install-vps.sh
#
# Output language: Russian / English / Simplified Chinese. Detected from
# LANG/LC_ALL, English by default. Override with AY_LANG=ru|en|zh.
#
# 输出语言：俄语 / 英语 / 简体中文。根据 LANG/LC_ALL 自动选择，默认英语。
# 可用 AY_LANG=ru|en|zh 指定。
#
# Что делает (идемпотентно — повторный запуск безопасен):
#   1. ставит бинарник в /usr/local/sbin;
#   2. создаёт ключ /etc/susanin/tunnel.key (если его ещё нет — НЕ перезаписывает);
#   3. ставит конфиг /etc/susanin/tunnel-server.conf (существующий не трогает);
#   4. включает ip_forward/NAT/MSS/rp_filter через server/tools/vps-setup.sh;
#   5. ставит systemd-юнит, daemon-reload, enable + restart;
#   6. печатает ключ и параметры для панели роутера.
#
# Идемпотентно: повторный запуск ничего не ломает и не перезаписывает ключ/конфиг.
# Idempotent: re-running keeps the existing key and config intact.
# 幂等：重复运行不会覆盖已有的密钥和配置。
#
# Переопределить туннель: TUN_IP=10.23.0.1/24 TUN_IF=tun10 sudo -E sh install-vps.sh
set -eu

# --- язык вывода ------------------------------------------------------------
AY_LANG=${AY_LANG:-}
if [ -z "$AY_LANG" ]; then
    case "${LC_ALL:-${LANG:-}}" in
        ru*|*_RU*) AY_LANG=ru ;;
        zh*|*_CN*|*_Hans*) AY_LANG=zh ;;
        *) AY_LANG=en ;;
    esac
fi
case "$AY_LANG" in ru|zh|en) ;; *) AY_LANG=en ;; esac

# loc РУССКИЙ ENGLISH 中文 — вернуть строку на выбранном языке.
loc() {
    case "$AY_LANG" in
        ru) printf '%s' "$1" ;;
        zh) printf '%s' "$3" ;;
        *)  printf '%s' "$2" ;;
    esac
}

say() { printf '== %s\n' "$(loc "$1" "$2" "$3")"; }
die() { printf 'ERROR: %s\n' "$(loc "$1" "$2" "$3")" >&2; exit 1; }
usage() {
    cat <<EOF
$(loc "Использование: sudo sh install-vps.sh" "Usage: sudo sh install-vps.sh" "用法：sudo sh install-vps.sh")
$(loc "  Переменные: TUN_IP (10.23.0.1/24), TUN_IF (tun10), PORT (5004), AY_LANG (ru|en|zh)" \
       "  Variables: TUN_IP (10.23.0.1/24), TUN_IF (tun10), PORT (5004), AY_LANG (ru|en|zh)" \
       "  变量：TUN_IP (10.23.0.1/24)、TUN_IF (tun10)、PORT (5004)、AY_LANG (ru|en|zh)")
EOF
}

case "${1:-}" in
    -h|--help) usage; exit 0 ;;
esac

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ARCH=$(uname -m)
BIN="$DIR/build/susanin-tunnel-server.$ARCH"
KEY=/etc/susanin/tunnel.key
CONF=/etc/susanin/tunnel-server.conf
UNIT=/etc/systemd/system/susanin-tunnel-server.service
TUN_IP=${TUN_IP:-10.23.0.1/24}
TUN_IF=${TUN_IF:-tun10}
PORT=${PORT:-}

[ "$(id -u)" = "0" ] || die "нужен root: sudo sh install-vps.sh" \
    "root is required: sudo sh install-vps.sh" \
    "需要 root 权限：sudo sh install-vps.sh"
command -v systemctl >/dev/null 2>&1 || die "нужен systemd (systemctl не найден)" \
    "systemd is required (systemctl not found)" \
    "需要 systemd（未找到 systemctl）"

# --- старая версия: остановить и удалить бинарник/юнит (ключ и конфиг целы) ---
if [ -x /usr/local/sbin/susanin-tunnel-server ]; then
    OLDV=$(/usr/local/sbin/susanin-tunnel-server --version 2>/dev/null | head -n1 || true)
    say "найдена старая версия${OLDV:+: $OLDV} — останавливаю и удаляю" \
        "found an old version${OLDV:+: $OLDV} — stopping and removing" \
        "发现旧版本${OLDV:+：$OLDV}——正在停止并删除"
    systemctl stop susanin-tunnel-server 2>/dev/null || true
    systemctl disable susanin-tunnel-server 2>/dev/null || true
    rm -f /usr/local/sbin/susanin-tunnel-serve
    rm -f "$UNIT"
    systemctl daemon-reload 2>/dev/null || true
fi

# --- зависимости (static-бинарник не требует библиотек) ---------------------
if ! command -v iptables >/dev/null 2>&1 || \
   ! command -v ip >/dev/null 2>&1 || \
   ! command -v sysctl >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        say "ставлю iptables, iproute2, procps" \
            "installing iptables, iproute2, procps" \
            "正在安装 iptables、iproute2、procps"
        apt-get update -qq || true
        apt-get install -y --no-install-recommends iptables iproute2 procps || \
            die "не удалось поставить iptables/iproute2/procps" \
                "failed to install iptables/iproute2/procps" \
                "无法安装 iptables/iproute2/procps"
    else
        die "нужны iptables, iproute2 и procps (apt-get не найден)" \
            "iptables, iproute2 and procps are required (apt-get not found)" \
            "需要 iptables、iproute2 和 procps（未找到 apt-get）"
    fi
fi

[ -f "$BIN" ] || die "нет бинарника $BIN — распакуйте комплект полностью
(если архитектура VDI не $ARCH, соберите под неё: TNL_TARGET=<arch> ...)" \
    "no binary $BIN — unpack the whole package
(if this machine is not $ARCH, build it for your arch: TNL_TARGET=<arch> ...)" \
    "缺少二进制文件 $BIN——请完整解压安装包
（如果本机架构不是 $ARCH，请为目标架构单独构建：TNL_TARGET=<arch> …）"
[ -x "$BIN" ] || chmod +x "$BIN"

# --- бинарник ---------------------------------------------------------------
say "бинарник: $BIN -> /usr/local/sbin/susanin-tunnel-server" \
    "binary: $BIN -> /usr/local/sbin/susanin-tunnel-server" \
    "二进制文件：$BIN -> /usr/local/sbin/susanin-tunnel-server"
install -d -m 0755 /etc/susanin /usr/local/sbin
install -m 0755 "$BIN" /usr/local/sbin/susanin-tunnel-serve

# --- ключ -------------------------------------------------------------------
if [ -s "$KEY" ]; then
    say "ключ уже есть: $KEY (не перезаписываю)" \
        "key already exists: $KEY (not overwriting)" \
        "密钥已存在：$KEY（不覆盖）"
else
    say "создаю ключ: $KEY" "creating key: $KEY" "正在生成密钥：$KEY"
    old_umask=$(umask)
    umask 077
    if ! /usr/local/sbin/susanin-tunnel-server --keygen > "$KEY"; then
        umask "$old_umask"
        rm -f "$KEY"
        die "keygen не сработал" "keygen failed" "keygen 执行失败"
    fi
    umask "$old_umask"
    chmod 0600 "$KEY"
fi
[ -s "$KEY" ] || die "файл ключа пуст: $KEY" "key file is empty: $KEY" "密钥文件为空：$KEY"
chmod 0600 "$KEY"

# --- конфиг -----------------------------------------------------------------
if [ -s "$CONF" ]; then
    say "конфиг уже есть: $CONF (не перезаписываю)" \
        "config already exists: $CONF (not overwriting)" \
        "配置已存在：$CONF（不覆盖）"
    # свежий пример кладём рядом — пригодятся новые ключи после обновления
    install -m 0640 "$DIR/server/config/tunnel-server.conf.example" "$CONF.example" 2>/dev/null || true
else
    say "конфиг: $CONF" "config: $CONF" "配置：$CONF"
    install -m 0640 "$DIR/server/config/tunnel-server.conf.example" "$CONF"
fi

# Туннель берём из конфига, если он там задан: иначе NAT настроится не на ту сеть.
_cfg_ip=$(sed -n 's/^[[:space:]]*tunnel_ip[[:space:]]*=[[:space:]]*//p' "$CONF" 2>/dev/null | tail -n 1)
_cfg_if=$(sed -n 's/^[[:space:]]*tunnel_iface[[:space:]]*=[[:space:]]*//p' "$CONF" 2>/dev/null | tail -n 1)
_cfg_port=$(sed -n 's/^[[:space:]]*tunnel_port[[:space:]]*=[[:space:]]*//p' "$CONF" 2>/dev/null | tail -n 1)
[ -n "$_cfg_ip" ] && TUN_IP=$_cfg_ip
[ -n "$_cfg_if" ] && TUN_IF=$_cfg_if
[ -n "$_cfg_port" ] && PORT=$_cfg_port
TUN_IP=$(printf '%s' "$TUN_IP" | tr -d ' \t\r')
TUN_IF=$(printf '%s' "$TUN_IF" | tr -d ' \t\r')
PORT=$(printf '%s' "$PORT" | tr -d ' \t\r')
[ -n "$PORT" ] || PORT=5004

# --- NAT / forward / MSS / rp_filter ---------------------------------------
say "сеть: NAT и forward для $TUN_IP на $TUN_IF, UDP-порт $PORT" \
    "network: NAT and forward for $TUN_IP on $TUN_IF, UDP port $PORT" \
    "网络：$TUN_IF 上为 $TUN_IP 配置 NAT 和转发，UDP 端口 $PORT"
sh "$DIR/server/tools/vps-setup.sh" "$TUN_IP" "$TUN_IF" "$PORT" || \
    die "vps-setup.sh не отработал" "vps-setup.sh failed" "vps-setup.sh 执行失败"

# --- systemd ----------------------------------------------------------------
say "systemd: /etc/systemd/system/susanin-tunnel-server.service" \
    "systemd: /etc/systemd/system/susanin-tunnel-server.service" \
    "systemd：/etc/systemd/system/susanin-tunnel-server.service"
install -m 0644 "$DIR/server/systemd/susanin-tunnel-server.service" "$UNIT"
systemctl daemon-reload
systemctl enable susanin-tunnel-server >/dev/null 2>&1 || true
if ! systemctl restart susanin-tunnel-server; then
    journalctl -u susanin-tunnel-server -n 30 --no-pager 2>/dev/null || true
    die "служба не запустилась (журнал выше)" \
        "service failed to start (see the journal above)" \
        "服务启动失败（见上方日志）"
fi
sleep 1

if ! systemctl is-active --quiet susanin-tunnel-server; then
    journalctl -u susanin-tunnel-server -n 30 --no-pager 2>/dev/null || true
    die "служба не поднялась (журнал выше)" \
        "service is not running (see the journal above)" \
        "服务未运行（见上方日志）"
fi
say "служба запущена" "service is running" "服务已启动"

# --- DNS-резолвер для AY: клиент ходит на 10.23.0.1:53 через tun10 ----------
if ! command -v dnsmasq >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        say "ставлю dnsmasq (DNS-резолвер туннеля)" \
            "installing dnsmasq (DNS resolver of the tunnel)" \
            "正在安装 dnsmasq（隧道 DNS 解析器）"
        apt-get update -qq || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends dnsmasq || \
            die "не удалось поставить dnsmasq" "failed to install dnsmasq" "无法安装 dnsmasq"
    else
        die "нужен dnsmasq (apt-get не найден)" \
            "dnsmasq is required (apt-get not found)" \
            "需要 dnsmasq（未找到 apt-get）"
    fi
fi

TUN_ADDR=$(printf '%s' "${TUN_IP%%/*}" | tr -d ' \t\r')
say "dnsmasq: $TUN_ADDR:53 на $TUN_IF, upstream 1.1.1.1/9.9.9.9" \
    "dnsmasq: $TUN_ADDR:53 on $TUN_IF, upstream 1.1.1.1/9.9.9.9" \
    "dnsmasq：$TUN_IF 上的 $TUN_ADDR:53，上游 1.1.1.1/9.9.9.9"
cat >/etc/dnsmasq.d/susanin-ay.conf <<EOF
# Susanin.Keenetic.AY: DNS-резолвер внутри туннеля.
# Клиент (dns_lan в режиме AY) шлёт сюда, ответы идут через tun10.
port=53
listen-address=$TUN_ADDR
bind-interfaces
interface=$TUN_IF
no-resolv
server=1.1.1.1
server=9.9.9.9
cache-size=10000
EOF
systemctl enable dnsmasq >/dev/null 2>&1 || true
if ! systemctl restart dnsmasq; then
    journalctl -u dnsmasq -n 30 --no-pager 2>/dev/null || true
    die "dnsmasq не запустился (журнал выше)" \
        "dnsmasq failed to start (see the journal above)" \
        "dnsmasq 启动失败（见上方日志）"
fi
sleep 1
if ! systemctl is-active --quiet dnsmasq; then
    journalctl -u dnsmasq -n 30 --no-pager 2>/dev/null || true
    die "dnsmasq не активен (журнал выше)" \
        "dnsmasq is not active (see the journal above)" \
        "dnsmasq 未运行（见上方日志）"
fi
say "DNS туннеля работает: $TUN_ADDR:53" \
    "tunnel DNS is working: $TUN_ADDR:53" \
    "隧道 DNS 工作正常：$TUN_ADDR:53"

# --- итог -------------------------------------------------------------------
KEYVAL=$(cat "$KEY")
# Адрес для подсказки: источник default-route (eth0), а не docker0, который
# `hostname -I` часто отдаёт первым. Публичный EIP облака отсюда не виден.
ADDR=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9][0-9.]*\).*/\1/p' | head -n 1)
[ -n "${ADDR:-}" ] || ADDR=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -n "${ADDR:-}" ] || ADDR=$(loc "<адрес этого сервера>" "<address of this server>" "本服务器地址")
MPID=$(systemctl show -p MainPID --value susanin-tunnel-server 2>/dev/null || true)
[ -n "${MPID:-}" ] || MPID=$(pgrep -f '/usr/local/sbin/susanin-tunnel-server' 2>/dev/null | head -n 1 || true)
[ -n "${MPID:-}" ] || MPID='<PID>'

case "$AY_LANG" in
ru)
cat <<EOF

=== Готово ===
Сервер (в панели Susanin.Keenetic): $ADDR
  ^ это адрес машины; если VDI за NAT/EIP — укажите публичный адрес
UDP-порт:                            $PORT
Ключ (поле «Ключ» в разделе AY):     $KEYVAL
Туннель:                             $TUN_IF ($TUN_IP)
DNS туннеля:                         $TUN_ADDR:53 (dnsmasq, 1.1.1.1/9.9.9.9)

Проверка и обслуживание:
  systemctl status susanin-tunnel-serve
  journalctl -u susanin-tunnel-server -f
  kill -HUP $MPID     # сводка счётчиков и сессий
  kill -USR1 $MPID    # только список сессий

ВАЖНО: откройте UDP/$PORT на файрволе/security group VDI.
Ключ — секрет: не публикуйте его и не пересылайте открытым каналом.
EOF
;;
zh)
cat <<EOF

=== 完成 ===
服务器（填入 Susanin.Keenetic 面板）：$ADDR
  ^ 这是本机地址；如果 VDI 位于 NAT/EIP 之后，请填写公网地址
UDP 端口：                           $PORT
密钥（AY 分区的“密钥”字段）：        $KEYVAL
隧道：                               $TUN_IF ($TUN_IP)
隧道 DNS：                           $TUN_ADDR:53 (dnsmasq, 1.1.1.1/9.9.9.9)

检查与维护：
  systemctl status susanin-tunnel-serve
  journalctl -u susanin-tunnel-server -f
  kill -HUP $MPID     # 计数器与会话摘要
  kill -USR1 $MPID    # 仅会话列表

重要：请在 VDI 的防火墙/安全组中放行 UDP/$PORT。
密钥属于机密：不要公开，也不要通过明文渠道传输。
EOF
;;
*)
cat <<EOF

=== Done ===
Server (in the Susanin.Keenetic panel): $ADDR
  ^ this is the machine address; if the VDI is behind NAT/EIP, use the public one
UDP port:                            $PORT
Key (the "Key" field in the AY section): $KEYVAL
Tunnel:                              $TUN_IF ($TUN_IP)
Tunnel DNS:                          $TUN_ADDR:53 (dnsmasq, 1.1.1.1/9.9.9.9)

Checks and maintenance:
  systemctl status susanin-tunnel-serve
  journalctl -u susanin-tunnel-server -f
  kill -HUP $MPID     # counters and sessions summary
  kill -USR1 $MPID    # sessions list only

IMPORTANT: open UDP/$PORT on the VDI firewall / security group.
The key is a secret: do not publish it or send it over an open channel.
EOF
;;
esac
