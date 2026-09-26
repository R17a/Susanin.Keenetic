# XRay (VLESS-REALITY) + Susanin.Keenetic

Коротко: **Susanin.Keenetic решает, что заворачивать, а Xray на роутере выносит это
наружу.** Работает в режиме `egress_type=tproxy` — без TUN.

## Как это работает (в двух словах)

- Susanin.Keenetic помечает нужные соединения (из `vpn_always` и из выученных адресов).
- Помеченный **TCP** уходит в Xray через `REDIRECT` (перенаправление на
  локальный порт Xray), а Xray гонит его в VLESS/REALITY.
- Помеченный **UDP** заворачивается на локальный порт демона («релей»), демон
  отправляет его в Xray через локальный `socks` и возвращает ответы клиенту.
- Всё остальное идёт напрямую.

## Что нужно

- Бинарь Xray на роутере: `/opt/sbin/xray` (в комплекте есть `xray/xray.mipsel`
  и `xray/xray.aarch64`, версия 1.8.24).
- Конфиг клиента: `/opt/susanin/etc/xray-tproxy.json`
  (образец — `xray-tproxy.json.example`).
- Рабочий Xray-сервер VLESS+REALITY (на VPS). На роутере под него ничего
  настраивать не нужно.
- Для UDP-релея нужен модуль ядра **`xt_TPROXY`** (плюс `xt_socket`,
  `nf_tproxy_ipv4`). `datapath.sh` подгружает его сам: `modprobe`, а если его
  нет — `insmod /lib/modules/$(uname -r)/<модуль>.ko` (на Keenetic `modprobe`
  часто отсутствует, `insmod` из busybox есть). Если модуль всё равно
  недоступен, TCP-ветка работает, а UDP через XRay не пойдёт — `datapath.sh`
  напишет предупреждение и не станет валить правила.

## Маскировка (SNI / camo-домен)

Для REALITY `serverName` (SNI) — это **реальный сторонний сайт**, под который
маскируется сервер, а `address` в клиенте лучше указывать **IP** сервера:

- сервер: `realitySettings.dest = "<camo>:443"`, `serverNames = ["<camo>"]`;
- клиент: `address = <IP>`, `serverName = "<camo>"`;
- `<camo>` должен быть **иностранным**, реально доступным из РФ (SNI не из
  блок-листа), поддерживать **TLS 1.3 + X25519 + HTTP/2** и быть **не «слишком
  популярным»** (топ-домены вроде `google.com`/`microsoft.com`/`ozon.ru` массово
  используют в прикрытии — они в чёрных списках). Хороши средние, но живые
  сайты (напр. `apache.org`, `docker.com`, `www.postgresql.org`).

Проверка кандидата (с сервера):
```sh
echo | openssl s_client -connect <camo>:443 -servername <camo> -tls1_3 2>/dev/null \
  | grep -E 'Protocol|Peer Temp'
```
Нужно `Protocol: TLSv1.3` и `Peer Temp Key: X25519` (или `X25519MLKEM768`).

После смены camo-домена убедитесь, что запрос с **чужим** SNI к вашему серверу
**не** отдаёт сертификат вашего домена:
```sh
echo | openssl s_client -connect <IP_сервера>:443 -servername example.org 2>/dev/null \
  | openssl x509 -noout -subject
```

## Настройка

1. Положить бинарь:
   ```sh
   cp xray/xray.mipsel /opt/sbin/xray && chmod +x /opt/sbin/xray   # mips/mipsel
   # или: cp xray/xray.aarch64 /opt/sbin/xray && chmod +x /opt/sbin/xray
   ```
2. Положить конфиг и подставить свои данные:
   ```sh
   cp /opt/susanin/etc/xray-tproxy.json.example /opt/susanin/etc/xray-tproxy.json
   # заменить SERVER/UUID/SNI/PBK/SID
   ```
3. Включить:
   ```sh
   sh /opt/susanin/tools/xray-egress.sh enable
   ```
   Ключи в `susanin.conf` (`egress_type=tproxy`, `tproxy_port=12345`,
   `udp_relay=1`, `udp_relay_port=1081`, `socks_addr=127.0.0.1`, `socks_port=1080`)
   прописываются автоматически.

## Проверка

Безопасный тест (в туннель уйдёт только один адрес):
```sh
sh /opt/susanin/tools/xray-egress.sh run 1.1.1.1 both
```
С компьютера в вашей сети:
```sh
# Windows:
nslookup ya.ru 1.1.1.1
nslookup -class=chaos -type=txt whoami.cloudflare. 1.1.1.1   # ожидаем IP вашего сервера
# Linux/macOS:
curl -s https://1.1.1.1/cdn-cgi/trace | grep '^ip='          # ожидаем IP вашего сервера
```
На роутере:
```sh
sh /opt/susanin/tools/xray-egress.sh status
# ожидаем: redirect: port=12345 rules=2 ; udp-relay: port=1081 rules=2
sh /opt/susanin/tools/xray-egress.sh default     # вернуть всё в DIRECT
```
Проверяйте UDP **с компьютера**, не с роутера: трафик самого роутера в этот
механизм не попадает.

## Включение и выключение

```sh
sh /opt/susanin/tools/xray-egress.sh enable     # боевой режим: всё помеченное -> XRay
sh /opt/susanin/tools/xray-egress.sh disable    # выключить, вернуть DIRECT
```

## Тонкости

- **Политики Keenetic.** Если у клиента назначена политика («Приоритеты
  подключений»), она перекрывает Susanin.Keenetic. Для таких клиентов уберите политику.
- **Не проверяйте DNS-адресом «на бою».** `1.1.1.1`/`8.8.8.8` без ограничения
  могут «положить» разрешение имён; для проверки используйте
  `xray-egress.sh run <IP>` (адрес метится на 60 секунд).
- **IPv6.** Схема работает по IPv4; часть трафика через IPv6 может идти мимо.
- **Нагрузка.** Шифрование Xray идёт на процессоре роутера. При большом списке
  адресов возможна перегрузка — держите под рукой `xray-egress.sh disable`.
- **Не запускайте XKeen вместе с Susanin.Keenetic** — это два перехватчика одного
  трафика; для Reality используйте встроенный режим Susanin.Keenetic.

## Логи (Susanin.Keenetic и Xray — раздельно)

- **Susanin.Keenetic** — ключ `log_level` в `susanin.conf`
  (`quiet|error|warn|info|debug|trace`), пишет в `/opt/susanin/var/susanin.log`.
- **Xray** — два параметра в его `xray-tproxy.json`:
  - `"loglevel"` — общий уровень (`debug|info|warning|error|none`);
  - `"access"` — access-лог (строки `from … accepted …`); при `"none"` не пишется.
  В `susanin.conf` задаётся `xray_loglevel`; при `xray-egress.sh enable|run`
  он применяется к `xray-tproxy.json` (вместе с `"access": "none"`), и Xray
  **перезапускается** (уровень читается только при старте). Уровни Susanin.Keenetic и
  Xray независимы.

Важно: `from … accepted …` — это **access-лог**, он **не управляется
`loglevel`**. Чтобы этих строк не было, нужен именно `"access": "none"`:
```json
"log": { "access": "none", "loglevel": "warning" },
```
Обрезать лог: `: > /opt/susanin/var/xray.log`.

## Если не работает

- Xray не запущен/не слушает: `netstat -lntu | grep -E ':(12345|1080)'`.
  Важно: если Xray не запущен, Susanin.Keenetic **не поднимает** tproxy-правила и пускает
  трафик напрямую (fail-open) — чёрной дыры не будет. Поднять Xray:
  `/opt/etc/init.d/S93xray-tproxy start` (или `xray-egress.sh enable`).
- Нет правил: `iptables -t nat -S PREROUTING | grep REDIRECT` и
  `iptables -t mangle -S PREROUTING | grep TPROXY`; если пусто — повторите
  `xray-egress.sh enable`.
- Смотрите логи: `tail -n 40 /opt/susanin/var/xray.log` и
  `tail -f /opt/susanin/var/susanin.log`.
- Подробнее — [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## Безопасность

В репозитории и архиве не должно быть ваших ключей, UUID и ссылок `vless://` —
только плейсхолдеры `SERVER/UUID/SNI/PBK/SID`.
