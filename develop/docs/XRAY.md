# XRay (VLESS-REALITY) + Susanin

Коротко: **Susanin решает, что заворачивать, а Xray на роутере выносит это
наружу.** Работает в режиме `egress_type=tproxy` — без TUN.

## Как это работает (в двух словах)

- Susanin помечает нужные соединения (из `vpn_always` и из выученных адресов).
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
  подключений»), она перекрывает Susanin. Для таких клиентов уберите политику.
- **Не проверяйте DNS-адресом «на бою».** `1.1.1.1`/`8.8.8.8` без ограничения
  могут «положить» разрешение имён; для проверки используйте
  `xray-egress.sh run <IP>` (адрес метится на 60 секунд).
- **IPv6.** Схема работает по IPv4; часть трафика через IPv6 может идти мимо.
- **Нагрузка.** Шифрование Xray идёт на процессоре роутера. При большом списке
  адресов возможна перегрузка — держите под рукой `xray-egress.sh disable`.
- **Не запускайте XKeen вместе с Susanin** — это два перехватчика одного
  трафика; для Reality используйте встроенный режим Susanin.

## Если не работает

- Xray не запущен/не слушает: `netstat -lntu | grep -E ':(12345|1080)'`.
  Важно: если Xray не запущен, Susanin **не поднимает** tproxy-правила и пускает
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
