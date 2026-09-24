# Susanin.Keenetic — если что-то не работает

Сначала соберите диагностику:
```sh
sh /opt/susanin/tools/diagnose.sh   # проверит окружение, конфиг, правила, списки
sh /opt/susanin/tools/report.sh     # отчёт: /opt/susanin/var/report.txt
```
`diagnose.sh` в конце сам печатает подсказки, что поправить.

## Сайт не открывается

1. **Проверьте VPN.** `sh /opt/susanin/tools/susanin.sh status` — демон должен
   быть запущен, а правила и таблица — на месте. Если VPN-интерфейс удалили или
   переименовали — `sh /opt/susanin/tools/susanin.sh rescan`.
2. **DNS.** Без шифрованного DNS (DoH/DoT) провайдер подменяет ответы, и клиент
   не получает настоящий адрес даже при рабочем VPN. Включите DoH/DoT. Проверка:
   `nslookup example.com` должен вернуть реальный IP.
3. **Политика Keenetic.** Любая политика у клиента (Web → «Приоритеты
   подключений») перекрывает Susanin. У такого клиента оставьте системную
   политику «по умолчанию».
4. **Домен в `vpn_never.txt`.** Такой адрес специально идёт напрямую. Проверьте
   списки.

## Открывается, но с задержкой в первый раз

Так работает обучение: первый заход идёт напрямую → обрывается → Susanin
заворачивает адрес в VPN → клиент переподключается. Дальше адрес в кэше и
открывается сразу.

Ускорить: добавьте домен (или `*.домен`) в `vpn_always.txt` — тогда сразу через
VPN, без обучения.

## Превью/видео YouTube, медиа Instagram/x.com

Они работают через поддомены (`i.ytimg.com`, `*.googlevideo.com` и т.п.), а не
через основной домен. Добавьте зоны:
```
*.ytimg.com
*.googlevideo.com
*.ggpht.com
*.googleusercontent.com
```
Изменения подхватываются без перезапуска.

## В логе много «no A records»

Это норма для CDN: у основного домена может не быть A-записей, работают
поддомены. В логе теперь одна сводка вместо строки на каждый домен. Если домен из
`vpn_always.txt` не разрешается — укажите поддомен или `*.домен`.

## VPN-интерфейс исчез / подключение удалили

Демон сам переоценивает egress: пропавший интерфейс исключается, живой
подхватывается; если живых нет — всё идёт напрямую (запись в логе). Чтобы
подтянуть новый интерфейс из системы:
`sh /opt/susanin/tools/susanin.sh rescan`.

## Трафик идёт мимо VPN (правила снесены)

Keenetic пересобирает правила при изменениях в Web. Susanin восстанавливает свои
правила сам. Проверьте `sh /opt/susanin/tools/datapath.sh status` — должен быть
`jump: present`. Если нет — `sh /opt/susanin/tools/susanin.sh install`.

## Обучение не работает (наборы пустые)

- у клиента политика Keenetic (см. выше);
- порт в списке `learn_exclude_ports` — по нему обучение ограничено (скан-шум).
  Для полностью заблокированного сервиса на таком порту добавьте его домен/IP в
  `vpn_always.txt`;
- через роутер просто нет трафика.

## Адрес «мельтешит» (то в VPN, то нет)

`ok_evict_misses` (по умолчанию 3) — сколько сбоев подряд нужно, чтобы убрать
адрес из VPN-кэша. Увеличьте, если адрес «прыгает».

## Много записей на носитель

Включите `disk_mode=soft` — лог не ведётся, бэкапов нет, состояние сохраняется
редко. Установщик включает его сам при установке во внутреннюю память.

## После установки/перезагрузки часть сайтов не открывается (tproxy + Xray)

Симптом: в конфиге `egress_type=tproxy`, но Xray не запущен — тогда выученные
(помеченные) сайты уходят в никуда. Признак: `ps | grep '[x]ray'` пусто и
`netstat -lnt | grep 12345` пусто.

Что делает Susanin: при старте проверяет порт `tproxy_port`; если Xray не
слушает — правила tproxy **не поднимает** и пускает трафик напрямую (fail-open),
в лог пишет предупреждение. Так что «глухой» чёрной дыры быть не должно; если
она возникла — значит правила остались с прошлого запуска:

```sh
sh /opt/susanin/tools/datapath.sh down        # снять правила (вернуть DIRECT)
sed -i 's/^egress_type=.*/egress_type=interface/' /opt/susanin/etc/susanin.conf
sh /opt/susanin/tools/susanin.sh restart      # обычный режим, пока Xray не готов
```
Либо поднимите Xray и оставьте tproxy:
```sh
/opt/etc/init.d/S93xray-tproxy start
sh /opt/susanin/tools/susanin.sh restart
sh /opt/susanin/tools/susanin.sh status       # строка mode=tproxy ... (Xray LISTEN)
```

## XRay-режим: не идёт через туннель

Режим XRay — `egress_type=tproxy`. Проверяйте по шагам:

1. **Xray слушает:** `netstat -lntu 2>/dev/null | grep -E ':(12345|1080)'`
   (12345/TCP и 1080/TCP+UDP).
2. **Правила на месте:** `iptables -t nat -S PREROUTING | grep REDIRECT` (TCP) и
   `iptables -t mangle -S PREROUTING | grep TPROXY` (UDP). Если пусто — включите
   заново: `sh /opt/susanin/tools/xray-egress.sh enable`.
3. **Тест одного адреса:** `sh /opt/susanin/tools/xray-egress.sh run 1.1.1.1 both`,
   затем с компьютера `curl -s https://1.1.1.1/cdn-cgi/trace | grep '^ip='`
   (ожидаем IP сервера) и `nslookup ya.ru 1.1.1.1`.
4. **TCP идёт, UDP — нет:** смотрите
   `grep -i 'udp-relay' /opt/susanin/var/susanin.log` и
   `grep 'accepted udp:' /opt/susanin/var/xray.log`. UDP проверяйте
   **с компьютера**, не с роутера.
5. **Xray не стартует:** `tail -n 40 /opt/susanin/var/xray.log`. Для mipsel нужен
   бинарь 1.8.24 softfloat.
6. **Вернуть DIRECT:** `sh /opt/susanin/tools/xray-egress.sh disable`.

## XKeen и Susanin вместе

**XKeen** — отдельный перехватчик трафика, у него свои правила и маршруты. Если он
запущен, он мешает Susanin: сайты «то работают, то нет», правила Susanin
сбрасываются. Не запускайте XKeen вместе с Susanin; для Reality используйте
встроенный XRay-режим Susanin (скрипт `S05xkeen` держите выключенным).

## Веб-панель не открывается

- В `susanin.conf`: `web_enable=1`, `web_listen` — **LAN-адрес роутера**
  (`192.168.1.1`), не `0.0.0.0` и не `127.0.0.1`.
- Запустите сервис: `/opt/etc/init.d/S95susanin-web start`.
- Проверка: `netstat -lnt | grep 8087` и
  `curl -s "http://127.0.0.1:8087/api/status?token=ТОКЕН" | head -c 200`.
- Пустой `web_token` — вход без пароля (только из вашей сети).

## Профили маршрутизации не применяются

- профиль включается, только если задан `profileN_name`; файл списка
  (`profileN_list`) должен существовать и быть непустым;
- `profileN_egress` — существующий интерфейс;
- проверьте `diagnose.sh`, затем `sh /opt/susanin/tools/profiles.sh up` и
  `sh /opt/susanin/tools/profiles.sh status`;
- адрес обрабатывается **первым совпавшим** профилем.

## Постоянно мигает носитель (флешка/USB), система подтормаживает

Частая причина — `datapath.sh up` падает, а агент повторяет его (с записью
бэкапа на носитель). В логе видно строки `datapath provisioning failed`.

- Посмотреть причину:
  ```sh
  grep -c 'provisioning failed' /opt/susanin/var/susanin.log
  tail -40 /opt/susanin/var/susanin.log
  ```
- Частый конкретный случай — не загружен модуль ядра для UDP-релея:
  `iptables ... -j TPROXY` → `iptables: No chain/target/match by that name`.
  TCP при этом работает. На Keenetic `modprobe` обычно нет — грузите `insmod`:
  ```sh
  K=/lib/modules/$(uname -r)
  insmod $K/nf_tproxy_ipv4.ko 2>/dev/null
  insmod $K/xt_socket.ko 2>/dev/null
  insmod $K/xt_TPROXY.ko 2>/dev/null
  cat /proc/modules | grep -iE 'tproxy|socket'
  ```
  (в свежих сборках `datapath.sh` делает это сам). Если модуля .ko нет — UDP
  через XRay не пойдёт, это не мешает TCP.
- Убрать поток записей на носитель:
  ```sh
  sed -i 's/^disk_mode=.*/disk_mode=soft/' /opt/susanin/etc/susanin.conf
  sh /opt/susanin/tools/susanin.sh restart
  rm -rf /opt/susanin/var/datapath-* /opt/susanin/var/archive/*
  ```
  (в свежих сборках бэкапы уже ограничены — не чаще раза в час).

## Отчёт для Issue

```sh
sh /opt/susanin/tools/report.sh
# файл: /opt/susanin/var/report.txt
```
