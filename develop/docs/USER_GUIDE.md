# Susanin.Keenetic — руководство пользователя

Кратко: программа смотрит, какие соединения «не работают» из-за блокировок,
пробует их через VPN, запоминает рабочие и держит их в VPN. Если VPN недоступен —
всё идёт напрямую. Есть списки «всегда через VPN» и «всегда напрямую».

Подробности и устройство — в [README.md](README.md); установка/обновление —
в [DEPLOY.md](DEPLOY.md).

## Быстрый старт

```sh
# 1. Нужные пакеты Entware
opkg update && opkg install ca-certificates ipset iptables conntrack

# 2. Установка (одной строкой)
wget -qO- https://raw.githubusercontent.com/R17a/Susanin.Keenetic/main/install.sh | sh

# 3. Проверка
sh /opt/susanin/tools/susanin.sh status
```

Установщик сам определит архитектуру, LAN и VPN, спросит подтверждение и
запустит демон. `susanin.conf`, `vpn_always.txt` и `vpn_never.txt` при
обновлении **не перезаписываются**, но списки **могут дополняться** новыми
записями из сборки (merge; существующие строки не удаляются).

## Управление

| Действие | Команда |
|---|---|
| Состояние | `sh /opt/susanin/tools/susanin.sh status` |
| Запуск / стоп / рестарт | `… start` / `… stop` / `… restart` (веб-панель не затрагивается) |
| Веб-панель | `… web {start\|stop\|restart\|status}` |
| Перечитать конфиг | `… reload` |
| Заново найти LAN/VPN | `… rescan` |
| Лог (последние N строк) | `… log 100` |
| Убрать адрес из кэша | `… reset <ip|домен>` (синоним `forget`) |
| Добавить в VPN вручную | `… add <ip> tcp test` |
| Диагностика | `sh /opt/susanin/tools/diagnose.sh` |
| Отчёт для Issue | `sh /opt/susanin/tools/report.sh` |

## Настройка

Файл `/opt/susanin/etc/susanin.conf`. Открытые вопросы и примеры полей — в
[README.md](README.md). Длительности пишутся числом без букв, единица указана
в описании параметра (сек / мин / ч); каждый параметр описан в
`config.example.conf` и в самом генерируемом конфиге. Часто трогают:

- `egress_interface` — VPN-интерфейс(ы); несколько через запятую (фейловер);
- `lan_interfaces`, `lan_subnets` — трафик каких сетей анализировать;
- `fast_syn_min_op=1` — быстрее детект «SYN без ответа» (больше ложных);
- `soft_interval=1` — быстрее детект «заглохшего» потока (сек; по умолчанию 1);
- `ok_evict_misses=3` — сколько «сбоев» подряд до снятия из VPN-кэша;
- `promo_per_min=30` — лимит новых проверок через VPN в минуту;
- `learn_exclude_ports` — порты, где отключено быстрое обучение (скан-шум);
- `disk_mode=normal|soft` — сколько писать на носитель.

После правки: `sh /opt/susanin/tools/susanin.sh reload` (или `rescan`, если
меняли сетевые поля). Изменения `vpn_always.txt`/`vpn_never.txt` подхватываются
сами, перезапуск не нужен.

## Веб-панель

Встроенная панель поднимается отдельным процессом, если `web_enable=1`:

- откройте `http://<LAN-IP-роутера>:<web_port>` (по умолчанию `192.168.1.1:8087`);
- раздел «Конфигурация агента» — правка параметров из браузера; списки
  `vpn_always`/`vpn_never` — перетаскиванием между колонками;
- управление панелью: `sh /opt/susanin/tools/susanin.sh web {start|stop|restart|status}`;
- кнопка Restart в панели перезапускает демон и **не затрагивает саму панель**;
  `susanin.sh status` показывает строки `daemon:` и `web:`.

## Типовые задачи

**Домен всегда через VPN.** Добавьте строку в `/opt/susanin/etc/vpn_always.txt`:

```
example.com          # только сам домен
*.example.com        # домен и все поддомены (для CDN)
192.0.2.0/24         # диапазон
```

**Домен всегда напрямую (никогда в VPN).** Строка в
`/opt/susanin/etc/vpn_never.txt` (тот же формат, включая `*.example.com`).
Такой адрес не попадёт в VPN-кэш и не будет обучен; если добавлен позже —
уже открытые VPN-потоки разрываются, клиент переподключается напрямую.

**Адрес ошибочно в VPN.** `sh /opt/susanin/tools/susanin.sh reset <ip|домен>` (синоним `forget`).

**Сменили или удалили VPN.** `sh /opt/susanin/tools/susanin.sh rescan` — заново
найдёт LAN/VPN, обновит конфиг и применит без полной перезагрузки.

**Несколько VPN (фейловер).** В конфиге:

```
egress_interface=nwg0,nwg1
egress_address=10.8.1.1,10.8.1.2
```

Активен один туннель; при обрыве трафик автоматически идёт через следующий
живой, а если живых нет — напрямую.

**Экономия носителя.** При установке во внутреннюю память включится
`disk_mode=soft`: лог не ведётся, бэкапов нет, состояние сохраняется раз в
`soft_state_interval` (12 часов).

**XRay/VLESS-REALITY как egress (режим `tproxy`).** Susanin.Keenetic умеет выносить
помеченный трафик в Xray: TCP — `REDIRECT` в `dokodemo-door`, UDP — релей в
демоне (TPROXY + SOCKS5 UDP ASSOCIATE). Включается боевым режимом:
`sh /opt/susanin/tools/xray-egress.sh enable` (откат — `disable`). Требуются
бинарь `/opt/sbin/xray` и конфиг `/opt/susanin/etc/xray-tproxy.json` (шаблон
`xray-tproxy.json.example`, подставить `SERVER/UUID/SNI/PBK/SID`). Подробности:
[XRAY.md](XRAY.md). Обычный VPN из «Других подключений» (`nwg*`) при этом
продолжает работать как раньше (`egress_type=interface`).

**Вместе с qWDTT_Server_Keenetic.** Не добавляйте серверные интерфейсы qWDTT
(`wdtt0`/`wdttraw0`) в `lan_interfaces`/`lan_subnets` и не выбирайте их как
`egress_interface` — они в `discover_exclude`. VPN-подсеть Susanin.Keenetic не должна
пересекаться с сетями qWDTT (`10.66.66.0/24`, `10.70.66.0/16`).
`diagnose.sh` подскажет при конфликте. Подробнее — README, раздел «Вместе с
qWDTT_Server_Keenetic».

**Профили маршрутизации.** Можно задать профили: список (домены/IP/CIDR) → свой
туннель. Профилей до 4; задаются повторяющимися ключами `profile1_*` …
`profile4_*` в `susanin.conf` (`_name`, `_egress`, `_list`, `_geo_url`,
`_auto`, `_table`, `_mark`) или файлом
`/opt/susanin/etc/profiles.d/<имя>.conf`. Профиль включается только при заданном
`profileN_name`; `_table`/`_mark` можно опустить — подставятся значения по
умолчанию (таблицы `201..204`, метки `0x40000000/0x08000000/…`).

Пример:
```
profile1_name=cdn
profile1_egress=nwg1
profile1_list=/opt/susanin/etc/profiles/cdn.txt
profile2_name=social
profile2_egress=nwg2
profile2_list=/opt/susanin/etc/profiles/social.txt
```
Списки кладите в `/opt/susanin/etc/profiles/<имя>.txt` (по строке: домен, IP или
CIDR; `#` — комментарий). Адрес обрабатывается первым совпавшим профилем.

Управление: `sh /opt/susanin/tools/profiles.sh {up|down|status}`. Профили
поднимаются при старте демона; если не заданы — ничего не меняется.

**XRay/REALITY как egress (режим `tproxy`).** Рекомендуемый способ (без TUN):
в `susanin.conf` — `egress_type=tproxy`, `tproxy_port=12345`; при желании UDP —
`udp_relay=1`, `udp_relay_port=1081`, `socks_addr=127.0.0.1`, `socks_port=1080`.
Проще всего — `sh /opt/susanin/tools/xray-egress.sh enable` (сам выставит ключи,
поднимет Xray и перезапустит агента). Откат — `disable`. Подробности, проверка
TCP/UDP и грабли — [XRAY.md](XRAY.md).

## Обновление и удаление

```sh
sh /opt/susanin/tools/susanin.sh update vX.Y.Z   # версия (актуальную см. в Releases)
sh /opt/susanin/tools/susanin.sh uninstall        # снять, конфиг сохранить
sh /opt/susanin/tools/susanin.sh uninstall --purge # удалить всё
```

Если что-то не работает — см. [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
