# Susanin.Keenetic — руководство пользователя

Кратко: программа смотрит, какие соединения «не работают» из-за блокировок,
пробует их через VPN, запоминает рабочие и держит их в VPN. Если VPN недоступен —
всё идёт напрямую. Есть списки «всегда через VPN» и «всегда напрямую».

Подробности и устройство — в [README.md](README.md); установка/обновление —
в [DEPLOY.md](DEPLOY.md).

## Быстрый старт

```sh
# 1. Нужные пакеты Entware
opkg update && opkg install ca-certificates ipset iptables conntrack wget-ssl

# 2. Установка пакетом .ipk (рекомендуется): архитектура и SHA256 — автоматически
wget -qO- https://raw.githubusercontent.com/R17a/Susanin.Keenetic/main/install.sh | sh -s -- --ipk

# либо из tar-архива:
# wget -qO- https://raw.githubusercontent.com/R17a/Susanin.Keenetic/main/install.sh | sh

# 3. Проверка
susanin version && susanin status
```

Установщик сам определит архитектуру, LAN и VPN, спросит подтверждение и
запустит демон. `susanin.conf`, `vpn_always.txt` и `vpn_never.txt` при
обновлении **не перезаписываются**, но списки **могут дополняться** новыми
записями из сборки (merge; существующие строки не удаляются). Чтобы обновление
вообще не касалось списков — флаг `--keep-lists`:

```sh
susanin update --keep-lists          # списки не трогать
sh install.sh --keep-lists           # то же при установке
```

Для старых BusyBox (где `tar` не знает `--exclude`) — `bootstrap.sh`:

```sh
cd /opt/tmp
wget -qO- https://raw.githubusercontent.com/R17a/Susanin.Keenetic/main/bootstrap.sh | sh -s -- --yes
# пакетом .ipk:  sh -s -- --yes --ipk
```

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
  если задан `web_token`, первый раз — `http://192.168.1.1:8087/?token=<токен>`:
  сервер поставит cookie, и стили/скрипты загрузятся сами, без токена в URL;
- раздел «Конфигурация агента» — правка параметров из браузера; списки
  `vpn_always`/`vpn_never` — перетаскиванием между колонками **или кнопкой
  «Редактор»** (весь файл текстом: можно вставить сразу много строк, сохранить
  комментарии `#` и пустые строки; нераспознанные строки отбрасываются, панель
  сообщит их число);
- рядом с версией в шапке может появиться оранжевый «!» — на GitHub есть более
  новый релиз; наведите курсор (или коснитесь) — подсказка «Есть обновление до
  версии …», клик открывает страницу релиза. Проверка идёт раз в 12 ч и
  отключается в конфиге (`release_check=0`);
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

**Клиенты qWDTT — через Susanin.Keenetic (если так нужно).** Штатная поддержка
«LAN-серверов»: `lan_server_interfaces=wdtt0,wdttraw0` + `mss_clamp=pmtu`,
затем `sh /opt/susanin/tools/susanin.sh rescan` и `restart`. Это двойной туннель
(клиент → qWDTT → Susanin → VPN): скорость ниже, `mss_clamp` обязателен.
`ipv6_block`/`quic_block` на клиентов qWDTT не действуют. Откат: очистить
`lan_server_interfaces` и снова `rescan`.

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

**Что нужно знать, чтобы профиль заработал** (актуально для 0.4.0):

1. **`reload` применяет профили.** После правки `susanin.conf` или сохранения в
   панели достаточно `susanin.sh reload`; `profiles.sh up` остался для ручного
   применения.
2. **`profileN_egress` — точное имя интерфейса** (`ip link show`, у Keenetic это
   `nwg0`, `nwg1`, … по порядку создания подключений). Если интерфейса нет,
   профиль пропускается, в логе — `[profiles] <имя>: egress … не найден`.
3. **Профиль приоритетнее основной схемы.** Его цепочка стоит первой в
   PREROUTING, основная цепочка делает `RETURN` для адресов профиля, а метка
   дублируется в `CONNMARK` — адрес, выученный ранее, уйдёт в профиль.
4. **Туннель профиля с MTU меньше 1500 требует `mss_clamp`.** Иначе страницы
   будут открываться, но очень медленно. Ставьте `mss_clamp=pmtu` (или число не
   больше `MTU − 40`: для 1200 — 1160, для 1420 — 1380).
5. **Для сервисов с ротацией адресов** (Google/Gemini, CDN) список доменов
   ненадёжен: браузер резолвит через DoH и получает другие IP. Используйте
   `profileN_geo_url` со CIDR-списком в виде простого текста.
6. **Метки профилей по умолчанию разные** (`0x40000000`, `0x08000000`,
   `0x04000000`, `0x02000000` по индексу) — задавать вручную не нужно.
7. Проверить, что профиль реально срабатывает, можно по счётчику пакетов:
   `iptables -t mangle -vnL SUSANIN_PROFILES` (метка пакета в conntrack не видна).

**XRay/REALITY как egress (режим `tproxy`).** Рекомендуемый способ (без TUN):
в `susanin.conf` — `egress_type=tproxy`, `tproxy_port=12345`; при желании UDP —
`udp_relay=1`, `udp_relay_port=1081`, `socks_addr=127.0.0.1`, `socks_port=1080`.
Сам бинарь Xray в поставку не входит — его скачивает установщик:
```sh
sh bootstrap.sh --with-xray --yes                    # tar-архив
wget -qO- https://raw.githubusercontent.com/R17a/Susanin.Keenetic/main/install.sh \
  | sh -s -- --ipk --with-xray-tproxy                 # пакет .ipk
```
(Xray ставится в `/opt/sbin/xray`, SHA256 сверяется; конфиг-шаблон —
`/opt/susanin/etc/xray-tproxy.json.example`.)
Проще всего включить — `sh /opt/susanin/tools/xray-egress.sh enable` (сам выставит
ключи, поднимет Xray и перезапустит агента). Откат — `disable`. Подробности,
проверка TCP/UDP и грабли — [XRAY.md](XRAY.md).

**Резервный путь через Xray (кандидат `tproxy`).** В `egress_interface` можно
указать `tproxy` (синоним `xray`) вместе с обычными интерфейсами:
`egress_interface=nwg1,tproxy`. Кандидат проверяется SOCKS-пробой апстрима Xray;
если `nwg1` пропал, агент переключит датаплейн в tproxy-режим (`down` + `up`,
нужен запущенный Xray), а при возврате — обратно. Fail-safe: пока Xray не слушает
`tproxy_port`, переключения не будет (в логе WARN).

**Клиенты OpenConnect-сервера.** Если на роутере поднят OpenConnect, добавьте в
`lan_interfaces` шаблон `oc+` В КОНЕЦ списка (`br0,br1,oc+`) — иначе трафик
клиентов не обрабатывается («часть сайтов висит»). `discover`/`rescan` держат
`oc+` и подсеть пула автоматически, пока сервер жив.
Если на телефоне `DNS_PROBE_FINISHED_NXDOMAIN` (Android шлёт DNS на 8.8.8.8) —
включите `dns_hijack=1`: DNS клиентов `oc+`/`wdtt+` уйдёт на резолвер роутера,
`br0`/`br1` не затрагиваются.

## Обновление и удаление

```sh
sh /opt/susanin/tools/susanin.sh update 0.4.0     # или latest — последний релиз
sh /opt/susanin/tools/susanin.sh uninstall        # снять, конфиг сохранить
sh /opt/susanin/tools/susanin.sh uninstall --purge # удалить всё
```

Пакетом Entware (`.ipk`, рекомендуется): установщик сам определит архитектуру,
скачает пакет из релиза, сверит SHA256 и выполнит `opkg install`:

```sh
wget -qO- https://raw.githubusercontent.com/R17a/Susanin.Keenetic/main/install.sh | sh -s -- --ipk
```

Флаги: `--version v0.4.0`, `--force` (переустановить), `--yes` (без вопросов),
`--with-xray-tproxy` (плюс Xray). Вручную то же самое:

```sh
mkdir -p /opt/tmp
wget -O /opt/tmp/susanin-keenetic_0.4.0_mipsel-3.4.ipk \
  https://github.com/R17a/Susanin.Keenetic/releases/download/v0.4.0/susanin-keenetic_0.4.0_mipsel-3.4.ipk
opkg install /opt/tmp/susanin-keenetic_0.4.0_mipsel-3.4.ipk
```

Файл под свою архитектуру (её показывает `opkg print-architecture`) выбирайте по
таблице в [README.md](README.md) → «Пакетом Entware `.ipk`». Удаление:

```sh
opkg remove susanin-keenetic        # служба, init и правила снимаются; данные остаются
rm -rf /opt/susanin                 # если нужно удалить и конфиг/списки/состояние
```

`www/` (веб-панель) обновляется и через `susanin.sh update` — раньше правки
статики до установленных систем не доезжали.

Если что-то не работает — см. [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## Благодарности

За помощь проекту (тестирование на реальных роутерах, отчёты с логами, разбор
проблем и предложения по улучшению) — спасибо **Gave_Karen**, **pegakmop** и
**NJmist**.
