# Susanin.Keenetic — если что-то не работает

Сначала соберите диагностику:
```sh
sh /opt/susanin/tools/diagnose.sh   # проверит окружение, конфиг, правила, списки
sh /opt/susanin/tools/report.sh     # отчёт: /opt/susanin/var/report.txt
```
`diagnose.sh` в конце сам печатает подсказки, что поправить.

## Установка падает на распаковке (`tar: unrecognized option: exclude`)

В старых BusyBox у `tar` нет `--exclude`. Ставьте установщиком:

```sh
cd /opt/tmp
wget -qO- https://raw.githubusercontent.com/R17a/Susanin.Keenetic/main/bootstrap.sh | sh -s -- --yes
# только показать платформу (arch, ядро, BusyBox): sh susanin-install.sh --check
```

Он распаковывает только бинарник под свою архитектуру (без полной распаковки на
~85 МБ); полную можно разрешить лишь явным `--allow-full-unpack`. Если `tar` не
умеет и список файлов — поставьте GNU tar: `opkg update && opkg install tar`.

Вручную: `tar -xzf susanin-keenetic-deploy-<arch>.tar.gz && sh install.sh --yes`
(чужие `bin/susanin-agent.*` можно удалить — нужный `install.sh` выбирает сам).
Xray в архиве нет: `sh bootstrap.sh --with-xray --yes`. Архив в RAM — `--tmp /tmp`.

## `opkg: Not downgrading package susanin-keenetic ... 0.4.0.RC1.Hotfix to 0.4.0`

Так opkg сравнивает версии: `0.4.0` для него **меньше** `0.4.0.RC1.Hotfix`
(короткая строка идёт раньше суффикса), поэтому установка `0.4.0` поверх
`0.4.0.RC1.Hotfix` считается понижением и блокируется.

Варианты:

```sh
# поставить пакет с явным разрешением понижения
opkg install --force-downgrade /opt/tmp/susanin-keenetic_0.4.0_<arch>.ipk

# либо обновиться архивом — там проверки версии нет
sh /opt/susanin/tools/susanin.sh update v0.4.0
```

Свежий `install.sh` из `main` уже добавляет `--force-downgrade` сам, так что
`wget -qO- .../main/install.sh | sh -s -- --ipk` тоже сработает.

## Сайт «грузится бесконечно» (tproxy + HTTP/3)

Спиннер на конкретной странице, хотя `ping`/`curl` работают и сайт может вообще
идти напрямую (`ipset test susanin_never <IP>` → «is in set») — тогда `vpn_never`
не поможет. Причина: браузер идёт по HTTP/3 (QUIC, UDP 443), а в tproxy помеченный
UDP уходит в UDP-релей (Xray) и ответа нет.

```sh
sed -i 's/^quic_block=.*/quic_block=1/' /opt/susanin/etc/susanin.conf
grep -q '^quic_block=' /opt/susanin/etc/susanin.conf || echo 'quic_block=1' >> /opt/susanin/etc/susanin.conf
sh /opt/susanin/tools/susanin.sh restart
iptables -t mangle -S PREROUTING | grep -- '--dport 443 -j DROP'   # ждём 2 правила
```

`xray-egress.sh enable` ставит `quic_block=1` сам, `diagnose.sh` предупреждает,
если он не 1.

## Сайт отдаёт 403 / блок-страницу

Симптом: сайт отвечает `HTTP 403`, в теле — «Доступ запрещён … с вашего ip адреса
наблюдается подозрительная активность», в заголовках `X-SP-CRID`; в тексте указан
IP. С телефона по мобильной сети тот же сайт открывается. `vpn_always`/`vpn_never`
тут **ни при чём** — это блокировка вашего публичного IP на стороне сайта
(антибот/защита от накрутки), а не маршрутизация.

Что проверить:
```sh
# WAN-IP роутера — его же печатает diagnose.sh
ip route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p'
# тот же ответ с роутера и с ПК (значит, дело не в клиенте и не в туннеле)
curl -sSI https://САЙТ | head -5
```
Что делать:
1. Написать в поддержку сайта, приложив текст ошибки (там есть Datetime/ip/id).
2. Сменить публичный IP (переподключение PPPoE / другой выходной канал).
3. Не «лечить» это списками: добавление сайта в `vpn_never` ситуацию не изменит,
   а в `vpn_always` — просто сменит видимый сайту IP на адрес VPN.

`diagnose.sh` печатает строку `WAN-IP: …` — по ней сразу видно, совпадает ли
заблокированный адрес с вашим.

## `vpn_never` и поддомены: «сайт открывается частично»

По wildcard-строке (`*.example.com`) пиннятся apex и типовые поддомены
(`www`, `cdn`, `api`, `static`, `m` + две пробы), но у сервисов с несколькими
хостами часть адресов может остаться вне набора — тогда HTML приходит, а стили и
картинки с других поддоменов уходят в VPN и не грузятся.

Правило: для сервисов с несколькими хостами указывайте **явные имена**, а не
wildcard. Проверка:
```sh
nslookup static.example.com   # адрес должен быть в наборе:
ipset test susanin_never <IP>
sh /opt/susanin/tools/diagnose.sh | sed -n '/vpn_never: wildcard/,+2p'
```

## Сайт не открывается

1. **Проверьте VPN.** `sh /opt/susanin/tools/susanin.sh status` — демон должен
   быть запущен, а правила и таблица — на месте. Если VPN-интерфейс удалили или
   переименовали — `sh /opt/susanin/tools/susanin.sh rescan`.
2. **DNS.** Без шифрованного DNS (DoH/DoT) провайдер подменяет ответы, и клиент
   не получает настоящий адрес даже при рабочем VPN. Включите DoH/DoT. Проверка:
   `nslookup example.com` должен вернуть реальный IP.
3. **Политика Keenetic.** Любая политика у клиента (Web → «Приоритеты
   подключений») перекрывает Susanin.Keenetic. У такого клиента оставьте системную
   политику «по умолчанию».
4. **Домен в `vpn_never.txt`.** Такой адрес специально идёт напрямую. Проверьте
   списки.

## Открывается, но с задержкой в первый раз

Так работает обучение: первый заход идёт напрямую → обрывается → Susanin.Keenetic
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

## После обновления вернулись записи, которые я удалил из списка

Так работает merge: `install.sh`/`update.sh` (и `.ipk`-`postinst`) **дополняют**
`vpn_always.txt`/`vpn_never.txt` строками из сборки. Существующие строки не
удаляются, но удалённые и даже закомментированные записи возвращаются — они
дописываются в конец под маркером `# susanin-update: added missing default entries`
(комментарий считается отсутствующей записью).

Чтобы обновление не трогало списки вообще, запускайте его с флагом:

```sh
sh /opt/susanin/tools/susanin.sh update 0.4.1 --keep-lists
# или напрямую: sh /opt/susanin/tools/update.sh --version v0.4.1 --keep-lists
```

В выводе будет строка `--keep-lists: списки vpn_always/vpn_never не трогаем`, а
файлы останутся байт в байт (проверить: `md5sum /opt/susanin/etc/vpn_*.txt` до и
после). Синоним флага — `--no-lists`, обратный — `--lists`.

Оговорка: при обновлении **через `.ipk`** (`opkg install`) флаг передать нельзя —
`postinst` дополняет списки всегда. Если нужен полный контроль над списками,
обновляйтесь скриптом с `--keep-lists` (или после `opkg upgrade` удалите
дописанный блок и нужные строки, затем `susanin reload`).

## VPN-интерфейс исчез / подключение удалили

Демон сам переоценивает egress: пропавший интерфейс исключается, живой
подхватывается; если живых нет — всё идёт напрямую (запись в логе). Чтобы
подтянуть новый интерфейс из системы:
`sh /opt/susanin/tools/susanin.sh rescan`.

## Трафик идёт мимо VPN (правила снесены)

Keenetic пересобирает правила при изменениях в Web. Susanin.Keenetic восстанавливает свои
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

Что делает Susanin.Keenetic: при старте проверяет порт `tproxy_port`; если Xray не
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

## xray.log быстро растёт (строки `from … accepted …`)

Это **access-лог Xray**. Он **не управляется `loglevel`** — выключается
отдельным параметром `"access": "none"` в блоке `log` файла
`/opt/susanin/etc/xray-tproxy.json`:
```json
"log": { "access": "none", "loglevel": "warning" },
```
В свежих сборках `xray-egress.sh enable|run` выставляет это сам и перезапускает
Xray. Вручную:
```sh
sed -i 's|"log"[[:space:]]*:[[:space:]]*{|"log": { "access": "none",|' /opt/susanin/etc/xray-tproxy.json
sh /opt/susanin/tools/xray-egress.sh enable     # перезапустит Xray
: > /opt/susanin/var/xray.log                    # обрезать старый
```
(`log_level` Susanin.Keenetic и `xray_loglevel` Xray — независимые ключи.)

## XKeen и Susanin.Keenetic вместе

**XKeen** — отдельный перехватчик трафика, у него свои правила и маршруты. Если он
запущен, он мешает Susanin.Keenetic: сайты «то работают, то нет», правила Susanin.Keenetic
сбрасываются. Не запускайте XKeen вместе с Susanin.Keenetic; для Reality используйте
встроенный XRay-режим Susanin.Keenetic (скрипт `S05xkeen` держите выключенным).

## «all egress DOWN», хотя VPN работает (ICMP молчит)

Симптом: в логе `all egress DOWN, fail-open DIRECT`, наборы `susanin_ok_*`
пусты, обучение стоит — но `ping 1.1.1.1` с адреса туннеля и HTTPS через VPN
работают, а после `susanin.sh restart` всё оживает само.

Причина: health-проба ходит ICMP-эхом со своим Echo ID; если на промежуточном
сервере каскада (Keenetic → РФ → NL) залипло NAT-состояние по этому ID, ответы
перестают приходить, хотя туннель жив. До 0.4.0 ID был постоянным (равен PID
демона), поэтому «лечил» только перезапуск.

Что делать:
1. Проверить руками, что туннель жив:
   ```sh
   ping -I nwg0 1.1.1.1            # нужен адрес/интерфейс вашего туннеля
   curl -sI https://1.1.1.1 --interface nwg0 | head -1
   ```
2. Если ping идёт, а агент считает egress мёртвым — обновиться до 0.4.0:
   там Echo ID случайный на каждую цель, при молчании ICMP делается TCP-проба
   через тот же egress, а простой пишется в лог раз в 5 минут.
3. Посмотреть, что было:
   ```sh
   grep -E 'egress .* (UP|DOWN)|all egress DOWN|health:' /opt/susanin/var/susanin.log | tail -10
   sh /opt/susanin/tools/diagnose.sh | sed -n '/Health (по логу)/,+6p'
   ```
4. До обновления помогает `sh /opt/susanin/tools/susanin.sh restart` (новый ID)
   либо `health_mode=tcp` — тогда проба идёт TCP-соединением, без ICMP.

## Клиенты OpenConnect (oc+) не обрабатываются

Симптом: с телефона/ноутбука по OpenConnect «обычный интернет» очень медленный,
а заблокированные сайты не открываются вовсе. При этом `susanin.sh status`
зелёный: цепочка `SUSANIN` есть, `ip rule` на месте.

Причина: правила перехвата строятся по `lan_interfaces`, а интерфейса `oc*` там
нет. Tun у Keenetic создаётся **по требованию** (на каждого клиента свой `ocN`),
поэтому после `susanin.sh rescan` или сохранения формы в панели при отключённом
клиенте `oc0` выпадает из списка, а подсеть пула в `lan_subnets` остаётся —
«полу-состояние».

Лечение:
```sh
# 'oc+' — В КОНЕЦ списка: dns_sniff и DNS-fallback берут первый интерфейс
sed -i 's|^lan_interfaces=.*|lan_interfaces=br0,br1,oc+|' /opt/susanin/etc/susanin.conf
sh /opt/susanin/tools/susanin.sh restart
```
С 0.4.0 `discover`/`rescan` больше **не добавляют** `oc+` сами (сервер
есть не у всех) — нужен явный `--with-oc` при установке или строка в конфиге, как
выше. Зато если `oc+` указан, подсеть пула поддерживается автоматически.

Отдельный случай (исправлено в 0.4.0): Keenetic помечает трафик oc-клиентов
своей меткой `0xffffaXX`, и она пересекается с нашей маской `0x30000000`. Из-за
этого правило «`-m mark 0x0/0x30000000`» не срабатывало, CONNMARK не ставился и
трафик уходил по политике NDM, а не в VPN. Теперь для `oc*` метки ставятся без
этой предусловицы. На старых сборках проверка выглядела так:

```sh
iptables -t mangle -S SUSANIN | grep 'oc+' | head          # видно ли наши CONNMARK-правила
conntrack -L 2>/dev/null | grep 172.16.5 | head -3         # mark=0xffffaXX = не обработан
```
Если у клиентов `mark=0xffffaXX` — обновитесь до 0.4.0 или поставьте
`lan_interfaces` с `oc+` и перезапустите службу.

Проверка, что клиент обрабатывается:
```sh
iptables -t mangle -vnL SUSANIN | awk '/oc\+/ && $1>0' | grep -c CONNMARK
grep 172.16.5 /proc/net/nf_conntrack | head -3     # mark=0x20000000/0x10000000
```

## Веб-панель не открывается

- В `susanin.conf`: `web_enable=1`, `web_listen` — **LAN-адрес роутера**
  (`192.168.1.1`), не `0.0.0.0` и не `127.0.0.1`.
- Запустите сервис: `/opt/etc/init.d/S95susanin-web start` или
  `sh /opt/susanin/tools/susanin.sh web start` (`… web status` — состояние).
- Панель пропала после кнопки Restart? В 0.4.0 это исправлено (демон и web
  разведены). До обновления поможет `S95susanin-web start`.
- Проверка: `netstat -lnt | grep 8087` и
  `curl -s -H 'X-Auth-Token: ТОКЕН' http://127.0.0.1:8087/api/status | head -c 200`.
- **Пустой `web_token` = доступ без пароля, но только из LAN** — панель работает
  полностью (Reload/Restart/сохранение). Так и задумано:
  токен — необязательное усиление. Если хотите закрыть панель паролем:
  `susanin-agent config set web_token <секрет> && susanin restart`, затем
  открывайте один раз с `?token=<секрет>` — дальше токен хранится в браузере и
  уходит заголовком `X-Auth-Token`/cookie.
- **Панель без стилей, кнопки не работают (задан `web_token`).** В сборках до
  0.4.0 проверка токена распространялась и на `style.css`/`app.js`/`config.js`,
  а браузер не прикладывает `X-Auth-Token` к `<link>`/`<script>`. В 0.4.0 первый
  GET с `?token=…` ставит cookie `susanin_token` (`Path=/`, `HttpOnly`, год),
  и подресурсы авторизуются автоматически. На старой сборке — обновите
  бинарник либо временно очистите токен.

## Нет значка «!» рядом с версией

Значок появляется только если агент **успешно** узнал с GitHub, что там есть
релиз новее установленного. Проверьте по порядку:

- в `susanin.conf` не выключена проверка: `release_check=1`; период —
  `release_check_interval` (по умолчанию 43200 секунд, 12 часов);
- на роутере есть HTTPS-клиент и корневые сертификаты:
  `wget -qO- https://api.github.com/repos/R17a/Susanin.Keenetic/releases/latest | head -c 200`
  (если BusyBox-wget без TLS — `curl -fsS --max-time 10 <тот же URL>`);
- последняя проверка была недавно, а GitHub тогда был недоступен — подождите
  период или удалите кэш и перезапустите демон:
  ```sh
  cat /opt/susanin/var/release.state     # tag=, url=, checked=
  rm -f /opt/susanin/var/release.state
  sh /opt/susanin/tools/susanin.sh restart
  ```
- установленная версия уже равна последнему релизу (или новее) — значка не будет;
  это же верно для dev-сборки: `0.4.2-dev1` считается старее `0.4.2`, но
  `0.4.2` и `0.4.1` — уже нет обновления;
- в `/api/status` поля `version_latest`, `update_available`, `release_url`,
  `release_checked` показывают, что именно запомнил агент:
  ```sh
  curl -s -H 'X-Auth-Token: ТОКЕН' http://127.0.0.1:8087/api/status | head -c 300
  ```

## Сайт не открывается: бан (ТСПУ) или ошибка Susanin?

Сначала понять, **где** рвётся. На роутере для проблемного имени:

```sh
nslookup px1.rapo.dev                       # какой IP
curl -v --max-time 10 https://px1.rapo.dev 2>&1 | tail -20     # напрямую
curl -v --max-time 10 --interface nwg1 https://px1.rapo.dev 2>&1 | tail -20  # через VPN
grep 193.233.218.166 /proc/net/nf_conntrack | head -3          # какая метка у потока
ipset test susanin_never 193.233.218.166                       # не в «напрямую» ли
ipset test susanin_ok_tcp 193.233.218.166                       # не выучен ли в VPN
```

Что означает вывод:

- **напрямую `Connection reset by peer` сразу после ClientHello / `SSL_ERROR_SYSCALL`**, а через `nwg1` — `200`/`302` → это блокировка по SNI (ТСПУ). Лечится VPN; в Susanin добавьте домен в `vpn_always.txt` (или дождитесь автообучения).
- **напрямую `timed out`** → блок по IP; то же лечение.
- **через VPN тоже `reset`/`timeout`** → дело не в блокировке: хостинг/файрвол не пускает адрес VPN-выхода (часто бывает у российских хостингов и у серверов с allowlist). Проверьте `ping -I nwg1 <IP>` и `curl` ещё раз; если так — нужен другой egress, Susanin не поможет.
- **оба способа дают `200`** → блокировки нет, а Susanin ошибся (ложное срабатывание). Сбросьте адрес: `susanin forget <IP>`, при необходимости уберите из `vpn_always.txt`.
- Если в логе по этому IP видно `COOLDOWN` — это значит «проба через VPN не прошла», а не «заблокировано»: см. третий пункт.

## Профили маршрутизации не применяются

- профиль включается, только если задан `profileN_name`; файл списка
  (`profileN_list`) должен существовать и быть непустым;
- `profileN_egress` — существующий интерфейс;
- проверьте `diagnose.sh`, затем `sh /opt/susanin/tools/profiles.sh up` и
  `sh /opt/susanin/tools/profiles.sh status`;
- адрес обрабатывается **первым совпавшим** профилем.

### `entries=0` — набор профиля пуст

`status` при этом показывает бодрое «ip rule=есть, default в таблице=есть,
правило mark=есть»: правила и маршрут создаются независимо от содержимого
набора, а метка не встанет ни на один пакет.

```sh
sh /opt/susanin/tools/profiles.sh status     # смотрим entries=
cat -A /opt/susanin/etc/profiles/<имя>.txt | tail -3   # строка обязана кончаться $
nslookup <домен_из_списка>                   # резолвится ли он с роутера
```

Три причины по частоте:

1. **В файле списка нет перевода строки в конце** (создан через `printf` без
   `\n`, «Блокнотом», копипастом). В сборках до 0.4.0 `fill_set()` терял
   последнюю строку: `read` на EOF без разделителя возвращает не-ноль, и тело
   цикла не выполняется — файл из одной строки даёт пустой набор. В 0.4.0
   исправлено (последняя строка читается и без `\n`); на старой сборке допишите
   перевод строки (`printf 'домен\n' >> файл`).
2. **Домен не резолвится с роутера** (нет DNS/фильтр): `nslookup` пуст → в набор
   ничего не добавится. Указывайте IP/CIDR или добавьте `profileN_geo_url`.
3. **Файл пуст или закомментирован целиком** — тривиально, но проверяется первым.

После правки списка: `sh /opt/susanin/tools/profiles.sh refresh` (перечитать
адреса) или `up` (если профиль ещё не поднимался).

### Профиль не применился после правки `susanin.conf` или сохранения в панели

`reload` (`SIGHUP`) пересобирает только основной датаплейн (`datapath.sh`) —
профили он **не поднимает**. Статические профили (набор, `ip rule`, маршрут в
таблице) создаёт `profiles.sh up`, а он вызывается лишь при старте службы
(`/opt/etc/init.d/S94susanin start`) или вручную:

```sh
sh /opt/susanin/tools/profiles.sh up
/opt/etc/init.d/S94susanin restart      # если нужно перезапустить всё
```

### Профиль поднят, но счётчик пакетов равен нулю

Значит профиль не поймал ни одного пакета. Две причины:

- адресами уже владеет основная схема (выученные `susanin_ok_*`/`susanin_test_*`
  или `vpn_always`) — разбор и обходной путь в разделе «Профиль маршрутизации:
  трафик идёт мимо своего интерфейса»;
- клиент ходит на другие адреса, чем попали в набор: браузер резолвит через DoH
  и получает иные IP из ротации сервиса (типично для Google/Gemini). Проверьте
  `nslookup` **на клиенте** и сравните с набором.

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
- Если пишет `xray.log` (много `accepted`-строк) — понизьте уровень Xray, см.
  раздел «xray.log быстро растёт».
- Убрать поток записей на носитель:
  ```sh
  sed -i 's/^disk_mode=.*/disk_mode=soft/' /opt/susanin/etc/susanin.conf
  sh /opt/susanin/tools/susanin.sh restart
  rm -rf /opt/susanin/var/datapath.bak
  ```
  (в свежих сборках бэкап правил один — `/opt/susanin/var/datapath.bak`, файлы
  перезаписываются, копии не накапливаются; остатки старого формата
  `var/datapath-<дата>` и `var/archive` удаляются автоматически при первом `up`).

## Не возвращается на основной VPN после восстановления (failback)

Симптом: `egress_interface=nwg2,nwg0`; `nwg2` упал, трафик ушёл на `nwg0`, а
когда `nwg2` поднялся — трафик остался на `nwg0` (WARP) до ручного `reload`.

- Убедитесь, что включён возврат: `egress_failback=1` в `susanin.conf`.
- Возврат происходит после антидребезга `egress_failback_debounce` (по умолчанию
  30 с стабильного UP). Уменьшите, если нужно быстрее.
- В логе ищите строки `egress <X> UP` и `egress <X> -> <Y> (failback)`.
- Проверка выхода: `curl -s https://chatgpt.com/cdn-cgi/trace`.

## Xray пропал / падает (память, OOM, watchdog)

Симптом: страницы «крутятся», в `susanin.log` — `tproxy: Xray :12345 пропал …
fail-open DIRECT`.

- С `xray_watchdog=1` (по умолчанию) агент сам поднимает Xray с backoff и
  возвращает правила — в логе `tproxy: Xray … поднимаю`. Если Xray падает
  регулярно, смотрите память.
- Диагностика: `sh /opt/susanin/tools/diagnose.sh` — покажет `free`, swap, топ
  по RSS и случаи OOM из `dmesg`.

## Роутер «зависает»: в top много процессов xray

Симптом (2026-10-10): `top` показывает десятки процессов
`/opt/sbin/xray run -config /opt/susanin/etc/xray-tproxy.json` (часть в состоянии
`D`), память почти вся занята (`101M/122M`), `load average` ~20 — интернет встаёт.

Причина (в сборках до `0.4.0`): `S93xray-tproxy` искал свой Xray через `pidof xray`
(BusyBox-апплета может не быть в окружении init-скриптов — тогда `stop` не убивал
никого, а каждый `start` поднимал новый процесс) и посылал один `SIGTERM` без
ожидания завершения: если процесс висел в `D`, следующий `start`/`restart` (в том
числе от вотчдога агента) поднимал второй экземпляр рядом со старым.

Лечение на роутере (ручное):
```sh
sh /opt/susanin/tools/susanin.sh stop      # чтобы агент не поднимал новые Xray
for p in /proc/[0-9]*; do
    tr '\0' ' ' < "$p/cmdline" 2>/dev/null | grep -q xray-tproxy.json \
        && kill -9 "${p#/proc/}"
done                                        # убиваем ТОЛЬКО наш конфиг
/opt/etc/init.d/S93xray-tproxy start
sh /opt/susanin/tools/susanin.sh start
```
Если процессы в состоянии `D` не уходят — перезагрузка роутера.

Что изменено в `0.4.0`: свой PID пишется в `/opt/susanin/var/xray.pid`,
процессы ищутся по `cmdline` с нашим конфигом (без `pidof`), `stop` ждёт
завершения и добивает `kill -9`, `restart` отменяется, если старый процесс не
ушёл, а вотчдог агента не поднимает новый экземпляр, пока жив старый (в логе —
`процесс Xray есть, но :порт не слушает — повторный запуск пропускаю`).
`S93xray-tproxy status` покажет текущий PID.
- На роутере ~128 МБ без swap задайте в `susanin.conf`:
  ```
  xray_gogc=50
  xray_gomemlimit=64MiB
  ```
  и перезапустите Xray: `xray-egress.sh restart`.
- Ручной подъём: `/opt/etc/init.d/S93xray-tproxy start`.

## Отчёт для Issue

```sh
sh /opt/susanin/tools/report.sh
# файл: /opt/susanin/var/report.txt
```

Если речь о деградации со временем (память, размеры наборов, рост conntrack,
ошибки в логе) — приложите ещё `var/soak.log`:

```sh
sh /opt/susanin/tools/soak.sh &   # метрики раз в 60 c; Ctrl-C даёт сводку
```

## IPTV / сайт за Cloudflare: «то грузится, то нет»

Симптом: приложение/плеер периодически встаёт, показывает ссылку и конечную
страницу сервиса; у части пользователей работает, у части — нет. Сервис за CDN
(Cloudflare/Fastly) — у него много быстро меняющихся edge-адресов.

Что важно знать:
- **Не кладите адреса провайдера/сайта в `vpn_never.txt`.** `vpn_never` — это
  принудительный DIRECT: правило `susanin_never dst -j RETURN` срабатывает
  раньше маркировки, и Susanin уже не сможет завернуть адрес в VPN, даже если
  автообучение поймёт, что прямой путь «ломается». Именно это даёт «CONFIRMED
  есть, а всё равно лагает».
- **`ok_ttl=0` (не истекает)** опасен: однажды выученный адрес остаётся в VPN
  навсегда, наборы растут. Ставьте конечный TTL (напр. `ok_ttl=21600`).
- **IPv6.** Susanin работает только по IPv4. Если у клиента/провайдера есть
  глобальный IPv6, а у CDN есть AAAA-записи — часть трафика идёт мимо Susanin и
  может душиться. Проверка: `ip -6 route show default` (пусто — IPv6 нет).
- **FASTNAT/offload.** Уже установленный поток (`mark=0`, `[FASTNAT]`) не
  удаляется `conntrack -F` и держится на старом пути. Чтобы применить новый
  маршрут, перезапустите воспроизведение на клиенте (или временно снимите
  «Аппаратное ускорение NAT» в Keenetic).

Диагностика (заменить `<TV>` на IP приставки, напр. `192.168.1.64`):
```sh
# 1) какой хост резолвит плеер (LAN-DNS открытым текстом; DoT — уже наружу)
tcpdump -i br0 -n "host <TV> and port 53"

# 2) куда реально идёт поток: через Xray (sport=12345) или напрямую (mark=0)
grep -F '<TV>' /proc/net/nf_conntrack | grep -E 'dport=80|dport=443|sport=12345'

# 3) что решил агент по этим адресам
grep -iE 'STALL|CONFIRMED|COOLDOWN' /opt/susanin/var/susanin.log | tail -40

# 4) не залип ли адрес в never (должно быть пусто)
grep -nE '<первые-октеты-IP>' /opt/susanin/etc/vpn_never.txt
ipset list susanin_never | grep '<IP>'
```

Обходное на время (если подтвердилось, что прямой путь режется): добавить
нужные хосты в `vpn_always.txt` (для конкретных доменов) и перезапустить:
`sh /opt/susanin/tools/susanin.sh reload`. Универсальное решение (агрегация по
CDN-префиксу без ручных списков) — в `PLAN.md`, раздел «Универсальное решение
для CDN/Cloudflare».

## Профиль маршрутизации: трафик идёт мимо своего интерфейса

Симптом: профиль задан (`profileN_egress`, таблица, список), но сайт из списка
открывается через основной туннель или провайдера, а не через указанный интерфейс.

Проверьте (короткие команды — после установки dev7):

```sh
susanin profiles status      # или: sh /opt/susanin/tools/profiles.sh status
ip rule show | grep 0x4
ip route show table 201      # номер таблицы профиля
iptables -t mangle -S SUSANIN_PROFILES
ipset list susanin_prof_<имя> | head
```

Что означает вывод:

- `egress=… (НЕТ живого интерфейса!)` — интерфейса нет в `/sys/class/net`:
  профиль пропускается, метка не ставится (иначе трафик ушёл бы по чужой политике).
  Проверьте имя интерфейса (`ip link show`) и укажите его в `profileN_egress`.
- `ip rule=НЕТ` — правило метки не создано: профиль не сможет использовать свою
  таблицу. Перезапустите профили (`susanin profiles up`).
- `default в таблице=НЕТ` — в таблице профиля нет маршрута по умолчанию через
  интерфейс профиля; обычно это значит, что интерфейс был недоступен в момент
  поднятия профиля.
- `правило mark=НЕТ` — правило маркировки не добавлено (профиль был пропущен из-за
  пунктов выше). В логе будет строка `[profiles] <имя>: … профиль пропущен`.
- предупреждение «правил с метками 0x4… больше одного»: метка профиля может
  пересекаться с политикой Keenetic («Приоритет подключений») — тогда помеченный
  трафик уходит на её интерфейс. Проверьте `ip rule show` и при конфликте задайте
  профилю свободную метку `profileN_mark=0x40080000` и перезапустите профили.

Список профиля наполняется адресами, разрешёнными в момент настройки. Если домен
сменил адреса (CDN), выполните `susanin profiles refresh` — списки перерезолвятся
без пересборки правил.

### Счётчик пакетов: единственный честный признак «профиль сработал»

Профиль ставит **метку пакета** (`-j MARK`), а не `CONNMARK`, поэтому в
`/proc/net/nf_conntrack` его метку **не видно** (`mark=` там — это connmark
основной схемы). Смотреть надо счётчик на правиле:

```sh
iptables -t mangle -vnL SUSANIN_PROFILES
# pkts растёт при заходе на адрес из списка — профиль работает
# pkts = 0 — профиль не совпал ни с одним потоком (см. ниже)
```

Ещё полезно: `ip route get <IP> mark 0x40000000` должно показать
`dev <egress> table <N>`, а `grep <IP> /proc/net/nf_conntrack` — куда реально
ушёл поток (`mark=0x20000000` → основной VPN/основная цепочка, `mark=0` → прямой
или профильный путь).

### «Заработало один раз, потом снова основной туннель»

Это не случайность, а конфликт профиля с основной схемой и автообучением.

Правило профиля требует `mark 0x0`, то есть **профиль берёт только те адреса,
которые не тронула основная цепочка**. Основная цепочка метит адрес из
`susanin_ok_*` / `susanin_test_*` (выученные) или из `vpn_always` и забирает поток
независимо от порядка цепочек: её проверки идут с маской `0x30000000`, а бит
профиля `0x40000000` в маску не входит. При этом движок читает `ctmark`, а профиль
ставит только метку пакета — поэтому профильный поток для движка выглядит
«неразмеченным» и попадает в автообучение. Отсюда картина: первое соединение
прошло по профилю, движок выучил адрес → далее адрес уходит в основной туннель
навсегда.

Проверка:

```sh
ipset test susanin_ok_tcp <IP>; ipset test susanin_test_tcp <IP>
grep -n '<IP>' /opt/susanin/etc/vpn_always.txt
grep '<IP>' /opt/susanin/var/susanin.state     # например «ok tcp <IP> <expire>»
```

Обходной путь **до** исправления (PLAN.md, п.17):

```sh
sh /opt/susanin/tools/susanin.sh forget <IP>            # снять обучение
# убрать адрес из vpn_always.txt, если он там есть
# и защитить от повторного захвата — добавить его в vpn_never.txt:
#   основная цепочка делает RETURN, метка остаётся 0, и профиль забирает поток
sh /opt/susanin/tools/profiles.sh up
```

Для сервисов с ротацией адресов (Google, Gemini, CDN) список доменов плохо
работает: браузер резолвит через DoH и получает не те IP, что `nslookup` на
роутере (отсюда «в наборе 63 адреса, а пакетов 0»). Используйте
`profileN_geo_url` с готовым CIDR-списком (простой текст, по строке один
IP/CIDR) либо заносите адреса, снятые `nslookup` **на клиенте**.

### Профиль работает, но страница открывается долго

Проверьте MTU туннеля профиля и `mss_clamp`:

```sh
ip link show <egress>                     # например mtu 1200 или 1420
grep -E '^mss_clamp' /opt/susanin/etc/susanin.conf
iptables -t mangle -vnL SUSANIN_MSS
```

`mss_clamp` не должен превышать `MTU − 40` (при MTU 1200 это 1160, при 1420 —
1380). Типовая ошибка — оставить `1400`: кламп формально включён, но разрешает
сегменты, которые туннель не несёт, и каждое соединение упирается в
фрагментацию/PMTU — рукопожатие проходит за секунды, а страница «висит».
Правильно: `mss_clamp=pmtu` (возьмёт значение из MTU маршрута) и
`mss_clamp_lan=1`. Подробности и правки — PLAN.md, п.16.