# Susanin.Keenetic — Develop-сборка `0.4.0-dev` (инструкция тестеру)

Это **тестовая (Develop)** сборка, не Release. В ней проверяются:
XRay-egress (VLESS/REALITY), веб-панель, профили маршрутизации и совместимость
с qWDTT_Server_Keenetic. Обычный режим (VPN из «Других подключений») работает
как раньше и не изменён.

Что в пакете (разложено по папкам): `bin/` — демон, `tools/` — скрипты,
`etc/` — образцы конфигов и списки, `init/` — автозапуск, `www/` — веб-панель,
`xray/` — бинари Xray, `docs/` — эта инструкция и другие. Краткая шапка —
`README-FIRST.txt` в корне пакета.

## Установка

Сборка лежит в папке **develop** репозитория:
`https://github.com/R17a/Susanin.Keenetic/tree/main/develop`.

1. Создать папку на роутере и скачать туда архив:
   ```sh
   mkdir -p /opt/tmp/sus-dist && cd /opt/tmp/sus-dist
   wget -O susanin-dev.tar.gz \
     https://github.com/R17a/Susanin.Keenetic/raw/main/develop/susanin-keenetic-0.4.0-dev.tar.gz
   ```
   (короткая ссылка на файл: `…/raw/main/develop/susanin-keenetic-0.4.0-dev.tar.gz`)
2. Распаковать и установить:
   ```sh
   tar -xzf susanin-dev.tar.gz
   cd susanin-keenetic-0.4.0-dev
   sh install.sh --yes
   ```
3. Проверить:
   ```sh
   sh /opt/susanin/tools/susanin.sh status
   /opt/susanin/bin/susanin-agent version      # покажет точную версию сборки
   ```

Конфиг, `vpn_always.txt` и `vpn_never.txt` при обновлении не перезаписываются.
В архиве нет ваших серверов: в шаблоне Xray только `SERVER/UUID/SNI/PBK/SID`.

## XRay (VLESS/REALITY)

XRay подключается как egress: Susanin помечает нужные соединения, TCP уходит в
Xray через `REDIRECT`, UDP — через релей в демоне. TUN не нужен.

**Настройка**
1. Положить бинарь Xray:
   ```sh
   cp xray/xray.mipsel /opt/sbin/xray && chmod +x /opt/sbin/xray   # mips/mipsel
   # или: cp xray/xray.aarch64 /opt/sbin/xray && chmod +x /opt/sbin/xray
   ```
2. Положить конфиг клиента и подставить свои данные:
   ```sh
   cp /opt/susanin/etc/xray-tproxy.json.example /opt/susanin/etc/xray-tproxy.json
   # в файле заменить SERVER/UUID/SNI/PBK/SID
   ```
3. Включить боевой режим:
   ```sh
   sh /opt/susanin/tools/xray-egress.sh enable
   ```
   Ключи (`egress_type=tproxy`, `udp_relay=1` и др.) прописываются сами.
   Логи Xray — отдельным ключом `xray_loglevel` (по умолчанию `warning`):
   `enable`/`run` применяют его и перезапускают Xray. Не ставьте `info` — иначе
   Xray пишет строку на каждое соединение (`from … accepted …`).

**Проверка**
Безопасно проверить один адрес (в туннель уйдёт только он):
```sh
sh /opt/susanin/tools/xray-egress.sh run 1.1.1.1 both
```
С компьютера в вашей сети:
```sh
# Windows:
nslookup ya.ru 1.1.1.1
nslookup -class=chaos -type=txt whoami.cloudflare. 1.1.1.1   # должен быть IP вашего сервера
# Linux/macOS:
curl -s https://1.1.1.1/cdn-cgi/trace | grep '^ip='          # должен быть IP вашего сервера
```
На роутере:
```sh
sh /opt/susanin/tools/xray-egress.sh status
# ожидаем: redirect: port=12345 rules=2 ; udp-relay: port=1081 rules=2
sh /opt/susanin/tools/xray-egress.sh default      # вернуть всё в DIRECT
```
Выключить боевой режим: `sh /opt/susanin/tools/xray-egress.sh disable`.

Важно: UDP проверяйте **с компьютера**, а не с роутера — трафик самого роутера
в этот механизм не попадает.

Если Xray не запущен, Susanin сам не поднимает tproxy-правила и пускает трафик
напрямую (fail-open) — в `status` это видно как `(Xray NOT LISTENING)`. Поднять
Xray: `/opt/etc/init.d/S93xray-tproxy start` или `xray-egress.sh enable`.

## Веб-панель

**Включение** — в `/opt/susanin/etc/susanin.conf`:
```
web_enable=1
web_listen=192.168.1.1     # LAN-адрес вашего роутера
web_port=8087
web_token=ПРИДУМАЙТЕ_ПАРОЛЬ
```
`web_token` — пароль, который вы придумываете сами. Если оставить пусто, вход
без пароля (доступ только из вашей сети).

Запуск:
```sh
/opt/etc/init.d/S95susanin-web start
```

**Проверка**
```sh
curl -s "http://127.0.0.1:8087/api/status?token=ПАРОЛЬ" | head -c 200; echo
netstat -lnt | grep 8087
```
В браузере: `http://192.168.1.1:8087/?token=ПАРОЛЬ` — откроется панель со
статусом, хвостом лога и кнопками Reload / Rescan / Restart / Forget, а также
правкой списков `vpn_always` / `vpn_never`.

## qWDTT_Server_Keenetic

Это совместимость, а не интеграция: клиентами qWDTT Susanin не занимается.

- серверные туннели qWDTT (`wdtt0`/`wdttraw0`) не должны попадать в
  `lan_interfaces`/`lan_subnets`/`egress_interface` — они в `discover_exclude`;
- подсеть Susanin (`egress_address`) не должна пересекаться с сетями qWDTT
  (`10.66.66.0/24`, `10.70.66.0/16`).

**Проверка**
```sh
sh /opt/susanin/tools/diagnose.sh | sed -n '/qWDTT/,/^$/p'
# ожидаем "qWDTT: обнаружен" и без предупреждений про wdtt* в egress/lan
```

## Профили маршрутизации

Профиль — это список (домены / IP / CIDR), который идёт в **свой** туннель.
Профилей до 4, включаются ключами `profile1_*` … `profile4_*`; профиль работает,
только если задан `profileN_name`. Если профилей нет — ничего не меняется.

В `/opt/susanin/etc/susanin.conf`:
```
profile1_name=cdn
profile1_egress=nwg1
profile1_list=/opt/susanin/etc/profiles/cdn.txt
profile2_name=social
profile2_egress=nwg2
profile2_list=/opt/susanin/etc/profiles/social.txt
```
Список — файл `/opt/susanin/etc/profiles/<имя>.txt`: по строке домен, IP или
CIDR, `#` — комментарий. `profileN_table` / `profileN_mark` можно не задавать.

**Проверка**
```sh
sh /opt/susanin/tools/profiles.sh up
sh /opt/susanin/tools/profiles.sh status
```
Адрес обрабатывается **первым совпавшим** профилем.

## Если что-то не так

```sh
sh /opt/susanin/tools/susanin.sh status
sh /opt/susanin/tools/diagnose.sh
sh /opt/susanin/tools/report.sh        # отчёт: /opt/susanin/var/report.txt
```
Частые случаи — в [TROUBLESHOOTING.md](TROUBLESHOOTING.md). Откат XRay:
`sh /opt/susanin/tools/xray-egress.sh disable`. Возврат прежней версии — тем же
`sh install.sh --yes` из прежнего архива.
