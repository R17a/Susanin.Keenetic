# Susanin.Keenetic — установка, обновление и удаление (0.4.6)

Установка на Keenetic с Entware: пакетом `.ipk` (рекомендуется), установщиком
одной строкой (`bootstrap.sh`) или вручную из архива. Обновление — `opkg` или
`susanin.sh update`; конфиг, списки и состояние при обновлении сохраняются.

Обзор проекта, все способы установки и таблица файлов — в [README.md](README.md).
Быстрый старт и настройки — в [USER_GUIDE.md](USER_GUIDE.md).
Если что-то не работает — [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
Xray/VLESS+REALITY — [XRAY.md](XRAY.md).

## Что нужно

- Keenetic с Entware (`/opt` на флешке/USB или внутренняя память);
- пакеты Entware: `ca-certificates ipset iptables conntrack wget-ssl`
  (`wget-ssl` — чтобы работал HTTPS; у BusyBox-wget его нет):
  ```sh
  opkg update && opkg install ca-certificates ipset iptables conntrack wget-ssl
  ```
- работающий туннель WireGuard/AmneziaWG (для `egress_type=interface`) либо Xray
  (для `egress_type=tproxy`, Xray ставится отдельно).

## Установка

### 1. Пакетом Entware `.ipk` (рекомендуется)

Архитектура определяется автоматически, файл берётся из последнего релиза
(`v0.4.6`), SHA256 сверяется по `SHA256SUMS`, установка — штатным `opkg`
(учёт пакета, `opkg remove`, конфиг и списки не перезаписываются):

```sh
opkg update && opkg install ca-certificates wget-ssl
wget -qO- https://raw.githubusercontent.com/R17a/Susanin.Keenetic/main/install.sh | sh -s -- --ipk
```

Режим VLESS/REALITY — добавьте `--with-xray-tproxy` (Xray скачается в
`/opt/sbin/xray` и будет проверен по SHA256).
Ответ `ERROR: unknown arg: --ipk` означает, что взят старый скрипт (кэш или ветка
до 0.4.0).

Вручную (если нужен контроль над файлом) — скачать, **сверить SHA256**, потом
ставить. Имя файла под свою архитектуру (`opkg print-architecture`) — таблица в
[README.md](README.md) → «Пакетом Entware `.ipk`»:

```sh
mkdir -p /opt/tmp && cd /opt/tmp
wget -O susanin-keenetic_0.4.6_mipsel-3.4.ipk \
  https://github.com/R17a/Susanin.Keenetic/releases/download/v0.4.6/susanin-keenetic_0.4.6_mipsel-3.4.ipk
wget -O SHA256SUMS \
  https://github.com/R17a/Susanin.Keenetic/releases/download/v0.4.6/SHA256SUMS
sha256sum -c SHA256SUMS 2>/dev/null | grep mipsel-3.4     # ожидаем: ...: OK
opkg install susanin-keenetic_0.4.6_mipsel-3.4.ipk
```

### 2. Установщик одной строкой

Работает и там, где `tar` не знает `--exclude`; сам определит arch/ядро,
скачает архив из релиза и распакует нужное:

```sh
cd /opt/tmp
wget -qO- https://raw.githubusercontent.com/R17a/Susanin.Keenetic/main/bootstrap.sh | sh -s -- --yes
```

Флаги: `--check` (показать arch/ядро/BusyBox), `--file`, `--channel stable`,
`--ipk` (ставить пакетом), `--with-xray` (Xray + tproxy-режим), `--verify`,
`--tmp`. Подробности: `sh bootstrap.sh --help`.

### 3. Вручную из архива

```sh
mkdir -p /opt/tmp/sus-dist && cd /opt/tmp/sus-dist
wget -O susanin.tar.gz \
  https://github.com/R17a/Susanin.Keenetic/releases/download/v0.4.6/susanin-keenetic-deploy-mipsel.tar.gz
tar -xzf susanin.tar.gz
sh install.sh --yes
```

`install.sh` выберет бинарник под вашу архитектуру (или остановится с ошибкой),
найдёт LAN/VPN и разложит файлы в `/opt/susanin`. Xray в архиве нет — для
`tproxy`: `sh bootstrap.sh --with-xray --yes`.

`susanin.conf`, `vpn_always.txt`, `vpn_never.txt` при обновлении **не
перезаписываются** (нужно перезаписать — `sh install.sh --force`); новые ключи и
строки списков **дописываются**. Чтобы списки не дописывались вообще —
`--keep-lists` (см. ниже).

## Обновление

```sh
# .ipk:
opkg install /opt/tmp/susanin-keenetic_0.4.6_mipsel-3.4.ipk

# tar-архив:
sh /opt/susanin/tools/susanin.sh update 0.4.6     # или latest

# без автодополнения списков (vpn_always.txt / vpn_never.txt не трогаются):
sh /opt/susanin/tools/susanin.sh update 0.4.6 --keep-lists
```

`susanin.sh update` определяет установленную версию и архитектуру, скачивает
deploy-архив из Releases, сохраняет конфиг/списки/состояние, дописывает новые
ключи и перезапускает службу. Перед обновлением полезно сохранить копию:
`cp -a /opt/susanin/etc /opt/susanin/etc.bak-$(date +%F-%H%M)`.

`--keep-lists` (синоним `--no-lists`) выключает только merge списков: оба файла
остаются байт в байт, всё остальное (бинарь, `tools/`, `www/`, новые ключи
конфига) обновляется как обычно. Обратный флаг — `--lists`.

## Что и куда ставится

| В пакете/архиве | На роутере |
|---|---|
| `bin/susanin-agent.<arch>` (в `.ipk` — `bin/susanin-agent`) | `/opt/susanin/bin/susanin-agent` |
| `tools/*.sh` | `/opt/susanin/tools/` |
| `etc/config.example.conf` | `/opt/susanin/etc/susanin.conf` (если файла нет) |
| `etc/xray-tproxy.json.example`, `etc/cdn_ranges.txt`, списки | `/opt/susanin/etc/` |
| `www/` | `/opt/susanin/www/` |
| `init/S93xray-tproxy`, `init/S94susanin`, `init/S95susanin-web` | `/opt/etc/init.d/` |
| `docs/` | `/opt/susanin/docs/` |
| `xray/README.txt`, `xray/SHA256SUMS` | справка; бинарники Xray скачивает `--with-xray` в `/opt/sbin/xray` |

## Проверка после установки

```sh
susanin status        # служба, цепочка, ip rule, таблица (короткий вызов)
susanin version       # точная версия сборки — то же, что susanin-agent version
susanin diagnose      # окружение, правила, списки, рекомендации
```

Если симлинка `susanin` нет (его ставит установщик в `/opt/bin`):

```sh
sh /opt/susanin/tools/susanin.sh status
/opt/susanin/bin/susanin-agent version
```

## Настройка

- `/opt/susanin/etc/susanin.conf` — настройки демона (образец — `config.example.conf`);
- `/opt/susanin/etc/vpn_always.txt` — домены/IP/CIDR, которые всегда через VPN;
- `/opt/susanin/etc/vpn_never.txt` — которые всегда напрямую;
- веб-панель — `web_enable=1`, `web_listen`, `web_port`, `web_token`
  (см. README, «Веб-панель»);
- профили — `profileN_*` или `profiles.d/<name>.conf` (см. README, «Профили»).

Логи: у Susanin.Keenetic — `log_level` (файл `/opt/susanin/var/susanin.log`), у
Xray — `xray_loglevel` (применяется при `xray-egress.sh enable|run`).

## Остановка и удаление

```sh
sh /opt/susanin/tools/susanin.sh stop           # остановить демон
sh /opt/susanin/tools/xray-egress.sh disable    # выключить XRay и вернуть DIRECT
sh /opt/susanin/tools/datapath.sh down          # снять правила
opkg remove susanin-keenetic                    # если ставили .ipk (данные остаются)
rm -rf /opt/susanin                             # удалить конфиг/списки/состояние
# либо: sh /opt/susanin/tools/uninstall.sh [--purge]
```

Перед `datapath.sh up` сохраняется снимок правил в `/opt/susanin/var/datapath.bak/` —
**один** каталог, файлы перезаписываются (история не накапливается; при
`disk_mode=soft` бэкап не делается).

## Автозапуск

```sh
/opt/etc/init.d/S94susanin start        # демон
/opt/etc/init.d/S93xray-tproxy start    # Xray (нужен только для режима tproxy)
/opt/etc/init.d/S95susanin-web start    # веб-панель (если включена)
```

Скрипты `S93`/`S94`/`S95` запускаются автоматически при загрузке, если они
исполняемые (`chmod +x`).

## Приоритеты подключений Keenetic

Keenetic умеет сам заворачивать устройства в VPN (Web → «Приоритеты
подключений»). Это **отдельный** механизм, он **перекрывает** Susanin.Keenetic: у
клиента должна быть системная политика «по умолчанию», чтобы решал Susanin.Keenetic.
