# Susanin.Keenetic — установка Develop-сборки

Это **Develop-сборка**: ставится из ветки `develop` — универсальным установщиком
`bootstrap.sh` (одна строка, он сам скачает архив) либо вручную из скачанного
архива. Публикация в GitHub Releases и `susanin.sh update` относятся к
Release-сборкам и для dev-сборки не используются.

Порядок настройки новых возможностей (XRay, веб-панель, профили, qWDTT) —
в [TESTBUILD.md](TESTBUILD.md).

## Что нужно
- Keenetic с Entware (`/opt` на флешке/USB).
- Пакеты Entware: `ca-certificates ipset iptables conntrack`.
  ```sh
  opkg update && opkg install ca-certificates ipset iptables conntrack
  ```

## Установка

1. **Установщик** (работает и там, где `tar` не знает `--exclude`):
   ```sh
   cd /opt/tmp
   wget -qO- https://raw.githubusercontent.com/R17a/Susanin.Keenetic/develop/bootstrap.sh | sh -s -- --yes
   ```
   Флаги: `--check` (показать arch/ядро/BusyBox), `--file`, `--channel stable`,
   `--with-xray`, `--verify`, `--tmp`. Подробности: `sh bootstrap.sh --help`.

2. **Вручную из архива**:
   ```sh
   mkdir -p /opt/tmp/sus-dist && cd /opt/tmp/sus-dist
   wget -O susanin-dev.tar.gz <ССЫЛКА_НА_АРХИВ>
   tar -xzf susanin-dev.tar.gz
   cd susanin-keenetic-0.4.0-dev
   sh install.sh --yes
   ```
   `install.sh` выберет бинарник под вашу архитектуру (или остановится с ошибкой),
   найдёт LAN/VPN и разложит файлы в `/opt/susanin`. Xray в архиве нет — только для
   `tproxy`: `sh bootstrap.sh --with-xray --yes`.

`susanin.conf`, `vpn_always.txt`, `vpn_never.txt` при обновлении **не
перезаписываются** (нужно перезаписать — `sh install.sh --force`).

## Что и куда ставится
| В архиве | На роутере |
|---|---|
| `bin/susanin-agent.<arch>` | `/opt/susanin/bin/susanin-agent` |
| `tools/*.sh` | `/opt/susanin/tools/` |
| `etc/config.example.conf` | `/opt/susanin/etc/susanin.conf` |
| `etc/xray-tproxy.json.example` | `/opt/susanin/etc/xray-tproxy.json.example` |
| `www/` | `/opt/susanin/www/` |
| `init/S93xray-tproxy`, `init/S94susanin`, `init/S95susanin-web` | `/opt/etc/init.d/` |
| `xray/README.txt`, `xray/SHA256SUMS` | (справка; сами бинарники Xray в архив не входят — их скачивает `--with-xray` и кладёт в `/opt/sbin/xray`) |
| `docs/` | (документация; на роутер не копируется) |

## Проверка после установки
```sh
sh /opt/susanin/tools/susanin.sh status
/opt/susanin/bin/susanin-agent version      # покажет точную версию сборки
```

## Настройка
Основные файлы:
- `/opt/susanin/etc/susanin.conf` — настройки демона (образец — `config.example.conf`);
- `/opt/susanin/etc/vpn_always.txt` — домены, которые всегда через VPN;
- `/opt/susanin/etc/vpn_never.txt` — домены, которые всегда напрямую.

Как включить и проверить новые возможности — в [TESTBUILD.md](TESTBUILD.md):
- XRay-egress (VLESS/REALITY) — раздел «XRay»;
- веб-панель — раздел «Веб-панель»;
- профили маршрутизации — раздел «Профили»;
- совместимость с qWDTT — раздел «qWDTT».

Обычный режим (VPN из «Других подключений», `egress_type=interface`) работает
как обычно и ничего дополнительно настраивать не нужно.

Логи: у Susanin.Keenetic — `log_level` (файл `/opt/susanin/var/susanin.log`), у Xray —
отдельный `xray_loglevel` (применяется к `xray-tproxy.json` при
`xray-egress.sh enable|run`). Подробнее — [XRAY.md](XRAY.md), раздел «Логи».

## Остановка и удаление
```sh
sh /opt/susanin/tools/susanin.sh stop          # остановить демон
sh /opt/susanin/tools/xray-egress.sh disable    # выключить XRay и вернуть DIRECT
sh /opt/susanin/tools/datapath.sh down          # снять правила Susanin.Keenetic
sh /opt/susanin/tools/uninstall.sh              # удалить (конфиг сохранить)
sh /opt/susanin/tools/uninstall.sh --purge      # удалить всё
```
Перед изменениями `datapath.sh up` сохраняет бэкап правил в
`/opt/susanin/var/datapath-<дата>/`.

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
