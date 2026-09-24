# Susanin.Keenetic — установка Develop-сборки

Это **Develop-сборка**: ставится вручную из архива. Автоматическая установка
одной строкой и `susanin.sh update` относятся к публичным Release-сборкам и
здесь не используются.

Порядок настройки новых возможностей (XRay, веб-панель, профили, qWDTT) —
в [TESTBUILD.md](TESTBUILD.md).

## Что нужно
- Keenetic с Entware (`/opt` на флешке/USB).
- Пакеты Entware: `ca-certificates ipset iptables conntrack`.
  ```sh
  opkg update && opkg install ca-certificates ipset iptables conntrack
  ```

## Установка из архива

1. Создать папку и скачать туда архив из папки **Develop** репозитория
   (ссылка — в [TESTBUILD.md](TESTBUILD.md), раздел «Установка»).
2. Распаковать и запустить установщик:
   ```sh
   mkdir -p /opt/tmp/sus-dist && cd /opt/tmp/sus-dist
   wget -O susanin-dev.tar.gz <ССЫЛКА_НА_АРХИВ>
   tar -xzf susanin-dev.tar.gz
   cd susanin-keenetic-0.4.0-dev1
   sh install.sh --yes
   ```
   Установщик сам:
   - выберет бинарь под вашу архитектуру (в папке есть `susanin-agent.mips`,
     `susanin-agent.mipsel`, `susanin-agent.aarch64`, `susanin-agent.armv7`,
     `susanin-agent.x86_64`);
   - найдёт LAN и VPN-интерфейс;
   - разложит файлы в `/opt/susanin` и запустит демон.

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
| `xray/xray.mipsel`, `xray/xray.aarch64` | (по желанию) `/opt/sbin/xray` |
| `docs/` | (документация; на роутер не копируется) |

## Проверка после установки
```sh
sh /opt/susanin/tools/susanin.sh status
/opt/susanin/bin/susanin-agent version      # 0.4.0-dev1
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

## Остановка и удаление
```sh
sh /opt/susanin/tools/susanin.sh stop          # остановить демон
sh /opt/susanin/tools/xray-egress.sh disable    # выключить XRay и вернуть DIRECT
sh /opt/susanin/tools/datapath.sh down          # снять правила Susanin
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
подключений»). Это **отдельный** механизм, он **перекрывает** Susanin: у
клиента должна быть системная политика «по умолчанию», чтобы решал Susanin.
