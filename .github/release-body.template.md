Susanin.Keenetic {{TAG}}

### Установка (первый раз)
```sh
opkg update && opkg install ca-certificates ipset iptables conntrack wget-ssl
wget -qO- https://raw.githubusercontent.com/R17a/Susanin.Keenetic/main/install.sh | sh
```
Установщик скачивает готовый архив под вашу архитектуру, определяет LAN/VPN и
(при наличии) OpenConnect, запрашивает подтверждение и запускает демон.
Существующие `susanin.conf`, `vpn_always.txt`, `vpn_never.txt` и кэш сохраняются.

### Установка пакетом Entware (`.ipk`)
Начиная с 0.4.0 есть пакет `.ipk`: ставится и обновляется штатным `opkg`, конфиг,
списки и состояние при обновлении не перезаписываются. Проще всего — дать
установщику скачать пакет под вашу архитектуру и сверить SHA256:
```sh
opkg update && opkg install ca-certificates wget-ssl
wget -qO- https://raw.githubusercontent.com/R17a/Susanin.Keenetic/main/install.sh | sh -s -- --ipk
```
Вручную: в Assets лежат пакеты `susanin-keenetic_{{VER}}_<arch>.ipk` и общий
`SHA256SUMS`. Свою архитектуру показывает `opkg print-architecture`
(например, `mipsel-3.4`). Скачать, сверить сумму и поставить:
```sh
cd /opt/tmp
wget https://github.com/R17a/Susanin.Keenetic/releases/download/{{TAG}}/susanin-keenetic_{{VER}}_mipsel-3.4.ipk
wget https://github.com/R17a/Susanin.Keenetic/releases/download/{{TAG}}/SHA256SUMS
sha256sum -c SHA256SUMS 2>/dev/null | grep mipsel-3.4   # ожидаем: ...: OK
opkg install susanin-keenetic_{{VER}}_mipsel-3.4.ipk
```

### Обновление
```sh
# если ставили пакетом:
opkg install susanin-keenetic_{{VER}}_<arch>.ipk

# если ставили архивом:
sh /opt/susanin/tools/susanin.sh update {{TAG}}
```
Если opkg считает пакет понижением версии (например, при откате на более
старую), используйте `opkg install --force-downgrade susanin-keenetic_{{VER}}_<arch>.ipk`
или обновление архивом (`susanin.sh update`).
`update` печатает `installed → target`, делает бэкап `susanin.conf` и
`susanin.state` в `/opt/susanin/var/backup/`, заменяет бинарь и скрипты,
**не трогая** `etc/` и `var/`, затем перезапускает демон.
Версию после обновления видно первой строкой в `susanin-agent status`.

### Удаление
```sh
opkg remove susanin-keenetic                        # если ставили пакетом, данные остаются
sh /opt/susanin/tools/susanin.sh uninstall
sh /opt/susanin/tools/susanin.sh uninstall --purge
```

### Что нового

<!-- CHANGELOG -->
### Диагностика

Если что-то работает не так — сначала запустите диагностику: проверит окружение,
настройки и списки, выдаст рекомендации:
```sh
sh /opt/susanin/tools/diagnose.sh
```
Для отправки полного отчёта (логи, состояние) — соберите и приложите вывод:
```sh
sh /opt/susanin/tools/report.sh
# или без установки:
wget -qO- https://raw.githubusercontent.com/R17a/Susanin.Keenetic/{{TAG}}/tools/report.sh | sh
```
Отчёт сохраняется в `/opt/susanin/var/report.txt`.

### Сборки
- архивы: `susanin-keenetic-deploy-mipsel.tar.gz`, `…-mips.tar.gz`,
  `…-aarch64.tar.gz`, `…-armv7.tar.gz`, `…-x86_64.tar.gz` и `SHA256SUMS`;
- пакеты Entware: `susanin-keenetic_{{VER}}_mipsel-3.4.ipk`, `…_mips-3.4.ipk`,
  `…_aarch64-3.10.ipk`, `…_armv7sf-k3.2.ipk`, `…_x86-64.ipk` и `SHA256SUMS`.

**Проверено**: host-сборка и автотесты; пакеты и архивы собраны для 5
архитектур. На живом железе проверьте под свою модель и прошивку — об ошибках
пишите в Issues.
