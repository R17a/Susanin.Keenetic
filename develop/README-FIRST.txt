Susanin.Keenetic — Develop-сборка 0.4.0-dev1 (не Release)

Это тестовая сборка. В ней: XRay-egress (VLESS/REALITY), веб-панель,
профили маршрутизации, совместимость с qWDTT. Обычный режим (VPN из
«Других подключений») работает как раньше.

Документация (папка docs/):
  TESTBUILD.md       — установка и настройка новых возможностей (начните отсюда)
  DEPLOY.md          — только установка
  TROUBLESHOOTING.md — если что-то не работает
  XRAY.md            — про XRay подробно

Перед установкой на роутере нужен Entware с пакетами
ca-certificates ipset iptables conntrack:
  opkg update && opkg install ca-certificates ipset iptables conntrack

Установка:
  1) Создать папку на роутере и скачать туда архив из папки Develop:
       mkdir -p /opt/tmp/sus-dist && cd /opt/tmp/sus-dist
       wget -O susanin-dev.tar.gz \
         https://github.com/R17a/Susanin.Keenetic/raw/main/Develop/susanin-keenetic-0.4.0-dev1.tar.gz

  2) Распаковать и запустить установщик:
       tar -xzf susanin-dev.tar.gz
       cd susanin-keenetic-0.4.0-dev1
       sh install.sh --yes

     Установщик сам выберет бинарь под вашу архитектуру, найдёт LAN и VPN,
     разложит файлы в /opt/susanin и запустит демон.
     Конфиг и списки (susanin.conf, vpn_always.txt, vpn_never.txt) при
     обновлении не перезаписываются.

  3) Проверить:
       sh /opt/susanin/tools/susanin.sh status
       /opt/susanin/bin/susanin-agent version      # 0.4.0-dev1

Структура пакета:
  install.sh      установщик (запускать из корня пакета)
  bin/            susanin-agent.<arch> (mips, mipsel, aarch64, armv7, x86_64)
  tools/          скрипты (susanin.sh, datapath.sh, xray-egress.sh, ...)
  etc/            config.example.conf, xray-tproxy.json.example, vpn_always/never.txt
  init/           S93xray-tproxy, S94susanin, S95susanin-web
  www/            файлы веб-панели
  xray/           бинари Xray (xray.mipsel, xray.aarch64), LICENSE
  docs/           документация
