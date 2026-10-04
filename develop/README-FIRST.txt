Susanin.Keenetic — Develop-сборка 0.4.0-dev (не Release)

Точную версию/сборку смотрите в выводе `susanin-agent version` и в report.txt.

Это тестовая сборка. В ней: XRay-egress (VLESS/REALITY), веб-панель,
профили маршрутизации, совместимость с qWDTT, возврат на основной VPN
(failback), watchdog Xray и лимит памяти, DNS-снифинг. Обычный режим
(VPN из «Других подключений») работает как раньше.

Документация (папка docs/):
  TESTBUILD.md       — установка и настройка новых возможностей (начните отсюда)
  DEPLOY.md          — только установка
  TROUBLESHOOTING.md — если что-то не работает
  XRAY.md            — про XRay подробно

Перед установкой на роутере нужен Entware с пакетами
ca-certificates ipset iptables conntrack wget-ssl:
  opkg update && opkg install ca-certificates ipset iptables conntrack wget-ssl

Установка — установщик (работает и на старых BusyBox, где tar не знает --exclude):
  cd /opt/tmp
  wget -qO- https://raw.githubusercontent.com/R17a/Susanin.Keenetic/develop/bootstrap.sh | sh -s -- --yes

  Варианты (если сохранить файл susanin-install.sh рядом):
    sh susanin-install.sh --check                 # arch/ядро/BusyBox, без установки
    sh susanin-install.sh --file <архив> --yes    # из скачанного архива
    sh susanin-install.sh --channel stable --yes  # последний релиз
    sh susanin-install.sh --with-xray --yes       # + Xray для tproxy

Установка вручную (без интернета):
  1) mkdir -p /opt/tmp/sus-dist && cd /opt/tmp/sus-dist
     wget -O susanin-dev.tar.gz \
       https://github.com/R17a/Susanin.Keenetic/raw/develop/develop/susanin-keenetic-0.4.0-dev.tar.gz
  2) tar -xzf susanin-dev.tar.gz && cd susanin-keenetic-0.4.0-dev && sh install.sh --yes
     (бинарник под вашу архитектуру install.sh выберет сам; конфиг и списки
      susanin.conf / vpn_always.txt / vpn_never.txt при обновлении не перезаписываются)
  3) Проверить: sh /opt/susanin/tools/susanin.sh status
               /opt/susanin/bin/susanin-agent version

Структура пакета:
  install.sh      установщик (запускать из корня пакета)
  bin/            susanin-agent.<arch> (mips, mipsel, aarch64, armv7, x86_64)
  tools/          скрипты (susanin.sh, datapath.sh, xray-egress.sh, ...)
  etc/            config.example.conf, cdn_ranges.txt, xray-tproxy.json.example, vpn_always/never.txt
  init/           S93xray-tproxy, S94susanin, S95susanin-web
  www/            файлы веб-панели
  xray/           README.txt, SHA256SUMS, LICENSE (бинарников Xray в архиве нет —
                  они лежат в репозитории, develop/xray/; ставит их --with-xray)
  docs/           документация
