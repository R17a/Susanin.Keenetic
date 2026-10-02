OpenWRT-сборка Susanin.Keenetic {{TAG}}

Экспериментальная сборка для роутеров **Keenetic / Netcraze, перепрошитых на
OpenWRT**. На живом железе не тестировалась — предварительный выпуск для проверки
сообществом. Для штатного KeeneticOS/Entware используйте релиз канала `v*`.

### Установка

Онлайн (архитектура и версия определяются автоматически):
```sh
wget -qO- https://raw.githubusercontent.com/R17a/Susanin.Keenetic/{{TAG}}/install-openwrt.sh | sh -s -- --yes
```
`--deps` дополнительно поставит нужные пакеты через `opkg` (`ipset`,
`conntrack-tools`, `iptables-legacy`, `ip-full`, `ca-bundle` и kmods
`kmod-ipset kmod-ipt-conntrack kmod-ipt-connmark kmod-ipt-tcp-mss`); без него
установите их вручную.

Офлайн: возьмите архив под свою архитектуру (см. ниже), распакуйте и выполните
`sh install-openwrt.sh`.

Сервис: `/etc/init.d/susanin enable && /etc/init.d/susanin start`;
проверка: `/usr/bin/susanin-agent status`; лог: `/var/lib/susanin/susanin.log`.

### Архитектуры
| Архив | SoC | Устройства |
|---|---|---|
| `susanin-openwrt-mipsel_24kc.tar.gz` | MT7620 / MT7621 / MT7628 | большинство Keenetic/Netcraze (Start, 4G, Omni, Extra, Viva, Giga, Ultra) |
| `susanin-openwrt-aarch64_cortex-a53.tar.gz` | MT7622 / MT7981 / MT7986 | новые модели (ARM/filogic) |

### Сообщить о проблемах

Диагностика (запустите в момент проблемы, отчёт сохраняется в `/tmp/susanin-report.txt`):
```sh
wget -qO- https://raw.githubusercontent.com/R17a/Susanin.Keenetic/{{TAG}}/tools/owrt-report.sh | sh
```
Приложите вывод последней команды (`[susanin] report saved: …`) целиком.

- Issues: https://github.com/R17a/Susanin.Keenetic/issues
- Форум: https://forum.keenetic.ru/topic/30791-susaninkeenetic-%D0%B0%D0%B4%D0%B0%D0%BF%D1%82%D0%B8%D0%B2%D0%BD%D0%B0%D1%8F-vpn-%D0%BC%D0%B0%D1%80%D1%88%D1%80%D1%83%D1%82%D0%B8%D0%B7%D0%B0%D1%86%D0%B8%D1%8F/
- Telegram: https://t.me/Susanin_Keenetic

**Проверено**: только сборка (компиляция). Поведение на устройстве не проверялось.
