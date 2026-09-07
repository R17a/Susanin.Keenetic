# Susanin.Keenetic

Адаптивная маршрутизация «как в Susanin (MikroTik)» для роутеров **Keenetic**
с **Entware**. Автоматически обнаруживает заблокированные направления,
пробует их через VPN-туннель, запоминает рабочие пути и возвращается в
прямой доступ (fail-open), если туннель недоступен. Без ручных списков
доменов/IP.

> **Статус: активная разработка / полевое тестирование.**
> Проверено на Keenetic Viva (MT7621, MIPS), KeeneticOS 5.1.4, Entware,
> WireGuard/AmneziaWG-туннель `nwg0`. Основная среда — legacy iptables + ipset
> (nftables на этом ядре нет).

## Что делает

- наблюдает за поведением соединений (conntrack), а не за содержимым;
- по «тихим» признакам блокировок (TCP SYN без ответа, QUIC/UDP без reply,
  TCP-stall, late-stall) отправляет IP на проверку через VPN;
- подтверждает рабочие направления (кэш `ok`) и запоминает их **постоянно**
  (`ok_ttl=0`, переживает перезагрузки; снимает сам, если маршрут через VPN
  перестал отвечать);
- TCP и UDP/QUIC учит раздельно;
- fail-open: при недоступности туннеля — прямой доступ (DIRECT);
- автоматически чинит правила, если их снёс NDM (Web-UI change) — reconcile;
- работает как демон под Entware (`/opt`), управление — только CLI/SSH.

Не является VPN-клиентом: туннель (WireGuard/AmneziaWG «Дополнительное
подключение») должен уже работать. IPv6 в v1 не поддерживается.

## Как это устроено (кратко)

- **Сенсор**: чтение `/proc/net/nf_conntrack` — поля, аналогичные
  `/ip firewall connection` RouterOS (tcp-state, orig/reply packets/bytes, mark).
- **Дата-плейн**: собственная цепочка `SUSANIN` в конце mangle PREROUTING
  (после правил NDM), mark через `CONNMARK`/`MARK`, отдельная routing table
  (например `100`, малый номер — busybox `ip` не принимает большие),
  ipset-наборы `susanin_{test,ok}_{tcp,udp}`.
- **Логика**: демон с таймерами FAST 1с / SOFT 2с / JUDGE 1с / HEALTH 3с;
  удаляет «зависшие» соединения из conntrack, чтобы повтор клиента ушёл через
  VPN. Пороги наследованы из проекта Susanin.MikroTik.

## Требования

- KeeneticOS с установленным **Entware**;
- пакеты Entware: `ipset`, `conntrack`, busybox, `iptables` (legacy);
- работающий VPN/туннель (WireGuard/AmneziaWG) — интерфейс egress;
- LAN-интерфейсы (обычно `br0`, `br1`);
- root-доступ по SSH.

## Дистрибутив (для тестеров)

Готовые сборки — в разделе **Releases**:
- `susanin-agent.mipsel` — статический бинарь (архитектура **mipsel**, проверено
  на Keenetic Viva / KeeneticOS 5.1.4 / Entware);
- `susanin-keenetic-deploy.tar.gz` — комплект для установки
  (`susanin-agent.mipsel`, `datapath.sh`, `susanin.sh`, конфиг, `manual.install.sh`).

Для других архитектур (armv7/aarch64) — собирайте из исходников (см. «Сборка»).

## Быстрый старт

1. Соберите бинарь (см. «Сборка») или возьмите готовый из GitHub Releases.
2. Залейте на роутер и установите:

```sh
cd /opt
tar -xzf susanin-keenetic-deploy.tar.gz -C /opt/sp && cd /opt/sp
sh manual.install.sh
```

3. Настройте один раз:

```sh
sh /opt/susanin/tools/susanin.sh install
# при необходимости укажите вручную:
#   /opt/susanin/bin/susanin-agent setup --egress nwg0 --lan br0,br1 --table 100
```

4. Управление демоном:

| Действие | Команда |
|---|---|
| Запуск | `sh /opt/susanin/tools/susanin.sh start` |
| Остановка | `sh /opt/susanin/tools/susanin.sh stop` |
| Перезапуск | `sh /opt/susanin/tools/susanin.sh restart` |
| Состояние | `sh /opt/susanin/tools/susanin.sh status` |
| Лог | `sh /opt/susanin/tools/susanin.sh log` |
| Снять правила | `sh /opt/susanin/tools/susanin.sh down` |
| IP вручную в VPN | `sh /opt/susanin/tools/susanin.sh add <ip> tcp test` |

## CLI

```
susanin-agent version
susanin-agent discover
susanin-agent setup [--egress <if>] [--lan <if,...>] [--table <n>]
susanin-agent status
susanin-agent apply [--dry-run]
susanin-agent ct-scan
susanin-agent datapath {up|down|status|flush|add|del}
susanin-agent run
susanin-agent install | uninstall
```

## Сборка

Кросс-компиляция в MIPS (mipsel, static) — через WSL или Docker:

```sh
# WSL (Debian/Ubuntu):
sudo apt-get install -y gcc-mipsel-linux-gnu make file
sh tools/wsl-build.sh            # -> build/susanin-agent.mipsel

# Docker:
docker build -f Dockerfile.cross -t susanin-build .
```

## Конфиг (важные поля)

`/opt/susanin/etc/susanin.conf`:

| Поле | Назначение | По умолчанию |
|---|---|---|
| `egress_interface` | VPN-интерфейс | `nwg0` |
| `lan_interfaces` / `lan_subnets` | LAN для анализа | `br0,br1` |
| `routing_table` | номер таблицы (малый!) | `100` |
| `ok_ttl` | TTL подтверждённых IP; `0` = бесконечно | `0` |
| `fast_syn_min_op` | сколько SYN без ответа до детекта | `2` (`1` = быстрее) |
| `health_probe` | цели проверки туннеля | `1.1.1.1,8.8.8.8` |

## Известные ограничения v1

- только IPv4;
- первое открытие «нового» IP чуть медленнее (реактивное обучение);
- busybox-`ip`: номер таблицы должен быть малым; `ip rule` через `lookup`;
- при пересборке netfilter NDM (любое изменение в Web) демон чинит правила
  сам в течение ~15 секунд.

## Документы

- [DEPLOY.md](DEPLOY.md) и [manual.install.sh](manual.install.sh) — установка на
  роутер.
- `tools/susanin.sh`, `tools/datapath.sh` — управление демоном и дата-плейном.

## Дисклеймер

Проект не связан и не аффилирован с Keenetic, Amnezia, WireGuard, MikroTik или
авторами упомянутых сторонних проектов. Используйте на свой страх и риск —
сделайте резервную копию конфигурации роутера.

## Лицензия

MIT — см. [LICENSE](LICENSE).
