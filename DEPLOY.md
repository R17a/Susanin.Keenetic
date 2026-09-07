# Susanin.Keenetic — развёртывание на роутер

> Важно: на Keenetic с Entware всё ставится на флешку/USB, префикс `/opt`.
> Каталог `/tmp` — маленький (tmpfs), его для установки не используем.

## Что в архиве
- `susanin-agent.mipsel` — статический бинарь (ELF MIPS32) — демон.
- `datapath.sh` — управление правилами (iptables+ipset).
- `S94susanin` — init-скрипт автозапуска демона.
- `config.example.conf` — конфиг (на роутере — `/opt/susanin/etc/susanin.conf`).
- `manual.install.sh` — установщик «в один шаг» (рекомендуется).
- `DEPLOY.md` — этот файл.

## Установка в один шаг (рекомендуется)

С Windows залейте архив в `/opt` роутера (флешка), например:
```
scp susanin-keenetic-deploy-v2.tar.gz root@<роутер>:/opt/
```
На роутере:
```sh
cd /opt
rm -rf sp && mkdir sp
tar -xzf /opt/susanin-keenetic-deploy-v2.tar.gz -C /opt/sp
cd /opt/sp
sh manual.install.sh
```
Скрипт сам создаст `/opt/susanin/{bin,etc,var,tools}` и разложит файлы:
- `/opt/susanin/bin/susanin-agent`
- `/opt/susanin/tools/datapath.sh`
- `/opt/susanin/etc/susanin.conf`
- `/opt/etc/init.d/S94susanin`

После установки:
```sh
/opt/susanin/bin/susanin-agent version
sh /opt/susanin/tools/datapath.sh up
sh /opt/susanin/tools/datapath.sh status
SUSANIN_CONF=/opt/susanin/etc/susanin.conf /opt/susanin/bin/susanin-agent run
```

## Ручная раскладка (если без скрипта)
| Откуда (в архиве) | Куда на роутере |
|---|---|
| `susanin-agent.mipsel` | `/opt/susanin/bin/susanin-agent` |
| `datapath.sh` | `/opt/susanin/tools/datapath.sh` |
| `config.example.conf` | `/opt/susanin/etc/susanin.conf` |
| `S94susanin` | `/opt/etc/init.d/S94susanin` |
```sh
mkdir -p /opt/susanin/bin /opt/susanin/etc /opt/susanin/var /opt/susanin/tools
chmod +x /opt/susanin/bin/susanin-agent /opt/susanin/tools/datapath.sh /opt/etc/init.d/S94susanin
```

## Остановить / откатить
```sh
sh /opt/susanin/tools/datapath.sh down    # снять правила Susanin (как было)
```
`datapath.sh up` перед изменениями сохраняет бэкап в `/opt/susanin/var/datapath-<дата>/`.

## Автозапуск демона (после успешного теста)
```sh
/opt/etc/init.d/S94susanin start
/opt/etc/init.d/S94susanin stop
```
