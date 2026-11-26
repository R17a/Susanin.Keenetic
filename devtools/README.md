# devtools — инструменты разработки и упаковки

Здесь лежит всё, что **не ставится на устройство**. В `tools/` — только
скрипты, которые входят в `.ipk` и в tar-архив релиза (см.
`packaging/manifest.txt`).

## Сборка и упаковка

- `wsl-build.sh` — кросс-сборка агента в WSL, раскладывает бинарники в `build/`.
- `build-mips.sh` — сборка под MIPS в текущем каталоге (запускать из корня).
- `make-ipk.sh` — сборка `.ipk` для Entware по `packaging/manifest.txt`.
- `stage-release.sh` — раскладка tar-архива релиза по манифесту (CI).
- `check-shipping.sh` — сверка манифеста, `tools/`, `init/entware/` и `.ipk`.
- `../packaging/Dockerfile.cross` — образ для кросс-сборки (GHCR).

## Языковые словари

- `gen-lang.py` — собирает `src/lang_catalog.c` из `lang/slog.json` (шаг сборки).
- `split-lang.py` — раскладывает `lang/slog.json` на `lang/RU|EN|ZH.json`.
- `extract-slog.py` — извлекает шаблоны `slogf()` из `src/*.c`.
- `make-lang-skeleton.py` — каркас словаря из извлечённых строк.
- `check-lang.sh` — сверка словарей веб-панели `www/lang/*.JSON`.

## Веб-панель

- `dev-web.py` — локальный сервер `www/` с мок-API (без роутера).

## Отладка и эксперименты

- `egress-failover.sh` — внешний наблюдатель «интерфейс → Xray» (в поставку не
  входит: в движке есть кандидат tproxy).
- `failover.conf.example` — пример конфига для него.
- `diag-watch.sh` — сбор телеметрии для разбора OOM/переподключений.
- `xray-socks.sh` — ручная врезка SOCKS-инбаунда Xray.

## init-скрипты вне поставки

`init/` — скрипты, которые не ставятся из пакета: TUN-режим (`S93xray-tun`),
сторож Xray (`S95xray-guard`), init для наблюдателя (`S96susanin-failover`).
Штатные init-скрипты — в `../init/entware/`.

## Тесты

`../tests/` и `../testdata/` — host-тесты и сэмплы. Они **не публикуются**:
каталоги в `.gitignore`, `make test` работает в локальном дереве и сообщает об
отсутствии, если их нет.
