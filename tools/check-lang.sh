#!/bin/sh
# check-lang.sh — сверка языковых словарей веб-панели (dev-инструмент).
#
# Проверяет:
#   1) www/lang/RU.JSON, EN.JSON, ZH.JSON — валидный JSON и один и тот же
#      набор ключей (RU — эталон);
#   2) подстановки {name} в переводе совпадают с RU (иначе на экране будет
#      «{value}» вместо значения);
#   3) каждый ключ, который код берёт через T('...') или через data-i18n* в
#      index.html, есть в RU.JSON (ловит забытые строки при добавлении полей);
#   4) нет пустых значений.
#
# Usage:  sh tools/check-lang.sh
# Требует python3 (на роутере не нужен — инструмент разработчика).
set -u

SRC=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WWW="$SRC/www"

if ! command -v python3 >/dev/null 2>&1; then
    echo "check-lang: нужен python3" >&2
    exit 2
fi

exec python3 - "$WWW" <<'PY'
import json
import os
import re
import sys

www = sys.argv[1]
lang_dir = os.path.join(www, 'lang')
files = {'ru': 'RU.JSON', 'en': 'EN.JSON', 'zh': 'ZH.JSON'}

dicts = {}
bad = 0

for code, name in files.items():
    path = os.path.join(lang_dir, name)
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
    except FileNotFoundError:
        print('FAIL: нет файла %s' % path)
        bad = 1
        continue
    except Exception as exc:
        print('FAIL: %s не парсится как JSON: %s' % (name, exc))
        bad = 1
        continue
    dicts[code] = data
    print('%-8s ключей: %d' % (code, len(data)))

if 'ru' not in dicts:
    print('FAIL: без RU.JSON сверять нечего')
    sys.exit(1)

ru = dicts['ru']
ru_keys = set(ru)

for code, data in dicts.items():
    if code == 'ru':
        continue
    missing = sorted(ru_keys - set(data))
    extra = sorted(set(data) - ru_keys)
    if missing:
        bad = 1
        print('FAIL: %s — нет %d ключей: %s' % (code, len(missing), ', '.join(missing[:15])))
    if extra:
        bad = 1
        print('FAIL: %s — лишние %d ключей: %s' % (code, len(extra), ', '.join(extra[:15])))

# пустые значения
for code, data in dicts.items():
    empty = [k for k, v in data.items() if isinstance(v, str) and not v.strip()]
    if empty:
        bad = 1
        print('FAIL: %s — пустые значения: %s' % (code, ', '.join(empty[:10])))

# подстановки
ph = re.compile(r'\{(\w+)\}')
for code, data in dicts.items():
    if code == 'ru':
        continue
    for key, val in data.items():
        if key not in ru or not isinstance(val, str):
            continue
        a = set(ph.findall(ru[key])) if isinstance(ru[key], str) else set()
        b = set(ph.findall(val))
        if a != b:
            bad = 1
            print('FAIL: %s/%s — подстановки %s != RU %s'
                  % (code, key, sorted(b) or '-', sorted(a) or '-'))

# ключи, которые использует код
used = set()
key_re = re.compile(r"\bT\(\s*'([^']+)'")
for fname in ('app.js', 'config.js', 'i18n.js'):
    path = os.path.join(www, fname)
    if not os.path.exists(path):
        continue
    with open(path, 'r', encoding='utf-8') as fh:
        used.update(key_re.findall(fh.read()))

path = os.path.join(www, 'index.html')
if os.path.exists(path):
    with open(path, 'r', encoding='utf-8') as fh:
        used.update(re.findall(r'data-i18n(?:-html|-title|-ph)?="([^"]+)"', fh.read()))

# динамические префиксы (grp.<tab>.<n>, tab.<id>.label) в коде собираются
# конкатенацией — их проверяет только полнота словаря, не этот список.
used = {k for k in used if k and not k.endswith('.')}
missing_used = sorted(k for k in used if k not in ru_keys)
if missing_used:
    bad = 1
    print('FAIL: код использует ключи, которых нет в RU.JSON: %s' % ', '.join(missing_used))

if bad:
    print('\ncheck-lang: ЕСТЬ ПРОБЛЕМЫ')
    sys.exit(1)
print('\ncheck-lang: словари согласованы (%d ключей)' % len(ru_keys))
PY
