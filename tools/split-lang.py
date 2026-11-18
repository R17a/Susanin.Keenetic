#!/usr/bin/env python3
"""Разложить lang/slog.json на три словаря RU/EN/ZH (ключ — русский шаблон).

Файлы нужны как человекочитаемые словари: править переводы удобно в них или в
slog.json, а собирает их в агент tools/gen-lang.py.
"""
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
data = json.load(open(os.path.join(ROOT, "lang", "slog.json"), encoding="utf-8"))

for code, field in (("RU", "ru"), ("EN", "en"), ("ZH", "zh")):
    out = {e["ru"]: e.get(field) or e["ru"] for e in data}
    path = os.path.join(ROOT, "lang", code + ".json")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, ensure_ascii=False, indent=1, sort_keys=True)
        f.write("\n")
    print(f"{code}.json: {len(out)}")
