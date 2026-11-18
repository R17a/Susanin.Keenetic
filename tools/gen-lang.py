#!/usr/bin/env python3
"""Собрать src/lang_catalog.c из lang/slog.json.

lang/slog.json — массив объектов {"ru": "...", "en": "...", "zh": "..."}.
Ключ — русский шаблон (ровно та строка, что стоит в slogf()), поэтому вызовы
в коде менять не нужно: slogf() ищет шаблон в таблице и берёт перевод.

Проверки: у перевода должны совпадать спецификаторы формата с русским
шаблоном — иначе %s/%d разъедутся и агент напечатает мусор.
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "lang", "slog.json")
SPEC = re.compile(r"%(?:[-+ #0]*\d*(?:\.\d+)?)(?:hh|h|ll|l|z|j|t)?[diouxXeEfgGcs%]")


def specs(s):
    return sorted(m.group(0).replace("%%", "") for m in SPEC.finditer(s) if m.group(0) != "%%")


def cstr(s):
    out = []
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 32:
            out.append("\\x%02x" % ord(ch))
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def main():
    with open(SRC, encoding="utf-8") as f:
        data = json.load(f)
    errors = []
    for i, e in enumerate(data):
        ru = e.get("ru", "")
        if not ru:
            errors.append(f"#{i}: пустой ru")
            continue
        for lang in ("en", "zh"):
            tr = e.get(lang) or ""
            if tr and specs(tr) != specs(ru):
                errors.append(f"#{i} ({lang}): спецификаторы {specs(tr)} != {specs(ru)} в {ru[:60]!r}")
    if errors:
        sys.stderr.write("\n".join(errors) + "\n")
        sys.exit(1)

    w = sys.stdout.write
    w("/* Сгенерировано tools/gen-lang.py из lang/slog.json — не править руками. */\n")
    w('#include "lang.h"\n\n')
    w(f"const struct lang_msg g_lang_msgs[] = {{\n")
    for e in data:
        w("    { %s, %s, %s },\n" % (cstr(e["ru"]),
                                     cstr(e.get("en") or e["ru"]),
                                     cstr(e.get("zh") or e["ru"])))
    w("};\n")
    w(f"const int g_lang_msgs_n = {len(data)};\n")


if __name__ == "__main__":
    main()
