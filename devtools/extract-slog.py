#!/usr/bin/env python3
"""Извлечь форматы сообщений slogf() из src/*.c.

Печатает JSON-массив уникальных строк в порядке появления. Нужен, чтобы
словари переводов собирались из одного источника, а не переписывались руками.
"""
import glob
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")

# slogf(LEVEL, "строка" "продолжение", args...)
CALL = re.compile(r'slogf\(\s*SL_[A-Z]+\s*,\s*((?:"(?:[^"\\]|\\.)*"\s*)+)', re.S)
LIT = re.compile(r'"((?:[^"\\]|\\.)*)"')


def unescape(s):
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            out.append({"n": "\n", "t": "\t", '"': '"', "\\": "\\"}.get(n, n))
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def main():
    seen = []
    index = {}
    for path in sorted(glob.glob(os.path.join(SRC, "*.c"))):
        with open(path, encoding="utf-8") as f:
            text = f.read()
        for m in CALL.finditer(text):
            parts = LIT.findall(m.group(1))
            fmt = unescape("".join(parts))
            if fmt not in index:
                index[fmt] = len(seen)
                seen.append(fmt)
    json.dump(seen, sys.stdout, ensure_ascii=False, indent=1)
    sys.stdout.write("\n")
    sys.stderr.write(f"messages: {len(seen)}\n")


if __name__ == "__main__":
    main()
