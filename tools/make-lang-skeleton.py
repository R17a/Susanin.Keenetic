#!/usr/bin/env python3
"""Собрать lang/slog.json (ru + пустые en/zh) из извлечённых сообщений."""
import json
import sys

src = json.load(open(sys.argv[1], encoding="utf-8"))
out = [{"ru": s, "en": "", "zh": ""} for s in src]
json.dump(out, open(sys.argv[2], "w", encoding="utf-8"), ensure_ascii=False, indent=1)
sys.stderr.write(f"entries: {len(out)}\n")
