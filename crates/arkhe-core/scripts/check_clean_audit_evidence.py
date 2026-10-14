#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[1]
p = root / "TEST_RESULTS.txt"
text = p.read_text(encoding="utf-8", errors="replace")

for forbidden in ["Traceback (most recent call last)", "spreadsheet", "warm-up", "warmup"]:
    if forbidden.lower() in text.lower():
        raise SystemExit(f"FAIL: forbidden environmental noise in TEST_RESULTS.txt: {forbidden}")

print("PASS: audit evidence is clean")
