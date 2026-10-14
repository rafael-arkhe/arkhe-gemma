#!/usr/bin/env python3
import hashlib, os, time, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = Path(os.environ.get("ARKHE_RELEASE_OUT", ROOT.parent / f"{ROOT.name}.zip"))
SOURCE_DATE_EPOCH = int(os.environ.get("SOURCE_DATE_EPOCH", "1704067200"))
dt = time.gmtime(SOURCE_DATE_EPOCH)[:6]
if dt[0] < 1980:
    dt = (1980, 1, 1, 0, 0, 0)

def build(path: Path):
    if path.exists():
        path.unlink()
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for p in sorted(ROOT.rglob("*")):
            if not p.is_file():
                continue
            if "__pycache__" in p.parts or p.suffix == ".pyc":
                continue
            rel = f"{ROOT.name}/{p.relative_to(ROOT).as_posix()}"
            info = zipfile.ZipInfo(rel, date_time=dt)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (0o100644 & 0xFFFF) << 16
            info.flag_bits |= 0x800
            zf.writestr(info, p.read_bytes())
    return hashlib.sha256(path.read_bytes()).hexdigest()

first = OUT.with_suffix(".pass1.zip")
second = OUT.with_suffix(".pass2.zip")
h1 = build(first)
h2 = build(second)
if h1 != h2:
    raise SystemExit(f"FAIL: non-deterministic rebuild: {h1} != {h2}")

OUT.write_bytes(first.read_bytes())
first.unlink()
second.unlink()
print(f"PASS reproducible_release_digest={h1}")
print(f"SOURCE_DATE_EPOCH={SOURCE_DATE_EPOCH}")
