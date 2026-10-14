#!/usr/bin/env python3
import hashlib, importlib.util, json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REF = ROOT / "reference" / "python" / "arkhe_p0_ref.py"
VECTORS = ROOT / "vectors" / "canonicalization-v1.1.json"
DIGEST_FILE = ROOT / "vectors" / "VECTOR_SET_DIGEST.sha256"

spec = importlib.util.spec_from_file_location("arkhe_ref", REF)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

expected = mod.build_vectors()
actual = json.loads(VECTORS.read_text(encoding="utf-8"))
if actual != expected:
    raise SystemExit("FAIL: checked-in vectors differ from independent reference output")

digest = hashlib.sha256(VECTORS.read_bytes()).hexdigest()
declared = DIGEST_FILE.read_text().split()[0]
if digest != declared:
    raise SystemExit("FAIL: VectorSetDigest mismatch")

for name, ok in actual["invariants"].items():
    if not ok:
        raise SystemExit(f"FAIL: invariant {name}")

print("PASS: independent Python vectors reproducible")
print(f"vectors={len(actual['vectors'])}")
print(f"VectorSetDigest={digest}")
