#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json
from pathlib import Path
from typing import Any

PROFILE = "arkhe.cbor.det.v1"
DOMAINS = {
    "canonicalization": b"ARKHE:canonicalization\x00",
    "artifact_envelope": b"ARKHE:artifact_envelope\x00",
    "evidence_record": b"ARKHE:evidence_record\x00",
    "mmr_leaf": b"ARKHE:mmr_leaf\x00",
    "authorization_proof": b"ARKHE:authorization_proof\x00",
}

class CanonicalError(Exception):
    pass

def _head(major: int, value: int) -> bytes:
    p = major << 5
    if value <= 23: return bytes([p | value])
    if value <= 0xff: return bytes([p | 24, value])
    if value <= 0xffff: return bytes([p | 25]) + value.to_bytes(2, "big")
    if value <= 0xffffffff: return bytes([p | 26]) + value.to_bytes(4, "big")
    if value <= 0xffffffffffffffff: return bytes([p | 27]) + value.to_bytes(8, "big")
    raise CanonicalError("integer too large")

def encode(v: Any) -> bytes:
    if v is None: return b"\xf6"
    if v is False: return b"\xf4"
    if v is True: return b"\xf5"
    if isinstance(v, int):
        return _head(0, v) if v >= 0 else _head(1, -1-v)
    if isinstance(v, bytes):
        return _head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(v, list):
        return _head(4, len(v)) + b"".join(encode(x) for x in v)
    if isinstance(v, dict):
        items = [(encode(k), encode(val)) for k,val in v.items()]
        items.sort(key=lambda kv: (len(kv[0]), kv[0]))
        for i in range(1, len(items)):
            if items[i-1][0] == items[i][0]:
                raise CanonicalError("duplicate canonical key")
        return _head(5, len(items)) + b"".join(k+val for k,val in items)
    raise CanonicalError(f"unsupported type: {type(v)!r}")

def sha256_raw(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def sha256_structured(domain: str, value: Any) -> bytes:
    p = PROFILE.encode()
    material = DOMAINS[domain] + len(p).to_bytes(2, "big") + p + encode(value)
    return hashlib.sha256(material).digest()

def json_safe(v):
    if isinstance(v, bytes): return {"$bytes": v.hex()}
    if isinstance(v, list): return [json_safe(x) for x in v]
    if isinstance(v, dict): return {"$map": [[json_safe(k), json_safe(val)] for k,val in v.items()]}
    return v

def vector(name, value):
    c = encode(value)
    return {
        "name": name,
        "semantic": json_safe(value),
        "canonical_cbor_hex": c.hex(),
        "sha256_raw_canonical_hex": sha256_raw(c).hex(),
        "sha256_structured_canonicalization_hex": sha256_structured("canonicalization", value).hex(),
        "sha256_structured_artifact_envelope_hex": sha256_structured("artifact_envelope", value).hex(),
        "sha256_structured_evidence_record_hex": sha256_structured("evidence_record", value).hex(),
    }

def build_vectors():
    values = [
        ("null", None),
        ("unsigned-23", 23),
        ("unsigned-24", 24),
        ("negative-1", -1),
        ("bytes-000102", bytes([0,1,2])),
        ("text-arkhe", "arkhe"),
        ("array-mixed", [1, "x", bytes([0xaa]), None, True]),
        ("map-order-a", {"b": 2, "a": 1}),
        ("map-order-b", {"a": 1, "b": 2}),
        ("unicode-no-normalization", "é"),
    ]
    vectors = [vector(n,v) for n,v in values]
    return {
        "profile": PROFILE,
        "domains_hex": {k:v.hex() for k,v in DOMAINS.items()},
        "algorithm": "sha256",
        "vectors": vectors,
        "invariants": {
            "map_order_equivalent": vectors[7]["canonical_cbor_hex"] == vectors[8]["canonical_cbor_hex"],
            "map_order_digest_equivalent": vectors[7]["sha256_structured_canonicalization_hex"] == vectors[8]["sha256_structured_canonicalization_hex"],
            "domain_separation_distinct": vectors[5]["sha256_structured_canonicalization_hex"] != vectors[5]["sha256_structured_artifact_envelope_hex"],
        },
    }

if __name__ == "__main__":
    root = Path(__file__).resolve().parents[2]
    out = root / "vectors" / "canonicalization-v1.1.json"
    out.write_text(json.dumps(build_vectors(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(out)
