use arkhe_p0_foundation::{
    canonical_bytes, digest_canonical, digest_raw, AlgorithmId, CanonicalValue, HashDomain,
    ARKHE_CANONICAL_PROFILE_V1,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct FileVectors { vectors: Vec<Vector>, invariants: Invariants }

#[derive(Debug, Deserialize)]
struct Invariants {
    map_order_equivalent: bool,
    map_order_digest_equivalent: bool,
    domain_separation_distinct: bool,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    semantic: serde_json::Value,
    canonical_cbor_hex: String,
    sha256_raw_canonical_hex: String,
    sha256_structured_canonicalization_hex: String,
    sha256_structured_artifact_envelope_hex: String,
    sha256_structured_evidence_record_hex: String,
}

#[test]
fn python_vectors_match_rust() {
    let parsed: FileVectors =
        serde_json::from_str(include_str!("../vectors/canonicalization-v1.1.json")).unwrap();

    assert!(parsed.invariants.map_order_equivalent);
    assert!(parsed.invariants.map_order_digest_equivalent);
    assert!(parsed.invariants.domain_separation_distinct);

    for v in parsed.vectors {
        let value = from_json_fixture(&v.semantic);
        let canonical = canonical_bytes(&value).unwrap();
        assert_eq!(to_hex(&canonical), v.canonical_cbor_hex, "canonical bytes: {}", v.name);

        let raw = digest_raw(AlgorithmId::Sha256, &canonical);
        assert_eq!(to_hex(raw.bytes()), v.sha256_raw_canonical_hex, "raw digest: {}", v.name);

        for (domain, expected) in [
            (HashDomain::Canonicalization, v.sha256_structured_canonicalization_hex.as_str()),
            (HashDomain::ArtifactEnvelope, v.sha256_structured_artifact_envelope_hex.as_str()),
            (HashDomain::EvidenceRecord, v.sha256_structured_evidence_record_hex.as_str()),
        ] {
            let d = digest_canonical(
                AlgorithmId::Sha256, domain, ARKHE_CANONICAL_PROFILE_V1, &value
            ).unwrap();
            assert_eq!(to_hex(d.bytes()), expected, "domain digest: {}", v.name);
        }
    }
}

fn from_json_fixture(v: &serde_json::Value) -> CanonicalValue {
    match v {
        serde_json::Value::Null => CanonicalValue::Null,
        serde_json::Value::Bool(b) => CanonicalValue::Bool(*b),
        serde_json::Value::Number(n) if n.as_u64().is_some() => CanonicalValue::Unsigned(n.as_u64().unwrap()),
        serde_json::Value::Number(n) => CanonicalValue::Negative(n.as_i64().unwrap()),
        serde_json::Value::String(s) => CanonicalValue::Text(s.clone()),
        serde_json::Value::Array(items) => CanonicalValue::Array(items.iter().map(from_json_fixture).collect()),
        serde_json::Value::Object(obj) if obj.contains_key("$bytes") =>
            CanonicalValue::Bytes(from_hex(obj["$bytes"].as_str().unwrap())),
        serde_json::Value::Object(obj) if obj.contains_key("$map") => {
            let entries = obj["$map"].as_array().unwrap();
            CanonicalValue::Map(entries.iter().map(|pair| {
                let p = pair.as_array().unwrap();
                (from_json_fixture(&p[0]), from_json_fixture(&p[1]))
            }).collect())
        }
        other => panic!("unsupported fixture form: {other:?}"),
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap())
        .collect()
}
