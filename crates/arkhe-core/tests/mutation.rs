use arkhe_p0_foundation::{
    canonical_bytes, decode_canonical, decode_canonical_with_limits, digest_canonical, AlgorithmId, CanonicalError, DecodeLimits,
    CanonicalValue, HashDomain, ARKHE_CANONICAL_PROFILE_V1,
};

#[test]
fn duplicate_key_rejected() {
    let value = CanonicalValue::Map(vec![
        (CanonicalValue::Text("a".into()), CanonicalValue::Unsigned(1)),
        (CanonicalValue::Text("a".into()), CanonicalValue::Unsigned(2)),
    ]);
    assert_eq!(canonical_bytes(&value), Err(CanonicalError::DuplicateMapKey));
}

#[test]
fn float_encoding_rejected() {
    assert_eq!(decode_canonical(&[0xf9, 0x00, 0x00]), Err(CanonicalError::FloatForbidden));
}

#[test]
fn indefinite_length_rejected() {
    assert_eq!(decode_canonical(&[0x9f, 0x01, 0xff]), Err(CanonicalError::IndefiniteLengthForbidden));
}

#[test]
fn noncanonical_map_order_rejected() {
    let raw = [0xa2, 0x61, b'b', 0x02, 0x61, b'a', 0x01];
    assert_eq!(decode_canonical(&raw), Err(CanonicalError::NonCanonicalMapOrder));
}

#[test]
fn invalid_utf8_rejected() {
    assert_eq!(decode_canonical(&[0x61, 0xff]), Err(CanonicalError::InvalidUtf8));
}

#[test]
fn non_shortest_integer_rejected() {
    assert_eq!(decode_canonical(&[0x18, 0x17]), Err(CanonicalError::NonShortestInteger));
}

#[test]
fn security_relevant_value_mutation_changes_digest() {
    let a = CanonicalValue::Array(vec![CanonicalValue::Text("tool".into()), CanonicalValue::Unsigned(1)]);
    let b = CanonicalValue::Array(vec![CanonicalValue::Text("tool".into()), CanonicalValue::Unsigned(2)]);
    let da = digest_canonical(AlgorithmId::Sha256, HashDomain::Canonicalization, ARKHE_CANONICAL_PROFILE_V1, &a).unwrap();
    let db = digest_canonical(AlgorithmId::Sha256, HashDomain::Canonicalization, ARKHE_CANONICAL_PROFILE_V1, &b).unwrap();
    assert_ne!(da, db);
}

#[test]
fn domain_mutation_changes_digest() {
    let value = CanonicalValue::Text("arkhe".into());
    let a = digest_canonical(AlgorithmId::Sha256, HashDomain::ArtifactEnvelope, ARKHE_CANONICAL_PROFILE_V1, &value).unwrap();
    let b = digest_canonical(AlgorithmId::Sha256, HashDomain::EvidenceRecord, ARKHE_CANONICAL_PROFILE_V1, &value).unwrap();
    assert_ne!(a, b);
}


#[test]
fn oversized_array_rejected_before_allocation() {
    // array(4097) encoded as 0x99 0x10 0x01
    let raw = [0x99, 0x10, 0x01];
    assert_eq!(
        decode_canonical(&raw),
        Err(CanonicalError::CollectionTooLarge { declared: 4097, max: 4096 })
    );
}

#[test]
fn oversized_bstr_rejected_before_payload_read() {
    // bstr(524289) => major 2 + 32-bit length
    let raw = [0x5a, 0x00, 0x08, 0x00, 0x01];
    assert_eq!(
        decode_canonical(&raw),
        Err(CanonicalError::ByteStringTooLarge { declared: 524289, max: 524288 })
    );
}

#[test]
fn oversized_tstr_rejected_before_payload_read() {
    let raw = [0x7a, 0x00, 0x08, 0x00, 0x01];
    assert_eq!(
        decode_canonical(&raw),
        Err(CanonicalError::TextStringTooLarge { declared: 524289, max: 524288 })
    );
}

#[test]
fn excessive_nesting_rejected() {
    let limits = DecodeLimits {
        max_input_bytes: 1024,
        max_bstr_bytes: 1024,
        max_tstr_utf8_bytes: 1024,
        max_collection_members: 32,
        max_nesting_depth: 3,
        ..Default::default()
    };
    // [[[[null]]]]
    let raw = [0x81, 0x81, 0x81, 0x81, 0xf6];
    assert!(matches!(
        decode_canonical_with_limits(&raw, limits),
        Err(CanonicalError::NestingTooDeep { .. })
    ));
}

#[test]
fn trailing_bytes_rejected() {
    assert_eq!(
        decode_canonical(&[0x01, 0x02]),
        Err(CanonicalError::TrailingBytes)
    );
}

#[test]
fn forbidden_tag_rejected() {
    // tag(0) + null
    assert_eq!(
        decode_canonical(&[0xc0, 0xf6]),
        Err(CanonicalError::TagForbidden)
    );
}

#[test]
fn reserved_additional_info_rejected() {
    assert!(matches!(
        decode_canonical(&[0x1c]),
        Err(CanonicalError::UnsupportedSimpleValue(28))
    ));
}

#[test]
fn truncated_length_rejected() {
    assert_eq!(
        decode_canonical(&[0x1a, 0x00, 0x00]),
        Err(CanonicalError::UnexpectedEof)
    );
}

#[test]
fn truncated_payload_rejected() {
    assert_eq!(
        decode_canonical(&[0x43, 0x01]),
        Err(CanonicalError::UnexpectedEof)
    );
}


#[test]
fn cumulative_item_budget_rejects_nested_small_collections() {
    let limits = DecodeLimits {
        max_input_bytes: 1024,
        max_bstr_bytes: 1024,
        max_tstr_utf8_bytes: 1024,
        max_collection_members: 16,
        max_nesting_depth: 16,
        max_item_cost: 4,
        max_allocation_cost_bytes: 4096,
        max_prealloc_members: 16,
    };
    // [ [null], [null] ] is locally small but exceeds global item budget.
    let raw = [0x82, 0x81, 0xf6, 0x81, 0xf6];
    assert!(matches!(
        decode_canonical_with_limits(&raw, limits),
        Err(CanonicalError::ItemBudgetExceeded { .. })
    ));
}

#[test]
fn cumulative_allocation_budget_rejects_before_allocation() {
    let limits = DecodeLimits {
        max_input_bytes: 1024,
        max_bstr_bytes: 1024,
        max_tstr_utf8_bytes: 1024,
        max_collection_members: 16,
        max_nesting_depth: 16,
        max_item_cost: 128,
        max_allocation_cost_bytes: 8,
        max_prealloc_members: 16,
    };
    // bstr(9)
    let raw = [0x49, 0,0,0,0,0,0,0,0,0];
    assert!(matches!(
        decode_canonical_with_limits(&raw, limits),
        Err(CanonicalError::AllocationBudgetExceeded { .. })
    ));
}
