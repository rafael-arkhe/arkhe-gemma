use arkhe_p0_foundation::{
    digest_raw, AlgorithmId, ArtifactEnvelope, ArtifactId, CausalParent, CausalProvenance,
    EvidenceRecord, ProvenanceError, RecordId, RelationType, TimeEvidence,
};

#[test]
fn artifact_envelope_digest_is_deterministic_under_parent_order() {
    let p1 = CausalParent {
        relation: RelationType::DerivedFrom,
        digest: digest_raw(AlgorithmId::Sha256, b"parent-1"),
    };
    let p2 = CausalParent {
        relation: RelationType::Used,
        digest: digest_raw(AlgorithmId::Sha256, b"parent-2"),
    };
    let policy = digest_raw(AlgorithmId::Sha256, b"policy");
    let artifact = digest_raw(AlgorithmId::Sha256, b"asset");

    let a = ArtifactEnvelope {
        artifact_id: ArtifactId::try_from("asset-1").unwrap(),
        digest: artifact.clone(),
        provenance: CausalProvenance::new(vec![p1.clone(), p2.clone()]).unwrap(),
        authentication: None,
        anchor: None,
        policy_ref: policy.clone(),
    };
    let b = ArtifactEnvelope {
        provenance: CausalProvenance::new(vec![p2, p1]).unwrap(),
        ..a.clone()
    };

    assert_eq!(
        a.digest(AlgorithmId::Sha256).unwrap(),
        b.digest(AlgorithmId::Sha256).unwrap()
    );
}

#[test]
fn evidence_record_digest_binds_time_and_witness() {
    let envelope_digest = digest_raw(AlgorithmId::Sha256, b"envelope");
    let witness = digest_raw(AlgorithmId::Sha256, b"witness");

    let a = EvidenceRecord {
        record_id: RecordId::try_from("record-1").unwrap(),
        envelope_digest: envelope_digest.clone(),
        timestamp: TimeEvidence::None,
        witness: None,
    };

    let b = EvidenceRecord {
        timestamp: TimeEvidence::LocalClock { unix_millis: 1 },
        witness: Some(witness),
        ..a.clone()
    };

    assert_ne!(
        a.digest(AlgorithmId::Sha256).unwrap(),
        b.digest(AlgorithmId::Sha256).unwrap()
    );
}

#[test]
fn duplicate_causal_parents_are_semantically_idempotent() {
    let p = CausalParent {
        relation: RelationType::DerivedFrom,
        digest: digest_raw(AlgorithmId::Sha256, b"same-parent"),
    };
    let once = CausalProvenance::new(vec![p.clone()]).unwrap();
    let twice = CausalProvenance::new(vec![p.clone(), p]).unwrap();
    assert_eq!(once, twice);
}

#[test]
fn artifact_id_is_semantically_bounded() {
    assert!(ArtifactId::try_from(vec![b'a'; ArtifactId::MAX_LENGTH]).is_ok());
    assert!(ArtifactId::try_from(vec![b'a'; ArtifactId::MAX_LENGTH + 1]).is_err());
}

#[test]
fn causal_parent_count_is_semantically_bounded() {
    let parents: Vec<CausalParent> = (0..=CausalProvenance::MAX_PARENTS)
        .map(|i| CausalParent {
            relation: RelationType::DerivedFrom,
            digest: digest_raw(AlgorithmId::Sha256, format!("p-{i}").as_bytes()),
        })
        .collect();

    assert!(matches!(
        CausalProvenance::new(parents),
        Err(ProvenanceError::TooManyParents { .. })
    ));
}


#[test]
fn record_id_is_semantically_bounded() {
    assert!(RecordId::try_from(vec![b'r'; RecordId::MAX_LENGTH]).is_ok());
    assert!(RecordId::try_from(vec![b'r'; RecordId::MAX_LENGTH + 1]).is_err());
    assert!(RecordId::try_from(Vec::<u8>::new()).is_err());
}
