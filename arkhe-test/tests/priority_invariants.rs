//! Integration tests for the 10 Priority Invariants (I-01 through I-10).
//!
//! Principle:
//! "Nenhuma funcionalidade entra em produção sem um teste que possa reprová-la."

use arkhe_test::{
    hash_sha256, AfirReceipt, AfirValidator, AppendOnlyMmr, Chunk, DeviceCheckpoint, EngineError,
    GovernanceProposal, ManifestChunkEntry, OfflineAuditBundle, ProposalType, RewardDispatcher,
    RoleRegistry, VerifiableManifest,
};

#[test]
fn test_i01_chunk_integrity_corrupted_byte_rejected() {
    // Invariant I-01: Alterar 1 byte e tentar aceitar => Rejeição imediata.
    let original_data = b"canonical-arkhe-chunk-payload-alpha";
    let mut chunk = Chunk::new("chunk-01", original_data.to_vec());

    // Valid chunk passes
    assert!(chunk.verify_integrity().is_ok());

    // Corrupt exactly 1 byte
    chunk.content[0] ^= 0xFF;

    // Fail-closed assertion: corrupted chunk must be rejected
    let result = chunk.verify_integrity();
    assert!(result.is_err());
    match result {
        Err(EngineError::ChunkCorrupted { .. }) => {}
        other => panic!("Expected ChunkCorrupted, got {:?}", other),
    }
}

#[test]
fn test_i02_verifiable_manifest_divergent_cid_rejected() {
    // Invariant I-02: Trocar CID ou remover chunk do manifesto => Manifesto rejeitado.
    let entry1 = ManifestChunkEntry {
        index: 0,
        cid: "cid-chunk-1".to_string(),
        size_bytes: 1024,
    };
    let entry2 = ManifestChunkEntry {
        index: 1,
        cid: "cid-chunk-2".to_string(),
        size_bytes: 2048,
    };

    let manifest = VerifiableManifest::new("manifest-01", vec![entry1, entry2]);

    // Matching chunk list passes
    let valid_chunks = vec!["cid-chunk-1".to_string(), "cid-chunk-2".to_string()];
    assert!(manifest.verify(&valid_chunks).is_ok());

    // Divergent chunk CID
    let altered_chunks = vec!["cid-chunk-1".to_string(), "cid-chunk-tampered".to_string()];
    let result = manifest.verify(&altered_chunks);
    assert!(result.is_err());
    match result {
        Err(EngineError::ManifestInvalid(msg)) => {
            assert!(msg.contains("CID mismatch"));
        }
        other => panic!("Expected ManifestInvalid, got {:?}", other),
    }

    // Missing chunk (count mismatch)
    let incomplete_chunks = vec!["cid-chunk-1".to_string()];
    let result_missing = manifest.verify(&incomplete_chunks);
    assert!(result_missing.is_err());
}

#[test]
fn test_i03_afir_receipt_invalid_signature_and_reused_nonce_rejected() {
    // Invariant I-03: Assinar com chave errada ou reusar nonce => Recibo rejeitado.
    let mut validator = AfirValidator::new();
    let worker = "worker-001";
    let token = "ml-dsa-valid-key";
    validator.register_key(worker, token);

    let mut receipt = AfirReceipt {
        receipt_id: "rec-101".to_string(),
        nonce: 42,
        worker_id: worker.to_string(),
        task_digest: "digest-task-abc".to_string(),
        signature: String::new(),
    };

    // Calculate valid signature
    let sig = hash_sha256(&[receipt.signing_bytes().as_slice(), token.as_bytes()].concat());
    receipt.signature = sig;

    // First presentation: valid
    assert!(validator.verify_receipt(&receipt).is_ok());

    // 1. Reused nonce test
    let replay_result = validator.verify_receipt(&receipt);
    assert!(replay_result.is_err());
    match replay_result {
        Err(EngineError::ReceiptInvalid(msg)) => {
            assert!(msg.contains("replay detected"));
        }
        other => panic!("Expected replay detection error, got {:?}", other),
    }

    // 2. Invalid signature test with new nonce
    let bad_sig_receipt = AfirReceipt {
        receipt_id: "rec-102".to_string(),
        nonce: 43,
        worker_id: worker.to_string(),
        task_digest: "digest-task-abc".to_string(),
        signature: "bad-invalid-signature-deadbeef".to_string(),
    };
    let bad_sig_result = validator.verify_receipt(&bad_sig_receipt);
    assert!(bad_sig_result.is_err());
    match bad_sig_result {
        Err(EngineError::ReceiptInvalid(msg)) => {
            assert!(msg.contains("invalid signature"));
        }
        other => panic!("Expected invalid signature error, got {:?}", other),
    }
}

#[test]
fn test_i04_mmr_append_only_mutation_or_reordering_rejected() {
    // Invariant I-04 / I-05: Remover/reordenar MobileWER => Operação proibida.
    let mut mmr = AppendOnlyMmr::new();
    mmr.append(b"wer-001");
    mmr.append(b"wer-002");
    mmr.append(b"wer-003");

    // Case 1: Valid append-only extension
    let mut extended_mmr = mmr.clone();
    extended_mmr.append(b"wer-004");
    assert!(mmr.verify_append_only_extension(&extended_mmr).is_ok());

    // Case 2: Shrink / removal of MobileWER entry
    let mut shrunken_mmr = mmr.clone();
    shrunken_mmr.leaves.pop();
    assert!(mmr.verify_append_only_extension(&shrunken_mmr).is_err());

    // Case 3: Reordering of leaves
    let mut reordered_mmr = mmr.clone();
    reordered_mmr.leaves.swap(0, 1);
    assert!(mmr.verify_append_only_extension(&reordered_mmr).is_err());
}

#[test]
fn test_i05_offline_audit_bundle_detects_tampering_without_network() {
    // Invariant I-05 / I-09: Corromper bundle e verificar => Falha offline detectada.
    let receipts = vec![AfirReceipt {
        receipt_id: "rec-01".to_string(),
        nonce: 1,
        worker_id: "worker-1".to_string(),
        task_digest: "task-1".to_string(),
        signature: "sig-1".to_string(),
    }];

    let mut bundle = OfflineAuditBundle::new("v1.0", "mmr-root-001", receipts, "checkpoint-001");

    // Unmodified bundle verifies offline cleanly (I-09: chain-agnostic)
    assert!(bundle.verify_offline().is_ok());

    // Tamper with MMR root inside bundle
    bundle.mmr_root = "mmr-root-tampered".to_string();

    let result = bundle.verify_offline();
    assert!(result.is_err());
    match result {
        Err(EngineError::BundleAuditFailed(_)) => {}
        other => panic!("Expected BundleAuditFailed, got {:?}", other),
    }
}

#[test]
fn test_i06_device_binding_checkpoint_without_hardware_attestation_rejected() {
    // Invariant I-06: Usar chave sem atestação válida => Checkpoint rejeitado.
    let valid_cp = DeviceCheckpoint {
        epoch: 10,
        device_id: "device-sec-01".to_string(),
        attestation_token: "attest:hardware:enclave:sgx-token-99".to_string(),
        state_root: "root-abc".to_string(),
    };
    assert!(valid_cp.verify_device_binding().is_ok());

    let invalid_cp = DeviceCheckpoint {
        epoch: 10,
        device_id: "device-sec-02".to_string(),
        attestation_token: "software-simulated-token".to_string(),
        state_root: "root-abc".to_string(),
    };
    let result = invalid_cp.verify_device_binding();
    assert!(result.is_err());
    match result {
        Err(EngineError::DeviceAttestationMissing(_)) => {}
        other => panic!("Expected DeviceAttestationMissing, got {:?}", other),
    }
}

#[test]
fn test_i07_human_governance_autonomous_constitution_amendment_blocked() {
    // Invariant I-07: Proposta autônoma tentando alterar constituição sem aprovação humana é bloqueada.
    let auto_proposal = GovernanceProposal {
        proposal_id: "prop-999".to_string(),
        author_is_autonomous_agent: true,
        proposal_type: ProposalType::ConstitutionalAmendment,
        human_canonical_signature: None,
    };

    let result = auto_proposal.assert_valid_amendment();
    assert!(result.is_err());
    match result {
        Err(EngineError::AutonomousConstitutionAmendment(_)) => {}
        other => panic!("Expected AutonomousConstitutionAmendment, got {:?}", other),
    }

    // Human canonized amendment is permitted
    let canonized_proposal = GovernanceProposal {
        proposal_id: "prop-1000".to_string(),
        author_is_autonomous_agent: true,
        proposal_type: ProposalType::ConstitutionalAmendment,
        human_canonical_signature: Some("human-ed25519-signature-token".to_string()),
    };
    assert!(canonized_proposal.assert_valid_amendment().is_ok());
}

#[test]
fn test_i08_reward_by_proof_blocked_without_receipt_or_mmr_anchor() {
    // Invariant I-08: Pagar sem recibo/MMR/verificação => Pagamento bloqueado.
    let receipt = AfirReceipt {
        receipt_id: "rec-pay".to_string(),
        nonce: 99,
        worker_id: "worker-pay".to_string(),
        task_digest: "digest".to_string(),
        signature: "sig".to_string(),
    };

    // Attempt reward with missing receipt
    assert!(RewardDispatcher::verify_and_dispatch(None, Some(0)).is_err());

    // Attempt reward with missing MMR anchor
    assert!(RewardDispatcher::verify_and_dispatch(Some(&receipt), None).is_err());

    // With both valid proof components, reward is dispatched
    let payout = RewardDispatcher::verify_and_dispatch(Some(&receipt), Some(0));
    assert!(payout.is_ok());
    assert_eq!(payout.unwrap(), 100);
}

#[test]
fn test_i10_disjoint_roles_worker_cannot_validate_in_same_epoch() {
    // Invariant I-10: Worker tentar validar no mesmo epoch => Rejeição de papel.
    let mut registry = RoleRegistry::new();
    let epoch = 100;
    let node_id = "node-apollo";

    // Register node as worker in epoch 100
    registry.register_worker(epoch, node_id);

    // Attempt to register same node as validator in the same epoch
    let result = registry.register_validator(epoch, node_id);
    assert!(result.is_err());
    match result {
        Err(EngineError::DisjointRoleViolation { worker, epoch: ep }) => {
            assert_eq!(worker, node_id);
            assert_eq!(ep, epoch);
        }
        other => panic!("Expected DisjointRoleViolation, got {:?}", other),
    }

    // Different epoch is permitted
    assert!(registry.register_validator(epoch + 1, node_id).is_ok());
}
