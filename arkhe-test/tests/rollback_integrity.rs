//! Rollback safety and immutable evidence preservation tests.
//!
//! Invariant I-T05:
//! `rollback => evidência existente intacta`

use arkhe_test::{EvidenceStateSnapshot, RollbackError, RollbackVerifier};

#[test]
fn test_rollback_preserves_historical_evidence() {
    let before_rollback = EvidenceStateSnapshot {
        mmr_root: "root-hash-epoch-10".to_string(),
        total_mmr_nodes: 500,
        receipt_count: 1200,
        checkpoint_hashes: vec![
            "checkpoint-epoch-8".to_string(),
            "checkpoint-epoch-9".to_string(),
            "checkpoint-epoch-10".to_string(),
        ],
    };

    // A valid rollback retains all historical MMR nodes, receipts, and checkpoints
    let after_rollback = EvidenceStateSnapshot {
        mmr_root: "root-hash-epoch-10".to_string(),
        total_mmr_nodes: 500,
        receipt_count: 1200,
        checkpoint_hashes: vec![
            "checkpoint-epoch-8".to_string(),
            "checkpoint-epoch-9".to_string(),
            "checkpoint-epoch-10".to_string(),
        ],
    };

    assert!(RollbackVerifier::assert_intact(&before_rollback, &after_rollback).is_ok());
}

#[test]
fn test_rollback_rejects_mmr_node_loss() {
    let before_rollback = EvidenceStateSnapshot {
        mmr_root: "root-hash-epoch-10".to_string(),
        total_mmr_nodes: 500,
        receipt_count: 1200,
        checkpoint_hashes: vec!["checkpoint-epoch-10".to_string()],
    };

    // Corrupted rollback that lost MMR nodes
    let after_rollback = EvidenceStateSnapshot {
        mmr_root: "root-hash-epoch-9".to_string(),
        total_mmr_nodes: 450, // Truncation
        receipt_count: 1200,
        checkpoint_hashes: vec!["checkpoint-epoch-10".to_string()],
    };

    let result = RollbackVerifier::assert_intact(&before_rollback, &after_rollback);
    assert!(result.is_err());
    match result {
        Err(RollbackError::EvidenceLoss { expected, found }) => {
            assert_eq!(expected, 500);
            assert_eq!(found, 450);
        }
        other => panic!("Expected EvidenceLoss, got {:?}", other),
    }
}

#[test]
fn test_rollback_rejects_checkpoint_mutation() {
    let before_rollback = EvidenceStateSnapshot {
        mmr_root: "root-hash-epoch-10".to_string(),
        total_mmr_nodes: 500,
        receipt_count: 1200,
        checkpoint_hashes: vec!["checkpoint-epoch-10".to_string()],
    };

    // Corrupted rollback missing epoch-10 checkpoint
    let after_rollback = EvidenceStateSnapshot {
        mmr_root: "root-hash-epoch-10".to_string(),
        total_mmr_nodes: 500,
        receipt_count: 1200,
        checkpoint_hashes: vec!["checkpoint-epoch-09-corrupted".to_string()],
    };

    let result = RollbackVerifier::assert_intact(&before_rollback, &after_rollback);
    assert!(result.is_err());
    match result {
        Err(RollbackError::CheckpointMutated { id }) => {
            assert_eq!(id, "checkpoint-epoch-10");
        }
        other => panic!("Expected CheckpointMutated, got {:?}", other),
    }
}
