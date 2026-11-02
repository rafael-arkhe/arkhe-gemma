//! Rollback verification and invariant preservation.
//!
//! Invariant I-T05:
//! `rollback => evidência existente intacta`
//!
//! Rules:
//! - Rollback is permitted for code and configuration ONLY.
//! - Rollback NEVER rewrites or mutates MMR, receipts, or checkpoints.
//! - If the newer version created valid evidence, the previous version must be able
//!   to read it or preserve it without truncating historical roots.
//! - In case of schema upgrade incompatibility, migration must be append-only, never deletion.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RollbackError {
    #[error("Corrupted MMR root after rollback: original {original}, post_rollback {current}")]
    MmrRootMismatch { original: String, current: String },
    #[error("Evidence record loss detected: expected {expected} records, found {found}")]
    EvidenceLoss { expected: usize, found: usize },
    #[error("Checkpoint rewritten or deleted during rollback: id {id}")]
    CheckpointMutated { id: String },
    #[error("Attempted non-append-only schema migration during rollback: {reason}")]
    IllegalMigration { reason: String },
}

/// Snapshot of system evidence state before a deployment or rollback action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceStateSnapshot {
    pub mmr_root: String,
    pub total_mmr_nodes: usize,
    pub receipt_count: usize,
    pub checkpoint_hashes: Vec<String>,
}

/// Rollback verification engine.
#[derive(Debug, Default)]
pub struct RollbackVerifier;

impl RollbackVerifier {
    /// Asserts that a rollback operation preserved all immutable evidence.
    pub fn assert_intact(
        before: &EvidenceStateSnapshot,
        after: &EvidenceStateSnapshot,
    ) -> Result<(), RollbackError> {
        // MMR nodes and receipts must never decrease (append-only)
        if after.total_mmr_nodes < before.total_mmr_nodes {
            return Err(RollbackError::EvidenceLoss {
                expected: before.total_mmr_nodes,
                found: after.total_mmr_nodes,
            });
        }

        if after.receipt_count < before.receipt_count {
            return Err(RollbackError::EvidenceLoss {
                expected: before.receipt_count,
                found: after.receipt_count,
            });
        }

        // All pre-rollback checkpoints must remain present in post-rollback state
        for cp in &before.checkpoint_hashes {
            if !after.checkpoint_hashes.contains(cp) {
                return Err(RollbackError::CheckpointMutated { id: cp.clone() });
            }
        }

        Ok(())
    }
}
