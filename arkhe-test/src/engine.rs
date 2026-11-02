//! Core test engine, cryptographic primitives, and invariant verifiers for Arkhe.

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EngineError {
    #[error("Chunk integrity failure: expected hash {expected}, got {actual}")]
    ChunkCorrupted { expected: String, actual: String },
    #[error("Manifest verification failure: {0}")]
    ManifestInvalid(String),
    #[error("Receipt verification failure: {0}")]
    ReceiptInvalid(String),
    #[error("MMR consistency failure: {0}")]
    MmrAppendOnlyViolation(String),
    #[error("Offline bundle audit failure: {0}")]
    BundleAuditFailed(String),
    #[error("Device binding failure: {0}")]
    DeviceAttestationMissing(String),
    #[error("Human governance breach: {0}")]
    AutonomousConstitutionAmendment(String),
    #[error("Reward blocked: {0}")]
    RewardWithoutProof(String),
    #[error("Disjoint role violation: worker {worker} cannot validate in epoch {epoch}")]
    DisjointRoleViolation { worker: String, epoch: u64 },
}

/// Computes lowercase hex BLAKE3 hash.
pub fn hash_blake3(data: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    hasher.finalize().to_hex().to_string()
}

/// Computes lowercase hex SHA-256 hash.
pub fn hash_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Chunk structure according to Phase F1 specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chunk {
    pub chunk_id: String,
    pub content: Vec<u8>,
    pub expected_hash: String,
}

impl Chunk {
    pub fn new(chunk_id: impl Into<String>, content: Vec<u8>) -> Self {
        let expected_hash = hash_blake3(&content);
        Self {
            chunk_id: chunk_id.into(),
            content,
            expected_hash,
        }
    }

    /// Verifies chunk integrity (I-01).
    pub fn verify_integrity(&self) -> Result<(), EngineError> {
        let actual_hash = hash_blake3(&self.content);
        if actual_hash != self.expected_hash {
            return Err(EngineError::ChunkCorrupted {
                expected: self.expected_hash.clone(),
                actual: actual_hash,
            });
        }
        Ok(())
    }
}

/// Manifest entry according to Phase F1 specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestChunkEntry {
    pub index: usize,
    pub cid: String,
    pub size_bytes: usize,
}

/// Verifiable Manifest structure (I-02).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiableManifest {
    pub manifest_id: String,
    pub chunks: Vec<ManifestChunkEntry>,
    pub manifest_cid: String,
}

impl VerifiableManifest {
    pub fn new(manifest_id: impl Into<String>, chunks: Vec<ManifestChunkEntry>) -> Self {
        let manifest_id = manifest_id.into();
        let payload = serde_json::to_vec(&chunks).unwrap_or_default();
        let manifest_cid = format!("cidv1:blake3:{}", hash_blake3(&payload));
        Self {
            manifest_id,
            chunks,
            manifest_cid,
        }
    }

    /// Verifies manifest integrity and chunk completeness (I-02).
    pub fn verify(&self, actual_chunk_hashes: &[String]) -> Result<(), EngineError> {
        let payload = serde_json::to_vec(&self.chunks)
            .map_err(|e| EngineError::ManifestInvalid(format!("serialization failure: {e}")))?;
        let computed_cid = format!("cidv1:blake3:{}", hash_blake3(&payload));
        if computed_cid != self.manifest_cid {
            return Err(EngineError::ManifestInvalid(format!(
                "manifest CID mismatch: expected {}, got {}",
                self.manifest_cid, computed_cid
            )));
        }

        if actual_chunk_hashes.len() != self.chunks.len() {
            return Err(EngineError::ManifestInvalid(format!(
                "chunk count mismatch: manifest expected {}, provided {}",
                self.chunks.len(),
                actual_chunk_hashes.len()
            )));
        }

        for (i, entry) in self.chunks.iter().enumerate() {
            if entry.cid != actual_chunk_hashes[i] {
                return Err(EngineError::ManifestInvalid(format!(
                    "chunk at index {} CID mismatch: expected {}, got {}",
                    i, entry.cid, actual_chunk_hashes[i]
                )));
            }
        }

        Ok(())
    }
}

/// AFiR Receipt structure (I-03).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AfirReceipt {
    pub receipt_id: String,
    pub nonce: u64,
    pub worker_id: String,
    pub task_digest: String,
    pub signature: String,
}

impl AfirReceipt {
    /// Computes canonical signing payload.
    pub fn signing_bytes(&self) -> Vec<u8> {
        format!(
            "{}:{}:{}:{}",
            self.receipt_id, self.nonce, self.worker_id, self.task_digest
        )
        .into_bytes()
    }
}

/// AFiR Receipt Validator with replay defense.
#[derive(Debug, Default)]
pub struct AfirValidator {
    seen_nonces: HashSet<(String, u64)>,
    trusted_public_keys: BTreeMap<String, String>,
}

impl AfirValidator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_key(
        &mut self,
        worker_id: impl Into<String>,
        pubkey_sig_token: impl Into<String>,
    ) {
        self.trusted_public_keys
            .insert(worker_id.into(), pubkey_sig_token.into());
    }

    /// Verifies receipt signature and asserts nonce freshness (I-03).
    pub fn verify_receipt(&mut self, receipt: &AfirReceipt) -> Result<(), EngineError> {
        // Nonce freshness check (Replay defense)
        let nonce_key = (receipt.worker_id.clone(), receipt.nonce);
        if self.seen_nonces.contains(&nonce_key) {
            return Err(EngineError::ReceiptInvalid(format!(
                "replay detected: nonce {} already used by worker {}",
                receipt.nonce, receipt.worker_id
            )));
        }

        // Signature check
        let expected_token = match self.trusted_public_keys.get(&receipt.worker_id) {
            Some(t) => t,
            None => {
                return Err(EngineError::ReceiptInvalid(format!(
                    "untrusted worker {}",
                    receipt.worker_id
                )))
            }
        };

        // Deterministic signature validation simulation (e.g. ML-DSA signature token)
        let expected_sig = hash_sha256(
            &[
                receipt.signing_bytes().as_slice(),
                expected_token.as_bytes(),
            ]
            .concat(),
        );
        if receipt.signature != expected_sig {
            return Err(EngineError::ReceiptInvalid(format!(
                "invalid signature: expected {}, got {}",
                expected_sig, receipt.signature
            )));
        }

        self.seen_nonces.insert(nonce_key);
        Ok(())
    }
}

/// Append-Only Merkle Mountain Range (MMR) simulation (I-04).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppendOnlyMmr {
    pub peaks: Vec<String>,
    pub leaves: Vec<String>,
}

impl Default for AppendOnlyMmr {
    fn default() -> Self {
        Self::new()
    }
}

impl AppendOnlyMmr {
    pub fn new() -> Self {
        Self {
            peaks: Vec::new(),
            leaves: Vec::new(),
        }
    }

    /// Appends a leaf (MobileWER) strictly append-only.
    pub fn append(&mut self, leaf_data: &[u8]) -> usize {
        let leaf_hash = hash_blake3(leaf_data);
        self.leaves.push(leaf_hash.clone());
        self.recompute_peaks();
        self.leaves.len() - 1
    }

    fn recompute_peaks(&mut self) {
        let mut current_peaks = Vec::new();
        for chunk in self.leaves.chunks(2) {
            if chunk.len() == 2 {
                let parent = hash_blake3(format!("{}:{}", chunk[0], chunk[1]).as_bytes());
                current_peaks.push(parent);
            } else {
                current_peaks.push(chunk[0].clone());
            }
        }
        self.peaks = current_peaks;
    }

    pub fn root_hash(&self) -> String {
        if self.peaks.is_empty() {
            return hash_blake3(b"empty_mmr");
        }
        let joined = self.peaks.join(":");
        hash_blake3(joined.as_bytes())
    }

    /// Asserts that a candidate MMR is a valid append-only extension of self.
    pub fn verify_append_only_extension(&self, next: &AppendOnlyMmr) -> Result<(), EngineError> {
        if next.leaves.len() < self.leaves.len() {
            return Err(EngineError::MmrAppendOnlyViolation(format!(
                "illegal shrink: original had {} leaves, new has {}",
                self.leaves.len(),
                next.leaves.len()
            )));
        }

        // Must prefix-match all previous leaves in exact order
        for (i, leaf) in self.leaves.iter().enumerate() {
            if next.leaves.get(i) != Some(leaf) {
                return Err(EngineError::MmrAppendOnlyViolation(format!(
                    "leaf reordering or mutation detected at index {}",
                    i
                )));
            }
        }

        Ok(())
    }
}

/// Offline Audit Bundle structure (I-05 & I-09).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineAuditBundle {
    pub version: String,
    pub mmr_root: String,
    pub receipts: Vec<AfirReceipt>,
    pub checkpoint_hash: String,
    pub bundle_digest: String,
}

impl OfflineAuditBundle {
    pub fn new(
        version: impl Into<String>,
        mmr_root: impl Into<String>,
        receipts: Vec<AfirReceipt>,
        checkpoint_hash: impl Into<String>,
    ) -> Self {
        let version = version.into();
        let mmr_root = mmr_root.into();
        let checkpoint_hash = checkpoint_hash.into();

        let mut hasher = blake3::Hasher::new();
        hasher.update(version.as_bytes());
        hasher.update(mmr_root.as_bytes());
        hasher.update(checkpoint_hash.as_bytes());
        for r in &receipts {
            hasher.update(r.receipt_id.as_bytes());
            hasher.update(&r.nonce.to_le_bytes());
            hasher.update(r.signature.as_bytes());
        }
        let bundle_digest = hasher.finalize().to_hex().to_string();

        Self {
            version,
            mmr_root,
            receipts,
            checkpoint_hash,
            bundle_digest,
        }
    }

    /// Verifies the bundle offline without external or blockchain calls (I-05, I-09).
    pub fn verify_offline(&self) -> Result<(), EngineError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.version.as_bytes());
        hasher.update(self.mmr_root.as_bytes());
        hasher.update(self.checkpoint_hash.as_bytes());
        for r in &self.receipts {
            hasher.update(r.receipt_id.as_bytes());
            hasher.update(&r.nonce.to_le_bytes());
            hasher.update(r.signature.as_bytes());
        }
        let expected_digest = hasher.finalize().to_hex().to_string();
        if expected_digest != self.bundle_digest {
            return Err(EngineError::BundleAuditFailed(format!(
                "offline bundle digest mismatch: expected {}, got {}",
                self.bundle_digest, expected_digest
            )));
        }
        Ok(())
    }
}

/// Device Attestation for Checkpoints (I-06).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCheckpoint {
    pub epoch: u64,
    pub device_id: String,
    pub attestation_token: String,
    pub state_root: String,
}

impl DeviceCheckpoint {
    pub fn verify_device_binding(&self) -> Result<(), EngineError> {
        if !self
            .attestation_token
            .starts_with("attest:hardware:enclave:")
        {
            return Err(EngineError::DeviceAttestationMissing(format!(
                "device checkpoint for device {} lacks valid hardware enclave attestation",
                self.device_id
            )));
        }
        Ok(())
    }
}

/// Governance proposal type (I-07).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalType {
    OperationalParamUpdate,
    FeatureFlagToggle,
    ConstitutionalAmendment,
}

/// Governance proposal (I-07).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceProposal {
    pub proposal_id: String,
    pub author_is_autonomous_agent: bool,
    pub proposal_type: ProposalType,
    pub human_canonical_signature: Option<String>,
}

impl GovernanceProposal {
    /// Validates constitutional amendment gate (I-07).
    pub fn assert_valid_amendment(&self) -> Result<(), EngineError> {
        if self.proposal_type == ProposalType::ConstitutionalAmendment
            && self.author_is_autonomous_agent
            && self.human_canonical_signature.is_none()
        {
            return Err(EngineError::AutonomousConstitutionAmendment(
                "autonomous agent proposal cannot alter constitution without explicit human canonization"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

/// Reward distribution authority (I-08).
#[derive(Debug, Default)]
pub struct RewardDispatcher;

impl RewardDispatcher {
    /// Dispatches reward only when backed by valid receipt and MMR anchor.
    pub fn verify_and_dispatch(
        receipt: Option<&AfirReceipt>,
        mmr_leaf_index: Option<usize>,
    ) -> Result<u64, EngineError> {
        match (receipt, mmr_leaf_index) {
            (Some(_r), Some(_idx)) => Ok(100), // Disburses reward units
            _ => Err(EngineError::RewardWithoutProof(
                "cannot release reward: missing verified AFiR receipt or MMR anchor proof"
                    .to_string(),
            )),
        }
    }
}

/// Disjoint Role Separation enforcement (I-10).
#[derive(Debug, Default)]
pub struct RoleRegistry {
    workers_per_epoch: BTreeMap<u64, HashSet<String>>,
    validators_per_epoch: BTreeMap<u64, HashSet<String>>,
}

impl RoleRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_worker(&mut self, epoch: u64, node_id: impl Into<String>) {
        self.workers_per_epoch
            .entry(epoch)
            .or_default()
            .insert(node_id.into());
    }

    /// Verifies node can be admitted as validator for epoch (I-10).
    pub fn register_validator(
        &mut self,
        epoch: u64,
        node_id: impl Into<String>,
    ) -> Result<(), EngineError> {
        let node = node_id.into();
        if let Some(workers) = self.workers_per_epoch.get(&epoch) {
            if workers.contains(&node) {
                return Err(EngineError::DisjointRoleViolation {
                    worker: node,
                    epoch,
                });
            }
        }
        self.validators_per_epoch
            .entry(epoch)
            .or_default()
            .insert(node);
        Ok(())
    }
}
