//! 3-Stage Quality Pipeline for continuous invariant verification.
//!
//! Stages:
//! 1. Fast Feedback (< 5 min): Lint, types, unit tests, canonical serialization, BLAKE3/CID, AFiR schemas, MMR append-only, flags.
//! 2. Integration (< 20 min): Node startup, chunk corruption, invalid manifest, AFiR receipt anchoring, MMR rewrite rejection, offline bundle, rollback.
//! 3. Adversarial (Nightly / Release Gate): Receipt replay, invalid ML-DSA signature, chunk byte tampering, divergent CID, deleted MMR entry, split checkpoint, fake fraud proof, same-epoch worker validation, MCP prompt injection.

use crate::invariants::ArkheInvariant;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PipelineError {
    #[error("Pipeline Stage {stage} failed fail-closed check: {reason}")]
    StageFailed { stage: u8, reason: String },
    #[error("Deployment blocked: Invariant {invariant:?} failed falsification test")]
    InvariantFailed {
        invariant: ArkheInvariant,
        detail: String,
    },
    #[error("Timeout budget exceeded: expected under {max:?}, took {elapsed:?}")]
    TimeoutExceeded { max: Duration, elapsed: Duration },
}

/// Pipeline stage classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PipelineStage {
    /// Stage 1: Fast feedback (< 5 min)
    Stage1FastFeedback,
    /// Stage 2: Integration (< 20 min)
    Stage2Integration,
    /// Stage 3: Adversarial (Continuous / Pre-Release)
    Stage3Adversarial,
}

impl PipelineStage {
    pub fn max_budget(&self) -> Duration {
        match self {
            Self::Stage1FastFeedback => Duration::from_secs(300),
            Self::Stage2Integration => Duration::from_secs(1200),
            Self::Stage3Adversarial => Duration::from_secs(3600),
        }
    }
}

/// Result of executing a specific test case within a pipeline stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestCaseResult {
    pub name: String,
    pub invariant: ArkheInvariant,
    pub passed: bool,
    pub execution_time_ms: u64,
    pub artifact_hash: String,
    pub error_message: Option<String>,
}

/// Summary report of a pipeline stage execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageReport {
    pub stage: PipelineStage,
    pub total_tests: usize,
    pub passed_tests: usize,
    pub failed_tests: usize,
    pub duration_ms: u64,
    pub results: Vec<TestCaseResult>,
}

impl StageReport {
    pub fn is_success(&self) -> bool {
        self.failed_tests == 0 && self.total_tests > 0
    }
}
