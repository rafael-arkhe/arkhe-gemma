//! Arkhe-Test: Quality & Invariant Verification Pipeline.
//!
//! Core principle:
//! "No functionality enters production without a test that can fail it."
//! (Nenhuma funcionalidade entra em produção sem um teste que possa reprová-la.)

pub mod engine;
pub mod flags;
pub mod invariants;
pub mod pipeline;
pub mod rollback;

pub use engine::*;
pub use flags::*;
pub use invariants::*;
pub use pipeline::*;
pub use rollback::*;

use serde::{Deserialize, Serialize};

/// High-level report format for CI/CD audit trails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineExecutionReport {
    pub commit_hash: String,
    pub timestamp_utc: String,
    pub stages: Vec<StageReport>,
    pub invariant_coverage_percentage: u32,
    pub report_digest: String,
}

impl PipelineExecutionReport {
    pub fn new(
        commit: impl Into<String>,
        timestamp: impl Into<String>,
        stages: Vec<StageReport>,
    ) -> Self {
        let commit_hash = commit.into();
        let timestamp_utc = timestamp.into();

        // Calculate invariant coverage (10 of 10 must be tested)
        let mut tested_invariants = std::collections::HashSet::new();
        for s in &stages {
            for r in &s.results {
                tested_invariants.insert(r.invariant);
            }
        }
        let total_inv = ArkheInvariant::all().len();
        let covered = tested_invariants.len();
        let invariant_coverage_percentage = ((covered as f64 / total_inv as f64) * 100.0) as u32;

        let payload = serde_json::to_vec(&stages).unwrap_or_default();
        let report_digest = hash_blake3(&payload);

        Self {
            commit_hash,
            timestamp_utc,
            stages,
            invariant_coverage_percentage,
            report_digest,
        }
    }

    /// Verifies if the pipeline run satisfies release gate conditions.
    pub fn meets_release_gate(&self) -> bool {
        self.invariant_coverage_percentage == 100 && self.stages.iter().all(|s| s.is_success())
    }
}
