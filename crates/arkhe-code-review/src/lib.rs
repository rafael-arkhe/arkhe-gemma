#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! # arkhe-code-review
//!
//! Facade pública para o pipeline de code review.
//! Reexporta todos os tipos necessários das crates internas.

/// Versão atual da crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// Re-exports
pub use arkhe_code_review_agents::{
    fan_out, AgentError, AgentKind, FanOutResult, MockLogicAgent, MockSecurityAgent, ReviewAgent,
};
pub use arkhe_code_review_context::{ContextError, ReviewContext};
pub use arkhe_code_review_core::{
    CoreError, ReviewConfig, ReviewOrchestrator, ReviewResult,
};
pub use arkhe_code_review_diff::{Diff, DiffError, FileDiff, Hunk, DiffLine, LineKind};
pub use arkhe_code_review_judge::{judge, JudgeConfig, JudgeContext, JudgeResult, RejectReason};
pub use arkhe_code_review_static::{
    Evidence, Finding, FindingSource, NoUnwrapAnalyzer, Severity, StaticAnalyzer, StaticError,
};
