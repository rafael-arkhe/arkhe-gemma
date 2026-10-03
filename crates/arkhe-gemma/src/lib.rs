#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! # arkhe-gemma
//!
//! Integração verificável do modelo Gemma 4 com o Arkhe OS.
//!
//! ## Invariantes
//!
//! - `INV-GEMMA-01`: Todo modelo é verificado antes de ser carregado
//! - `INV-GEMMA-02`: Inferência falha fechado se o orçamento for excedido
//! - `INV-GEMMA-03`: Cada patch proposto tem `record_hash` verificável
//! - `INV-GEMMA-04`: O agente não modifica ficheiros fora do escopo declarado
//! - `INV-GEMMA-05`: `SelfModel` detecta divergências entre declaração e ação

/// Módulo agent
pub mod agent;
/// Módulo backend
pub mod backend;
/// Módulo config
pub mod config;
/// Módulo error
pub mod error;
/// Módulo verify
pub mod verify;

pub use agent::{AgentOutcome, GemmaAction, GemmaAgent};
pub use backend::{GemmaBackend, InferenceRequest, InferenceResponse};
pub use config::{GemmaConfig, ModelSource};
pub use error::GemmaError;
pub use verify::{verify_model_integrity, ModelManifest, ModelVerificationResult};
