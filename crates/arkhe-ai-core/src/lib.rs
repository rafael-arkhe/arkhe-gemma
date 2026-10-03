#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! # arkhe-ai-core
//!
//! Orquestrador de inferência verificável.
//!
//! ## Invariantes
//!
//! - `INV-AI-07`: Toda inferência tem `record_hash`
//! - `INV-AI-08`: Trust anchor obrigatória (fail-closed)
//! - `INV-AI-09`: Custo verificado contra orçamento
//! - `INV-AI-10`: Nenhuma inferência usa modelo não-verificado

use std::sync::Arc;

use arkhe_ai_context::{Context, ContextError};
use arkhe_ai_routing::{Router, RoutingError, RoutingRequest};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;

/// Erro do orquestrador.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Erro de contexto.
    #[error("contexto: {0}")]
    Context(#[from] ContextError),
    /// Erro de roteamento.
    #[error("roteamento: {0}")]
    Routing(#[from] RoutingError),
    /// Trust anchor ausente.
    #[error("trust anchor ausente")]
    MissingTrustAnchor,
    /// Orçamento insuficiente.
    #[error("orçamento insuficiente: necessário {required:.4}, disponível {available:.4}")]
    InsufficientBudget {
        /// Necessário.
        required: f64,
        /// Disponível.
        available: f64,
    },
    /// Backend de inferência falhou.
    #[error("backend: {0}")]
    Backend(String),
}

/// Resultado de inferência.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceResult {
    /// Texto gerado.
    pub output: String,
    /// Modelo usado.
    pub model_id: String,
    /// Tokens de entrada.
    pub input_tokens: usize,
    /// Tokens de saída.
    pub output_tokens: usize,
    /// Custo.
    pub cost: f64,
    /// `record_hash` da inferência.
    pub record_hash: [u8; 32],
}

/// Backend de inferência.
#[async_trait::async_trait]
pub trait InferenceBackend: Send + Sync + std::fmt::Debug {
    /// Executa inferência.
    ///
    /// # Errors
    ///
    /// Devolve [`CoreError::Backend`] se a inferência falhar.
    async fn infer(
        &self,
        model_id: &str,
        prompt: &str,
        max_tokens: usize,
    ) -> Result<String, CoreError>;

    /// Nome do backend.
    fn name(&self) -> &str;
}

/// Backend determinístico para testes.
#[derive(Debug, Default)]
pub struct EchoBackend;

#[async_trait::async_trait]
impl InferenceBackend for EchoBackend {
    async fn infer(
        &self,
        _model_id: &str,
        prompt: &str,
        _max_tokens: usize,
    ) -> Result<String, CoreError> {
        Ok(format!("echo: {prompt}"))
    }

    fn name(&self) -> &str {
        "echo"
    }
}

/// Configuração do orquestrador.
#[derive(Debug, Clone, Default)]
pub struct AiConfig {
    /// Trust anchor (DID).
    pub trust_anchor: Option<String>,
    /// Orçamento disponível em USD.
    pub budget: f64,
}

/// Orquestrador de inferência.
#[derive(Debug)]
pub struct AiOrchestrator {
    router: Arc<RwLock<Router>>,
    backend: Arc<dyn InferenceBackend>,
    config: AiConfig,
}

impl AiOrchestrator {
    /// Cria um orquestrador.
    #[must_use]
    pub fn new(router: Router, backend: Arc<dyn InferenceBackend>, config: AiConfig) -> Self {
        Self {
            router: Arc::new(RwLock::new(router)),
            backend,
            config,
        }
    }

    /// Executa uma inferência verificável.
    ///
    /// # Errors
    ///
    /// Fail-closed em quatro pontos:
    /// 1. Trust anchor ausente (`INV-AI-08`)
    /// 2. Roteamento sem modelo `Verified` (`INV-AI-10`)
    /// 3. Custo > orçamento (`INV-AI-09`)
    /// 4. Backend falhou
    pub async fn infer(
        &self,
        req: RoutingRequest,
        context: Context,
    ) -> Result<InferenceResult, CoreError> {
        // 1. Trust anchor (fail-closed)
        if self.config.trust_anchor.is_none() {
            return Err(CoreError::MissingTrustAnchor);
        }

        // 2. Roteamento (delega verificação ao router)
        let decision = {
            let router = self.router.read().await;
            router.route(&req)?
        };

        // 3. Orçamento (fail-closed)
        let estimated_cost = decision.expected_cost * (context.total_tokens() as f64 / 1000.0);
        if estimated_cost > self.config.budget {
            return Err(CoreError::InsufficientBudget {
                required: estimated_cost,
                available: self.config.budget,
            });
        }

        // 4. Montar prompt a partir do contexto
        let prompt: String = context
            .segments
            .iter()
            .map(|s| format!("[{}] {}", s.role, s.content))
            .collect::<Vec<_>>()
            .join("\n");

        // 5. Inferência
        let output = self.backend.infer(&decision.model_id, &prompt, 512).await?;

        // 6. `record_hash` da inferência (`INV-AI-07`)
        let output_tokens = arkhe_ai_context::estimate_tokens(&output);
        let mut h = blake3::Hasher::new_derive_key("arkhe-ai-inference-v1");
        h.update(decision.model_id.as_bytes());
        h.update(decision.record_hash.as_slice());
        h.update(context.record_hash.as_slice());
        h.update(output.as_bytes());
        let record_hash = *h.finalize().as_bytes();

        tracing::info!(
            model = %decision.model_id,
            backend = %self.backend.name(),
            cost = estimated_cost,
            record_hash = %hex::encode(record_hash),
            "inferência concluída"
        );

        Ok(InferenceResult {
            output,
            model_id: decision.model_id,
            input_tokens: context.total_tokens(),
            output_tokens,
            cost: estimated_cost,
            record_hash,
        })
    }

    /// Registra um modelo no router.
    pub async fn register_model(&self, model: arkhe_ai_routing::RegisteredModel) {
        self.router.write().await.register(model);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arkhe_ai_context::ContextSegment;
    use arkhe_ai_routing::{Capability, ModelStatus, Preference, RegisteredModel};

    fn ctx() -> Context {
        Context::new(
            vec![
                ContextSegment::new("system", "You are Arkhe.", "did:arkhe:sys"),
                ContextSegment::new("user", "hello", "did:arkhe:user"),
            ],
            1000,
        )
        .unwrap()
    }

    fn model() -> RegisteredModel {
        RegisteredModel {
            id: "test-model".into(),
            model_hash: "sha256:abc".into(),
            status: ModelStatus::Verified,
            capabilities: vec![Capability::TextGeneration],
            cost_per_1k: 0.001,
            latency_p50_ms: 50,
        }
    }

    fn req() -> RoutingRequest {
        RoutingRequest {
            capability: Capability::TextGeneration,
            max_cost: None,
            max_latency_ms: None,
            preference: Preference::Cost,
        }
    }

    #[tokio::test]
    async fn inv_ai_08_missing_trust_anchor_blocks() {
        let mut router = Router::new();
        router.register(model());
        let orch = AiOrchestrator::new(
            router,
            Arc::new(EchoBackend),
            AiConfig {
                trust_anchor: None,
                budget: 100.0,
            },
        );
        assert!(matches!(
            orch.infer(req(), ctx()).await.unwrap_err(),
            CoreError::MissingTrustAnchor
        ));
    }

    #[tokio::test]
    async fn inv_ai_09_insufficient_budget_blocks() {
        let mut router = Router::new();
        router.register(model());
        let orch = AiOrchestrator::new(
            router,
            Arc::new(EchoBackend),
            AiConfig {
                trust_anchor: Some("did:arkhe:a".into()),
                budget: 0.0,
            },
        );
        assert!(matches!(
            orch.infer(req(), ctx()).await.unwrap_err(),
            CoreError::InsufficientBudget { .. }
        ));
    }

    #[tokio::test]
    async fn inv_ai_07_happy_path_produces_record_hash() {
        let mut router = Router::new();
        router.register(model());
        let orch = AiOrchestrator::new(
            router,
            Arc::new(EchoBackend),
            AiConfig {
                trust_anchor: Some("did:arkhe:a".into()),
                budget: 100.0,
            },
        );
        let r = orch.infer(req(), ctx()).await.unwrap();
        assert!(r.output.starts_with("echo:"));
        assert_ne!(r.record_hash, [0u8; 32]);
    }

    #[tokio::test]
    async fn inv_ai_10_unverified_model_blocks() {
        let mut router = Router::new();
        let mut m = model();
        m.status = ModelStatus::Failed;
        router.register(m);
        let orch = AiOrchestrator::new(
            router,
            Arc::new(EchoBackend),
            AiConfig {
                trust_anchor: Some("did:arkhe:a".into()),
                budget: 100.0,
            },
        );
        assert!(matches!(
            orch.infer(req(), ctx()).await.unwrap_err(),
            CoreError::Routing(_)
        ));
    }
}
