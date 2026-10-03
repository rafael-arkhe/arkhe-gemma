#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! # arkhe-ai-routing
//!
//! Roteamento de modelos com verificação de capabilities.
//!
//! ## Invariantes
//!
//! - `INV-AI-04`: Modelo sem capability declarada é rejeitado (fail-closed)
//! - `INV-AI-05`: Roteamento é determinístico para a mesma `RoutingRequest`
//! - `INV-AI-06`: Modelos com `status != Verified` não recebem tráfego

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Erro de roteamento.
#[derive(Debug, Error)]
pub enum RoutingError {
    /// Nenhum modelo disponível.
    #[error("nenhum modelo disponível para a capability: {0}")]
    NoModel(String),
    /// Modelo não verificado.
    #[error("modelo não verificado: {0}")]
    UnverifiedModel(String),
    /// Capability não declarada.
    #[error("capability não declarada: {0}")]
    MissingCapability(String),
}

/// Capability de modelo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Geração de texto.
    TextGeneration,
    /// Raciocínio multi-passo.
    Reasoning,
    /// Código.
    Code,
    /// Análise de imagem.
    Vision,
    /// Análise de áudio.
    Audio,
    /// Ferramentas (tool use).
    ToolUse,
}

/// Estado de verificação do modelo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModelStatus {
    /// Verificado.
    Verified,
    /// Parcial.
    Partial,
    /// Falhado.
    Failed,
    /// Não existente.
    Nonexistent,
}

/// Modelo registado.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredModel {
    /// ID.
    pub id: String,
    /// `record_hash` do modelo.
    pub model_hash: String,
    /// Status.
    pub status: ModelStatus,
    /// Capabilities.
    pub capabilities: Vec<Capability>,
    /// Custo por 1k tokens.
    pub cost_per_1k: f64,
    /// Latência p50 (ms).
    pub latency_p50_ms: u64,
}

/// Pedido de roteamento.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRequest {
    /// Capability necessária.
    pub capability: Capability,
    /// Máximo de custo por 1k tokens.
    pub max_cost: Option<f64>,
    /// Máximo de latência (ms).
    pub max_latency_ms: Option<u64>,
    /// Preferência: `cost`, `latency`, `balanced`.
    pub preference: Preference,
}

/// Preferência de roteamento.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Preference {
    /// Menor custo.
    Cost,
    /// Menor latência.
    Latency,
    /// Equilibrado.
    Balanced,
}

/// Resultado do roteamento.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingDecision {
    /// Modelo escolhido.
    pub model_id: String,
    /// Custo esperado por 1k.
    pub expected_cost: f64,
    /// Latência esperada.
    pub expected_latency_ms: u64,
    /// `record_hash` da decisão.
    pub record_hash: [u8; 32],
}

/// Tabela de roteamento.
#[derive(Debug, Default)]
pub struct Router {
    models: Vec<RegisteredModel>,
}

impl Router {
    /// Cria um router vazio.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registra um modelo.
    pub fn register(&mut self, model: RegisteredModel) {
        self.models.push(model);
    }

    /// Roteia um pedido (fail-closed).
    ///
    /// # Errors
    ///
    /// - Sem capability → [`RoutingError::MissingCapability`]
    /// - Sem `Verified` → [`RoutingError::UnverifiedModel`]
    /// - Nenhum candidato após filtros → [`RoutingError::NoModel`]
    pub fn route(&self, req: &RoutingRequest) -> Result<RoutingDecision, RoutingError> {
        let candidates: Vec<&RegisteredModel> = self
            .models
            .iter()
            .filter(|m| m.capabilities.contains(&req.capability))
            .collect();

        if candidates.is_empty() {
            return Err(RoutingError::MissingCapability(format!(
                "{:?}",
                req.capability
            )));
        }

        let verified: Vec<&RegisteredModel> = candidates
            .iter()
            .filter(|m| m.status == ModelStatus::Verified)
            .copied()
            .collect();

        if verified.is_empty() {
            return Err(RoutingError::UnverifiedModel(format!(
                "{} candidatos sem status VERIFIED",
                candidates.len()
            )));
        }

        let filtered: Vec<&RegisteredModel> = verified
            .iter()
            .filter(|m| req.max_cost.is_none_or(|c| m.cost_per_1k <= c))
            .filter(|m| req.max_latency_ms.is_none_or(|l| m.latency_p50_ms <= l))
            .copied()
            .collect();

        if filtered.is_empty() {
            return Err(RoutingError::NoModel(format!(
                "após filtros de custo/latência para {:?}",
                req.capability
            )));
        }

        let chosen = match req.preference {
            Preference::Cost => filtered.iter().min_by(|a, b| {
                a.cost_per_1k
                    .partial_cmp(&b.cost_per_1k)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then(a.id.cmp(&b.id))
            }),
            Preference::Latency => filtered.iter().min_by(|a, b| {
                a.latency_p50_ms
                    .cmp(&b.latency_p50_ms)
                    .then(a.id.cmp(&b.id))
            }),
            Preference::Balanced => filtered.iter().min_by(|a, b| {
                let sa = a.cost_per_1k * 0.5 + (a.latency_p50_ms as f64) * 0.5;
                let sb = b.cost_per_1k * 0.5 + (b.latency_p50_ms as f64) * 0.5;
                sa.partial_cmp(&sb)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then(a.id.cmp(&b.id))
            }),
        }
        .ok_or_else(|| RoutingError::NoModel("seleção falhou".into()))?;

        let mut h = blake3::Hasher::new_derive_key("arkhe-ai-routing-v1");
        h.update(chosen.id.as_bytes());
        h.update(chosen.model_hash.as_bytes());
        h.update(&chosen.cost_per_1k.to_le_bytes());
        h.update(&chosen.latency_p50_ms.to_le_bytes());
        h.update(format!("{:?}", req.capability).as_bytes());
        let record_hash = *h.finalize().as_bytes();

        Ok(RoutingDecision {
            model_id: chosen.id.clone(),
            expected_cost: chosen.cost_per_1k,
            expected_latency_ms: chosen.latency_p50_ms,
            record_hash,
        })
    }

    /// Número de modelos registados.
    #[must_use]
    pub fn len(&self) -> usize {
        self.models.len()
    }

    /// Vazio?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.models.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model(id: &str, status: ModelStatus, cost: f64, latency: u64) -> RegisteredModel {
        RegisteredModel {
            id: id.into(),
            model_hash: format!("sha256:{id}"),
            status,
            capabilities: vec![Capability::TextGeneration, Capability::Reasoning],
            cost_per_1k: cost,
            latency_p50_ms: latency,
        }
    }

    fn req(capability: Capability) -> RoutingRequest {
        RoutingRequest {
            capability,
            max_cost: None,
            max_latency_ms: None,
            preference: Preference::Cost,
        }
    }

    #[test]
    fn inv_ai_06_selects_verified_only() {
        let mut r = Router::new();
        r.register(model("a", ModelStatus::Failed, 0.1, 10));
        r.register(model("b", ModelStatus::Verified, 0.5, 50));
        let d = r.route(&req(Capability::TextGeneration)).unwrap();
        assert_eq!(d.model_id, "b");
    }

    #[test]
    fn inv_ai_06_rejects_when_all_unverified() {
        let mut r = Router::new();
        r.register(model("a", ModelStatus::Failed, 0.1, 10));
        assert!(matches!(
            r.route(&req(Capability::TextGeneration)),
            Err(RoutingError::UnverifiedModel(_))
        ));
    }

    #[test]
    fn inv_ai_04_rejects_missing_capability() {
        let mut r = Router::new();
        r.register(model("a", ModelStatus::Verified, 0.1, 10));
        assert!(matches!(
            r.route(&req(Capability::Vision)),
            Err(RoutingError::MissingCapability(_))
        ));
    }

    #[test]
    fn inv_ai_05_routing_is_deterministic() {
        let mut r = Router::new();
        r.register(model("a", ModelStatus::Verified, 0.3, 30));
        r.register(model("b", ModelStatus::Verified, 0.2, 40));
        let request = req(Capability::TextGeneration);
        let d1 = r.route(&request).unwrap();
        let d2 = r.route(&request).unwrap();
        assert_eq!(d1.record_hash, d2.record_hash);
        assert_eq!(d1.model_id, d2.model_id);
    }

    #[test]
    fn cost_filter_works() {
        let mut r = Router::new();
        r.register(model("expensive", ModelStatus::Verified, 10.0, 10));
        let mut request = req(Capability::TextGeneration);
        request.max_cost = Some(1.0);
        assert!(matches!(r.route(&request), Err(RoutingError::NoModel(_))));
    }

    #[test]
    fn latency_filter_works() {
        let mut r = Router::new();
        r.register(model("slow", ModelStatus::Verified, 0.1, 500));
        let mut request = req(Capability::TextGeneration);
        request.max_latency_ms = Some(100);
        assert!(matches!(r.route(&request), Err(RoutingError::NoModel(_))));
    }
}
