use serde::{Deserialize, Serialize};

/// Fonte do modelo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModelSource {
    /// Ficheiro local.
    Local {
        /// Caminho.
        path: String,
    },
    /// HuggingFace Hub.
    HuggingFace {
        /// Repositório.
        repo: String,
        /// Ficheiro.
        file: String,
    },
}

/// Configuração do agente Gemma.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GemmaConfig {
    /// Fonte do modelo.
    pub source: ModelSource,
    /// SHA-256 esperado.
    pub expected_sha256: String,
    /// Orçamento em USD.
    pub budget: f64,
    /// Máximo de tokens por inferência.
    pub max_tokens: usize,
    /// Trust anchor.
    pub trust_anchor: Option<String>,
}

impl Default for GemmaConfig {
    fn default() -> Self {
        Self {
            source: ModelSource::HuggingFace {
                repo: "google/gemma-4-31B-it-qat-w4a16-ct".into(),
                file: "model.safetensors".into(),
            },
            expected_sha256: String::new(),
            budget: 100.0,
            max_tokens: 4096,
            trust_anchor: Some("did:arkhe:gemma-agent".into()),
        }
    }
}
