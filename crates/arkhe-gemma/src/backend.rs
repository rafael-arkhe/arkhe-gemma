use serde::{Deserialize, Serialize};

use crate::error::GemmaError;

/// Pedido de inferência.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceRequest {
    /// Prompt do utilizador.
    pub prompt: String,
    /// Contexto do repositório.
    pub repo_context: Option<String>,
    /// Ficheiro alvo.
    pub target_file: Option<String>,
    /// Máximo de tokens a gerar.
    pub max_tokens: usize,
}

/// Resposta de inferência.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceResponse {
    /// Output gerado.
    pub output: String,
    /// Tokens de entrada.
    pub input_tokens: usize,
    /// Tokens de saída.
    pub output_tokens: usize,
    /// `record_hash` da inferência.
    pub record_hash: [u8; 32],
}

/// Backend de inferência para o Gemma 4.
#[async_trait::async_trait]
pub trait GemmaBackend: Send + Sync + std::fmt::Debug {
    /// Executa inferência.
    ///
    /// # Errors
    ///
    /// Devolve [`GemmaError::Backend`] se a inferência falhar.
    async fn infer(&self, request: &InferenceRequest) -> Result<InferenceResponse, GemmaError>;

    /// Nome do backend.
    fn name(&self) -> &str;

    /// Verifica se o backend está disponível.
    async fn health_check(&self) -> bool;
}

/// Backend determinístico para testes.
#[derive(Debug, Default)]
pub struct EchoGemmaBackend;

#[async_trait::async_trait]
impl GemmaBackend for EchoGemmaBackend {
    async fn infer(&self, request: &InferenceRequest) -> Result<InferenceResponse, GemmaError> {
        let output = format!("echo: {}", request.prompt);
        let input_tokens = (request.prompt.chars().count() / 4).max(1);
        let output_tokens = (output.chars().count() / 4).max(1);

        let mut h = blake3::Hasher::new_derive_key("arkhe-gemma-inference-v1");
        h.update(request.prompt.as_bytes());
        h.update(output.as_bytes());
        let record_hash = *h.finalize().as_bytes();

        Ok(InferenceResponse {
            output,
            input_tokens,
            output_tokens,
            record_hash,
        })
    }

    fn name(&self) -> &str {
        "echo-gemma"
    }

    async fn health_check(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn echo_backend_produces_record_hash() {
        let backend = EchoGemmaBackend;
        let request = InferenceRequest {
            prompt: "fix the bug".into(),
            repo_context: None,
            target_file: None,
            max_tokens: 100,
        };
        let response = backend.infer(&request).await.unwrap();
        assert!(response.output.starts_with("echo:"));
        assert_ne!(response.record_hash, [0u8; 32]);
    }

    #[tokio::test]
    async fn health_check_passes() {
        let backend = EchoGemmaBackend;
        assert!(backend.health_check().await);
    }
}
