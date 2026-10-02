use thiserror::Error;

/// Erro da integração Gemma.
#[derive(Debug, Error)]
pub enum GemmaError {
    /// Modelo não verificado.
    #[error("modelo não verificado: {0}")]
    UnverifiedModel(String),

    /// Hash do modelo inválido.
    #[error("hash mismatch: esperado {expected}, obtido {actual}")]
    HashMismatch {
        /// Esperado.
        expected: String,
        /// Obtido.
        actual: String,
    },

    /// Orçamento excedido.
    #[error("orçamento excedido: necessário {required:.4}, disponível {available:.4}")]
    BudgetExceeded {
        /// Necessário.
        required: f64,
        /// Disponível.
        available: f64,
    },

    /// Erro do backend de inferência.
    #[error("backend: {0}")]
    Backend(String),

    /// Erro do agente.
    #[error("agente: {0}")]
    Agent(String),

    /// Erro de verificação de patch.
    #[error("patch inválido: {0}")]
    InvalidPatch(String),

    /// I/O.
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    /// Serialização.
    #[error("serialização: {0}")]
    Serialization(String),
}
