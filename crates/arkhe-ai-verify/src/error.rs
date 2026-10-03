#![deny(missing_docs)]
#![deny(unsafe_code)]

//! Erros de verificação.

use thiserror::Error;

/// Erro de verificação.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// Formato não suportado.
    #[error("formato não suportado: {0}")]
    UnsupportedFormat(String),
    /// Limite excedido.
    #[error("artefato excede limite: {field} = {value} > {max}")]
    LimitExceeded {
        /// Campo.
        field: String,
        /// Valor observado.
        value: u64,
        /// Limite máximo.
        max: u64,
    },
    /// Hash mismatch.
    #[error("hash mismatch: esperado {expected}, obtido {actual}")]
    HashMismatch {
        /// Esperado.
        expected: String,
        /// Obtido.
        actual: String,
    },
    /// Validação de segurança falhou.
    #[error("segurança: {0}")]
    Security(String),
    /// I/O.
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    /// Parse.
    #[error("parse: {0}")]
    Parse(String),
}
