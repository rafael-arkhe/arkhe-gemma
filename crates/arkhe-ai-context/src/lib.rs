#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! # arkhe-ai-context
//!
//! Gestão de contexto verificável.
//!
//! ## Invariantes
//!
//! - `INV-AI-01`: Todo contexto tem `record_hash` verificável
//! - `INV-AI-02`: Contexto vazio é rejeitado (fail-closed)
//! - `INV-AI-03`: Contexto excedendo limite é truncado, nunca silenciado

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Erro de contexto.
#[derive(Debug, Error)]
pub enum ContextError {
    /// Contexto vazio.
    #[error("contexto vazio")]
    Empty,
    /// Contexto excede o limite.
    #[error("contexto excede limite: {actual} > {max}")]
    Overflow {
        /// Tamanho actual.
        actual: usize,
        /// Limite máximo.
        max: usize,
    },
    /// Segmento com proveniência ausente.
    #[error("segmento sem proveniência: {0}")]
    MissingProvenance(String),
}

/// Segmento de contexto.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextSegment {
    /// Papel (`system`, `user`, `assistant`, `tool`).
    pub role: String,
    /// Conteúdo.
    pub content: String,
    /// Proveniência (`did:arkhe:...` ou `none`).
    pub provenance: String,
    /// Número estimado de tokens.
    pub tokens: usize,
}

impl ContextSegment {
    /// Cria um segmento.
    #[must_use]
    pub fn new(
        role: impl Into<String>,
        content: impl Into<String>,
        provenance: impl Into<String>,
    ) -> Self {
        let content = content.into();
        let tokens = estimate_tokens(&content);
        Self {
            role: role.into(),
            content,
            provenance: provenance.into(),
            tokens,
        }
    }
}

/// Contexto de inferência.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Context {
    /// Segmentos.
    pub segments: Vec<ContextSegment>,
    /// Limite de tokens.
    pub max_tokens: usize,
    /// `record_hash` do contexto.
    pub record_hash: [u8; 32],
}

impl Context {
    /// Cria um contexto.
    ///
    /// # Errors
    ///
    /// - Vazio → [`ContextError::Empty`]
    /// - Sem proveniência → [`ContextError::MissingProvenance`]
    pub fn new(segments: Vec<ContextSegment>, max_tokens: usize) -> Result<Self, ContextError> {
        if segments.is_empty() {
            return Err(ContextError::Empty);
        }
        for s in &segments {
            if s.provenance.is_empty() {
                return Err(ContextError::MissingProvenance(s.role.clone()));
            }
        }
        let mut ctx = Self {
            segments,
            max_tokens,
            record_hash: [0u8; 32],
        };
        ctx.record_hash = ctx.compute_hash();
        Ok(ctx)
    }

    /// Total de tokens.
    #[must_use]
    pub fn total_tokens(&self) -> usize {
        self.segments.iter().map(|s| s.tokens).sum()
    }

    /// Trunca ao limite, mantendo `system` intacto (`INV-AI-03`).
    pub fn truncate_to_limit(&mut self) {
        let mut system: Vec<_> = self
            .segments
            .iter()
            .filter(|s| s.role == "system")
            .cloned()
            .collect();
        let mut others: Vec<_> = self
            .segments
            .iter()
            .filter(|s| s.role != "system")
            .cloned()
            .collect();

        let mut total: usize = system.iter().map(|s| s.tokens).sum();
        while let Some(seg) = others.pop() {
            if total + seg.tokens <= self.max_tokens {
                total += seg.tokens;
                system.push(seg);
            }
        }
        self.segments = system;
        self.record_hash = self.compute_hash();
    }

    /// Computa o `record_hash` (`INV-AI-01`).
    #[must_use]
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key("arkhe-ai-context-v1");
        for s in &self.segments {
            put_str(&mut h, &s.role);
            put_str(&mut h, &s.content);
            put_str(&mut h, &s.provenance);
            h.update(&(s.tokens as u64).to_le_bytes());
        }
        h.update(&(self.max_tokens as u64).to_le_bytes());
        *h.finalize().as_bytes()
    }

    /// Hash em hex.
    #[must_use]
    pub fn record_hash_hex(&self) -> String {
        hex::encode(self.record_hash)
    }
}

fn put_str(h: &mut blake3::Hasher, s: &str) {
    h.update(&(s.len() as u64).to_le_bytes());
    h.update(s.as_bytes());
}

/// Estimador de tokens (~4 chars/token).
#[must_use]
pub fn estimate_tokens(s: &str) -> usize {
    (s.chars().count() / 4).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_rejected() {
        assert!(matches!(
            Context::new(vec![], 100),
            Err(ContextError::Empty)
        ));
    }

    #[test]
    fn missing_provenance_rejected() {
        let seg = ContextSegment::new("user", "hello", "");
        assert!(matches!(
            Context::new(vec![seg], 100),
            Err(ContextError::MissingProvenance(_))
        ));
    }

    #[test]
    fn record_hash_deterministic() {
        let seg = ContextSegment::new("user", "hello", "did:arkhe:test");
        let c1 = Context::new(vec![seg.clone()], 100).unwrap();
        let c2 = Context::new(vec![seg], 100).unwrap();
        assert_eq!(c1.record_hash, c2.record_hash);
        assert_ne!(c1.record_hash, [0u8; 32]);
    }

    #[test]
    fn truncate_preserves_system() {
        let system = ContextSegment::new("system", "You are Arkhe.", "did:arkhe:sys");
        let user = ContextSegment::new("user", "hello world", "did:arkhe:user");
        let mut ctx = Context::new(vec![system, user], 5).unwrap();
        ctx.truncate_to_limit();
        assert!(ctx.segments.iter().any(|s| s.role == "system"));
    }
}
