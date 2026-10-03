#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! # arkhe-code-review-static
//!
//! Análise estática determinística. Findings desta camada têm precedência
//! sobre LLM findings em conflito (`INV-CR-08`).
//!
//! ## Invariantes
//!
//! - `INV-CR-03`: Finding sem evidência é rejeitado (fail-closed)
//! - `INV-CR-04`: `dedup_key` combina `(file, line, hash(rule))`
//! - `INV-CR-07`: Finding sem proveniência é rejeitado
//! - `INV-CR-09`: Finding tem evidência groundada (ficheiro + linha + snippet)

use arkhe_code_review_diff::{Diff, LineKind};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Severidade de um finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informativo.
    Info,
    /// Aviso.
    Warning,
    /// Erro.
    Error,
    /// Crítico.
    Critical,
}

/// Fonte de um finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSource {
    /// Análise estática.
    Static,
    /// Agente LLM.
    Llm,
}

/// Evidência verificável de um finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Ficheiro.
    pub file: String,
    /// Linha (1-indexed no ficheiro novo).
    pub line: usize,
    /// Fragmento de código.
    pub snippet: String,
}

/// Finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// ID único.
    pub id: String,
    /// Regra ou categoria.
    pub rule: String,
    /// Mensagem.
    pub message: String,
    /// Severidade.
    pub severity: Severity,
    /// Fonte.
    pub source: FindingSource,
    /// Evidência (`INV-CR-09`).
    pub evidence: Evidence,
    /// Proveniência (`INV-CR-07`).
    pub provenance: String,
    /// Confiança (0.0..=1.0).
    pub confidence: f64,
}

impl Finding {
    /// Valida as invariantes estruturais.
    ///
    /// # Errors
    ///
    /// - [`StaticError::EmptyEvidence`] se `evidence.snippet` for vazio (`INV-CR-03`)
    /// - [`StaticError::EmptyProvenance`] se `provenance` for vazio (`INV-CR-07`)
    /// - [`StaticError::EmptyField`] para outros campos vazios
    /// - [`StaticError::InvalidConfidence`] se `confidence ∉ [0, 1]`
    pub fn validate(&self) -> Result<(), StaticError> {
        if self.id.is_empty() {
            return Err(StaticError::EmptyField("id".into()));
        }
        if self.rule.is_empty() {
            return Err(StaticError::EmptyField("rule".into()));
        }
        if self.provenance.is_empty() {
            return Err(StaticError::EmptyProvenance(self.id.clone()));
        }
        if self.evidence.file.is_empty() {
            return Err(StaticError::EmptyField("evidence.file".into()));
        }
        if self.evidence.line == 0 {
            return Err(StaticError::EmptyField("evidence.line == 0".into()));
        }
        if self.evidence.snippet.is_empty() {
            return Err(StaticError::EmptyEvidence(self.id.clone()));
        }
        if !(0.0..=1.0).contains(&self.confidence) {
            return Err(StaticError::InvalidConfidence(self.confidence));
        }
        Ok(())
    }

    /// Chave de deduplicação (`INV-CR-04`).
    ///
    /// Combina `(file, line, hash(rule))` num digest de 8 bytes.
    #[must_use]
    pub fn dedup_key(&self) -> String {
        let rule_hash = blake3::hash(self.rule.as_bytes());
        let mut h = blake3::Hasher::new_derive_key("arkhe-cr-dedup-v1");
        h.update(self.evidence.file.as_bytes());
        h.update(&(self.evidence.line as u64).to_le_bytes());
        h.update(rule_hash.as_bytes());
        let digest = h.finalize();
        hex::encode(&digest.as_bytes()[..8])
    }
}

/// Erro da análise estática.
#[derive(Debug, Error)]
pub enum StaticError {
    /// Evidência vazia.
    #[error("finding {0} sem evidência")]
    EmptyEvidence(String),
    /// Proveniência vazia.
    #[error("finding {0} sem proveniência")]
    EmptyProvenance(String),
    /// Campo vazio.
    #[error("campo obrigatório vazio: {0}")]
    EmptyField(String),
    /// Confiança inválida.
    #[error("confidence inválida: {0}")]
    InvalidConfidence(f64),
}

/// Trait de analisador estático.
#[async_trait::async_trait]
pub trait StaticAnalyzer: Send + Sync + std::fmt::Debug {
    /// Executa a análise sobre o diff.
    async fn analyze(&self, diff: &Diff) -> Vec<Finding>;
    /// Nome do analisador.
    fn name(&self) -> &str;
}

/// Analisador que detecta `.unwrap()` em linhas adicionadas de Rust.
#[derive(Debug, Default)]
pub struct NoUnwrapAnalyzer;

#[async_trait::async_trait]
impl StaticAnalyzer for NoUnwrapAnalyzer {
    async fn analyze(&self, diff: &Diff) -> Vec<Finding> {
        let mut findings = Vec::new();
        for file in &diff.files {
            if !file.new_path.ends_with(".rs") {
                continue;
            }
            for hunk in &file.hunks {
                for line in &hunk.lines {
                    if line.kind != LineKind::Added {
                        continue;
                    }
                    if !line.content.contains(".unwrap()") {
                        continue;
                    }
                    let Some(line_no) = line.new_line else {
                        continue;
                    };
                    findings.push(Finding {
                        id: format!("static-unwrap-{}-{}", file.new_path, line_no),
                        rule: "no-unwrap".into(),
                        message:
                            "`.unwrap()` pode panicar; considere `?` ou `expect()` com contexto"
                                .into(),
                        severity: Severity::Warning,
                        source: FindingSource::Static,
                        evidence: Evidence {
                            file: file.new_path.clone(),
                            line: line_no,
                            snippet: line.content.clone(),
                        },
                        provenance: "static:no-unwrap".into(),
                        confidence: 0.99,
                    });
                }
            }
        }
        findings
    }

    fn name(&self) -> &str {
        "no-unwrap"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diff_with_unwrap() -> Diff {
        let input = "\
diff --git a/x.rs b/x.rs
--- a/x.rs
+++ b/x.rs
@@ -1,2 +1,3 @@
 fn f() {
+    let x = g().unwrap();
 }
";
        Diff::parse(input).unwrap()
    }

    fn diff_without_unwrap() -> Diff {
        let input = "\
diff --git a/x.rs b/x.rs
--- a/x.rs
+++ b/x.rs
@@ -1,2 +1,3 @@
 fn f() {
+    let x = g()?;
 }
";
        Diff::parse(input).unwrap()
    }

    fn valid_finding() -> Finding {
        Finding {
            id: "f1".into(),
            rule: "no-unwrap".into(),
            message: "test".into(),
            severity: Severity::Warning,
            source: FindingSource::Static,
            evidence: Evidence {
                file: "x.rs".into(),
                line: 2,
                snippet: "    let x = g().unwrap();".into(),
            },
            provenance: "static:no-unwrap".into(),
            confidence: 0.99,
        }
    }

    #[tokio::test]
    async fn detects_unwrap_in_added_line() {
        let diff = diff_with_unwrap();
        let findings = NoUnwrapAnalyzer.analyze(&diff).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "no-unwrap");
        assert_eq!(findings[0].evidence.file, "x.rs");
        assert_eq!(findings[0].evidence.line, 2);
        assert!(findings[0].evidence.snippet.contains(".unwrap()"));
        assert!(findings[0].validate().is_ok());
    }

    #[tokio::test]
    async fn does_not_flag_question_mark() {
        let diff = diff_without_unwrap();
        let findings = NoUnwrapAnalyzer.analyze(&diff).await;
        assert_eq!(findings.len(), 0);
    }

    #[tokio::test]
    async fn ignores_non_rust_files() {
        let input = "\
diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,1 +1,2 @@
 def f():
+    x = g().unwrap()
";
        let diff = Diff::parse(input).unwrap();
        let findings = NoUnwrapAnalyzer.analyze(&diff).await;
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn inv_cr_03_rejects_empty_evidence() {
        let mut f = valid_finding();
        f.evidence.snippet = String::new();
        assert!(matches!(f.validate(), Err(StaticError::EmptyEvidence(_))));
    }

    #[test]
    fn inv_cr_03_rejects_zero_line() {
        let mut f = valid_finding();
        f.evidence.line = 0;
        assert!(matches!(f.validate(), Err(StaticError::EmptyField(_))));
    }

    #[test]
    fn inv_cr_07_rejects_empty_provenance() {
        let mut f = valid_finding();
        f.provenance = String::new();
        assert!(matches!(f.validate(), Err(StaticError::EmptyProvenance(_))));
    }

    #[test]
    fn rejects_invalid_confidence() {
        let mut f = valid_finding();
        f.confidence = 1.5;
        assert!(matches!(
            f.validate(),
            Err(StaticError::InvalidConfidence(_))
        ));
    }

    #[test]
    fn inv_cr_04_dedup_key_is_stable() {
        let f = valid_finding();
        assert_eq!(f.dedup_key(), f.dedup_key());
    }

    #[test]
    fn dedup_key_varies_with_line() {
        let mut f1 = valid_finding();
        let mut f2 = valid_finding();
        f1.evidence.line = 2;
        f2.evidence.line = 3;
        assert_ne!(f1.dedup_key(), f2.dedup_key());
    }

    #[test]
    fn dedup_key_varies_with_rule() {
        let mut f1 = valid_finding();
        let mut f2 = valid_finding();
        f1.rule = "rule-a".into();
        f2.rule = "rule-b".into();
        assert_ne!(f1.dedup_key(), f2.dedup_key());
    }

    #[test]
    fn dedup_key_varies_with_file() {
        let mut f1 = valid_finding();
        let mut f2 = valid_finding();
        f1.evidence.file = "a.rs".into();
        f2.evidence.file = "b.rs".into();
        assert_ne!(f1.dedup_key(), f2.dedup_key());
    }

    #[test]
    fn dedup_key_ignores_snippet() {
        let mut f1 = valid_finding();
        let mut f2 = valid_finding();
        f1.evidence.snippet = "one".into();
        f2.evidence.snippet = "two".into();
        assert_eq!(f1.dedup_key(), f2.dedup_key());
    }

    #[test]
    fn severity_ordering_is_total() {
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Error);
        assert!(Severity::Error < Severity::Critical);
    }
}
