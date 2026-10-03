#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! # arkhe-code-review-agents
//!
//! Agentes LLM especializados com fan-out resiliente a falhas **e panics**.
//!
//! ## Invariantes
//!
//! - `INV-CR-06`: Falha (ou panic) de um agente não bloqueia os outros

use std::collections::HashSet;
use std::sync::Arc;

use arkhe_code_review_context::ReviewContext;
use arkhe_code_review_diff::{Diff, LineKind};
use arkhe_code_review_static::{Evidence, Finding, FindingSource, Severity};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Erro de agente.
#[derive(Debug, Error)]
pub enum AgentError {
    /// Backend LLM indisponível.
    #[error("backend LLM indisponível: {0}")]
    Backend(String),
    /// Resposta inválida do modelo.
    #[error("resposta inválida do modelo {model}: {reason}")]
    InvalidResponse {
        /// Modelo.
        model: String,
        /// Razão.
        reason: String,
    },
}

/// Especialização de agente.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    /// Lógica e correção.
    Logic,
    /// Segurança.
    Security,
    /// Cobertura de testes.
    Coverage,
    /// Manutenibilidade.
    Maintainability,
    /// Histórico Git.
    History,
}

impl AgentKind {
    /// Nome legível.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Logic => "logic",
            Self::Security => "security",
            Self::Coverage => "coverage",
            Self::Maintainability => "maintainability",
            Self::History => "history",
        }
    }
}

/// Trait de agente de review.
#[async_trait]
pub trait ReviewAgent: Send + Sync + std::fmt::Debug {
    /// Executa o agente.
    ///
    /// # Errors
    ///
    /// Devolve [`AgentError`] se o backend falhar ou a resposta for inválida.
    async fn review(
        &self,
        diff: &Diff,
        context: &ReviewContext,
    ) -> Result<Vec<Finding>, AgentError>;

    /// Especialização.
    fn kind(&self) -> AgentKind;

    /// Modelo subjacente.
    fn model(&self) -> &str;
}

/// Resultado agregado de um fan-out.
#[derive(Debug, Clone)]
pub struct FanOutResult {
    /// Findings agregados.
    pub findings: Vec<Finding>,
    /// Erros por agente (não propagados — `INV-CR-06`).
    pub errors: Vec<(AgentKind, String)>,
    /// Panics capturados (não propagados — `INV-CR-06`).
    pub panics: Vec<(AgentKind, String)>,
    /// Modelos que produziram pelo menos um finding.
    pub models_used: HashSet<String>,
}

impl FanOutResult {
    /// Número total de agentes que falharam (erros + panics).
    #[must_use]
    pub fn failures(&self) -> usize {
        self.errors.len() + self.panics.len()
    }

    /// Indica se todos os agentes falharam.
    #[must_use]
    pub fn all_failed(&self) -> bool {
        self.findings.is_empty() && !self.errors.is_empty()
    }
}

/// Executa múltiplos agentes em paralelo, capturando falhas e panics.
///
/// Usa `tokio::spawn` para isolar panics (`JoinError::is_panic()`).
/// Uma falha (ou panic) em qualquer agente é capturada e não interrompe
/// os restantes (`INV-CR-06`).
pub async fn fan_out(
    agents: Vec<Arc<dyn ReviewAgent>>,
    diff: Arc<Diff>,
    context: Arc<ReviewContext>,
) -> FanOutResult {
    let mut handles = Vec::with_capacity(agents.len());

    for agent in agents {
        let diff = Arc::clone(&diff);
        let context = Arc::clone(&context);
        let kind = agent.kind();
        let model = agent.model().to_string();
        let handle = tokio::spawn(async move { agent.review(&diff, &context).await });
        handles.push((kind, model, handle));
    }

    let mut findings = Vec::new();
    let mut errors = Vec::new();
    let mut panics = Vec::new();
    let mut models_used = HashSet::new();

    for (kind, model, handle) in handles {
        match handle.await {
            Ok(Ok(mut fs)) => {
                if !fs.is_empty() {
                    models_used.insert(model);
                }
                findings.append(&mut fs);
            }
            Ok(Err(e)) => {
                tracing::warn!(kind = ?kind, error = %e, "agente falhou");
                errors.push((kind, e.to_string()));
            }
            Err(join_err) => {
                let msg = if join_err.is_panic() {
                    "panic capturado".to_string()
                } else {
                    "cancelled".to_string()
                };
                tracing::error!(kind = ?kind, panic = %msg, "agente panicou");
                panics.push((kind, msg));
            }
        }
    }

    FanOutResult {
        findings,
        errors,
        panics,
        models_used,
    }
}

/// Agente determinístico de demonstração (Logic).
#[derive(Debug, Clone)]
pub struct MockLogicAgent {
    model: String,
}

impl MockLogicAgent {
    /// Cria um agente.
    #[must_use]
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
        }
    }
}

#[async_trait]
impl ReviewAgent for MockLogicAgent {
    async fn review(
        &self,
        diff: &Diff,
        _context: &ReviewContext,
    ) -> Result<Vec<Finding>, AgentError> {
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
                    if !line.content.contains("== None") {
                        continue;
                    }
                    let Some(line_no) = line.new_line else {
                        continue;
                    };
                    findings.push(Finding {
                        id: format!("llm-logic-{}-{}", file.new_path, line_no),
                        rule: "logic-none-comparison".into(),
                        message: "Compare com `None` usando `is_none()`".into(),
                        severity: Severity::Info,
                        source: FindingSource::Llm,
                        evidence: Evidence {
                            file: file.new_path.clone(),
                            line: line_no,
                            snippet: line.content.clone(),
                        },
                        provenance: format!("llm:{}", self.model),
                        confidence: 0.7,
                    });
                }
            }
        }
        Ok(findings)
    }

    fn kind(&self) -> AgentKind {
        AgentKind::Logic
    }

    fn model(&self) -> &str {
        &self.model
    }
}

/// Agente determinístico de demonstração (Security).
#[derive(Debug, Clone)]
pub struct MockSecurityAgent {
    model: String,
}

impl MockSecurityAgent {
    /// Cria um agente.
    #[must_use]
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
        }
    }
}

#[async_trait]
impl ReviewAgent for MockSecurityAgent {
    async fn review(
        &self,
        diff: &Diff,
        _context: &ReviewContext,
    ) -> Result<Vec<Finding>, AgentError> {
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
                    if !line.content.contains("format!(\"SELECT") {
                        continue;
                    }
                    let Some(line_no) = line.new_line else {
                        continue;
                    };
                    findings.push(Finding {
                        id: format!("llm-sec-{}-{}", file.new_path, line_no),
                        rule: "sql-injection".into(),
                        message: "Possível SQL injection: use prepared statements".into(),
                        severity: Severity::Critical,
                        source: FindingSource::Llm,
                        evidence: Evidence {
                            file: file.new_path.clone(),
                            line: line_no,
                            snippet: line.content.clone(),
                        },
                        provenance: format!("llm:{}", self.model),
                        confidence: 0.85,
                    });
                }
            }
        }
        Ok(findings)
    }

    fn kind(&self) -> AgentKind {
        AgentKind::Security
    }

    fn model(&self) -> &str {
        &self.model
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIFF: &str = concat!(
        "diff --git a/x.rs b/x.rs\n",
        "--- a/x.rs\n",
        "+++ b/x.rs\n",
        "@@ -1,2 +1,3 @@\n",
        " fn f() {\n",
        "+    if x == None { panic!() }\n",
        " }\n",
    );

    const SEC_DIFF: &str = concat!(
        "diff --git a/x.rs b/x.rs\n",
        "--- a/x.rs\n",
        "+++ b/x.rs\n",
        "@@ -1,2 +1,3 @@\n",
        " fn f() {\n",
        "+    let q = format!(\"SELECT * FROM users WHERE id = {}\", id);\n",
        " }\n",
    );

    fn diff() -> Arc<Diff> {
        Arc::new(Diff::parse(DIFF).unwrap())
    }

    fn sec_diff() -> Arc<Diff> {
        Arc::new(Diff::parse(SEC_DIFF).unwrap())
    }

    #[tokio::test]
    async fn inv_cr_06_fan_out_collects_findings() {
        let ctx = Arc::new(ReviewContext::new());
        let agents: Vec<Arc<dyn ReviewAgent>> = vec![
            Arc::new(MockLogicAgent::new("claude-opus")),
            Arc::new(MockSecurityAgent::new("gpt-5")),
        ];
        let result = fan_out(agents, diff(), ctx).await;
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.errors.len(), 0);
        assert_eq!(result.panics.len(), 0);
        assert_eq!(result.models_used.len(), 1);
    }

    #[tokio::test]
    async fn inv_cr_06_agent_error_isolated() {
        #[derive(Debug)]
        struct FailingAgent;
        #[async_trait]
        impl ReviewAgent for FailingAgent {
            async fn review(
                &self,
                _: &Diff,
                _: &ReviewContext,
            ) -> Result<Vec<Finding>, AgentError> {
                Err(AgentError::Backend("timeout".into()))
            }
            fn kind(&self) -> AgentKind {
                AgentKind::Logic
            }
            fn model(&self) -> &str {
                "failing"
            }
        }

        let ctx = Arc::new(ReviewContext::new());
        let agents: Vec<Arc<dyn ReviewAgent>> = vec![
            Arc::new(FailingAgent),
            Arc::new(MockLogicAgent::new("claude")),
        ];
        let result = fan_out(agents, diff(), ctx).await;
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.panics.len(), 0);
    }

    #[tokio::test]
    async fn inv_cr_06_agent_panic_isolated() {
        #[derive(Debug)]
        struct PanickingAgent;
        #[async_trait]
        impl ReviewAgent for PanickingAgent {
            async fn review(
                &self,
                _: &Diff,
                _: &ReviewContext,
            ) -> Result<Vec<Finding>, AgentError> {
                panic!("simulated panic");
            }
            fn kind(&self) -> AgentKind {
                AgentKind::Security
            }
            fn model(&self) -> &str {
                "panicking"
            }
        }

        let ctx = Arc::new(ReviewContext::new());
        let agents: Vec<Arc<dyn ReviewAgent>> = vec![
            Arc::new(PanickingAgent),
            Arc::new(MockLogicAgent::new("claude")),
        ];
        let result = fan_out(agents, diff(), ctx).await;
        assert_eq!(result.panics.len(), 1);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.errors.len(), 0);
        assert_eq!(result.models_used.len(), 1);
    }

    #[tokio::test]
    async fn both_agents_produce_findings_on_relevant_diff() {
        let ctx = Arc::new(ReviewContext::new());
        // Diff com ambas as regras no mesmo ficheiro
        let combined = concat!(
            "diff --git a/x.rs b/x.rs\n",
            "--- a/x.rs\n",
            "+++ b/x.rs\n",
            "@@ -1,2 +1,4 @@\n",
            " fn f() {\n",
            "+    if x == None { return; }\n",
            "+    let q = format!(\"SELECT * FROM t\");\n",
            " }\n",
        );
        let d = Arc::new(Diff::parse(combined).unwrap());
        let agents: Vec<Arc<dyn ReviewAgent>> = vec![
            Arc::new(MockLogicAgent::new("claude")),
            Arc::new(MockSecurityAgent::new("gpt")),
        ];
        let result = fan_out(agents, d, ctx).await;
        assert_eq!(result.findings.len(), 2);
        assert_eq!(result.models_used.len(), 2);
    }

    #[tokio::test]
    async fn empty_findings_dont_count_as_models_used() {
        let ctx = Arc::new(ReviewContext::new());
        let empty = concat!(
            "diff --git a/x.rs b/x.rs\n",
            "--- a/x.rs\n",
            "+++ b/x.rs\n",
            "@@ -1,1 +1,1 @@\n",
            " unchanged\n",
        );
        let d = Arc::new(Diff::parse(empty).unwrap());
        let agents: Vec<Arc<dyn ReviewAgent>> = vec![
            Arc::new(MockLogicAgent::new("claude")),
            Arc::new(MockSecurityAgent::new("gpt")),
        ];
        let result = fan_out(agents, d, ctx).await;
        assert_eq!(result.findings.len(), 0);
        assert_eq!(result.models_used.len(), 0);
    }

    #[tokio::test]
    async fn security_agent_detects_sql_injection() {
        let ctx = Arc::new(ReviewContext::new());
        let agents: Vec<Arc<dyn ReviewAgent>> = vec![Arc::new(MockSecurityAgent::new("gpt"))];
        let result = fan_out(agents, sec_diff(), ctx).await;
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].rule, "sql-injection");
        assert_eq!(result.findings[0].severity, Severity::Critical);
        assert!(result.findings[0].validate().is_ok());
    }

    #[tokio::test]
    async fn agent_kind_name_is_stable() {
        assert_eq!(AgentKind::Logic.name(), "logic");
        assert_eq!(AgentKind::Security.name(), "security");
        assert_eq!(AgentKind::Coverage.name(), "coverage");
        assert_eq!(AgentKind::Maintainability.name(), "maintainability");
        assert_eq!(AgentKind::History.name(), "history");
    }

    #[tokio::test]
    async fn fan_out_with_empty_agents_returns_empty() {
        let ctx = Arc::new(ReviewContext::new());
        let agents: Vec<Arc<dyn ReviewAgent>> = vec![];
        let result = fan_out(agents, diff(), ctx).await;
        assert_eq!(result.findings.len(), 0);
        assert_eq!(result.errors.len(), 0);
        assert_eq!(result.panics.len(), 0);
        assert_eq!(result.models_used.len(), 0);
        assert!(!result.all_failed());
    }
}
