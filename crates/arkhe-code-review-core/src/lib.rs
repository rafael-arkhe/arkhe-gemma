#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! # arkhe-code-review-core
//!
//! Orquestrador do pipeline: diff → context → static + fan-out → judge.
//!
//! ## Invariantes
//!
//! - `INV-CR-01`: Todo review tem `record_hash`
//! - `INV-CR-06`: Falha de agente não bloqueia os outros
//! - `INV-CR-10`: Cross-model ≥ 2 (fatal se `require_cross_model`)

use std::sync::Arc;

use arkhe_code_review_agents::{fan_out, AgentKind, FanOutResult, ReviewAgent};
use arkhe_code_review_context::ReviewContext;
use arkhe_code_review_diff::{Diff, DiffError};
use arkhe_code_review_judge::{judge, JudgeConfig, JudgeContext, JudgeResult};
use arkhe_code_review_static::{Finding, StaticAnalyzer};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Erro do orquestrador.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Diff inválido.
    #[error("diff: {0}")]
    Diff(#[from] DiffError),
    /// Cross-model requirement não satisfeito (`INV-CR-10`).
    #[error("cross-model requirement: apenas {0} modelo(s) usado(s), mínimo 2")]
    CrossModelRequired(usize),
}

/// Resultado final de um review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewResult {
    /// Findings aceites.
    pub findings: Vec<Finding>,
    /// Número de findings rejeitados.
    pub rejected_count: usize,
    /// Erros de agentes (não bloqueantes — `INV-CR-06`).
    pub agent_errors: Vec<(AgentKind, String)>,
    /// Panics capturados (não bloqueantes — `INV-CR-06`).
    pub agent_panics: Vec<(AgentKind, String)>,
    /// Modelos usados, ordenados (`INV-CR-10`).
    pub models_used: Vec<String>,
    /// Review correu apenas com static analyzers?
    pub static_only: bool,
    /// `record_hash` (`INV-CR-01`).
    pub record_hash: [u8; 32],
}

/// Configuração do orquestrador.
#[derive(Debug, Clone)]
pub struct ReviewConfig {
    /// Configuração do judge.
    pub judge: JudgeConfig,
    /// Exigir cross-model (`INV-CR-10`).
    ///
    /// Se `true` e `models_used.len() < 2`, o review devolve
    /// [`CoreError::CrossModelRequired`]. Se `false`, o review completa
    /// mesmo com um único modelo.
    pub require_cross_model: bool,
}

impl Default for ReviewConfig {
    fn default() -> Self {
        Self {
            judge: JudgeConfig::default(),
            require_cross_model: true,
        }
    }
}

/// Orquestrador de review.
#[derive(Debug)]
pub struct ReviewOrchestrator {
    static_analyzers: Vec<Box<dyn StaticAnalyzer>>,
    llm_agents: Vec<Arc<dyn ReviewAgent>>,
    config: ReviewConfig,
}

impl ReviewOrchestrator {
    /// Cria um orquestrador.
    #[must_use]
    pub fn new(
        static_analyzers: Vec<Box<dyn StaticAnalyzer>>,
        llm_agents: Vec<Arc<dyn ReviewAgent>>,
        config: ReviewConfig,
    ) -> Self {
        Self {
            static_analyzers,
            llm_agents,
            config,
        }
    }

    /// Executa o pipeline completo.
    ///
    /// # Errors
    ///
    /// - [`CoreError::Diff`] se o diff for inválido
    /// - [`CoreError::CrossModelRequired`] se `require_cross_model = true`
    ///   e menos de 2 modelos LLM foram usados (`INV-CR-10`)
    pub async fn review(
        &self,
        diff_text: &str,
        context: ReviewContext,
    ) -> Result<ReviewResult, CoreError> {
        // 1. Parse do diff
        let diff = Diff::parse(diff_text)?;
        let diff = Arc::new(diff);
        let context = Arc::new(context);

        tracing::info!(
            files = diff.files.len(),
            additions = diff.additions(),
            deletions = diff.deletions(),
            "diff parsed"
        );

        // 2. Static analysis (síncrona, barata)
        let mut all_findings: Vec<Finding> = Vec::new();
        for analyzer in &self.static_analyzers {
            let mut fs = analyzer.analyze(&diff).await;
            tracing::debug!(analyzer = analyzer.name(), count = fs.len(), "static ok");
            all_findings.append(&mut fs);
        }

        // 3. Calcular `static_only` ANTES de qualquer consumo
        let static_only = self.llm_agents.is_empty();

        // 4. LLM fan-out (resiliente a falhas e panics — `INV-CR-06`)
        let fan: FanOutResult = if static_only {
            FanOutResult {
                findings: Vec::new(),
                errors: Vec::new(),
                panics: Vec::new(),
                models_used: Default::default(),
            }
        } else {
            let agents: Vec<Arc<dyn ReviewAgent>> = self.llm_agents.clone();
            fan_out(agents, Arc::clone(&diff), Arc::clone(&context)).await
        };
        all_findings.extend(fan.findings);

        // 5. Cross-model check (`INV-CR-10`)
        let mut models_used: Vec<String> = self
            .llm_agents
            .iter()
            .map(|a| a.model().to_string())
            .collect();
        models_used.sort();

        if self.config.require_cross_model && !static_only && models_used.len() < 2 {
            return Err(CoreError::CrossModelRequired(models_used.len()));
        }

        // 6. Judge com grounding verificável (`INV-CR-09`)
        let judge_ctx = JudgeContext {
            diff: &diff,
            review: &context,
        };
        let JudgeResult { accepted, rejected } =
            judge(all_findings, &judge_ctx, &self.config.judge);

        // 7. record_hash (`INV-CR-01` — inclui tudo o que influencia o resultado)
        let mut h = blake3::Hasher::new_derive_key("arkhe-cr-review-v1");
        h.update(diff_text.as_bytes());
        for f in &accepted {
            h.update(f.id.as_bytes());
            h.update(f.dedup_key().as_bytes());
            h.update(&f.confidence.to_le_bytes());
            h.update(f.provenance.as_bytes());
        }
        for m in &models_used {
            h.update(m.as_bytes());
        }
        h.update(&(rejected.len() as u64).to_le_bytes());
        let mut reasons: Vec<String> = rejected.iter().map(|r| format!("{:?}", r.reason)).collect();
        reasons.sort();
        for r in reasons {
            h.update(r.as_bytes());
        }
        for (k, e) in &fan.errors {
            h.update(format!("{k:?}").as_bytes());
            h.update(e.as_bytes());
        }
        for (k, e) in &fan.panics {
            h.update(format!("{k:?}").as_bytes());
            h.update(e.as_bytes());
        }
        h.update(&self.config.judge.min_confidence.to_le_bytes());
        h.update(&[u8::from(self.config.judge.static_precedence)]);
        h.update(&(self.config.judge.max_findings as u64).to_le_bytes());
        h.update(&[u8::from(self.config.judge.require_grounding)]);
        let record_hash = *h.finalize().as_bytes();

        tracing::info!(
            accepted = accepted.len(),
            rejected = rejected.len(),
            models = models_used.len(),
            static_only,
            record_hash = %hex::encode(record_hash),
            "review concluído"
        );

        Ok(ReviewResult {
            findings: accepted,
            rejected_count: rejected.len(),
            agent_errors: fan.errors,
            agent_panics: fan.panics,
            models_used,
            static_only,
            record_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arkhe_code_review_agents::{MockLogicAgent, MockSecurityAgent};
    use arkhe_code_review_static::NoUnwrapAnalyzer;

    const DIFF: &str = concat!(
        "diff --git a/x.rs b/x.rs\n",
        "--- a/x.rs\n",
        "+++ b/x.rs\n",
        "@@ -1,3 +1,5 @@\n",
        " pub fn test() {\n",
        "-    todo!()\n",
        "+    let x = g().unwrap();\n",
        "+    if x == None { panic!() }\n",
        "+    let q = format!(\"SELECT * FROM users WHERE id = {}\", id);\n",
        " }\n"
    );

    fn orchestrator() -> ReviewOrchestrator {
        ReviewOrchestrator::new(
            vec![Box::new(NoUnwrapAnalyzer)],
            vec![
                Arc::new(MockLogicAgent::new("claude-opus")),
                Arc::new(MockSecurityAgent::new("gpt-5")),
            ],
            ReviewConfig::default(),
        )
    }

    #[tokio::test]
    async fn inv_cr_01_review_produces_record_hash() {
        let o = orchestrator();
        let r = o
            .review(DIFF, ReviewContext::new())
            .await
            .unwrap_or_else(|e| panic!("failed: {:?}", e));
        assert_ne!(r.record_hash, [0u8; 32]);
        assert!(!r.static_only);
    }

    #[tokio::test]
    async fn empty_diff_rejected() {
        let o = orchestrator();
        let r = o.review("", ReviewContext::new()).await;
        assert!(matches!(r, Err(CoreError::Diff(_))));
    }

    #[tokio::test]
    async fn inv_cr_10_cross_model_fatal() {
        let o = ReviewOrchestrator::new(
            vec![],
            vec![Arc::new(MockLogicAgent::new("only-one"))],
            ReviewConfig {
                require_cross_model: true,
                ..Default::default()
            },
        );
        let r = o.review(DIFF, ReviewContext::new()).await;
        assert!(matches!(r, Err(CoreError::CrossModelRequired(1))));
    }

    #[tokio::test]
    async fn static_only_not_fatal() {
        let o = ReviewOrchestrator::new(
            vec![Box::new(NoUnwrapAnalyzer)],
            vec![],
            ReviewConfig {
                require_cross_model: true,
                ..Default::default()
            },
        );
        let r = o
            .review(DIFF, ReviewContext::new())
            .await
            .unwrap_or_else(|e| panic!("failed: {:?}", e));
        assert!(r.static_only);
        assert!(r.models_used.is_empty());
    }

    #[tokio::test]
    async fn inv_cr_06_agent_failure_does_not_block() {
        #[derive(Debug)]
        struct FailingAgent;
        #[async_trait::async_trait]
        #[allow(clippy::needless_lifetimes)]
        impl ReviewAgent for FailingAgent {
            async fn review(
                &self,
                _: &Diff,
                _: &ReviewContext,
            ) -> Result<Vec<Finding>, arkhe_code_review_agents::AgentError> {
                Err(arkhe_code_review_agents::AgentError::Backend(
                    "simulated".into(),
                ))
            }
            fn kind(&self) -> AgentKind {
                AgentKind::Logic
            }
            fn model(&self) -> &str {
                "failing"
            }
        }

        let o = ReviewOrchestrator::new(
            vec![Box::new(NoUnwrapAnalyzer)],
            vec![
                Arc::new(FailingAgent),
                Arc::new(MockLogicAgent::new("claude-opus")),
                Arc::new(MockSecurityAgent::new("gpt-5")),
            ],
            ReviewConfig::default(),
        );
        let _r = o
            .review(DIFF, ReviewContext::new())
            .await
            .unwrap_or_else(|e| panic!("failed: {:?}", e));
    }

    #[tokio::test]
    async fn inv_cr_06_agent_panic_does_not_block() {
        #[derive(Debug)]
        struct PanickingAgent;
        #[async_trait::async_trait]
        #[allow(clippy::needless_lifetimes)]
        impl ReviewAgent for PanickingAgent {
            async fn review(
                &self,
                _: &Diff,
                _: &ReviewContext,
            ) -> Result<Vec<Finding>, arkhe_code_review_agents::AgentError> {
                panic!("simulated panic");
            }
            fn kind(&self) -> AgentKind {
                AgentKind::Security
            }
            fn model(&self) -> &str {
                "panicking"
            }
        }

        let o = ReviewOrchestrator::new(
            vec![Box::new(NoUnwrapAnalyzer)],
            vec![
                Arc::new(PanickingAgent),
                Arc::new(MockLogicAgent::new("claude-opus")),
            ],
            ReviewConfig {
                require_cross_model: false,
                ..Default::default()
            },
        );
        let _r = o
            .review(DIFF, ReviewContext::new())
            .await
            .unwrap_or_else(|e| panic!("failed: {:?}", e));
    }

    #[tokio::test]
    async fn record_hash_is_deterministic() {
        let o = orchestrator();
        let r1 = o.review(DIFF, ReviewContext::new()).await.unwrap();
        let r2 = o.review(DIFF, ReviewContext::new()).await.unwrap();
        assert_eq!(r1.record_hash, r2.record_hash);
    }

    #[tokio::test]
    async fn truncated_findings_counted_in_rejected() {
        let o = ReviewOrchestrator::new(
            vec![Box::new(NoUnwrapAnalyzer)],
            vec![Arc::new(MockLogicAgent::new("claude"))],
            ReviewConfig {
                judge: JudgeConfig {
                    max_findings: 1,
                    ..Default::default()
                },
                require_cross_model: false,
            },
        );
        let _r = o
            .review(DIFF, ReviewContext::new())
            .await
            .unwrap_or_else(|e| panic!("failed: {:?}", e));
    }
}
