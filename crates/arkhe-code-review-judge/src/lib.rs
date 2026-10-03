#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! # arkhe-code-review-judge
//!
//! Judge layer: deduplicação, **grounding verificável**, filtro de confiança,
//! ranking por severidade e precedência static > LLM.
//!
//! ## Invariantes
//!
//! - `INV-CR-04`: Deduplica por `(file, line, hash(rule))`
//! - `INV-CR-05`: Findings com `confidence < threshold` são filtrados
//! - `INV-CR-08`: Static findings têm precedência sobre LLM em conflito
//! - `INV-CR-09`: Todo finding é groundado em evidência verificável

use std::collections::HashMap;

use arkhe_code_review_context::ReviewContext;
use arkhe_code_review_diff::Diff;
use arkhe_code_review_static::{Finding, FindingSource};

/// Configuração do judge.
#[derive(Debug, Clone)]
pub struct JudgeConfig {
    /// Confiança mínima para aceitar um finding.
    pub min_confidence: f64,
    /// Precedência de static sobre LLM em conflito (`INV-CR-08`).
    pub static_precedence: bool,
    /// Máximo de findings emitidos.
    pub max_findings: usize,
    /// Exigir grounding verificável (`INV-CR-09`).
    pub require_grounding: bool,
}

impl Default for JudgeConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.5,
            static_precedence: true,
            max_findings: 50,
            require_grounding: true,
        }
    }
}

/// Contexto de verificação para o judge.
#[derive(Debug)]
pub struct JudgeContext<'a> {
    /// Diff em análise.
    pub diff: &'a Diff,
    /// Contexto de ficheiros carregados.
    pub review: &'a ReviewContext,
}

/// Resultado do judge.
#[derive(Debug, Clone)]
pub struct JudgeResult {
    /// Findings aceites, ordenados por severidade e confiança.
    pub accepted: Vec<Finding>,
    /// Findings rejeitados com razão.
    pub rejected: Vec<RejectedFinding>,
}

/// Finding rejeitado.
#[derive(Debug, Clone)]
pub struct RejectedFinding {
    /// Finding.
    pub finding: Finding,
    /// Razão.
    pub reason: RejectReason,
}

/// Razão de rejeição.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// Falha estrutural (`INV-CR-03`, `INV-CR-07`).
    Invalid,
    /// Falha de grounding (`INV-CR-09`).
    NotGrounded,
    /// Confiança abaixo do threshold (`INV-CR-05`).
    LowConfidence,
    /// Duplicado (`INV-CR-04`).
    Duplicate,
    /// Perdeu precedência para static (`INV-CR-08`).
    SupersededByStatic,
    /// Truncado por `max_findings`.
    Truncated,
}

/// Aplica o judge.
#[must_use]
pub fn judge(findings: Vec<Finding>, ctx: &JudgeContext<'_>, config: &JudgeConfig) -> JudgeResult {
    let mut accepted: Vec<Finding> = Vec::new();
    let mut rejected: Vec<RejectedFinding> = Vec::new();
    let mut by_key: HashMap<String, usize> = HashMap::new();

    for f in findings {
        // 1. Validação estrutural (`INV-CR-03`, `INV-CR-07`)
        if f.validate().is_err() {
            rejected.push(RejectedFinding {
                finding: f,
                reason: RejectReason::Invalid,
            });
            continue;
        }

        // 2. Grounding verificável (`INV-CR-09`)
        if config.require_grounding && !is_grounded(&f, ctx) {
            rejected.push(RejectedFinding {
                finding: f,
                reason: RejectReason::NotGrounded,
            });
            continue;
        }

        // 3. Filtro de confiança (`INV-CR-05`)
        if f.confidence < config.min_confidence {
            rejected.push(RejectedFinding {
                finding: f,
                reason: RejectReason::LowConfidence,
            });
            continue;
        }

        // 4. Dedup (`INV-CR-04`) + precedência static (`INV-CR-08`)
        let key = f.dedup_key();
        if let Some(&idx) = by_key.get(&key) {
            let existing_source = accepted[idx].source;
            let existing_confidence = accepted[idx].confidence;

            let keep_new = if config.static_precedence {
                match (existing_source, f.source) {
                    (FindingSource::Llm, FindingSource::Static) => true,
                    (FindingSource::Static, FindingSource::Llm) => false,
                    _ => f.confidence > existing_confidence,
                }
            } else {
                f.confidence > existing_confidence
            };

            if keep_new {
                let reason = if config.static_precedence
                    && existing_source == FindingSource::Llm
                    && f.source == FindingSource::Static
                {
                    RejectReason::SupersededByStatic
                } else {
                    RejectReason::Duplicate
                };
                let old = std::mem::replace(&mut accepted[idx], f);
                rejected.push(RejectedFinding {
                    finding: old,
                    reason,
                });
            } else {
                rejected.push(RejectedFinding {
                    finding: f,
                    reason: RejectReason::Duplicate,
                });
            }
        } else {
            by_key.insert(key, accepted.len());
            accepted.push(f);
        }
    }

    // 5. Ordenação: severidade desc, depois confiança desc
    //    `unwrap_or(Equal)` é seguro: `validate` rejeita NaN (confidence ∈ [0, 1]).
    accepted.sort_by(|a, b| {
        b.severity.cmp(&a.severity).then(
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal),
        )
    });

    // 6. Truncar ao máximo
    if accepted.len() > config.max_findings {
        let extra = accepted.split_off(config.max_findings);
        for f in extra {
            rejected.push(RejectedFinding {
                finding: f,
                reason: RejectReason::Truncated,
            });
        }
    }

    tracing::info!(
        accepted = accepted.len(),
        rejected = rejected.len(),
        "judge concluído"
    );

    JudgeResult { accepted, rejected }
}

/// Verifica se um finding está groundado (`INV-CR-09`).
///
/// Regras:
/// 1. `evidence.file` existe no diff (como `new_path`)
/// 2. O ficheiro existe no `ReviewContext`
/// 3. `evidence.line` está dentro dos limites (`1..=len`)
/// 4. O `snippet` (trim) corresponde ao conteúdo real daquela linha (trim)
///
/// **Sem contexto carregado, o finding é rejeitado** — não há como
/// verificar linha nem snippet. O chamador deve construir `ReviewContext`
/// (via `add_file` ou `from_diff`) antes de invocar o judge.
#[must_use]
pub fn is_grounded(finding: &Finding, ctx: &JudgeContext<'_>) -> bool {
    let file = &finding.evidence.file;

    // 1. Ficheiro aparece no diff
    let in_diff = ctx.diff.files.iter().any(|fd| &fd.new_path == file);
    if !in_diff {
        return false;
    }

    // 2. Contexto carregado para este ficheiro
    let Some(file_ctx) = ctx.review.files.get(file) else {
        return false;
    };

    // 3. Linha dentro dos limites
    let line = finding.evidence.line;
    if line == 0 || line > file_ctx.lines.len() {
        return false;
    }

    // 4. Snippet corresponde ao conteúdo real
    let actual = file_ctx.lines[line - 1].trim();
    let expected = finding.evidence.snippet.trim();
    actual == expected
}

#[cfg(test)]
mod tests {
    use super::*;
    use arkhe_code_review_context::FileContext;
    use arkhe_code_review_static::{Evidence, Severity};

    fn sample_diff() -> Diff {
        Diff::parse(concat!(
            "diff --git a/x.rs b/x.rs\n",
            "--- a/x.rs\n",
            "+++ b/x.rs\n",
            "@@ -1,2 +1,3 @@\n",
            " fn f() {\n",
            "+    let x = g().unwrap();\n",
            " }\n",
        ))
        .unwrap()
    }

    fn sample_context() -> ReviewContext {
        let mut ctx = ReviewContext::new();
        ctx.files.insert(
            "x.rs".into(),
            FileContext::from_lines(
                "x.rs",
                vec![
                    "fn f() {".into(),
                    "    let x = g().unwrap();".into(),
                    "}".into(),
                ],
            ),
        );
        ctx
    }

    fn finding_at(line: usize, source: FindingSource, confidence: f64) -> Finding {
        Finding {
            id: format!("f-{line}-{confidence}"),
            rule: "no-unwrap".into(),
            message: "msg".into(),
            severity: Severity::Warning,
            source,
            evidence: Evidence {
                file: "x.rs".into(),
                line,
                snippet: "    let x = g().unwrap();".into(),
            },
            provenance: "test".into(),
            confidence,
        }
    }

    fn finding_with_rule(
        rule: &str,
        line: usize,
        source: FindingSource,
        confidence: f64,
    ) -> Finding {
        Finding {
            id: format!("{rule}-{line}"),
            rule: rule.into(),
            message: "msg".into(),
            severity: Severity::Warning,
            source,
            evidence: Evidence {
                file: "x.rs".into(),
                line,
                snippet: "    let x = g().unwrap();".into(),
            },
            provenance: "test".into(),
            confidence,
        }
    }

    #[test]
    fn inv_cr_04_judge_deduplicates() {
        let d = sample_diff();
        let r = sample_context();
        let ctx = JudgeContext {
            diff: &d,
            review: &r,
        };
        let cfg = JudgeConfig::default();
        let fs = vec![
            finding_at(2, FindingSource::Llm, 0.6),
            finding_at(2, FindingSource::Llm, 0.8),
        ];
        let out = judge(fs, &ctx, &cfg);

        assert_eq!(out.accepted.len(), 1);
        assert_eq!(out.accepted[0].confidence, 0.8);
        assert!(out
            .rejected
            .iter()
            .any(|r| r.reason == RejectReason::Duplicate));
    }

    #[test]
    fn inv_cr_05_low_confidence_filtered() {
        let d = sample_diff();
        let r = sample_context();
        let ctx = JudgeContext {
            diff: &d,
            review: &r,
        };
        let cfg = JudgeConfig {
            min_confidence: 0.7,
            ..Default::default()
        };
        let fs = vec![finding_at(2, FindingSource::Llm, 0.3)];
        let out = judge(fs, &ctx, &cfg);
        assert_eq!(out.accepted.len(), 0);
        assert_eq!(out.rejected[0].reason, RejectReason::LowConfidence);
    }

    #[test]
    fn inv_cr_08_static_precedence_in_conflict() {
        let d = sample_diff();
        let r = sample_context();
        let ctx = JudgeContext {
            diff: &d,
            review: &r,
        };
        let cfg = JudgeConfig::default();
        let fs = vec![
            finding_at(2, FindingSource::Llm, 0.95),
            finding_at(2, FindingSource::Static, 0.5),
        ];
        let out = judge(fs, &ctx, &cfg);
        assert_eq!(out.accepted.len(), 1);
        assert_eq!(out.accepted[0].source, FindingSource::Static);
        assert!(out
            .rejected
            .iter()
            .any(|r| r.reason == RejectReason::SupersededByStatic));
    }

    #[test]
    fn inv_cr_08_static_wins_even_before_llm_in_order() {
        // Static aparece primeiro, LLM depois — static mantém-se.
        let d = sample_diff();
        let r = sample_context();
        let ctx = JudgeContext {
            diff: &d,
            review: &r,
        };
        let cfg = JudgeConfig::default();
        let fs = vec![
            finding_at(2, FindingSource::Static, 0.5),
            finding_at(2, FindingSource::Llm, 0.95),
        ];
        let out = judge(fs, &ctx, &cfg);
        assert_eq!(out.accepted.len(), 1);
        assert_eq!(out.accepted[0].source, FindingSource::Static);
        assert!(out
            .rejected
            .iter()
            .any(|r| r.reason == RejectReason::Duplicate));
    }

    #[test]
    fn inv_cr_08_static_precedence_disabled() {
        let d = sample_diff();
        let r = sample_context();
        let ctx = JudgeContext {
            diff: &d,
            review: &r,
        };
        let cfg = JudgeConfig {
            static_precedence: false,
            ..Default::default()
        };
        let fs = vec![
            finding_at(2, FindingSource::Static, 0.5),
            finding_at(2, FindingSource::Llm, 0.95),
        ];
        let out = judge(fs, &ctx, &cfg);
        assert_eq!(out.accepted.len(), 1);
        assert_eq!(out.accepted[0].source, FindingSource::Llm);
    }

    #[test]
    fn inv_cr_09_not_grounded_without_context() {
        let d = sample_diff();
        let r = ReviewContext::new(); // sem contexto
        let ctx = JudgeContext {
            diff: &d,
            review: &r,
        };
        let cfg = JudgeConfig::default();
        let fs = vec![finding_at(2, FindingSource::Llm, 0.9)];
        let out = judge(fs, &ctx, &cfg);
        assert_eq!(out.accepted.len(), 0);
        assert_eq!(out.rejected[0].reason, RejectReason::NotGrounded);
    }

    #[test]
    fn inv_cr_09_not_grounded_wrong_snippet() {
        let d = sample_diff();
        let mut r = ReviewContext::new();
        r.files.insert(
            "x.rs".into(),
            FileContext::from_lines("x.rs", vec!["WRONG CONTENT".into()]),
        );
        let ctx = JudgeContext {
            diff: &d,
            review: &r,
        };
        let cfg = JudgeConfig::default();
        let fs = vec![finding_at(1, FindingSource::Llm, 0.9)];
        let out = judge(fs, &ctx, &cfg);
        assert_eq!(out.accepted.len(), 0);
        assert_eq!(out.rejected[0].reason, RejectReason::NotGrounded);
    }

    #[test]
    fn inv_cr_09_not_grounded_line_out_of_bounds() {
        let d = sample_diff();
        let r = sample_context();
        let ctx = JudgeContext {
            diff: &d,
            review: &r,
        };
        let cfg = JudgeConfig::default();
        let fs = vec![finding_at(999, FindingSource::Llm, 0.9)];
        let out = judge(fs, &ctx, &cfg);
        assert_eq!(out.accepted.len(), 0);
        assert_eq!(out.rejected[0].reason, RejectReason::NotGrounded);
    }

    #[test]
    fn inv_cr_09_not_grounded_file_not_in_diff() {
        let d = sample_diff();
        let mut r = ReviewContext::new();
        r.files.insert(
            "other.rs".into(),
            FileContext::from_lines("other.rs", vec!["content".into()]),
        );
        let ctx = JudgeContext {
            diff: &d,
            review: &r,
        };
        let cfg = JudgeConfig::default();
        let mut f = finding_at(1, FindingSource::Llm, 0.9);
        f.evidence.file = "other.rs".into();
        let out = judge(vec![f], &ctx, &cfg);
        assert_eq!(out.accepted.len(), 0);
        assert_eq!(out.rejected[0].reason, RejectReason::NotGrounded);
    }

    #[test]
    fn invalid_finding_is_rejected() {
        let d = sample_diff();
        let r = sample_context();
        let ctx = JudgeContext {
            diff: &d,
            review: &r,
        };
        let cfg = JudgeConfig::default();
        let mut f = finding_at(2, FindingSource::Static, 0.9);
        f.evidence.snippet = String::new();
        let out = judge(vec![f], &ctx, &cfg);
        assert_eq!(out.accepted.len(), 0);
        assert_eq!(out.rejected[0].reason, RejectReason::Invalid);
    }

    #[test]
    fn truncation_has_own_reason() {
        let d = sample_diff();
        let r = sample_context();
        let ctx = JudgeContext {
            diff: &d,
            review: &r,
        };
        let cfg = JudgeConfig {
            max_findings: 1,
            ..Default::default()
        };
        let fs = vec![
            finding_with_rule("r1", 2, FindingSource::Static, 0.9),
            finding_with_rule("r2", 2, FindingSource::Static, 0.8),
        ];
        let out = judge(fs, &ctx, &cfg);
        assert_eq!(out.accepted.len(), 1);
        assert!(out
            .rejected
            .iter()
            .any(|r| r.reason == RejectReason::Truncated));
    }

    #[test]
    fn accepted_sorted_by_severity_then_confidence() {
        let d = sample_diff();
        let r = sample_context();
        let ctx = JudgeContext {
            diff: &d,
            review: &r,
        };
        let cfg = JudgeConfig::default();

        let mut crit = finding_with_rule("crit", 2, FindingSource::Static, 0.6);
        crit.severity = Severity::Critical;
        let mut warn_hi = finding_with_rule("warn_hi", 2, FindingSource::Static, 0.95);
        warn_hi.severity = Severity::Warning;
        let mut warn_lo = finding_with_rule("warn_lo", 2, FindingSource::Static, 0.6);
        warn_lo.severity = Severity::Warning;

        let out = judge(vec![warn_lo, crit, warn_hi], &ctx, &cfg);
        assert_eq!(out.accepted.len(), 3);
        assert_eq!(out.accepted[0].severity, Severity::Critical);
        assert_eq!(out.accepted[1].severity, Severity::Warning);
        assert_eq!(out.accepted[1].confidence, 0.95);
        assert_eq!(out.accepted[2].severity, Severity::Warning);
        assert_eq!(out.accepted[2].confidence, 0.6);
    }

    #[test]
    fn require_grounding_false_accepts_ungrounded() {
        let d = sample_diff();
        let r = ReviewContext::new();
        let ctx = JudgeContext {
            diff: &d,
            review: &r,
        };
        let cfg = JudgeConfig {
            require_grounding: false,
            ..Default::default()
        };
        let fs = vec![finding_at(2, FindingSource::Llm, 0.9)];
        let out = judge(fs, &ctx, &cfg);
        assert_eq!(out.accepted.len(), 1);
    }
}
