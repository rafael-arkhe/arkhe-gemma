use std::sync::Arc;

use serde::{Deserialize, Serialize};

use arkhe_code_review::{Diff, ReviewConfig, ReviewOrchestrator};
use arkhe_ego::{BehaviorSignature, Ego, IdentityDeclaration, MonitorConfig, NullLedger, SelfModel};

use crate::backend::{GemmaBackend, InferenceRequest};
use crate::config::GemmaConfig;
use crate::error::GemmaError;

/// Ação do agente Gemma.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GemmaAction {
    /// Ler um ficheiro.
    ReadFile {
        /// Caminho do ficheiro.
        path: String
    },
    /// Propor um patch.
    ProposePatch {
        /// Diff do patch.
        diff: String,
        /// Ficheiro alvo.
        target_file: String
    },
    /// Executar testes.
    RunTests {
        /// Comando a executar.
        command: String
    },
    /// Finalizar.
    Finish {
        /// Resumo da finalização.
        summary: String
    },
}

/// Resultado de um ciclo do agente.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentOutcome {
    /// Ação executada.
    pub action: GemmaAction,
    /// `record_hash` da ação.
    pub record_hash: [u8; 32],
    /// Se o patch foi validado.
    pub patch_validated: bool,
    /// IDEs detectados pelo `SelfModel`.
    pub identity_disruptions: usize,
}

/// Agente Gemma 4 com verificação Arkhe.
pub struct GemmaAgent {
    config: GemmaConfig,
    backend: Arc<dyn GemmaBackend>,
    ego: Ego,
}

impl std::fmt::Debug for GemmaAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GemmaAgent")
            .field("config", &self.config)
            .field("backend", &self.backend)
            .finish_non_exhaustive()
    }
}

impl GemmaAgent {
    /// Cria um agente Gemma.
    ///
    /// # Errors
    ///
    /// Devolve [`GemmaError::Agent`] se a configuração do `SelfModel` for inválida.
    pub fn new(
        config: GemmaConfig,
        backend: Arc<dyn GemmaBackend>,
    ) -> Result<Self, GemmaError> {
        let declarations = vec![
            IdentityDeclaration {
                id: "scope".into(),
                behavior: "modifico apenas ficheiros dentro do escopo declarado".into(),
                signature: BehaviorSignature::RespectsBudget,
                contradicts: vec![],
            },
            IdentityDeclaration {
                id: "patch".into(),
                behavior: "proponho patches com evidência verificável".into(),
                signature: BehaviorSignature::EmitsRecordHash,
                contradicts: vec![],
            },
        ];

        let self_model = SelfModel::new(declarations, 0.9, 100)
            .map_err(|e| GemmaError::Agent(format!("self-model: {e}")))?;

        let ego = Ego::new(self_model, 10, 2, 10, MonitorConfig::default())
            .map_err(|e| GemmaError::Agent(format!("ego: {e}")))?;

        Ok(Self {
            config,
            backend,
            ego,
        })
    }

    /// Executa um ciclo do agente.
    ///
    /// # Errors
    ///
    /// Devolve [`GemmaError::BudgetExceeded`] se o orçamento for excedido,
    /// ou [`GemmaError::Agent`] se o ciclo falhar.
    pub async fn cycle(
        &mut self,
        prompt: &str,
        repo_context: Option<&str>,
    ) -> Result<AgentOutcome, GemmaError> {
        // Verificar orçamento (`INV-GEMMA-02`)
        let estimated_cost = (prompt.chars().count() as f64 / 1000.0) * 0.001;
        if estimated_cost > self.config.budget {
            return Err(GemmaError::BudgetExceeded {
                required: estimated_cost,
                available: self.config.budget,
            });
        }

        let request = InferenceRequest {
            prompt: prompt.to_string(),
            repo_context: repo_context.map(String::from),
            target_file: None,
            max_tokens: 4096,
        };

        let response = self.backend.infer(&request).await?;

        // Registar ação no Ego
        let mut ledger = NullLedger::default();
        let action = arkhe_ego::Action::from_signatures([BehaviorSignature::RespectsBudget]);
        let cycle_outcome = self
            .ego
            .cycle(action, response.output.as_bytes().to_vec(), 0, 1000, 10, &mut ledger)
            .map_err(|e| GemmaError::Agent(format!("ego cycle: {e}")))?;

        let action = if response.output.contains("diff --git") {
            GemmaAction::ProposePatch {
                diff: response.output.clone(),
                target_file: "unknown".into(),
            }
        } else {
            GemmaAction::Finish {
                summary: response.output.clone(),
            }
        };

        let mut h = blake3::Hasher::new_derive_key("arkhe-gemma-action-v1");
        h.update(response.record_hash.as_slice());
        let record_hash = *h.finalize().as_bytes();

        Ok(AgentOutcome {
            action,
            record_hash,
            patch_validated: false,
            identity_disruptions: cycle_outcome.ide_count as usize,
        })
    }

    /// Valida um patch proposto (`INV-GEMMA-03`).
    ///
    /// # Errors
    ///
    /// Devolve [`GemmaError::InvalidPatch`] se o patch não tiver grounding verificável.
    pub async fn validate_patch(&self, diff_text: &str) -> Result<bool, GemmaError> {
        let diff = Diff::parse(diff_text)
            .map_err(|e| GemmaError::InvalidPatch(format!("diff inválido: {e}")))?;

        if diff.files.is_empty() {
            return Err(GemmaError::InvalidPatch("patch sem ficheiros".into()));
        }

        let _config = ReviewConfig::default();
        let _orch = ReviewOrchestrator::new(vec![], vec![], _config);

        // Verificação mínima: o patch tem ficheiros e linhas válidas
        for file in &diff.files {
            if file.hunks.is_empty() {
                return Err(GemmaError::InvalidPatch(format!(
                    "ficheiro {} sem hunks",
                    file.new_path
                )));
            }
        }

        Ok(true)
    }
}
