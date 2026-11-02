//! Invariant definitions and traceability mapping for Arkhe.

use serde::{Deserialize, Serialize};

/// The primary Arkhe System Invariants (I-01 through I-10) as formulated in the Arkhe Whitepaper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ArkheInvariant {
    /// I-01: Chunk integrity - Corrupting 1 byte must fail verification.
    I01ChunkIntegrity,
    /// I-02: Verifiable manifest - CID alteration or missing chunk must be rejected.
    I02VerifiableManifest,
    /// I-03: AFiR receipt - Invalid signature or reused nonce must be rejected.
    I03AfirReceipt,
    /// I-04: Append-only MMR - Removing or reordering MobileWER operations is prohibited.
    I04MmrAppendOnly,
    /// I-05: Offline audit - Corrupted bundle must fail verification offline.
    I05OfflineAudit,
    /// I-06: Device binding - Uncertified or unattested device key cannot produce checkpoints.
    I06DeviceBinding,
    /// I-07: Human governance - Autonomous proposals cannot alter constitutional rules.
    I07HumanGovernance,
    /// I-08: Proof-of-Reward - Payment/reward without verifiable receipt/MMR is blocked.
    I08RewardByProof,
    /// I-09: Chain-agnostic evidence - Bundles must verify independently without blockchain connectivity.
    I09ChainAgnosticEvidence,
    /// I-10: Disjoint roles - Worker cannot validate in the same epoch.
    I10DisjointRoles,
}

impl ArkheInvariant {
    /// Identifier string (e.g., "I-01").
    pub fn id(&self) -> &'static str {
        match self {
            Self::I01ChunkIntegrity => "I-01",
            Self::I02VerifiableManifest => "I-02",
            Self::I03AfirReceipt => "I-03",
            Self::I04MmrAppendOnly => "I-04",
            Self::I05OfflineAudit => "I-05",
            Self::I06DeviceBinding => "I-06",
            Self::I07HumanGovernance => "I-07",
            Self::I08RewardByProof => "I-08",
            Self::I09ChainAgnosticEvidence => "I-09",
            Self::I10DisjointRoles => "I-10",
        }
    }

    /// Short descriptive title.
    pub fn title(&self) -> &'static str {
        match self {
            Self::I01ChunkIntegrity => "Chunk íntegro",
            Self::I02VerifiableManifest => "Manifesto verificável",
            Self::I03AfirReceipt => "Recibo AFiR",
            Self::I04MmrAppendOnly => "MMR append-only",
            Self::I05OfflineAudit => "Auditoria offline",
            Self::I06DeviceBinding => "Vínculo ao dispositivo",
            Self::I07HumanGovernance => "Governança humana",
            Self::I08RewardByProof => "Reward por prova",
            Self::I09ChainAgnosticEvidence => "Evidência chain-agnostic",
            Self::I10DisjointRoles => "Papéis disjuntos",
        }
    }

    /// Roadmap phase mapping (F1 through F5).
    pub fn phase(&self) -> &'static str {
        match self {
            Self::I01ChunkIntegrity => "F1",
            Self::I02VerifiableManifest => "F1",
            Self::I03AfirReceipt => "F2",
            Self::I04MmrAppendOnly => "F2",
            Self::I05OfflineAudit => "F3",
            Self::I06DeviceBinding => "F3",
            Self::I07HumanGovernance => "F4",
            Self::I08RewardByProof => "F4",
            Self::I09ChainAgnosticEvidence => "F5",
            Self::I10DisjointRoles => "F5",
        }
    }

    /// Rejection criterion: what condition causes the test to fail.
    pub fn rejection_criterion(&self) -> &'static str {
        match self {
            Self::I01ChunkIntegrity => "Chunk aceito com byte alterado",
            Self::I02VerifiableManifest => "Manifesto aceito com CID divergente ou chunk ausente",
            Self::I03AfirReceipt => "Recibo aceito com assinatura inválida ou nonce repetido",
            Self::I04MmrAppendOnly => "Operação permitida que remove ou reordena nós na MMR",
            Self::I05OfflineAudit => "Verificador aceita bundle corrompido ou reescrito offline",
            Self::I06DeviceBinding => {
                "Checkpoint aceito com chave sem atestação válida de dispositivo"
            }
            Self::I07HumanGovernance => {
                "Mudança constitucional aplicada por proposta autônoma sem canonização humana"
            }
            Self::I08RewardByProof => "Pagamento/reward liberado sem recibo/MMR/verificação válida",
            Self::I09ChainAgnosticEvidence => {
                "Falha indevida na verificação de bundle válido sem chain conectada"
            }
            Self::I10DisjointRoles => "Worker aceito como validador no mesmo epoch",
        }
    }

    /// Mandatory test requirement description.
    pub fn mandatory_test(&self) -> &'static str {
        match self {
            Self::I01ChunkIntegrity => "Alterar 1 byte e tentar aceitar",
            Self::I02VerifiableManifest => "Trocar CID ou remover chunk do manifesto",
            Self::I03AfirReceipt => "Assinar com chave errada ou reusar nonce",
            Self::I04MmrAppendOnly => "Remover/reordenar MobileWER",
            Self::I05OfflineAudit => "Corromper bundle e verificar",
            Self::I06DeviceBinding => "Usar chave sem atestação válida",
            Self::I07HumanGovernance => "Proposta autônoma tentando alterar constituição",
            Self::I08RewardByProof => "Pagar sem recibo/MMR/verificação",
            Self::I09ChainAgnosticEvidence => "Verificar bundle sem chain",
            Self::I10DisjointRoles => "Worker tentar validar no mesmo epoch",
        }
    }

    /// List all 10 invariants.
    pub fn all() -> &'static [ArkheInvariant] {
        &[
            Self::I01ChunkIntegrity,
            Self::I02VerifiableManifest,
            Self::I03AfirReceipt,
            Self::I04MmrAppendOnly,
            Self::I05OfflineAudit,
            Self::I06DeviceBinding,
            Self::I07HumanGovernance,
            Self::I08RewardByProof,
            Self::I09ChainAgnosticEvidence,
            Self::I10DisjointRoles,
        ]
    }
}

/// The Pipeline Meta-Invariants (I-T01 through I-T08) enforced by arkhe-test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ArkheTestInvariant {
    /// I-T01: Test before merge.
    IT01TestBeforeMerge,
    /// I-T02: Fail-closed on security failure.
    IT02FailClosed,
    /// I-T03: Traceability to Arkhe invariants and roadmap.
    IT03Traceability,
    /// I-T04: Deterministic reproducibility.
    IT04Reproducibility,
    /// I-T05: Safe rollback without evidence loss.
    IT05SafeRollback,
    /// I-T06: Feature flags never weaken security.
    IT06FeatureFlagsCannotWeakenSecurity,
    /// I-T07: Content-addressed auditable test evidence.
    IT07AuditableEvidence,
    /// I-T08: Continuous adversarial testing.
    IT08ContinuousAdversarialTesting,
}

impl ArkheTestInvariant {
    pub fn id(&self) -> &'static str {
        match self {
            Self::IT01TestBeforeMerge => "I-T01",
            Self::IT02FailClosed => "I-T02",
            Self::IT03Traceability => "I-T03",
            Self::IT04Reproducibility => "I-T04",
            Self::IT05SafeRollback => "I-T05",
            Self::IT06FeatureFlagsCannotWeakenSecurity => "I-T06",
            Self::IT07AuditableEvidence => "I-T07",
            Self::IT08ContinuousAdversarialTesting => "I-T08",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::IT01TestBeforeMerge => "Nenhum PR entra na branch principal sem testes de invariante relevantes",
            Self::IT02FailClosed => "Qualquer teste de segurança que falhe bloqueia deploy; fail-closed sem warnings aceitáveis",
            Self::IT03Traceability => "Todo teste referencia um invariante Arkhe (I-01 a I-10) e um requisito de roadmap",
            Self::IT04Reproducibility => "O mesmo commit, dependências e vetores produzem o mesmo resultado",
            Self::IT05SafeRollback => "Rollback retorna à versão anterior sem corromper MMR, recibos ou checkpoints",
            Self::IT06FeatureFlagsCannotWeakenSecurity => "Flags ativam funcionalidades, nunca desativam verificação obrigatória",
            Self::IT07AuditableEvidence => "Cada execução gera artefato assinado e content-addressed",
            Self::IT08ContinuousAdversarialTesting => "Pipeline tenta quebrar o sistema adversarialmente",
        }
    }
}
