#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! # arkhe-ai-verify
//!
//! Pipeline de 4 gates fail-closed para artefatos de IA.
//!
//! ## Invariantes
//!
//! - `INV-AI-V-01`: Todo artefato verificado tem `record_hash`
//! - `INV-AI-V-02`: Formato desconhecido → `NONEXISTENT`
//! - `INV-AI-V-03`: Gate 0 rejeita artefatos que excedem limites
//! - `INV-AI-V-06`: `data_offsets` consistentes com shape/dtype
//! - `INV-AI-V-07`: Alignment GGUF ∈ [4, 1 MiB] e potência de 2
//! - `INV-AI-V-08`: `n_dims` ≤ 4
//! - `INV-AI-V-09`: `gguf_type` ∈ [0, 12]
//! - `INV-AI-V-10`: `blck_size` ≠ 0

pub mod error;
pub mod formats;
pub mod gates;
pub mod security;

pub use error::VerifyError;
pub use security::{
    validate_gguf_alignment, validate_gguf_block_size, validate_gguf_n_dims, validate_gguf_type,
    validate_safetensors_offsets, SafeTensorDtype,
};

use serde::{Deserialize, Serialize};

/// Estado honesto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArkheStatus {
    /// Verificado.
    Verified,
    /// Parcial.
    Partial,
    /// Falhado.
    Failed,
    /// Não existente.
    Nonexistent,
    /// Pendente.
    Pending,
    /// Bloqueado.
    Blocked,
}

/// Formato detectado.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactFormat {
    /// `.safetensors`.
    Safetensors,
    /// `.gguf`.
    Gguf,
    /// `.onnx`.
    Onnx,
    /// `.engine` / `.plan`.
    Tensorrt,
    /// `.tflite`.
    Tflite,
    /// `.mlmodel`.
    Coreml,
    /// `.pt` / `.pth` / `.bin` / `.ckpt`.
    Pytorch,
    /// Desconhecido.
    Unknown,
}

/// Resultado de um gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateResult {
    /// ID (0..3).
    pub gate_id: u8,
    /// Nome.
    pub name: String,
    /// Status.
    pub status: ArkheStatus,
    /// Detalhe.
    pub detail: String,
    /// `record_hash` BLAKE3 em hex.
    pub record_hash: String,
}

/// Resultado completo de verificação.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    /// Status geral.
    pub status: ArkheStatus,
    /// Formato.
    pub artifact_format: ArtifactFormat,
    /// Digest SHA-256.
    pub artifact_digest: String,
    /// Gates.
    pub gates: Vec<GateResult>,
    /// `record_hash` BLAKE3.
    pub record_hash: [u8; 32],
}

/// Trust anchor para Gate 2/3.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    /// Issuer OIDC.
    pub issuer: String,
    /// Identity.
    pub identity: String,
}

impl Default for TrustAnchor {
    fn default() -> Self {
        Self {
            issuer: "sigstore".into(),
            identity: "https://gist.github.com/rafael-arkhe".into(),
        }
    }
}

/// Detecta o formato a partir da extensão.
#[must_use]
pub fn detect_format(path: &std::path::Path) -> ArtifactFormat {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "safetensors" => ArtifactFormat::Safetensors,
        "gguf" => ArtifactFormat::Gguf,
        "onnx" => ArtifactFormat::Onnx,
        "engine" | "plan" => ArtifactFormat::Tensorrt,
        "tflite" => ArtifactFormat::Tflite,
        "mlmodel" => ArtifactFormat::Coreml,
        "pt" | "pth" | "bin" | "ckpt" => ArtifactFormat::Pytorch,
        _ => ArtifactFormat::Unknown,
    }
}

/// Executa o pipeline de 4 gates.
///
/// # Errors
///
/// Devolve [`VerifyError`] se um gate falhar com erro irrecuperável.
pub async fn verify_artifact(
    path: &std::path::Path,
    expected_hash: Option<&str>,
    trust_anchor: &TrustAnchor,
) -> Result<VerifyResult, VerifyError> {
    let format = detect_format(path);
    if format == ArtifactFormat::Unknown {
        return Ok(VerifyResult {
            status: ArkheStatus::Nonexistent,
            artifact_format: format,
            artifact_digest: String::new(),
            gates: Vec::new(),
            record_hash: [0u8; 32],
        });
    }

    let gate0 = gates::sanitize(path, format).await?;
    let gate1 = gates::hash(path, expected_hash).await?;
    let gate2 = gates::verify_signature(path, trust_anchor).await?;
    let gate3 = gates::verify_inclusion(path, trust_anchor).await?;
    let digest = gate1.detail.clone();

    let gates = vec![gate0, gate1, gate2, gate3];
    let overall = if gates.iter().all(|g| g.status == ArkheStatus::Verified) {
        ArkheStatus::Verified
    } else if gates.iter().any(|g| g.status == ArkheStatus::Failed) {
        ArkheStatus::Failed
    } else {
        ArkheStatus::Partial
    };

    let mut hasher = blake3::Hasher::new_derive_key("arkhe-ai-verify-v1");
    for g in &gates {
        hasher.update(g.record_hash.as_bytes());
    }
    let record_hash = *hasher.finalize().as_bytes();

    Ok(VerifyResult {
        status: overall,
        artifact_format: format,
        artifact_digest: digest,
        gates,
        record_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_all_formats() {
        for (ext, expected) in [
            ("safetensors", ArtifactFormat::Safetensors),
            ("gguf", ArtifactFormat::Gguf),
            ("onnx", ArtifactFormat::Onnx),
            ("engine", ArtifactFormat::Tensorrt),
            ("tflite", ArtifactFormat::Tflite),
            ("mlmodel", ArtifactFormat::Coreml),
            ("pt", ArtifactFormat::Pytorch),
        ] {
            let p = std::path::PathBuf::from(format!("model.{ext}"));
            assert_eq!(detect_format(&p), expected, "falhou para {ext}");
        }
    }

    #[tokio::test]
    async fn inv_ai_v_02_unknown_format_is_nonexistent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("model.xyz");
        std::fs::write(&path, b"fake").unwrap();
        let r = verify_artifact(&path, None, &TrustAnchor::default())
            .await
            .unwrap();
        assert_eq!(r.status, ArkheStatus::Nonexistent);
        assert_eq!(r.record_hash, [0u8; 32]);
        assert!(r.gates.is_empty());
    }

    #[tokio::test]
    async fn inv_ai_v_01_verify_produces_record_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("model.safetensors");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&2u64.to_le_bytes());
        bytes.extend_from_slice(b"{}");
        std::fs::write(&path, &bytes).unwrap();

        let r = verify_artifact(&path, None, &TrustAnchor::default())
            .await
            .unwrap();
        assert_ne!(r.record_hash, [0u8; 32]);
        assert_eq!(r.gates.len(), 4);
    }

    #[tokio::test]
    async fn hash_mismatch_fails_gate1() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("model.gguf");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"GGUF");
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();

        let r = verify_artifact(&path, Some("deadbeef"), &TrustAnchor::default())
            .await
            .unwrap();
        assert_eq!(r.gates[1].status, ArkheStatus::Failed);
        assert_eq!(r.status, ArkheStatus::Failed);
    }

    #[tokio::test]
    async fn gate2_and_gate3_are_nonexistent_without_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("model.safetensors");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&2u64.to_le_bytes());
        bytes.extend_from_slice(b"{}");
        std::fs::write(&path, &bytes).unwrap();

        let r = verify_artifact(&path, None, &TrustAnchor::default())
            .await
            .unwrap();
        assert_eq!(r.gates[2].status, ArkheStatus::Nonexistent);
        assert_eq!(r.gates[3].status, ArkheStatus::Nonexistent);
        assert_eq!(r.status, ArkheStatus::Partial);
    }
}
