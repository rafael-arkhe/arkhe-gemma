use std::path::Path;

use serde::{Deserialize, Serialize};

use arkhe_ai_verify::{detect_format, verify_artifact, ArkheStatus, ArtifactFormat, TrustAnchor};

use crate::error::GemmaError;

/// Manifesto do modelo Gemma 4.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelManifest {
    /// Nome do modelo.
    pub name: String,
    /// Versão.
    pub version: String,
    /// SHA-256 esperado.
    pub sha256: String,
    /// Formato.
    pub format: String,
    /// Tamanho em bytes.
    pub size_bytes: u64,
    /// URL de origem.
    pub source_url: Option<String>,
}

/// Resultado da verificação do modelo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelVerificationResult {
    /// Estado honesto.
    pub status: ArkheStatus,
    /// Manifesto.
    pub manifest: ModelManifest,
    /// `record_hash` da verificação.
    pub record_hash: [u8; 32],
    /// Detalhes dos gates.
    pub gate_details: Vec<String>,
}

/// Verifica a integridade do modelo Gemma 4 (`INV-GEMMA-01`).
///
/// # Errors
///
/// Devolve [`GemmaError::UnverifiedModel`] se o modelo não existir,
/// [`GemmaError::HashMismatch`] se o hash não corresponder,
/// ou [`GemmaError::Io`] se o ficheiro não puder ser lido.
pub async fn verify_model_integrity(
    path: &Path,
    expected_sha256: &str,
) -> Result<ModelVerificationResult, GemmaError> {
    if !path.exists() {
        return Err(GemmaError::UnverifiedModel(format!(
            "ficheiro não encontrado: {}",
            path.display()
        )));
    }

    let format = detect_format(path);
    if format == ArtifactFormat::Unknown {
        return Err(GemmaError::UnverifiedModel(format!(
            "formato desconhecido: {}",
            path.display()
        )));
    }

    let anchor = TrustAnchor::default();
    let result = verify_artifact(path, Some(expected_sha256), &anchor)
        .await
        .map_err(|e| GemmaError::Backend(format!("verificação falhou: {e}")))?;

    let manifest = ModelManifest {
        name: path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("gemma-4-31b")
            .to_string(),
        version: "31B-it-qat-w4a16-ct".to_string(),
        sha256: expected_sha256.to_string(),
        format: format!("{format:?}"),
        size_bytes: std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
        source_url: Some("https://huggingface.co/google/gemma-4-31B-it-qat-w4a16-ct".to_string()),
    };

    let gate_details: Vec<String> = result
        .gates
        .iter()
        .map(|g| format!("Gate {}: {:?} — {}", g.gate_id, g.status, g.detail))
        .collect();

    if result.status == ArkheStatus::Failed {
        return Err(GemmaError::HashMismatch {
            expected: expected_sha256.to_string(),
            actual: result.artifact_digest,
        });
    }

    Ok(ModelVerificationResult {
        status: result.status,
        manifest,
        record_hash: result.record_hash,
        gate_details,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_file_is_fail_closed() {
        let path = Path::new("/nonexistent/gemma.gguf");
        let result = verify_model_integrity(path, "abc123").await;
        assert!(matches!(result, Err(GemmaError::UnverifiedModel(_))));
    }

    #[tokio::test]
    async fn unknown_format_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("model.xyz");
        std::fs::write(&path, b"fake").unwrap();
        let result = verify_model_integrity(&path, "abc123").await;
        assert!(matches!(result, Err(GemmaError::UnverifiedModel(_))));
    }
}
