use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum ArtifactFormat {
    Unknown,
    Gguf,
    Safetensors,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum ArkheStatus {
    Passed,
    Failed,
}

#[derive(Default)]
pub struct TrustAnchor {
    _priv: (),
}


#[derive(Debug, Clone)]
pub struct GateDetail {
    pub gate_id: String,
    pub status: ArkheStatus,
    pub detail: String,
}

pub struct VerifyResult {
    pub status: ArkheStatus,
    pub artifact_digest: String,
    pub gates: Vec<GateDetail>,
    pub record_hash: [u8; 32],
}

pub fn detect_format(path: &Path) -> ArtifactFormat {
    if let Some(ext) = path.extension() {
        if ext == "gguf" {
            return ArtifactFormat::Gguf;
        } else if ext == "safetensors" {
            return ArtifactFormat::Safetensors;
        }
    }
    ArtifactFormat::Unknown
}

pub async fn verify_artifact(_path: &Path, _expected: Option<&str>, _anchor: &TrustAnchor) -> Result<VerifyResult, String> {
    Ok(VerifyResult {
        status: ArkheStatus::Passed,
        artifact_digest: "dummy_digest".to_string(),
        gates: vec![],
        record_hash: [0; 32],
    })
}
