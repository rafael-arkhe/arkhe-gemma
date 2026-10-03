#![deny(missing_docs)]
#![deny(unsafe_code)]

//! Pipeline de 4 gates fail-closed.

use crate::{ArkheStatus, ArtifactFormat, GateResult, TrustAnchor, VerifyError};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

/// Gate 0: sanitização.
///
/// # Errors
///
/// Devolve erro se o artefato exceder 16 GiB ou falhar o parser do formato.
pub async fn sanitize(
    path: &std::path::Path,
    format: ArtifactFormat,
) -> Result<GateResult, VerifyError> {
    let meta = tokio::fs::metadata(path).await?;
    let size = meta.len();
    const MAX: u64 = 16 * 1024 * 1024 * 1024;
    if size > MAX {
        return Err(VerifyError::LimitExceeded {
            field: "artifact.size".into(),
            value: size,
            max: MAX,
        });
    }

    let detail = match format {
        ArtifactFormat::Safetensors => {
            let header = crate::formats::safetensors::parse(path)?;
            format!("safetensors OK · {} tensores", header.tensors.len())
        }
        ArtifactFormat::Gguf => {
            let header = crate::formats::gguf::parse_header(path)?;
            format!(
                "GGUF v{} OK · {} tensores · {} KV",
                header.version, header.tensor_count, header.metadata_kv_count
            )
        }
        _ => format!("{size} bytes · limites OK"),
    };

    Ok(GateResult {
        gate_id: 0,
        name: "Sanitização".into(),
        status: ArkheStatus::Verified,
        detail,
        record_hash: hex::encode(blake3::hash(b"gate0-ok").as_bytes()),
    })
}

/// Gate 1: hash SHA-256.
///
/// # Errors
///
/// Devolve erro de I/O se o ficheiro não puder ser lido.
pub async fn hash(
    path: &std::path::Path,
    expected: Option<&str>,
) -> Result<GateResult, VerifyError> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 65536];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hex::encode(hasher.finalize());

    let status = match expected {
        Some(exp) if exp.eq_ignore_ascii_case(&digest) => ArkheStatus::Verified,
        Some(_) => ArkheStatus::Failed,
        None => ArkheStatus::Verified,
    };

    Ok(GateResult {
        gate_id: 1,
        name: "Hash".into(),
        status,
        detail: digest.clone(),
        record_hash: hex::encode(blake3::hash(digest.as_bytes()).as_bytes()),
    })
}

/// Gate 2: assinatura Sigstore.
///
/// **Estado actual:** stub honesto. Reporta `Nonexistent` quando não há
/// bundle `.sigstore.json`. A verificação criptográfica real exige
/// integração com `sigstore-verify`.
///
/// # Errors
///
/// Devolve erro de I/O se o metadata do ficheiro não puder ser lido.
pub async fn verify_signature(
    path: &std::path::Path,
    _trust_anchor: &TrustAnchor,
) -> Result<GateResult, VerifyError> {
    let bundle_path = path.with_extension("sigstore.json");
    if tokio::fs::metadata(&bundle_path).await.is_err() {
        return Ok(GateResult {
            gate_id: 2,
            name: "Assinatura".into(),
            status: ArkheStatus::Nonexistent,
            detail: "bundle Sigstore ausente (.sigstore.json)".into(),
            record_hash: hex::encode(blake3::hash(b"gate2-nonexistent").as_bytes()),
        });
    }
    Ok(GateResult {
        gate_id: 2,
        name: "Assinatura".into(),
        status: ArkheStatus::Nonexistent,
        detail: "bundle presente, verificação não implementada".into(),
        record_hash: hex::encode(blake3::hash(b"gate2-stub").as_bytes()),
    })
}

/// Gate 3: inclusão Rekor.
///
/// **Estado actual:** stub honesto análogo ao Gate 2.
///
/// # Errors
///
/// Devolve erro de I/O se o metadata do ficheiro não puder ser lido.
pub async fn verify_inclusion(
    path: &std::path::Path,
    _trust_anchor: &TrustAnchor,
) -> Result<GateResult, VerifyError> {
    let bundle_path = path.with_extension("sigstore.json");
    if tokio::fs::metadata(&bundle_path).await.is_err() {
        return Ok(GateResult {
            gate_id: 3,
            name: "Inclusão".into(),
            status: ArkheStatus::Nonexistent,
            detail: "sem prova de inclusão".into(),
            record_hash: hex::encode(blake3::hash(b"gate3-nonexistent").as_bytes()),
        });
    }
    Ok(GateResult {
        gate_id: 3,
        name: "Inclusão".into(),
        status: ArkheStatus::Nonexistent,
        detail: "bundle presente, verificação não implementada".into(),
        record_hash: hex::encode(blake3::hash(b"gate3-stub").as_bytes()),
    })
}
