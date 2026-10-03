#![deny(missing_docs)]
#![deny(unsafe_code)]

//! Validações de segurança contra vulnerabilidades conhecidas.
//!
//! ## CVEs mitigados
//!
//! - CVE-2026-65920 (path traversal em `weight_map`)
//! - CVE-2026-7482 (GGUF OOB read)
//! - PR #3364 (safetensors `data_offsets` inconsistentes)

use crate::error::VerifyError;

/// Tamanho máximo do header safetensors (100 MB).
pub const MAX_SAFETENSORS_HEADER: usize = 100 * 1024 * 1024;

/// Tamanho máximo de uma string GGUF (64 MB).
pub const MAX_GGUF_STRING: u64 = 64 * 1024 * 1024;

/// Máximo de elementos num array GGUF.
pub const MAX_GGUF_ARRAY: u64 = 1024 * 1024;

/// Alignment máximo GGUF (1 MiB).
pub const MAX_GGUF_ALIGNMENT: u64 = 1024 * 1024;

/// Alignment mínimo GGUF.
pub const MIN_GGUF_ALIGNMENT: u64 = 4;

/// Máximo de dimensões GGUF.
pub const MAX_GGUF_DIMS: u32 = 4;

/// Tipos de dados safetensors suportados.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeTensorDtype {
    /// fp16.
    F16,
    /// bf16.
    BF16,
    /// fp32.
    F32,
    /// fp64.
    F64,
    /// int8.
    I8,
    /// int16.
    I16,
    /// int32.
    I32,
    /// int64.
    I64,
    /// uint8.
    U8,
    /// uint16.
    U16,
    /// uint32.
    U32,
    /// uint64.
    U64,
    /// bool.
    Bool,
}

impl SafeTensorDtype {
    /// Tamanho em bytes.
    #[must_use]
    pub fn size_bytes(self) -> usize {
        match self {
            Self::F16 | Self::BF16 | Self::I16 | Self::U16 => 2,
            Self::F32 | Self::I32 | Self::U32 => 4,
            Self::F64 | Self::I64 | Self::U64 => 8,
            Self::I8 | Self::U8 | Self::Bool => 1,
        }
    }

    /// Parse de string.
    ///
    /// # Errors
    ///
    /// Devolve [`VerifyError::Parse`] se o dtype for desconhecido.
    pub fn parse(s: &str) -> Result<Self, VerifyError> {
        match s {
            "F16" => Ok(Self::F16),
            "BF16" => Ok(Self::BF16),
            "F32" => Ok(Self::F32),
            "F64" => Ok(Self::F64),
            "I8" => Ok(Self::I8),
            "I16" => Ok(Self::I16),
            "I32" => Ok(Self::I32),
            "I64" => Ok(Self::I64),
            "U8" => Ok(Self::U8),
            "U16" => Ok(Self::U16),
            "U32" => Ok(Self::U32),
            "U64" => Ok(Self::U64),
            "BOOL" => Ok(Self::Bool),
            _ => Err(VerifyError::Parse(format!("dtype desconhecido: {s}"))),
        }
    }
}

/// Valida `data_offsets` de um tensor safetensors.
///
/// # Errors
///
/// Devolve [`VerifyError::Security`] se os offsets forem inconsistentes.
pub fn validate_safetensors_offsets(
    shape: &[usize],
    dtype: SafeTensorDtype,
    data_offsets: &[usize; 2],
    data_buffer_len: usize,
) -> Result<(), VerifyError> {
    let [start, end] = *data_offsets;
    if start > end {
        return Err(VerifyError::Security(format!(
            "data_offsets inválidos: start={start} > end={end}"
        )));
    }
    if end > data_buffer_len {
        return Err(VerifyError::Security(format!(
            "data_offsets excedem buffer: end={end} > len={data_buffer_len}"
        )));
    }

    let expected_elems: usize = shape.iter().product();
    let expected_bytes = expected_elems.saturating_mul(dtype.size_bytes());
    let actual_bytes = end - start;
    if expected_bytes != actual_bytes {
        return Err(VerifyError::Security(format!(
            "data_offsets inconsistentes: esperado {expected_bytes} bytes, obtido {actual_bytes}"
        )));
    }
    Ok(())
}

/// Sanitiza paths do `weight_map` (CVE-2026-65920).
///
/// # Errors
///
/// Devolve [`VerifyError::Security`] se o path tentar escapar ao base dir.
pub fn sanitize_weight_map_path(
    base_dir: &std::path::Path,
    relative: &str,
) -> Result<std::path::PathBuf, VerifyError> {
    if relative.contains("..") || relative.starts_with('/') {
        return Err(VerifyError::Security(format!(
            "path traversal detectado: {relative}"
        )));
    }

    let candidate = base_dir.join(relative);
    let canonical_base = base_dir
        .canonicalize()
        .map_err(|e| VerifyError::Security(format!("base dir inválido: {e}")))?;

    if let Some(parent) = candidate.parent() {
        if let Ok(canonical_parent) = parent.canonicalize() {
            if !canonical_parent.starts_with(&canonical_base) {
                return Err(VerifyError::Security(format!(
                    "path escapa ao diretório base: {relative}"
                )));
            }
        }
    }

    Ok(candidate)
}

/// Valida alignment GGUF.
///
/// # Errors
///
/// Devolve [`VerifyError::Security`] se o alignment estiver fora dos limites.
pub fn validate_gguf_alignment(alignment: u64) -> Result<(), VerifyError> {
    if !(MIN_GGUF_ALIGNMENT..=MAX_GGUF_ALIGNMENT).contains(&alignment) {
        return Err(VerifyError::Security(format!(
            "alignment GGUF fora de limites: {alignment}"
        )));
    }
    if !alignment.is_power_of_two() {
        return Err(VerifyError::Security(format!(
            "alignment GGUF não é potência de 2: {alignment}"
        )));
    }
    Ok(())
}

/// Valida `n_dims` GGUF.
///
/// # Errors
///
/// Devolve [`VerifyError::Security`] se exceder o máximo.
pub fn validate_gguf_n_dims(n_dims: u32) -> Result<(), VerifyError> {
    if n_dims > MAX_GGUF_DIMS {
        return Err(VerifyError::Security(format!(
            "n_dims GGUF excede máximo: {n_dims} > {MAX_GGUF_DIMS}"
        )));
    }
    Ok(())
}

/// Valida `gguf_type`.
///
/// # Errors
///
/// Devolve [`VerifyError::Security`] se o tipo for desconhecido.
pub fn validate_gguf_type(t: i32) -> Result<(), VerifyError> {
    const KNOWN: std::ops::RangeInclusive<i32> = 0..=12;
    if !KNOWN.contains(&t) {
        return Err(VerifyError::Security(format!(
            "gguf_type desconhecido: {t} (esperado 0..=12)"
        )));
    }
    Ok(())
}

/// Valida `blck_size` não-zero.
///
/// # Errors
///
/// Devolve [`VerifyError::Security`] se for zero.
pub fn validate_gguf_block_size(blck_size: u64) -> Result<(), VerifyError> {
    if blck_size == 0 {
        return Err(VerifyError::Security(
            "blck_size GGUF é zero (divisão por zero)".into(),
        ));
    }
    Ok(())
}

/// Valida string GGUF.
///
/// # Errors
///
/// Devolve [`VerifyError::LimitExceeded`] se exceder o máximo.
pub fn validate_gguf_string_len(len: u64) -> Result<(), VerifyError> {
    if len > MAX_GGUF_STRING {
        return Err(VerifyError::LimitExceeded {
            field: "gguf.string_len".into(),
            value: len,
            max: MAX_GGUF_STRING,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_inconsistent_offsets() {
        let shape = vec![1000usize, 1000];
        let offsets = [0usize, 4];
        assert!(validate_safetensors_offsets(&shape, SafeTensorDtype::F32, &offsets, 100).is_err());
    }

    #[test]
    fn accept_consistent_offsets() {
        let shape = vec![2usize, 2];
        let offsets = [0usize, 16];
        assert!(validate_safetensors_offsets(&shape, SafeTensorDtype::F32, &offsets, 16).is_ok());
    }

    #[test]
    fn path_traversal_rejected() {
        let base = std::path::Path::new("/tmp");
        assert!(sanitize_weight_map_path(base, "../etc/passwd").is_err());
        assert!(sanitize_weight_map_path(base, "/etc/passwd").is_err());
    }

    #[test]
    fn alignment_bounds() {
        assert!(validate_gguf_alignment(0).is_err());
        assert!(validate_gguf_alignment(2).is_err());
        assert!(validate_gguf_alignment(32).is_ok());
        assert!(validate_gguf_alignment(1024 * 1024).is_ok());
        assert!(validate_gguf_alignment(2 * 1024 * 1024).is_err());
    }

    #[test]
    fn n_dims_bounds() {
        for n in 0..=4 {
            assert!(validate_gguf_n_dims(n).is_ok());
        }
        assert!(validate_gguf_n_dims(5).is_err());
    }

    #[test]
    fn gguf_type_bounds() {
        for t in 0..=12 {
            assert!(validate_gguf_type(t).is_ok());
        }
        assert!(validate_gguf_type(13).is_err());
        assert!(validate_gguf_type(-1).is_err());
    }

    #[test]
    fn block_size_nonzero() {
        assert!(validate_gguf_block_size(1).is_ok());
        assert!(validate_gguf_block_size(0).is_err());
    }
}
