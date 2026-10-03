#![deny(missing_docs)]
#![deny(unsafe_code)]

//! Parsers de formato.

pub mod safetensors {
    //! Parser safetensors: `[8B header_len LE][JSON header][data]`.

    use crate::error::VerifyError;
    use crate::security::{self, SafeTensorDtype};
    use serde::Deserialize;
    use std::collections::HashMap;
    use std::io::Read;

    /// Info de um tensor.
    #[derive(Debug, Deserialize)]
    pub struct TensorInfo {
        /// Dtype.
        pub dtype: String,
        /// Shape.
        pub shape: Vec<usize>,
        /// Offsets `[start, end]`.
        pub data_offsets: [usize; 2],
    }

    /// Header completo.
    #[derive(Debug, Deserialize)]
    pub struct Header {
        /// Tensores por nome.
        #[serde(flatten)]
        pub tensors: HashMap<String, TensorInfo>,
        /// Metadados.
        #[serde(rename = "__metadata__")]
        pub metadata: Option<HashMap<String, String>>,
    }

    /// Lê o header de um ficheiro safetensors.
    ///
    /// # Errors
    ///
    /// Devolve erro se o header exceder limites, não começar por `{`,
    /// ou tiver offsets inconsistentes.
    pub fn parse(path: &std::path::Path) -> Result<Header, VerifyError> {
        let mut file = std::fs::File::open(path)?;

        let mut len_bytes = [0u8; 8];
        file.read_exact(&mut len_bytes)?;
        let header_len_u64 = u64::from_le_bytes(len_bytes);
        let header_len = usize::try_from(header_len_u64)
            .map_err(|_| VerifyError::Parse("header length overflow".into()))?;

        if header_len > security::MAX_SAFETENSORS_HEADER {
            return Err(VerifyError::LimitExceeded {
                field: "safetensors.header_len".into(),
                value: header_len as u64,
                max: security::MAX_SAFETENSORS_HEADER as u64,
            });
        }

        let mut buf = vec![0u8; header_len];
        file.read_exact(&mut buf)?;

        if buf.first() != Some(&b'{') {
            return Err(VerifyError::Parse(
                "safetensors header não começa com '{'".into(),
            ));
        }

        let header: Header = serde_json::from_slice(&buf)
            .map_err(|e| VerifyError::Parse(format!("safetensors header: {e}")))?;

        let meta = std::fs::metadata(path)?;
        let file_len = usize::try_from(meta.len())
            .map_err(|_| VerifyError::Parse("file length overflow".into()))?;
        let data_buffer_len = file_len
            .checked_sub(8)
            .and_then(|v| v.checked_sub(header_len))
            .ok_or_else(|| VerifyError::Parse("safetensors: header maior que ficheiro".into()))?;

        for (name, info) in &header.tensors {
            let dtype = SafeTensorDtype::parse(&info.dtype)
                .map_err(|e| VerifyError::Parse(format!("tensor {name}: {e}")))?;
            security::validate_safetensors_offsets(
                &info.shape,
                dtype,
                &info.data_offsets,
                data_buffer_len,
            )
            .map_err(|e| VerifyError::Security(format!("tensor {name}: {e}")))?;
        }

        Ok(header)
    }
}

pub mod gguf {
    //! Parser GGUF.

    use crate::error::VerifyError;
    use std::io::Read;

    /// Magic bytes.
    pub const MAGIC: &[u8; 4] = b"GGUF";

    /// Versão suportada.
    pub const VERSION: u32 = 3;

    /// Header GGUF.
    #[derive(Debug, Clone, Copy)]
    pub struct Header {
        /// Versão.
        pub version: u32,
        /// Número de tensores.
        pub tensor_count: u64,
        /// Número de pares KV.
        pub metadata_kv_count: u64,
    }

    /// Lê o header GGUF.
    ///
    /// # Errors
    ///
    /// Devolve erro se o magic ou versão forem inválidos.
    pub fn parse_header(path: &std::path::Path) -> Result<Header, VerifyError> {
        let mut file = std::fs::File::open(path)?;

        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(VerifyError::Parse("GGUF magic inválido".into()));
        }

        let mut buf4 = [0u8; 4];
        file.read_exact(&mut buf4)?;
        let version = u32::from_le_bytes(buf4);
        if version != VERSION {
            return Err(VerifyError::Parse(format!(
                "GGUF versão não suportada: {version}"
            )));
        }

        let mut buf8 = [0u8; 8];
        file.read_exact(&mut buf8)?;
        let tensor_count = u64::from_le_bytes(buf8);
        file.read_exact(&mut buf8)?;
        let metadata_kv_count = u64::from_le_bytes(buf8);

        if tensor_count > 1_000_000 {
            return Err(VerifyError::LimitExceeded {
                field: "gguf.tensor_count".into(),
                value: tensor_count,
                max: 1_000_000,
            });
        }
        if metadata_kv_count > 1_000_000 {
            return Err(VerifyError::LimitExceeded {
                field: "gguf.metadata_kv_count".into(),
                value: metadata_kv_count,
                max: 1_000_000,
            });
        }

        Ok(Header {
            version,
            tensor_count,
            metadata_kv_count,
        })
    }
}
