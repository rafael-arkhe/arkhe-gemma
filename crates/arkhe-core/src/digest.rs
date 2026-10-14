use crate::{canonical_bytes, CanonicalError, CanonicalValue};
use sha2::{Digest as ShaDigest, Sha256};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum AlgorithmId {
    Sha256 = 1,
    Blake3_256 = 2,
}

impl AlgorithmId {
    pub fn from_u16(value: u16) -> Result<Self, DigestError> {
        match value {
            1 => Ok(Self::Sha256),
            2 => Ok(Self::Blake3_256),
            other => Err(DigestError::UnsupportedAlgorithm(other)),
        }
    }

    pub const fn code(self) -> u16 { self as u16 }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HashDomain {
    Canonicalization,
    ArtifactEnvelope,
    EvidenceRecord,
    MmrLeaf,
    AuthorizationProof,
}

impl HashDomain {
    pub const fn label(self) -> &'static [u8] {
        match self {
            Self::Canonicalization => b"ARKHE:canonicalization\x00",
            Self::ArtifactEnvelope => b"ARKHE:artifact_envelope\x00",
            Self::EvidenceRecord => b"ARKHE:evidence_record\x00",
            Self::MmrLeaf => b"ARKHE:mmr_leaf\x00",
            Self::AuthorizationProof => b"ARKHE:authorization_proof\x00",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest {
    algorithm: AlgorithmId,
    bytes: [u8; 32],
}

impl Digest {
    pub const fn new(algorithm: AlgorithmId, bytes: [u8; 32]) -> Self {
        Self { algorithm, bytes }
    }

    pub const fn algorithm(&self) -> AlgorithmId { self.algorithm }
    pub const fn bytes(&self) -> &[u8; 32] { &self.bytes }

    pub fn to_tagged_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(34);
        out.extend_from_slice(&self.algorithm.code().to_be_bytes());
        out.extend_from_slice(&self.bytes);
        out
    }

    pub fn from_tagged_bytes(input: &[u8]) -> Result<Self, DigestError> {
        if input.len() != 34 {
            return Err(DigestError::InvalidTaggedLength(input.len()));
        }
        let algorithm = AlgorithmId::from_u16(u16::from_be_bytes([input[0], input[1]]))?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&input[2..]);
        Ok(Self { algorithm, bytes })
    }
}

#[derive(Debug)]
pub enum DigestError {
    UnsupportedAlgorithm(u16),
    InvalidTaggedLength(usize),
    Canonical(CanonicalError),
    ProfileTooLong(usize),
}

impl fmt::Display for DigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAlgorithm(v) => write!(f, "unsupported digest algorithm id {v}"),
            Self::InvalidTaggedLength(v) => write!(f, "invalid tagged digest length {v}, expected 34"),
            Self::Canonical(e) => write!(f, "canonicalization failed: {e}"),
            Self::ProfileTooLong(v) => write!(f, "profile identifier too long: {v}"),
        }
    }
}

impl std::error::Error for DigestError {}
impl From<CanonicalError> for DigestError {
    fn from(value: CanonicalError) -> Self { Self::Canonical(value) }
}

/// Exact bytes, no Arkhe canonicalization. Use for C2PA/RATS/SCITT/etc. evidence.
pub fn digest_raw(algorithm: AlgorithmId, bytes: &[u8]) -> Digest {
    Digest::new(algorithm, hash(algorithm, bytes))
}

/// Arkhe-native structured digest with explicit context and profile separation.
pub fn digest_canonical(
    algorithm: AlgorithmId,
    domain: HashDomain,
    profile: &str,
    value: &CanonicalValue,
) -> Result<Digest, DigestError> {
    let canonical = canonical_bytes(value)?;
    let profile_bytes = profile.as_bytes();
    let profile_len: u16 = profile_bytes
        .len()
        .try_into()
        .map_err(|_| DigestError::ProfileTooLong(profile_bytes.len()))?;

    let mut input = Vec::with_capacity(
        domain.label().len() + 2 + profile_bytes.len() + canonical.len()
    );
    input.extend_from_slice(domain.label());
    input.extend_from_slice(&profile_len.to_be_bytes());
    input.extend_from_slice(profile_bytes);
    input.extend_from_slice(&canonical);

    Ok(Digest::new(algorithm, hash(algorithm, &input)))
}

fn hash(algorithm: AlgorithmId, bytes: &[u8]) -> [u8; 32] {
    match algorithm {
        AlgorithmId::Sha256 => {
            let out = Sha256::digest(bytes);
            let mut result = [0u8; 32];
            result.copy_from_slice(&out);
            result
        }
        AlgorithmId::Blake3_256 => *blake3::hash(bytes).as_bytes(),
    }
}
