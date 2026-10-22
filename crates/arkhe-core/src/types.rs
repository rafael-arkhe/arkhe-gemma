use crate::{
    digest_canonical, AlgorithmId, CanonicalValue, Digest, DigestError, HashDomain,
    ARKHE_CANONICAL_PROFILE_V1,
};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArtifactId(Vec<u8>);

impl ArtifactId {
    pub const MAX_LENGTH: usize = 256;

    pub fn as_bytes(&self) -> &[u8] { &self.0 }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArtifactError {
    EmptyId,
    IdTooLong { len: usize, max: usize },
}

impl fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyId => write!(f, "artifact id must not be empty"),
            Self::IdTooLong { len, max } => write!(f, "artifact id length {len} exceeds max {max}"),
        }
    }
}
impl std::error::Error for ArtifactError {}

impl TryFrom<Vec<u8>> for ArtifactId {
    type Error = ArtifactError;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(ArtifactError::EmptyId);
        }
        if value.len() > Self::MAX_LENGTH {
            return Err(ArtifactError::IdTooLong { len: value.len(), max: Self::MAX_LENGTH });
        }
        Ok(Self(value))
    }
}

impl TryFrom<&str> for ArtifactId {
    type Error = ArtifactError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_from(value.as_bytes().to_vec())
    }
}


#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OperationId(Vec<u8>);

impl OperationId {
    pub const MAX_LENGTH: usize = 256;

    pub fn as_bytes(&self) -> &[u8] { &self.0 }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperationError {
    EmptyId,
    IdTooLong { len: usize, max: usize },
}

impl fmt::Display for OperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyId => write!(f, "operation id must not be empty"),
            Self::IdTooLong { len, max } => write!(f, "operation id length {len} exceeds max {max}"),
        }
    }
}
impl std::error::Error for OperationError {}

impl TryFrom<Vec<u8>> for OperationId {
    type Error = OperationError;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(OperationError::EmptyId);
        }
        if value.len() > Self::MAX_LENGTH {
            return Err(OperationError::IdTooLong { len: value.len(), max: Self::MAX_LENGTH });
        }
        Ok(Self(value))
    }
}

impl TryFrom<&str> for OperationId {
    type Error = OperationError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_from(value.as_bytes().to_vec())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordId(Vec<u8>);

impl RecordId {
    pub const MAX_LENGTH: usize = 256;

    pub fn as_bytes(&self) -> &[u8] { &self.0 }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordError {
    EmptyId,
    IdTooLong { len: usize, max: usize },
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyId => write!(f, "record id must not be empty"),
            Self::IdTooLong { len, max } => write!(f, "record id length {len} exceeds max {max}"),
        }
    }
}
impl std::error::Error for RecordError {}

impl TryFrom<Vec<u8>> for RecordId {
    type Error = RecordError;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(RecordError::EmptyId);
        }
        if value.len() > Self::MAX_LENGTH {
            return Err(RecordError::IdTooLong { len: value.len(), max: Self::MAX_LENGTH });
        }
        Ok(Self(value))
    }
}

impl TryFrom<&str> for RecordId {
    type Error = RecordError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_from(value.as_bytes().to_vec())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum RelationType {
    DerivedFrom = 1,
    RevisionOf = 2,
    Used = 3,
    GeneratedBy = 4,
    AuthorizedBy = 5,
    ClassifiedAs = 6,
    AttestedBy = 7,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CausalParent {
    pub relation: RelationType,
    pub digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CausalProvenance {
    parents: Vec<CausalParent>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProvenanceError {
    TooManyParents { count: usize, max: usize },
}

impl fmt::Display for ProvenanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyParents { count, max } => write!(f, "causal parent count {count} exceeds max {max}"),
        }
    }
}
impl std::error::Error for ProvenanceError {}

impl CausalProvenance {
    pub const MAX_PARENTS: usize = 64;

    /// Set semantics: duplicates are semantically idempotent.
    pub fn new(mut parents: Vec<CausalParent>) -> Result<Self, ProvenanceError> {
        if parents.len() > Self::MAX_PARENTS {
            return Err(ProvenanceError::TooManyParents {
                count: parents.len(),
                max: Self::MAX_PARENTS,
            });
        }
        parents.sort();
        parents.dedup();
        Ok(Self { parents })
    }

    pub fn empty() -> Self { Self { parents: Vec::new() } }
    pub fn parents(&self) -> &[CausalParent] { &self.parents }

    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Array(
            self.parents
                .iter()
                .map(|p| CanonicalValue::Array(vec![
                    CanonicalValue::Unsigned(p.relation as u16 as u64),
                    digest_value(&p.digest),
                ]))
                .collect(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactEnvelope {
    pub artifact_id: ArtifactId,
    pub digest: Digest,
    pub provenance: CausalProvenance,
    pub authentication: Option<Digest>,
    pub anchor: Option<Digest>,
    pub policy_ref: Digest,
}

impl ArtifactEnvelope {
    pub fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Array(vec![
            CanonicalValue::Unsigned(1),
            CanonicalValue::Bytes(self.artifact_id.as_bytes().to_vec()),
            digest_value(&self.digest),
            self.provenance.to_canonical_value(),
            optional_digest_value(self.authentication.as_ref()),
            optional_digest_value(self.anchor.as_ref()),
            digest_value(&self.policy_ref),
        ])
    }

    pub fn digest(&self, algorithm: AlgorithmId) -> Result<Digest, DigestError> {
        digest_canonical(
            algorithm,
            HashDomain::ArtifactEnvelope,
            ARKHE_CANONICAL_PROFILE_V1,
            &self.to_canonical_value(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TimeEvidence {
    None,
    LocalClock { unix_millis: i64 },
    ExternalRef { kind: u16, evidence_digest: Digest },
}

impl TimeEvidence {
    fn to_canonical_value(&self) -> CanonicalValue {
        match self {
            Self::None => CanonicalValue::Array(vec![CanonicalValue::Unsigned(0)]),
            Self::LocalClock { unix_millis } => CanonicalValue::Array(vec![
                CanonicalValue::Unsigned(1),
                integer_value(*unix_millis),
            ]),
            Self::ExternalRef { kind, evidence_digest } => CanonicalValue::Array(vec![
                CanonicalValue::Unsigned(2),
                CanonicalValue::Unsigned(*kind as u64),
                digest_value(evidence_digest),
            ]),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceRecord {
    pub record_id: RecordId,
    pub envelope_digest: Digest,
    pub timestamp: TimeEvidence,
    pub witness: Option<Digest>,
}

impl EvidenceRecord {
    pub fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Array(vec![
            CanonicalValue::Unsigned(1),
            CanonicalValue::Bytes(self.record_id.as_bytes().to_vec()),
            digest_value(&self.envelope_digest),
            self.timestamp.to_canonical_value(),
            optional_digest_value(self.witness.as_ref()),
        ])
    }

    pub fn digest(&self, algorithm: AlgorithmId) -> Result<Digest, DigestError> {
        digest_canonical(
            algorithm,
            HashDomain::EvidenceRecord,
            ARKHE_CANONICAL_PROFILE_V1,
            &self.to_canonical_value(),
        )
    }
}

fn digest_value(digest: &Digest) -> CanonicalValue {
    CanonicalValue::Array(vec![
        CanonicalValue::Unsigned(digest.algorithm().code() as u64),
        CanonicalValue::Bytes(digest.bytes().to_vec()),
    ])
}

fn optional_digest_value(digest: Option<&Digest>) -> CanonicalValue {
    match digest {
        None => CanonicalValue::Null,
        Some(d) => digest_value(d),
    }
}

fn integer_value(value: i64) -> CanonicalValue {
    if value >= 0 { CanonicalValue::Unsigned(value as u64) }
    else { CanonicalValue::Negative(value) }
}
