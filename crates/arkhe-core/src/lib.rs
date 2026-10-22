#![forbid(unsafe_code)]

pub mod canonical;
pub mod digest;
pub mod authority;
pub mod types;

pub use canonical::{
    canonical_bytes, decode_canonical, decode_canonical_with_limits, CanonicalError, CanonicalValue, DecodeLimits,
};
pub use digest::{
    digest_canonical, digest_raw, AlgorithmId, Digest, DigestError, HashDomain,
};
pub use types::{ArtifactEnvelope, ArtifactError, ArtifactId, CausalParent, CausalProvenance, EvidenceRecord, ProvenanceError, RecordError, RecordId, RelationType, TimeEvidence, OperationId, OperationError};
pub use authority::{Mandate, Execution, ActionProof, ContainmentGate, ContainmentError};

pub const ARKHE_CANONICAL_PROFILE_V1: &str = "arkhe.cbor.det.v1";
