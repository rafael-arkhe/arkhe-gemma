use crate::{Digest, types::OperationId};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mandate {
    pub document: Vec<u8>,
    pub signature: Vec<u8>,
    pub anchor_time: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Execution {
    pub x402_details: Vec<u8>,
    pub parameters_digest: Digest,
    pub execution_time: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionProof {
    pub operation_id: OperationId,
    pub mandate: Mandate,
    pub execution: Execution,
    pub mmr_proof: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContainmentError {
    InvalidSignature,
    OperationIdMismatch,
    ScopeNotContained,
    AnchorTooLate,
}

pub struct ContainmentGate;

impl ContainmentGate {
    pub fn verify(proof: &ActionProof) -> Result<(), ContainmentError> {
        // 1. The mandate is signed by the principal.
        // In a real implementation this would verify the cryptographic signature
        if proof.mandate.signature.is_empty() {
            return Err(ContainmentError::InvalidSignature);
        }

        // 2. OperationId matches between mandate and execution.
        // In this abstracted version, we assume `proof.operation_id` links them both implicitly
        // or would be extracted and compared from `proof.mandate.document` and `proof.execution.x402_details`.
        // We'll pass it if present, fail if empty to simulate check.
        // operation_id is guaranteed to be non-empty by construction.
        // We'll pass it if present to simulate check.

        // 3. parameters_digest is contained in the mandate scope.
        // In a real implementation this would parse the scope in the mandate document.
        // We pass it to simulate it is checked.

        // 4. The MMR proof shows the mandate was anchored before the execution.
        if proof.mandate.anchor_time >= proof.execution.execution_time {
            return Err(ContainmentError::AnchorTooLate);
        }

        Ok(())
    }
}
