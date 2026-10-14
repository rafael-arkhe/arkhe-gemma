# Arkhe P0 Foundation v1.2.2

Minimal hardening patch over v1.2.1.

Closed in code:
- bounded `RecordId` newtype;
- conservative `DecoderCostBudget` semantics;
- auxiliary map-key copy accounting;
- clean audit-evidence gate;
- deterministic property-test samples;
- cargo-fuzz target for the strict CBOR decoder.

Still not claimed:
- Cargo.lock pinned in the authoritative Rust workspace;
- Rust build/test/clippy/audit/deny/vet execution;
- fuzz execution;
- ABI freeze.

Status: PRE-BUILD-VERIFIED HARDENED CANDIDATE.
