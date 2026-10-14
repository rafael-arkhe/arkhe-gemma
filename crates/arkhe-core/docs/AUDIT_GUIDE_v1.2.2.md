# Audit Guide — Arkhe P0 Foundation v1.2

## Integrity

1. Verify the release ZIP SHA-256 against `arkhe-p0-foundation-v1.2.zip.sha256`.
2. Extract the archive.
3. Verify the full internal manifest with `sha256sum -c ARTIFACT_MANIFEST.sha256`.
4. Verify the exact vector file with `sha256sum -c vectors/VECTOR_SET_DIGEST.sha256`.
5. `FOUNDATION_DIGEST.sha256` is a lineage declaration. It is verifiable only when the predecessor ZIP is separately available.

## Authoritative vector gate

Run:

`python3 scripts/verify_vectors.py`

Do not use undocumented CLI arguments on the reference encoder.

The authoritative vector schema is the checked-in `vectors/canonicalization-v1.1.json`.

## Exact structured digest formula

The code hashes:

`DomainLabel || u16_be(ProfileIdLength) || ProfileId || CanonicalCBOR(Object)`

The domain labels are defined in `src/digest.rs`.

## Rust gate

Standalone release:
1. `cargo generate-lockfile`
2. review the dependency graph
3. commit/pin `Cargo.lock`
4. then run all normal gates with `--locked`

Monorepo integration:
use the authoritative workspace `Cargo.lock`.

Required gates after a lock exists:

- `cargo fmt --check`
- `cargo check --locked --workspace`
- `cargo clippy --locked --workspace --all-targets -- -D warnings`
- `cargo test --locked --workspace`
- `cargo audit`
- `cargo deny check`

## Resource-exhaustion review

The strict decoder enforces bounds before allocation/iteration:
- total input bytes;
- byte-string bytes;
- text-string UTF-8 bytes;
- collection member count;
- nesting depth.

Audit invariant:

`UntrustedCBOR => BoundedMemory ∧ BoundedDepth ∧ BoundedItems`

and:

`DeclaredContainerLength > ProfileLimit => RejectBeforeAllocation`

## Provenance semantics

P0 v1.x freezes causal parents as a mathematical set:
duplicate `(RelationType, Digest)` parents are semantically idempotent.
Multiplicity is not represented.


## v1.2.1 audit corrections

### Vector schema

The authoritative vector fields are:
- `name`
- `semantic`
- `canonical_cbor_hex`
- `sha256_raw_canonical_hex`
- `sha256_structured_canonicalization_hex`
- `sha256_structured_artifact_envelope_hex`
- `sha256_structured_evidence_record_hex`

### Semantic manifest

Verify:
1. `sha256sum -c SEMANTIC_SOURCE_MANIFEST.sha256`
2. `sha256sum -c SEMANTIC_SOURCE_MANIFEST.txt`

### Resource budget

Audit both per-object and cumulative limits. Local limits alone are insufficient.

### cargo-audit

Run `cargo audit` only after the authoritative `Cargo.lock` is pinned.
Do not use an undocumented `cargo audit --locked` gate.


## v1.2.2 audit additions

### Decoder cost semantics
Audit cumulative counters as conservative `DecoderCostBudget`, not exact node counts.
Verify auxiliary map-key copies are charged before allocation.

### RecordId
Verify `RecordId` is a private bounded newtype with non-empty validation and a
256-byte maximum, matching the persistent-identifier invariant.

### Clean audit evidence
Run `python3 scripts/check_clean_audit_evidence.py`.

### Property/fuzz gates
Run normal property tests via `cargo test --locked`.
For fuzzing, install cargo-fuzz and run the `decode_canonical` target for the
project-defined CI budget. Merely shipping a fuzz target is IMPLEMENTED, not VERIFIED.
