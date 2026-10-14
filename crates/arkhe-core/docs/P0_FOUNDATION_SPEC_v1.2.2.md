# Arkhe P0 Foundation v1.1 — Executable Candidate

Foundation predecessor digest:

`a6ba64378b18dca30296df7be2d4ccfe06bc636e460a40b2a2ee58e87d808092`

This slice closes the pending items identified during review of the first P0 executable foundation.

## Frozen in this candidate

1. `DigestRaw(algorithm, exact_bytes)` for protocol-defined/raw evidence.
2. Restricted deterministic-CBOR profile for Arkhe-native objects.
3. `Digest = (AlgorithmId, DigestBytes)`.
4. SHA-256 and BLAKE3-256 initial algorithm registry.
5. Explicit hash-domain separation.
6. `ArtifactEnvelope` with 0..N typed causal parents.
7. `EvidenceRecord` with conditional witness evidence.
8. Independent Python vector generation.
9. `VectorSetDigest` binding the exact vector file.
10. Strict canonical decoder for negative/mutation tests.

## Hash domains

The following domain labels are byte-exact and include the trailing NUL byte:

| Context | Domain bytes as UTF-8 |
|---|---|
| Canonicalization | `ARKHE:canonicalization\0` |
| ArtifactEnvelope | `ARKHE:artifact_envelope\0` |
| EvidenceRecord | `ARKHE:evidence_record\0` |
| MMR leaf | `ARKHE:mmr_leaf\0` |
| AuthorizationProof | `ARKHE:authorization_proof\0` |

Structured digest material is:

`domain || u16_be(profile_id_length) || profile_id || CanonicalCBOR(object)`

External/protocol-defined evidence MUST use `DigestRaw` over exact bytes and MUST NOT be silently reserialized.

## Canonicalization rejection requirements

The strict decoder rejects:

- duplicate map keys;
- non-canonical map ordering;
- floating-point values;
- indefinite-length items;
- non-shortest integer/length encodings;
- invalid UTF-8 text strings;
- CBOR tags in v1;
- unsupported simple values;
- trailing bytes.

## ABI status

The conceptual contracts are frozen. This is still an **executable candidate**, not a frozen public ABI or wire/API v1.

Rust build verification remains a repository gate.


## v1.2 hardening addendum

### Normative resource limits

Default decoder profile:

- `MAX_INPUT_BYTES = 1 MiB`
- `MAX_BSTR_BYTES = 512 KiB`
- `MAX_TSTR_UTF8_BYTES = 512 KiB`
- `MAX_COLLECTION_MEMBERS = 4096`
- `MAX_NESTING_DEPTH = 64`

All definite-length bounds MUST be checked before allocation or iteration.

### Provenance multiplicity

`CausalProvenance` is a set of typed parents in P0 v1.x.
Duplicate `(RelationType, Digest)` pairs are semantically idempotent.

### Release reproducibility

Release ZIPs are built deterministically from sorted files using:
- fixed timestamps derived from `SOURCE_DATE_EPOCH`;
- normalized Unix permissions;
- no runtime caches (`__pycache__`, `.pyc`);
- stable archive ordering.

`ReleaseArtifactDigest` identifies the exact ZIP.
`SemanticSourceManifestDigest` identifies the semantic source contents independent of ZIP metadata.


## v1.2.1 hardening addendum

This patch does not alter the P0 architecture.

### Cumulative resource budget

The decoder now enforces both per-object limits and cumulative budgets:

- `MAX_TOTAL_ITEMS = 16384`
- `MAX_ALLOCATION_BYTES = 2 MiB`
- `MAX_PREALLOC_MEMBERS = 1024`

Declared collection costs are charged before eager allocation/iteration.

Normative invariant:

`UntrustedCBOR => BoundedMemory ∧ BoundedDepth ∧ BoundedItems`

### Semantic type bounds

- `ArtifactId::MAX_LENGTH = 256 bytes`
- `CausalProvenance::MAX_PARENTS = 64`

These are enforced in constructors/newtypes, independently from generic CBOR limits.

### Provenance semantics

Causal parent multiplicity has no meaning in P0 v1.x.
The type constructor sorts and deduplicates parents, giving mathematical-set semantics.


## v1.2.2 minimal hardening addendum

This patch does not alter the P0 architecture.

### DecoderCostBudget

The cumulative budget is normative as a conservative implementation-cost budget,
not as an exact decoded-node count. Charging MAY conservatively exceed exact heap
usage. Security depends on rejecting before allocation when declared cost exceeds
the remaining budget.

Default cost limits:
- `MAX_ITEM_COST = 16384`
- `MAX_ALLOCATION_COST_BYTES = 2 MiB`
- `MAX_PREALLOC_MEMBERS = 1024`

Auxiliary map-key copies are charged to allocation cost before copying.

### Persistent identifier invariant

`PersistentIdentifier => BoundedValidatedNewtype`

Both `ArtifactId` and `RecordId` have:
- non-empty validation;
- `MAX_LENGTH = 256 bytes`;
- private inner representation;
- `TryFrom` construction.

### Verification status vocabulary

- IMPLEMENTED: code exists.
- VERIFIED: the relevant gate executed successfully against the identified snapshot.
- BUILD-VERIFIED: authoritative lock is pinned and Rust build gate passes.

Property-test samples and cargo-fuzz targets are included. Fuzzing remains PENDING
until executed in a Rust environment.
