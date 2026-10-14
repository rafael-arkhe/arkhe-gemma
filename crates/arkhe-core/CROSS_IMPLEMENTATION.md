# Cross-Implementation Gate

Current implemented direction:

`Independent Python encoder -> checked-in vectors -> Rust verifier/tests`

Before public wire freeze, require:

1. Python -> Rust parity.
2. Rust -> second independent implementation parity.
3. Differential checks against a mature RFC 8949 implementation.
4. Negative vectors for every forbidden encoding.
5. Property/fuzz testing.

`VECTOR_SET_DIGEST.sha256` binds the exact vector set consumed by implementations.
