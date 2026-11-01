## v0.1 → v0.2 (AKG-META-0001)
- Refutado: "verify_sigstore_bundle devolve Ok(true)" — assinatura não verificada.
- Refutado: "v.len() == 64 aceita qualquer digest" — binding decorativo.
- Corrigido: sigstore-verify = "=0.7.0" com teste de API pinada.
- Estado: execução PENDING.

## Arkhe-B Order Spec v0.1 → v0.2
- Refutado: "canonicalidade Ed25519 exige S/A/R" — faltavam small-order e cofactorless.
- Corrigido: cinco verificações; falsificadores small_order_A e torsion_component_R.
- Fonte: RFC 8032; Rhizomatic.