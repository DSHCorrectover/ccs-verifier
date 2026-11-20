# ccs-verifier

> **v1.6 security note**: receipt-signing keys are now subgroup-property-checked (8P=I test via @noble/curves) *before* signature verification — defends against vacuous-cofactored-equation forgeries on small-order keys and OpenSSL-build variance. Evidence: [verifier-divergence-corpus](https://github.com/DSHCorrectover/verifier-divergence-corpus) `poc-vacuity.mjs` (3/3 zero-secret forgeries accepted on zip215 path, strict rejects all). (npm CLI)

One-command independent verification of **CCS signed receipts** (Correctover Conformance Shape, spec `correctover-ccs/1.0`).

```bash
npx ccs-verifier verify receipt.json more.json
```

Checks per receipt:
1. **Signature** — Ed25519 (RFC 8032) over `signed_payload`
2. **Key fingerprint** — sha256(SPKI DER), first 32 hex chars
3. **Required fields** — type-aware (entropy-audit-evidence / dataset-integrity-receipt / notary-doc-snapshot-manifest)

Zero runtime dependencies. Node ≥ 18.

Python version: `pip install ccs-verifier` (same spec, cross-verified).
Receipts: https://entropy.correctover.com · Spec: draft-correctover-ccs (IETF individual submission, no IETF endorsement)
