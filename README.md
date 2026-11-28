# ccs-verifier
> 🛡️ Part of [Correctover Agent Audit Hub](https://github.com/DSHCorrectover/agent-audit-hub) — open an [Audit Request](https://github.com/DSHCorrectover/agent-audit-hub/issues/new?template=audit-request.yml) or [Data Request](https://github.com/DSHCorrectover/agent-audit-hub/issues/new?template=data-request.yml).


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

## Meta-Verification (L2) — v1.7

"Verification of the verification": if a receipt declares a `meta_verification`
object, the verifier enforces four checks and gates the overall result on them
(receipts without the field keep prior semantics):

1. **judge_diversity** — `judges[]` has >= 2 distinct independent implementations
2. **claim_double_lock** — sha256(claim_text)[:16] equals `claim_digest` (prevents claim substitution)
3. **idempotent_replay** — `replay_digest` equals `claim_digest` (determinism attestation)
4. **min_dependency_surface** — `deps[]` and `axioms[]` declared

Any failed check -> overall FAIL with `meta_verification` details in `detail`.
Method origin: the discipline used to verify the Claude-assisted Riemann
hypothesis proof (multiple independent checkers, claim-text comparison,
idempotent recompilation, minimal axiom surface), productized as a receipt
signing precondition. See `verifier-divergence-corpus/meta-verification/`.
