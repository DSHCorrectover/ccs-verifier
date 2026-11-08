/**
 * CCS Verifier - Runtime Behavior Evidence verification for MCP servers.
 *
 * Implements RFC 9334 Remote Attestation concepts for AI Agent security.
 *
 * @packageDocumentation
 */

// Core classes
export { Verifier, EvidenceCollector, PolicyEngine } from "./verifier";

// Default policy
export { DEFAULT_POLICY } from "./policy";

// Receipt / attestation utilities
export {
  canonicalize,
  sha256,
  hashEvidence,
  generateSigningKeyPair,
  createAttestation,
  verifyAttestation,
  createSignedReceipt,
  verifyReceipt,
} from "./receipt";

// Types
export type {
  EvidenceCategory,
  RuntimeBehaviorEvent,
  RuntimeBehaviorEvidence,
  DeclaredIdentity,
  PermissionScope,
  PolicyCheckResult,
  SecurityPolicy,
  PolicyRule,
  VerdictStatus,
  Verdict,
  Attestation,
  SignedReceipt,
  VerifierConfig,
} from "./types";

export type { KeyPair } from "./receipt";
