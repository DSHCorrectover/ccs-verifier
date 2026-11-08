/**
 * CCS Verifier - Type Definitions
 *
 * Core interfaces and types for runtime behavior evidence collection,
 * cryptographic attestation, and policy-based verdict generation.
 * Aligned with RFC 9334 (Remote Attestation Procedures) concepts.
 */

// ─── Evidence Types ──────────────────────────────────────────────────────────

/** The categories of runtime behavior that can be observed and attested. */
export type EvidenceCategory =
  | "tool_calls"
  | "data_access"
  | "network_requests"
  | "file_operations"
  | "permission_escalation";

/** A single observed runtime behavior event from an MCP server session. */
export interface RuntimeBehaviorEvent {
  /** Monotonically increasing sequence number within the session. */
  sequence: number;
  /** ISO 8601 timestamp of when the event was observed. */
  timestamp: string;
  /** The category of behavior observed. */
  category: EvidenceCategory;
  /** Human-readable description of the event. */
  description: string;
  /** Structured payload specific to the category. */
  payload: Record<string, unknown>;
}

/** Complete evidence collected from an MCP server session. */
export interface RuntimeBehaviorEvidence {
  /** Unique identifier for this evidence collection session. */
  sessionId: string;
  /** Identifier for the MCP server being attested. */
  serverId: string;
  /** Declared identity/capabilities of the MCP server. */
  declaredIdentity: DeclaredIdentity;
  /** Ordered list of observed runtime behavior events. */
  events: RuntimeBehaviorEvent[];
  /** ISO 8601 timestamp when evidence collection started. */
  collectionStart: string;
  /** ISO 8601 timestamp when evidence collection ended. */
  collectionEnd: string;
}

/** What an MCP server declares about itself before runtime. */
export interface DeclaredIdentity {
  /** Unique name of the MCP server. */
  name: string;
  /** Version string. */
  version: string;
  /** Set of tools the server declares it may call. */
  allowedTools: string[];
  /** Set of network endpoints the server declares it may contact. */
  allowedEndpoints: string[];
  /** Set of file paths/patterns the server declares it may access. */
  allowedFilePatterns: string[];
  /** Maximum permission scope the server declares it needs. */
  declaredPermissionScope: PermissionScope;
}

/** Permission scope levels for MCP server operations. */
export type PermissionScope = "read_only" | "read_write" | "admin" | "unrestricted";

// ─── Policy Types ────────────────────────────────────────────────────────────

/** Result of evaluating a single policy rule. */
export interface PolicyCheckResult {
  /** Identifier of the policy rule. */
  ruleId: string;
  /** Human-readable name of the rule. */
  ruleName: string;
  /** Whether this rule passed. */
  passed: boolean;
  /** Reason for failure, if applicable. */
  reason?: string;
  /** Specific events that violated the rule. */
  violatingEvents?: RuntimeBehaviorEvent[];
}

/** A complete security policy to evaluate evidence against. */
export interface SecurityPolicy {
  /** Unique identifier for this policy. */
  policyId: string;
  /** Human-readable name. */
  name: string;
  /** Version of the policy. */
  version: string;
  /** Individual rules that make up this policy. */
  rules: PolicyRule[];
}

/** A single policy rule definition. */
export interface PolicyRule {
  /** Unique identifier for this rule. */
  ruleId: string;
  /** Human-readable name. */
  ruleName: string;
  /** The category of evidence this rule inspects. */
  category: EvidenceCategory | "all";
  /** Evaluation function: returns true if the evidence passes. */
  evaluate: (evidence: RuntimeBehaviorEvidence, declared: DeclaredIdentity) => PolicyCheckResult;
}

// ─── Verdict Types ───────────────────────────────────────────────────────────

/** The possible verdict outcomes from verification. */
export type VerdictStatus = "PASS" | "FAIL" | "CONDITIONAL";

/** The final verdict produced by the verifier. */
export interface Verdict {
  /** The verdict status. */
  status: VerdictStatus;
  /** The session that was verified. */
  sessionId: string;
  /** The server that was verified. */
  serverId: string;
  /** ISO 8601 timestamp of when the verdict was issued. */
  timestamp: string;
  /** Individual policy check results. */
  policyResults: PolicyCheckResult[];
  /** Conditions that must be met for a CONDITIONAL verdict. */
  conditions?: string[];
  /** Hash of the evidence that was verified. */
  evidenceHash: string;
}

// ─── Attestation / Receipt Types ─────────────────────────────────────────────

/** A signed attestation binding a verdict to evidence. */
export interface Attestation {
  /** Version of the attestation format. */
  version: "1.0";
  /** Unique identifier for this attestation. */
  attestationId: string;
  /** The verdict being attested. */
  verdict: Verdict;
  /** SHA-256 hash of the canonical evidence JSON. */
  evidenceHash: string;
  /** Ed25519 signature over the attestation payload. */
  signature: string;
  /** Public key (hex) of the signer. */
  signerPublicKey: string;
  /** ISO 8601 timestamp of attestation creation. */
  createdAt: string;
}

/** SCITT-style signed receipt for an attestation. */
export interface SignedReceipt {
  /** Receipt format version. */
  version: "1.0";
  /** Unique receipt identifier. */
  receiptId: string;
  /** The attestation this receipt covers. */
  attestation: Attestation;
  /** Ed25519 signature over the receipt payload (by the transparency log). */
  receiptSignature: string;
  /** Public key (hex) of the receipt issuer (transparency log). */
  receiptIssuerPublicKey: string;
  /** ISO 8601 timestamp of receipt issuance. */
  issuedAt: string;
  /** Merkle leaf hash for inclusion in a transparency log. */
  merkleLeafHash: string;
}

// ─── Verifier Configuration ──────────────────────────────────────────────────

/** Configuration options for the Verifier. */
export interface VerifierConfig {
  /** The security policy to use. Defaults to the built-in default policy. */
  policy?: SecurityPolicy;
  /** Whether to fail-closed on incomplete evidence. Default: true. */
  failClosed?: boolean;
  /** Ed25519 private key (hex) for signing. Auto-generated if not provided. */
  signingKey?: string;
  /** Ed25519 public key (hex) for verification. Derived from signingKey if not provided. */
  publicKey?: string;
}
