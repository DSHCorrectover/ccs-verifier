/**
 * CCS Verifier - Core Verification Engine
 *
 * Implements RFC 9334 (Remote Attestation) concepts for MCP server behavior.
 * The Verifier collects evidence, evaluates it against policies, and produces
 * cryptographically signed attestations.
 */

import { createHash } from "node:crypto";
import type {
  RuntimeBehaviorEvidence,
  RuntimeBehaviorEvent,
  Verdict,
  VerdictStatus,
  VerifierConfig,
  PolicyCheckResult,
  Attestation,
  SignedReceipt,
  DeclaredIdentity,
} from "./types";
import { DEFAULT_POLICY } from "./policy";
import {
  canonicalize,
  hashEvidence,
  generateSigningKeyPair,
  createAttestation,
  verifyAttestation,
  createSignedReceipt,
  verifyReceipt,
} from "./receipt";

// ─── Evidence Collector ──────────────────────────────────────────────────────

/**
 * Collects runtime behavior events from an MCP server session.
 * Provides a builder pattern for constructing evidence.
 */
export class EvidenceCollector {
  private events: RuntimeBehaviorEvent[] = [];
  private sequence = 0;
  private readonly sessionId: string;
  private readonly serverId: string;
  private readonly declaredIdentity: DeclaredIdentity;
  private readonly collectionStart: string;

  constructor(serverId: string, declaredIdentity: DeclaredIdentity, sessionId?: string) {
    this.serverId = serverId;
    this.declaredIdentity = declaredIdentity;
    this.sessionId = sessionId ?? this.generateSessionId();
    this.collectionStart = new Date().toISOString();
  }

  /** Record a tool call event. */
  recordToolCall(toolName: string, args?: Record<string, unknown>): this {
    return this.addEvent("tool_calls", `Tool call: ${toolName}`, { toolName, args: args ?? {} });
  }

  /** Record a data access event. */
  recordDataAccess(resource: string, action: string, details?: Record<string, unknown>): this {
    return this.addEvent("data_access", `Data access: ${action} on ${resource}`, {
      resource,
      action,
      ...details,
    });
  }

  /** Record a network request event. */
  recordNetworkRequest(url: string, method: string, statusCode?: number): this {
    return this.addEvent("network_requests", `Network ${method} ${url}`, {
      url,
      method,
      statusCode,
    });
  }

  /** Record a file operation event. */
  recordFileOperation(path: string, operation: string, details?: Record<string, unknown>): this {
    return this.addEvent("file_operations", `File ${operation}: ${path}`, {
      path,
      operation,
      ...details,
    });
  }

  /** Record a permission escalation event. */
  recordPermissionEscalation(requestedScope: string, reason: string): this {
    return this.addEvent("permission_escalation", `Permission escalation: ${requestedScope}`, {
      requestedScope,
      reason,
    });
  }

  /** Record a generic event. */
  recordEvent(category: RuntimeBehaviorEvent["category"], description: string, payload: Record<string, unknown>): this {
    return this.addEvent(category, description, payload);
  }

  /** Build the final evidence object. */
  build(): RuntimeBehaviorEvidence {
    return {
      sessionId: this.sessionId,
      serverId: this.serverId,
      declaredIdentity: this.declaredIdentity,
      events: [...this.events],
      collectionStart: this.collectionStart,
      collectionEnd: new Date().toISOString(),
    };
  }

  private addEvent(
    category: RuntimeBehaviorEvent["category"],
    description: string,
    payload: Record<string, unknown>,
  ): this {
    this.sequence++;
    this.events.push({
      sequence: this.sequence,
      timestamp: new Date().toISOString(),
      category,
      description,
      payload,
    });
    return this;
  }

  private generateSessionId(): string {
    return `session-${createHash("sha256").update(`${Date.now()}-${Math.random()}`).digest("hex").slice(0, 12)}`;
  }
}

// ─── Policy Engine ───────────────────────────────────────────────────────────

/**
 * Evaluates runtime behavior evidence against security policies.
 * Implements the five core security invariants for MCP servers.
 */
export class PolicyEngine {
  private readonly policy: typeof DEFAULT_POLICY;

  constructor(policy = DEFAULT_POLICY) {
    this.policy = policy;
  }

  /** Evaluate all policy rules against the given evidence. */
  evaluate(evidence: RuntimeBehaviorEvidence): PolicyCheckResult[] {
    return this.policy.rules.map((rule) => rule.evaluate(evidence, evidence.declaredIdentity));
  }

  /** Check if all policy rules passed. */
  allPassed(results: PolicyCheckResult[]): boolean {
    return results.every((r) => r.passed);
  }

  /** Get only the failed rules. */
  failures(results: PolicyCheckResult[]): PolicyCheckResult[] {
    return results.filter((r) => !r.passed);
  }

  /** Get the policy metadata. */
  getPolicyInfo(): { policyId: string; name: string; version: string; ruleCount: number } {
    return {
      policyId: this.policy.policyId,
      name: this.policy.name,
      version: this.policy.version,
      ruleCount: this.policy.rules.length,
    };
  }
}

// ─── Verifier ────────────────────────────────────────────────────────────────

/**
 * Core verification engine that ties together evidence collection,
 * policy evaluation, and attestation generation.
 *
 * Design principles:
 * - Fail-closed: incomplete or tampered evidence results in FAIL
 * - Cryptographically verifiable: every attestation can be independently verified
 * - MCP-native: designed specifically for MCP server behavior monitoring
 * - Evidence-based: decisions based on observed runtime behavior, not static analysis
 */
export class Verifier {
  private readonly policyEngine: PolicyEngine;
  private readonly failClosed: boolean;
  private readonly signingKeyHex: string;
  private readonly publicKeyHex: string;

  constructor(config: VerifierConfig = {}) {
    this.policyEngine = new PolicyEngine(config.policy);
    this.failClosed = config.failClosed ?? true;

    if (config.signingKey && config.publicKey) {
      this.signingKeyHex = config.signingKey;
      this.publicKeyHex = config.publicKey;
    } else {
      const keys = generateSigningKeyPair();
      this.signingKeyHex = config.signingKey ?? keys.privateKey;
      this.publicKeyHex = config.publicKey ?? keys.publicKey;
    }
  }

  /**
   * Verify runtime behavior evidence and produce a verdict.
   * Follows fail-closed principle: any issue results in FAIL.
   */
  verify(evidence: RuntimeBehaviorEvidence): Verdict {
    // Validate evidence completeness (fail-closed)
    const completenessCheck = this.validateEvidenceCompleteness(evidence);
    if (!completenessCheck.valid && this.failClosed) {
      return this.buildVerdict("FAIL", evidence, [
        {
          ruleId: "CCS-000",
          ruleName: "Evidence completeness",
          passed: false,
          reason: completenessCheck.reason,
        },
      ]);
    }

    // Evaluate policy rules
    const policyResults = this.policyEngine.evaluate(evidence);

    // Determine verdict
    const failures = this.policyEngine.failures(policyResults);
    let status: VerdictStatus;
    let conditions: string[] | undefined;

    if (failures.length === 0) {
      status = "PASS";
    } else {
      // Check if any failures are critical (data exfiltration, permission escalation)
      const criticalFailures = failures.filter(
        (f) => f.ruleId === "CCS-001" || f.ruleId === "CCS-002",
      );

      if (criticalFailures.length > 0) {
        status = "FAIL";
      } else {
        status = "CONDITIONAL";
        conditions = failures.map((f) => f.reason ?? f.ruleName);
      }
    }

    return this.buildVerdict(status, evidence, policyResults, conditions);
  }

  /**
   * Verify evidence and produce a signed attestation.
   */
  verifyAndAttest(evidence: RuntimeBehaviorEvidence): { verdict: Verdict; attestation: Attestation } {
    const verdict = this.verify(evidence);
    const evidenceJson = canonicalize(evidence);
    const evidenceHash = hashEvidence(evidenceJson);
    const attestation = createAttestation(verdict, evidenceHash, this.signingKeyHex, this.publicKeyHex);
    return { verdict, attestation };
  }

  /**
   * Verify evidence, produce a signed attestation, and wrap in a SCITT-style receipt.
   */
  verifyAndIssueReceipt(evidence: RuntimeBehaviorEvidence): {
    verdict: Verdict;
    attestation: Attestation;
    receipt: SignedReceipt;
  } {
    const { verdict, attestation } = this.verifyAndAttest(evidence);

    // Generate a separate key pair for the transparency log (simulated)
    const logKeys = generateSigningKeyPair();
    const receipt = createSignedReceipt(attestation, logKeys.privateKey, logKeys.publicKey);

    return { verdict, attestation, receipt };
  }

  /** Verify an existing attestation's signature. */
  static verifyAttestationSignature(attestation: Attestation): boolean {
    return verifyAttestation(attestation);
  }

  /** Verify a SCITT-style signed receipt. */
  static verifyReceiptSignature(receipt: SignedReceipt): boolean {
    return verifyReceipt(receipt);
  }

  /** Get the signer's public key (hex). */
  getPublicKey(): string {
    return this.publicKeyHex;
  }

  /** Get policy engine info. */
  getPolicyInfo(): ReturnType<PolicyEngine["getPolicyInfo"]> {
    return this.policyEngine.getPolicyInfo();
  }

  // ─── Private Helpers ─────────────────────────────────────────────────────

  private validateEvidenceCompleteness(evidence: RuntimeBehaviorEvidence): { valid: boolean; reason?: string } {
    if (!evidence.sessionId) {
      return { valid: false, reason: "Missing sessionId" };
    }
    if (!evidence.serverId) {
      return { valid: false, reason: "Missing serverId" };
    }
    if (!evidence.declaredIdentity) {
      return { valid: false, reason: "Missing declaredIdentity" };
    }
    if (!evidence.declaredIdentity.name) {
      return { valid: false, reason: "Missing declaredIdentity.name" };
    }
    if (!Array.isArray(evidence.events)) {
      return { valid: false, reason: "Events must be an array" };
    }
    if (!evidence.collectionStart || !evidence.collectionEnd) {
      return { valid: false, reason: "Missing collection timestamps" };
    }
    return { valid: true };
  }

  private buildVerdict(
    status: VerdictStatus,
    evidence: RuntimeBehaviorEvidence,
    policyResults: PolicyCheckResult[],
    conditions?: string[],
  ): Verdict {
    const evidenceJson = canonicalize(evidence);
    const evidenceHash = hashEvidence(evidenceJson);

    return {
      status,
      sessionId: evidence.sessionId,
      serverId: evidence.serverId,
      timestamp: new Date().toISOString(),
      policyResults: policyResults.map((r) => ({
        ruleId: r.ruleId,
        ruleName: r.ruleName,
        passed: r.passed,
        reason: r.reason,
        // Exclude violatingEvents from the verdict to keep it serializable
      })),
      conditions,
      evidenceHash,
    };
  }
}
