/**
 * CCS Verifier - Tests
 *
 * Uses Node.js built-in test runner (node:test).
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  Verifier,
  EvidenceCollector,
  PolicyEngine,
  DEFAULT_POLICY,
  canonicalize,
  sha256,
  generateSigningKeyPair,
  createAttestation,
  verifyAttestation,
  createSignedReceipt,
  verifyReceipt,
} from "../src/index";
import type { DeclaredIdentity, RuntimeBehaviorEvidence } from "../src/index";

// ─── Test Fixtures ───────────────────────────────────────────────────────────

function makeDeclaredIdentity(overrides?: Partial<DeclaredIdentity>): DeclaredIdentity {
  return {
    name: "test-mcp-server",
    version: "1.0.0",
    allowedTools: ["read_file", "list_files", "search"],
    allowedEndpoints: ["https://api.example.com", "https://logs.example.com"],
    allowedFilePatterns: ["/workspace/**", "/tmp/*"],
    declaredPermissionScope: "read_write",
    ...overrides,
  };
}

function makeCompliantEvidence(): RuntimeBehaviorEvidence {
  const identity = makeDeclaredIdentity();
  const collector = new EvidenceCollector("server-001", identity, "session-test-001");

  collector
    .recordToolCall("read_file", { path: "/workspace/config.json" })
    .recordToolCall("list_files", { path: "/workspace/src" })
    .recordNetworkRequest("https://api.example.com/v1/data", "GET", 200)
    .recordFileOperation("/workspace/output.txt", "write")
    .recordDataAccess("/workspace/config.json", "read");

  return collector.build();
}

function makeNonCompliantEvidence(): RuntimeBehaviorEvidence {
  const identity = makeDeclaredIdentity();
  const collector = new EvidenceCollector("server-002", identity, "session-test-002");

  collector
    .recordToolCall("read_file", { path: "/workspace/config.json" })
    .recordToolCall("delete_database", { table: "users" })  // Unauthorized tool
    .recordNetworkRequest("https://evil.com/steal", "POST", 200)  // Undeclared endpoint
    .recordFileOperation("/etc/passwd", "read")  // Outside declared patterns
    .recordPermissionEscalation("unrestricted", "need full access");  // Beyond declared scope

  return collector.build();
}

// ─── Canonicalization Tests ──────────────────────────────────────────────────

describe("canonicalize", () => {
  it("should produce deterministic output for objects", () => {
    const a = canonicalize({ b: 2, a: 1 });
    const b = canonicalize({ a: 1, b: 2 });
    assert.equal(a, b);
    assert.equal(a, '{"a":1,"b":2}');
  });

  it("should handle nested objects", () => {
    const result = canonicalize({ z: { b: 2, a: 1 }, a: "hello" });
    assert.equal(result, '{"a":"hello","z":{"a":1,"b":2}}');
  });

  it("should handle arrays", () => {
    const result = canonicalize([3, 1, 2]);
    assert.equal(result, "[3,1,2]");
  });

  it("should handle null and booleans", () => {
    assert.equal(canonicalize(null), "null");
    assert.equal(canonicalize(true), "true");
    assert.equal(canonicalize(false), "false");
  });
});

// ─── SHA-256 Tests ───────────────────────────────────────────────────────────

describe("sha256", () => {
  it("should produce consistent hashes", () => {
    const h1 = sha256("hello world");
    const h2 = sha256("hello world");
    assert.equal(h1, h2);
  });

  it("should produce different hashes for different inputs", () => {
    const h1 = sha256("hello");
    const h2 = sha256("world");
    assert.notEqual(h1, h2);
  });

  it("should produce 64-character hex strings", () => {
    const h = sha256("test");
    assert.equal(h.length, 64);
    assert.match(h, /^[0-9a-f]+$/);
  });
});

// ─── Key Generation Tests ────────────────────────────────────────────────────

describe("generateSigningKeyPair", () => {
  it("should generate a valid key pair", () => {
    const keys = generateSigningKeyPair();
    assert.ok(keys.publicKey);
    assert.ok(keys.privateKey);
    assert.equal(keys.publicKey.length, 64); // 32 bytes = 64 hex chars
    assert.equal(keys.privateKey.length, 64);
  });

  it("should generate unique key pairs", () => {
    const k1 = generateSigningKeyPair();
    const k2 = generateSigningKeyPair();
    assert.notEqual(k1.publicKey, k2.publicKey);
    assert.notEqual(k1.privateKey, k2.privateKey);
  });
});

// ─── Policy Engine Tests ─────────────────────────────────────────────────────

describe("PolicyEngine", () => {
  it("should have 5 default rules", () => {
    const engine = new PolicyEngine();
    const info = engine.getPolicyInfo();
    assert.equal(info.ruleCount, 5);
  });

  it("should pass compliant evidence", () => {
    const engine = new PolicyEngine();
    const evidence = makeCompliantEvidence();
    const results = engine.evaluate(evidence);
    assert.ok(engine.allPassed(results), `Expected all pass but got failures: ${JSON.stringify(engine.failures(results))}`);
  });

  it("should fail non-compliant evidence", () => {
    const engine = new PolicyEngine();
    const evidence = makeNonCompliantEvidence();
    const results = engine.evaluate(evidence);
    const failures = engine.failures(results);
    assert.ok(failures.length > 0, "Expected at least one failure");
  });
});

// ─── Evidence Collector Tests ────────────────────────────────────────────────

describe("EvidenceCollector", () => {
  it("should build evidence with correct structure", () => {
    const identity = makeDeclaredIdentity();
    const collector = new EvidenceCollector("server-001", identity, "session-001");
    collector.recordToolCall("test_tool", { arg: "value" });
    const evidence = collector.build();

    assert.equal(evidence.sessionId, "session-001");
    assert.equal(evidence.serverId, "server-001");
    assert.equal(evidence.events.length, 1);
    assert.equal(evidence.events[0].category, "tool_calls");
    assert.equal(evidence.events[0].sequence, 1);
    assert.ok(evidence.collectionStart);
    assert.ok(evidence.collectionEnd);
  });

  it("should auto-generate session ID if not provided", () => {
    const identity = makeDeclaredIdentity();
    const collector = new EvidenceCollector("server-001", identity);
    const evidence = collector.build();
    assert.ok(evidence.sessionId.startsWith("session-"));
  });

  it("should sequence events correctly", () => {
    const identity = makeDeclaredIdentity();
    const collector = new EvidenceCollector("server-001", identity, "session-seq");
    collector
      .recordToolCall("tool1")
      .recordNetworkRequest("https://example.com", "GET")
      .recordFileOperation("/tmp/test", "read");
    const evidence = collector.build();

    assert.equal(evidence.events[0].sequence, 1);
    assert.equal(evidence.events[1].sequence, 2);
    assert.equal(evidence.events[2].sequence, 3);
  });
});

// ─── Verifier Tests ──────────────────────────────────────────────────────────

describe("Verifier", () => {
  it("should produce PASS verdict for compliant evidence", () => {
    const verifier = new Verifier();
    const evidence = makeCompliantEvidence();
    const verdict = verifier.verify(evidence);

    assert.equal(verdict.status, "PASS");
    assert.equal(verdict.sessionId, evidence.sessionId);
    assert.equal(verdict.serverId, evidence.serverId);
    assert.ok(verdict.evidenceHash);
    assert.ok(verdict.timestamp);
  });

  it("should produce FAIL verdict for non-compliant evidence", () => {
    const verifier = new Verifier();
    const evidence = makeNonCompliantEvidence();
    const verdict = verifier.verify(evidence);

    assert.equal(verdict.status, "FAIL");
    const failedRules = verdict.policyResults.filter((r) => !r.passed);
    assert.ok(failedRules.length > 0);
  });

  it("should fail-closed on incomplete evidence", () => {
    const verifier = new Verifier({ failClosed: true });
    const incomplete = {
      sessionId: "",
      serverId: "server-001",
      declaredIdentity: makeDeclaredIdentity(),
      events: [],
      collectionStart: new Date().toISOString(),
      collectionEnd: new Date().toISOString(),
    } as RuntimeBehaviorEvidence;

    const verdict = verifier.verify(incomplete);
    assert.equal(verdict.status, "FAIL");
  });

  it("should produce CONDITIONAL for minor violations", () => {
    const identity = makeDeclaredIdentity();
    const collector = new EvidenceCollector("server-cond", identity, "session-cond");
    // Only a file pattern violation (CCS-005) — not critical
    collector.recordFileOperation("/var/log/syslog", "read");
    const evidence = collector.build();

    const verifier = new Verifier();
    const verdict = verifier.verify(evidence);
    assert.equal(verdict.status, "CONDITIONAL");
    assert.ok(verdict.conditions);
    assert.ok(verdict.conditions!.length > 0);
  });

  it("should produce FAIL for critical violations (exfiltration)", () => {
    const identity = makeDeclaredIdentity();
    const collector = new EvidenceCollector("server-exfil", identity, "session-exfil");
    collector.recordDataAccess("/secret/data", "export");
    const evidence = collector.build();

    const verifier = new Verifier();
    const verdict = verifier.verify(evidence);
    assert.equal(verdict.status, "FAIL");
  });

  it("should produce FAIL for permission escalation beyond scope", () => {
    const identity = makeDeclaredIdentity({ declaredPermissionScope: "read_only" });
    const collector = new EvidenceCollector("server-esc", identity, "session-esc");
    collector.recordPermissionEscalation("admin", "need write access");
    const evidence = collector.build();

    const verifier = new Verifier();
    const verdict = verifier.verify(evidence);
    assert.equal(verdict.status, "FAIL");
  });
});

// ─── Attestation Tests ───────────────────────────────────────────────────────

describe("Attestation", () => {
  it("should create and verify a signed attestation", () => {
    const verifier = new Verifier();
    const evidence = makeCompliantEvidence();
    const { verdict, attestation } = verifier.verifyAndAttest(evidence);

    assert.equal(verdict.status, "PASS");
    assert.ok(attestation.attestationId);
    assert.ok(attestation.signature);
    assert.ok(attestation.signerPublicKey);
    assert.equal(attestation.version, "1.0");

    // Verify the signature
    const isValid = Verifier.verifyAttestationSignature(attestation);
    assert.ok(isValid, "Attestation signature should be valid");
  });

  it("should detect tampered attestation", () => {
    const verifier = new Verifier();
    const evidence = makeCompliantEvidence();
    const { attestation } = verifier.verifyAndAttest(evidence);

    // Tamper with the attestation
    const tampered = { ...attestation, evidenceHash: "deadbeef" };
    const isValid = Verifier.verifyAttestationSignature(tampered);
    assert.ok(!isValid, "Tampered attestation should fail verification");
  });
});

// ─── Receipt Tests ───────────────────────────────────────────────────────────

describe("Signed Receipt", () => {
  it("should create and verify a SCITT-style receipt", () => {
    const verifier = new Verifier();
    const evidence = makeCompliantEvidence();
    const { verdict, attestation, receipt } = verifier.verifyAndIssueReceipt(evidence);

    assert.equal(verdict.status, "PASS");
    assert.ok(receipt.receiptId);
    assert.ok(receipt.receiptSignature);
    assert.ok(receipt.merkleLeafHash);
    assert.equal(receipt.version, "1.0");

    // Verify the receipt
    const isValid = Verifier.verifyReceiptSignature(receipt);
    assert.ok(isValid, "Receipt signature should be valid");
  });
});

// ─── Default Policy Tests ────────────────────────────────────────────────────

describe("DEFAULT_POLICY", () => {
  it("should have correct metadata", () => {
    assert.equal(DEFAULT_POLICY.policyId, "CCS-DEFAULT-2026-01");
    assert.equal(DEFAULT_POLICY.name, "CCS Default Security Policy");
    assert.equal(DEFAULT_POLICY.version, "1.0.0");
    assert.equal(DEFAULT_POLICY.rules.length, 5);
  });

  it("should have all required rule IDs", () => {
    const ruleIds = DEFAULT_POLICY.rules.map((r) => r.ruleId);
    assert.ok(ruleIds.includes("CCS-001"));
    assert.ok(ruleIds.includes("CCS-002"));
    assert.ok(ruleIds.includes("CCS-003"));
    assert.ok(ruleIds.includes("CCS-004"));
    assert.ok(ruleIds.includes("CCS-005"));
  });
});
