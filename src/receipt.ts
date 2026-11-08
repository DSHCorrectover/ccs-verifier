/**
 * CCS Verifier - SCITT-style Signed Receipt Generation
 *
 * Implements JSON Canonicalization (RFC 8785) and Ed25519 signing
 * to produce verifiable receipts suitable for a SCITT transparency log.
 */

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import type { Attestation, SignedReceipt, Verdict } from "./types";

// ─── JSON Canonicalization (JCS - RFC 8785 subset) ──────────────────────────

/**
 * Canonicalize a JSON value per RFC 8785 (JCS).
 * Keys sorted lexicographically, no whitespace, proper escaping.
 */
export function canonicalize(value: unknown): string {
  if (value === null || value === undefined) {
    return "null";
  }
  if (typeof value === "boolean" || typeof value === "number") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    const items = value.map((item) => canonicalize(item));
    return `[${items.join(",")}]`;
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const pairs = keys.map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`);
    return `{${pairs.join(",")}}`;
  }
  throw new Error(`Cannot canonicalize value of type ${typeof value}`);
}

// ─── Hashing ─────────────────────────────────────────────────────────────────

/** Compute SHA-256 hash of a string, returned as hex. */
export function sha256(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

/** Compute SHA-256 hash of evidence for binding. */
export function hashEvidence(evidenceJson: string): string {
  return sha256(evidenceJson);
}

// ─── Key Management ──────────────────────────────────────────────────────────

export interface KeyPair {
  publicKey: string;  // hex
  privateKey: string; // hex
}

/** Generate an Ed25519 key pair for signing attestations. */
export function generateSigningKeyPair(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");

  const pubDer = publicKey.export({ type: "spki", format: "der" });
  const privDer = privateKey.export({ type: "pkcs8", format: "der" });

  // Ed25519 raw public key is last 32 bytes of SPKI DER
  const pubRaw = pubDer.subarray(pubDer.length - 32);
  // Ed25519 raw private key is bytes 16..48 of PKCS8 DER
  const privRaw = privDer.subarray(16, 48);

  return {
    publicKey: pubRaw.toString("hex"),
    privateKey: privRaw.toString("hex"),
  };
}

/** Create a crypto.KeyObject from raw Ed25519 private key bytes (hex). */
export function privateKeyObject(hex: string): import("node:crypto").KeyObject {
  const rawKey = Buffer.from(hex, "hex");
  // PKCS8 DER prefix for Ed25519: 302e020100300506032b657004220420
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  const der = Buffer.concat([prefix, rawKey]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

/** Create a crypto.KeyObject from raw Ed25519 public key bytes (hex). */
export function publicKeyObject(hex: string): import("node:crypto").KeyObject {
  const rawKey = Buffer.from(hex, "hex");
  // SPKI DER prefix for Ed25519: 302a300506032b6570032100
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  const der = Buffer.concat([prefix, rawKey]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

// ─── Signing ─────────────────────────────────────────────────────────────────

/** Sign data with an Ed25519 private key, returning hex signature. */
export function signData(data: string, privateKeyHex: string): string {
  const keyObj = privateKeyObject(privateKeyHex);
  const sig = sign(null, Buffer.from(data, "utf8"), keyObj);
  return sig.toString("hex");
}

/** Verify an Ed25519 signature. */
export function verifySignature(
  data: string,
  signatureHex: string,
  publicKeyHex: string,
): boolean {
  const keyObj = publicKeyObject(publicKeyHex);
  return verify(
    null,
    Buffer.from(data, "utf8"),
    keyObj,
    Buffer.from(signatureHex, "hex"),
  );
}

// ─── Attestation Generation ──────────────────────────────────────────────────

/** Generate a unique identifier. */
function generateId(prefix: string): string {
  const random = createHash("sha256")
    .update(`${Date.now()}-${Math.random()}`)
    .digest("hex")
    .slice(0, 16);
  return `${prefix}-${random}`;
}

/** Create a signed attestation for a verdict. */
export function createAttestation(
  verdict: Verdict,
  evidenceHash: string,
  privateKeyHex: string,
  publicKeyHex: string,
): Attestation {
  const attestationId = generateId("att");
  const createdAt = new Date().toISOString();

  // Build the payload to sign (canonical JSON of the attestation without signature)
  const payload = canonicalize({
    attestationId,
    verdict,
    evidenceHash,
    createdAt,
  });

  const signature = signData(payload, privateKeyHex);

  return {
    version: "1.0",
    attestationId,
    verdict,
    evidenceHash,
    signature,
    signerPublicKey: publicKeyHex,
    createdAt,
  };
}

/** Verify an attestation's signature. */
export function verifyAttestation(attestation: Attestation): boolean {
  const payload = canonicalize({
    attestationId: attestation.attestationId,
    verdict: attestation.verdict,
    evidenceHash: attestation.evidenceHash,
    createdAt: attestation.createdAt,
  });

  return verifySignature(payload, attestation.signature, attestation.signerPublicKey);
}

// ─── SCITT-style Signed Receipt ──────────────────────────────────────────────

/** Create a SCITT-style signed receipt for an attestation. */
export function createSignedReceipt(
  attestation: Attestation,
  logPrivateKeyHex: string,
  logPublicKeyHex: string,
): SignedReceipt {
  const receiptId = generateId("rcpt");
  const issuedAt = new Date().toISOString();

  // Merkle leaf hash: hash of the canonical attestation
  const attestationCanonical = canonicalize(attestation);
  const merkleLeafHash = sha256(attestationCanonical);

  // Receipt payload
  const receiptPayload = canonicalize({
    receiptId,
    attestation,
    merkleLeafHash,
    issuedAt,
  });

  const receiptSignature = signData(receiptPayload, logPrivateKeyHex);

  return {
    version: "1.0",
    receiptId,
    attestation,
    receiptSignature,
    receiptIssuerPublicKey: logPublicKeyHex,
    issuedAt,
    merkleLeafHash,
  };
}

/** Verify a signed receipt. */
export function verifyReceipt(receipt: SignedReceipt): boolean {
  // First verify the inner attestation
  if (!verifyAttestation(receipt.attestation)) {
    return false;
  }

  // Then verify the receipt signature
  const receiptPayload = canonicalize({
    receiptId: receipt.receiptId,
    attestation: receipt.attestation,
    merkleLeafHash: receipt.merkleLeafHash,
    issuedAt: receipt.issuedAt,
  });

  return verifySignature(receiptPayload, receipt.receiptSignature, receipt.receiptIssuerPublicKey);
}
