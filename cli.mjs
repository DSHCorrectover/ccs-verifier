#!/usr/bin/env node
// ccs-verifier CLI (npm) — verify CCS signed receipts: Ed25519 (RFC8032) + SPKI fingerprint + type-aware fields
// Receipt spec: correctover-ccs/1.0 | deps: Node>=18 built-ins + @noble/curves (audited, pinned — key property check)
import fs from 'node:fs';
import crypto from 'node:crypto';
import { ed25519KeyPropertyCheck } from './propcheck.mjs';

function spkiRaw(pem) {
  const b64 = pem.split(/\r?\n/).filter(l => l && !l.includes('-----')).join('');
  return Buffer.from(b64, 'base64');
}
// v1.7: meta-verification (L2) — "verification of the verification".
// If receipt declares `meta_verification`, all four checks must PASS for overall PASS:
//   1) judge diversity: >=2 distinct independent implementations
//   2) claim double-lock: sha256(claim_text)[:16] === claim_digest (prevents claim substitution)
//   3) idempotent replay: replay_digest === claim_digest (determinism attestation; external re-run is the proof, consistency checked here)
//   4) minimal dependency surface: deps + axioms declared (non-empty)
// Receipts without the field keep v1.6 semantics (backward compatible).
function metaVerificationCheck(j, sha256hex) {
  const mv = j.meta_verification;
  if (!mv) return { performed: false };
  const checks = {};
  checks.judge_diversity = Array.isArray(mv.judges) && mv.judges.length >= 2
    && new Set(mv.judges.map(x => x && x.impl)).size === mv.judges.length;
  checks.claim_double_lock = typeof mv.claim_text === 'string' && mv.claim_text.length > 0
    && typeof mv.claim_digest === 'string'
    && ('sha256:' + sha256hex(mv.claim_text).slice(0, 16)) === mv.claim_digest;
  checks.idempotent_replay = typeof mv.replay_digest === 'string'
    && mv.replay_digest === mv.claim_digest;
  checks.min_dependency_surface = Array.isArray(mv.deps) && mv.deps.length > 0
    && Array.isArray(mv.axioms) && mv.axioms.length > 0;
  const pass = Object.values(checks).every(Boolean);
  return { performed: true, pass, checks };
}

function verifyReceiptFile(path) {
  const r = { file: path.split('/').pop(), result: 'ERROR', detail: null };
  const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');
  try {
    const j = JSON.parse(fs.readFileSync(path, 'utf8'));
    const pubPem = j.verification.public_key;
    const sig = Buffer.from(j.signature, 'base64');
    const payload = Buffer.from(j.signed_payload, 'utf8');
    const der = spkiRaw(pubPem);
    // SPKI DER → raw Ed25519 public key = last 32 bytes
    const rawPub = der.subarray(der.length - 32);
    // v1.6: explicit subgroup property check BEFORE signature verification —
    // defense against vacuous-cofactored-equation forgeries on small-order keys
    // (see verifier-divergence-corpus poc-vacuity.mjs) and OpenSSL-build variance.
    const prop = ed25519KeyPropertyCheck(rawPub);
    const okProp = prop.ok;
    const okSig = crypto.verify(null, payload, crypto.createPublicKey({
      key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), rawPub]),
      format: 'der', type: 'spki',
    }), sig);
    const fp = 'sha256:' + crypto.createHash('sha256').update(der).digest('hex').slice(0, 32);
    const okFp = fp === j.verification.public_key_fingerprint;
    const t = j.type;
    const okF = t === 'entropy-audit-evidence'
      ? !!(j.subject?.package && j.finding?.cve && j.evidence_integrity?.report_sha256)
      : t === 'dataset-integrity-receipt'
        ? !!(j.subject?.dataset && j.integrity?.sha256)
        : !!(j.snapshots && j.day); // notary-doc-snapshot-manifest & structural default
    r.result = okProp && okSig && okFp && okF ? 'PASS' : 'FAIL';
    if (r.result === 'FAIL') r.detail = { key_property: prop, signature: okSig, fingerprint: okFp, fields: okF };
    r.type = t;
    // v1.7 L2: meta-verification, only gates overall result when declared
    const mv = metaVerificationCheck(j, sha256hex);
    if (mv.performed) {
      r.meta_verification = { pass: mv.pass, checks: mv.checks };
      if (!mv.pass) { r.result = 'FAIL'; r.detail = Object.assign(r.detail || {}, { meta_verification: mv.checks }); }
    }
  } catch (e) { r.detail = String(e.message).slice(0, 80); }
  return r;
}
const files = process.argv.slice(2);
if (!files.length) { console.error('usage: ccs-verifier verify <receipt.json> [...]\n       (or: ccs-verifier verify here)'); process.exit(2); }
let passed = 0, failed = 0;
for (const f of files) {
  const r = verifyReceiptFile(f);
  console.log(JSON.stringify(r));
  r.result === 'PASS' ? passed++ : failed++;
}
console.log(`${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
