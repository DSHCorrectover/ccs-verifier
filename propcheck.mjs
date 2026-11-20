// propcheck.mjs — subgroup property check for Ed25519 receipt keys.
// Absorbed from verifier-divergence-corpus v1.1 vacuity theorem (2026-11-20):
// cofactored/zip215 acceptance equations are VACUOUS for small-order keys
// (zero-secret forgery R = s·B − k_used·A accepted for ANY message), and
// node:crypto's own verdict varies with the OpenSSL build. The only sound
// verifier-side defense is an explicit subgroup property test on the key.
// Implementation uses @noble/curves (audited, pinned) — NOT hand-rolled math.
import { ed25519 } from '@noble/curves/ed25519.js';

export function ed25519KeyPropertyCheck(raw32) {
  if (!(raw32 instanceof Uint8Array) || raw32.length !== 32) return { ok: false, reason: 'bad-length' };
  try {
    const P = ed25519.Point.fromBytes(raw32); // strict decode: rejects non-canonical y
    if (P.multiply(8n).equals(ed25519.Point.ZERO)) return { ok: false, reason: 'small-order-key' };
    return { ok: true, reason: 'prime-order-coset' };
  } catch (e) {
    return { ok: false, reason: 'invalid-encoding' }; // non-canonical / off-curve
  }
}
