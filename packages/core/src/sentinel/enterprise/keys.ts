import { createHash, createPublicKey, randomUUID, verify } from "node:crypto";
import type Database from "better-sqlite3";
import { EngbrainError } from "../../errors.js";
import { requireRole, type Actor } from "../../memory/operators.js";

/**
 * Org-approved verifier keys (Sentinel 3E). Only Ed25519 PUBLIC keys are ever stored: anything that looks like private key material is refused before it is parsed, and the stored PEM is
 * re-exported from the parsed public key (so nothing the caller typed beyond the key itself survives). A key is registered by an admin who is not the key's principal, has a hard expiry and can
 * only be revoked (schema triggers refuse any other change and any delete). A signature counts only under an active, unexpired key of the named principal.
 */
export interface VerifierKeyRow { key_id: string; principal: string; algorithm: "ed25519"; public_key_pem: string; key_fingerprint: string; registered_by: string; at: string; not_after: string; status: "active" | "revoked" }

const PRINCIPAL = /^[a-zA-Z0-9._:-]{1,60}$/;
const clock = (now?: Date): Date => now ?? new Date();

export function registerVerifierKey(db: Database.Database, actor: Actor, input: { principal: string; publicKeyPem: string; notAfter: Date | string }, now?: Date): VerifierKeyRow {
  requireRole(actor, "admin");
  if (!PRINCIPAL.test(input.principal)) {
    throw new EngbrainError("POLICY_REFUSED", "a verifier principal is a simple name (letters, digits, . _ : -)");
  }
  if (actor.id === input.principal) {
    throw new EngbrainError("POLICY_REFUSED", "a principal cannot register its own verifier key: a second person registers it");
  }
  if (typeof input.publicKeyPem !== "string" || input.publicKeyPem.length > 2048 || /PRIVATE|ENCRYPTED/i.test(input.publicKeyPem)) {
    throw new EngbrainError("POLICY_REFUSED", "only an Ed25519 PUBLIC key (SPKI PEM) is accepted: private key material is never stored");
  }
  let pem: string;
  let der: Buffer;
  try {
    const key = createPublicKey({ key: input.publicKeyPem, format: "pem" });
    if (key.asymmetricKeyType !== "ed25519") {
      throw new Error("not ed25519");
    }
    pem = key.export({ type: "spki", format: "pem" }).toString();
    der = key.export({ type: "spki", format: "der" });
  } catch {
    throw new EngbrainError("POLICY_REFUSED", "the key is not a valid Ed25519 public key in SPKI PEM form");
  }
  const at = clock(now);
  const notAfter = new Date(input.notAfter);
  if (Number.isNaN(notAfter.getTime()) || notAfter.getTime() <= at.getTime() || notAfter.getTime() - at.getTime() > 2 * 366 * 86_400_000) {
    throw new EngbrainError("POLICY_REFUSED", "a verifier key needs an expiry in the future, at most two years away");
  }
  const row: VerifierKeyRow = {
    key_id: `vk_${randomUUID().replace(/-/g, "").slice(0, 16)}`, principal: input.principal, algorithm: "ed25519", public_key_pem: pem, key_fingerprint: createHash("sha256").update(der).digest("hex"),
    registered_by: actor.id, at: at.toISOString(), not_after: notAfter.toISOString(), status: "active"
  };
  try {
    db.prepare("INSERT INTO sentinel_verifier_keys (key_id, principal, algorithm, public_key_pem, key_fingerprint, registered_by, at, not_after, status) VALUES (@key_id, @principal, @algorithm, @public_key_pem, @key_fingerprint, @registered_by, @at, @not_after, @status)").run(row);
  } catch {
    throw new EngbrainError("POLICY_REFUSED", "that key is already registered");
  }
  return row;
}

/** Admin only. A revoked key never verifies again (a revocation cannot be undone: the schema trigger refuses it). */
export function revokeVerifierKey(db: Database.Database, actor: Actor, keyId: string): void {
  requireRole(actor, "admin");
  if (db.prepare("UPDATE sentinel_verifier_keys SET status = 'revoked' WHERE key_id = ? AND status = 'active'").run(keyId).changes !== 1) {
    throw new EngbrainError("INVALID_ROOT", "no such active verifier key");
  }
}

/** Plain Ed25519 verification. Any malformed key or signature is simply `false`, never an exception. */
export function verifyEd25519(publicKeyPem: string, data: string | Buffer, signatureHex: string): boolean {
  if (typeof signatureHex !== "string" || !/^[0-9a-f]{128}$/i.test(signatureHex)) {
    return false;
  }
  try {
    const key = createPublicKey({ key: publicKeyPem, format: "pem" });
    return key.asymmetricKeyType === "ed25519" && verify(null, typeof data === "string" ? Buffer.from(data, "utf8") : data, key, Buffer.from(signatureHex, "hex"));
  } catch {
    return false;
  }
}

/** The id of the active, unexpired key of `principal` that verifies the signature, or null. */
export function verifyingKey(db: Database.Database, principal: string, data: string | Buffer, signatureHex: string, now?: Date): string | null {
  const at = clock(now).toISOString();
  const keys = db.prepare("SELECT key_id, public_key_pem FROM sentinel_verifier_keys WHERE principal = ? AND status = 'active' AND not_after > ? AND at <= ?").all(principal, at, at) as Array<{ key_id: string; public_key_pem: string }>;
  return keys.find((k) => verifyEd25519(k.public_key_pem, data, signatureHex))?.key_id ?? null;
}

export function signatureValid(db: Database.Database, principal: string, data: string | Buffer, signatureHex: string, now?: Date): boolean {
  return verifyingKey(db, principal, data, signatureHex, now) !== null;
}
