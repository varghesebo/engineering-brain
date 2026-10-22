import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { chmodSync, existsSync, linkSync, lstatSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { EngbrainError } from "../errors.js";
import { requireRole, type Actor } from "../memory/operators.js";

/**
 * Logical orchestrator roles and the capability tokens that carry them. A token is `payload.mac` (HMAC-SHA256 under the controller key in `.engineering-brain/sentinel-key`, 0600), bound to one role,
 * one task, one principal and an expiry. These are LOGICAL roles: one process may play several of them in turn, and no hosted model is required.
 * Limit (documented, not hidden): a process running as the same OS user can read the key file; this separates roles inside the tool's API, it is not an OS security boundary.
 */
export const SENTINEL_KEY_FILE = "sentinel-key";
export const ROLES = ["architect", "builder", "reviewer", "adversarial_reviewer", "verification_worker", "assurance_controller"] as const;
export type Role = (typeof ROLES)[number];

export interface CapabilityPayload { v: 1; role: Role; taskId: string; principal: string; exp: string; epoch: number }

function keyOf(storeDir: string, create: boolean): Buffer {
  const path = join(storeDir, SENTINEL_KEY_FILE);
  if (!existsSync(path)) {
    if (!create) {
      throw new EngbrainError("POLICY_REFUSED", "no controller key exists: no capability or machine evidence has been issued in this store");
    }
    const temp = `${path}.tmp-${process.pid}`;
    writeFileSync(temp, randomBytes(32).toString("hex"), { mode: 0o600 });
    try {
      linkSync(temp, path); // atomic and exclusive: a concurrent reader never sees a partial key
    } catch {
      // another process created it first
    } finally {
      rmSync(temp, { force: true });
    }
  }
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size !== 64) {
    throw new EngbrainError("STORE_UNSAFE_PATH", "the controller key is not a regular 64-character file");
  }
  try {
    chmodSync(path, 0o600);
  } catch {
    // not supported everywhere
  }
  const hex = readFileSync(path, "utf8").trim();
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new EngbrainError("STORE_UNSAFE_PATH", "the controller key is not 64 hexadecimal characters");
  }
  return Buffer.from(hex, "hex");
}

export const controllerKey = (storeDir: string, create = false): Buffer => keyOf(storeDir, create);
export const hmacHex = (storeDir: string, data: string, create = false): string => createHmac("sha256", keyOf(storeDir, create)).update(data).digest("hex");

/** Issued by an authenticated admin operator (the human decides which role may act on which task). */
export function issueCapability(storeDir: string, input: { role: Role; taskId: string; principal: string; ttlSeconds: number; issuer: Actor; /** The task's current capability epoch: revoking capabilities bumps it and kills every older token. */ epoch: number; now?: Date }): string {
  requireRole(input.issuer, "admin");
  if (!ROLES.includes(input.role) || !/^st_[0-9a-f]{16}$/.test(input.taskId) || !/^[a-zA-Z0-9._:-]{1,60}$/.test(input.principal) || !(input.ttlSeconds > 0 && input.ttlSeconds <= 86_400)) {
    throw new EngbrainError("POLICY_REFUSED", "a capability needs a known role, a task id, a simple principal name and a lifetime of at most 24 h");
  }
  const payload: CapabilityPayload = { v: 1, role: input.role, taskId: input.taskId, principal: input.principal, exp: new Date((input.now ?? new Date()).getTime() + input.ttlSeconds * 1000).toISOString(), epoch: input.epoch };
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${body}.${hmacHex(storeDir, body, true)}`;
}

export function verifyCapability(storeDir: string, token: string, options: { now?: Date; taskId?: string; roles?: readonly Role[] } = {}): CapabilityPayload {
  const refuse = (): never => { throw new EngbrainError("POLICY_REFUSED", "the capability token is invalid, expired, or not for this task or role"); };
  const [body, mac, ...rest] = token.split(".");
  if (body === undefined || mac === undefined || rest.length > 0 || !/^[0-9a-f]{64}$/.test(mac)) {
    return refuse();
  }
  const expected = Buffer.from(hmacHex(storeDir, body), "hex");
  if (!timingSafeEqual(expected, Buffer.from(mac, "hex"))) {
    return refuse();
  }
  let payload: CapabilityPayload;
  try {
    payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as CapabilityPayload;
  } catch {
    return refuse();
  }
  if (payload.v !== 1 || !ROLES.includes(payload.role) || new Date(payload.exp).getTime() <= (options.now ?? new Date()).getTime()
    || (options.taskId !== undefined && payload.taskId !== options.taskId) || (options.roles !== undefined && !options.roles.includes(payload.role))) {
    return refuse();
  }
  return payload;
}

/** What each role may move a task into. Approval, policy changes and execution authorization are never reachable with a capability: they need an authenticated operator. */
export const ROLE_TARGETS: Readonly<Record<Role, readonly string[]>> = {
  architect: ["CONTEXT_READY", "SPECIFICATION_READY", "BLOCKED"],
  builder: ["IMPLEMENTING", "IMPLEMENTED", "REPAIRING", "BLOCKED"],
  reviewer: ["FINDINGS_REPORTED", "BLOCKED"],
  adversarial_reviewer: ["FINDINGS_REPORTED", "BLOCKED"],
  verification_worker: ["VERIFYING", "REVERIFYING", "FINDINGS_REPORTED", "ASSURANCE_REVIEW", "BLOCKED"],
  assurance_controller: ["ASSURANCE_REVIEW", "APPROVAL_REQUIRED", "BLOCKED", "FAILED"]
};
