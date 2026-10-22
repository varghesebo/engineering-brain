import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { chmodSync, existsSync, lstatSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { EngbrainError } from "../errors.js";

/**
 * Operator authorization for memory WRITES. Memory is written only through the CLI by an authenticated operator, never through MCP and never from repository text.
 * An operator is a named principal with roles and a secret token; the store keeps only the SHA-256 of the token (file mode 0600, inside the store directory that is
 * gitignored and refused if tracked). The CLI authenticates from `ENGBRAIN_OPERATOR` + `ENGBRAIN_OPERATOR_TOKEN`.
 * LIMIT (stated, not hidden): this is LOCAL token authentication. It stops an agent that only has MCP or repository text; it does not stop a hostile process running as the same
 * OS user that can read the operator's environment or token. Stronger identity (OS keychain, hardware keys) is out of scope for this build.
 */
export const OPERATOR_FILE = "operators.json";
export type OperatorRole = "propose" | "approve" | "verify" | "admin";
const ROLES = new Set<OperatorRole>(["propose", "approve", "verify", "admin"]);

export interface OperatorRecord { id: string; tokenSha256: string; roles: OperatorRole[]; createdAt: string; createdBy: string }
export interface OperatorPolicy { operators: OperatorRecord[]; distinctApprover: boolean }
export interface Actor { id: string; roles: readonly OperatorRole[] }

const sha = (token: string): string => createHash("sha256").update(token).digest("hex");
const ID = /^[a-z0-9][a-z0-9._-]{0,39}$/;

export function loadOperators(storeDir: string): OperatorPolicy {
  const path = join(storeDir, OPERATOR_FILE);
  if (!existsSync(path)) {
    return { operators: [], distinctApprover: false };
  }
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 65_536) {
    throw new EngbrainError("STORE_UNSAFE_PATH", "operators.json is not a regular file of reasonable size");
  }
  try {
    const doc = JSON.parse(readFileSync(path, "utf8")) as Partial<OperatorPolicy>;
    const operators = (Array.isArray(doc.operators) ? doc.operators : []).filter((o): o is OperatorRecord => typeof o?.id === "string" && typeof o.tokenSha256 === "string" && Array.isArray(o.roles)
      && o.roles.every((r) => ROLES.has(r as OperatorRole)));
    return { operators, distinctApprover: doc.distinctApprover === true };
  } catch {
    throw new EngbrainError("INVALID_CONFIG", "operators.json is not valid");
  }
}

function save(storeDir: string, policy: OperatorPolicy): void {
  const path = join(storeDir, OPERATOR_FILE);
  const temp = `${path}.tmp-${process.pid}`;
  writeFileSync(temp, `${JSON.stringify(policy, null, 2)}\n`, { mode: 0o600, flag: "w" });
  renameSync(temp, path);
  try {
    chmodSync(path, 0o600);
  } catch {
    // not supported on every platform
  }
}

/** Authenticates the operator named in the environment; refuses unknown operators and wrong tokens with one generic message. */
export function authenticate(storeDir: string, env: NodeJS.ProcessEnv): Actor {
  const id = env["ENGBRAIN_OPERATOR"];
  const token = env["ENGBRAIN_OPERATOR_TOKEN"];
  const policy = loadOperators(storeDir);
  const fail = (): never => {
    throw new EngbrainError("POLICY_REFUSED", "memory writes need an authenticated operator: set ENGBRAIN_OPERATOR and ENGBRAIN_OPERATOR_TOKEN (see `engbrain memory operator add`)");
  };
  if (id === undefined || token === undefined) {
    return fail();
  }
  const record = policy.operators.find((o) => o.id === id);
  const expected = Buffer.from(record?.tokenSha256 ?? "0".repeat(64), "hex");
  const given = Buffer.from(sha(token), "hex");
  if (record === undefined || expected.length !== given.length || !timingSafeEqual(expected, given)) {
    return fail();
  }
  return { id: record.id, roles: record.roles };
}

export function requireRole(actor: Actor, role: OperatorRole): void {
  if (!actor.roles.includes(role) && !actor.roles.includes("admin")) {
    throw new EngbrainError("POLICY_REFUSED", `operator ${actor.id} lacks the ${role} role`);
  }
}

/** Serialises changes to operators.json (a concurrent add or revoke must not lose the other's update). A lock older than 30 s is considered abandoned. */
export function withLock<T>(storeDir: string, fn: () => T, file: string = OPERATOR_FILE): T {
  const lock = join(storeDir, `${file}.lock`);
  for (let attempt = 0; ; attempt += 1) {
    try {
      writeFileSync(lock, `${process.pid}\n`, { flag: "wx", mode: 0o600 });
      break;
    } catch {
      try {
        if (Date.now() - statSync(lock).mtimeMs > 30_000) {
          rmSync(lock, { force: true });
          continue;
        }
      } catch {
        continue;
      }
      if (attempt >= 100) {
        throw new EngbrainError("LOCK_TIMEOUT", `${file} is locked by another process`);
      }
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
    }
  }
  try {
    return fn();
  } finally {
    rmSync(lock, { force: true });
  }
}

/**
 * Adds an operator and returns its one-time token. Creating the FIRST operator (who becomes an admin) is an explicit local act that needs `confirmBootstrap`: an agent that merely
 * has a shell cannot stumble into it, though a determined local process still can (see the limit above). Later operators need an authenticated admin.
 */
export function addOperator(storeDir: string, input: { id: string; roles: readonly OperatorRole[]; actor: Actor | null; confirmBootstrap?: boolean; now?: Date }): { id: string; token: string } {
  return withLock(storeDir, () => {
    const policy = loadOperators(storeDir);
    if (!ID.test(input.id)) {
      throw new EngbrainError("INVALID_ROOT", "operator ids are lowercase letters, digits, . _ - (at most 40)");
    }
    if (input.roles.length === 0 || input.roles.some((r) => !ROLES.has(r))) {
      throw new EngbrainError("INVALID_ROOT", "roles must be from: propose, approve, verify, admin");
    }
    if (policy.operators.length > 0 && (input.actor === null || !input.actor.roles.includes("admin"))) {
      throw new EngbrainError("POLICY_REFUSED", "adding an operator needs an authenticated admin");
    }
    if (policy.operators.length === 0 && input.confirmBootstrap !== true) {
      throw new EngbrainError("POLICY_REFUSED", "creating the first operator (an admin who can approve memory) is a deliberate local act: repeat the command with --yes");
    }
    if (policy.operators.some((o) => o.id === input.id)) {
      throw new EngbrainError("POLICY_REFUSED", "that operator already exists");
    }
    const bootstrap = policy.operators.length === 0;
    const token = randomBytes(24).toString("base64url");
    const roles = bootstrap ? [...new Set([...input.roles, "admin" as const])] : [...input.roles];
    policy.operators.push({ id: input.id, tokenSha256: sha(token), roles, createdAt: (input.now ?? new Date()).toISOString(), createdBy: input.actor?.id ?? "bootstrap" });
    save(storeDir, policy);
    return { id: input.id, token };
  });
}

/** Removes an operator (an admin act). The last admin cannot be removed: the store would be left with nobody who can administer it. */
export function revokeOperator(storeDir: string, input: { id: string; actor: Actor }): void {
  requireRole(input.actor, "admin");
  withLock(storeDir, () => {
    const policy = loadOperators(storeDir);
    const target = policy.operators.find((o) => o.id === input.id);
    if (target === undefined) {
      throw new EngbrainError("INVALID_ROOT", "no such operator");
    }
    if (target.roles.includes("admin") && policy.operators.filter((o) => o.roles.includes("admin")).length <= 1) {
      throw new EngbrainError("POLICY_REFUSED", "the last admin cannot be revoked");
    }
    policy.operators = policy.operators.filter((o) => o.id !== input.id);
    save(storeDir, policy);
  });
}

/** Replaces an operator's token (by an admin, or by the operator itself) and returns the new one-time token; the old token stops working immediately. */
export function rotateOperator(storeDir: string, input: { id: string; actor: Actor }): { id: string; token: string } {
  if (input.actor.id !== input.id) {
    requireRole(input.actor, "admin");
  }
  return withLock(storeDir, () => {
    const policy = loadOperators(storeDir);
    const target = policy.operators.find((o) => o.id === input.id);
    if (target === undefined) {
      throw new EngbrainError("INVALID_ROOT", "no such operator");
    }
    const token = randomBytes(24).toString("base64url");
    target.tokenSha256 = sha(token);
    save(storeDir, policy);
    return { id: input.id, token };
  });
}

export function setDistinctApprover(storeDir: string, actor: Actor, value: boolean): void {
  requireRole(actor, "admin");
  withLock(storeDir, () => {
    const policy = loadOperators(storeDir);
    policy.distinctApprover = value;
    save(storeDir, policy);
  });
}
