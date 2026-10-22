import { spawn, execFile, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve } from "node:path";
import { promisify } from "node:util";
import type Database from "better-sqlite3";
import { EngbrainError } from "../errors.js";
import { requireRole, type Actor } from "../memory/operators.js";
import { policyHash } from "./policy.js";
import { assertCanApprove, authMac, cancellationHooks, getTask, holdsLease } from "./tasks.js";

const run = promisify(execFile);

/**
 * The execution interface. Authorization to EXECUTE is a separate, explicit, expiring grant from an authenticated operator, bound to the source fingerprint and policy (approval eligibility
 * never implies it). Execution additionally needs a sandbox backend whose capability self-test PASSED on this machine; there is no unsafe fallback. In this phase the only thing that runs is a
 * built-in synthetic worker (fixed internal programs): the interface is real, but this is NOT a promise that arbitrary untrusted repository code can be run safely.
 */
export interface SelfTestResult { verified: boolean; detail: string; checks: Array<{ name: string; passed: boolean; note: string }> }
export interface SandboxBackend {
  name: string;
  /** What the backend confines, stated plainly. */
  confines: string[];
  /** What it does NOT limit. */
  doesNotLimit: string[];
  selfTest(): Promise<SelfTestResult>;
  wrap(command: string, args: string[]): { command: string; args: string[] };
}

const SB_PROFILE = "(version 1)(allow default)(deny file-write*)(deny network*)";
const SB_EXEC = "/usr/bin/sandbox-exec";

/** macOS sandbox-exec (deprecated by Apple but present): denies file writes and network for the child. It is weak confinement and does not limit CPU or memory. */
export const macosSandboxExec: SandboxBackend = {
  name: "macos-sandbox-exec",
  confines: ["file writes (verified by probe)", "network access (in the profile, NOT verified by the probe)"],
  doesNotLimit: ["file reads", "CPU time", "memory", "process count"],
  wrap: (command, args) => ({ command: SB_EXEC, args: ["-p", SB_PROFILE, command, ...args] }),
  async selfTest(): Promise<SelfTestResult> {
    const checks: SelfTestResult["checks"] = [];
    if (process.platform !== "darwin" || !existsSync(SB_EXEC)) {
      return { verified: false, detail: "sandbox-exec is not available on this platform", checks };
    }
    const dir = mkdtempSync(join(tmpdir(), "engbrain-sbprobe-"));
    try {
      const probe = join(dir, "probe");
      const attempt = async (profile: string, name: string): Promise<boolean> => {
        try {
          await run(SB_EXEC, ["-p", profile, "/bin/sh", "-c", `echo x > ${probe}`], { timeout: 5000 });
          return existsSync(probe);
        } catch {
          return false;
        } finally {
          rmSync(probe, { force: true });
          void name;
        }
      };
      const control = await attempt("(version 1)(allow default)", "control");
      checks.push({ name: "positive control: a write succeeds without the deny rule", passed: control, note: control ? "ok" : "the probe could not write even unconfined" });
      const denied = !(await attempt(SB_PROFILE, "deny"));
      checks.push({ name: "a file write is refused under the worker profile", passed: denied, note: denied ? "ok" : "the write went through: no confinement" });
      const verified = control && denied;
      return { verified, detail: verified ? "file-write denial verified by probe; network denial is in the profile but not probed (weak confinement; no CPU/memory limits)" : "the confinement probe failed", checks };
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
};

/** A backend that is never verified: what strict mode sees when no sandbox exists. */
export const noSandbox: SandboxBackend = {
  name: "none", confines: [], doesNotLimit: ["everything"],
  async selfTest() { return { verified: false, detail: "no sandbox backend is available", checks: [] }; },
  wrap: () => { throw new EngbrainError("POLICY_REFUSED", "no verified sandbox: execution is not permitted"); }
};

export async function probeCapabilities(backends: SandboxBackend[] = [macosSandboxExec]): Promise<{ backend: SandboxBackend; result: SelfTestResult }> {
  for (const backend of backends) {
    const result = await backend.selfTest();
    if (result.verified) {
      return { backend, result };
    }
  }
  return { backend: noSandbox, result: await noSandbox.selfTest() };
}

/** Repository path confinement: a path must resolve (after symlinks) inside the root. */
export function confinePath(root: string, candidate: string): string {
  const real = realpathSync(root);
  let full: string;
  try {
    full = realpathSync(isAbsolute(candidate) ? candidate : resolve(real, candidate));
  } catch {
    throw new EngbrainError("POLICY_REFUSED", "the path does not exist inside the repository");
  }
  const rel = relative(real, full);
  if (rel === ".." || rel.startsWith("../") || isAbsolute(rel)) {
    throw new EngbrainError("POLICY_REFUSED", "the path leaves the repository");
  }
  return full;
}

// ---------- authorization ----------

/** States in which running something for the task is meaningful. An authorization from any other state (before a plan exists, or after the work is done) is refused. */
const EXECUTION_STATES = ["PLAN_APPROVED", "IMPLEMENTING", "IMPLEMENTED", "VERIFYING", "REPAIRING", "REVERIFYING"];

export function authorizeExecution(db: Database.Database, storeDir: string, id: string, actor: Actor, currentFingerprint: string, options: { ttlMinutes?: number; maxRuns?: number; now?: Date } = {}): string {
  requireRole(actor, "approve");
  const ttl = options.ttlMinutes ?? 30;
  const runs = options.maxRuns ?? 1;
  if (!(ttl > 0 && ttl <= 60) || !Number.isInteger(runs) || runs < 1 || runs > 10) {
    throw new EngbrainError("POLICY_REFUSED", "an execution authorization lasts at most 60 minutes and allows 1-10 runs (default: one run)");
  }
  const at = options.now ?? new Date();
  return db.transaction((): string => {
    const task = getTask(db, id);
    if (!EXECUTION_STATES.includes(task.state)) {
      throw new EngbrainError("POLICY_REFUSED", `a task in ${task.state} cannot be authorized to execute (only ${EXECUTION_STATES.join(", ")})`);
    }
    assertCanApprove(db, task, actor.id);
    if (currentFingerprint !== task.source_fingerprint) {
      throw new EngbrainError("POLICY_REFUSED", "the source changed since the task's fingerprint: refresh the task first");
    }
    if (task.policy_hash !== policyHash(storeDir)) {
      throw new EngbrainError("POLICY_REFUSED", "the policy changed since the task was created: it must be re-planned");
    }
    const row = { auth_id: `ea_${randomUUID().replace(/-/g, "").slice(0, 16)}`, task_id: id, authorized_by: actor.id, at: at.toISOString(), expires_at: new Date(at.getTime() + ttl * 60_000).toISOString(), source_fingerprint: currentFingerprint, policy_hash: policyHash(storeDir), runs_left: runs, status: "active" };
    db.prepare("INSERT INTO sentinel_exec_auth (auth_id, task_id, authorized_by, at, expires_at, source_fingerprint, policy_hash, runs_left, status, mac) VALUES (@auth_id, @task_id, @authorized_by, @at, @expires_at, @source_fingerprint, @policy_hash, @runs_left, @status, @mac)")
      .run({ ...row, mac: authMac(storeDir, row) });
    return row.auth_id;
  }).immediate();
}

export function revokeExecution(db: Database.Database, storeDir: string, id: string, actor: Actor): void {
  requireRole(actor, "approve");
  for (const a of db.prepare("SELECT * FROM sentinel_exec_auth WHERE task_id = ? AND status = 'active'").all(id) as Array<Record<string, any>>) {
    db.prepare("UPDATE sentinel_exec_auth SET status = 'revoked', mac = ? WHERE auth_id = ?").run(authMac(storeDir, { ...a, status: "revoked" }), a["auth_id"]);
  }
}

export interface Permission { permitted: boolean; reasons: string[]; authId: string | null }
/** Strict by default and only: indexing and MCP never need this; running anything needs ALL of an active, signed, unexpired authorization with runs left, the same source and policy, a live task and a verified sandbox. */
export function executionPermitted(db: Database.Database, storeDir: string, id: string, currentFingerprint: string, sandbox: SelfTestResult, now: Date = new Date()): Permission {
  const reasons: string[] = [];
  const task = getTask(db, id);
  if (!EXECUTION_STATES.includes(task.state)) {
    reasons.push(`the task is ${task.state}`);
  }
  if (!sandbox.verified) {
    reasons.push(`no verified sandbox (${sandbox.detail}): execution is not permitted`);
  }
  const auths = db.prepare("SELECT * FROM sentinel_exec_auth WHERE task_id = ? AND status = 'active' ORDER BY at DESC").all(id) as Array<Record<string, any>>;
  const signed = auths.filter((a) => a["mac"] === authMac(storeDir, a));
  const usable = signed.find((a) => a["runs_left"] > 0 && new Date(a["expires_at"]).getTime() > now.getTime() && a["source_fingerprint"] === currentFingerprint && a["policy_hash"] === policyHash(storeDir) && task.source_fingerprint === currentFingerprint);
  if (auths.length === 0) {
    reasons.push("no active execution authorization");
  } else if (signed.length === 0) {
    reasons.push("the execution authorization failed its integrity check");
  } else if (usable === undefined) {
    reasons.push(signed.every((a) => a["runs_left"] <= 0) ? "the execution authorization is used up" : signed.every((a) => new Date(a["expires_at"]).getTime() <= now.getTime()) ? "the execution authorization expired" : "the source or policy changed since authorization: it is stale");
  }
  return { permitted: reasons.length === 0, reasons, authId: usable?.["auth_id"] ?? null };
}

// ---------- synthetic worker ----------

/** The only programs this phase can run: fixed, internal, and unrelated to repository content. */
export const SYNTHETIC_PROGRAMS = {
  ok: "process.stdout.write('synthetic-ok')",
  sleep: "setTimeout(() => {}, 120000)",
  write_attempt: "try { require('fs').writeFileSync(require('os').tmpdir() + '/engbrain-escape-' + process.pid, 'x'); process.exit(0); } catch { process.exit(7); }"
} as const;
export type SyntheticProgram = keyof typeof SYNTHETIC_PROGRAMS;

const active = new Map<string, Set<ChildProcess>>();
cancellationHooks.push((taskId) => {
  for (const child of active.get(taskId) ?? []) {
    child.kill("SIGKILL");
  }
});

export interface WorkerResult { outcome: "passed" | "failed" | "timed_out" | "cancelled" | "incomplete"; exitCode: number | null; stdout: string; reason: string }

export async function runSyntheticWorker(
  db: Database.Database, storeDir: string, id: string,
  options: { leaseToken: string; program: SyntheticProgram; backend: SandboxBackend; fingerprint: () => string; timeoutMs: number; now?: () => Date }
): Promise<WorkerResult> {
  const now = options.now ?? ((): Date => new Date());
  const task0 = getTask(db, id);
  if (!holdsLease(db, id, options.leaseToken, now())) {
    throw new EngbrainError("POLICY_REFUSED", "only the controller holding the task's lease may execute");
  }
  if (!(options.timeoutMs > 0 && options.timeoutMs <= 600_000) || new Date(task0.lease_expires!).getTime() - now().getTime() < options.timeoutMs) {
    throw new EngbrainError("POLICY_REFUSED", "the timeout must be at most 10 minutes and shorter than the remaining lease");
  }
  const sandbox = await options.backend.selfTest(); // verified here, by the backend itself, never taken from the caller
  const startFingerprint = options.fingerprint();
  // consume one authorized run atomically with the permission check: two racing workers cannot both use the last run
  db.transaction(() => {
    const permission = executionPermitted(db, storeDir, id, startFingerprint, sandbox, now());
    if (!permission.permitted) {
      throw new EngbrainError("POLICY_REFUSED", `execution is not permitted: ${permission.reasons.join("; ")}`);
    }
    const auth = db.prepare("SELECT * FROM sentinel_exec_auth WHERE auth_id = ?").get(permission.authId) as Record<string, any>;
    const used = { ...auth, runs_left: auth["runs_left"] - 1 };
    db.prepare("UPDATE sentinel_exec_auth SET runs_left = ?, mac = ? WHERE auth_id = ?").run(used.runs_left, authMac(storeDir, used), auth["auth_id"]);
  }).immediate();
  const wrapped = options.backend.wrap(process.execPath, ["-e", SYNTHETIC_PROGRAMS[options.program]]);
  const cwd = mkdtempSync(join(tmpdir(), "engbrain-worker-"));
  return await new Promise<WorkerResult>((done) => {
    const child = spawn(wrapped.command, wrapped.args, { cwd, env: {}, stdio: ["ignore", "pipe", "ignore"] });
    const set = active.get(id) ?? new Set<ChildProcess>();
    set.add(child);
    active.set(id, set);
    let stdout = "";
    let timedOut = false;
    child.stdout!.on("data", (b: Buffer) => { if (stdout.length < 4096) { stdout += b.toString("utf8").slice(0, 4096); } });
    const timer = setTimeout(() => { timedOut = true; child.kill("SIGKILL"); }, options.timeoutMs);
    // a cancellation from ANOTHER process (the CLI) only reaches us through the task state: poll it
    const poll = setInterval(() => {
      if (getTask(db, id).state === "CANCELLED") {
        child.kill("SIGKILL");
      }
    }, 200);
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      clearInterval(poll);
      set.delete(child);
      rmSync(cwd, { recursive: true, force: true });
      const after = getTask(db, id);
      const moved = options.fingerprint() !== startFingerprint;
      const cancelled = after.state === "CANCELLED";
      const leaseLost = !holdsLease(db, id, options.leaseToken, now());
      const outcome: WorkerResult["outcome"] = cancelled ? "cancelled" : timedOut ? "timed_out" : moved || leaseLost ? "incomplete" : code === 0 ? "passed" : "failed";
      done({ outcome, exitCode: code, stdout, reason: cancelled ? "the task was cancelled" : timedOut ? "timeout" : moved ? "the working tree changed during the run" : leaseLost ? "the lease was lost during the run" : signal !== null ? `terminated by ${signal}` : `exit ${code}` });
    });
    child.on("error", () => {
      clearTimeout(timer);
      clearInterval(poll);
      rmSync(cwd, { recursive: true, force: true });
      done({ outcome: "incomplete", exitCode: null, stdout, reason: "the worker could not be started" });
    });
  });
}
