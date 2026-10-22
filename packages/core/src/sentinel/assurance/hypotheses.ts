import { randomUUID } from "node:crypto";
import type Database from "better-sqlite3";
import { EngbrainError } from "../../errors.js";
import { requireRole, type Actor } from "../../memory/operators.js";
import { findSecretIn } from "../../memory/records.js";
import { verifyCapability, type Role } from "../capabilities.js";
import { recordTaskAct, assertCanApprove, getTask, type Who } from "../tasks.js";

/**
 * Failure hypotheses ("under a duplicated request, the ledger double-credits") and the per-task target allowlist they are tested against. A hypothesis can only name a target an approver put on
 * the allowlist, and a target can only be a repository fixture or a local process: anything that looks external (URL, host, IP address, absolute or home path) is refused before it is stored.
 * Nothing here runs a test.
 */
export const HYPOTHESIS_FAILURE_MODES = [
  "boundary_input", "malformed_data", "duplicate_request", "concurrent_write", "event_drop", "event_duplicate", "event_reorder", "retry_storm", "db_downtime", "restart", "resource_limit", "auth_privilege"
] as const;
export type FailureMode = (typeof HYPOTHESIS_FAILURE_MODES)[number];
export const HYPOTHESIS_STATUSES = ["proposed", "testing", "refuted", "confirmed", "not_run", "unsupported"] as const;
export type HypothesisStatus = (typeof HYPOTHESIS_STATUSES)[number];
export type TargetKind = "fixture" | "local_process";

/** Legal status moves. `refuted`, `confirmed` and `unsupported` are final. */
export const HYPOTHESIS_MOVES: Readonly<Record<HypothesisStatus, readonly HypothesisStatus[]>> = {
  proposed: ["testing", "not_run", "unsupported"],
  testing: ["refuted", "confirmed", "not_run"],
  not_run: ["testing", "unsupported"],
  refuted: [],
  confirmed: [],
  unsupported: []
};

export interface HypothesisRow { hyp_id: string; task_id: string; failure_mode: FailureMode; statement: string; target: string; invariant_id: string | null; status: HypothesisStatus; proposed_by: string; at: string }
export interface HypothesisInput { failureMode: FailureMode; statement: string; target: string; invariantId?: string }

const PROPOSER_ROLES: readonly Role[] = ["architect", "adversarial_reviewer", "reviewer"];
const STATUS_ROLES: readonly Role[] = ["adversarial_reviewer", "verification_worker", "assurance_controller"];
const clock = (now?: Date): Date => now ?? new Date();

/**
 * A target must be a repository-relative path or a local process name: letters, digits and `. _ - /` only, no `..`, no leading `/` or `~`, and (fail closed, since `example.com/x` and `fixtures/x`
 * cannot otherwise be told apart) a first segment without a dot unless it is a hidden directory. That rejects URLs, `host:port`, IP addresses, host names and absolute paths.
 */
function localTarget(target: string): string {
  const t = target.trim();
  const refuse = (why: string): never => { throw new EngbrainError("POLICY_REFUSED", `the target must be a repository fixture or a local process, not ${why}: ${t.slice(0, 80)}`); };
  if (t.length < 1 || t.length > 200) {
    return refuse("empty or longer than 200 characters");
  }
  if (/^[a-z][a-z0-9+.-]*:/i.test(t) || t.includes("//")) {
    return refuse("a URL");
  }
  if (t.startsWith("/") || t.startsWith("~") || t.includes("\\")) {
    return refuse("an absolute or home path");
  }
  if (!/^[A-Za-z0-9._/-]+$/.test(t)) {
    return refuse("a host, address or path with unexpected characters");
  }
  const segments = t.split("/");
  if (segments.some((s, i) => s === ".." || s === "." || (s === "" && i !== segments.length - 1))) {
    return refuse("a path that leaves the repository");
  }
  const first = segments[0]!;
  if (/^\d+(\.\d+){1,3}$/.test(first)) {
    return refuse("an IP address");
  }
  if (first.includes(".") && !first.startsWith(".")) {
    return refuse("something that looks like a host name (put fixtures under a directory)");
  }
  if (/^localhost$/i.test(first)) {
    return refuse("a host name");
  }
  return t;
}

/** Validates a capability for the task (with one of the roles) against the task's current epoch, and keeps the builder out. */
function capabilityPrincipal(db: Database.Database, storeDir: string, taskId: string, who: Who, roles: readonly Role[], now: Date): { principal: string; role: Role } {
  if (!("capability" in who)) {
    throw new EngbrainError("POLICY_REFUSED", `this step needs a capability of: ${roles.join(", ")}`);
  }
  const payload = verifyCapability(storeDir, who.capability, { now, taskId, roles });
  const task = getTask(db, taskId);
  if (task.cap_epoch !== payload.epoch) {
    throw new EngbrainError("POLICY_REFUSED", "the capability was revoked");
  }
  if (payload.principal === task.builder_principal) {
    throw new EngbrainError("POLICY_REFUSED", "the builder cannot propose or judge hypotheses against its own work");
  }
  return { principal: payload.principal, role: payload.role };
}

/** An approver (not the builder, not anyone who acted as an agent role on the task) puts a local fixture or process on the task's target allowlist. The allowlist is append-only. */
export function allowTarget(db: Database.Database, taskId: string, target: string, kind: TargetKind, actor: Actor, now?: Date): { taskId: string; target: string; kind: TargetKind } {
  requireRole(actor, "approve");
  if (kind !== "fixture" && kind !== "local_process") {
    throw new EngbrainError("POLICY_REFUSED", "a target is a fixture or a local_process");
  }
  const t = localTarget(target);
  return db.transaction(() => {
    assertCanApprove(db, getTask(db, taskId), actor.id);
    if (db.prepare("SELECT 1 FROM sentinel_target_allowlist WHERE task_id = ? AND target = ?").get(taskId, t) !== undefined) {
      throw new EngbrainError("POLICY_REFUSED", "that target is already allowlisted for this task");
    }
    db.prepare("INSERT INTO sentinel_target_allowlist (task_id, target, kind, allowed_by, at) VALUES (?, ?, ?, ?, ?)").run(taskId, t, kind, actor.id, clock(now).toISOString());
    return { taskId, target: t, kind };
  }).immediate();
}

/** Fails closed: refuses any target that looks external or that is not on the task's allowlist. Returns the allowlisted kind. */
export function assertTargetAllowed(db: Database.Database, taskId: string, target: string): TargetKind {
  const t = localTarget(target);
  const row = db.prepare("SELECT kind FROM sentinel_target_allowlist WHERE task_id = ? AND target = ?").get(taskId, t) as { kind: TargetKind } | undefined;
  if (row === undefined) {
    throw new EngbrainError("POLICY_REFUSED", `the target ${t} is not on this task's allowlist`);
  }
  return row.kind;
}

/** An architect, adversarial reviewer or reviewer (never the builder) proposes a failure hypothesis against an allowlisted target, optionally tied to an approved invariant of the same task. */
export function proposeHypothesis(db: Database.Database, storeDir: string, taskId: string, input: HypothesisInput, who: Who, now?: Date): HypothesisRow {
  const at = clock(now);
  if (!HYPOTHESIS_FAILURE_MODES.includes(input.failureMode)) {
    throw new EngbrainError("POLICY_REFUSED", `failure mode must be one of: ${HYPOTHESIS_FAILURE_MODES.join(", ")}`);
  }
  const statement = input.statement.trim();
  if (statement.length < 1 || statement.length > 1000 || /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(statement) || findSecretIn({ statement }) !== null) {
    throw new EngbrainError("POLICY_REFUSED", "a hypothesis is 1-1000 characters without control characters or secrets");
  }
  const id = `hy_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
  return db.transaction((): HypothesisRow => {
    const { principal, role } = capabilityPrincipal(db, storeDir, taskId, who, PROPOSER_ROLES, at);
    recordTaskAct(db, storeDir, taskId, "hypothesis_proposed", principal, role, { failureMode: input.failureMode }, at);
    const target = localTarget(input.target);
    assertTargetAllowed(db, taskId, target);
    if (input.invariantId !== undefined) {
      const inv = db.prepare("SELECT task_id FROM sentinel_invariants WHERE invariant_id = ?").get(input.invariantId) as { task_id: string } | undefined;
      if (inv === undefined || inv.task_id !== taskId) {
        throw new EngbrainError("POLICY_REFUSED", "the hypothesis must refer to an approved invariant of the same task");
      }
    }
    db.prepare("INSERT INTO sentinel_hypotheses (hyp_id, task_id, failure_mode, statement, target, invariant_id, status, proposed_by, at) VALUES (?, ?, ?, ?, ?, ?, 'proposed', ?, ?)")
      .run(id, taskId, input.failureMode, statement, target, input.invariantId ?? null, principal, at.toISOString());
    return db.prepare("SELECT * FROM sentinel_hypotheses WHERE hyp_id = ?").get(id) as HypothesisRow;
  }).immediate();
}

/** Moves a hypothesis along a legal edge (see HYPOTHESIS_MOVES), by an adversarial reviewer, verification worker or assurance controller other than the builder. Entering `testing` re-checks the target. */
export function setHypothesisStatus(db: Database.Database, storeDir: string, hypId: string, status: HypothesisStatus, who: Who, now?: Date): HypothesisRow {
  const at = clock(now);
  if (!HYPOTHESIS_STATUSES.includes(status)) {
    throw new EngbrainError("POLICY_REFUSED", `status must be one of: ${HYPOTHESIS_STATUSES.join(", ")}`);
  }
  return db.transaction((): HypothesisRow => {
    const row = db.prepare("SELECT * FROM sentinel_hypotheses WHERE hyp_id = ?").get(hypId) as HypothesisRow | undefined;
    if (row === undefined) {
      throw new EngbrainError("INVALID_ROOT", "no such hypothesis");
    }
    const acting = capabilityPrincipal(db, storeDir, row.task_id, who, STATUS_ROLES, at);
    if (!HYPOTHESIS_MOVES[row.status].includes(status)) {
      throw new EngbrainError("POLICY_REFUSED", `illegal hypothesis move ${row.status} -> ${status}`);
    }
    if (status === "testing") {
      assertTargetAllowed(db, row.task_id, row.target);
    }
    db.prepare("UPDATE sentinel_hypotheses SET status = ? WHERE hyp_id = ? AND status = ?").run(status, hypId, row.status);
    recordTaskAct(db, storeDir, row.task_id, "hypothesis_decided", acting.principal, acting.role, { hypId, status }, at);
    return db.prepare("SELECT * FROM sentinel_hypotheses WHERE hyp_id = ?").get(hypId) as HypothesisRow;
  }).immediate();
}

/** A task's hypotheses in proposal order, optionally only those in one status. */
export function listHypotheses(db: Database.Database, taskId: string, options: { status?: HypothesisStatus } = {}): HypothesisRow[] {
  return (options.status === undefined
    ? db.prepare("SELECT * FROM sentinel_hypotheses WHERE task_id = ? ORDER BY at, rowid LIMIT 1000").all(taskId)
    : db.prepare("SELECT * FROM sentinel_hypotheses WHERE task_id = ? AND status = ? ORDER BY at, rowid LIMIT 1000").all(taskId, options.status)) as HypothesisRow[];
}
