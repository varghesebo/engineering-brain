import { createHash, randomBytes, randomUUID } from "node:crypto";
import type Database from "better-sqlite3";
import { EngbrainError } from "../errors.js";
import { requireRole, type Actor } from "../memory/operators.js";
import { findSecretIn } from "../memory/records.js";
import { showEvidence } from "../evidence/store.js";
import { controllerKey, hmacHex, ROLE_TARGETS, verifyCapability, type Role } from "./capabilities.js";
import { effectiveProfile, policyHash, PROFILES, requiredChecks, type Profile } from "./policy.js";

/**
 * Sentinel task state machine. Everything durable lives in the one store: task rows, a hash-chained and MAC-protected event log, a hash-chained and MAC-protected evidence log, approvals and
 * execution authorizations bound to a source fingerprint and a policy hash, and a MAC "seal" over each task's state and log heads (so a raw edit of the state, or truncating a log, is detected).
 * Every state change is one immediate transaction that also checks the revision the caller saw. ELIGIBLE_FOR_APPROVAL means "every mandatory check has current, trusted, passing evidence and
 * the required human approvals are recorded": it grants NO permission to execute, merge or release.
 *
 * Trust boundary (stated, not hidden): the MAC key is a 0600 file owned by the same OS user, and the functions below take the repository fingerprint from their (trusted) caller. Roles and
 * checks separate duties inside this API; they are not an OS security boundary.
 */
export const STATES = [
  "CREATED", "CONTEXT_READY", "SPECIFICATION_READY", "PLAN_APPROVED", "IMPLEMENTING", "IMPLEMENTED", "VERIFYING", "FINDINGS_REPORTED", "REPAIRING", "REVERIFYING", "ASSURANCE_REVIEW",
  "APPROVAL_REQUIRED", "ELIGIBLE_FOR_APPROVAL", "BLOCKED", "FAILED", "CANCELLED"
] as const;
export type TaskState = (typeof STATES)[number];
const TERMINAL: readonly TaskState[] = ["FAILED", "CANCELLED"];
const ESCAPES: TaskState[] = ["BLOCKED", "FAILED", "CANCELLED"];

/** Legal transitions. Anything not listed is refused. */
export const LEGAL: Readonly<Record<TaskState, readonly TaskState[]>> = {
  CREATED: ["CONTEXT_READY", ...ESCAPES],
  CONTEXT_READY: ["SPECIFICATION_READY", ...ESCAPES],
  SPECIFICATION_READY: ["PLAN_APPROVED", ...ESCAPES],
  PLAN_APPROVED: ["IMPLEMENTING", ...ESCAPES],
  IMPLEMENTING: ["IMPLEMENTED", ...ESCAPES],
  IMPLEMENTED: ["VERIFYING", ...ESCAPES],
  VERIFYING: ["FINDINGS_REPORTED", "ASSURANCE_REVIEW", ...ESCAPES],
  FINDINGS_REPORTED: ["REPAIRING", ...ESCAPES],
  REPAIRING: ["REVERIFYING", ...ESCAPES],
  REVERIFYING: ["FINDINGS_REPORTED", "ASSURANCE_REVIEW", ...ESCAPES],
  ASSURANCE_REVIEW: ["APPROVAL_REQUIRED", ...ESCAPES],
  APPROVAL_REQUIRED: ["ELIGIBLE_FOR_APPROVAL", ...ESCAPES],
  ELIGIBLE_FOR_APPROVAL: ["APPROVAL_REQUIRED", ...ESCAPES],
  BLOCKED: ["CONTEXT_READY", "FAILED", "CANCELLED"],
  FAILED: [],
  CANCELLED: []
};

export const SENTINEL_LIMITS = { tasks: 10_000, eventsPerTask: 5000, evidencePerTask: 5000, queuedPerTask: 500, reason: 500 } as const;

export interface TaskRow {
  task_id: string; created_at: string; requester: string; title: string; state: TaskState; revision: number; profile: Profile; policy_hash: string; source_fingerprint: string; worktree_id: string | null;
  scope_json: string; requirements_json: string; components_json: string; builder_principal: string | null; budgets_json: string; blocked_reason: string | null; claimed_by: string | null;
  lease_expires: string | null; lease_hash: string | null; base_revision: string | null; cap_epoch: number; seal: string; checkpoint_json: string | null; updated_at: string;
}

export type Who = { operator: Actor } | { capability: string };
interface Resolved { principal: string; role: Role | null; operator: Actor | null }

const clock = (now?: Date): Date => now ?? new Date();
const sha = (s: string): string => createHash("sha256").update(s).digest("hex");
const text = (v: string, max: number, what: string): string => {
  const t = v.trim();
  if (t.length < 1 || t.length > max || /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(t)) {
    throw new EngbrainError("POLICY_REFUSED", `${what} must be 1-${max} characters without control or invisible formatting characters`);
  }
  return t;
};
const safeScope = (p: string): string => {
  const t = text(p, 500, "scope path");
  if (t.startsWith("/") || t.includes("\\") || t.split("/").some((s, i, all) => s === ".." || (s === "" && i !== all.length - 1))) {
    throw new EngbrainError("POLICY_REFUSED", `scope paths are repository-relative and cannot leave the repository: ${t}`);
  }
  return t;
};

/** Validates a capability or an operator AND that the capability is for this task and has not been revoked (epoch). */
function resolveWho(db: Database.Database, storeDir: string, who: Who, taskId: string, now: Date, roles?: readonly Role[]): Resolved {
  if ("operator" in who) {
    if (roles !== undefined) {
      throw new EngbrainError("POLICY_REFUSED", "this step needs an orchestrator capability, not an operator");
    }
    return { principal: who.operator.id, role: null, operator: who.operator };
  }
  const payload = verifyCapability(storeDir, who.capability, { now, taskId, ...(roles === undefined ? {} : { roles }) });
  if (getTask(db, taskId).cap_epoch !== payload.epoch) {
    throw new EngbrainError("POLICY_REFUSED", "the capability was revoked");
  }
  return { principal: payload.principal, role: payload.role, operator: null };
}

export function getTask(db: Database.Database, id: string): TaskRow {
  const row = db.prepare("SELECT * FROM sentinel_tasks WHERE task_id = ?").get(id) as TaskRow | undefined;
  if (row === undefined) {
    throw new EngbrainError("INVALID_ROOT", "no such task");
  }
  return row;
}

const genesis = (taskId: string): string => sha(`genesis:${taskId}`);
const eventHash = (e: { prev: string; taskId: string; at: string; kind: string; from: string | null; to: string | null; actor: string; role: string | null; revision: number; payload: string }): string =>
  sha(JSON.stringify([e.prev, e.taskId, e.at, e.kind, e.from, e.to, e.actor, e.role, e.revision, e.payload]));

const heads = (db: Database.Database, id: string): { event: string; evidence: string; events: number; evidenceRows: number } => {
  const e = db.prepare("SELECT hash, (SELECT COUNT(*) FROM sentinel_task_events WHERE task_id = ?) AS n FROM sentinel_task_events WHERE task_id = ? ORDER BY seq DESC LIMIT 1").get(id, id) as { hash: string; n: number } | undefined;
  const v = db.prepare("SELECT hash, (SELECT COUNT(*) FROM sentinel_evidence WHERE task_id = ?) AS n FROM sentinel_evidence WHERE task_id = ? ORDER BY seq DESC LIMIT 1").get(id, id) as { hash: string; n: number } | undefined;
  return { event: e?.hash ?? genesis(id), evidence: v?.hash ?? genesis(id), events: e?.n ?? 0, evidenceRows: v?.n ?? 0 };
};

const sealData = (t: TaskRow, h: ReturnType<typeof heads>): string => JSON.stringify([t.task_id, t.state, t.revision, t.builder_principal, t.policy_hash, t.source_fingerprint, t.cap_epoch, h.event, h.evidence, h.events, h.evidenceRows]);
/** Re-seals a task after any change to its state or logs: a raw edit of the state, or truncating a log, no longer matches the seal. */
function reseal(db: Database.Database, storeDir: string, id: string): void {
  const t = getTask(db, id);
  db.prepare("UPDATE sentinel_tasks SET seal = ? WHERE task_id = ?").run(hmacHex(storeDir, sealData(t, heads(db, id)), true), id);
}

function appendEvent(db: Database.Database, storeDir: string, taskId: string, at: string, kind: string, from: TaskState | null, to: TaskState | null, who: Resolved, revision: number, payload: Record<string, unknown>): void {
  const h = heads(db, taskId);
  if (h.events >= SENTINEL_LIMITS.eventsPerTask) {
    throw new EngbrainError("POLICY_REFUSED", "this task's event log is full");
  }
  const body = JSON.stringify(payload);
  const hash = eventHash({ prev: h.event, taskId, at, kind, from, to, actor: who.principal, role: who.role, revision, payload: body });
  db.prepare("INSERT INTO sentinel_task_events (task_id, at, kind, from_state, to_state, actor, role, revision, payload_json, prev_hash, hash, mac) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
    .run(taskId, at, kind, from, to, who.principal, who.role, revision, body, h.event, hash, hmacHex(storeDir, `${hash}\0${who.principal}`, true));
}

// ---------- separation of duties ----------

/** Everything a principal has done on a task: capability roles it played, and human acts (plan approval, approval, execution authorization). */
function actsOf(db: Database.Database, id: string, principal: string): Set<string> {
  const acts = new Set<string>();
  for (const r of db.prepare("SELECT DISTINCT role, kind, to_state AS toState FROM sentinel_task_events WHERE task_id = ? AND actor = ?").all(id, principal) as Array<{ role: string | null; kind: string; toState: string | null }>) {
    if (r.role !== null) {
      acts.add(r.role);
    } else if (r.kind === "approved" || (r.kind === "transition" && r.toState === "PLAN_APPROVED")) {
      acts.add("human_approval");
    }
  }
  if (db.prepare("SELECT 1 FROM sentinel_exec_auth WHERE task_id = ? AND authorized_by = ? LIMIT 1").get(id, principal) !== undefined) {
    acts.add("human_approval");
  }
  if (db.prepare("SELECT 1 FROM sentinel_approvals WHERE task_id = ? AND approver = ? LIMIT 1").get(id, principal) !== undefined) {
    acts.add("human_approval");
  }
  return acts;
}
const CHECKING_ROLES: readonly string[] = ["verification_worker", "reviewer", "adversarial_reviewer", "assurance_controller"];

/** A human who approves, authorizes or approves the plan must not have built, verified or reviewed the task (under the same principal name), and the builder must not have approved it. */
export function assertCanApprove(db: Database.Database, task: TaskRow, principal: string): void {
  if (principal === task.builder_principal) {
    throw new EngbrainError("POLICY_REFUSED", "the builder cannot approve or authorize its own work");
  }
  const acts = actsOf(db, task.task_id, principal);
  if (["builder", ...CHECKING_ROLES, "architect"].some((r) => acts.has(r))) {
    throw new EngbrainError("POLICY_REFUSED", "a principal that acted as an agent role on this task cannot also approve or authorize it");
  }
}
function assertCanBuild(db: Database.Database, task: TaskRow, principal: string): void {
  const acts = actsOf(db, task.task_id, principal);
  if (acts.has("human_approval") || CHECKING_ROLES.some((r) => acts.has(r))) {
    throw new EngbrainError("POLICY_REFUSED", "the builder cannot also have approved, verified or reviewed this task");
  }
}
function assertCanCheck(db: Database.Database, task: TaskRow, principal: string): void {
  if (principal === task.builder_principal || actsOf(db, task.task_id, principal).has("builder")) {
    throw new EngbrainError("POLICY_REFUSED", "the builder cannot verify or review its own work");
  }
}

// ---------- creation and transitions ----------

export interface NewTask {
  title: string; requester: Actor; profile: Profile; scope: string[]; requirements?: string[]; components?: string[]; budgets?: { maxMinutes?: number; maxFilesChanged?: number }; worktreeId?: string;
  /** The current source-tree fingerprint, computed by the trusted caller from the repository (never typed in by an agent). */
  sourceFingerprint: string;
  /** The commit the task starts from: the scope check compares changes since it with the authorized scope. */
  baseRevision?: string;
}

export function createTask(db: Database.Database, storeDir: string, input: NewTask, now?: Date): TaskRow {
  requireRole(input.requester, "propose");
  if (!PROFILES.includes(input.profile)) {
    throw new EngbrainError("POLICY_REFUSED", "profile must be A1, A2, A3 or A4");
  }
  const title = text(input.title, 200, "title");
  const scope = [...new Set(input.scope.map(safeScope))].sort();
  if (scope.length === 0 || scope.length > 200) {
    throw new EngbrainError("POLICY_REFUSED", "the authorized scope must name 1-200 repository-relative paths (a trailing / means a directory)");
  }
  const requirements = (input.requirements ?? []).map((r) => text(r, 500, "requirement")).slice(0, 50);
  const components = (input.components ?? []).map((r) => text(r, 200, "component")).slice(0, 50);
  if (!/^[0-9a-f]{64}$/.test(input.sourceFingerprint) || (input.baseRevision !== undefined && !/^[0-9a-f]{40,64}$/.test(input.baseRevision))) {
    throw new EngbrainError("POLICY_REFUSED", "the source fingerprint and base revision must be digests computed from the repository");
  }
  if (findSecretIn({ title, requirements, components }) !== null) {
    throw new EngbrainError("POLICY_REFUSED", "the task looks like it contains a secret");
  }
  const at = clock(now).toISOString();
  const id = `st_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
  return db.transaction((): TaskRow => {
    if ((db.prepare("SELECT COUNT(*) AS n FROM sentinel_tasks").get() as { n: number }).n >= SENTINEL_LIMITS.tasks) {
      throw new EngbrainError("POLICY_REFUSED", "the task table is full");
    }
    db.prepare(
      `INSERT INTO sentinel_tasks (task_id, created_at, requester, title, state, revision, profile, policy_hash, source_fingerprint, worktree_id, scope_json, requirements_json, components_json, builder_principal, budgets_json, base_revision, updated_at)
       VALUES (?, ?, ?, ?, 'CREATED', 1, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)`
    ).run(id, at, input.requester.id, title, input.profile, policyHash(storeDir), input.sourceFingerprint, input.worktreeId ?? null, JSON.stringify(scope), JSON.stringify(requirements), JSON.stringify(components), JSON.stringify(input.budgets ?? {}), input.baseRevision ?? null, at);
    appendEvent(db, storeDir, id, at, "created", null, "CREATED", { principal: input.requester.id, role: null, operator: input.requester }, 1, { profile: input.profile, requiredChecks: requiredChecks(storeDir, input.profile, scope) });
    reseal(db, storeDir, id);
    return getTask(db, id);
  }).immediate();
}

export interface TransitionOptions { expectedRevision?: number; reason?: string; now?: Date; leaseToken?: string; sourceFingerprint?: string }

const leaseHeld = (task: TaskRow, now: Date): boolean => task.lease_hash !== null && task.lease_expires !== null && new Date(task.lease_expires).getTime() > now.getTime();
const leaseValid = (task: TaskRow, token: string | undefined, now: Date): boolean => token !== undefined && leaseHeld(task, now) && task.lease_hash === sha(token);

/** A task leaving the line (BLOCKED, FAILED, CANCELLED) loses every approval and execution authorization it held: they cannot be revived by a later round trip. */
function revokeAuthority(db: Database.Database, storeDir: string, id: string, dropQueue: boolean): void {
  for (const a of db.prepare("SELECT * FROM sentinel_approvals WHERE task_id = ? AND status = 'active'").all(id) as Array<Record<string, any>>) {
    db.prepare("UPDATE sentinel_approvals SET status = 'revoked', mac = ? WHERE approval_id = ?").run(approvalMac(storeDir, { ...a, status: "revoked" }), a["approval_id"]);
  }
  for (const a of db.prepare("SELECT * FROM sentinel_exec_auth WHERE task_id = ? AND status = 'active'").all(id) as Array<Record<string, any>>) {
    db.prepare("UPDATE sentinel_exec_auth SET status = 'revoked', mac = ? WHERE auth_id = ?").run(authMac(storeDir, { ...a, status: "revoked" }), a["auth_id"]);
  }
  if (dropQueue) {
    db.prepare("UPDATE sentinel_queue SET status = 'dropped' WHERE task_id = ? AND status IN ('queued', 'running')").run(id);
  }
}
export const approvalMac = (storeDir: string, a: Record<string, any>): string => hmacHex(storeDir, JSON.stringify(["approval", a["approval_id"], a["task_id"], a["approver"], a["at"], a["task_revision"], a["source_fingerprint"], a["policy_hash"], a["evidence_head"], a["status"]]), true);
export const authMac = (storeDir: string, a: Record<string, any>): string => hmacHex(storeDir, JSON.stringify(["exec_auth", a["auth_id"], a["task_id"], a["authorized_by"], a["at"], a["expires_at"], a["source_fingerprint"], a["policy_hash"], a["runs_left"], a["status"]]), true);

/** Moves a task along a legal edge. Approval, eligibility and cancellation have their own functions and cannot be reached through here. */
export function transitionTask(db: Database.Database, storeDir: string, id: string, to: TaskState, who: Who, options: TransitionOptions = {}): TaskRow {
  const now = clock(options.now);
  const resolved = resolveWho(db, storeDir, who, id, now);
  if (to === "APPROVAL_REQUIRED" || to === "ELIGIBLE_FOR_APPROVAL") {
    throw new EngbrainError("POLICY_REFUSED", "use `assure` and `approve`: eligibility is computed from evidence, not asserted");
  }
  if (to === "CANCELLED") {
    throw new EngbrainError("POLICY_REFUSED", "use `cancel`: it revokes authority, drops queued work and stops running children");
  }
  if (options.reason !== undefined && (options.reason.length > SENTINEL_LIMITS.reason || findSecretIn({ reason: options.reason }) !== null)) {
    throw new EngbrainError("POLICY_REFUSED", "the reason is too long or looks like it contains a secret");
  }
  if (options.sourceFingerprint !== undefined && (!/^[0-9a-f]{64}$/.test(options.sourceFingerprint) || !["IMPLEMENTED", "VERIFYING", "REVERIFYING", "CONTEXT_READY"].includes(to))) {
    throw new EngbrainError("POLICY_REFUSED", "a new source fingerprint is accepted only when work completes (IMPLEMENTED, VERIFYING, REVERIFYING) or the task is re-planned");
  }
  return db.transaction((): TaskRow => {
    const task = getTask(db, id);
    if (options.expectedRevision !== undefined && options.expectedRevision !== task.revision) {
      throw new EngbrainError("POLICY_REFUSED", `the task moved on (revision ${task.revision}, you saw ${options.expectedRevision}): re-read it`);
    }
    if (!LEGAL[task.state].includes(to)) {
      throw new EngbrainError("POLICY_REFUSED", `illegal transition ${task.state} -> ${to}`);
    }
    if (leaseHeld(task, now) && !leaseValid(task, options.leaseToken, now)) {
      throw new EngbrainError("POLICY_REFUSED", `another controller (${task.claimed_by}) holds this task`);
    }
    const allowed = resolved.operator === null
      ? ROLE_TARGETS[resolved.role!].includes(to)
      : (resolved.operator.roles.includes("admin") || resolved.operator.roles.includes("approve")) && ["PLAN_APPROVED", "FAILED", "BLOCKED", "CONTEXT_READY"].includes(to);
    if (!allowed) {
      throw new EngbrainError("POLICY_REFUSED", `${resolved.role ?? "this operator"} may not move a task to ${to}`);
    }
    let builder = task.builder_principal;
    if (to === "PLAN_APPROVED") {
      assertCanApprove(db, task, resolved.principal);
    }
    if (to === "IMPLEMENTING") {
      if (builder !== null && builder !== resolved.principal) {
        throw new EngbrainError("POLICY_REFUSED", "this task already has a different builder");
      }
      assertCanBuild(db, task, resolved.principal);
      builder = resolved.principal;
    }
    if (to === "VERIFYING" || to === "REVERIFYING") {
      if (resolved.role !== null) {
        assertCanCheck(db, task, resolved.principal);
      }
    }
    const revision = task.revision + 1;
    const at = now.toISOString();
    const reason = to === "BLOCKED" ? (options.reason ?? "blocked").slice(0, SENTINEL_LIMITS.reason) : null;
    db.prepare("UPDATE sentinel_tasks SET state = ?, revision = ?, builder_principal = ?, blocked_reason = ?, source_fingerprint = ?, updated_at = ? WHERE task_id = ? AND revision = ?")
      .run(to, revision, builder, reason, options.sourceFingerprint ?? task.source_fingerprint, at, id, task.revision);
    if (to === "BLOCKED" || to === "FAILED") {
      revokeAuthority(db, storeDir, id, to === "FAILED");
    }
    appendEvent(db, storeDir, id, at, "transition", task.state, to, resolved, revision, { reason: options.reason ?? null, sourceFingerprint: options.sourceFingerprint ?? null });
    reseal(db, storeDir, id);
    return getTask(db, id);
  }).immediate();
}

/**
 * A new blocking finding withdraws what a person approved: approvals and execution authorizations are revoked and an APPROVAL_REQUIRED / ELIGIBLE task is blocked, so eligibility never outlives an
 * open blocking finding (findings are not evidence, so the evidence head alone would not have invalidated the approvals).
 */
export function withdrawApprovals(db: Database.Database, storeDir: string, id: string, reason: string, now?: Date): void {
  const task = getTask(db, id);
  if (task.state === "APPROVAL_REQUIRED" || task.state === "ELIGIBLE_FOR_APPROVAL") {
    systemBlock(db, storeDir, id, `eligibility withdrawn: ${reason}`, now);
  } else {
    revokeAuthority(db, storeDir, id, false);
  }
}

/** The controller itself stops a task (budget exhausted, concurrent change, recurrent failure): BLOCKED with a reason, every approval and execution authorization revoked. */
export function systemBlock(db: Database.Database, storeDir: string, id: string, reason: string, now?: Date): TaskRow {
  return db.transaction((): TaskRow => {
    const task = getTask(db, id);
    if (TERMINAL.includes(task.state) || task.state === "BLOCKED") {
      return task;
    }
    const at = clock(now).toISOString();
    const revision = task.revision + 1;
    // a controller stop is a real stop: authority, queued work, the lease and every agent capability are withdrawn (a person re-plans and re-issues)
    db.prepare("UPDATE sentinel_tasks SET state = 'BLOCKED', revision = ?, blocked_reason = ?, claimed_by = NULL, lease_expires = NULL, lease_hash = NULL, cap_epoch = cap_epoch + 1, updated_at = ? WHERE task_id = ?").run(revision, reason.slice(0, SENTINEL_LIMITS.reason), at, id);
    revokeAuthority(db, storeDir, id, true);
    appendEvent(db, storeDir, id, at, "system_block", task.state, "BLOCKED", { principal: "controller", role: null, operator: null }, revision, { reason: reason.slice(0, SENTINEL_LIMITS.reason) });
    reseal(db, storeDir, id);
    return getTask(db, id);
  }).immediate();
}

/**
 * Records that a principal ACTED on a task in a role without changing its state (e.g. proposed or decided an adversarial hypothesis). It goes into the signed event log, so separation of duties
 * (`assertCanApprove`, `assertCanBuild`) sees it: someone who reviewed or attacked the work cannot later approve it under the same name.
 */
export function recordTaskAct(db: Database.Database, storeDir: string, id: string, kind: string, principal: string, role: Role, payload: Record<string, unknown> = {}, now?: Date): void {
  if (!/^[a-z][a-z0-9_]{1,39}$/.test(kind)) {
    throw new EngbrainError("POLICY_REFUSED", "an act kind is a lowercase word");
  }
  db.transaction(() => {
    const task = getTask(db, id);
    appendEvent(db, storeDir, id, clock(now).toISOString(), kind, task.state, task.state, { principal, role, operator: null }, task.revision, payload);
    reseal(db, storeDir, id);
  }).immediate();
}

/** Admin only: every capability issued for the task before now stops working (a compromised or finished agent role is cut off). */
export function revokeCapabilities(db: Database.Database, storeDir: string, id: string, actor: Actor, now?: Date): number {
  requireRole(actor, "admin");
  return db.transaction(() => {
    const task = getTask(db, id);
    db.prepare("UPDATE sentinel_tasks SET cap_epoch = cap_epoch + 1, updated_at = ? WHERE task_id = ?").run(clock(now).toISOString(), id);
    appendEvent(db, storeDir, id, clock(now).toISOString(), "capabilities_revoked", task.state, task.state, { principal: actor.id, role: null, operator: actor }, task.revision, {});
    reseal(db, storeDir, id);
    return task.cap_epoch + 1;
  }).immediate();
}

// ---------- evidence ----------

export type EvidenceOutcome = "passed" | "failed" | "skipped" | "timed_out" | "incomplete" | "not_run" | "invalidated";
export interface EvidenceInput {
  origin: "machine" | "agent_note"; kind: string; checkId?: string; outcome: EvidenceOutcome; environment?: Record<string, string>; payload?: Record<string, unknown>;
  /** A claimed fingerprint is checked against the repository's real one; it is never trusted. */
  claimedSourceFingerprint?: string;
}
const evidenceHash = (e: { prev: string; taskId: string; at: string; origin: string; kind: string; checkId: string | null; outcome: string; verifier: string; fp: string; policy: string; env: string; payload: string }): string =>
  sha(JSON.stringify([e.prev, e.taskId, e.at, e.origin, e.kind, e.checkId, e.outcome, e.verifier, e.fp, e.policy, e.env, e.payload]));

/** Which capability roles may record machine evidence for a check. Review checks belong to reviewers, never to the worker that ran the tests. */
const CHECK_ROLES: Readonly<Record<string, readonly Role[]>> = {
  adversarial_review: ["adversarial_reviewer"],
  security_review: ["reviewer", "adversarial_reviewer"],
  independent_review: ["reviewer"]
};
const DEFAULT_CHECK_ROLES: readonly Role[] = ["verification_worker", "assurance_controller"];
const EVIDENCE_STATES: readonly TaskState[] = ["VERIFYING", "REVERIFYING", "ASSURANCE_REVIEW", "APPROVAL_REQUIRED", "ELIGIBLE_FOR_APPROVAL"]; // late evidence is accepted; it invalidates earlier approvals

/**
 * Appends evidence. The verifier identity comes from the authenticated capability (never the caller), the timestamp from the clock, and the source fingerprint must equal both the
 * repository's current fingerprint and the task's. Machine evidence is accepted only in a verifying state, only from the role that owns that check, and never from the task's builder; everything
 * an agent merely asserts is an `agent_note` and never counts. New evidence invalidates earlier approvals; a failing result for a required check pulls the task out of approval.
 */
export function appendEvidence(db: Database.Database, storeDir: string, id: string, input: EvidenceInput, who: Who, currentFingerprint: string, now?: Date): number {
  const at = clock(now);
  const resolved = resolveWho(db, storeDir, who, id, at);
  if (!/^[a-z][a-z0-9_]{1,39}$/.test(input.kind) || (input.checkId !== undefined && !/^[a-z][a-z0-9_]{1,39}$/.test(input.checkId))) {
    throw new EngbrainError("POLICY_REFUSED", "kind and check ids are lowercase words");
  }
  if (input.origin === "machine") {
    const allowedRoles = CHECK_ROLES[input.checkId ?? ""] ?? DEFAULT_CHECK_ROLES;
    if (resolved.role === null || !allowedRoles.includes(resolved.role)) {
      throw new EngbrainError("POLICY_REFUSED", `machine evidence for ${input.checkId ?? input.kind} can only be recorded by: ${allowedRoles.join(", ")}`);
    }
  }
  const env = JSON.stringify(Object.fromEntries(Object.entries(input.environment ?? {}).slice(0, 20).map(([k, v]) => [text(k, 60, "environment key"), text(v, 200, "environment value")])));
  const payload = JSON.stringify(input.payload ?? {});
  if (payload.length > 16_384 || findSecretIn({ env, payload }) !== null) {
    throw new EngbrainError("POLICY_REFUSED", "evidence payload is too large or looks like it contains a secret");
  }
  return db.transaction((): number => {
    const task = getTask(db, id);
    if (TERMINAL.includes(task.state)) {
      throw new EngbrainError("POLICY_REFUSED", "the task is finished");
    }
    if (input.origin === "machine") {
      if (!EVIDENCE_STATES.includes(task.state)) {
        throw new EngbrainError("POLICY_REFUSED", `machine evidence is only recorded while the task is being verified (it is ${task.state})`);
      }
      assertCanCheck(db, task, resolved.principal);
    }
    if (input.claimedSourceFingerprint !== undefined && input.claimedSourceFingerprint !== currentFingerprint) {
      throw new EngbrainError("POLICY_REFUSED", "the claimed source fingerprint does not match the repository: evidence refused");
    }
    if (currentFingerprint !== task.source_fingerprint) {
      throw new EngbrainError("POLICY_REFUSED", "the source changed since the task's fingerprint was recorded: refresh the task (a transition with the new fingerprint) before recording evidence");
    }
    const h = heads(db, id);
    if (h.evidenceRows >= SENTINEL_LIMITS.evidencePerTask) {
      throw new EngbrainError("POLICY_REFUSED", "this task's evidence log is full");
    }
    const last = db.prepare("SELECT at FROM sentinel_evidence WHERE task_id = ? ORDER BY seq DESC LIMIT 1").get(id) as { at: string } | undefined;
    if (last !== undefined && new Date(last.at).getTime() > at.getTime()) {
      throw new EngbrainError("POLICY_REFUSED", "evidence timestamps cannot go backwards");
    }
    const policy = policyHash(storeDir);
    const stamp = at.toISOString();
    const hash = evidenceHash({ prev: h.evidence, taskId: id, at: stamp, origin: input.origin, kind: input.kind, checkId: input.checkId ?? null, outcome: input.outcome, verifier: resolved.principal, fp: currentFingerprint, policy, env, payload });
    const mac = hmacHex(storeDir, `${hash}\0${resolved.principal}`, true);
    const info = db.prepare(
      `INSERT INTO sentinel_evidence (task_id, at, origin, kind, check_id, outcome, verifier, source_fingerprint, policy_hash, environment_json, payload_json, prev_hash, hash, mac) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(id, stamp, input.origin, input.kind, input.checkId ?? null, input.outcome, resolved.principal, currentFingerprint, policy, env, payload, h.evidence, hash, mac);
    // evidence recorded after approval makes those approvals stale (they are bound to the evidence head)
    if (task.state === "APPROVAL_REQUIRED" || task.state === "ELIGIBLE_FOR_APPROVAL") {
      const required = requiredChecks(storeDir, task.profile, JSON.parse(task.scope_json) as string[]);
      const failing = input.origin === "machine" && input.outcome !== "passed" && input.checkId !== undefined && required.includes(input.checkId);
      const to: TaskState = failing ? "BLOCKED" : "APPROVAL_REQUIRED";
      if (failing || task.state === "ELIGIBLE_FOR_APPROVAL") {
        const revision = task.revision + 1;
        db.prepare("UPDATE sentinel_tasks SET state = ?, revision = ?, blocked_reason = ?, updated_at = ? WHERE task_id = ?").run(to, revision, failing ? `${input.checkId}: ${input.outcome}` : null, stamp, id);
        if (failing) {
          revokeAuthority(db, storeDir, id, false);
        }
        appendEvent(db, storeDir, id, stamp, "eligibility_withdrawn", task.state, to, resolved, revision, { checkId: input.checkId ?? null, outcome: input.outcome });
      }
    }
    reseal(db, storeDir, id);
    return Number(info.lastInsertRowid);
  }).immediate();
}

/** Records the result of comparing the files changed since the task's base commit with its authorized scope. A path outside the scope fails the mandatory `scope` check until a later check passes. */
export function recordScopeCheck(db: Database.Database, storeDir: string, id: string, changedPaths: readonly string[], who: Who, currentFingerprint: string, now?: Date): { outcome: "passed" | "failed"; violations: string[] } {
  const task = getTask(db, id);
  const scope = JSON.parse(task.scope_json) as string[];
  const inScope = (p: string): boolean => scope.some((s) => p === s || (s.endsWith("/") ? p.startsWith(s) : p.startsWith(`${s}/`)));
  // a path that is not plainly repository-relative (absolute, `..`, empty segment, backslash) can never count as inside the scope
  const plain = (p: string): boolean => !p.startsWith("/") && !p.includes("\\") && !p.split("/").some((seg) => seg === ".." || seg === "." || seg === "");
  const violations = [...new Set(changedPaths)].filter((p) => !plain(p) || !inScope(p)).sort();
  const outcome = violations.length === 0 ? "passed" : "failed";
  appendEvidence(db, storeDir, id, { origin: "machine", kind: "scope_check", checkId: "scope", outcome, payload: { changed: changedPaths.length, violations: violations.slice(0, 50), violationCount: violations.length } }, who, currentFingerprint, now);
  return { outcome, violations };
}

export interface ChainReport { ok: boolean; problems: string[]; events: number; evidence: number }
/** Recomputes every hash and MAC of a task's logs, and the seal over its state and log heads. A forged, altered, reordered, truncated or re-attributed row shows up here. */
export function verifyTaskChain(db: Database.Database, storeDir: string, id: string): ChainReport {
  const problems: string[] = [];
  let keyOk = true;
  try {
    controllerKey(storeDir);
  } catch {
    keyOk = false;
  }
  let prev = genesis(id);
  const events = db.prepare("SELECT * FROM sentinel_task_events WHERE task_id = ? ORDER BY seq").all(id) as Array<Record<string, any>>;
  for (const e of events) {
    const expected = eventHash({ prev, taskId: id, at: e["at"], kind: e["kind"], from: e["from_state"], to: e["to_state"], actor: e["actor"], role: e["role"], revision: e["revision"], payload: e["payload_json"] });
    if (e["prev_hash"] !== prev || e["hash"] !== expected) {
      problems.push(`event ${e["seq"]} does not match its hash chain`);
    } else if (!keyOk || e["mac"] !== hmacHex(storeDir, `${e["hash"]}\0${e["actor"]}`)) {
      problems.push(`event ${e["seq"]} carries no valid signature`);
    }
    prev = e["hash"];
  }
  prev = genesis(id);
  const rows = db.prepare("SELECT * FROM sentinel_evidence WHERE task_id = ? ORDER BY seq").all(id) as Array<Record<string, any>>;
  for (const r of rows) {
    const expected = evidenceHash({ prev, taskId: id, at: r["at"], origin: r["origin"], kind: r["kind"], checkId: r["check_id"], outcome: r["outcome"], verifier: r["verifier"], fp: r["source_fingerprint"], policy: r["policy_hash"], env: r["environment_json"], payload: r["payload_json"] });
    if (r["prev_hash"] !== prev || r["hash"] !== expected) {
      problems.push(`evidence ${r["seq"]} does not match its hash chain`);
    } else if (!keyOk || r["mac"] !== hmacHex(storeDir, `${r["hash"]}\0${r["verifier"]}`)) {
      problems.push(`evidence ${r["seq"]} carries no valid verifier signature`);
    }
    prev = r["hash"];
  }
  const task = getTask(db, id);
  if (!keyOk || task.seal !== hmacHex(storeDir, sealData(task, heads(db, id)), false)) {
    problems.push("the task's state or log heads do not match its seal (edited or truncated behind the API)");
  }
  return { ok: problems.length === 0, problems, events: events.length, evidence: rows.length };
}

// ---------- eligibility, assurance, approval ----------


export interface CheckStanding { checkId: string; outcome: EvidenceOutcome | "not_run"; state: "none" | "current" | "stale" | "expired" | "environment_changed"; recordedAt: string | null; blocker: string | null; payload: Record<string, unknown> | null }

/** The latest TRUSTED result of one check and whether it still stands: bound to the current source, policy and (when given) environment, inside its lifetime, and passing. */
export function checkStanding(db: Database.Database, storeDir: string, id: string, check: string, currentFingerprint: string, now?: Date, environment?: Readonly<Record<string, string>>): CheckStanding {
  const task = getTask(db, id);
  const profile = effectiveProfile(storeDir, task.profile);
  const latest = db.prepare("SELECT outcome, at, source_fingerprint AS fp, policy_hash AS policy, environment_json AS env, payload_json AS payload FROM sentinel_evidence WHERE task_id = ? AND origin = 'machine' AND check_id = ? ORDER BY seq DESC LIMIT 1").get(id, check) as { outcome: EvidenceOutcome; at: string; fp: string; policy: string; env: string; payload: string } | undefined;
  if (latest === undefined) {
    return { checkId: check, outcome: "not_run", state: "none", recordedAt: null, blocker: `${check}: pending (no trusted evidence)`, payload: null };
  }
  const recordedEnv = JSON.parse(latest.env) as Record<string, string>;
  const payload = JSON.parse(latest.payload) as Record<string, unknown>;
  const base = { checkId: check, outcome: latest.outcome, recordedAt: latest.at, payload };
  // the environment the run declared must still be the recorded one: an explicit expectation, or the store's current environment assumptions for the keys the run declared
  const current: Record<string, string> = { ...(environment ?? {}) };
  for (const key of Object.keys(recordedEnv)) {
    if (!(key in current)) {
      const row = db.prepare("SELECT value FROM memory_environment WHERE key = ? ORDER BY id DESC LIMIT 1").get(key) as { value: string } | undefined;
      if (row !== undefined) {
        current[key] = row.value;
      }
    }
  }
  if (Object.entries(current).some(([k, v]) => recordedEnv[k] !== v)) {
    return { ...base, state: "environment_changed", blocker: `${check}: evidence is stale (the environment it ran in changed)` };
  }
  // evidence bridged from an import only stands while that import still applies (not rejected, not stale, not on another line of history)
  const importId = typeof payload["importId"] === "string" ? payload["importId"] : null;
  if (importId !== null && latest.outcome === "passed") {
    const source = showEvidence(db, importId, now === undefined ? {} : { now: () => now });
    if (source === null || (source.trust !== "signed" && source.trust !== "accepted") || source.standing !== "applies") {
      return { ...base, state: "stale", blocker: `${check}: the import behind this evidence no longer applies (${source === null ? "missing" : `${source.trust}, ${source.standing}`})` };
    }
  }
  if (latest.fp !== currentFingerprint || latest.policy !== policyHash(storeDir)) {
    return { ...base, state: "stale", blocker: `${check}: evidence is stale (recorded for different source or policy)` };
  }
  if (clock(now).getTime() - new Date(latest.at).getTime() > profile.evidenceMaxAgeHours * 3_600_000) {
    return { ...base, state: "expired", blocker: `${check}: evidence expired (older than ${profile.evidenceMaxAgeHours} h)` };
  }
  return { ...base, state: "current", blocker: latest.outcome === "passed" ? null : `${check}: ${latest.outcome}` };
}

export interface Eligibility { checksPassing: boolean; blockers: string[]; stale: string[]; approvalsValid: number; approvalsNeeded: number; requiredChecks: string[] }

/** Whether the mandatory checks currently hold. Only trusted (machine) evidence bound to the CURRENT fingerprint and policy, within its lifetime, and passing, counts; anything else is a blocker. */
export function evaluateEligibility(db: Database.Database, storeDir: string, id: string, currentFingerprint: string, now?: Date, environment?: Readonly<Record<string, string>>): Eligibility {
  const task = getTask(db, id);
  const profile = effectiveProfile(storeDir, task.profile);
  const checks = requiredChecks(storeDir, task.profile, JSON.parse(task.scope_json) as string[]);
  const blockers: string[] = [];
  const stale: string[] = [];
  const policyNow = policyHash(storeDir);
  if (task.policy_hash !== policyNow) {
    stale.push("the policy changed since the task was created");
  }
  if (task.source_fingerprint !== currentFingerprint) {
    stale.push("the source changed since the task's fingerprint was recorded");
  }
  const chain = verifyTaskChain(db, storeDir, id);
  if (!chain.ok) {
    blockers.push(`the event or evidence log failed verification: ${chain.problems[0]}`);
  }
  for (const check of checks) {
    const st = checkStanding(db, storeDir, id, check, currentFingerprint, now, environment);
    if (st.blocker !== null) {
      blockers.push(st.blocker);
    }
  }
  const openBlocking = (db.prepare("SELECT COUNT(*) AS n FROM sentinel_findings WHERE task_id = ? AND disposition = 'open' AND severity = 'blocking'").get(id) as { n: number }).n;
  if (openBlocking > 0) {
    blockers.push(`${openBlocking} open blocking review finding(s)`);
  }
  const valid = validApprovals(db, storeDir, task, currentFingerprint, policyNow);
  return { checksPassing: blockers.length === 0 && stale.length === 0, blockers, stale, approvalsValid: valid.length, approvalsNeeded: profile.minApprovals, requiredChecks: checks };
}

/** Approvals that still count: active, signed, bound to the CURRENT source, policy and evidence head, from distinct principals other than the builder. */
function validApprovals(db: Database.Database, storeDir: string, task: TaskRow, currentFingerprint: string, policyNow: string): Array<{ approver: string }> {
  const head = heads(db, task.task_id).evidence;
  const rows = db.prepare("SELECT * FROM sentinel_approvals WHERE task_id = ? AND status = 'active'").all(task.task_id) as Array<Record<string, any>>;
  const seen = new Set<string>();
  return rows
    .filter((r) => r["source_fingerprint"] === currentFingerprint && r["policy_hash"] === policyNow && r["evidence_head"] === head && r["approver"] !== task.builder_principal && r["mac"] === approvalMac(storeDir, r))
    .filter((r) => !seen.has(r["approver"]) && seen.add(r["approver"]))
    .map((r) => ({ approver: r["approver"] as string }));
}

/** The assurance controller's verdict: failed, pending, stale or unauthorized work forces BLOCKED; otherwise the task waits for human approval. */
export function assureTask(db: Database.Database, storeDir: string, id: string, capability: string, currentFingerprint: string, now?: Date): { state: TaskState; eligibility: Eligibility } {
  const at = clock(now);
  const resolved = resolveWho(db, storeDir, { capability }, id, at, ["assurance_controller"]);
  return db.transaction(() => {
    const task = getTask(db, id);
    if (task.state !== "ASSURANCE_REVIEW") {
      throw new EngbrainError("POLICY_REFUSED", `assurance runs from ASSURANCE_REVIEW (the task is ${task.state})`);
    }
    assertCanCheck(db, task, resolved.principal);
    const eligibility = evaluateEligibility(db, storeDir, id, currentFingerprint, at);
    const problems = [...eligibility.blockers, ...eligibility.stale];
    const to: TaskState = problems.length > 0 ? "BLOCKED" : "APPROVAL_REQUIRED";
    const revision = task.revision + 1;
    db.prepare("UPDATE sentinel_tasks SET state = ?, revision = ?, blocked_reason = ?, updated_at = ? WHERE task_id = ?").run(to, revision, to === "BLOCKED" ? problems.join("; ").slice(0, SENTINEL_LIMITS.reason) : null, at.toISOString(), id);
    if (to === "BLOCKED") {
      revokeAuthority(db, storeDir, id, false);
    }
    appendEvent(db, storeDir, id, at.toISOString(), "assurance", task.state, to, resolved, revision, { blockers: eligibility.blockers, stale: eligibility.stale });
    reseal(db, storeDir, id);
    return { state: to, eligibility };
  }).immediate();
}

/**
 * A human approval by an AUTHENTICATED operator (never a name typed in chat). It is bound to the current source fingerprint, policy hash and evidence head, can never come from the task's
 * builder or from a principal that acted as an agent role on the task, and counts once per distinct approver. When enough valid approvals exist the task becomes ELIGIBLE_FOR_APPROVAL
 * (still no permission to execute or release).
 */
export function approveTask(db: Database.Database, storeDir: string, id: string, actor: Actor, currentFingerprint: string, now?: Date): { state: TaskState; approvalsValid: number; approvalsNeeded: number } {
  requireRole(actor, "approve");
  const at = clock(now);
  return db.transaction(() => {
    const task = getTask(db, id);
    if (task.state !== "APPROVAL_REQUIRED" && task.state !== "ELIGIBLE_FOR_APPROVAL") {
      throw new EngbrainError("POLICY_REFUSED", `a task can only be approved from APPROVAL_REQUIRED (it is ${task.state})`);
    }
    assertCanApprove(db, task, actor.id);
    const eligibility = evaluateEligibility(db, storeDir, id, currentFingerprint, at);
    if (!eligibility.checksPassing) {
      throw new EngbrainError("POLICY_REFUSED", `the task is not eligible: ${[...eligibility.blockers, ...eligibility.stale].join("; ")}`);
    }
    const policyNow = policyHash(storeDir);
    if (validApprovals(db, storeDir, task, currentFingerprint, policyNow).some((a) => a.approver === actor.id)) {
      throw new EngbrainError("POLICY_REFUSED", "this operator already approved the current state");
    }
    const row = { approval_id: `ap_${randomUUID().replace(/-/g, "").slice(0, 16)}`, task_id: id, approver: actor.id, at: at.toISOString(), task_revision: task.revision, source_fingerprint: currentFingerprint, policy_hash: policyNow, evidence_head: heads(db, id).evidence, status: "active" };
    db.prepare("INSERT INTO sentinel_approvals (approval_id, task_id, approver, at, task_revision, source_fingerprint, policy_hash, evidence_head, status, mac) VALUES (@approval_id, @task_id, @approver, @at, @task_revision, @source_fingerprint, @policy_hash, @evidence_head, @status, @mac)")
      .run({ ...row, mac: approvalMac(storeDir, row) });
    const valid = validApprovals(db, storeDir, task, currentFingerprint, policyNow).length;
    const resolved: Resolved = { principal: actor.id, role: null, operator: actor };
    let state = task.state;
    let revision = task.revision;
    if (valid >= eligibility.approvalsNeeded && task.state === "APPROVAL_REQUIRED") {
      state = "ELIGIBLE_FOR_APPROVAL";
      revision += 1;
      db.prepare("UPDATE sentinel_tasks SET state = ?, revision = ?, updated_at = ? WHERE task_id = ?").run(state, revision, at.toISOString(), id);
    }
    appendEvent(db, storeDir, id, at.toISOString(), "approved", task.state, state, resolved, revision, { approvalsValid: valid, approvalsNeeded: eligibility.approvalsNeeded });
    reseal(db, storeDir, id);
    return { state, approvalsValid: valid, approvalsNeeded: eligibility.approvalsNeeded };
  }).immediate();
}

/**
 * Re-checks a task that holds approvals against the repository, policy and evidence as they are NOW. If the source or the policy moved, or the checks no longer hold, every approval and
 * execution authorization is revoked and the task is BLOCKED (or returned to APPROVAL_REQUIRED when only approvals are short): old authorization is never reused.
 */
export function revalidateTask(db: Database.Database, storeDir: string, id: string, currentFingerprint: string, now?: Date): { stale: boolean; reasons: string[]; state: TaskState } {
  const at = clock(now);
  return db.transaction(() => {
    const task = getTask(db, id);
    if (task.state !== "APPROVAL_REQUIRED" && task.state !== "ELIGIBLE_FOR_APPROVAL") {
      return { stale: false, reasons: [], state: task.state };
    }
    const e = evaluateEligibility(db, storeDir, id, currentFingerprint, at);
    const reasons = [...e.stale, ...e.blockers];
    const demoted = reasons.length === 0 && task.state === "ELIGIBLE_FOR_APPROVAL" && e.approvalsValid < e.approvalsNeeded;
    if (reasons.length === 0 && !demoted) {
      return { stale: false, reasons, state: task.state };
    }
    const to: TaskState = demoted ? "APPROVAL_REQUIRED" : "BLOCKED";
    if (!demoted) {
      revokeAuthority(db, storeDir, id, false);
    }
    const revision = task.revision + 1;
    db.prepare("UPDATE sentinel_tasks SET state = ?, revision = ?, blocked_reason = ?, updated_at = ? WHERE task_id = ?").run(to, revision, demoted ? null : `authorization stale: ${reasons.join("; ").slice(0, 400)}`, at.toISOString(), id);
    appendEvent(db, storeDir, id, at.toISOString(), "authorization_stale", task.state, to, { principal: "controller", role: null, operator: null }, revision, { reasons: demoted ? ["approvals no longer valid"] : reasons });
    reseal(db, storeDir, id);
    return { stale: true, reasons: demoted ? ["approvals no longer valid"] : reasons, state: to };
  }).immediate();
}

// ---------- lease, checkpoints, queue, cancel, report ----------

/** Exclusive lease so two controllers cannot work (or execute) the same task. The holder gets a secret token it must present; a lease that expired can be taken over. */
export function claimTask(db: Database.Database, id: string, controller: string, leaseSeconds: number, now?: Date, renewToken?: string): { task: TaskRow; leaseToken: string } {
  const at = clock(now);
  if (!/^[a-zA-Z0-9._:-]{1,60}$/.test(controller) || !(leaseSeconds > 0 && leaseSeconds <= 3600)) {
    throw new EngbrainError("POLICY_REFUSED", "a controller name and a lease of at most one hour are required");
  }
  return db.transaction(() => {
    const task = getTask(db, id);
    if (TERMINAL.includes(task.state)) {
      throw new EngbrainError("POLICY_REFUSED", "the task is finished");
    }
    if (leaseHeld(task, at) && !leaseValid(task, renewToken, at)) {
      throw new EngbrainError("POLICY_REFUSED", `another controller (${task.claimed_by}) holds this task until ${task.lease_expires}`);
    }
    const token = randomBytes(24).toString("hex");
    db.prepare("UPDATE sentinel_tasks SET claimed_by = ?, lease_expires = ?, lease_hash = ?, updated_at = ? WHERE task_id = ?").run(controller, new Date(at.getTime() + leaseSeconds * 1000).toISOString(), sha(token), at.toISOString(), id);
    return { task: getTask(db, id), leaseToken: token };
  }).immediate();
}

export function releaseTask(db: Database.Database, id: string, leaseToken: string): void {
  db.prepare("UPDATE sentinel_tasks SET claimed_by = NULL, lease_expires = NULL, lease_hash = NULL WHERE task_id = ? AND lease_hash = ?").run(id, sha(leaseToken));
}

/** True while the presented token still holds an unexpired lease. */
export function holdsLease(db: Database.Database, id: string, leaseToken: string, now?: Date): boolean {
  return leaseValid(getTask(db, id), leaseToken, clock(now));
}

/** A recovery checkpoint: small structured state saved by the lease holder. `resumeInfo` hands it to the next controller after a crash. */
export function saveCheckpoint(db: Database.Database, id: string, leaseToken: string, checkpoint: Record<string, unknown>, now?: Date): void {
  const body = JSON.stringify(checkpoint);
  if (body.length > 16_384 || findSecretIn({ body }) !== null) {
    throw new EngbrainError("POLICY_REFUSED", "a checkpoint is small structured state, without secrets");
  }
  const at = clock(now);
  if (!leaseValid(getTask(db, id), leaseToken, at)) {
    throw new EngbrainError("POLICY_REFUSED", "only the controller holding the task's lease can save a checkpoint");
  }
  db.prepare("UPDATE sentinel_tasks SET checkpoint_json = ?, updated_at = ? WHERE task_id = ?").run(body, at.toISOString(), id);
}

/** What a restarted controller needs: the task state, its last checkpoint, and the work that was running when the last controller died (re-queued here). */
export function resumeInfo(db: Database.Database, id: string, now?: Date): { state: TaskState; revision: number; checkpoint: unknown; requeued: number } {
  return db.transaction(() => {
    const task = getTask(db, id);
    const requeued = leaseHeld(task, clock(now)) ? 0 : db.prepare("UPDATE sentinel_queue SET status = 'queued' WHERE task_id = ? AND status = 'running'").run(id).changes;
    return { state: task.state, revision: task.revision, checkpoint: task.checkpoint_json === null ? null : JSON.parse(task.checkpoint_json), requeued };
  }).immediate();
}

export function enqueueWork(db: Database.Database, id: string, kind: string): number {
  const task = getTask(db, id);
  if (TERMINAL.includes(task.state)) {
    throw new EngbrainError("POLICY_REFUSED", "the task is finished: nothing can be queued");
  }
  if ((db.prepare("SELECT COUNT(*) AS n FROM sentinel_queue WHERE task_id = ? AND status IN ('queued', 'running')").get(id) as { n: number }).n >= SENTINEL_LIMITS.queuedPerTask) {
    throw new EngbrainError("POLICY_REFUSED", "too much work is already queued for this task");
  }
  return Number(db.prepare("INSERT INTO sentinel_queue (task_id, kind, status) VALUES (?, ?, 'queued')").run(id, text(kind, 60, "work kind")).lastInsertRowid);
}

/** The next queued item of a task that is still live. Items of cancelled or finished tasks are dropped, never returned. */
export function dequeueWork(db: Database.Database): { itemId: number; taskId: string; kind: string } | null {
  return db.transaction(() => {
    for (;;) {
      const item = db.prepare("SELECT item_id AS itemId, task_id AS taskId, kind FROM sentinel_queue WHERE status = 'queued' ORDER BY item_id LIMIT 1").get() as { itemId: number; taskId: string; kind: string } | undefined;
      if (item === undefined) {
        return null;
      }
      if (TERMINAL.includes(getTask(db, item.taskId).state)) {
        db.prepare("UPDATE sentinel_queue SET status = 'dropped' WHERE item_id = ?").run(item.itemId);
        continue;
      }
      db.prepare("UPDATE sentinel_queue SET status = 'running' WHERE item_id = ?").run(item.itemId);
      return item;
    }
  }).immediate();
}

export function completeWork(db: Database.Database, itemId: number): void {
  db.prepare("UPDATE sentinel_queue SET status = 'done' WHERE item_id = ? AND status = 'running'").run(itemId);
}

/** Called when a task is cancelled: lets the execution layer terminate active child processes of that task in this process. Other processes notice through the task state (see the worker's poll). */
export const cancellationHooks: Array<(taskId: string) => void> = [];

export function cancelTask(db: Database.Database, storeDir: string, id: string, actor: Actor, reason: string, now?: Date): TaskRow {
  requireRole(actor, "approve");
  const at = clock(now);
  const why = text(reason, 300, "reason");
  const task = db.transaction((): TaskRow => {
    const current = getTask(db, id);
    if (TERMINAL.includes(current.state)) {
      throw new EngbrainError("POLICY_REFUSED", "the task is already finished");
    }
    const revision = current.revision + 1;
    db.prepare("UPDATE sentinel_tasks SET state = 'CANCELLED', revision = ?, blocked_reason = ?, claimed_by = NULL, lease_expires = NULL, lease_hash = NULL, updated_at = ? WHERE task_id = ?").run(revision, why, at.toISOString(), id);
    revokeAuthority(db, storeDir, id, true);
    db.prepare("UPDATE sentinel_worktrees SET status = 'revoked' WHERE task_id = ?").run(id);
    appendEvent(db, storeDir, id, at.toISOString(), "cancelled", current.state, "CANCELLED", { principal: actor.id, role: null, operator: actor }, revision, { reason: why });
    reseal(db, storeDir, id);
    return getTask(db, id);
  }).immediate();
  cancellationHooks.forEach((hook) => hook(id));
  return task;
}

export function listTasks(db: Database.Database, options: { state?: TaskState; limit?: number } = {}): Array<Pick<TaskRow, "task_id" | "title" | "state" | "profile" | "revision" | "updated_at" | "blocked_reason">> {
  const limit = Math.min(Math.max(1, options.limit ?? 50), 200);
  return (options.state === undefined
    ? db.prepare("SELECT task_id, title, state, profile, revision, updated_at, blocked_reason FROM sentinel_tasks ORDER BY created_at DESC, task_id LIMIT ?").all(limit)
    : db.prepare("SELECT task_id, title, state, profile, revision, updated_at, blocked_reason FROM sentinel_tasks WHERE state = ? ORDER BY created_at DESC, task_id LIMIT ?").all(options.state, limit)) as never;
}

export interface TaskReport {
  task: TaskRow & { scope: string[]; requirements: string[]; components: string[] };
  eligibility: Eligibility;
  authorization: { standing: "none" | "current" | "stale"; reasons: string[] };
  chain: ChainReport;
  evidence: Array<{ seq: number; at: string; origin: string; kind: string; checkId: string | null; outcome: string; verifier: string }>;
  events: Array<{ seq: number; at: string; kind: string; from: string | null; to: string | null; actor: string; role: string | null }>;
  approvals: Array<{ approver: string; at: string; status: string; counts: boolean }>;
  note: string;
}

/** Everything about a task and how it stands NOW against the given repository fingerprint. A task stored as ELIGIBLE whose checks no longer hold is reported `stale`. */
export function taskReport(db: Database.Database, storeDir: string, id: string, currentFingerprint: string, now?: Date): TaskReport {
  const task = getTask(db, id);
  const eligibility = evaluateEligibility(db, storeDir, id, currentFingerprint, now);
  const policyNow = policyHash(storeDir);
  const counting = new Set(validApprovals(db, storeDir, task, currentFingerprint, policyNow).map((a) => a.approver));
  const approvals = (db.prepare("SELECT approver, at, status FROM sentinel_approvals WHERE task_id = ? ORDER BY at").all(id) as Array<{ approver: string; at: string; status: string }>).map((a) => ({ ...a, counts: a.status === "active" && counting.has(a.approver) }));
  const holds = task.state === "APPROVAL_REQUIRED" || task.state === "ELIGIBLE_FOR_APPROVAL";
  const problems = [...eligibility.stale, ...eligibility.blockers];
  const standing = !holds && approvals.length === 0 ? "none" as const
    : problems.length > 0 || (task.state === "ELIGIBLE_FOR_APPROVAL" && eligibility.approvalsValid < eligibility.approvalsNeeded) || approvals.some((a) => a.status === "active" && !a.counts) ? "stale" as const : holds ? "current" as const : "none" as const;
  return {
    task: { ...task, scope: JSON.parse(task.scope_json) as string[], requirements: JSON.parse(task.requirements_json) as string[], components: JSON.parse(task.components_json) as string[] },
    eligibility, authorization: { standing, reasons: standing === "stale" ? problems : [] }, chain: verifyTaskChain(db, storeDir, id),
    evidence: db.prepare("SELECT seq, at, origin, kind, check_id AS checkId, outcome, verifier FROM sentinel_evidence WHERE task_id = ? ORDER BY seq LIMIT 500").all(id) as TaskReport["evidence"],
    events: db.prepare("SELECT seq, at, kind, from_state AS \"from\", to_state AS \"to\", actor, role FROM sentinel_task_events WHERE task_id = ? ORDER BY seq LIMIT 500").all(id) as TaskReport["events"],
    approvals,
    note: "ELIGIBLE_FOR_APPROVAL grants no permission to execute, merge or release. Evidence from agents (agent_note) never counts; only machine evidence bound to the current source and policy does."
  };
}
