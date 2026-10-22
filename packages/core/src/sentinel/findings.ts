import { randomUUID } from "node:crypto";
import type Database from "better-sqlite3";
import { EngbrainError } from "../errors.js";
import { requireRole, type Actor } from "../memory/operators.js";
import { findSecretIn } from "../memory/records.js";
import { assertCanApprove, checkStanding, getTask, withdrawApprovals, type TaskRow, type Who } from "./tasks.js";
import { verifyCapability } from "./capabilities.js";
import { requiredChecks } from "./policy.js";
import { checkWorktree } from "./worktree.js";

/**
 * Review findings. Each carries evidence and a reproduction, and the evidence is CHECKED, not believed: it must point at real, non-passing machine evidence of this task, a check whose latest trusted
 * result is not passing, or a file whose current hash equals the one the reviewer cites. A finding built on invented evidence is refused. Machine verification stays authoritative for deterministic
 * checks: a finding can open a repair, but only new passing machine evidence (or a person) closes it.
 */
export type EvidenceRef =
  | { kind: "evidence"; seq: number }
  | { kind: "check"; checkId: string }
  | { kind: "file"; path: string; sha256: string; line: number };

/** `provider` is what the reviewer CLAIMS produced the finding; nothing verifies it (listFindings exposes `providerVerified: false`). */
export interface NewFinding { severity: "blocking" | "advisory"; title: string; evidence: EvidenceRef; reproduction: string; provider?: string }

const REVIEW_ROLES = ["reviewer", "adversarial_reviewer", "assurance_controller"] as const;
/** Outcomes a finding may rest on: a real failure or an unfinished run. `skipped`, `not_run` and `invalidated` prove nothing. */
const FAILING_OUTCOMES: readonly string[] = ["failed", "timed_out", "incomplete"];

const inTaskScope = (task: TaskRow, path: string): boolean => {
  const scope = JSON.parse(task.scope_json) as string[];
  return scope.some((s) => path === s || (s.endsWith("/") ? path.startsWith(s) : path.startsWith(`${s}/`)));
};

/** Checks one evidence reference against the store and returns the check it concerns (null for a file reference). Throws when the reference does not support a finding. */
function verifyEvidenceRef(db: Database.Database, storeDir: string, task: TaskRow, ref: EvidenceRef, currentFingerprint: string, resolveFileHash: (path: string) => string | null, at: Date): string | null {
  const id = task.task_id;
  if (ref.kind === "evidence") {
    const row = db.prepare("SELECT outcome, check_id AS c, origin FROM sentinel_evidence WHERE task_id = ? AND seq = ?").get(id, ref.seq) as { outcome: string; c: string | null; origin: string } | undefined;
    if (row === undefined || row.origin !== "machine" || row.c === null) {
      throw new EngbrainError("POLICY_REFUSED", "the cited evidence does not exist for this task (or is not a machine check result): the finding is refused");
    }
    if (row.outcome === "passed") {
      throw new EngbrainError("POLICY_REFUSED", "the cited evidence PASSED: it does not support a finding");
    }
    if (!FAILING_OUTCOMES.includes(row.outcome)) {
      throw new EngbrainError("POLICY_REFUSED", `the cited evidence is ${row.outcome}: only a failed, timed-out or incomplete run supports a finding`);
    }
    const latest = db.prepare("SELECT MAX(seq) AS s FROM sentinel_evidence WHERE task_id = ? AND origin = 'machine' AND check_id = ?").get(id, row.c) as { s: number };
    if (latest.s !== ref.seq) {
      throw new EngbrainError("POLICY_REFUSED", `the cited evidence was superseded by a later result for ${row.c}: cite the latest result`);
    }
    return row.c;
  }
  if (ref.kind === "check") {
    if (!requiredChecks(storeDir, task.profile, JSON.parse(task.scope_json) as string[]).includes(ref.checkId)) {
      throw new EngbrainError("POLICY_REFUSED", `${ref.checkId} is not a check required for this task: the finding is refused`);
    }
    const st = checkStanding(db, storeDir, id, ref.checkId, currentFingerprint, at);
    if (st.state === "current" && st.outcome === "passed") {
      throw new EngbrainError("POLICY_REFUSED", "that check currently passes: the cited evidence does not support a finding");
    }
    if (st.state !== "current" || !FAILING_OUTCOMES.includes(st.outcome)) {
      throw new EngbrainError("POLICY_REFUSED", `that check has no current failing result (${st.outcome}, ${st.state}): a missing or stale result does not support a finding`);
    }
    return ref.checkId;
  }
  if (!Number.isInteger(ref.line) || ref.line < 1) {
    throw new EngbrainError("POLICY_REFUSED", "a file reference needs a line number (1 or more)");
  }
  if (typeof ref.path !== "string" || ref.path.startsWith("/") || ref.path.includes("\\") || ref.path.split("/").some((s) => s === ".." || s === "") || !inTaskScope(task, ref.path)) {
    throw new EngbrainError("POLICY_REFUSED", "the cited file is outside the task's authorized scope: the finding is refused");
  }
  const hash = resolveFileHash(ref.path);
  if (hash === null || hash !== ref.sha256) {
    throw new EngbrainError("POLICY_REFUSED", "the cited file does not exist or its content hash does not match: the finding is refused");
  }
  return null;
}

export function addFinding(db: Database.Database, storeDir: string, id: string, input: NewFinding, capability: string, currentFingerprint: string, resolveFileHash: (path: string) => string | null, now?: Date): string {
  const at = now ?? new Date();
  const who = verifyCapability(storeDir, capability, { now: at, taskId: id, roles: REVIEW_ROLES });
  if (getTask(db, id).cap_epoch !== who.epoch) {
    throw new EngbrainError("POLICY_REFUSED", "the capability was revoked");
  }
  const title = input.title.trim();
  const reproduction = input.reproduction.trim();
  if (title.length < 3 || title.length > 200 || reproduction.length < 5 || reproduction.length > 1000 || findSecretIn({ title, reproduction }) !== null) {
    throw new EngbrainError("POLICY_REFUSED", "a finding needs a short title and a reproduction (5-1000 characters), without secrets");
  }
  return db.transaction((): string => {
    const task = getTask(db, id);
    if (["FAILED", "CANCELLED"].includes(task.state)) {
      throw new EngbrainError("POLICY_REFUSED", "the task is finished");
    }
    if (who.principal === task.builder_principal) {
      throw new EngbrainError("POLICY_REFUSED", "the builder cannot review its own work");
    }
    const ref = input.evidence;
    const checkId = verifyEvidenceRef(db, storeDir, task, ref, currentFingerprint, resolveFileHash, at);
    const findingId = `fd_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
    db.prepare(
      `INSERT INTO sentinel_findings (finding_id, task_id, at, source_role, source_principal, provider, severity, title, evidence_json, reproduction, check_id, disposition) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')`
    ).run(findingId, id, at.toISOString(), who.role, who.principal, input.provider ?? null, input.severity, title, JSON.stringify(ref), reproduction, checkId);
    if (input.severity === "blocking") {
      withdrawApprovals(db, storeDir, id, `blocking finding ${findingId}: ${title}`, at);
    }
    return findingId;
  }).immediate();
}

/** `provider` is an unverified claim by the reviewer: `providerVerified` is always false. */
export interface FindingRow { finding_id: string; task_id: string; at: string; source_role: string; source_principal: string; provider: string | null; severity: string; title: string; evidence_json: string; reproduction: string; check_id: string | null; disposition: string; disposition_by: string | null; disposition_reason: string | null; providerVerified: false }

export function listFindings(db: Database.Database, id: string, options: { open?: boolean } = {}): FindingRow[] {
  const rows = (options.open === true
    ? db.prepare("SELECT * FROM sentinel_findings WHERE task_id = ? AND disposition = 'open' ORDER BY at, finding_id LIMIT 500").all(id)
    : db.prepare("SELECT * FROM sentinel_findings WHERE task_id = ? ORDER BY at, finding_id LIMIT 500").all(id)) as Array<Omit<FindingRow, "providerVerified">>;
  return rows.map((r) => ({ ...r, providerVerified: false as const }));
}

/** `fixed` needs proof: the protected-files finding closes only when the worktree no longer shows protected changes; a check finding only when the check's LATEST machine result passed, after the finding, on the current source. */
function assertFixed(db: Database.Database, task: TaskRow, f: Omit<FindingRow, "providerVerified">): void {
  const evidence = JSON.parse(f.evidence_json) as { kind: string };
  if (evidence.kind === "worktree") {
    let protectedChanges: string[];
    try {
      protectedChanges = checkWorktree(db, task.task_id).protectedChanges;
    } catch {
      throw new EngbrainError("POLICY_REFUSED", "a protected-files finding is fixed only when the authorized worktree can be re-checked: this task has no active worktree");
    }
    if (protectedChanges.length > 0) {
      throw new EngbrainError("POLICY_REFUSED", `protected files are still changed (${protectedChanges.slice(0, 5).join(", ")}): restore them before marking the finding fixed`);
    }
    return;
  }
  const latest = f.check_id === null ? undefined : db.prepare("SELECT outcome, at, source_fingerprint AS fp FROM sentinel_evidence WHERE task_id = ? AND origin = 'machine' AND check_id = ? ORDER BY seq DESC LIMIT 1").get(task.task_id, f.check_id) as { outcome: string; at: string; fp: string } | undefined;
  if (latest === undefined || latest.outcome !== "passed" || latest.at <= f.at || latest.fp !== task.source_fingerprint) {
    throw new EngbrainError("POLICY_REFUSED", "a finding is fixed only by NEW passing machine evidence for its check (recorded after the finding, the latest result, on the task's current source)");
  }
}

/**
 * Decides a finding, once. `fixed` needs proof (see assertFixed); `rejected` (a false positive) and `accepted_risk` need an authenticated
 * operator who is not the builder, with a reason. Nothing here weakens a mandatory check: an accepted risk only closes the finding, the checks still have to pass.
 */
export function resolveFinding(db: Database.Database, id: string, findingId: string, disposition: "fixed" | "rejected" | "accepted_risk", actor: Actor, reason: string, now?: Date): void {
  requireRole(actor, "approve");
  const why = reason.trim();
  if (why.length < 3 || why.length > 500 || findSecretIn({ why }) !== null) {
    throw new EngbrainError("POLICY_REFUSED", "a disposition needs a reason (3-500 characters)");
  }
  db.transaction(() => {
    const task = getTask(db, id);
    assertCanApprove(db, task, actor.id);
    const f = db.prepare("SELECT * FROM sentinel_findings WHERE finding_id = ? AND task_id = ?").get(findingId, id) as Omit<FindingRow, "providerVerified"> | undefined;
    if (f === undefined || f.disposition !== "open") {
      throw new EngbrainError("POLICY_REFUSED", "no such open finding");
    }
    if (disposition === "fixed") {
      assertFixed(db, task, f);
    }
    db.prepare("UPDATE sentinel_findings SET disposition = ?, disposition_by = ?, disposition_reason = ?, disposition_at = ? WHERE finding_id = ?").run(disposition, actor.id, why, (now ?? new Date()).toISOString(), findingId);
  }).immediate();
}

export type { Who };
