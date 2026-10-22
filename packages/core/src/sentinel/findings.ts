import { randomUUID } from "node:crypto";
import type Database from "better-sqlite3";
import { EngbrainError } from "../errors.js";
import { requireRole, type Actor } from "../memory/operators.js";
import { findSecretIn } from "../memory/records.js";
import { checkStanding, getTask, type Who } from "./tasks.js";
import { verifyCapability } from "./capabilities.js";
import { assertCanApprove } from "./tasks.js";

/**
 * Review findings. Each carries evidence and a reproduction, and the evidence is CHECKED, not believed: it must point at real, non-passing machine evidence of this task, a check whose latest trusted
 * result is not passing, or a file whose current hash equals the one the reviewer cites. A finding built on invented evidence is refused. Machine verification stays authoritative for deterministic
 * checks: a finding can open a repair, but only new passing machine evidence (or a person) closes it.
 */
export type EvidenceRef =
  | { kind: "evidence"; seq: number }
  | { kind: "check"; checkId: string }
  | { kind: "file"; path: string; sha256: string; line?: number };

export interface NewFinding { severity: "blocking" | "advisory"; title: string; evidence: EvidenceRef; reproduction: string; provider?: string }

const REVIEW_ROLES = ["reviewer", "adversarial_reviewer", "assurance_controller"] as const;

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
    let checkId: string | null = null;
    const ref = input.evidence;
    if (ref.kind === "evidence") {
      const row = db.prepare("SELECT outcome, check_id AS c, origin FROM sentinel_evidence WHERE task_id = ? AND seq = ?").get(id, ref.seq) as { outcome: string; c: string | null; origin: string } | undefined;
      if (row === undefined || row.origin !== "machine") {
        throw new EngbrainError("POLICY_REFUSED", "the cited evidence does not exist for this task (or is not machine evidence): the finding is refused");
      }
      if (row.outcome === "passed") {
        throw new EngbrainError("POLICY_REFUSED", "the cited evidence PASSED: it does not support a finding");
      }
      checkId = row.c;
    } else if (ref.kind === "check") {
      const st = checkStanding(db, storeDir, id, ref.checkId, currentFingerprint, at);
      if (st.state === "current" && st.outcome === "passed") {
        throw new EngbrainError("POLICY_REFUSED", "that check currently passes: the cited evidence does not support a finding");
      }
      checkId = ref.checkId;
    } else {
      const hash = resolveFileHash(ref.path);
      if (hash === null || hash !== ref.sha256) {
        throw new EngbrainError("POLICY_REFUSED", "the cited file does not exist or its content hash does not match: the finding is refused");
      }
    }
    const findingId = `fd_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
    db.prepare(
      `INSERT INTO sentinel_findings (finding_id, task_id, at, source_role, source_principal, provider, severity, title, evidence_json, reproduction, check_id, disposition) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')`
    ).run(findingId, id, at.toISOString(), who.role, who.principal, input.provider ?? null, input.severity, title, JSON.stringify(ref), reproduction, checkId);
    return findingId;
  }).immediate();
}

export interface FindingRow { finding_id: string; task_id: string; at: string; source_role: string; source_principal: string; provider: string | null; severity: string; title: string; evidence_json: string; reproduction: string; check_id: string | null; disposition: string; disposition_by: string | null; disposition_reason: string | null }

export function listFindings(db: Database.Database, id: string, options: { open?: boolean } = {}): FindingRow[] {
  return (options.open === true
    ? db.prepare("SELECT * FROM sentinel_findings WHERE task_id = ? AND disposition = 'open' ORDER BY at, finding_id LIMIT 500").all(id)
    : db.prepare("SELECT * FROM sentinel_findings WHERE task_id = ? ORDER BY at, finding_id LIMIT 500").all(id)) as FindingRow[];
}

/**
 * Decides a finding, once. `fixed` needs NEW passing machine evidence for the finding's check recorded after the finding; `rejected` (a false positive) and `accepted_risk` need an authenticated
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
    const f = db.prepare("SELECT * FROM sentinel_findings WHERE finding_id = ? AND task_id = ?").get(findingId, id) as FindingRow | undefined;
    if (f === undefined || f.disposition !== "open") {
      throw new EngbrainError("POLICY_REFUSED", "no such open finding");
    }
    if (disposition === "fixed") {
      const newer = f.check_id === null ? undefined : db.prepare("SELECT 1 FROM sentinel_evidence WHERE task_id = ? AND origin = 'machine' AND check_id = ? AND outcome = 'passed' AND at > ? LIMIT 1").get(id, f.check_id, f.at);
      if (newer === undefined) {
        throw new EngbrainError("POLICY_REFUSED", "a finding is fixed only by NEW passing machine evidence for its check (recorded after the finding)");
      }
    }
    db.prepare("UPDATE sentinel_findings SET disposition = ?, disposition_by = ?, disposition_reason = ?, disposition_at = ? WHERE finding_id = ?").run(disposition, actor.id, why, (now ?? new Date()).toISOString(), findingId);
  }).immediate();
}

export type { Who };
