import { randomUUID } from "node:crypto";
import type Database from "better-sqlite3";
import { EngbrainError } from "../../errors.js";
import { requireRole, type Actor } from "../../memory/operators.js";
import { findSecretIn } from "../../memory/records.js";
import { hmacHex } from "../capabilities.js";
import { BASE_PROFILES, loadPolicyFile } from "../policy.js";
import { assertCanApprove, getTask } from "../tasks.js";
import { assertGrant } from "./grants.js";

/**
 * Logged risk acceptance for a single check (Sentinel 3E). An exception NEVER removes a check from `requiredChecks` and never turns it into a pass: the controller reports it next to the failing
 * check and the best outcome it allows is APPROVAL_REQUIRED. Only checks a local policy file ADDED to a profile can be excepted; the profile's own mandatory checks (and checks added by risk
 * scoring) cannot be excepted at all. The flow is requested -> active -> revoked (schema trigger), MAC-protected, approved by a second person holding an `exception_approver` grant who is
 * neither the requester nor the builder nor any agent role on the task.
 */
export interface ExceptionRow { exception_id: string; task_id: string; check_id: string; requested_by: string; approved_by: string | null; risk_statement: string; at: string; expires_at: string; status: "requested" | "active" | "revoked"; mac: string }

const MAX_DAYS = 90;
const clock = (now?: Date): Date => now ?? new Date();
export const exceptionMac = (storeDir: string, e: Omit<ExceptionRow, "mac">): string =>
  hmacHex(storeDir, JSON.stringify(["exception", e.exception_id, e.task_id, e.check_id, e.requested_by, e.approved_by, e.risk_statement, e.at, e.expires_at, e.status]), true);

/** The checks of this task that may be excepted: those the local policy file added to the profile, minus every base mandatory check. */
export function exceptableChecks(storeDir: string, taskId: string, db: Database.Database): string[] {
  const task = getTask(db, taskId);
  const added = loadPolicyFile(storeDir).extraChecks[task.profile];
  return (Array.isArray(added) ? added : []).filter((c) => typeof c === "string" && !BASE_PROFILES[task.profile].mandatoryChecks.includes(c)).sort();
}

function getException(db: Database.Database, id: string): ExceptionRow {
  const row = db.prepare("SELECT * FROM sentinel_exceptions WHERE exception_id = ?").get(id) as ExceptionRow | undefined;
  if (row === undefined) {
    throw new EngbrainError("INVALID_ROOT", "no such exception");
  }
  return row;
}

export function requestException(db: Database.Database, storeDir: string, taskId: string, checkId: string, requester: Actor, riskStatement: string, expiresAt: Date | string, now?: Date): ExceptionRow {
  requireRole(requester, "propose");
  const at = clock(now);
  if (!exceptableChecks(storeDir, taskId, db).includes(checkId)) {
    throw new EngbrainError("POLICY_REFUSED", `${checkId} cannot be excepted: mandatory profile checks are never waivable (only checks a local policy added can carry a logged risk acceptance)`);
  }
  const risk = riskStatement.trim();
  if (risk.length < 10 || risk.length > 1000 || /[\p{Cc}\p{Cf}]/u.test(risk) || findSecretIn({ risk }) !== null) {
    throw new EngbrainError("POLICY_REFUSED", "a risk statement is 10-1000 characters, plain text, without secrets");
  }
  const expires = new Date(expiresAt);
  if (Number.isNaN(expires.getTime()) || expires.getTime() <= at.getTime() || expires.getTime() - at.getTime() > MAX_DAYS * 86_400_000) {
    throw new EngbrainError("POLICY_REFUSED", `an exception expires in the future, at most ${MAX_DAYS} days away`);
  }
  const row: Omit<ExceptionRow, "mac"> = { exception_id: `ex_${randomUUID().replace(/-/g, "").slice(0, 16)}`, task_id: taskId, check_id: checkId, requested_by: requester.id, approved_by: null, risk_statement: risk, at: at.toISOString(), expires_at: expires.toISOString(), status: "requested" };
  db.prepare("INSERT INTO sentinel_exceptions (exception_id, task_id, check_id, requested_by, approved_by, risk_statement, at, expires_at, status, mac) VALUES (@exception_id, @task_id, @check_id, @requested_by, @approved_by, @risk_statement, @at, @expires_at, @status, @mac)")
    .run({ ...row, mac: exceptionMac(storeDir, row) });
  return getException(db, row.exception_id);
}

export function approveException(db: Database.Database, storeDir: string, id: string, approver: Actor, now?: Date): ExceptionRow {
  requireRole(approver, "approve");
  const at = clock(now);
  return db.transaction((): ExceptionRow => {
    const ex = getException(db, id);
    if (ex.mac !== exceptionMac(storeDir, ex)) {
      throw new EngbrainError("INTEGRITY_FAILED", "the exception request does not match its MAC (edited behind the API)");
    }
    if (ex.status !== "requested" || new Date(ex.expires_at).getTime() <= at.getTime()) {
      throw new EngbrainError("POLICY_REFUSED", "only an unexpired, requested exception can be approved");
    }
    if (approver.id === ex.requested_by) {
      throw new EngbrainError("POLICY_REFUSED", "the requester cannot approve its own exception");
    }
    const task = getTask(db, ex.task_id);
    assertCanApprove(db, task, approver.id);
    assertGrant(db, approver.id, "exception_approver", JSON.parse(task.scope_json) as string[], at);
    const next: Omit<ExceptionRow, "mac"> = { ...ex, approved_by: approver.id, status: "active" };
    db.prepare("UPDATE sentinel_exceptions SET approved_by = ?, status = 'active', mac = ? WHERE exception_id = ? AND status = 'requested'").run(approver.id, exceptionMac(storeDir, next), id);
    return getException(db, id);
  }).immediate();
}

export function revokeException(db: Database.Database, storeDir: string, id: string, actor: Actor): ExceptionRow {
  requireRole(actor, "approve");
  const ex = getException(db, id);
  if (ex.status === "revoked") {
    return ex;
  }
  db.prepare("UPDATE sentinel_exceptions SET status = 'revoked', mac = ? WHERE exception_id = ?").run(exceptionMac(storeDir, { ...ex, status: "revoked" }), id);
  return getException(db, id);
}

/** Active, unexpired exceptions of a task. Pass `storeDir` to also drop rows whose MAC does not verify (the controller always does). */
export function activeExceptions(db: Database.Database, taskId: string, now?: Date, storeDir?: string): ExceptionRow[] {
  const at = clock(now).toISOString();
  return (db.prepare("SELECT * FROM sentinel_exceptions WHERE task_id = ? AND status = 'active' AND expires_at > ? ORDER BY at").all(taskId, at) as ExceptionRow[])
    .filter((e) => storeDir === undefined || e.mac === exceptionMac(storeDir, e));
}
