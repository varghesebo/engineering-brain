import type Database from "better-sqlite3";
import { EngbrainError } from "../../errors.js";
import { requireRole, type Actor } from "../../memory/operators.js";
import { assertCanApprove, getTask } from "../tasks.js";
import { ADAPTER_TECHNIQUES, type AdapterTechnique } from "./adapters.js";

/**
 * Per-task, per-technique budgets for assurance work (runs, cases, seconds). A quota is set once by an approver and can only be consumed: the store refuses raising a maximum or refunding usage.
 * Consuming a technique that has no quota is refused (fail closed).
 */
export interface QuotaLimits { maxRuns: number; maxCases: number; maxSeconds: number }
export interface QuotaUsage { runs: number; cases: number; seconds: number }
export interface QuotaStanding { technique: AdapterTechnique; max: QuotaLimits; used: QuotaUsage; remaining: QuotaUsage }

interface QuotaRow { task_id: string; technique: AdapterTechnique; max_runs: number; max_cases: number; max_seconds: number; used_runs: number; used_cases: number; used_seconds: number }

const LIMIT_CAP = 1_000_000_000;
const count = (v: number, what: string): number => {
  if (!Number.isSafeInteger(v) || v < 0 || v > LIMIT_CAP) {
    throw new EngbrainError("POLICY_REFUSED", `${what} must be a whole number between 0 and ${LIMIT_CAP}`);
  }
  return v;
};
const knownTechnique = (technique: AdapterTechnique): AdapterTechnique => {
  if (!ADAPTER_TECHNIQUES.includes(technique)) {
    throw new EngbrainError("POLICY_REFUSED", `technique must be one of: ${ADAPTER_TECHNIQUES.join(", ")}`);
  }
  return technique;
};
const standing = (r: QuotaRow): QuotaStanding => ({
  technique: r.technique,
  max: { maxRuns: r.max_runs, maxCases: r.max_cases, maxSeconds: r.max_seconds },
  used: { runs: r.used_runs, cases: r.used_cases, seconds: r.used_seconds },
  remaining: { runs: r.max_runs - r.used_runs, cases: r.max_cases - r.used_cases, seconds: r.max_seconds - r.used_seconds }
});
const rowOf = (db: Database.Database, taskId: string, technique: string): QuotaRow | undefined =>
  db.prepare("SELECT * FROM sentinel_quotas WHERE task_id = ? AND technique = ?").get(taskId, technique) as QuotaRow | undefined;

/** An approver (never the builder or anyone who acted as an agent role on the task) sets a technique's quota once. A second set for the same technique is refused: quotas never grow. */
export function setQuota(db: Database.Database, taskId: string, technique: AdapterTechnique, limits: QuotaLimits, actor: Actor): QuotaStanding {
  requireRole(actor, "approve");
  knownTechnique(technique);
  const maxRuns = count(limits.maxRuns, "maxRuns");
  const maxCases = count(limits.maxCases, "maxCases");
  const maxSeconds = count(limits.maxSeconds, "maxSeconds");
  return db.transaction((): QuotaStanding => {
    assertCanApprove(db, getTask(db, taskId), actor.id);
    if (rowOf(db, taskId, technique) !== undefined) {
      throw new EngbrainError("POLICY_REFUSED", `a ${technique} quota is already set for this task: quotas are set once and never raised`);
    }
    db.prepare("INSERT INTO sentinel_quotas (task_id, technique, max_runs, max_cases, max_seconds) VALUES (?, ?, ?, ?, ?)").run(taskId, technique, maxRuns, maxCases, maxSeconds);
    return standing(rowOf(db, taskId, technique)!);
  }).immediate();
}

/** Consumes part of a quota. Refused when the technique has no quota (fail closed) or when any dimension would overrun; a refused call consumes nothing. */
export function consumeQuota(db: Database.Database, taskId: string, technique: AdapterTechnique, usage: QuotaUsage): QuotaStanding {
  knownTechnique(technique);
  const runs = count(usage.runs, "runs");
  const cases = count(usage.cases, "cases");
  const seconds = count(usage.seconds, "seconds");
  return db.transaction((): QuotaStanding => {
    const row = rowOf(db, taskId, technique);
    if (row === undefined) {
      throw new EngbrainError("POLICY_REFUSED", `no ${technique} quota is set for this task: nothing may be consumed`);
    }
    const over = [
      row.used_runs + runs > row.max_runs ? "runs" : null,
      row.used_cases + cases > row.max_cases ? "cases" : null,
      row.used_seconds + seconds > row.max_seconds ? "seconds" : null
    ].filter((x) => x !== null);
    if (over.length > 0) {
      throw new EngbrainError("POLICY_REFUSED", `the ${technique} quota would be overrun (${over.join(", ")})`);
    }
    db.prepare("UPDATE sentinel_quotas SET used_runs = used_runs + ?, used_cases = used_cases + ?, used_seconds = used_seconds + ? WHERE task_id = ? AND technique = ?").run(runs, cases, seconds, taskId, technique);
    return standing(rowOf(db, taskId, technique)!);
  }).immediate();
}

/** What is left of a technique's quota, or null when none was set (which means nothing may be consumed). */
export function remainingQuota(db: Database.Database, taskId: string, technique: AdapterTechnique): QuotaStanding | null {
  const row = rowOf(db, taskId, knownTechnique(technique));
  return row === undefined ? null : standing(row);
}
