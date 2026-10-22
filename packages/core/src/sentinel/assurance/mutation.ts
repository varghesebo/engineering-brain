import { randomUUID } from "node:crypto";
import type Database from "better-sqlite3";
import { EngbrainError } from "../../errors.js";
import { assuranceDetail, showEvidence } from "../../evidence/store.js";
import { requireRole, type Actor } from "../../memory/operators.js";
import { findSecretIn } from "../../memory/records.js";
import { assertCanApprove, getTask, type EvidenceOutcome } from "../tasks.js";

/**
 * Mutation testing (Sentinel 3D). A mutation score measures how SENSITIVE the tests are to small code changes; it is never a proof of correctness, so a run can never claim proof (the schema pins
 * `claims_proof` to 0) and even 100% killed is reported with that limit stated. A surviving mutant fails the check unless a human approver (never the builder) records why it is equivalent.
 */
export const MUTATION_MIN_MUTANTS = 5;
export const MUTATION_NOT_PROOF = "not proof: a mutation score shows test sensitivity only";

export interface MutationSummary { killed: number; survived: number; equivalent: number; inconclusive: number }
export interface MutationVerdict { outcome: EvidenceOutcome; reasons: string[]; scorePct: number | null }

/** Killed share of the mutants that could be judged (equivalent mutants excluded). Null when nothing could be judged. */
export const mutationScore = (s: MutationSummary): number | null => {
  const judged = s.killed + s.survived + s.inconclusive;
  return judged === 0 ? null : Math.round((s.killed / judged) * 10_000) / 100;
};

export function mutationVerdict(summary: MutationSummary, minMutants = MUTATION_MIN_MUTANTS): MutationVerdict {
  const scorePct = mutationScore(summary);
  const total = summary.killed + summary.survived + summary.equivalent + summary.inconclusive;
  if (summary.survived > 0) {
    return { outcome: "failed", reasons: [`${summary.survived} mutant(s) survived (score ${scorePct}%)`], scorePct };
  }
  if (summary.inconclusive > 0) {
    return { outcome: "incomplete", reasons: [`${summary.inconclusive} mutant(s) are inconclusive (timeout, no coverage, error or an unconfirmed equivalence claim)`], scorePct };
  }
  if (total < minMutants) {
    return { outcome: "incomplete", reasons: [`only ${total} mutant(s): at least ${minMutants} are needed for a meaningful result`], scorePct };
  }
  return { outcome: "passed", reasons: [MUTATION_NOT_PROOF, `${summary.killed} killed, ${summary.equivalent} equivalent by human decision`], scorePct };
}

/** A tool's own "equivalent" label is a claim, not a decision: it is stored as inconclusive until an approver decides it. */
const storedStatus = (s: string): "killed" | "survived" | "inconclusive" => (s === "killed" || s === "survived" ? s : "inconclusive");

/** Records a mutation run of a task from a signed or accepted Stryker import: one run per (task, import), with each mutant. Returns the run id and its summary as imported. */
export function recordMutationRun(db: Database.Database, taskId: string, importId: string, now?: Date): { runId: string; summary: MutationSummary; scorePct: number | null } {
  return db.transaction(() => {
    getTask(db, taskId);
    const ev = showEvidence(db, importId, now === undefined ? {} : { now: () => now });
    if (ev === null) {
      throw new EngbrainError("INVALID_ROOT", "no such evidence import");
    }
    if (ev.trust !== "signed" && ev.trust !== "accepted") {
      throw new EngbrainError("POLICY_REFUSED", `this import is ${ev.trust}: only signed or accepted evidence can record a mutation run`);
    }
    const detail = assuranceDetail(db, importId);
    if (detail === null || detail.kind !== "mutation" || detail.mutants === undefined) {
      throw new EngbrainError("POLICY_REFUSED", "this import carries no mutation detail (a mutation run needs a mutation-testing report such as Stryker's)");
    }
    if (db.prepare("SELECT 1 FROM sentinel_mutation_runs WHERE task_id = ? AND import_id = ?").get(taskId, importId) !== undefined) {
      throw new EngbrainError("POLICY_REFUSED", "this import was already recorded as a mutation run of this task");
    }
    const seen = new Set<string>();
    const mutants = detail.mutants.filter((m) => !seen.has(m.key) && seen.add(m.key)).map((m) => ({ ...m, status: storedStatus(m.status) }));
    const summary: MutationSummary = { killed: 0, survived: 0, equivalent: 0, inconclusive: 0 };
    mutants.forEach((m) => { summary[m.status] += 1; });
    const scorePct = mutationScore(summary);
    const runId = `mr_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
    db.prepare("INSERT INTO sentinel_mutation_runs (run_id, task_id, import_id, killed, survived, equivalent, inconclusive, score_pct, claims_proof, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)")
      .run(runId, taskId, importId, summary.killed, summary.survived, summary.equivalent, summary.inconclusive, scorePct, (now ?? new Date()).toISOString());
    const ins = db.prepare("INSERT INTO sentinel_mutants (run_id, mutant_key, file, line, mutator, status) VALUES (?, ?, ?, ?, ?, ?)");
    mutants.forEach((m) => ins.run(runId, m.key, m.file === "" ? "(unknown)" : m.file, m.line, m.mutator, m.status));
    return { runId, summary, scorePct };
  }).immediate();
}

/** The summary of a run as it stands now (after equivalence decisions). */
export function mutationRunSummary(db: Database.Database, runId: string): MutationSummary {
  const summary: MutationSummary = { killed: 0, survived: 0, equivalent: 0, inconclusive: 0 };
  for (const r of db.prepare("SELECT status, COUNT(*) AS n FROM sentinel_mutants WHERE run_id = ? GROUP BY status").all(runId) as Array<{ status: keyof MutationSummary; n: number }>) {
    summary[r.status] = r.n;
  }
  return summary;
}

/** The latest recorded run of this import for this task, or null. */
export function mutationRunFor(db: Database.Database, taskId: string, importId: string): string | null {
  return (db.prepare("SELECT run_id AS id FROM sentinel_mutation_runs WHERE task_id = ? AND import_id = ? ORDER BY at DESC, run_id LIMIT 1").get(taskId, importId) as { id: string } | undefined)?.id ?? null;
}

/**
 * A human approver records that a surviving (or tool-labelled) mutant is equivalent, with the basis. The builder, and anyone who acted as an agent role on the task, cannot decide it. A killed or
 * already-decided mutant cannot be changed.
 */
export function decideEquivalent(db: Database.Database, runId: string, mutantKey: string, actor: Actor, basis: string): void {
  requireRole(actor, "approve");
  const why = basis.trim();
  if (why.length < 10 || why.length > 500 || /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(why) || findSecretIn({ why }) !== null) {
    throw new EngbrainError("POLICY_REFUSED", "an equivalence decision needs a basis of 10-500 characters (why no test can tell the mutant apart), without control characters or secrets");
  }
  db.transaction(() => {
    const run = db.prepare("SELECT task_id AS taskId FROM sentinel_mutation_runs WHERE run_id = ?").get(runId) as { taskId: string } | undefined;
    if (run === undefined) {
      throw new EngbrainError("INVALID_ROOT", "no such mutation run");
    }
    assertCanApprove(db, getTask(db, run.taskId), actor.id);
    const mutant = db.prepare("SELECT status FROM sentinel_mutants WHERE run_id = ? AND mutant_key = ?").get(runId, mutantKey) as { status: string } | undefined;
    if (mutant === undefined) {
      throw new EngbrainError("INVALID_ROOT", "no such mutant in this run");
    }
    if (mutant.status !== "survived" && mutant.status !== "inconclusive") {
      throw new EngbrainError("POLICY_REFUSED", `only a surviving or inconclusive mutant can be decided equivalent (this one is ${mutant.status})`);
    }
    db.prepare("UPDATE sentinel_mutants SET status = 'equivalent', decided_by = ?, equivalent_basis = ? WHERE run_id = ? AND mutant_key = ?").run(actor.id, why, runId, mutantKey);
  }).immediate();
}
