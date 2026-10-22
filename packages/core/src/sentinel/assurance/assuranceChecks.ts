import type Database from "better-sqlite3";
import { EngbrainError } from "../../errors.js";
import type { AssuranceDetail } from "../../evidence/assuranceTypes.js";
import { assuranceDetail } from "../../evidence/store.js";
import { appendEvidence, type EvidenceOutcome, type Who } from "../tasks.js";
import { formalRecorded, formalVerdict } from "./formal.js";
import { mutationRunFor, mutationRunSummary, mutationVerdict, type MutationSummary } from "./mutation.js";

/**
 * How adversarial-assurance artifacts read as one check outcome, and how a technique that cannot run here is recorded. Every verdict states its limits: a pass from a property test, a race
 * explorer or a static analyser means "nothing found in what was explored", never "proven correct".
 */
export interface AssuranceVerdict { outcome: EvidenceOutcome; reasons: string[] }

export const ASSURANCE_FORMATS: readonly string[] = ["stryker", "fastcheck", "hypothesis", "semgrep_json", "tla", "z3", "race_log"];

export function propertyVerdict(detail: AssuranceDetail): AssuranceVerdict {
  const p = detail.property;
  if (p === undefined) {
    return { outcome: "incomplete", reasons: ["the artifact carries no property-test result"] };
  }
  if (p.failed) {
    return { outcome: "failed", reasons: [`a counterexample was found${p.seed === null ? "" : ` (seed ${p.seed})`}${p.shrinkSteps === null ? "" : `, shrunk in ${p.shrinkSteps} steps`}`] };
  }
  if (p.numRuns !== null && p.numRuns <= 0) {
    return { outcome: "not_run", reasons: ["no generated cases were run"] };
  }
  return { outcome: "passed", reasons: [`not proof: no counterexample in ${p.numRuns === null ? "the (unreported number of)" : p.numRuns} generated cases`] };
}

export function raceVerdict(detail: AssuranceDetail): AssuranceVerdict {
  const r = detail.race;
  if (r === undefined) {
    return { outcome: "incomplete", reasons: ["the artifact carries no race-exploration result"] };
  }
  if (r.violation !== null) {
    return { outcome: "failed", reasons: [`violation: ${r.violation.slice(0, 200)}${r.seed === null ? "" : ` (seed ${r.seed})`}`] };
  }
  if (r.schedule.length === 0) {
    return { outcome: "not_run", reasons: ["no schedule was explored"] };
  }
  return { outcome: "passed", reasons: [`not proof: no violation in the ${r.schedule.length} explored schedule step(s)`] };
}

/** Static analysis (semgrep): any error-level finding fails; a partial report is incomplete. */
export function sastVerdict(db: Database.Database, importId: string, partial: boolean): AssuranceVerdict {
  const errors = (db.prepare("SELECT COUNT(*) AS n FROM evidence_findings WHERE import_id = ? AND level = 'error'").get(importId) as { n: number }).n;
  if (errors > 0) {
    return { outcome: "failed", reasons: [`${errors} error-level findings`] };
  }
  return partial ? { outcome: "incomplete", reasons: ["the analysis report is incomplete"] } : { outcome: "passed", reasons: ["not proof: no error-level finding for the rules that ran"] };
}

/**
 * The verdict for an adversarial-assurance import backing a check of a task. Mutation reads the recorded run (after equivalence decisions) when one exists; a formal success counts only once
 * its assumptions and applicability were recorded. A partial artifact never passes.
 */
export function assuranceVerdict(db: Database.Database, taskId: string, importId: string, format: string, partial: boolean): AssuranceVerdict {
  if (format === "semgrep_json") {
    return sastVerdict(db, importId, partial);
  }
  const detail = assuranceDetail(db, importId);
  if (detail === null) {
    return { outcome: "incomplete", reasons: ["the import carries no structured assurance detail"] };
  }
  let verdict: AssuranceVerdict;
  if (format === "stryker") {
    const runId = mutationRunFor(db, taskId, importId);
    const summary: MutationSummary = runId !== null ? mutationRunSummary(db, runId) : { killed: 0, survived: 0, equivalent: 0, inconclusive: 0 };
    if (runId === null) {
      (detail.mutants ?? []).forEach((m) => { summary[m.status === "killed" || m.status === "survived" ? m.status : "inconclusive"] += 1; });
    }
    const m = mutationVerdict(summary);
    verdict = { outcome: m.outcome, reasons: [...m.reasons, ...(m.scorePct === null ? [] : [`score ${m.scorePct}% (never a proof)`])] };
  } else if (format === "tla" || format === "z3") {
    verdict = detail.formal === undefined ? { outcome: "incomplete", reasons: ["the artifact carries no formal result"] } : formalVerdict(detail.formal.result);
    if (verdict.outcome === "passed" && !formalRecorded(db, taskId, importId)) {
      verdict = { outcome: "incomplete", reasons: ["record the model's assumptions and applicability first (recordFormalResult): a model success without them is not counted"] };
    }
  } else if (format === "fastcheck" || format === "hypothesis") {
    verdict = propertyVerdict(detail);
  } else if (format === "race_log") {
    verdict = raceVerdict(detail);
  } else {
    throw new EngbrainError("POLICY_REFUSED", `${format} is not an adversarial-assurance format`);
  }
  return verdict.outcome === "passed" && partial ? { outcome: "incomplete", reasons: ["the artifact is partial", ...verdict.reasons] } : verdict;
}

/**
 * A technique that cannot run here (no adapter, no solver, an unsupported platform) is recorded as machine evidence `not_run` with `unsupported: true`, so the gap is visible in the report and
 * the pass it belongs to can never read as PASSED.
 */
export function recordUnsupported(db: Database.Database, storeDir: string, taskId: string, checkId: string, who: Who, currentFingerprint: string, input: { adapterId?: string; reason: string }, now?: Date): number {
  const reason = input.reason.trim();
  if (reason.length < 1 || reason.length > 300 || /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(reason)) {
    throw new EngbrainError("POLICY_REFUSED", "an unsupported result needs a short reason (1-300 characters)");
  }
  let adapter: { status: string; reason: string } | null = null;
  if (input.adapterId !== undefined) {
    const row = db.prepare("SELECT status, status_reason AS reason FROM sentinel_adapters WHERE adapter_id = ?").get(input.adapterId) as { status: string; reason: string } | undefined;
    if (row === undefined) {
      throw new EngbrainError("INVALID_ROOT", "no such adapter");
    }
    adapter = row;
  }
  return appendEvidence(db, storeDir, taskId, {
    origin: "machine", kind: "unsupported", checkId, outcome: "not_run",
    payload: { unsupported: true, reason, adapterId: input.adapterId ?? null, adapterStatus: adapter?.status ?? null }
  }, who, currentFingerprint, now);
}
