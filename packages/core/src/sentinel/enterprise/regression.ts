import type Database from "better-sqlite3";
import { EngbrainError } from "../../errors.js";
import { requireRole, type Actor } from "../../memory/operators.js";
import { getTask } from "../tasks.js";

/**
 * Historical regression guardian (Sentinel 3E). Every approved or verified bug/incident memory record whose pointers or scope touch the task's scope is an affected incident; each one must be
 * reviewed (covered by a named test, not covered, or not applicable) by a person who is not the task's builder. An unreviewed incident keeps the controller at APPROVAL_REQUIRED, and an
 * incident reviewed as `not_covered` is reported as an unmeasured risk. Reviews are append-only (schema trigger).
 */
export interface AffectedIncident { incidentRef: string; title: string; kind: string; paths: string[]; incidentIds: string[] }
export type IncidentOutcome = "covered" | "not_covered" | "not_applicable";
export interface IncidentReview { incidentRef: string; outcome: IncidentOutcome; testPath: string | null; reviewedBy: string; at: string }

const touches = (scope: readonly string[], path: string): boolean =>
  scope.some((s) => path === s || (s.endsWith("/") ? path.startsWith(s) || `${path}/` === s : path.startsWith(`${s}/`)) || (path.endsWith("/") && s.startsWith(path)));

export function affectedIncidents(db: Database.Database, taskId: string): AffectedIncident[] {
  const scope = JSON.parse(getTask(db, taskId).scope_json) as string[];
  const rows = db.prepare(
    `SELECT record_id AS id, kind, title, scope_json AS scope, evidence_json AS evidence FROM memory_records
     WHERE status IN ('approved', 'verified') AND superseded_at IS NULL AND (kind = 'bug' OR json_extract(evidence_json, '$.type') = 'incident') ORDER BY record_id`
  ).all() as Array<{ id: string; kind: string; title: string; scope: string; evidence: string }>;
  const out: AffectedIncident[] = [];
  for (const r of rows) {
    const pointers = db.prepare("SELECT kind, path, ref FROM memory_pointers WHERE record_id = ? ORDER BY ordinal").all(r.id) as Array<{ kind: string; path: string | null; ref: string | null }>;
    const scoped = (JSON.parse(r.scope) as { paths?: string[] }).paths ?? [];
    const paths = [...new Set([...pointers.map((p) => p.path).filter((p): p is string => p !== null), ...scoped])].sort();
    if (paths.some((p) => touches(scope, p))) {
      out.push({ incidentRef: r.id, title: r.title, kind: r.kind, paths, incidentIds: pointers.filter((p) => p.kind === "incident" && p.ref !== null).map((p) => p.ref!) });
    }
  }
  return out;
}

export function incidentReviews(db: Database.Database, taskId: string): IncidentReview[] {
  return db.prepare("SELECT incident_ref AS incidentRef, outcome, test_path AS testPath, reviewed_by AS reviewedBy, at FROM sentinel_incident_reviews WHERE task_id = ? ORDER BY review_id").all(taskId) as IncidentReview[];
}

export function recordIncidentReview(db: Database.Database, taskId: string, incidentRef: string, testPath: string | null, reviewer: Actor, outcome: IncidentOutcome, now?: Date): IncidentReview {
  requireRole(reviewer, "verify");
  const task = getTask(db, taskId);
  if (reviewer.id === task.builder_principal) {
    throw new EngbrainError("POLICY_REFUSED", "the builder cannot review the incidents its own change affects");
  }
  if (!["covered", "not_covered", "not_applicable"].includes(outcome)) {
    throw new EngbrainError("POLICY_REFUSED", "an incident review is covered, not_covered or not_applicable");
  }
  if (!affectedIncidents(db, taskId).some((i) => i.incidentRef === incidentRef)) {
    throw new EngbrainError("POLICY_REFUSED", "that incident does not affect this task's scope");
  }
  if (outcome === "covered" && testPath === null) {
    throw new EngbrainError("POLICY_REFUSED", "`covered` names the regression test that covers the incident");
  }
  if (testPath !== null && (testPath.length > 500 || testPath.startsWith("/") || testPath.includes("\\") || testPath.split("/").includes("..") || /[\p{Cc}\p{Cf}]/u.test(testPath))) {
    throw new EngbrainError("POLICY_REFUSED", "the test path is repository-relative");
  }
  const at = (now ?? new Date()).toISOString();
  db.prepare("INSERT INTO sentinel_incident_reviews (task_id, incident_ref, test_path, reviewed_by, outcome, at) VALUES (?, ?, ?, ?, ?, ?)").run(taskId, incidentRef, testPath, reviewer.id, outcome, at);
  return { incidentRef, outcome, testPath, reviewedBy: reviewer.id, at };
}

/** Affected incidents with no review at all (the latest review of each incident decides its standing). */
export function regressionStanding(db: Database.Database, taskId: string): { affected: AffectedIncident[]; unreviewed: AffectedIncident[]; notCovered: AffectedIncident[] } {
  const affected = affectedIncidents(db, taskId);
  const latest = new Map<string, IncidentReview>();
  for (const r of incidentReviews(db, taskId)) {
    latest.set(r.incidentRef, r);
  }
  return { affected, unreviewed: affected.filter((i) => !latest.has(i.incidentRef)), notCovered: affected.filter((i) => latest.get(i.incidentRef)?.outcome === "not_covered") };
}
