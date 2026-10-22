import { createHash, randomUUID } from "node:crypto";
import type Database from "better-sqlite3";
import { EngbrainError } from "../../errors.js";
import type { Actor } from "../../memory/operators.js";
import { findSecretIn } from "../../memory/records.js";
import { getTask } from "../tasks.js";
import { activeGrants, type GrantRole } from "./grants.js";

/**
 * Classification-aware evidence export (Sentinel 3E). An export needs an `exporter` or `auditor` grant that is in force NOW and covers the task's whole scope; a missing or revoked grant gets
 * nothing at all (not even the task title) and the refusal itself is audited. Every section carries a classification; sections above the requested level, or above what the grant clears
 * (exporter: internal, auditor: restricted), are removed and listed as redactions. Evidence payloads, environments and anything the secret scanner flags are never exported. Every export
 * — and every refusal — is written to the append-only `sentinel_export_audit` with the sha256 of exactly what was released.
 */
export const CLASSIFICATIONS = ["public", "internal", "confidential", "restricted"] as const;
export type Classification = (typeof CLASSIFICATIONS)[number];
const CLEARANCE: Readonly<Record<"exporter" | "auditor", Classification>> = { exporter: "internal", auditor: "restricted" };
const EXPORT_ROLES: readonly GrantRole[] = ["exporter", "auditor"];
const rank = (c: Classification): number => CLASSIFICATIONS.indexOf(c);
const sha = (s: string): string => createHash("sha256").update(s).digest("hex");

export interface ExportResult { exportId: string; classification: Classification; content: Record<string, unknown>; json: string; sha256: string; redactions: string[] }

function audit(db: Database.Database, principal: string, scope: string, classification: Classification, contentSha: string, redactions: unknown, at: Date): string {
  const id = `xp_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
  db.prepare("INSERT INTO sentinel_export_audit (export_id, principal, repo_scope, classification, content_sha256, redactions_json, at) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .run(id, principal.slice(0, 60), scope, classification, contentSha, JSON.stringify(redactions), at.toISOString());
  return id;
}

/** Replaces any string the secret scanner flags (defence in depth: nothing secret should reach this point). */
function scrub(value: unknown): unknown {
  if (typeof value === "string") {
    return findSecretIn(value) === null ? value : "[redacted: looks like a secret]";
  }
  if (Array.isArray(value)) {
    return value.map(scrub);
  }
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, scrub(v)]));
  }
  return value;
}

function sections(db: Database.Database, taskId: string): Array<{ name: string; classification: Classification; data: unknown }> {
  const task = getTask(db, taskId);
  const decision = db.prepare("SELECT outcome, reasons_json AS reasons, unmeasured_json AS unmeasured, at FROM sentinel_decisions WHERE task_id = ? ORDER BY seq DESC LIMIT 1").get(taskId) as { outcome: string; reasons: string; unmeasured: string; at: string } | undefined;
  const checks = db.prepare("SELECT check_id AS checkId, outcome, at FROM sentinel_evidence WHERE task_id = ? AND origin = 'machine' AND check_id IS NOT NULL ORDER BY seq").all(taskId) as Array<{ checkId: string; outcome: string; at: string }>;
  const latest = [...new Map(checks.map((c) => [c.checkId, c])).values()];
  return [
    { name: "summary", classification: "public", data: { taskId, profile: task.profile, state: task.state, decision: decision?.outcome ?? null, decidedAt: decision?.at ?? null } },
    { name: "checks", classification: "internal", data: { latest, reasons: decision === undefined ? [] : JSON.parse(decision.reasons), unmeasured: decision === undefined ? [] : JSON.parse(decision.unmeasured) } },
    {
      name: "scope_and_people", classification: "confidential", data: {
        title: task.title, scope: JSON.parse(task.scope_json), requirements: JSON.parse(task.requirements_json), builder: task.builder_principal,
        verifiers: (db.prepare("SELECT DISTINCT verifier FROM sentinel_evidence WHERE task_id = ? AND origin = 'machine' ORDER BY verifier").all(taskId) as Array<{ verifier: string }>).map((v) => v.verifier),
        approvers: (db.prepare("SELECT approver, status FROM sentinel_approvals WHERE task_id = ? ORDER BY at").all(taskId) as Array<{ approver: string; status: string }>),
        findings: db.prepare("SELECT severity, title, disposition FROM sentinel_findings WHERE task_id = ? ORDER BY at").all(taskId)
      }
    },
    {
      name: "risk_acceptance_and_incidents", classification: "restricted", data: {
        exceptions: db.prepare("SELECT check_id AS checkId, status, requested_by AS requestedBy, approved_by AS approvedBy, risk_statement AS riskStatement, expires_at AS expiresAt FROM sentinel_exceptions WHERE task_id = ? ORDER BY at").all(taskId),
        incidentReviews: db.prepare("SELECT incident_ref AS incidentRef, outcome, test_path AS testPath, reviewed_by AS reviewedBy FROM sentinel_incident_reviews WHERE task_id = ? ORDER BY review_id").all(taskId)
      }
    }
  ];
}

export function exportReport(db: Database.Database, principal: Actor, taskId: string, classification: Classification, now?: Date): ExportResult {
  const at = now ?? new Date();
  if (!CLASSIFICATIONS.includes(classification)) {
    throw new EngbrainError("POLICY_REFUSED", `classification is one of: ${CLASSIFICATIONS.join(", ")}`);
  }
  const task = getTask(db, taskId);
  const scope = JSON.parse(task.scope_json) as string[];
  const grants = activeGrants(db, principal.id, EXPORT_ROLES, scope, at);
  if (grants.length === 0) {
    audit(db, principal.id, scope.join(","), classification, sha(""), { refused: "no active exporter/auditor grant covering the task scope" }, at);
    throw new EngbrainError("POLICY_REFUSED", "export refused: no active exporter or auditor grant covers this task (the refusal was audited)");
  }
  const clearance = Math.max(...grants.map((g) => rank(CLEARANCE[g.role as "exporter" | "auditor"])));
  const ceiling = Math.min(clearance, rank(classification));
  const content: Record<string, unknown> = { kind: "sentinel_evidence_export", classification: CLASSIFICATIONS[ceiling], exportedBy: principal.id, at: at.toISOString(), note: "No secrets, evidence payloads or environments are ever exported; this export certifies nothing." };
  const redactions: string[] = [];
  for (const s of sections(db, taskId)) {
    if (rank(s.classification) <= ceiling) {
      content[s.name] = scrub(s.data);
    } else {
      redactions.push(`${s.name} (${s.classification})`);
    }
  }
  const json = JSON.stringify(content);
  const digest = sha(json);
  const exportId = audit(db, principal.id, scope.join(","), CLASSIFICATIONS[ceiling]!, digest, redactions, at);
  return { exportId, classification: CLASSIFICATIONS[ceiling]!, content, json, sha256: digest, redactions };
}
