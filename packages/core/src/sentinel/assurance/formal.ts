import { createHash, randomUUID } from "node:crypto";
import type Database from "better-sqlite3";
import { EngbrainError } from "../../errors.js";
import { assuranceDetail, showEvidence } from "../../evidence/store.js";
import { findSecretIn } from "../../memory/records.js";
import { getTask, type EvidenceOutcome } from "../tasks.js";

/**
 * Formal checks (Sentinel 3D): TLA+ model checking and SMT solving. A success is a statement about the MODEL under its stated assumptions, never about the application: the schema pins
 * `scope = 'model_only'` and `claims_application_proof = 0`. A counterexample fails; an unknown or errored solver result is incomplete; a missing solver is recorded as unsupported
 * (`recordUnsupported` in assuranceChecks), never as a pass.
 */
export const FORMAL_MODEL_ONLY = "model only: not an application-wide proof";

export type FormalResult = "counterexample" | "scoped_success" | "unknown" | "unsupported" | "error";
export interface FormalVerdict { outcome: EvidenceOutcome; reasons: string[] }

export function formalVerdict(result: FormalResult): FormalVerdict {
  switch (result) {
    case "counterexample": return { outcome: "failed", reasons: ["the checker found a counterexample"] };
    case "scoped_success": return { outcome: "passed", reasons: [FORMAL_MODEL_ONLY] };
    case "unknown": return { outcome: "incomplete", reasons: ["the solver returned unknown (no result either way)"] };
    case "unsupported": return { outcome: "not_run", reasons: ["the formal tool is not available"] };
    case "error": return { outcome: "incomplete", reasons: ["the checker reported an error"] };
  }
}

export interface FormalInput {
  /** What the model assumes (bounds, environment, abstractions). At least one, stated by a person. */
  assumptions: string[];
  /** Which code the model stands for, and at which revision. */
  applicability: { paths: string[]; baseRevision: string };
  /** Used when the artifact itself does not name the model's digest or specification version. */
  modelSha256?: string;
  specVersion?: string;
}

const line = (v: unknown, max: number, what: string): string => {
  if (typeof v !== "string" || v.trim().length < 1 || v.length > max || /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(v)) {
    throw new EngbrainError("POLICY_REFUSED", `${what} must be 1-${max} characters without control or invisible formatting characters`);
  }
  return v.trim();
};

/** Records a TLA+/Z3 result for a task with its assumptions and applicability. The import must be signed or accepted and carry formal detail. */
export function recordFormalResult(db: Database.Database, taskId: string, importId: string, input: FormalInput, now?: Date): { formalId: string; result: FormalResult; verdict: FormalVerdict } {
  if (!Array.isArray(input.assumptions) || input.assumptions.length === 0 || input.assumptions.length > 50) {
    throw new EngbrainError("POLICY_REFUSED", "a formal result needs 1-50 stated assumptions: a model check without its assumptions means nothing");
  }
  const assumptions = input.assumptions.map((a) => line(a, 500, "an assumption"));
  const paths = (Array.isArray(input.applicability?.paths) ? input.applicability.paths : []).map((p) => line(p, 500, "an applicability path"));
  if (paths.length === 0 || paths.length > 200 || paths.some((p) => p.startsWith("/") || p.includes("\\") || p.split("/").includes(".."))) {
    throw new EngbrainError("POLICY_REFUSED", "applicability needs 1-200 repository-relative paths the model stands for");
  }
  if (typeof input.applicability.baseRevision !== "string" || !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(input.applicability.baseRevision)) {
    throw new EngbrainError("POLICY_REFUSED", "applicability needs the full commit id the model was written against");
  }
  if (input.modelSha256 !== undefined && !/^[0-9a-f]{64}$/.test(input.modelSha256)) {
    throw new EngbrainError("POLICY_REFUSED", "modelSha256 must be 64 hex characters");
  }
  if (findSecretIn({ assumptions, paths }) !== null) {
    throw new EngbrainError("POLICY_REFUSED", "the assumptions look like they contain a secret");
  }
  return db.transaction(() => {
    getTask(db, taskId);
    const ev = showEvidence(db, importId, now === undefined ? {} : { now: () => now });
    if (ev === null) {
      throw new EngbrainError("INVALID_ROOT", "no such evidence import");
    }
    if (ev.trust !== "signed" && ev.trust !== "accepted") {
      throw new EngbrainError("POLICY_REFUSED", `this import is ${ev.trust}: only signed or accepted evidence can record a formal result`);
    }
    const detail = assuranceDetail(db, importId);
    if (detail === null || detail.kind !== "formal" || detail.formal === undefined) {
      throw new EngbrainError("POLICY_REFUSED", "this import carries no formal-verification detail");
    }
    const modelSha = detail.formal.modelSha256 ?? input.modelSha256 ?? null;
    if (modelSha === null) {
      throw new EngbrainError("POLICY_REFUSED", "a formal result must name the digest of the model it checked (the artifact does not, so pass modelSha256)");
    }
    const result = detail.formal.result;
    const counterexample = result === "counterexample" ? JSON.stringify(detail.formal.counterexample ?? null) : null;
    const formalId = `fm_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
    db.prepare(
      `INSERT INTO sentinel_formal (formal_id, task_id, import_id, tool, tool_version, model_sha256, spec_version, assumptions_json, result_digest, result, counterexample_json, applicability_json, scope, claims_application_proof, at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'model_only', 0, ?)`
    ).run(formalId, taskId, importId, detail.tool ?? ev.format, detail.toolVersion ?? "unknown", modelSha, detail.formal.specVersion ?? input.specVersion ?? "unspecified", JSON.stringify(assumptions),
      createHash("sha256").update(JSON.stringify(detail.formal)).digest("hex"), result, counterexample, JSON.stringify({ paths, baseRevision: input.applicability.baseRevision }), (now ?? new Date()).toISOString());
    return { formalId, result, verdict: formalVerdict(result) };
  }).immediate();
}

/** Whether a formal result with stated assumptions was recorded for this task and import (a model success without them is not counted as a pass). */
export const formalRecorded = (db: Database.Database, taskId: string, importId: string): boolean =>
  db.prepare("SELECT 1 FROM sentinel_formal WHERE task_id = ? AND import_id = ? LIMIT 1").get(taskId, importId) !== undefined;
