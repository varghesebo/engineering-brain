import type Database from "better-sqlite3";
import { EngbrainError } from "../errors.js";
import { showEvidence } from "../evidence/store.js";
import { changedPathsSince } from "../impact/impactEngine.js";
import { selectTests, type TestSelection } from "../impact/testSelection.js";
import { findSecretIn } from "../memory/records.js";
import { macosSandboxExec, type SelfTestResult } from "./execution.js";
import { appendEvidence, checkStanding, evaluateEligibility, getTask, type CheckStanding, type EvidenceOutcome, type Who } from "./tasks.js";
import { requiredChecks } from "./policy.js";
import { ASSURANCE_FORMATS, assuranceVerdict } from "./assurance/assuranceChecks.js";
import type { Role } from "./capabilities.js";

/**
 * Verification campaigns (Sentinel 3B). Three structurally distinct passes: FUNCTIONAL, ADVERSARIAL, SYSTEM_ASSURANCE. A pass with no evidence at all is NOT_RUN, never PASSED; a pass is PASSED only
 * when every check it requires has current, trusted, passing evidence. Results are recorded only through machine evidence (a verification role) bridged from a signed or accepted evidence import:
 * this phase never runs a repository's tests itself (see `assessRunEnforcement`: a run is refused unless the OS can enforce every limit, and on this build it cannot).
 */
export const PASS_CLASSES = ["FUNCTIONAL", "ADVERSARIAL", "SYSTEM_ASSURANCE"] as const;
export type PassClass = (typeof PASS_CLASSES)[number];

const PASS_OF: Readonly<Record<string, PassClass>> = {
  scope: "FUNCTIONAL", build: "FUNCTIONAL", lint: "FUNCTIONAL", typecheck: "FUNCTIONAL", tests: "FUNCTIONAL", unit_tests: "FUNCTIONAL", integration_tests: "FUNCTIONAL", contract_tests: "FUNCTIONAL", e2e_tests: "FUNCTIONAL",
  adversarial_review: "ADVERSARIAL", property_tests: "ADVERSARIAL", mutation_tests: "ADVERSARIAL", fuzz: "ADVERSARIAL", concurrency_tests: "ADVERSARIAL", failure_injection: "ADVERSARIAL", auth_boundary_tests: "ADVERSARIAL",
  dependency_review: "SYSTEM_ASSURANCE", security_review: "SYSTEM_ASSURANCE", independent_review: "SYSTEM_ASSURANCE", reproducible_build: "SYSTEM_ASSURANCE", historical_regressions: "SYSTEM_ASSURANCE",
  invariants_mapping: "SYSTEM_ASSURANCE", artifact_provenance: "SYSTEM_ASSURANCE", cross_service_contract: "SYSTEM_ASSURANCE", formal_verification: "SYSTEM_ASSURANCE"
};
/** A check the policy adds that this table does not know is treated as FUNCTIONAL: it still has to pass, it just has no special pass class. */
export const passOf = (check: string): PassClass => PASS_OF[check] ?? "FUNCTIONAL";

/**
 * Which imported artifact formats may back which check. A test-result artifact backs a TEST check, a SARIF report backs lint/typecheck; adversarial checks take only their own technique's
 * artifact (a unit-test file is not a mutation, property, fuzz or race run); everything else (scope, builds, reviews including security_review, dependency and provenance checks) is never
 * import-backed. One import can back only one check of a task, so a single unit-test run cannot satisfy several passes.
 */
const TEST_FORMATS = ["junit", "jest", "vitest", "pytest", "playwright"] as const;
export const IMPORT_BACKED: Readonly<Record<string, readonly string[]>> = {
  tests: TEST_FORMATS, unit_tests: TEST_FORMATS, integration_tests: TEST_FORMATS, contract_tests: TEST_FORMATS, e2e_tests: ["playwright", "junit"],
  property_tests: ["fastcheck", "hypothesis"], mutation_tests: ["stryker"], fuzz: ["race_log"], concurrency_tests: ["race_log"], failure_injection: ["race_log"],
  formal_verification: ["tla", "z3"], auth_boundary_tests: ["sarif", "semgrep_json"],
  lint: ["sarif"], typecheck: ["sarif", "junit"]
};
const SELECTION_AWARE = new Set(["tests", "unit_tests", "integration_tests"]);

export type CampaignStatus = "NOT_REQUIRED" | "NOT_RUN" | "PASSED" | "FAILED" | "INCOMPLETE" | "INVALIDATED";
export interface CampaignPass { passClass: PassClass; status: CampaignStatus; checks: CheckStanding[] }

function statusOf(checks: CheckStanding[]): CampaignStatus {
  if (checks.length === 0) {
    return "NOT_REQUIRED";
  }
  if (checks.every((c) => c.state === "none")) {
    return "NOT_RUN";
  }
  if (checks.some((c) => c.state === "current" && (c.outcome === "failed" || c.outcome === "timed_out"))) {
    return "FAILED";
  }
  if (checks.some((c) => c.outcome === "invalidated" || c.state === "stale" || c.state === "environment_changed")) {
    return "INVALIDATED";
  }
  if (checks.some((c) => c.payload?.["unsupported"] === true)) {
    return "INCOMPLETE"; // a technique that could not run is a visible gap, never a pass
  }
  return checks.every((c) => c.state === "current" && c.outcome === "passed") ? "PASSED" : "INCOMPLETE";
}

export function planCampaigns(db: Database.Database, storeDir: string, id: string, currentFingerprint: string, options: { now?: Date; environment?: Readonly<Record<string, string>> } = {}): CampaignPass[] {
  const task = getTask(db, id);
  const required = requiredChecks(storeDir, task.profile, JSON.parse(task.scope_json) as string[]);
  return PASS_CLASSES.map((passClass) => {
    const checks = required.filter((c) => passOf(c) === passClass).map((c) => checkStanding(db, storeDir, id, c, currentFingerprint, options.now, options.environment));
    return { passClass, status: statusOf(checks), checks };
  });
}

// ---------- bridging imported CI/test evidence ----------

export interface ImportedOutcome { outcome: EvidenceOutcome; reasons: string[] }

/**
 * How an import's counts read as ONE check outcome. Anything that is not an unqualified pass is not green: failures and errors fail, a timeout is timed_out, an empty or entirely skipped run is not_run
 * or skipped, a partial run is incomplete, and skipped tests mean `skipped` unless the caller explicitly allows that many.
 */
export function outcomeOfCounts(c: { total: number; passed: number; failed: number; skipped: number; timedOut: number; errors: number; partial: boolean }, maxSkipped = 0): ImportedOutcome {
  if (c.total === 0) {
    return { outcome: "not_run", reasons: ["the artifact contains no test results"] };
  }
  if (c.failed > 0 || c.errors > 0) {
    return { outcome: "failed", reasons: [`${c.failed} failed, ${c.errors} errored`] };
  }
  if (c.timedOut > 0) {
    return { outcome: "timed_out", reasons: [`${c.timedOut} timed out`] };
  }
  if (c.partial) {
    return { outcome: "incomplete", reasons: ["the run is incomplete (partial artifact)"] };
  }
  if (c.passed === 0) {
    return { outcome: "skipped", reasons: ["every test was skipped"] };
  }
  if (c.skipped > maxSkipped) {
    return { outcome: "skipped", reasons: [`${c.skipped} skipped (at most ${maxSkipped} allowed)`] };
  }
  return { outcome: "passed", reasons: [] };
}

/**
 * Records a check's result from an evidence import. The import must be signed or accepted (never quarantined), complete, STILL applying, and for exactly the code the task is bound to: its revision
 * must be the current checkpoint with a clean tree, so a run of different or since-modified code cannot approve this artifact. The recorded evidence carries the import id and artifact digest.
 */
export function recordFromImport(db: Database.Database, storeDir: string, id: string, checkId: string, importId: string, who: Who, currentFingerprint: string, options: { now?: Date; maxSkipped?: number } = {}): ImportedOutcome {
  const allowed = IMPORT_BACKED[checkId];
  if (allowed === undefined) {
    throw new EngbrainError("POLICY_REFUSED", `${checkId} cannot be backed by an imported artifact (import-backed checks: ${Object.keys(IMPORT_BACKED).join(", ")})`);
  }
  return db.transaction((): ImportedOutcome => {
    const detail = showEvidence(db, importId, options.now === undefined ? {} : { now: () => options.now! });
    if (detail === null) {
      throw new EngbrainError("INVALID_ROOT", "no such evidence import");
    }
    if (!allowed.includes(detail.format)) {
      throw new EngbrainError("POLICY_REFUSED", `a ${detail.format} artifact cannot back ${checkId} (it takes: ${allowed.join(", ")})`);
    }
    if (detail.trust !== "signed" && detail.trust !== "accepted") {
      throw new EngbrainError("POLICY_REFUSED", `this import is ${detail.trust}: only signed or operator-accepted evidence can back a check (a quarantined artifact is a claim, not a result; an artifact whose signature was invalid can never be accepted)`);
    }
    if (detail.standing !== "applies") {
      throw new EngbrainError("POLICY_REFUSED", `this import no longer applies (${detail.standing}): ${detail.reasons.join("; ")}`);
    }
    const checkpoint = db.prepare("SELECT processed_oid AS oid, overlay_hash AS overlay FROM history_checkpoints WHERE ref_key = 'HEAD'").get() as { oid: string | null; overlay: string | null } | undefined;
    if (detail.sourceRevision === null || checkpoint?.oid !== detail.sourceRevision || checkpoint?.overlay !== null) {
      throw new EngbrainError("POLICY_REFUSED", "the run was not made on the code this task is bound to (a different revision, or the tree has uncommitted changes): it cannot approve this artifact");
    }
    const used = db.prepare("SELECT check_id AS c FROM sentinel_evidence WHERE task_id = ? AND origin = 'machine' AND json_extract(payload_json, '$.importId') = ?").all(id, importId) as Array<{ c: string }>;
    if (used.length > 0) {
      throw new EngbrainError("POLICY_REFUSED", `this import was already recorded for ${used[0]!.c}: one artifact backs one check`);
    }
    let verdict: ImportedOutcome;
    if (ASSURANCE_FORMATS.includes(detail.format)) {
      verdict = assuranceVerdict(db, id, importId, detail.format, detail.partial);
    } else if (detail.format === "sarif") {
      const errors = (db.prepare("SELECT COUNT(*) AS n FROM evidence_findings WHERE import_id = ? AND level = 'error'").get(importId) as { n: number }).n;
      verdict = detail.partial ? { outcome: "incomplete", reasons: ["the SARIF report is incomplete"] } : errors > 0 ? { outcome: "failed", reasons: [`${errors} error-level findings`] } : { outcome: "passed", reasons: [] };
    } else {
      verdict = outcomeOfCounts({ ...detail.counts, partial: detail.partial }, options.maxSkipped ?? 0);
    }
    let selectionNote: string | null = null;
    if (verdict.outcome === "passed" && SELECTION_AWARE.has(checkId)) {
      const task = getTask(db, id);
      const changed = task.base_revision === null ? null : changedPathsSince(db, task.base_revision);
      if (changed !== null && changed.relation === "ancestor" && !changed.truncated && changed.paths.length > 0) {
        const selection = selectTests(db, { files: changed.paths });
        const inRun = new Set((db.prepare("SELECT DISTINCT file FROM evidence_results WHERE import_id = ? AND file IS NOT NULL").all(importId) as Array<{ file: string }>).map((r) => r.file));
        const missing = selection.selected.filter((t) => !inRun.has(t.path)).map((t) => t.path);
        if (missing.length > 0) {
          verdict = { outcome: "incomplete", reasons: [`${missing.length} selected tests are not in the run: ${missing.slice(0, 5).join(", ")}`] };
        } else {
          selectionNote = `all ${selection.selected.length} selected tests are in the run`;
        }
      } else {
        selectionNote = "no test selection was available for this task";
      }
    }
    appendEvidence(db, storeDir, id, {
      origin: "machine", kind: "check_result", checkId, outcome: verdict.outcome, environment: detail.environment,
      payload: { importId, artifactSha256: detail.artifactSha256, format: detail.format, counts: detail.counts, reasons: verdict.reasons, selection: selectionNote }
    }, who, currentFingerprint, options.now);
    return verdict;
  }).immediate();
}

// ---------- invalidation ----------

/**
 * Writes an explicit `invalidated` result for every required check whose latest evidence no longer stands (different source or policy, or a changed environment), so the report says why instead of
 * silently showing "pending". Append-only: the earlier results stay as history.
 */
export function invalidateEvidence(db: Database.Database, storeDir: string, id: string, who: Who, currentFingerprint: string, options: { now?: Date; environment?: Readonly<Record<string, string>> } = {}): string[] {
  const task = getTask(db, id);
  const invalidated: string[] = [];
  for (const check of requiredChecks(storeDir, task.profile, JSON.parse(task.scope_json) as string[])) {
    const st = checkStanding(db, storeDir, id, check, currentFingerprint, options.now, options.environment);
    if ((st.state === "stale" || st.state === "environment_changed") && st.outcome !== "invalidated") {
      appendEvidence(db, storeDir, id, { origin: "machine", kind: "invalidation", checkId: check, outcome: "invalidated", payload: { reason: st.state, previousOutcome: st.outcome } }, who, currentFingerprint, options.now);
      invalidated.push(check);
    }
  }
  return invalidated;
}

// ---------- requirement -> behavior -> test -> evidence ----------

export interface TraceInput { requirementIx: number; behavior: string; testPath: string; testName?: string; checkId: string }

export function addTraceLink(db: Database.Database, id: string, input: TraceInput, principal: string, now?: Date): void {
  const task = getTask(db, id);
  const requirements = JSON.parse(task.requirements_json) as string[];
  const behavior = input.behavior.trim();
  if (!Number.isInteger(input.requirementIx) || input.requirementIx < 0 || input.requirementIx >= requirements.length) {
    throw new EngbrainError("POLICY_REFUSED", "requirementIx must name one of the task's requirements");
  }
  if (IMPORT_BACKED[input.checkId] === undefined) {
    throw new EngbrainError("POLICY_REFUSED", `a trace link must name a test-backed check (${Object.keys(IMPORT_BACKED).join(", ")})`);
  }
  if (behavior.length < 1 || behavior.length > 300 || input.testPath.length > 500 || input.testPath.startsWith("/") || input.testPath.split("/").includes("..") || !/^[a-z][a-z0-9_]{1,39}$/.test(input.checkId) || findSecretIn({ behavior }) !== null) {
    throw new EngbrainError("POLICY_REFUSED", "a trace link needs a short behavior, a repository-relative test path and a check id");
  }
  db.prepare("INSERT INTO sentinel_trace (task_id, at, created_by, requirement_ix, behavior, test_path, test_name, check_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    .run(id, (now ?? new Date()).toISOString(), principal, input.requirementIx, behavior, input.testPath, input.testName ?? null, input.checkId);
}

export interface TraceReport {
  requirements: Array<{ index: number; text: string; status: "uncovered" | "unverified" | "failing" | "verified"; links: Array<{ behavior: string; testPath: string; testName: string | null; checkId: string; result: "passed" | "failed" | "skipped" | "not_in_evidence" | "no_evidence" }> }>;
  missingCoverage: string[];
}

/** Which requirements are covered by a test whose result is in CURRENT trusted evidence. A link to a test that never appears in the evidence is `unverified`, never `verified`. */
export function traceabilityReport(db: Database.Database, storeDir: string, id: string, currentFingerprint: string, now?: Date): TraceReport {
  const task = getTask(db, id);
  const requirements = JSON.parse(task.requirements_json) as string[];
  const links = db.prepare("SELECT requirement_ix AS ix, behavior, test_path AS testPath, test_name AS testName, check_id AS checkId FROM sentinel_trace WHERE task_id = ? ORDER BY link_id").all(id) as Array<{ ix: number; behavior: string; testPath: string; testName: string | null; checkId: string }>;
  const resultOf = (l: { testPath: string; testName: string | null; checkId: string }): TraceReport["requirements"][number]["links"][number]["result"] => {
    const st = checkStanding(db, storeDir, id, l.checkId, currentFingerprint, now);
    const importId = st.state === "current" && st.outcome === "passed" ? (st.payload?.["importId"] as string | undefined) : undefined;
    if (importId === undefined) {
      return "no_evidence"; // the check has no current PASSING evidence: nothing it recorded can verify a requirement
    }
    const rows = (l.testName === null
      ? db.prepare("SELECT outcome FROM evidence_results WHERE import_id = ? AND file = ?").all(importId, l.testPath)
      : db.prepare("SELECT outcome FROM evidence_results WHERE import_id = ? AND file = ? AND name = ?").all(importId, l.testPath, l.testName)) as Array<{ outcome: string }>;
    if (rows.length === 0) {
      return "not_in_evidence";
    }
    return rows.every((r) => r.outcome === "passed") ? "passed" : rows.some((r) => r.outcome === "skipped") && rows.every((r) => r.outcome === "skipped") ? "skipped" : "failed";
  };
  const out: TraceReport["requirements"] = requirements.map((text, index) => {
    const mine = links.filter((l) => l.ix === index).map((l) => ({ behavior: l.behavior, testPath: l.testPath, testName: l.testName, checkId: l.checkId, result: resultOf(l) }));
    const status = mine.length === 0 ? "uncovered" as const : mine.some((l) => l.result === "failed") ? "failing" as const : mine.some((l) => l.result === "passed") && mine.every((l) => l.result === "passed") ? "verified" as const : "unverified" as const;
    return { index, text, status, links: mine };
  });
  return { requirements: out, missingCoverage: out.filter((r) => r.status !== "verified").map((r) => `requirement ${r.index} (${r.text.slice(0, 80)}): ${r.status}`) };
}

// ---------- selection, enforcement and the dry run ----------

/** How many unselected tests policy adds as a hedge against dependencies the index cannot see. Higher assurance, bigger hedge; nothing about it is decided by a model. */
export const POLICY_SAMPLE: Readonly<Record<string, number>> = { A1: 0, A2: 5, A3: 20, A4: 50 };

export interface RunEnforcement { permitted: boolean; verified: string[]; missing: string[]; backend: string }
/**
 * Running a repository's tests needs ALL of: file-write confinement, network egress denial, and CPU/memory/process limits, each verified on this machine. Anything missing means NO run (fail closed);
 * indexing, MCP, evidence import and reporting never need it.
 */
export function assessRunEnforcement(sandbox: SelfTestResult, backend: { name: string; confines: string[] } = macosSandboxExec): RunEnforcement {
  const verified: string[] = [];
  const missing: string[] = [];
  if (sandbox.verified) {
    verified.push("file-write confinement (probed)");
  } else {
    missing.push("file-write confinement (no verified sandbox)");
  }
  missing.push("network egress denial verified by a probe", "CPU, memory and process-count limits");
  return { permitted: missing.length === 0, verified, missing, backend: backend.name };
}

export interface VerificationPlan {
  taskId: string; state: string; campaigns: CampaignPass[]; selection: TestSelection | null; enforcement: RunEnforcement;
  adapters: Record<string, string[]>; explanation: string[];
}

const ADAPTERS: Readonly<Record<string, string[]>> = {
  tests: ["vitest", "jest", "pytest", "playwright", "junit"], unit_tests: ["vitest", "jest", "pytest", "junit"], e2e_tests: ["playwright"], lint: ["sarif"], typecheck: ["sarif", "junit"],
  mutation_tests: ["stryker"], property_tests: ["fastcheck", "hypothesis"], fuzz: ["race_log"], concurrency_tests: ["race_log"], failure_injection: ["race_log"], formal_verification: ["tla", "z3"], auth_boundary_tests: ["sarif", "semgrep_json"]
};

/** What a verification would do and why, without running anything: the passes, the tests selected (with proof, unknown areas and policy sampling), the enforcement a run needs, and what is missing. */
export function planVerification(db: Database.Database, storeDir: string, id: string, currentFingerprint: string, sandbox: SelfTestResult, options: { now?: Date; environment?: Readonly<Record<string, string>> } = {}): VerificationPlan {
  const task = getTask(db, id);
  const campaigns = planCampaigns(db, storeDir, id, currentFingerprint, options);
  let selection: TestSelection | null = null;
  const explanation: string[] = [];
  if (task.base_revision !== null) {
    const changed = changedPathsSince(db, task.base_revision);
    if (changed.relation === "ancestor" && !changed.truncated && changed.paths.length > 0) {
      const sample = Math.min(POLICY_SAMPLE[task.profile] ?? 0, 100);
      selection = selectTests(db, { files: changed.paths, sample, sampleSeed: `${id}:${currentFingerprint}` });
      if (selection.truncated) {
        explanation.push("the selection was truncated by a limit: omitted files are listed as unmapped (unknown)");
      }
      explanation.push(`selected ${selection.selected.length} tests with proof for ${changed.paths.length} committed changed files; ${selection.unmapped.length} files have no mapped test (unknown, not safe); policy ${task.profile} adds a sample of ${selection.sample.length} unselected tests as a hedge`);
    } else {
      explanation.push(`test selection is not available (${changed.relation}${changed.truncated ? ", truncated" : ""}, ${changed.paths.length} committed changed files); uncommitted edits are not visible to it`);
    }
  } else {
    explanation.push("the task has no base revision: no test selection");
  }
  for (const c of campaigns) {
    explanation.push(`${c.passClass}: ${c.status}${c.checks.length === 0 ? "" : ` (${c.checks.map((k) => `${k.checkId}=${k.state === "current" ? k.outcome : k.state}`).join(", ")})`}`);
  }
  const enforcement = assessRunEnforcement(sandbox);
  explanation.push(enforcement.permitted ? "a run is permitted by the sandbox" : `a run is NOT permitted: missing ${enforcement.missing.join("; ")}`);
  explanation.push("results can still be recorded from signed or accepted evidence imports (`evidence import`, then `sentinel import`)");
  const eligibility = evaluateEligibility(db, storeDir, id, currentFingerprint, options.now, options.environment);
  if (eligibility.blockers.length > 0) {
    explanation.push(`blocking: ${eligibility.blockers.join("; ")}`);
  }
  return { taskId: id, state: task.state, campaigns, selection, enforcement, adapters: Object.fromEntries(Object.entries(ADAPTERS)), explanation };
}

/** `verify --run`: authorization is checked elsewhere; this refuses outright when the OS cannot enforce every limit. */
export function refuseRunIfUnenforceable(sandbox: SelfTestResult): never {
  const e = assessRunEnforcement(sandbox);
  throw new EngbrainError("POLICY_REFUSED", `running repository tests is refused: the sandbox cannot enforce ${e.missing.join("; ")}. Import results from an isolated CI run instead.`);
}

export type { Role };
