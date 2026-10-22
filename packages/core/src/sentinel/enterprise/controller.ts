import { hmacHex } from "../capabilities.js";
import { createHash } from "node:crypto";
import type Database from "better-sqlite3";
import { planCampaigns } from "../campaigns.js";
import { effectiveProfile, policyHash } from "../policy.js";
import { approvalMac, evaluateEligibility, getTask, type CheckStanding, type TaskRow } from "../tasks.js";
import { activeExceptions } from "./exceptions.js";
import { assertGrant, assertIndependentApproval } from "./grants.js";
import { verifyingKey } from "./keys.js";
import { evidenceHead, latestManifest, verifyManifest, type SentinelManifestRow } from "./manifest.js";
import { regressionStanding } from "./regression.js";

/**
 * Assurance controller (Sentinel 3E). A deterministic verdict over everything the store holds for a task, appended to a hash-chained, append-only decision log:
 *   ELIGIBLE_FOR_APPROVAL  the latest manifest verifies for the exact current source/environment/policy/evidence, every required check has current, trusted, passing evidence, no blocking
 *                          finding is open, every affected incident was reviewed, verifier signatures (A3/A4) verify, and enough independent, granted approvals are bound to this state;
 *   APPROVAL_REQUIRED      only human acts are missing (approvals, grants, incident reviews, a verifier signature) or a check is covered by a logged exception (never a pass);
 *   INCOMPLETE             a required check was skipped, not run, unsupported, or there is no manifest;
 *   STALE_EVIDENCE         source, environment, policy or evidence moved on after verification;
 *   FAILED                 a required check currently fails (or the task itself failed);
 *   BLOCKED                tampering or forgery (manifest, approval MAC, signature, artifact digest), an open blocking finding, or a blocked task.
 * No outcome — ELIGIBLE_FOR_APPROVAL included — grants authority to merge, push, release or deploy; nothing here executes anything.
 */
export const DECISION_OUTCOMES = ["ELIGIBLE_FOR_APPROVAL", "APPROVAL_REQUIRED", "BLOCKED", "FAILED", "INCOMPLETE", "STALE_EVIDENCE"] as const;
export type DecisionOutcome = (typeof DECISION_OUTCOMES)[number];
/** Worst first: the first outcome any reason asks for wins. */
const SEVERITY: readonly DecisionOutcome[] = ["BLOCKED", "STALE_EVIDENCE", "FAILED", "INCOMPLETE", "APPROVAL_REQUIRED", "ELIGIBLE_FOR_APPROVAL"];
const SIGNED_PROFILES = new Set(["A3", "A4"]);
export const DECISION_NOTE = "ELIGIBLE_FOR_APPROVAL means the evidence supports a human release decision. It grants NO authority to merge, push, publish, release or deploy, and nothing was executed to reach it.";

export interface VerifierSignature { principal: string; signatureHex: string }
export interface DecideOptions {
  /** Ed25519 signatures by registered verifier principals over the manifest's `body_sha256`. Required (at least one valid, not the builder's) for A3/A4. */
  signatures?: readonly VerifierSignature[];
  /** Artifact digests recomputed now; any difference from the manifest is a swapped artifact. */
  artifacts?: Readonly<Record<string, string>>;
}
export interface Decision { outcome: DecisionOutcome; reasons: string[]; unmeasured: string[]; manifestId: string | null; independentApprovers: string[]; approvalsNeeded: number; note: string }
export interface RecordedDecision extends Decision { seq: number; hash: string }

const sha = (s: string): string => createHash("sha256").update(s).digest("hex");
const clock = (now?: Date): Date => now ?? new Date();

type Verdicts = Array<{ outcome: DecisionOutcome; reason: string }>;

function isUnsupported(c: CheckStanding): boolean {
  const p = c.payload ?? {};
  return p["unsupported"] === true || (typeof p["reason"] === "string" && /unsupported/i.test(p["reason"]));
}

function judgeManifest(manifest: SentinelManifestRow | null, verification: ReturnType<typeof verifyManifest> | null, out: Verdicts): void {
  if (manifest === null || verification === null) {
    out.push({ outcome: "INCOMPLETE", reason: "no proof-carrying manifest has been built for this task" });
    return;
  }
  for (const p of verification.problems) {
    out.push({ outcome: /tampered|forged|swapped|does not match|disagree/.test(p) ? "BLOCKED" : "STALE_EVIDENCE", reason: `manifest ${manifest.manifest_id}: ${p}` });
  }
}

function judgeChecks(checks: CheckStanding[], excepted: Map<string, string>, out: Verdicts, unmeasured: string[]): void {
  for (const c of checks) {
    const exception = excepted.get(c.checkId);
    const passing = c.state === "current" && c.outcome === "passed" && !isUnsupported(c);
    if (passing) {
      continue;
    }
    if (isUnsupported(c)) {
      unmeasured.push(`${c.checkId}: the tool or platform is unsupported, so it was not measured`);
    }
    if (exception !== undefined && c.state !== "stale" && c.state !== "environment_changed") {
      out.push({ outcome: "APPROVAL_REQUIRED", reason: `${c.checkId}: ${c.outcome} — NOT passed; risk accepted by exception ${exception} (still requires approval)` });
      continue;
    }
    if (c.state === "stale" || c.state === "environment_changed" || c.state === "expired") {
      out.push({ outcome: "STALE_EVIDENCE", reason: c.blocker ?? `${c.checkId}: evidence is stale` });
    } else if (c.state === "current" && (c.outcome === "failed" || c.outcome === "timed_out")) {
      out.push({ outcome: "FAILED", reason: `${c.checkId}: ${c.outcome}` });
    } else {
      if (c.state === "none" || c.outcome === "not_run") {
        unmeasured.push(`${c.checkId}: not run`);
      }
      out.push({ outcome: "INCOMPLETE", reason: `${c.checkId}: ${isUnsupported(c) ? "unsupported" : c.outcome} (a check that did not run to a pass is never a pass)` });
    }
  }
}

function judgeApprovals(db: Database.Database, storeDir: string, task: TaskRow, currentFingerprint: string, now: Date, out: Verdicts): string[] {
  const policy = policyHash(storeDir);
  const head = evidenceHead(db, task.task_id);
  const rows = db.prepare("SELECT * FROM sentinel_approvals WHERE task_id = ? AND status = 'active'").all(task.task_id) as Array<Record<string, any>>;
  const independent = new Set<string>();
  for (const r of rows) {
    if (r["mac"] !== approvalMac(storeDir, r)) {
      out.push({ outcome: "BLOCKED", reason: `approval ${String(r["approval_id"]).slice(0, 40)} by ${String(r["approver"]).slice(0, 60)} carries a forged or altered MAC` });
      continue;
    }
    if (r["source_fingerprint"] !== currentFingerprint || r["policy_hash"] !== policy || r["evidence_head"] !== head) {
      continue; // a stale approval simply does not count
    }
    try {
      assertIndependentApproval(db, task, r["approver"] as string, now);
      independent.add(r["approver"] as string);
    } catch (e) {
      out.push({ outcome: "APPROVAL_REQUIRED", reason: `approval by ${r["approver"]} does not count: ${(e as Error).message}` });
    }
  }
  const needed = effectiveProfile(storeDir, task.profile).minApprovals;
  if (independent.size < needed) {
    out.push({ outcome: "APPROVAL_REQUIRED", reason: `${independent.size} of ${needed} independent, granted approvals bound to the current source, policy and evidence` });
  }
  return [...independent].sort();
}

function judgeSignatures(db: Database.Database, task: TaskRow, manifest: SentinelManifestRow | null, signatures: readonly VerifierSignature[], now: Date, out: Verdicts): void {
  let valid = 0;
  for (const s of signatures) {
    const ok = manifest !== null && verifyingKey(db, s.principal, manifest.body_sha256, s.signatureHex, now) !== null;
    if (!ok) {
      out.push({ outcome: "BLOCKED", reason: `the verifier signature claimed for ${String(s.principal).slice(0, 60)} does not verify under an active, registered key (forged, revoked, expired or over a different manifest)` });
    } else if (s.principal === task.builder_principal) {
      out.push({ outcome: "BLOCKED", reason: "the builder cannot sign the verification of its own work" });
    } else {
      valid += 1;
    }
  }
  if (SIGNED_PROFILES.has(task.profile) && valid === 0) {
    out.push({ outcome: "APPROVAL_REQUIRED", reason: `${task.profile} needs a verifier signature over the manifest from a registered key` });
  }
}

/** Computes the verdict without recording it (the report uses this). `decide` records it. */
export function evaluateDecision(db: Database.Database, storeDir: string, taskId: string, currentFingerprint: string, env: Readonly<Record<string, string>>, now?: Date, options: DecideOptions = {}): Decision {
  const at = clock(now);
  const task = getTask(db, taskId);
  const out: Verdicts = [];
  const unmeasured: string[] = [];
  if (task.state === "FAILED" || task.state === "CANCELLED") {
    out.push({ outcome: "FAILED", reason: `the task is ${task.state}` });
  }
  if (task.state === "BLOCKED") {
    out.push({ outcome: "BLOCKED", reason: `the task is BLOCKED: ${task.blocked_reason ?? "no reason recorded"}` });
  }
  const manifest = latestManifest(db, taskId);
  const verification = manifest === null ? null : verifyManifest(db, storeDir, manifest.manifest_id, currentFingerprint, env, options.artifacts === undefined ? {} : { artifacts: options.artifacts });
  judgeManifest(manifest, verification, out);
  const eligibility = evaluateEligibility(db, storeDir, taskId, currentFingerprint, at);
  for (const s of eligibility.stale) {
    out.push({ outcome: "STALE_EVIDENCE", reason: s });
  }
  for (const b of eligibility.blockers.filter((x) => /log failed verification|open blocking/.test(x))) {
    out.push({ outcome: "BLOCKED", reason: b });
  }
  const excepted = new Map<string, string>();
  for (const e of activeExceptions(db, taskId, at, storeDir)) {
    try {
      assertGrant(db, e.approved_by ?? "", "exception_approver", JSON.parse(task.scope_json) as string[], at); // the approver must STILL hold the grant
      excepted.set(e.check_id, e.exception_id);
    } catch {
      out.push({ outcome: "APPROVAL_REQUIRED", reason: `exception ${e.exception_id} no longer counts: its approver's grant was revoked` });
    }
  }
  const checks = planCampaigns(db, storeDir, taskId, currentFingerprint, { now: at }).flatMap((c) => c.checks);
  judgeChecks(checks, excepted, out, unmeasured);
  judgeSignatures(db, task, manifest, options.signatures ?? [], at, out);
  const independentApprovers = judgeApprovals(db, storeDir, task, currentFingerprint, at, out);
  const regressions = regressionStanding(db, taskId);
  for (const i of regressions.unreviewed) {
    out.push({ outcome: "APPROVAL_REQUIRED", reason: `affected incident ${i.incidentRef} (${i.title.slice(0, 80)}) has not been reviewed for this change` });
  }
  for (const i of regressions.notCovered) {
    unmeasured.push(`affected incident ${i.incidentRef}: no regression test covers it`);
    out.push({ outcome: "APPROVAL_REQUIRED", reason: `affected incident ${i.incidentRef} is not covered by a regression test` });
  }
  const outcome = SEVERITY.find((o) => out.some((v) => v.outcome === o)) ?? "ELIGIBLE_FOR_APPROVAL";
  return {
    outcome, reasons: [...new Set(out.map((v) => `[${v.outcome}] ${v.reason}`))], unmeasured: [...new Set(unmeasured)], manifestId: manifest?.manifest_id ?? null,
    independentApprovers, approvalsNeeded: effectiveProfile(storeDir, task.profile).minApprovals, note: DECISION_NOTE
  };
}

const GENESIS = sha("genesis:sentinel_decisions");
const decisionHash = (d: { prev: string; taskId: string; manifestId: string | null; outcome: string; reasons: string; unmeasured: string; policy: string; fp: string; at: string }): string =>
  sha(JSON.stringify([d.prev, d.taskId, d.manifestId, d.outcome, d.reasons, d.unmeasured, d.policy, d.fp, d.at]));

/** Evaluates and appends the verdict to the decision log (one global hash chain, append-only by trigger). */
export function decide(db: Database.Database, storeDir: string, taskId: string, currentFingerprint: string, env: Readonly<Record<string, string>>, now?: Date, options: DecideOptions = {}): RecordedDecision {
  const at = clock(now);
  return db.transaction((): RecordedDecision => {
    const d = evaluateDecision(db, storeDir, taskId, currentFingerprint, env, at, options);
    const prev = (db.prepare("SELECT hash FROM sentinel_decisions ORDER BY seq DESC LIMIT 1").get() as { hash: string } | undefined)?.hash ?? GENESIS;
    const row = { prev, taskId, manifestId: d.manifestId, outcome: d.outcome, reasons: JSON.stringify(d.reasons), unmeasured: JSON.stringify(d.unmeasured), policy: policyHash(storeDir), fp: currentFingerprint, at: at.toISOString() };
    const hash = decisionHash(row);
    // the MAC (controller key) makes a raw INSERT that correctly extends the chain detectable: only this code can sign a decision
    const info = db.prepare("INSERT INTO sentinel_decisions (task_id, manifest_id, outcome, reasons_json, unmeasured_json, policy_hash, source_fingerprint, at, prev_hash, hash, mac) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .run(taskId, d.manifestId, d.outcome, row.reasons, row.unmeasured, row.policy, row.fp, row.at, prev, hash, hmacHex(storeDir, `decision\0${hash}`, true));
    return { ...d, seq: Number(info.lastInsertRowid), hash };
  }).immediate();
}

/** Recomputes every link of the decision chain. An inserted, reordered or altered decision breaks it (the triggers already refuse UPDATE and DELETE). */
export function verifyDecisionChain(db: Database.Database, storeDir?: string): { ok: boolean; problems: string[]; decisions: number } {
  const problems: string[] = [];
  let prev = GENESIS;
  const rows = db.prepare("SELECT * FROM sentinel_decisions ORDER BY seq").all() as Array<Record<string, any>>;
  for (const r of rows) {
    const expected = decisionHash({ prev, taskId: r["task_id"], manifestId: r["manifest_id"], outcome: r["outcome"], reasons: r["reasons_json"], unmeasured: r["unmeasured_json"], policy: r["policy_hash"], fp: r["source_fingerprint"], at: r["at"] });
    if (r["prev_hash"] !== prev || r["hash"] !== expected) {
      problems.push(`decision ${r["seq"]} does not match the hash chain`);
    } else if (storeDir !== undefined && r["mac"] !== safeMac(storeDir, `decision\0${r["hash"]}`)) {
      problems.push(`decision ${r["seq"]} carries no valid controller signature`);
    }
    prev = r["hash"];
  }
  return { ok: problems.length === 0, problems, decisions: rows.length };
}

/** The controller MAC, or "" when no controller key exists (then every signed row fails to verify, as it should). */
function safeMac(storeDir: string, data: string): string {
  try {
    return hmacHex(storeDir, data);
  } catch {
    return "";
  }
}
