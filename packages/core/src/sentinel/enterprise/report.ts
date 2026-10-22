import type Database from "better-sqlite3";
import { planCampaigns } from "../campaigns.js";
import { getTask } from "../tasks.js";
import { evaluateDecision, DECISION_NOTE, type DecideOptions } from "./controller.js";
import { latestManifest, verifyManifest } from "./manifest.js";
import { regressionStanding } from "./regression.js";

/**
 * Human-readable and JSON assurance report (Sentinel 3E) with FIXED sections. It states what the evidence shows and, just as prominently, what it does not: nothing is certified, nothing is
 * formally proved, nothing was executed by this build, several platforms are untested, and the independent review of this implementation was done by a Claude agent, not Codex. Read-only:
 * it evaluates the controller's verdict without appending a decision.
 */
export const NOT_CERTIFIED: readonly string[] = [
  "A1-A4 are internal assurance profiles of this tool; they are not industry certifications and imply no compliance with any standard or regulation (e.g. SOC 2, ISO 27001, PCI DSS, DO-178C, IEC 62304).",
  "ELIGIBLE_FOR_APPROVAL is not a release approval: it grants no authority to merge, push, publish, release or deploy.",
  "Approver, verifier and operator identities are local principals (token/grant based), not SSO-, HSM- or PKI-backed identities.",
  "Verifier keys are org-registered Ed25519 public keys; this build does not validate them against an external PKI or transparency log."
];
export const NOT_FORMALLY_PROVED: readonly string[] = [
  "No property of the change is formally proved: check results are recorded evidence, not proofs.",
  "Hash chains and MACs detect edits behind the API; they do not prove the recorded results were true when recorded (the MAC key is a local 0600 file of the same OS user)."
];
export const NOT_EXECUTED: readonly string[] = [
  "This build executes nothing: no tests, builds, linters or tools were run by Sentinel 3E; every check result is imported or recorded evidence.",
  "No merge, push, release or deployment was performed or authorized."
];
export const UNSUPPORTED_PLATFORMS: readonly string[] = ["Linux: untested", "Windows: untested", "Node 24: untested"];
export const INDEPENDENT_REVIEW = "The independent review of this Sentinel 3E implementation was performed by a Claude agent, not Codex; an independent (Codex or human) review is still outstanding and is a blocker for high-assurance use.";

export interface AssuranceReport {
  taskId: string; profile: string; state: string;
  decision: { outcome: string; reasons: string[]; unmeasured: string[]; note: string };
  verified: { manifestId: string | null; manifestOk: boolean; manifestProblems: string[]; passingChecks: string[]; independentApprovers: string[]; incidentsAffected: number; incidentsUnreviewed: number };
  notCertified: readonly string[]; notFormallyProved: readonly string[]; notExecuted: readonly string[]; unsupportedPlatforms: readonly string[]; independentReview: string;
}

export function assuranceReport(db: Database.Database, storeDir: string, taskId: string, currentFingerprint: string, env: Readonly<Record<string, string>>, now?: Date, options: DecideOptions = {}): { json: AssuranceReport; text: string } {
  const task = getTask(db, taskId);
  const decision = evaluateDecision(db, storeDir, taskId, currentFingerprint, env, now, options);
  const manifest = latestManifest(db, taskId);
  const mv = manifest === null ? null : verifyManifest(db, storeDir, manifest.manifest_id, currentFingerprint, env, options.artifacts === undefined ? {} : { artifacts: options.artifacts });
  const checks = planCampaigns(db, storeDir, taskId, currentFingerprint, now === undefined ? {} : { now }).flatMap((c) => c.checks);
  const regressions = regressionStanding(db, taskId);
  const json: AssuranceReport = {
    taskId, profile: task.profile, state: task.state,
    decision: { outcome: decision.outcome, reasons: decision.reasons, unmeasured: decision.unmeasured, note: DECISION_NOTE },
    verified: {
      manifestId: manifest?.manifest_id ?? null, manifestOk: mv?.ok ?? false, manifestProblems: mv?.problems ?? ["no manifest"],
      passingChecks: checks.filter((c) => c.state === "current" && c.outcome === "passed").map((c) => c.checkId).sort(), independentApprovers: decision.independentApprovers,
      incidentsAffected: regressions.affected.length, incidentsUnreviewed: regressions.unreviewed.length
    },
    notCertified: NOT_CERTIFIED, notFormallyProved: NOT_FORMALLY_PROVED, notExecuted: NOT_EXECUTED, unsupportedPlatforms: UNSUPPORTED_PLATFORMS, independentReview: INDEPENDENT_REVIEW
  };
  const list = (items: readonly string[]): string[] => (items.length === 0 ? ["  (none)"] : items.map((i) => `  - ${i}`));
  const text = [
    `Sentinel assurance report — task ${taskId} (profile ${task.profile}, state ${task.state})`,
    `Outcome: ${decision.outcome}`, `  ${DECISION_NOTE}`,
    "", "WHAT WAS VERIFIED",
    `  Manifest: ${json.verified.manifestId ?? "none"} (${json.verified.manifestOk ? "verifies for the current source, environment, policy and evidence" : "does NOT verify"})`,
    ...list(json.verified.manifestProblems.map((p) => `manifest: ${p}`)),
    `  Passing checks with current, trusted evidence: ${json.verified.passingChecks.join(", ") || "none"}`,
    `  Independent, granted approvals: ${decision.independentApprovers.length} of ${decision.approvalsNeeded}`,
    `  Affected incidents: ${json.verified.incidentsAffected} (unreviewed: ${json.verified.incidentsUnreviewed})`,
    "", "REASONS", ...list(decision.reasons),
    "", "UNMEASURED RISKS", ...list(decision.unmeasured),
    "", "NOT CERTIFIED", ...list(NOT_CERTIFIED),
    "", "NOT FORMALLY PROVED", ...list(NOT_FORMALLY_PROVED),
    "", "NOT EXECUTED", ...list(NOT_EXECUTED),
    "", "UNSUPPORTED / UNTESTED PLATFORMS", ...list(UNSUPPORTED_PLATFORMS),
    "", "INDEPENDENT REVIEW", `  ${INDEPENDENT_REVIEW}`
  ].join("\n");
  return { json, text };
}
