import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { EngbrainError } from "../errors.js";
import { requireRole, withLock, type Actor } from "../memory/operators.js";

/**
 * Policy-as-code profiles. A1-A4 are INTERNAL assurance profiles of this tool: they are not industry certifications and do not imply compliance with any standard.
 * A local policy file may only make a profile STRICTER (add checks, raise the approval count, shorten the evidence lifetime); nothing in it can remove a mandatory check. Changing it needs an
 * authenticated admin operator, never an agent capability. Risk scoring likewise only ever adds checks.
 */
export const SENTINEL_POLICY_FILE = "sentinel-policy.json";
export const PROFILES = ["A1", "A2", "A3", "A4"] as const;
export type Profile = (typeof PROFILES)[number];

export interface ProfilePolicy {
  description: string;
  mandatoryChecks: string[];
  /** Distinct human approvers needed; the builder principal can never be one of them. */
  minApprovals: number;
  evidenceMaxAgeHours: number;
  /** Reserved. This build has NO override mechanism: every mandatory check is non-waivable, so every profile says `none`. */
  overrides: "none";
  /** Who a human should escalate to; informational only in this build (nothing routes to it). */
  escalation: string;
}

export const BASE_PROFILES: Readonly<Record<Profile, ProfilePolicy>> = {
  A1: { description: "A1 Standard (internal profile)", mandatoryChecks: ["scope", "tests", "lint"], minApprovals: 1, evidenceMaxAgeHours: 168, overrides: "none", escalation: "task owner" },
  A2: { description: "A2 Production (internal profile)", mandatoryChecks: ["scope", "tests", "lint", "typecheck", "dependency_review"], minApprovals: 1, evidenceMaxAgeHours: 72, overrides: "none", escalation: "service owner" },
  A3: { description: "A3 High Assurance (internal profile)", mandatoryChecks: ["scope", "tests", "lint", "typecheck", "dependency_review", "security_review", "adversarial_review"], minApprovals: 2, evidenceMaxAgeHours: 24, overrides: "none", escalation: "security lead" },
  A4: { description: "A4 Mission Critical (internal profile)", mandatoryChecks: ["scope", "tests", "lint", "typecheck", "dependency_review", "security_review", "adversarial_review", "independent_review", "reproducible_build"], minApprovals: 2, evidenceMaxAgeHours: 8, overrides: "none", escalation: "engineering director" }
};

const CHECK_ID = /^[a-z][a-z0-9_]{1,39}$/;
export interface PolicyFile { extraChecks: Partial<Record<Profile, string[]>>; minApprovals: Partial<Record<Profile, number>>; evidenceMaxAgeHours: Partial<Record<Profile, number>>; updatedBy: string; updatedAt: string }
const emptyFile = (): PolicyFile => ({ extraChecks: {}, minApprovals: {}, evidenceMaxAgeHours: {}, updatedBy: "", updatedAt: "" });

export function loadPolicyFile(storeDir: string): PolicyFile {
  const path = join(storeDir, SENTINEL_POLICY_FILE);
  if (!existsSync(path)) {
    return emptyFile();
  }
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 65_536) {
    throw new EngbrainError("STORE_UNSAFE_PATH", "sentinel-policy.json is not a regular file of reasonable size");
  }
  try {
    const raw = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
    const obj = (v: unknown): Record<string, never> => (typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, never>) : {});
    return { extraChecks: obj(raw["extraChecks"]), minApprovals: obj(raw["minApprovals"]), evidenceMaxAgeHours: obj(raw["evidenceMaxAgeHours"]), updatedBy: typeof raw["updatedBy"] === "string" ? raw["updatedBy"] : "", updatedAt: typeof raw["updatedAt"] === "string" ? raw["updatedAt"] : "" };
  } catch {
    throw new EngbrainError("INVALID_CONFIG", "sentinel-policy.json is not valid");
  }
}

/** The effective policy: base profile made stricter by the local file. A malformed or loosening entry is ignored, never applied. */
export function effectiveProfile(storeDir: string, profile: Profile): ProfilePolicy {
  const base = BASE_PROFILES[profile];
  const file = loadPolicyFile(storeDir);
  const extra = (Array.isArray(file.extraChecks[profile]) ? file.extraChecks[profile]! : []).filter((c) => typeof c === "string" && CHECK_ID.test(c));
  const approvals = file.minApprovals[profile];
  const age = file.evidenceMaxAgeHours[profile];
  return {
    ...base,
    mandatoryChecks: [...new Set([...base.mandatoryChecks, ...extra])].sort(),
    minApprovals: typeof approvals === "number" && Number.isInteger(approvals) ? Math.min(Math.max(base.minApprovals, approvals), 5) : base.minApprovals,
    evidenceMaxAgeHours: typeof age === "number" && age > 0 ? Math.min(base.evidenceMaxAgeHours, age) : base.evidenceMaxAgeHours
  };
}

/** Hash of every effective profile: a task (and its approvals) is bound to it, so any policy change makes older authorizations stale. */
export function policyHash(storeDir: string): string {
  return createHash("sha256").update(JSON.stringify(PROFILES.map((p) => [p, effectiveProfile(storeDir, p)]))).digest("hex");
}

const RISK_PATTERNS: Array<{ pattern: RegExp; check: string }> = [
  { pattern: /(auth|crypto|secret|password|token|permission|acl|jwt|session|login|signin)/i, check: "security_review" },
  { pattern: /(migration|schema|package\.json|lock)/i, check: "dependency_review" }
];

/** Checks required for this scope: the profile's mandatory checks plus any the scope's risk adds. Never fewer than the profile demands. */
export function requiredChecks(storeDir: string, profile: Profile, scope: readonly string[]): string[] {
  const added = RISK_PATTERNS.filter((r) => scope.some((p) => r.pattern.test(p))).map((r) => r.check);
  return [...new Set([...effectiveProfile(storeDir, profile).mandatoryChecks, ...added])].sort();
}

export interface PolicyPatch { extraChecks?: Partial<Record<Profile, string[]>>; minApprovals?: Partial<Record<Profile, number>>; evidenceMaxAgeHours?: Partial<Record<Profile, number>> }

/** Only an authenticated admin may tighten the policy. A patch that would loosen anything is refused rather than silently ignored. */
export function updatePolicy(storeDir: string, actor: Actor, patch: PolicyPatch, now: Date = new Date()): string {
  requireRole(actor, "admin");
  return withLock(storeDir, () => {
    const file = loadPolicyFile(storeDir);
    for (const [profile, checks] of Object.entries(patch.extraChecks ?? {}) as Array<[Profile, string[]]>) {
      if (!PROFILES.includes(profile) || !Array.isArray(checks) || !checks.every((c) => typeof c === "string" && CHECK_ID.test(c))) {
        throw new EngbrainError("POLICY_REFUSED", "extraChecks takes profile -> check ids (lowercase letters, digits, underscore)");
      }
      file.extraChecks[profile] = [...new Set([...(file.extraChecks[profile] ?? []), ...checks])].sort();
    }
    for (const [profile, n] of Object.entries(patch.minApprovals ?? {}) as Array<[Profile, number]>) {
      if (!PROFILES.includes(profile) || !Number.isInteger(n) || n < BASE_PROFILES[profile].minApprovals || n > 5) {
        throw new EngbrainError("POLICY_REFUSED", "the approval count can only be raised above the profile's minimum");
      }
      file.minApprovals[profile] = Math.max(n, file.minApprovals[profile] ?? 0);
    }
    for (const [profile, h] of Object.entries(patch.evidenceMaxAgeHours ?? {}) as Array<[Profile, number]>) {
      if (!PROFILES.includes(profile) || typeof h !== "number" || h <= 0 || h > BASE_PROFILES[profile].evidenceMaxAgeHours) {
        throw new EngbrainError("POLICY_REFUSED", "the evidence lifetime can only be shortened");
      }
      file.evidenceMaxAgeHours[profile] = Math.min(h, file.evidenceMaxAgeHours[profile] ?? h);
    }
    file.updatedBy = actor.id;
    file.updatedAt = now.toISOString();
    const path = join(storeDir, SENTINEL_POLICY_FILE);
    const temp = `${path}.tmp-${process.pid}`;
    writeFileSync(temp, `${JSON.stringify(file, null, 2)}\n`, { mode: 0o600 });
    renameSync(temp, path);
    return policyHash(storeDir);
  }, SENTINEL_POLICY_FILE);
}
