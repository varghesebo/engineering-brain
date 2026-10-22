import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  appendEvidence, approvalMac, approveTask, assureTask, authorizeExecution, BASE_PROFILES, claimTask, createTask, effectiveProfile, evaluateEligibility, executionPermitted, getTask, holdsLease,
  issueCapability, parseEvidence, parseXml, recordScopeCheck, releaseTask, revokeExecution, runSyntheticWorker, saveCheckpoint, SENTINEL_KEY_FILE, SENTINEL_POLICY_FILE, SYNTHETIC_PROGRAMS,
  transitionTask, updatePolicy, verifyCapability, verifyTaskChain, XML_LIMITS, type Actor, type Role, type SandboxBackend, type SelfTestResult
} from "@engbrain/core";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, engbrainHome, makeGitRepo } from "../helpers/env.js";
import { withStore, type Opened } from "../helpers/h1.js";

afterAll(cleanupTempDirs);

const ADMIN: Actor = { id: "alice", roles: ["propose", "approve", "verify", "admin"] };
const APPROVER: Actor = { id: "carol", roles: ["propose", "approve"] };
const APPROVER2: Actor = { id: "dave", roles: ["propose", "approve"] };
const PLAIN: Actor = { id: "eve", roles: ["propose"] };
const fp = (s: string): string => createHash("sha256").update(s).digest("hex");
const T0 = new Date("2026-05-01T10:00:00.000Z");
const at = (minutes: number): Date => new Date(T0.getTime() + minutes * 60_000);
const HOURS = 60;
const FAKE_OK: SelfTestResult = { verified: true, detail: "test double", checks: [] };
/** The generic capability refusal: invalid MAC, expired, wrong task or wrong role all read the same, so nothing leaks which part failed. */
const CAP_REFUSED = /the capability token is invalid, expired, or not for this task or role/;

/** A passthrough "sandbox" used ONLY to exercise the interface with the fixed synthetic programs; it confines nothing and says so. */
const passthrough: SandboxBackend = { name: "test-passthrough", confines: [], doesNotLimit: ["everything"], selfTest: async () => FAKE_OK, wrap: (command, args) => ({ command, args }) };

async function setup(): Promise<{ repo: string; home: string }> {
  const repo = makeGitRepo({ "a.ts": "export const a = 1;\n" });
  const home = engbrainHome();
  await withStore(repo, home, () => undefined, true);
  return { repo, home };
}

const cap = (o: Opened, role: Role, taskId: string, principal: string, minutes = 0): string => issueCapability(o.store.dir, { role, taskId, principal, ttlSeconds: 3600, issuer: ADMIN, epoch: getTask(o.store.db, taskId).cap_epoch, now: at(minutes) });
const newTask = (o: Opened, profile: "A1" | "A2" | "A3" | "A4" = "A1", scope = ["src/app.ts"]) => createTask(o.store.db, o.store.dir, { title: "Add a feature", requester: PLAIN, profile, scope, sourceFingerprint: fp("v1") }, at(0));

type Steps = Parameters<typeof transitionTask>;
/** Drives a task to IMPLEMENTING (plan approved by `carol`, builder `builder-1`). */
function driveToImplementing(o: Opened, id: string, minutes = 1): void {
  const { db, dir } = o.store;
  const t = (to: Steps[3], who: Steps[4], m: number) => transitionTask(db, dir, id, to, who, { now: at(minutes + m), sourceFingerprint: to === "CONTEXT_READY" ? fp("v1") : undefined } as never);
  t("CONTEXT_READY", { capability: cap(o, "architect", id, "arch", minutes) }, 0);
  t("SPECIFICATION_READY", { capability: cap(o, "architect", id, "arch", minutes) }, 1);
  t("PLAN_APPROVED", { operator: APPROVER }, 2);
  t("IMPLEMENTING", { capability: cap(o, "builder", id, "builder-1", minutes) }, 3);
}
/** Drives a task to ASSURANCE_REVIEW (verifier `verifier-1`). */
function driveToAssurance(o: Opened, id: string, minutes = 1): void {
  const { db, dir } = o.store;
  driveToImplementing(o, id, minutes);
  const t = (to: Steps[3], who: Steps[4], m: number) => transitionTask(db, dir, id, to, who, { now: at(minutes + m) });
  t("IMPLEMENTED", { capability: cap(o, "builder", id, "builder-1", minutes) }, 4);
  t("VERIFYING", { capability: cap(o, "verification_worker", id, "verifier-1", minutes) }, 5);
  t("ASSURANCE_REVIEW", { capability: cap(o, "verification_worker", id, "verifier-1", minutes) }, 6);
}
/** Review checks belong to reviewers; everything else to the verification worker. */
const CHECK_OWNER: Record<string, [Role, string]> = { security_review: ["reviewer", "reviewer-1"], independent_review: ["reviewer", "reviewer-1"], adversarial_review: ["adversarial_reviewer", "red-team"] };
function passChecks(o: Opened, id: string, minutes: number, checks: readonly string[]): void {
  for (const check of checks) {
    const [role, principal]: [Role, string] = CHECK_OWNER[check] ?? ["verification_worker", "verifier-1"];
    appendEvidence(o.store.db, o.store.dir, id, { origin: "machine", kind: "check_result", checkId: check, outcome: "passed", environment: { node: "22" } }, { capability: cap(o, role, id, principal, minutes) }, fp("v1"), at(minutes));
  }
}
const sorted = (a: readonly string[]): string[] => [...a].sort();

describe("S3 hardening: capability tokens", () => {
  it("a capability expires at its exp (boundary included) and its lifetime is bounded at issue", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const id = newTask(o).task_id;
      const token = issueCapability(dir, { role: "architect", taskId: id, principal: "arch", ttlSeconds: 600, issuer: ADMIN, epoch: getTask(db, id).cap_epoch, now: at(0) });
      expect(verifyCapability(dir, token, { now: at(9), taskId: id })).toMatchObject({ role: "architect", principal: "arch", taskId: id });
      expect(() => verifyCapability(dir, token, { now: at(10), taskId: id })).toThrow(CAP_REFUSED); // exactly at exp: already expired
      expect(() => transitionTask(db, dir, id, "CONTEXT_READY", { capability: token }, { now: at(11) })).toThrow(CAP_REFUSED);
      expect(getTask(db, id)).toMatchObject({ state: "CREATED", revision: 1 });
      const bounds = /a lifetime of at most 24 h/;
      expect(() => issueCapability(dir, { role: "architect", taskId: id, principal: "arch", ttlSeconds: 0, issuer: ADMIN, epoch: 0 })).toThrow(bounds);
      expect(() => issueCapability(dir, { role: "architect", taskId: id, principal: "arch", ttlSeconds: 86_401, issuer: ADMIN, epoch: 0 })).toThrow(bounds);
      expect(() => issueCapability(dir, { role: "architect", taskId: id, principal: "arch", ttlSeconds: 60, issuer: APPROVER, epoch: 0 })).toThrow(/carol lacks the admin role/);
    });
  });

  it("a flipped MAC byte, an altered payload (role escalation, other task, longer life) or a malformed token is refused", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const id = newTask(o).task_id;
      const other = newTask(o).task_id;
      const builder = cap(o, "builder", id, "builder-1");
      expect(verifyCapability(dir, builder, { now: at(1), taskId: id }).role).toBe("builder"); // control: the untouched token is good
      expect(() => transitionTask(db, dir, id, "CONTEXT_READY", { capability: builder }, { now: at(1) })).toThrow(/builder may not move a task to CONTEXT_READY/);
      const [body, mac] = builder.split(".") as [string, string];
      const flipped = `${body}.${mac.slice(0, 10)}${mac[10] === "0" ? "1" : "0"}${mac.slice(11)}`;
      expect(() => verifyCapability(dir, flipped, { now: at(1), taskId: id })).toThrow(CAP_REFUSED);
      expect(() => verifyCapability(dir, `${body}.${mac.toUpperCase()}`, { now: at(1), taskId: id })).toThrow(CAP_REFUSED);
      const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as Record<string, unknown>;
      const forge = (patch: Record<string, unknown>): string => `${Buffer.from(JSON.stringify({ ...payload, ...patch })).toString("base64url")}.${mac}`;
      // role escalation: the builder re-labels itself an architect and tries the architect's step
      expect(() => transitionTask(db, dir, id, "CONTEXT_READY", { capability: forge({ role: "architect" }) }, { now: at(1) })).toThrow(CAP_REFUSED);
      expect(() => verifyCapability(dir, forge({ role: "assurance_controller" }), { now: at(1), taskId: id })).toThrow(CAP_REFUSED);
      expect(() => verifyCapability(dir, forge({ taskId: other }), { now: at(1), taskId: other })).toThrow(CAP_REFUSED);
      expect(() => verifyCapability(dir, forge({ exp: "2099-01-01T00:00:00.000Z" }), { now: at(120), taskId: id })).toThrow(CAP_REFUSED);
      expect(() => verifyCapability(dir, forge({ principal: "verifier-1" }), { now: at(1), taskId: id })).toThrow(CAP_REFUSED);
      for (const malformed of ["", body, `${body}.`, `${builder}.extra`, `.${mac}`]) {
        expect(() => verifyCapability(dir, malformed, { now: at(1), taskId: id }), JSON.stringify(malformed.slice(0, 12))).toThrow(CAP_REFUSED);
      }
      expect(getTask(db, id)).toMatchObject({ state: "CREATED", revision: 1 });
    });
  });
});

describe("S3 hardening: the controller key", () => {
  it("a missing, symlinked, wrong-size or substituted key file is refused, and verifyTaskChain reports it; restoring the key restores the chain", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const id = newTask(o).task_id;
      driveToImplementing(o, id);
      const token = cap(o, "builder", id, "builder-1", 5);
      const keyPath = join(dir, SENTINEL_KEY_FILE);
      const original = readFileSync(keyPath, "utf8");
      expect(original).toMatch(/^[0-9a-f]{64}$/);
      expect(verifyTaskChain(db, dir, id).ok).toBe(true);
      const assertBroken = (refusal: RegExp, label: string): void => {
        expect(() => verifyCapability(dir, token, { now: at(6), taskId: id }), label).toThrow(refusal);
        expect(() => transitionTask(db, dir, id, "IMPLEMENTED", { capability: token }, { now: at(6) }), label).toThrow(refusal);
        const chain = verifyTaskChain(db, dir, id);
        expect(chain.ok, label).toBe(false);
        expect(chain.problems.join(" "), label).toMatch(/carries no valid signature/);
        expect(chain.problems.join(" "), label).toMatch(/do not match its seal/);
        expect(getTask(db, id).state, label).toBe("IMPLEMENTING");
      };
      // missing
      renameSync(keyPath, `${keyPath}.real`);
      assertBroken(/no controller key exists/, "missing");
      // symlinked (to a perfectly good key: the link itself is refused)
      symlinkSync(`${keyPath}.real`, keyPath);
      assertBroken(/the controller key is not a regular 64-character file/, "symlink");
      rmSync(keyPath);
      renameSync(`${keyPath}.real`, keyPath);
      // wrong size: truncated, and with a trailing newline
      writeFileSync(keyPath, original.slice(0, 32), { mode: 0o600 });
      assertBroken(/the controller key is not a regular 64-character file/, "truncated");
      writeFileSync(keyPath, `${original}\n`, { mode: 0o600 });
      assertBroken(/the controller key is not a regular 64-character file/, "65 bytes");
      // a well-formed but different key: every signature is wrong
      writeFileSync(keyPath, "ab".repeat(32), { mode: 0o600 });
      assertBroken(CAP_REFUSED, "substituted");
      writeFileSync(keyPath, original, { mode: 0o600 });
      expect(verifyTaskChain(db, dir, id)).toMatchObject({ ok: true, problems: [] });
      expect(transitionTask(db, dir, id, "IMPLEMENTED", { capability: token }, { now: at(6) }).state).toBe("IMPLEMENTED");
    });
  });
});

describe("S3 hardening: evidence lifetime", () => {
  it("A1 evidence older than 168 h blocks assurance; just inside the window it does not", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const id = newTask(o, "A1").task_id;
      driveToAssurance(o, id);
      passChecks(o, id, 20, BASE_PROFILES.A1.mandatoryChecks);
      expect(evaluateEligibility(db, dir, id, fp("v1"), at(20 + 168 * HOURS - 1))).toMatchObject({ checksPassing: true, blockers: [] });
      const late = 20 + 168 * HOURS + 1;
      const r = assureTask(db, dir, id, cap(o, "assurance_controller", id, "assurance-1", late), fp("v1"), at(late));
      expect(r.state).toBe("BLOCKED");
      expect(r.eligibility.blockers).toEqual(sorted(BASE_PROFILES.A1.mandatoryChecks).map((c) => `${c}: evidence expired (older than 168 h)`));
    });
  });

  it("A4 evidence older than 8 h blocks assurance; just inside the window it does not", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const id = newTask(o, "A4").task_id;
      driveToAssurance(o, id);
      passChecks(o, id, 20, BASE_PROFILES.A4.mandatoryChecks);
      expect(evaluateEligibility(db, dir, id, fp("v1"), at(20 + 8 * HOURS - 1))).toMatchObject({ checksPassing: true, blockers: [] });
      const late = 20 + 8 * HOURS + 1;
      const r = assureTask(db, dir, id, cap(o, "assurance_controller", id, "assurance-1", late), fp("v1"), at(late));
      expect(r.state).toBe("BLOCKED");
      expect(r.eligibility.blockers).toHaveLength(BASE_PROFILES.A4.mandatoryChecks.length);
      expect(r.eligibility.blockers.every((b) => b.endsWith(": evidence expired (older than 8 h)"))).toBe(true);
    });
  });
});

describe("S3 hardening: approvals", () => {
  it("A3 needs two distinct approvers: one is not enough, the same approver twice counts once, and a correctly-signed builder approval row is ignored", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const id = newTask(o, "A3").task_id;
      driveToAssurance(o, id);
      passChecks(o, id, 20, BASE_PROFILES.A3.mandatoryChecks);
      expect(assureTask(db, dir, id, cap(o, "assurance_controller", id, "assurance-1", 21), fp("v1"), at(21)).state).toBe("APPROVAL_REQUIRED");
      expect(approveTask(db, dir, id, APPROVER, fp("v1"), at(22))).toEqual({ state: "APPROVAL_REQUIRED", approvalsValid: 1, approvalsNeeded: 2 }); // one is not enough
      expect(() => approveTask(db, dir, id, APPROVER, fp("v1"), at(23))).toThrow(/this operator already approved the current state/);
      // rows planted behind the API WITH a valid MAC (the strongest forgery): a second row for carol and one for the builder
      const carol = db.prepare("SELECT * FROM sentinel_approvals WHERE task_id = ? AND approver = 'carol'").get(id) as Record<string, unknown>;
      const plant = (approvalId: string, approver: string): void => {
        const row = { ...carol, approval_id: approvalId, approver };
        db.prepare("INSERT INTO sentinel_approvals (approval_id, task_id, approver, at, task_revision, source_fingerprint, policy_hash, evidence_head, status, mac) VALUES (@approval_id, @task_id, @approver, @at, @task_revision, @source_fingerprint, @policy_hash, @evidence_head, @status, @mac)")
          .run({ ...row, mac: approvalMac(dir, row) });
      };
      plant("ap_carolagain00000", "carol");
      plant("ap_builderforged0", "builder-1");
      expect(evaluateEligibility(db, dir, id, fp("v1"), at(24)).approvalsValid).toBe(1);
      expect(getTask(db, id).state).toBe("APPROVAL_REQUIRED");
      expect(approveTask(db, dir, id, APPROVER2, fp("v1"), at(25))).toEqual({ state: "ELIGIBLE_FOR_APPROVAL", approvalsValid: 2, approvalsNeeded: 2 });
      // control: the planting itself is sound (a correctly-signed row from a fresh principal is counted), so the two rows above were refused by the rules, not by a bad MAC
      plant("ap_frankcontrol00", "frank");
      expect(evaluateEligibility(db, dir, id, fp("v1"), at(26)).approvalsValid).toBe(3);
    });
  });

  it("a verification or assurance token held by the builder principal is refused by appendEvidence, recordScopeCheck and assureTask", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const id = newTask(o, "A1").task_id;
      driveToAssurance(o, id);
      const asWorker = cap(o, "verification_worker", id, "builder-1", 20);
      const own = /the builder cannot verify or review its own work/;
      expect(() => appendEvidence(db, dir, id, { origin: "machine", kind: "check_result", checkId: "tests", outcome: "passed" }, { capability: asWorker }, fp("v1"), at(20))).toThrow(own);
      expect(() => recordScopeCheck(db, dir, id, ["src/app.ts"], { capability: asWorker }, fp("v1"), at(20))).toThrow(own);
      expect(() => appendEvidence(db, dir, id, { origin: "machine", kind: "check_result", checkId: "security_review", outcome: "passed" }, { capability: cap(o, "reviewer", id, "builder-1", 20) }, fp("v1"), at(20))).toThrow(own);
      expect(() => assureTask(db, dir, id, asWorker, fp("v1"), at(20))).toThrow(CAP_REFUSED); // wrong role for assurance
      expect(() => assureTask(db, dir, id, cap(o, "assurance_controller", id, "builder-1", 20), fp("v1"), at(20))).toThrow(own);
      expect(getTask(db, id).state).toBe("ASSURANCE_REVIEW");
      expect(db.prepare("SELECT COUNT(*) AS n FROM sentinel_evidence WHERE task_id = ?").get(id)).toEqual({ n: 0 });
      passChecks(o, id, 21, ["tests"]); // control: the real verifier can
      expect(db.prepare("SELECT verifier FROM sentinel_evidence WHERE task_id = ?").all(id)).toEqual([{ verifier: "verifier-1" }]);
    });
  });
});

describe("S3 hardening: scope boundary", () => {
  it("a file scope `src/auth` authorizes itself and its subtree only, never a sibling with the same prefix", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const id = newTask(o, "A1", ["src/auth"]).task_id;
      driveToAssurance(o, id);
      const worker = cap(o, "verification_worker", id, "verifier-1", 20);
      const check = (paths: string[], m: number) => recordScopeCheck(db, dir, id, paths, { capability: worker }, fp("v1"), at(20 + m));
      expect(check(["src/auth", "src/auth/login.ts", "src/auth/deep/x.ts"], 0)).toEqual({ outcome: "passed", violations: [] });
      expect(check(["src/authz.ts"], 1)).toEqual({ outcome: "failed", violations: ["src/authz.ts"] });
      expect(check(["src/auth-evil/x"], 2)).toEqual({ outcome: "failed", violations: ["src/auth-evil/x"] });
      expect(check(["src/auth/ok.ts", "src/auth.bak", "src/AUTH/x.ts"], 3)).toEqual({ outcome: "failed", violations: ["src/AUTH/x.ts", "src/auth.bak"] });
      const dirScoped = newTask(o, "A1", ["src/auth/"]).task_id;
      driveToAssurance(o, dirScoped, 30);
      const w2 = cap(o, "verification_worker", dirScoped, "verifier-1", 40);
      expect(recordScopeCheck(db, dir, dirScoped, ["src/auth/a.ts", "src/authz.ts"], { capability: w2 }, fp("v1"), at(40))).toEqual({ outcome: "failed", violations: ["src/authz.ts"] });
    });
  });

  it("scope paths that are relative-escaping, absolute, empty-segment or backslashed are refused at task creation", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const before = (o.store.db.prepare("SELECT COUNT(*) AS n FROM sentinel_tasks").get() as { n: number }).n;
      for (const bad of ["../x", "/abs", "a//b", "a\\b", "src/../../x", "src/..", ".."]) {
        expect(() => newTask(o, "A1", ["src/ok.ts", bad]), bad).toThrow(/scope paths are repository-relative and cannot leave the repository/);
      }
      expect(() => newTask(o, "A1", [])).toThrow(/must name 1-200 repository-relative paths/);
      expect(o.store.db.prepare("SELECT COUNT(*) AS n FROM sentinel_tasks").get()).toEqual({ n: before });
    });
  });
});

describe("S3 hardening: a hand-edited policy file", () => {
  it("loosening entries (zero approvals, huge evidence age, bad check ids, wrong types) are ignored or clamped, never applied", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      writeFileSync(join(dir, SENTINEL_POLICY_FILE), JSON.stringify({
        extraChecks: { A1: ["Bad-ID", "x", "../evil", 42, "license_scan"], A2: "not-an-array" },
        minApprovals: { A1: 0, A2: -3, A3: 1000, A4: 2.5 },
        evidenceMaxAgeHours: { A1: 1e9, A2: 0, A3: -1, A4: "1" }
      }));
      expect(effectiveProfile(dir, "A1")).toMatchObject({ mandatoryChecks: sorted([...BASE_PROFILES.A1.mandatoryChecks, "license_scan"]), minApprovals: 1, evidenceMaxAgeHours: 168 });
      expect(effectiveProfile(dir, "A2")).toMatchObject({ mandatoryChecks: sorted(BASE_PROFILES.A2.mandatoryChecks), minApprovals: 1, evidenceMaxAgeHours: 72 });
      expect(effectiveProfile(dir, "A3")).toMatchObject({ minApprovals: 5, evidenceMaxAgeHours: 24 }); // a raise is honoured but capped
      expect(effectiveProfile(dir, "A4")).toMatchObject({ minApprovals: 2, evidenceMaxAgeHours: 8 });
      const t = newTask(o, "A1");
      const e = evaluateEligibility(db, dir, t.task_id, fp("v1"), at(1));
      expect(e.approvalsNeeded).toBe(1);
      expect(e.requiredChecks).toEqual(sorted(["license_scan", "lint", "scope", "tests"]));
    });
  });

  it("an oversized or symlinked policy file is refused outright (reads and updates), not silently replaced by defaults", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const t = newTask(o, "A1");
      const path = join(dir, SENTINEL_POLICY_FILE);
      const unsafe = /sentinel-policy.json is not a regular file of reasonable size/;
      writeFileSync(path, JSON.stringify({ extraChecks: {}, pad: "x".repeat(65_536) }));
      expect(() => effectiveProfile(dir, "A1")).toThrow(unsafe);
      expect(() => evaluateEligibility(db, dir, t.task_id, fp("v1"), at(1))).toThrow(unsafe);
      expect(() => newTask(o, "A1")).toThrow(unsafe);
      rmSync(path);
      const elsewhere = join(dir, "elsewhere-policy.json");
      const target = JSON.stringify({ extraChecks: { A1: ["license_scan"] } });
      writeFileSync(elsewhere, target);
      symlinkSync(elsewhere, path);
      expect(() => effectiveProfile(dir, "A1")).toThrow(unsafe);
      expect(() => updatePolicy(dir, ADMIN, { extraChecks: { A1: ["more_checks"] } }, at(2))).toThrow(unsafe);
      expect(readFileSync(elsewhere, "utf8")).toBe(target); // the link's target was not written through
      rmSync(path);
      expect(effectiveProfile(dir, "A1").mandatoryChecks).toEqual(sorted(BASE_PROFILES.A1.mandatoryChecks));
    });
  });
});

describe("S3 hardening: execution bounds", () => {
  it("authorization bounds, a timeout that outlives the lease, and revokeExecution are all refused before anything runs", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, async (o) => {
      const { db, dir } = o.store;
      const id = newTask(o).task_id;
      driveToImplementing(o, id);
      const bounds = /an execution authorization lasts at most 60 minutes and allows 1-10 runs/;
      for (const options of [{ ttlMinutes: 61 }, { ttlMinutes: 0 }, { maxRuns: 11 }, { maxRuns: 0 }, { maxRuns: 1.5 }]) {
        expect(() => authorizeExecution(db, dir, id, APPROVER, fp("v1"), { now: at(10), ...options }), JSON.stringify(options)).toThrow(bounds);
      }
      expect(db.prepare("SELECT COUNT(*) AS n FROM sentinel_exec_auth").get()).toEqual({ n: 0 });
      const start = new Date();
      const clock = (): Date => new Date(start.getTime() + 60_000); // injected: one minute into a two-minute lease
      authorizeExecution(db, dir, id, APPROVER, fp("v1"), { now: start, ttlMinutes: 60, maxRuns: 10 }); // the maximum is accepted
      const lease = claimTask(db, id, "ctl", 120, start).leaseToken;
      const base = { leaseToken: lease, program: "ok" as const, backend: passthrough, fingerprint: () => fp("v1"), now: clock };
      const tooLong = /the timeout must be at most 10 minutes and shorter than the remaining lease/;
      await expect(runSyntheticWorker(db, dir, id, { ...base, timeoutMs: 61_000 })).rejects.toThrow(tooLong); // 60 s of lease left
      await expect(runSyntheticWorker(db, dir, id, { ...base, timeoutMs: 0 })).rejects.toThrow(tooLong);
      expect(db.prepare("SELECT runs_left FROM sentinel_exec_auth WHERE task_id = ?").get(id)).toEqual({ runs_left: 10 }); // refusals burn no run
      expect(await runSyntheticWorker(db, dir, id, { ...base, timeoutMs: 59_000 })).toMatchObject({ outcome: "passed", exitCode: 0, stdout: "synthetic-ok" }); // control: inside the lease
      expect(db.prepare("SELECT runs_left FROM sentinel_exec_auth WHERE task_id = ?").get(id)).toEqual({ runs_left: 9 });
      const longLease = claimTask(db, id, "ctl", 3600, start, lease).leaseToken;
      await expect(runSyntheticWorker(db, dir, id, { ...base, leaseToken: longLease, timeoutMs: 600_001 })).rejects.toThrow(tooLong); // over the 10-minute ceiling
      expect(() => revokeExecution(db, dir, id, PLAIN)).toThrow(/eve lacks the approve role/);
      revokeExecution(db, dir, id, APPROVER);
      expect(executionPermitted(db, dir, id, fp("v1"), FAKE_OK, clock()).reasons).toContain("no active execution authorization");
      await expect(runSyntheticWorker(db, dir, id, { ...base, leaseToken: longLease, timeoutMs: 5000 })).rejects.toThrow(/execution is not permitted: no active execution authorization/);
    });
  });

  it.skipIf(process.platform === "win32")("the synthetic child gets an empty environment: a parent secret does not reach it", async () => {
    const SECRET = "ENGBRAIN_HARDENING_PARENT_SECRET";
    // a wrapper backend around the fixed `ok` program: it refuses to start the program (exit 9) if the secret is visible to the child
    const PROBE = `if [ -n "\${${SECRET}+x}" ]; then exit 9; fi; exec "$0" "$@"`;
    const envProbe: SandboxBackend = { ...passthrough, name: "test-env-probe", wrap: (command, args) => ({ command: "/bin/sh", args: ["-c", PROBE, command, ...args] }) };
    const probeArgs = envProbe.wrap(process.execPath, ["-e", SYNTHETIC_PROGRAMS.ok]).args;
    expect(spawnSync("/bin/sh", probeArgs, { env: { [SECRET]: "leaked" } }).status).toBe(9); // control: the probe does detect an inherited secret
    expect(spawnSync("/bin/sh", probeArgs, { env: {}, encoding: "utf8" })).toMatchObject({ status: 0, stdout: "synthetic-ok" });
    const w = await setup();
    process.env[SECRET] = "parent-only-value";
    try {
      await withStore(w.repo, w.home, async (o) => {
        const { db, dir } = o.store;
        const id = newTask(o).task_id;
        driveToImplementing(o, id);
        const lease = claimTask(db, id, "ctl", 3600).leaseToken;
        authorizeExecution(db, dir, id, APPROVER, fp("v1"), { now: new Date() });
        expect(await runSyntheticWorker(db, dir, id, { leaseToken: lease, program: "ok", backend: envProbe, fingerprint: () => fp("v1"), timeoutMs: 10_000 })).toMatchObject({ outcome: "passed", exitCode: 0, stdout: "synthetic-ok" });
      });
    } finally {
      delete process.env[SECRET];
    }
  });
});

describe("S3 hardening: XML limits", () => {
  const nest = (depth: number): string => "<a>".repeat(depth) + "</a>".repeat(depth);
  const attrs = (n: number): string => Array.from({ length: n }, (_, i) => `a${i}="v"`).join(" ");

  it("depth, attribute count and attribute length are refused past their limits, through parseXml and parseEvidence", () => {
    expect(parseXml(nest(XML_LIMITS.depth - 1)).name).toBe("a");
    expect(() => parseXml(nest(XML_LIMITS.depth))).toThrow(/the XML document is nested too deeply/);
    expect(() => parseEvidence("junit", `<testsuite name="s">${nest(XML_LIMITS.depth)}</testsuite>`)).toThrow(/nested too deeply/);
    expect(Object.keys(parseXml(`<t ${attrs(XML_LIMITS.attributes)}/>`).attrs)).toHaveLength(XML_LIMITS.attributes);
    expect(() => parseXml(`<t ${attrs(XML_LIMITS.attributes + 1)}/>`)).toThrow(/too many XML attributes on one element/);
    expect(() => parseEvidence("junit", `<testsuite name="s"><testcase name="x" ${attrs(XML_LIMITS.attributes + 1)}/></testsuite>`)).toThrow(/too many XML attributes/);
    expect(parseXml(`<t a="${"x".repeat(XML_LIMITS.attributeLength)}"/>`).attrs["a"]).toHaveLength(XML_LIMITS.attributeLength);
    expect(() => parseXml(`<t a="${"x".repeat(XML_LIMITS.attributeLength + 1)}"/>`)).toThrow(/an XML attribute value is too long/);
  });

  it("oversized text is capped (also across text, CDATA and comments) and an oversized document is refused", () => {
    expect(parseXml(`<t>${"x".repeat(XML_LIMITS.textLength + 5000)}</t>`).text).toHaveLength(XML_LIMITS.textLength);
    const mixed = parseXml(`<t>${"x".repeat(40_000)}<!-- c --><![CDATA[${"y".repeat(40_000)}]]>${"z".repeat(40_000)}</t>`);
    expect(mixed.text).toHaveLength(XML_LIMITS.textLength);
    expect(mixed.text.startsWith("x".repeat(40_000) + "y")).toBe(true);
    const junit = parseEvidence("junit", `<testsuite name="s"><testcase name="big" file="a.test.ts"><failure message="m">${"f".repeat(XML_LIMITS.textLength * 2)}</failure></testcase></testsuite>`);
    expect(junit.results[0]!.outcome).toBe("failed");
    expect(() => parseXml(`<t>${"x".repeat(XML_LIMITS.bytes)}</t>`)).toThrow(/the XML document is larger than the 20 MiB limit/);
  });
});

describe("S3 hardening: lease renewal and release", () => {
  it("only the current token renews; renewal rotates the token and extends the lease; release needs the token and frees the task", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db } = o.store;
      const id = newTask(o).task_id;
      const a = claimTask(db, id, "ctl-a", 60, at(0)).leaseToken;
      expect(() => claimTask(db, id, "ctl-b", 60, at(0.5))).toThrow(/another controller \(ctl-a\) holds this task/);
      expect(() => claimTask(db, id, "ctl-a", 60, at(0.5), "not-the-token")).toThrow(/another controller \(ctl-a\) holds this task/);
      const renewed = claimTask(db, id, "ctl-a", 60, at(0.5), a);
      const b = renewed.leaseToken;
      expect(b).not.toBe(a);
      expect(renewed.task.lease_expires).toBe(at(1.5).toISOString());
      expect(holdsLease(db, id, a, at(0.6))).toBe(false); // the old token was rotated out
      expect(holdsLease(db, id, b, at(1.2))).toBe(true); // past the ORIGINAL expiry
      expect(() => claimTask(db, id, "ctl-b", 60, at(1.2))).toThrow(/holds this task/);
      expect(() => claimTask(db, id, "ctl-a", 60, at(1.2), a)).toThrow(/holds this task/); // the old token cannot renew
      releaseTask(db, id, a); // the wrong token releases nothing
      expect(getTask(db, id).claimed_by).toBe("ctl-a");
      releaseTask(db, id, b);
      expect(getTask(db, id)).toMatchObject({ claimed_by: null, lease_expires: null, lease_hash: null });
      expect(holdsLease(db, id, b, at(1.2))).toBe(false);
      expect(() => saveCheckpoint(db, id, b, { step: "x" }, at(1.2))).toThrow(/only the controller holding the task's lease/);
      expect(claimTask(db, id, "ctl-b", 60, at(1.3)).task.claimed_by).toBe("ctl-b"); // freed at once, without waiting for expiry
    });
  });
});
