import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  appendEvidence, approveTask, assureTask, authorizeExecution, cancelTask, claimTask, createTask, dequeueWork, enqueueWork, evaluateEligibility, executionPermitted, getTask, issueCapability, LEGAL, macosSandboxExec,
  noSandbox, probeCapabilities, recordScopeCheck, resumeInfo, revalidateTask, revokeCapabilities, revokeExecution, runSyntheticWorker, saveCheckpoint, STATES, taskReport, transitionTask, updatePolicy, verifyTaskChain, type Actor, type Role, type SandboxBackend, type SelfTestResult
} from "@engbrain/core";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, engbrainHome, makeGitRepo, runCli } from "../helpers/env.js";
import { withStore, type Opened } from "../helpers/h1.js";

afterAll(cleanupTempDirs);

const ADMIN: Actor = { id: "alice", roles: ["propose", "approve", "verify", "admin"] };
const APPROVER: Actor = { id: "carol", roles: ["propose", "approve"] };
const APPROVER2: Actor = { id: "dave", roles: ["propose", "approve"] };
const PLAIN: Actor = { id: "eve", roles: ["propose"] };
const fp = (s: string): string => createHash("sha256").update(s).digest("hex");
const T0 = new Date("2026-05-01T10:00:00.000Z");
const at = (minutes: number): Date => new Date(T0.getTime() + minutes * 60_000);
const FAKE_OK: SelfTestResult = { verified: true, detail: "test double", checks: [] };
/** Unauthenticated CLI calls pass these explicitly, so a developer's own ENGBRAIN_OPERATOR in the shell cannot make a refusal test pass or fail by accident. */
const NO_OPERATOR = { ENGBRAIN_OPERATOR: "", ENGBRAIN_OPERATOR_TOKEN: "" };
/** Probed once at module load: the real-sandbox test is reported as skipped (with the reason in its name) rather than silently returning. */
const REAL_SANDBOX = await probeCapabilities([macosSandboxExec]);

/** A passthrough "sandbox" used ONLY to exercise the interface with the fixed synthetic programs; it confines nothing and says so. */
const passthrough: SandboxBackend = { name: "test-passthrough", confines: [], doesNotLimit: ["everything"], selfTest: async () => FAKE_OK, wrap: (command, args) => ({ command, args }) };

async function setup(): Promise<{ repo: string; home: string }> {
  const repo = makeGitRepo({ "a.ts": "export const a = 1;\n" });
  const home = engbrainHome();
  await withStore(repo, home, () => undefined, true);
  return { repo, home };
}

const cap = (o: Opened, role: Role, taskId: string, principal: string, minutes = 0): string => issueCapability(o.store.dir, { role, taskId, principal, ttlSeconds: 3600, issuer: ADMIN, epoch: getTask(o.store.db, taskId).cap_epoch, now: at(minutes) });
const newTask = (o: Opened, profile: "A1" | "A2" | "A3" | "A4" = "A1", scope = ["src/app.ts"], fingerprint = fp("v1")) => createTask(o.store.db, o.store.dir, { title: "Add a feature", requester: PLAIN, profile, scope, sourceFingerprint: fingerprint }, at(0));

type Steps = Parameters<typeof transitionTask>;
/** Drives a task to IMPLEMENTING (plan approved by `carol`, builder `builder-1`). */
function driveToImplementing(o: Opened, id: string, fingerprint: string, minutes = 1): void {
  const { db, dir } = o.store;
  const t = (to: Steps[3], who: Steps[4], m: number) => transitionTask(db, dir, id, to, who, { now: at(minutes + m), sourceFingerprint: ["CONTEXT_READY"].includes(to) ? fingerprint : undefined } as never);
  t("CONTEXT_READY", { capability: cap(o, "architect", id, "arch", minutes) }, 0);
  t("SPECIFICATION_READY", { capability: cap(o, "architect", id, "arch", minutes) }, 1);
  t("PLAN_APPROVED", { operator: APPROVER }, 2);
  t("IMPLEMENTING", { capability: cap(o, "builder", id, "builder-1", minutes) }, 3);
}
/** Continues from IMPLEMENTING to ASSURANCE_REVIEW. */
function driveToAssurance(o: Opened, id: string, fingerprint: string, minutes = 1): void {
  const { db, dir } = o.store;
  if (getTask(db, id).state === "CREATED") {
    driveToImplementing(o, id, fingerprint, minutes);
  }
  const t = (to: Steps[3], who: Steps[4], m: number) => transitionTask(db, dir, id, to, who, { now: at(minutes + m) });
  t("IMPLEMENTED", { capability: cap(o, "builder", id, "builder-1", minutes) }, 4);
  t("VERIFYING", { capability: cap(o, "verification_worker", id, "verifier-1", minutes) }, 5);
  t("ASSURANCE_REVIEW", { capability: cap(o, "verification_worker", id, "verifier-1", minutes) }, 6);
}
function passAll(o: Opened, id: string, fingerprint: string, minutes: number, checks: string[]): void {
  const worker = cap(o, "verification_worker", id, "verifier-1", minutes);
  checks.forEach((check) => appendEvidence(o.store.db, o.store.dir, id, { origin: "machine", kind: "check_result", checkId: check, outcome: "passed", environment: { node: "22" } }, { capability: worker }, fingerprint, at(minutes)));
}

describe("S3A state machine", () => {
  it("rejects illegal sequences and every state has a defined edge set", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const task = newTask(o);
      const { db, dir } = o.store;
      expect(() => transitionTask(db, dir, task.task_id, "IMPLEMENTING", { capability: cap(o, "builder", task.task_id, "b") }, { now: at(1) })).toThrow(/illegal transition CREATED -> IMPLEMENTING/);
      expect(() => transitionTask(db, dir, task.task_id, "ELIGIBLE_FOR_APPROVAL", { operator: ADMIN }, { now: at(1) })).toThrow(/assure|approve/);
      expect(() => transitionTask(db, dir, task.task_id, "CONTEXT_READY", { capability: cap(o, "builder", task.task_id, "b") }, { now: at(1) })).toThrow(/may not move/); // a builder cannot do the architect's step
      expect(() => transitionTask(db, dir, task.task_id, "CONTEXT_READY", { capability: "garbage.token" }, { now: at(1) })).toThrow(/invalid/);
      // cross-task replay: a genuine token for task B, carrying the right epoch, is refused on task A by the task binding alone
      const other = newTask(o);
      const forB = cap(o, "architect", other.task_id, "a");
      expect(getTask(db, other.task_id).cap_epoch).toBe(getTask(db, task.task_id).cap_epoch); // the epoch would match: only the task id can refuse it
      expect(() => transitionTask(db, dir, task.task_id, "CONTEXT_READY", { capability: forB }, { now: at(1) })).toThrow(/not for this task/);
      expect(getTask(db, task.task_id)).toMatchObject({ state: "CREATED", revision: 1 });
      expect(transitionTask(db, dir, other.task_id, "CONTEXT_READY", { capability: forB }, { now: at(1) }).state).toBe("CONTEXT_READY"); // control: the same token is good on B
      expect(() => transitionTask(db, dir, task.task_id, "CANCELLED", { operator: ADMIN }, { now: at(1) })).toThrow(/use `cancel`/); // cancellation has one path: it revokes authority and stops children
      expect(Object.keys(LEGAL).sort()).toEqual([...STATES].sort());
      const done = cancelTask(db, dir, task.task_id, APPROVER, "not needed", at(2));
      expect(done.state).toBe("CANCELLED");
      expect(() => transitionTask(db, dir, task.task_id, "CONTEXT_READY", { operator: ADMIN }, { now: at(3) })).toThrow(/illegal/);
      expect(() => db.prepare("UPDATE sentinel_tasks SET state = 'CREATED' WHERE task_id = ?").run(task.task_id)).toThrow(/terminal/);
    });
  });

  it("survives a process crash: state, revision, checkpoint and orphaned queue work are durable; the lease needs its secret token and an expired lease can be taken over", async () => {
    const w = await setup();
    let id = "";
    let tokenA = "";
    await withStore(w.repo, w.home, (o) => {
      id = newTask(o).task_id;
      tokenA = claimTask(o.store.db, id, "controller-a", 3600, at(1)).leaseToken;
      transitionTask(o.store.db, o.store.dir, id, "CONTEXT_READY", { capability: cap(o, "architect", id, "arch") }, { now: at(2), leaseToken: tokenA });
      saveCheckpoint(o.store.db, id, tokenA, { step: "context", filesRead: 12 }, at(2));
      enqueueWork(o.store.db, id, "verify");
      expect(dequeueWork(o.store.db)).toMatchObject({ taskId: id }); // running when the process dies
      expect(() => saveCheckpoint(o.store.db, id, "guessed-token", { step: "x" }, at(2))).toThrow(/holding the task/);
      expect(() => saveCheckpoint(o.store.db, id, "controller-a", { step: "x" }, at(2))).toThrow(/holding the task/); // the controller's NAME is not the credential
    }); // the connection (process) is gone
    await withStore(w.repo, w.home, (o) => {
      const t = getTask(o.store.db, id);
      expect([t.state, t.revision, JSON.parse(t.checkpoint_json!)]).toEqual(["CONTEXT_READY", 2, { step: "context", filesRead: 12 }]);
      expect(() => claimTask(o.store.db, id, "controller-a", 3600, at(10))).toThrow(/holds this task/); // same name, no token: refused
      expect(() => transitionTask(o.store.db, o.store.dir, id, "SPECIFICATION_READY", { capability: cap(o, "architect", id, "arch") }, { now: at(11), leaseToken: "wrong" })).toThrow(/holds this task/);
      expect(resumeInfo(o.store.db, id, at(10)).requeued).toBe(0); // the lease is still held: do not steal its work
      expect(claimTask(o.store.db, id, "controller-b", 3600, at(90)).task.claimed_by).toBe("controller-b"); // the lease expired
      expect(resumeInfo(o.store.db, id, at(200))).toMatchObject({ state: "CONTEXT_READY", checkpoint: { step: "context", filesRead: 12 }, requeued: 1 });
      expect(verifyTaskChain(o.store.db, o.store.dir, id).ok).toBe(true);
    });
  });
});

describe("S3A policy and authority", () => {
  it("failed or pending mandatory checks and out-of-scope changes force BLOCKED", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const task = newTask(o, "A1");
      const id = task.task_id;
      driveToAssurance(o, id, fp("v1"));
      passAll(o, id, fp("v1"), 20, ["scope", "tests"]); // `lint` is still pending
      const blocked = assureTask(db, dir, id, cap(o, "assurance_controller", id, "assurance-1"), fp("v1"), at(21));
      expect(blocked.state).toBe("BLOCKED");
      expect(blocked.eligibility.blockers.join(" ")).toMatch(/lint: pending/);
      expect(getTask(db, id).blocked_reason).toMatch(/lint: pending/);
      for (const variant of ["failed", "violation"] as const) {
        const t = newTask(o, "A1", ["src/"]);
        driveToAssurance(o, t.task_id, fp("v1"));
        const worker = cap(o, "verification_worker", t.task_id, "verifier-1");
        for (const check of ["tests", "lint"]) {
          appendEvidence(db, dir, t.task_id, { origin: "machine", kind: "check_result", checkId: check, outcome: variant === "failed" && check === "lint" ? "failed" : "passed" }, { capability: worker }, fp("v1"), at(30));
        }
        const scope = recordScopeCheck(db, dir, t.task_id, variant === "violation" ? ["src/a.ts", "secrets/prod.env"] : ["src/a.ts"], { capability: worker }, fp("v1"), at(31));
        expect(scope.outcome).toBe(variant === "violation" ? "failed" : "passed");
        const r = assureTask(db, dir, t.task_id, cap(o, "assurance_controller", t.task_id, "assurance-1"), fp("v1"), at(32));
        expect(r.state).toBe("BLOCKED");
        expect(r.eligibility.blockers.join(" ")).toMatch(variant === "failed" ? /lint: failed/ : /scope: failed/);
      }
    });
  });

  it("the builder cannot approve or touch policy; roles cannot cross over; approvals need distinct authenticated principals", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const t = newTask(o, "A1");
      const id = t.task_id;
      driveToAssurance(o, id, fp("v1"));
      passAll(o, id, fp("v1"), 40, ["scope", "tests", "lint"]);
      expect(assureTask(db, dir, id, cap(o, "assurance_controller", id, "assurance-1"), fp("v1"), at(41)).state).toBe("APPROVAL_REQUIRED");
      expect(() => approveTask(db, dir, id, { id: "builder-1", roles: ["approve"] }, fp("v1"), at(42))).toThrow(/builder cannot approve/);
      expect(() => approveTask(db, dir, id, { id: "verifier-1", roles: ["approve"] }, fp("v1"), at(42))).toThrow(/acted as an agent role/); // the verifier's name cannot approve either
      expect(() => approveTask(db, dir, id, PLAIN, fp("v1"), at(42))).toThrow(/lacks the approve role/);
      expect(() => updatePolicy(dir, PLAIN, { extraChecks: { A1: ["extra_check"] } })).toThrow(/admin/);
      expect(() => updatePolicy(dir, APPROVER, { extraChecks: { A1: ["extra_check"] } })).toThrow(/admin/);
      expect(() => updatePolicy(dir, ADMIN, { minApprovals: { A1: 0 } })).toThrow(/only be raised/);
      expect(() => updatePolicy(dir, ADMIN, { evidenceMaxAgeHours: { A1: 9999 } })).toThrow(/only be shortened/);
      const ok = approveTask(db, dir, id, APPROVER, fp("v1"), at(43));
      expect(ok).toMatchObject({ state: "ELIGIBLE_FOR_APPROVAL", approvalsValid: 1 });
      expect(() => approveTask(db, dir, id, APPROVER, fp("v1"), at(44))).toThrow(/already approved/);
      expect(executionPermitted(db, dir, id, fp("v1"), FAKE_OK, at(44)).permitted).toBe(false); // ELIGIBLE grants no execution
    });
  });

  it("separation of duties: the plan approver cannot become the builder, the builder cannot verify, review checks belong to reviewers, and capabilities can be revoked", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const t = newTask(o, "A3");
      const id = t.task_id;
      const T = (to: Steps[3], who: Steps[4], m: number) => transitionTask(db, dir, id, to, who, { now: at(1 + m) });
      T("CONTEXT_READY", { capability: cap(o, "architect", id, "arch", 1) }, 0);
      T("SPECIFICATION_READY", { capability: cap(o, "architect", id, "arch", 1) }, 1);
      T("PLAN_APPROVED", { operator: APPROVER }, 2);
      expect(() => T("IMPLEMENTING", { capability: cap(o, "builder", id, "carol", 1) }, 3)).toThrow(/cannot also have approved/); // approver-then-builder
      T("IMPLEMENTING", { capability: cap(o, "builder", id, "builder-1", 1) }, 3);
      T("IMPLEMENTED", { capability: cap(o, "builder", id, "builder-1", 1) }, 4);
      expect(() => T("VERIFYING", { capability: cap(o, "verification_worker", id, "builder-1", 1) }, 5)).toThrow(/builder cannot verify/); // the builder under a verifier token
      T("VERIFYING", { capability: cap(o, "verification_worker", id, "verifier-1", 1) }, 5);
      const worker = cap(o, "verification_worker", id, "verifier-1", 1);
      const review = { origin: "machine" as const, kind: "check_result", outcome: "passed" as const };
      expect(() => appendEvidence(db, dir, id, { ...review, checkId: "adversarial_review" }, { capability: worker }, fp("v1"), at(20))).toThrow(/adversarial_reviewer/); // the test runner cannot attest the adversarial review
      appendEvidence(db, dir, id, { ...review, checkId: "adversarial_review" }, { capability: cap(o, "adversarial_reviewer", id, "red-team", 1) }, fp("v1"), at(21));
      expect(() => appendEvidence(db, dir, id, { ...review, checkId: "tests" }, { capability: cap(o, "builder", id, "builder-1", 1) }, fp("v1"), at(22))).toThrow(/can only be recorded by/);
      // machine evidence is refused outside a verifying state
      const early = newTask(o, "A1");
      expect(() => appendEvidence(db, dir, early.task_id, { ...review, checkId: "tests" }, { capability: cap(o, "verification_worker", early.task_id, "verifier-1", 1) }, fp("v1"), at(23))).toThrow(/only recorded while the task is being verified/);
      // revoking capabilities cuts every older token off
      const stale = cap(o, "architect", id, "arch", 1);
      revokeCapabilities(db, dir, id, ADMIN, at(24));
      expect(() => appendEvidence(db, dir, id, { origin: "agent_note", kind: "note", outcome: "passed" }, { capability: stale }, fp("v1"), at(25))).toThrow(/revoked/);
      expect(() => revokeCapabilities(db, dir, id, APPROVER, at(25))).toThrow(/admin/);
      appendEvidence(db, dir, id, { origin: "agent_note", kind: "note", outcome: "passed" }, { capability: cap(o, "architect", id, "arch", 1) }, fp("v1"), at(26)); // a fresh token works
    });
  });

  it("profiles may only gain checks: risk scoring adds, a policy tightening adds a mandatory check and stales older tasks", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const t = newTask(o, "A3");
      expect(evaluateEligibility(db, dir, t.task_id, fp("v1"), at(1)).requiredChecks).toEqual(["adversarial_review", "dependency_review", "lint", "scope", "security_review", "tests", "typecheck"]);
      const risky = newTask(o, "A1", ["src/oauth/login.ts"]);
      expect(evaluateEligibility(db, dir, risky.task_id, fp("v1"), at(1)).requiredChecks).toContain("security_review"); // risk scoring ADDS (and matches anywhere in the path)
      const before = evaluateEligibility(db, dir, t.task_id, fp("v1"), at(1));
      updatePolicy(dir, ADMIN, { extraChecks: { A3: ["license_scan"] } }, at(2));
      const after = evaluateEligibility(db, dir, t.task_id, fp("v1"), at(3));
      expect(after.requiredChecks).toEqual([...before.requiredChecks, "license_scan"].sort());
      expect(after.stale.join(" ")).toMatch(/policy changed/);
      expect(after.approvalsNeeded).toBe(2);
      writeFileSync(join(dir, "sentinel-policy.json"), JSON.stringify({ extraChecks: null, minApprovals: [] })); // a hand-edited malformed file must not break every call
      expect(evaluateEligibility(db, dir, t.task_id, fp("v1"), at(4)).requiredChecks).toContain("tests");
    });
  });
});

describe("S3A evidence integrity", () => {
  it("rejects forged evidence: fingerprint, verifier, origin, timestamp, and edits made behind the API", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const t = newTask(o, "A1");
      const id = t.task_id;
      driveToAssurance(o, id, fp("v1"));
      const worker = cap(o, "verification_worker", id, "verifier-1");
      const builder = cap(o, "builder", id, "builder-1");
      const evidence = { origin: "machine" as const, kind: "check_result", checkId: "tests", outcome: "passed" as const };
      expect(() => appendEvidence(db, dir, id, { ...evidence, claimedSourceFingerprint: fp("other") }, { capability: worker }, fp("v1"), at(20))).toThrow(/does not match the repository/);
      expect(() => appendEvidence(db, dir, id, evidence, { capability: worker }, fp("v2"), at(20))).toThrow(/source changed/);
      expect(() => appendEvidence(db, dir, id, evidence, { capability: builder }, fp("v1"), at(20))).toThrow(/can only be recorded by/); // a builder cannot mint machine evidence
      expect(() => appendEvidence(db, dir, id, evidence, { operator: ADMIN }, fp("v1"), at(20))).toThrow(/can only be recorded by/);
      appendEvidence(db, dir, id, { ...evidence, origin: "agent_note" }, { capability: builder }, fp("v1"), at(20)); // a note is allowed and counts for nothing
      appendEvidence(db, dir, id, evidence, { capability: worker }, fp("v1"), at(21));
      expect(() => appendEvidence(db, dir, id, evidence, { capability: worker }, fp("v1"), at(5))).toThrow(/backwards/);
      expect(db.prepare("SELECT verifier FROM sentinel_evidence WHERE origin = 'machine'").get()).toEqual({ verifier: "verifier-1" }); // identity comes from the token
      expect(verifyTaskChain(db, dir, id).ok).toBe(true);
      expect(evaluateEligibility(db, dir, id, fp("v1"), at(22)).blockers.join(" ")).not.toMatch(/tests:/); // the passing machine result counts; the agent note did not create the other checks
      expect(evaluateEligibility(db, dir, id, fp("v1"), at(22)).blockers.join(" ")).toMatch(/lint: pending/);

      // behind the API: triggers stop edits and replacement, and rows planted with the triggers dropped are caught
      expect(() => db.prepare("UPDATE sentinel_evidence SET outcome = 'passed'").run()).toThrow(/append-only/);
      expect(() => db.prepare("DELETE FROM sentinel_task_events").run()).toThrow(/append-only/);
      expect(() => db.prepare("INSERT OR REPLACE INTO sentinel_evidence (seq, task_id, at, origin, kind, check_id, outcome, verifier, source_fingerprint, policy_hash, environment_json, payload_json, prev_hash, hash, mac) VALUES (1, ?, 'x', 'machine', 'k', 'tests', 'passed', 'v', 'f', 'p', '{}', '{}', 'a', 'b', 'c')").run(id)).toThrow(/replaced or back-filled/);
      db.prepare("INSERT INTO sentinel_evidence (task_id, at, origin, kind, check_id, outcome, verifier, source_fingerprint, policy_hash, environment_json, payload_json, prev_hash, hash, mac) VALUES (?, ?, 'machine', 'check_result', 'lint', 'passed', 'verifier-1', ?, 'x', '{}', '{}', 'a', 'b', 'c')")
        .run(id, at(23).toISOString(), fp("v1"));
      const forged = verifyTaskChain(db, dir, id);
      expect(forged.ok).toBe(false);
      expect(forged.problems.join(" ")).toMatch(/hash chain/);
      expect(evaluateEligibility(db, dir, id, fp("v1"), at(24)).blockers.join(" ")).toMatch(/failed verification/);
    });
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const t = newTask(o, "A1");
      driveToAssurance(o, t.task_id, fp("v1"));
      const worker = cap(o, "verification_worker", t.task_id, "verifier-1");
      appendEvidence(db, dir, t.task_id, { origin: "machine", kind: "check_result", checkId: "tests", outcome: "failed" }, { capability: worker }, fp("v1"), at(20));
      db.exec("DROP TRIGGER sentinel_evidence_append_only_u");
      for (const [column, value] of [["verifier", "someone-else"], ["outcome", "passed"], ["at", "2030-01-01T00:00:00.000Z"], ["source_fingerprint", "f".repeat(64)]] as const) {
        const row = db.prepare("SELECT seq, " + column + " AS v FROM sentinel_evidence WHERE task_id = ? AND origin = 'machine' ORDER BY seq DESC LIMIT 1").get(t.task_id) as { seq: number; v: string };
        db.prepare(`UPDATE sentinel_evidence SET ${column} = ? WHERE seq = ?`).run(value, row.seq);
        expect(verifyTaskChain(db, dir, t.task_id).ok, column).toBe(false);
        db.prepare(`UPDATE sentinel_evidence SET ${column} = ? WHERE seq = ?`).run(row.v, row.seq);
        expect(verifyTaskChain(db, dir, t.task_id).ok, `${column} restored`).toBe(true);
      }
    });
  });

  it("the task seal catches a raw edit of the state and a truncated log; forged approval rows never count", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const t = newTask(o, "A1");
      const id = t.task_id;
      driveToAssurance(o, id, fp("v1"));
      passAll(o, id, fp("v1"), 20, ["scope", "tests", "lint"]);
      assureTask(db, dir, id, cap(o, "assurance_controller", id, "assurance-1"), fp("v1"), at(21));
      // a raw INSERT of an "active approval" carries no valid MAC and does not count
      db.prepare("INSERT INTO sentinel_approvals (approval_id, task_id, approver, at, task_revision, source_fingerprint, policy_hash, evidence_head, status, mac) VALUES ('ap_forged', ?, 'mallory', ?, 1, ?, 'p', 'h', 'active', 'x')")
        .run(id, at(22).toISOString(), fp("v1"));
      expect(evaluateEligibility(db, dir, id, fp("v1"), at(23)).approvalsValid).toBe(0);
      // a raw UPDATE of the state is detected by the seal
      db.prepare("UPDATE sentinel_tasks SET state = 'ELIGIBLE_FOR_APPROVAL' WHERE task_id = ?").run(id);
      expect(verifyTaskChain(db, dir, id).problems.join(" ")).toMatch(/seal/);
      expect(taskReport(db, dir, id, fp("v1"), at(24)).chain.ok).toBe(false);
      db.prepare("UPDATE sentinel_tasks SET state = 'APPROVAL_REQUIRED' WHERE task_id = ?").run(id);
      expect(verifyTaskChain(db, dir, id).ok).toBe(true);
      // truncating the newest event (with the append-only trigger removed) is detected
      db.exec("DROP TRIGGER sentinel_events_append_only_d");
      db.prepare("DELETE FROM sentinel_task_events WHERE seq = (SELECT MAX(seq) FROM sentinel_task_events WHERE task_id = ?)").run(id);
      expect(verifyTaskChain(db, dir, id).ok).toBe(false);
      // an execution authorization cannot be extended, topped up or revived behind the API: the trigger refuses each edit
      const t2 = newTask(o, "A1");
      driveToImplementing(o, t2.task_id, fp("v1"), 30);
      const auth = authorizeExecution(db, dir, t2.task_id, APPROVER, fp("v1"), { now: at(40), maxRuns: 2 });
      const row = () => db.prepare("SELECT expires_at, runs_left, status, mac FROM sentinel_exec_auth WHERE auth_id = ?").get(auth);
      const issued = row();
      expect(() => db.prepare("UPDATE sentinel_exec_auth SET expires_at = '2099-01-01T00:00:00.000Z' WHERE auth_id = ?").run(auth)).toThrow(/can only be used up or revoked/); // extend while active
      expect(() => db.prepare("UPDATE sentinel_exec_auth SET runs_left = 9 WHERE auth_id = ?").run(auth)).toThrow(/can only be used up or revoked/); // top up
      revokeExecution(db, dir, t2.task_id, APPROVER);
      expect(() => db.prepare("UPDATE sentinel_exec_auth SET status = 'active' WHERE auth_id = ?").run(auth)).toThrow(/can only be used up or revoked/); // revive
      expect(() => db.prepare("DELETE FROM sentinel_exec_auth WHERE auth_id = ?").run(auth)).toThrow(/never deleted/);
      expect(row()).toMatchObject({ expires_at: (issued as { expires_at: string }).expires_at, runs_left: 2, status: "revoked" });
      expect(executionPermitted(db, dir, t2.task_id, fp("v1"), FAKE_OK, at(41)).reasons).toContain("no active execution authorization");
    });
  });
});

describe("S3A authorization goes stale", () => {
  it("approvals are bound to source, policy and evidence; a source change, policy change or later evidence invalidates them", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const t = newTask(o, "A1");
      const id = t.task_id;
      driveToAssurance(o, id, fp("v1"));
      passAll(o, id, fp("v1"), 20, ["scope", "tests", "lint"]);
      assureTask(db, dir, id, cap(o, "assurance_controller", id, "assurance-1"), fp("v1"), at(21));
      approveTask(db, dir, id, APPROVER, fp("v1"), at(22));
      expect(taskReport(db, dir, id, fp("v1"), at(23)).authorization.standing).toBe("current");
      expect(taskReport(db, dir, id, fp("v2"), at(24)).authorization.standing).toBe("stale"); // the source changed
      expect(revalidateTask(db, dir, id, fp("v2"), at(25))).toMatchObject({ stale: true, state: "BLOCKED" });
      expect(db.prepare("SELECT COUNT(*) AS n FROM sentinel_approvals WHERE status = 'active'").get()).toEqual({ n: 0 });
      expect(() => approveTask(db, dir, id, APPROVER2, fp("v2"), at(26))).toThrow(/approved from APPROVAL_REQUIRED/);
    });
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const t = newTask(o, "A1");
      const id = t.task_id;
      driveToAssurance(o, id, fp("v1"));
      passAll(o, id, fp("v1"), 20, ["scope", "tests", "lint"]);
      assureTask(db, dir, id, cap(o, "assurance_controller", id, "assurance-1"), fp("v1"), at(21));
      approveTask(db, dir, id, APPROVER, fp("v1"), at(22));
      expect(getTask(db, id).state).toBe("ELIGIBLE_FOR_APPROVAL");
      // NEW evidence after approval makes that approval stale and withdraws eligibility; a failing result blocks
      appendEvidence(db, dir, id, { origin: "machine", kind: "check_result", checkId: "tests", outcome: "passed" }, { capability: cap(o, "verification_worker", id, "verifier-1") }, fp("v1"), at(30));
      expect(getTask(db, id).state).toBe("APPROVAL_REQUIRED");
      expect(evaluateEligibility(db, dir, id, fp("v1"), at(31)).approvalsValid).toBe(0);
      approveTask(db, dir, id, APPROVER, fp("v1"), at(32)); // approving again (the old approval no longer counts) is allowed
      expect(getTask(db, id).state).toBe("ELIGIBLE_FOR_APPROVAL");
      appendEvidence(db, dir, id, { origin: "machine", kind: "check_result", checkId: "lint", outcome: "failed" }, { capability: cap(o, "verification_worker", id, "verifier-1") }, fp("v1"), at(33));
      expect(getTask(db, id)).toMatchObject({ state: "BLOCKED" });
      expect(db.prepare("SELECT COUNT(*) AS n FROM sentinel_approvals WHERE status = 'active'").get()).toEqual({ n: 0 });
      // a policy change after approval
      const t3 = newTask(o, "A1");
      driveToAssurance(o, t3.task_id, fp("v1"), 50);
      passAll(o, t3.task_id, fp("v1"), 70, ["scope", "tests", "lint"]);
      assureTask(db, dir, t3.task_id, cap(o, "assurance_controller", t3.task_id, "assurance-1", 50), fp("v1"), at(71));
      approveTask(db, dir, t3.task_id, APPROVER, fp("v1"), at(72));
      updatePolicy(dir, ADMIN, { extraChecks: { A1: ["license_scan"] } }, at(73));
      expect(revalidateTask(db, dir, t3.task_id, fp("v1"), at(74))).toMatchObject({ stale: true, state: "BLOCKED" });
    });
  });

  it("execution authorization is state-gated, single-use, signed, expiring, and dies with the source, the policy, or any trip through BLOCKED", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const early = newTask(o, "A1");
      expect(() => authorizeExecution(db, dir, early.task_id, APPROVER, fp("v1"), { now: at(1) })).toThrow(/cannot be authorized to execute/); // nothing planned yet
      const t = newTask(o, "A1");
      const id = t.task_id;
      driveToImplementing(o, id, fp("v1"));
      expect(() => authorizeExecution(db, dir, id, { id: "builder-1", roles: ["approve"] }, fp("v1"), { now: at(10) })).toThrow(/builder cannot/);
      expect(() => authorizeExecution(db, dir, id, APPROVER, fp("v2"), { now: at(10) })).toThrow(/source changed/);
      authorizeExecution(db, dir, id, APPROVER, fp("v1"), { now: at(10) });
      expect(executionPermitted(db, dir, id, fp("v1"), FAKE_OK, at(11)).permitted).toBe(true);
      expect(executionPermitted(db, dir, id, fp("v2"), FAKE_OK, at(11)).reasons.join(" ")).toMatch(/stale/);
      expect(executionPermitted(db, dir, id, fp("v1"), FAKE_OK, at(60)).reasons.join(" ")).toMatch(/expired/);
      // a raw edit of the authorization (extend its life) fails its integrity check
      db.prepare("UPDATE sentinel_exec_auth SET runs_left = 0 WHERE task_id = ?").run(id); // using it up is allowed (it only ever decreases)...
      expect(() => db.prepare("UPDATE sentinel_exec_auth SET expires_at = '2099-01-01T00:00:00.000Z' WHERE task_id = ?").run(id)).toThrow(/used up or revoked/);
      expect(() => db.prepare("UPDATE sentinel_exec_auth SET runs_left = 5 WHERE task_id = ?").run(id)).toThrow(/used up or revoked/);
      const tampered = executionPermitted(db, dir, id, fp("v1"), FAKE_OK, at(11)); // ...but a raw edit, even a permitted one, breaks the MAC: the integrity path, not the used-up path
      expect(tampered.permitted).toBe(false);
      expect(tampered.reasons).toContain("the execution authorization failed its integrity check");
      expect(tampered.reasons.join(" ")).not.toMatch(/used up/);
      // BLOCKED then re-planned: the old authorization does not come back
      const t2 = newTask(o, "A1");
      driveToImplementing(o, t2.task_id, fp("v1"), 100);
      authorizeExecution(db, dir, t2.task_id, APPROVER, fp("v1"), { now: at(110) });
      transitionTask(db, dir, t2.task_id, "BLOCKED", { capability: cap(o, "builder", t2.task_id, "builder-1", 100) }, { now: at(111), reason: "waiting" });
      transitionTask(db, dir, t2.task_id, "CONTEXT_READY", { operator: ADMIN }, { now: at(112) });
      expect(db.prepare("SELECT COUNT(*) AS n FROM sentinel_exec_auth WHERE task_id = ? AND status = 'active'").get(t2.task_id)).toEqual({ n: 0 });
      // a policy change after authorization
      const t3 = newTask(o, "A1");
      driveToImplementing(o, t3.task_id, fp("v1"), 200);
      authorizeExecution(db, dir, t3.task_id, APPROVER, fp("v1"), { now: at(210) });
      updatePolicy(dir, ADMIN, { extraChecks: { A1: ["license_scan"] } }, at(211));
      expect(executionPermitted(db, dir, t3.task_id, fp("v1"), FAKE_OK, at(212)).reasons.join(" ")).toMatch(/stale/);
    });
  });
});

describe("S3A execution interface", () => {
  it("strict mode: with no verified sandbox nothing runs, a worker needs the lease secret, and indexing/MCP-facing reads stay usable", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, async (o) => {
      const { db, dir } = o.store;
      const t = newTask(o, "A1");
      const id = t.task_id;
      driveToImplementing(o, id, fp("v1"));
      authorizeExecution(db, dir, id, APPROVER, fp("v1"), { now: new Date(), maxRuns: 3 });
      const lease = claimTask(db, id, "ctl", 3600).leaseToken;
      expect((await probeCapabilities([noSandbox])).result.verified).toBe(false);
      await expect(runSyntheticWorker(db, dir, id, { leaseToken: lease, program: "ok", backend: noSandbox, fingerprint: () => fp("v1"), timeoutMs: 5000 })).rejects.toThrow(/no verified sandbox/);
      await expect(runSyntheticWorker(db, dir, id, { leaseToken: "ctl", program: "ok", backend: passthrough, fingerprint: () => fp("v1"), timeoutMs: 5000 })).rejects.toThrow(/lease/); // the controller NAME is not the credential
      await expect(runSyntheticWorker(db, dir, id, { leaseToken: lease, program: "ok", backend: passthrough, fingerprint: () => fp("v1"), timeoutMs: 7_200_000 })).rejects.toThrow(/timeout/);
      // a caller cannot vouch for the sandbox: the backend is probed inside the worker, so a backend that does not verify is refused whatever the caller believes
      await expect(runSyntheticWorker(db, dir, id, { leaseToken: lease, program: "ok", backend: { ...noSandbox, wrap: passthrough.wrap }, fingerprint: () => fp("v1"), timeoutMs: 5000 })).rejects.toThrow(/no verified sandbox/);
    });
    expect((await runCli(w.repo, ["index", "--json"], w.home, NO_OPERATOR)).code).toBe(0); // indexing is unaffected
    expect((await runCli(w.repo, ["status", "--json"], w.home, NO_OPERATOR)).code).toBe(0);
  });

  it("runs only the fixed synthetic programs, one authorized run each, enforces timeouts, stops on cancellation (also from another connection) and on a moving tree", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, async (o) => {
      const { db, dir } = o.store;
      const t = newTask(o, "A1");
      const id = t.task_id;
      driveToImplementing(o, id, fp("v1"));
      const lease = claimTask(db, id, "ctl", 3600).leaseToken;
      authorizeExecution(db, dir, id, APPROVER, fp("v1"), { now: new Date(), maxRuns: 4 });
      const base = { leaseToken: lease, backend: passthrough, fingerprint: () => fp("v1") };
      expect(await runSyntheticWorker(db, dir, id, { ...base, program: "ok", timeoutMs: 10_000 })).toMatchObject({ outcome: "passed", stdout: "synthetic-ok" });
      expect(await runSyntheticWorker(db, dir, id, { ...base, program: "sleep", timeoutMs: 300 })).toMatchObject({ outcome: "timed_out" });
      let calls = 0;
      expect((await runSyntheticWorker(db, dir, id, { ...base, program: "ok", timeoutMs: 10_000, fingerprint: () => (calls++ === 0 ? fp("v1") : fp("changed-while-running")) })).outcome).toBe("incomplete");
      // cancellation from another connection (the CLI is another process) stops the child; queued work is dropped
      enqueueWork(db, id, "verify");
      const running = runSyntheticWorker(db, dir, id, { ...base, program: "sleep", timeoutMs: 60_000 });
      await new Promise((r) => setTimeout(r, 500));
      await withStore(w.repo, w.home, (other) => { cancelTask(other.store.db, other.store.dir, id, APPROVER, "stop", new Date()); });
      expect((await running).outcome).toBe("cancelled");
      expect(dequeueWork(db)).toBeNull();
      expect(() => enqueueWork(db, id, "more")).toThrow(/finished/);
      await expect(runSyntheticWorker(db, dir, id, { ...base, program: "ok", timeoutMs: 1000 })).rejects.toThrow(/only the controller holding the task's lease may execute/); // cancellation cleared the lease
    });
    await withStore(w.repo, w.home, async (o) => {
      const { db, dir } = o.store;
      const t = newTask(o, "A1");
      driveToImplementing(o, t.task_id, fp("v1"));
      const lease = claimTask(db, t.task_id, "ctl", 3600).leaseToken;
      authorizeExecution(db, dir, t.task_id, APPROVER, fp("v1"), { now: new Date() }); // one run only
      const used = { leaseToken: lease, backend: passthrough, fingerprint: () => fp("v1"), timeoutMs: 10_000 };
      expect((await runSyntheticWorker(db, dir, t.task_id, { ...used, program: "ok" })).outcome).toBe("passed");
      await expect(runSyntheticWorker(db, dir, t.task_id, { ...used, program: "ok" })).rejects.toThrow(/used up/); // single use
    });
  });

  it.skipIf(!REAL_SANDBOX.result.verified)(`the real macOS sandbox, when it self-tests, denies writes (exit 7 from write_attempt) [sandbox probe: ${REAL_SANDBOX.result.detail}]`, async () => {
    const w = await setup();
    await withStore(w.repo, w.home, async (o) => {
      const { db, dir } = o.store;
      const t = newTask(o, "A1");
      driveToImplementing(o, t.task_id, fp("v1"));
      const lease = claimTask(db, t.task_id, "ctl", 3600).leaseToken;
      authorizeExecution(db, dir, t.task_id, APPROVER, fp("v1"), { now: new Date(), maxRuns: 2 });
      const common = { leaseToken: lease, backend: REAL_SANDBOX.backend, fingerprint: () => fp("v1"), timeoutMs: 15_000 };
      expect(REAL_SANDBOX.backend.name).toBe("macos-sandbox-exec");
      expect(await runSyntheticWorker(db, dir, t.task_id, { ...common, program: "ok" })).toMatchObject({ outcome: "passed", exitCode: 0, stdout: "synthetic-ok" });
      expect(await runSyntheticWorker(db, dir, t.task_id, { ...common, program: "write_attempt" })).toMatchObject({ outcome: "failed", exitCode: 7 }); // 7 = the program caught the denied write (not a crash or a signal)
    });
  });
});

describe("S3A atomicity and concurrency", () => {
  it("a second controller cannot take or advance a held task, and a stale revision is refused", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const t = newTask(o, "A1");
      const id = t.task_id;
      const a = claimTask(db, id, "controller-a", 3600, at(1)).leaseToken;
      expect(() => claimTask(db, id, "controller-b", 3600, at(2))).toThrow(/holds this task/);
      expect(() => transitionTask(db, dir, id, "CONTEXT_READY", { capability: cap(o, "architect", id, "arch") }, { now: at(2) })).toThrow(/holds this task/); // no token at all
      transitionTask(db, dir, id, "CONTEXT_READY", { capability: cap(o, "architect", id, "arch") }, { now: at(2), leaseToken: a, expectedRevision: 1 });
      expect(() => transitionTask(db, dir, id, "SPECIFICATION_READY", { capability: cap(o, "architect", id, "arch") }, { now: at(3), leaseToken: a, expectedRevision: 1 })).toThrow(/moved on/);
      const before = db.prepare("SELECT COUNT(*) AS n FROM sentinel_task_events").get() as { n: number };
      expect(() => transitionTask(db, dir, id, "IMPLEMENTING", { capability: cap(o, "builder", id, "b") }, { now: at(4), leaseToken: a })).toThrow(/illegal transition CONTEXT_READY -> IMPLEMENTING/);
      expect(db.prepare("SELECT COUNT(*) AS n FROM sentinel_task_events").get()).toEqual(before);
      expect(getTask(db, id).revision).toBe(2);
    });
  });
});

describe("S3A command line", () => {
  it("plan (dry run) writes no source and no task; list/status/report/cancel work with an authenticated operator; check-scope needs a capability", async () => {
    const w = await setup();
    const boot = await runCli(w.repo, ["memory", "operator", "add", "root", "--roles", "propose,approve,verify,admin", "--yes", "--json"], w.home, NO_OPERATOR);
    const env = { ENGBRAIN_OPERATOR: "root", ENGBRAIN_OPERATOR_TOKEN: (JSON.parse(boot.stdout) as { token: string }).token };
    await runCli(w.repo, ["index"], w.home, NO_OPERATOR);
    const dry = await runCli(w.repo, ["sentinel", "plan", "--title", "Add retries", "--scope", "src/app.ts", "--profile", "A2", "--dry-run", "--json"], w.home, env);
    expect(dry.code).toBe(0);
    expect(JSON.parse(dry.stdout)).toMatchObject({ dryRun: true, requiredChecks: expect.arrayContaining(["scope", "tests", "lint", "typecheck", "dependency_review"]) });
    expect(JSON.parse((await runCli(w.repo, ["sentinel", "list", "--json"], w.home, NO_OPERATOR)).stdout).tasks).toEqual([]);
    const unauthenticated = await runCli(w.repo, ["sentinel", "plan", "--title", "Add retries", "--scope", "src/app.ts", "--profile", "A2"], w.home, NO_OPERATOR);
    expect(unauthenticated.code).toBe(3);
    expect(unauthenticated.stderr).toMatch(/authenticated operator/);
    const made = await runCli(w.repo, ["sentinel", "plan", "--title", "Add retries", "--scope", "src/app.ts", "--profile", "A2", "--json"], w.home, env);
    expect(made.code).toBe(0);
    const id = (JSON.parse(made.stdout) as { id: string }).id;
    const status = JSON.parse((await runCli(w.repo, ["sentinel", "status", id, "--json"], w.home, NO_OPERATOR)).stdout) as { report: { task: { state: string }; chain: { ok: boolean } } };
    expect([status.report.task.state, status.report.chain.ok]).toEqual(["CREATED", true]);
    expect((await runCli(w.repo, ["sentinel", "report", id], w.home, NO_OPERATOR)).stdout).toMatch(/ELIGIBLE_FOR_APPROVAL grants no permission/);
    expect((await runCli(w.repo, ["sentinel", "check-scope", id], w.home, env)).code).toBe(2); // no capability supplied
    const issued = JSON.parse((await runCli(w.repo, ["sentinel", "capability", "issue", id, "--role", "verification_worker", "--principal", "ci-1", "--json"], w.home, env)).stdout) as { token: string };
    expect(issued.token).toContain(".");
    const anonymousCancel = await runCli(w.repo, ["sentinel", "cancel", id, "--reason", "test"], w.home, NO_OPERATOR);
    expect(anonymousCancel.code).toBe(3);
    expect(anonymousCancel.stderr).toMatch(/authenticated operator/);
    writeFileSync(join(w.repo, "src-drift.txt"), "the tree drifted after the last index"); // a stale index must not block an emergency cancel
    expect((await runCli(w.repo, ["sentinel", "cancel", id, "--reason", "test"], w.home, env)).code).toBe(0);
    expect(JSON.parse((await runCli(w.repo, ["sentinel", "status", id, "--json"], w.home, NO_OPERATOR)).stdout).report.task.state).toBe("CANCELLED");
    expect((await runCli(w.repo, ["sentinel", "plan", "--title", "Another", "--scope", "src/app.ts"], w.home, env)).code).toBe(3); // drifted tree: planning refuses a non-verified index
  });
});
