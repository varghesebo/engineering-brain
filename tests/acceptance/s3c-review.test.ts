import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  addFinding, appendEvidence, approveTask, assureTask, authorizeWorktree, createHandoff, createTask, createTaskHandoff, enforceWorktree, getTask, issueCapability, listFindings, recordIteration,
  resolveFinding, resumeFromHandoff, revokeWorktree, startRepair, transitionTask, type Actor, type Role
} from "@engbrain/core";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, engbrainHome, makeGitRepo, tempDir } from "../helpers/env.js";
import { withStore, type Opened } from "../helpers/h1.js";

afterAll(cleanupTempDirs);

const ADMIN: Actor = { id: "alice", roles: ["propose", "approve", "verify", "admin"] };
const APPROVER: Actor = { id: "carol", roles: ["propose", "approve"] };
const REQUESTER: Actor = { id: "req", roles: ["propose"] };
const fp = (s: string): string => createHash("sha256").update(s).digest("hex");
const FP = fp("tree-v1");
const sha = (s: string): string => createHash("sha256").update(s).digest("hex");

async function setup(): Promise<{ repo: string; home: string }> {
  const repo = makeGitRepo({ "a.ts": "export const a = 1;\n" });
  const home = engbrainHome();
  await withStore(repo, home, () => undefined, true);
  return { repo, home };
}
const cap = (o: Opened, role: Role, taskId: string, principal: string): string => issueCapability(o.store.dir, { role, taskId, principal, ttlSeconds: 3600, issuer: ADMIN, epoch: getTask(o.store.db, taskId).cap_epoch });

function worktree(): string {
  const dir = tempDir("engbrain-wt-");
  mkdirSync(join(dir, "src/auth"), { recursive: true });
  mkdirSync(join(dir, "tests"), { recursive: true });
  writeFileSync(join(dir, "src/app.ts"), "export const app = 1;\n");
  writeFileSync(join(dir, "README.md"), "# project\n");
  writeFileSync(join(dir, "tests/app.test.ts"), "it('works', () => {});\n");
  writeFileSync(join(dir, "sentinel-policy.json"), "{}\n");
  return dir;
}
function newTask(o: Opened, scope = ["src/"]) {
  return createTask(o.store.db, o.store.dir, { title: "Add authentication", requester: REQUESTER, profile: "A1", scope, sourceFingerprint: FP });
}
type Steps = Parameters<typeof transitionTask>;
function drive(o: Opened, id: string, until: "PLAN_APPROVED" | "IMPLEMENTING" | "VERIFYING"): void {
  const { db, dir } = o.store;
  const T = (to: Steps[3], who: Steps[4]) => transitionTask(db, dir, id, to, who);
  T("CONTEXT_READY", { capability: cap(o, "architect", id, "arch") });
  T("SPECIFICATION_READY", { capability: cap(o, "architect", id, "arch") });
  T("PLAN_APPROVED", { operator: APPROVER });
  if (until === "PLAN_APPROVED") {
    return;
  }
  T("IMPLEMENTING", { capability: cap(o, "builder", id, "builder-1") });
  if (until === "VERIFYING") {
    T("IMPLEMENTED", { capability: cap(o, "builder", id, "builder-1") });
    T("VERIFYING", { capability: cap(o, "verification_worker", id, "verifier-1") });
  }
}
const evidence = (o: Opened, id: string, checkId: string, outcome: "passed" | "failed" | "skipped" | "timed_out"): number =>
  appendEvidence(o.store.db, o.store.dir, id, { origin: "machine", kind: "check_result", checkId, outcome }, { capability: cap(o, "verification_worker", id, "verifier-1") }, FP);
const seqOf = (o: Opened, id: string, checkId: string, outcome: string): number =>
  (o.store.db.prepare("SELECT MAX(seq) AS s FROM sentinel_evidence WHERE task_id = ? AND check_id = ? AND outcome = ?").get(id, checkId, outcome) as { s: number }).s;

describe("S3C review: a finding's evidence must really support it", () => {
  it("refuses superseded, skipped, non-required, missing-check, out-of-scope and line-less references; records the provider as an unverified claim", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir: store } = o.store;
      const id = newTask(o).task_id;
      drive(o, id, "VERIFYING");
      const reviewer = cap(o, "reviewer", id, "rev-1");
      const hashOf = (p: string): string | null => (p === "src/app.ts" ? sha("export const app = 1;\n") : p === "README.md" ? sha("# project\n") : null);
      const finding = (ev: Parameters<typeof addFinding>[3]["evidence"], provider?: string) =>
        addFinding(db, store, id, { severity: "advisory", title: "login accepts empty passwords", evidence: ev, reproduction: "call login('') and observe true", ...(provider === undefined ? {} : { provider }) }, reviewer, FP, hashOf);
      // (a) an old failure superseded by a pass is not evidence; a skipped run is not evidence
      evidence(o, id, "tests", "failed");
      const oldFailure = seqOf(o, id, "tests", "failed");
      evidence(o, id, "tests", "passed");
      expect(() => finding({ kind: "evidence", seq: oldFailure })).toThrow(/superseded/);
      evidence(o, id, "lint", "skipped");
      expect(() => finding({ kind: "evidence", seq: seqOf(o, id, "lint", "skipped") })).toThrow(/only a failed, timed-out or incomplete/);
      evidence(o, id, "lint", "timed_out");
      expect(finding({ kind: "evidence", seq: seqOf(o, id, "lint", "timed_out") })).toMatch(/^fd_/); // the latest result, timed out: a genuine finding
      // (b) a check that is not required for this task, or one with no result at all, does not support a finding
      expect(() => finding({ kind: "check", checkId: "security_review" })).toThrow(/not a check required/);
      expect(() => finding({ kind: "check", checkId: "scope" })).toThrow(/no current failing result/);
      expect(() => finding({ kind: "check", checkId: "tests" })).toThrow(/currently passes/);
      // (c) a file reference must be in the authorized scope and name a line
      expect(() => finding({ kind: "file", path: "README.md", sha256: sha("# project\n"), line: 1 })).toThrow(/outside the task's authorized scope/);
      expect(() => finding({ kind: "file", path: "src/../README.md", sha256: sha("# project\n"), line: 1 })).toThrow(/outside the task's authorized scope/);
      expect(() => finding({ kind: "file", path: "src/app.ts", sha256: sha("export const app = 1;\n"), line: 0 })).toThrow(/line number/);
      expect(() => finding({ kind: "file", path: "src/app.ts", sha256: sha("export const app = 1;\n") } as never)).toThrow(/line number/);
      const fileFinding = finding({ kind: "file", path: "src/app.ts", sha256: sha("export const app = 1;\n"), line: 1 }, "codex");
      // (e) the provider is stored but never presented as verified
      const row = listFindings(db, id).find((f) => f.finding_id === fileFinding)!;
      expect(row).toMatchObject({ provider: "codex", providerVerified: false });
      expect(listFindings(db, id).every((f) => f.providerVerified === false)).toBe(true);
    });
  });

  it("(d) a blocking finding withdraws approvals from an ELIGIBLE task", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir: store } = o.store;
      const id = newTask(o).task_id;
      drive(o, id, "VERIFYING");
      for (const c of ["scope", "tests", "lint"]) {
        evidence(o, id, c, "passed");
      }
      transitionTask(db, store, id, "ASSURANCE_REVIEW", { capability: cap(o, "verification_worker", id, "verifier-1") });
      expect(assureTask(db, store, id, cap(o, "assurance_controller", id, "assurance-1"), FP).state).toBe("APPROVAL_REQUIRED");
      expect(approveTask(db, store, id, APPROVER, FP).state).toBe("ELIGIBLE_FOR_APPROVAL");
      addFinding(db, store, id, { severity: "blocking", title: "login accepts empty passwords", evidence: { kind: "file", path: "src/app.ts", sha256: sha("x"), line: 3 }, reproduction: "call login('') and observe true" }, cap(o, "reviewer", id, "rev-1"), FP, () => sha("x"));
      expect(getTask(db, id).state).toBe("BLOCKED");
      expect(getTask(db, id).blocked_reason).toMatch(/eligibility withdrawn/);
      expect(db.prepare("SELECT COUNT(*) AS n FROM sentinel_approvals WHERE task_id = ? AND status = 'active'").get(id)).toEqual({ n: 0 });
    });
  });
});

describe("S3C review: `fixed` needs real proof", () => {
  it("a protected-files finding is fixed only once the worktree no longer shows protected changes", async () => {
    const w = await setup();
    const dir = worktree();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir: store } = o.store;
      const id = newTask(o, ["src/auth/", "tests/"]).task_id;
      drive(o, id, "VERIFYING");
      authorizeWorktree(db, id, APPROVER, dir, w.repo);
      writeFileSync(join(dir, "tests/app.test.ts"), "// it('works', () => {});\n");
      enforceWorktree(db, store, id, { capability: cap(o, "verification_worker", id, "verifier-1") }, FP);
      const f = listFindings(db, id, { open: true })[0]!;
      expect(f.title).toBe("protected files changed");
      expect(() => resolveFinding(db, id, f.finding_id, "fixed", APPROVER, "restored")).toThrow(/protected files are still changed.*tests\/app\.test\.ts/);
      writeFileSync(join(dir, "tests/app.test.ts"), "it('works', () => {});\n"); // the test is restored byte for byte
      resolveFinding(db, id, f.finding_id, "fixed", APPROVER, "restored");
      expect(listFindings(db, id, { open: true })).toHaveLength(0);
    });
  });

  it("a check finding is not fixed by a pass that a later failure superseded, nor by a pass on another source", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir: store } = o.store;
      const id = newTask(o).task_id;
      drive(o, id, "VERIFYING");
      evidence(o, id, "tests", "failed");
      const fid = addFinding(db, store, id, { severity: "advisory", title: "tests fail on login", evidence: { kind: "check", checkId: "tests" }, reproduction: "run the suite and see login fail" }, cap(o, "reviewer", id, "rev-1"), FP, () => null);
      const later = new Date(Date.now() + 1000);
      appendEvidence(db, store, id, { origin: "machine", kind: "check_result", checkId: "tests", outcome: "passed" }, { capability: cap(o, "verification_worker", id, "verifier-1") }, FP, later);
      appendEvidence(db, store, id, { origin: "machine", kind: "check_result", checkId: "tests", outcome: "failed" }, { capability: cap(o, "verification_worker", id, "verifier-1") }, FP, new Date(later.getTime() + 1000));
      expect(() => resolveFinding(db, id, fid, "fixed", APPROVER, "it passed once")).toThrow(/NEW passing machine evidence/);
      // the source moves on (the task is refreshed to a new fingerprint): a pass recorded for the old source does not fix it
      appendEvidence(db, store, id, { origin: "machine", kind: "check_result", checkId: "tests", outcome: "passed" }, { capability: cap(o, "verification_worker", id, "verifier-1") }, FP, new Date(later.getTime() + 2000));
      db.prepare("UPDATE sentinel_tasks SET source_fingerprint = ? WHERE task_id = ?").run(fp("tree-v2"), id); // simulates a refresh; the seal is not consulted by resolveFinding
      expect(() => resolveFinding(db, id, fid, "fixed", APPROVER, "passed on the old tree")).toThrow(/current source/);
      db.prepare("UPDATE sentinel_tasks SET source_fingerprint = ? WHERE task_id = ?").run(FP, id);
      resolveFinding(db, id, fid, "fixed", APPROVER, "tests pass again");
    });
  });
});

describe("S3C review: the repair loop is started by a person and really bounded", () => {
  it("startRepair needs an approve operator who did not build, a live task, and a capped budget", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db } = o.store;
      const early = newTask(o).task_id;
      drive(o, early, "PLAN_APPROVED");
      expect(() => startRepair(db, early, APPROVER)).toThrow(/PLAN_APPROVED task cannot start a repair loop/);
      const id = newTask(o).task_id;
      drive(o, id, "VERIFYING");
      expect(() => startRepair(db, id, REQUESTER)).toThrow(/approve role/);
      expect(() => startRepair(db, id, { id: "builder-1", roles: ["approve"] })).toThrow(/builder cannot/);
      expect(() => startRepair(db, id, APPROVER, { maxIterations: 21 })).toThrow(/at most 20/);
      expect(() => startRepair(db, id, APPROVER, { maxMs: 8 * 3_600_000 + 1 })).toThrow(/maxMs may be at most/);
      expect(() => startRepair(db, id, APPROVER, { maxTokens: 10_000_001 })).toThrow(/maxTokens may be at most/);
      expect(() => startRepair(db, id, APPROVER, { maxCostMicro: 100_000_001 })).toThrow(/maxCostMicro may be at most/);
      expect(() => startRepair(db, id, APPROVER, { maxSameFailure: 11 })).toThrow(/maxSameFailure may be at most/);
      expect(startRepair(db, id, APPROVER, { maxIterations: 20 }).budget.maxIterations).toBe(20);
      expect((db.prepare("SELECT started_at AS s FROM sentinel_repair WHERE task_id = ?").get(id) as { s: string }).s).not.toBe("");
    });
  });

  it("recordIteration needs an authorized party and a started loop, honours the backoff, and measures time itself", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir: store } = o.store;
      const id = newTask(o).task_id;
      drive(o, id, "VERIFYING");
      const t0 = Date.now();
      const at = (ms: number): Date => new Date(t0 + ms);
      const usage = (key: string, sig = "tests:login") => ({ iterationKey: key, tokens: 1, costMicro: 1, elapsedMs: 1, failureSignature: sig });
      const builder = { capability: cap(o, "builder", id, "builder-1") };
      expect(() => recordIteration(db, store, id, builder, usage("k1"), at(0))).toThrow(/no repair loop was started/);
      startRepair(db, id, APPROVER, { maxIterations: 5, maxSameFailure: 5, maxMs: 600_000 }, at(0));
      expect(() => recordIteration(db, store, id, { capability: cap(o, "reviewer", id, "rev-1") }, usage("k1"), at(0))).toThrow();
      expect(() => recordIteration(db, store, id, { operator: REQUESTER }, usage("k1"), at(0))).toThrow(/approve role/);
      const other = newTask(o).task_id;
      expect(() => recordIteration(db, store, id, { capability: cap(o, "builder", other, "builder-1") }, usage("k1"), at(0))).toThrow(); // a capability for another task
      expect(recordIteration(db, store, id, builder, usage("k1"), at(0))).toMatchObject({ allowed: true, backoffMs: 1000 });
      expect(() => recordIteration(db, store, id, builder, usage("k2"), at(500))).toThrow(/backing off/); // before next_allowed_at
      expect(recordIteration(db, store, id, builder, usage("k1"), at(500)).state.iterations).toBe(1); // an idempotent replay is still answered during the backoff
      expect(recordIteration(db, store, id, builder, usage("k2"), at(1000))).toMatchObject({ allowed: true, backoffMs: 2000 });
      // the caller reports 1 ms per iteration, but 11 minutes passed since the loop started: the time budget is exhausted anyway
      const late = recordIteration(db, store, id, { operator: APPROVER }, usage("k3"), at(660_000));
      expect(late.allowed).toBe(false);
      expect(late.reason).toMatch(/time budget/);
      expect(late.state.elapsedMs).toBeGreaterThanOrEqual(660_000);
      expect(getTask(db, id).state).toBe("BLOCKED");
    });
  });

  it("varying the failure signature cannot evade the bound", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir: store } = o.store;
      const id = newTask(o).task_id;
      drive(o, id, "VERIFYING");
      const t0 = Date.now();
      startRepair(db, id, APPROVER, { maxIterations: 3, maxSameFailure: 10 }, new Date(t0));
      const results = [1, 2, 3, 4].map((n) => recordIteration(db, store, id, { operator: APPROVER }, { iterationKey: `k${n}`, tokens: 1, costMicro: 1, elapsedMs: 1, failureSignature: `unique-${n}` }, new Date(t0 + n * 120_000)));
      expect(results.slice(0, 3).every((r) => r.allowed)).toBe(true);
      expect(results[3]!.allowed).toBe(false);
      expect(getTask(db, id).state).toBe("BLOCKED");
    });
  });
});

describe("S3C review: resuming a handoff checks it really belongs to the task", () => {
  it("refuses a handoff with another scope, one not created for the task, and a task whose worktree was revoked", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir: store } = o.store;
      const id = newTask(o, ["src/"]).task_id;
      drive(o, id, "VERIFYING");
      const good = createTaskHandoff(db, store, id, REQUESTER, FP);
      expect(resumeFromHandoff(db, store, good, id, FP).taskId).toBe(id);
      const wideScope = createHandoff(db, store, { task: "resume", scope: ["src", "README.md"], references: [`task:${id}`] }, { actor: REQUESTER }).handoff_id;
      expect(() => resumeFromHandoff(db, store, wideScope, id, FP)).toThrow(/scope does not match/);
      const notFirst = createHandoff(db, store, { task: "resume", scope: ["src"], references: ["note:something", `task:${id}`] }, { actor: REQUESTER }).handoff_id;
      expect(() => resumeFromHandoff(db, store, notFirst, id, FP)).toThrow(/not for that task/);
      const twoTasks = createHandoff(db, store, { task: "resume", scope: ["src"], references: [`task:${id}`, "task:st_0000000000000000"] }, { actor: REQUESTER }).handoff_id;
      expect(() => resumeFromHandoff(db, store, twoTasks, id, FP)).toThrow(/not for that task/);
      authorizeWorktree(db, id, APPROVER, worktree(), w.repo);
      expect(resumeFromHandoff(db, store, good, id, FP).taskId).toBe(id); // an active worktree is fine
      revokeWorktree(db, id);
      expect(() => resumeFromHandoff(db, store, good, id, FP)).toThrow(/worktree authorization was revoked/);
    });
  });
});
