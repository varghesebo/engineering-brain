import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  addFinding, appendEvidence, approveTask, authorizeWorktree, cancelTask, checkWorktree, createTask, createTaskHandoff, detectProviders, enforceWorktree, evaluateEligibility, getTask, issueCapability, launchProvider,
  listFindings, recordIteration, resolveFinding, resumeFromHandoff, reviewerIndependence, startRepair, transitionTask, updatePolicy, type Actor, type Role
} from "@engbrain/core";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, engbrainHome, makeGitRepo, runCli, tempDir } from "../helpers/env.js";
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

/** A throwaway worktree with a small project in it. */
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
function newTask(o: Opened, scope = ["src/auth/"], profile: "A1" | "A2" = "A1") {
  return createTask(o.store.db, o.store.dir, { title: "Add authentication", requester: REQUESTER, profile, scope, sourceFingerprint: FP });
}
type Steps = Parameters<typeof transitionTask>;
function drive(o: Opened, id: string, until: "IMPLEMENTING" | "VERIFYING"): void {
  const { db, dir } = o.store;
  const T = (to: Steps[3], who: Steps[4]) => transitionTask(db, dir, id, to, who);
  T("CONTEXT_READY", { capability: cap(o, "architect", id, "arch") });
  T("SPECIFICATION_READY", { capability: cap(o, "architect", id, "arch") });
  T("PLAN_APPROVED", { operator: APPROVER });
  T("IMPLEMENTING", { capability: cap(o, "builder", id, "builder-1") });
  if (until === "VERIFYING") {
    T("IMPLEMENTED", { capability: cap(o, "builder", id, "builder-1") });
    T("VERIFYING", { capability: cap(o, "verification_worker", id, "verifier-1") });
  }
}

describe("S3C authorized worktrees: unauthorized, protected and concurrent changes", () => {
  it("a synthetic auth feature inside the approved worktree is clean; a stray file outside the scope is caught and fails the scope check", async () => {
    const w = await setup();
    const dir = worktree();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir: store } = o.store;
      const t = newTask(o);
      const id = t.task_id;
      drive(o, id, "IMPLEMENTING");
      expect(() => authorizeWorktree(db, id, APPROVER, w.repo, w.repo)).toThrow(/separate \(throwaway\) directory/); // never your main working tree
      expect(() => authorizeWorktree(db, id, { id: "builder-1", roles: ["approve"] }, dir, w.repo)).toThrow(/builder cannot/);
      expect(() => authorizeWorktree(db, id, REQUESTER, dir, w.repo)).toThrow(/approve role/);
      expect(authorizeWorktree(db, id, APPROVER, dir, w.repo).files).toBe(4);
      // the Builder (an external agent) implements the feature inside the scope, adding a NEW test
      writeFileSync(join(dir, "src/auth/login.ts"), "export function login(u: string) { return u.length > 0; }\n");
      writeFileSync(join(dir, "src/auth/login.test.ts"), "it('logs in', () => {});\n");
      let report = checkWorktree(db, id, ["src/auth/login.ts", "src/auth/login.test.ts"]);
      expect(report).toMatchObject({ ok: true, unauthorized: [], protectedChanges: [], undeclared: [] });
      expect(report.added).toEqual(["src/auth/login.test.ts", "src/auth/login.ts"]);
      // then writes a file outside the authorized scope
      writeFileSync(join(dir, "README.md"), "# project\nSURPRISE\n");
      report = checkWorktree(db, id, ["src/auth/login.ts", "src/auth/login.test.ts", "README.md"]);
      expect(report.ok).toBe(false);
      expect(report.unauthorized).toEqual(["README.md"]);
      // enforcement records a FAILED mandatory `scope` check, so the task cannot become eligible
      transitionTask(db, store, id, "IMPLEMENTED", { capability: cap(o, "builder", id, "builder-1") });
      transitionTask(db, store, id, "VERIFYING", { capability: cap(o, "verification_worker", id, "verifier-1") });
      enforceWorktree(db, store, id, { capability: cap(o, "verification_worker", id, "verifier-1") }, FP, ["src/auth/login.ts", "src/auth/login.test.ts", "README.md"]);
      expect(evaluateEligibility(db, store, id, FP).blockers.join(" ")).toMatch(/scope: failed/);
    });
  });

  it("editing an existing test or the policy file to hide a failure is flagged, opens a blocking finding only a person can close, and checks cannot be dropped", async () => {
    const w = await setup();
    const dir = worktree();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir: store } = o.store;
      const t = newTask(o, ["src/auth/", "tests/"]);
      const id = t.task_id;
      drive(o, id, "VERIFYING");
      authorizeWorktree(db, id, APPROVER, dir, w.repo);
      writeFileSync(join(dir, "src/auth/login.ts"), "export const login = () => true;\n");
      writeFileSync(join(dir, "tests/app.test.ts"), "// it('works', () => {});\n"); // the Builder comments out a failing test
      writeFileSync(join(dir, "sentinel-policy.json"), JSON.stringify({ extraChecks: {} })); // and touches the policy file
      const report = enforceWorktree(db, store, id, { capability: cap(o, "verification_worker", id, "verifier-1") }, FP);
      expect(report.protectedChanges.sort()).toEqual(["sentinel-policy.json", "tests/app.test.ts"]);
      const open = listFindings(db, id, { open: true });
      expect(open).toHaveLength(1);
      expect(open[0]).toMatchObject({ severity: "blocking", title: "protected files changed", source_role: "controller" });
      expect(evaluateEligibility(db, store, id, FP).blockers.join(" ")).toMatch(/1 open blocking review finding/);
      enforceWorktree(db, store, id, { capability: cap(o, "verification_worker", id, "verifier-1") }, FP); // idempotent: no duplicate finding
      expect(listFindings(db, id, { open: true })).toHaveLength(1);
      // the builder cannot close it; neither can a plain operator; a person who is not the builder can
      expect(() => resolveFinding(db, id, open[0]!.finding_id, "rejected", { id: "builder-1", roles: ["approve"] }, "it is fine")).toThrow(/builder cannot/);
      expect(() => resolveFinding(db, id, open[0]!.finding_id, "rejected", REQUESTER, "it is fine")).toThrow(/approve role/);
      expect(() => resolveFinding(db, id, open[0]!.finding_id, "fixed", APPROVER, "restored")).toThrow(/protected files are still changed/);
      // mandatory checks cannot be dropped by policy either
      expect(() => updatePolicy(store, REQUESTER, { extraChecks: { A1: ["x_check"] } })).toThrow(/admin/);
      expect(() => updatePolicy(store, ADMIN, { minApprovals: { A1: 0 } })).toThrow(/only be raised/);
      resolveFinding(db, id, open[0]!.finding_id, "accepted_risk", APPROVER, "reviewed the test change by hand");
      expect(evaluateEligibility(db, store, id, FP).blockers.join(" ")).not.toMatch(/open blocking/); // closing the finding does not make the checks pass
      expect(evaluateEligibility(db, store, id, FP).checksPassing).toBe(false);
    });
  });

  it("a change by another actor pauses the task as BLOCKED and nothing is overwritten", async () => {
    const w = await setup();
    const dir = worktree();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir: store } = o.store;
      const t = newTask(o, ["src/"]);
      const id = t.task_id;
      drive(o, id, "VERIFYING");
      authorizeWorktree(db, id, APPROVER, dir, w.repo);
      writeFileSync(join(dir, "src/auth/login.ts"), "export const login = () => 1;\n"); // the builder's declared change
      writeFileSync(join(dir, "src/app.ts"), "export const app = 'someone else was here';\n"); // another actor edits during the task
      const report = enforceWorktree(db, store, id, { capability: cap(o, "verification_worker", id, "verifier-1") }, FP, ["src/auth/login.ts"]);
      expect(report.undeclared).toEqual(["src/app.ts"]);
      expect(getTask(db, id)).toMatchObject({ state: "BLOCKED" });
      expect(getTask(db, id).blocked_reason).toMatch(/outside what the builder declared.*nothing was overwritten/);
      expect(readFileSync(join(dir, "src/app.ts"), "utf8")).toBe("export const app = 'someone else was here';\n"); // untouched
    });
  });
});

describe("S3C findings: fabricated evidence is refused, genuine findings drive a bounded repair", () => {
  it("rejects invented evidence; a genuine finding blocks, drives repair and reverification, and is closed only by new passing machine evidence", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir: store } = o.store;
      const t = newTask(o, ["src/"]);
      const id = t.task_id;
      drive(o, id, "VERIFYING");
      const worker = cap(o, "verification_worker", id, "verifier-1");
      const reviewer = cap(o, "reviewer", id, "rev-1");
      const hashOf = (p: string): string | null => (p === "src/app.ts" ? sha("export const app = 1;\n") : null);
      const finding = (evidence: Parameters<typeof addFinding>[3]["evidence"], cap2 = reviewer) => addFinding(db, store, id, { severity: "blocking", title: "login accepts empty passwords", evidence, reproduction: "call login('') and observe true" }, cap2, FP, hashOf);
      // fabricated: a made-up evidence number, a wrong file hash, a missing file, a check that currently passes
      expect(() => finding({ kind: "evidence", seq: 9999 })).toThrow(/does not exist/);
      expect(() => finding({ kind: "file", path: "src/app.ts", sha256: "0".repeat(64), line: 1 })).toThrow(/does not match/);
      expect(() => finding({ kind: "file", path: "src/ghost.ts", sha256: sha("x"), line: 1 })).toThrow(/does not exist or its content hash/);
      appendEvidence(db, store, id, { origin: "machine", kind: "check_result", checkId: "lint", outcome: "passed" }, { capability: worker }, FP);
      expect(() => finding({ kind: "check", checkId: "lint" })).toThrow(/currently passes/);
      expect(() => finding({ kind: "evidence", seq: 1 })).toThrow(/PASSED/);
      expect(() => finding({ kind: "evidence", seq: 1 }, cap(o, "builder", id, "builder-1"))).toThrow(); // a builder token cannot review
      expect(() => addFinding(db, store, id, { severity: "blocking", title: "x", evidence: { kind: "check", checkId: "tests" }, reproduction: "no" }, reviewer, FP, hashOf)).toThrow(/short title and a reproduction/);
      // genuine: tests failed
      appendEvidence(db, store, id, { origin: "machine", kind: "check_result", checkId: "tests", outcome: "failed", payload: { failing: "login rejects empty" } }, { capability: worker }, FP);
      const failedSeq = (db.prepare("SELECT seq FROM sentinel_evidence WHERE check_id = 'tests'").get() as { seq: number }).seq;
      const fid = finding({ kind: "evidence", seq: failedSeq });
      expect(listFindings(db, id, { open: true })).toHaveLength(1);
      expect(evaluateEligibility(db, store, id, FP).blockers.join(" ")).toMatch(/open blocking review finding/);
      // the repair loop: reviewer reports, builder repairs, verification re-runs
      transitionTask(db, store, id, "FINDINGS_REPORTED", { capability: reviewer });
      startRepair(db, id, APPROVER, { maxIterations: 3 });
      const it1 = recordIteration(db, store, id, { capability: cap(o, "builder", id, "builder-1") }, { iterationKey: "repair-1", tokens: 1000, costMicro: 100, elapsedMs: 5000, failureSignature: "tests:login" }, undefined);
      expect(it1).toMatchObject({ allowed: true, backoffMs: 1000 });
      transitionTask(db, store, id, "REPAIRING", { capability: cap(o, "builder", id, "builder-1") });
      transitionTask(db, store, id, "REVERIFYING", { capability: cap(o, "verification_worker", id, "verifier-1") });
      expect(() => resolveFinding(db, id, fid, "fixed", APPROVER, "looks right")).toThrow(/NEW passing machine evidence/); // no new passing evidence yet
      appendEvidence(db, store, id, { origin: "machine", kind: "check_result", checkId: "tests", outcome: "passed" }, { capability: worker }, FP);
      resolveFinding(db, id, fid, "fixed", APPROVER, "tests pass again");
      expect(listFindings(db, id, { open: true })).toHaveLength(0);
      expect(() => resolveFinding(db, id, fid, "rejected", APPROVER, "again")).toThrow(/no such open finding/); // decided once
    });
  });
});

describe("S3C providers: nothing is faked", () => {
  it("reports what is installed, never launches anything, and does not mistake labels for independence", () => {
    const empty = tempDir("engbrain-path-");
    expect(detectProviders(empty).map((p) => [p.id, p.installed])).toEqual([["claude-code", false], ["codex", false], ["local-model", false]]);
    const bin = tempDir("engbrain-bin-");
    writeFileSync(join(bin, "claude"), "#!/bin/sh\nexit 0\n");
    chmodSync(join(bin, "claude"), 0o755);
    const found = detectProviders(bin);
    expect(found.find((p) => p.id === "claude-code")).toMatchObject({ installed: true, hosted: true });
    expect(found.find((p) => p.id === "codex")).toMatchObject({ installed: false });
    expect(found.find((p) => p.id === "codex")!.note).toMatch(/cannot be used and no reviewer can claim it/);
    expect(() => launchProvider()).toThrow(/does not launch any agent/);
    const builder = { provider: "claude-code", inputDigest: "a" };
    const installed = ["claude-code"];
    expect(reviewerIndependence(builder, { provider: "claude-code", inputDigest: "b" }, installed)).toMatchObject({ independent: false });
    expect(reviewerIndependence(builder, { provider: "codex", inputDigest: "b" }, installed).reasons.join(" ")).toMatch(/not installed here/);
    expect(reviewerIndependence(builder, { provider: "codex", inputDigest: "a" }, ["claude-code", "codex"]).reasons.join(" ")).toMatch(/distinct inputs/);
    expect(reviewerIndependence(builder, { provider: null, inputDigest: "b" }, installed).independent).toBe(false);
    expect(reviewerIndependence(builder, { provider: "codex", inputDigest: "b" }, ["claude-code", "codex"]).independent).toBe(true);
  });
});

describe("S3C bounded repair, cancellation and resumable handoffs", () => {
  it("exhausting any bound blocks the task; a repeated failure escalates; replaying an iteration is not charged twice", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir: store } = o.store;
      const a = newTask(o);
      drive(o, a.task_id, "VERIFYING");
      const t0 = Date.now();
      const at = (n: number): Date => new Date(t0 + n * 120_000); // each iteration after the previous backoff
      startRepair(db, a.task_id, APPROVER, { maxIterations: 2, maxSameFailure: 5 }, at(0));
      const step = (n: number) => recordIteration(db, store, a.task_id, { operator: APPROVER }, { iterationKey: `k${n}`, tokens: 10, costMicro: 1, elapsedMs: 10, failureSignature: `f${n}` }, at(n));
      expect(step(1)).toMatchObject({ allowed: true, backoffMs: 1000 });
      expect(recordIteration(db, store, a.task_id, { operator: APPROVER }, { iterationKey: "k1", tokens: 10, costMicro: 1, elapsedMs: 10, failureSignature: "f1" }, at(1)).state.iterations).toBe(1); // replay after a crash: not charged
      expect(step(2)).toMatchObject({ allowed: true, backoffMs: 2000 });
      const over = step(3);
      expect(over).toMatchObject({ allowed: false });
      expect(over.reason).toMatch(/iteration limit/);
      expect(getTask(db, a.task_id)).toMatchObject({ state: "BLOCKED" });
      expect(() => step(4)).toThrow(/no further repair/);
      // the same failure again and again: escalation, long before the iteration limit
      const b = newTask(o);
      drive(o, b.task_id, "VERIFYING");
      startRepair(db, b.task_id, APPROVER, { maxIterations: 20, maxSameFailure: 2 }, at(0));
      const same = (n: number) => recordIteration(db, store, b.task_id, { operator: APPROVER }, { iterationKey: `s${n}`, tokens: 1, costMicro: 1, elapsedMs: 1, failureSignature: "tests:login" }, at(n));
      expect(same(1).allowed && same(2).allowed).toBe(true);
      expect(same(3).reason).toMatch(/same failure recurred 3 times: escalating to a person/);
      // token budget
      const c = newTask(o);
      drive(o, c.task_id, "VERIFYING");
      startRepair(db, c.task_id, APPROVER, { maxTokens: 100 });
      expect(recordIteration(db, store, c.task_id, { operator: APPROVER }, { iterationKey: "t1", tokens: 500, costMicro: 0, elapsedMs: 1, failureSignature: "x" }).reason).toMatch(/token budget/);
    });
  });

  it("cancellation stops future work; a blocked task leaves a useful handoff; resuming revalidates source and policy", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir: store } = o.store;
      const t = newTask(o, ["src/"]);
      const id = t.task_id;
      drive(o, id, "VERIFYING");
      const reviewer = cap(o, "reviewer", id, "rev-1");
      appendEvidence(db, store, id, { origin: "machine", kind: "check_result", checkId: "tests", outcome: "failed" }, { capability: cap(o, "verification_worker", id, "verifier-1") }, FP);
      addFinding(db, store, id, { severity: "blocking", title: "tests fail on login", evidence: { kind: "check", checkId: "tests" }, reproduction: "run the suite and see login fail" }, reviewer, FP, () => null);
      startRepair(db, id, APPROVER, { maxIterations: 1 });
      recordIteration(db, store, id, { operator: APPROVER }, { iterationKey: "a", tokens: 1, costMicro: 1, elapsedMs: 1, failureSignature: "tests" });
      expect(recordIteration(db, store, id, { operator: APPROVER }, { iterationKey: "b", tokens: 1, costMicro: 1, elapsedMs: 1, failureSignature: "tests" }, new Date(Date.now() + 5000)).allowed).toBe(false); // budget exhausted: BLOCKED
      expect(getTask(db, id).state).toBe("BLOCKED");
      const handoff = createTaskHandoff(db, store, id, REQUESTER, FP);
      const resumed = resumeFromHandoff(db, store, handoff, id, FP);
      expect(resumed).toMatchObject({ state: "BLOCKED", handoffStanding: "current" });
      expect(resumed.openFindings.map((f) => f.title)).toEqual(["tests fail on login"]);
      expect(resumed.pendingChecks).toContain("tests");
      expect(() => resumeFromHandoff(db, store, handoff, id, fp("another-tree"))).toThrow(/source fingerprint changed|stale/);
      expect(() => createTaskHandoff(db, store, id, REQUESTER, fp("another-tree"))).toThrow(/source changed/);
      expect(() => resumeFromHandoff(db, store, handoff, "st_0000000000000000", FP)).toThrow();
      updatePolicy(store, ADMIN, { extraChecks: { A1: ["license_scan"] } });
      expect(() => resumeFromHandoff(db, store, handoff, id, FP)).toThrow(/stale|policy changed/); // the policy moved: the packet no longer describes what is allowed
      // revocation and cancellation really stop further actions
      const c = newTask(o);
      drive(o, c.task_id, "VERIFYING");
      startRepair(db, c.task_id, APPROVER);
      cancelTask(db, store, c.task_id, APPROVER, "stop");
      expect(() => recordIteration(db, store, c.task_id, { operator: APPROVER }, { iterationKey: "z", tokens: 1, costMicro: 1, elapsedMs: 1, failureSignature: "x" })).toThrow(/no further repair/);
      expect(() => addFinding(db, store, c.task_id, { severity: "advisory", title: "late finding", evidence: { kind: "check", checkId: "tests" }, reproduction: "n/a (late)" }, cap(o, "reviewer", c.task_id, "rev-1"), FP, () => null)).toThrow(/finished/);
      expect(() => authorizeWorktree(db, c.task_id, APPROVER, worktree(), w.repo)).toThrow(/CANCELLED/);
    });
  });
});

describe("S3C command line", () => {
  it("lists providers truthfully and refuses to launch an agent", async () => {
    const w = await setup();
    const providers = JSON.parse((await runCli(w.repo, ["sentinel", "providers", "--json"], w.home)).stdout) as { providers: Array<{ id: string; installed: boolean }> };
    expect(providers.providers.map((p) => p.id)).toEqual(["claude-code", "codex", "local-model"]);
    const run = await runCli(w.repo, ["sentinel", "run", "st_0000000000000000", "--scope", "src/"], w.home);
    expect(run.code).toBe(3);
    expect(run.stderr).toMatch(/does not launch any agent or model/);
    expect(run.stderr).toMatch(/authorize a throwaway worktree/);
  });
});
