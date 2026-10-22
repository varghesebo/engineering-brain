import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  addTraceLink, addVerifier, rejectEvidence, setEnvironment, checkStanding, appendEvidence, assureTask, claimTask, createTask, dequeueWork, enqueueWork, evaluateEligibility, getTask, importEvidence, invalidateEvidence, issueCapability, outcomeOfCounts, parseEvidence,
  planCampaigns, planVerification, probeCapabilities, recordFromImport, refuseRunIfUnenforceable, repositoryFingerprint, resumeInfo, signArtifact, traceabilityReport, transitionTask, type Actor, type Role
} from "@engbrain/core";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, engbrainHome, makeGitRepo, runCli } from "../helpers/env.js";
import { commitAll } from "../helpers/dag-fixture.js";
import { refresh, withStore, type Opened } from "../helpers/h1.js";

afterAll(cleanupTempDirs);

const ADMIN: Actor = { id: "alice", roles: ["propose", "approve", "verify", "admin"] };
const APPROVER: Actor = { id: "carol", roles: ["propose", "approve"] };
const CI: Actor = { id: "ci-bot", roles: ["propose"] };
const sha = (b: Buffer): string => createHash("sha256").update(b).digest("hex");
const ENV = { node: "22" };

const JUNIT_OK = (extra = ""): Buffer => Buffer.from(`<testsuite name="api" tests="${2 + (extra === "" ? 0 : 1)}"><testcase name="returns a user" file="src/api.test.ts"/><testcase name="handles empty id" file="src/api.test.ts"/>${extra}</testsuite>`);

async function world(): Promise<{ repo: string; home: string; c1: string }> {
  const repo = makeGitRepo({}, false);
  const home = engbrainHome();
  writeFileSync(join(repo, "package.json"), JSON.stringify({ name: "w" }));
  mkdirSync(join(repo, "src"), { recursive: true });
  writeFileSync(join(repo, "src/api.ts"), "export const a = 1;\n");
  writeFileSync(join(repo, "src/lazy.ts"), "export async function lazy(n: string) { return import(n); }\n");
  writeFileSync(join(repo, "src/api.test.ts"), "import { a } from \"./api\";\nit(\"returns a user\", () => { a; });\nit(\"handles empty id\", () => {});\n");
  writeFileSync(join(repo, "src/lazy.test.ts"), "import { lazy } from \"./lazy\";\nit(\"loads api at runtime\", async () => { await lazy(\"./api\"); });\n");
  const c1 = commitAll(repo, "one");
  await refresh(repo, home, { history: "backfill" }, true);
  return { repo, home, c1 };
}

const cap = (o: Opened, role: Role, taskId: string, principal: string): string => issueCapability(o.store.dir, { role, taskId, principal, ttlSeconds: 3600, issuer: ADMIN, epoch: getTask(o.store.db, taskId).cap_epoch });

function newTask(o: Opened, profile: "A1" | "A3" = "A1", requirements: string[] = []) {
  const db = o.store.db;
  const base = (db.prepare("SELECT processed_oid AS oid FROM history_checkpoints WHERE ref_key = 'HEAD'").get() as { oid: string }).oid;
  return createTask(db, o.store.dir, { title: "Verify the api", requester: CI, profile, scope: ["src/"], requirements, sourceFingerprint: repositoryFingerprint(db), baseRevision: base });
}
/** Drives a task into VERIFYING (builder `builder-1`, plan approved by `carol`). */
function toVerifying(o: Opened, id: string): void {
  const { db, dir } = o.store;
  const fp = repositoryFingerprint(db);
  const T = (to: Parameters<typeof transitionTask>[3], who: Parameters<typeof transitionTask>[4]) => transitionTask(db, dir, id, to, who, to === "CONTEXT_READY" ? { sourceFingerprint: fp } : {});
  T("CONTEXT_READY", { capability: cap(o, "architect", id, "arch") });
  T("SPECIFICATION_READY", { capability: cap(o, "architect", id, "arch") });
  T("PLAN_APPROVED", { operator: APPROVER });
  T("IMPLEMENTING", { capability: cap(o, "builder", id, "builder-1") });
  T("IMPLEMENTED", { capability: cap(o, "builder", id, "builder-1") });
  T("VERIFYING", { capability: cap(o, "verification_worker", id, "verifier-1") });
}
/** Imports a signed artifact bound to the current checkpoint revision and returns its import id. */
function signedImport(o: Opened, data: Buffer, name: string, format: "junit" | "pytest" | "vitest" | "playwright" = "junit", env: Record<string, string> = ENV): string {
  const db = o.store.db;
  const revision = (db.prepare("SELECT processed_oid AS oid FROM history_checkpoints WHERE ref_key = 'HEAD'").get() as { oid: string }).oid;
  const key = (JSON.parse(JSONFILE(o)) as { verifiers: Array<{ id: string; keyHex: string }> }).verifiers.find((v) => v.id === "ci-main")?.keyHex ?? addVerifier(o.store.dir, { id: "ci-main", actor: ADMIN }).keyHex;
  const claim = { format, revision, command: "npm test", environment: env, verifier: "ci-main" } as const;
  return importEvidence(db, o.store.dir, { format, data, artifactName: name, revision, command: "npm test", environment: env, verifier: "ci-main", signature: signArtifact(key, data, claim) }, { actor: CI }).import_id;
}
function JSONFILE(o: Opened): string {
  try {
    return require("node:fs").readFileSync(join(o.store.dir, "evidence-policy.json"), "utf8");
  } catch {
    return JSON.stringify({ verifiers: [] });
  }
}

describe("S3B outcomes: a failing, timed-out, skipped or empty result is never green", () => {
  it("maps counts to one honest outcome", () => {
    const base = { total: 3, passed: 3, failed: 0, skipped: 0, timedOut: 0, errors: 0, partial: false };
    expect(outcomeOfCounts(base).outcome).toBe("passed");
    expect(outcomeOfCounts({ ...base, passed: 2, failed: 1 }).outcome).toBe("failed");
    expect(outcomeOfCounts({ ...base, passed: 2, errors: 1 }).outcome).toBe("failed");
    expect(outcomeOfCounts({ ...base, passed: 2, timedOut: 1 }).outcome).toBe("timed_out");
    expect(outcomeOfCounts({ ...base, passed: 2, skipped: 1 }).outcome).toBe("skipped");
    expect(outcomeOfCounts({ ...base, passed: 2, skipped: 1 }, 1).outcome).toBe("passed"); // only when policy explicitly allows
    expect(outcomeOfCounts({ ...base, passed: 0, skipped: 3 }).outcome).toBe("skipped");
    expect(outcomeOfCounts({ ...base, total: 0, passed: 0 }).outcome).toBe("not_run");
    expect(outcomeOfCounts({ ...base, partial: true }).outcome).toBe("incomplete");
  });

  it("a failing assertion, a timeout, a skipped and an empty suite each fail to satisfy a mandatory check", async () => {
    const w = await world();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const fp = repositoryFingerprint(db);
      const cases: Array<[string, Buffer, string]> = [
        ["failing assertion", JUNIT_OK(`<testcase name="broken" file="src/api.test.ts"><failure message="expected 1 to be 2"/></testcase>`), "failed"],
        ["timeout", JUNIT_OK(`<testcase name="slow" file="src/api.test.ts"><error type="TimeoutError" message="timed out after 5000ms"/></testcase>`), "failed"],
        ["skipped test", JUNIT_OK(`<testcase name="later" file="src/api.test.ts"><skipped/></testcase>`), "skipped"],
        ["empty suite", Buffer.from(`<testsuite name="api" tests="0"></testsuite>`), "not_run"]
      ];
      cases.forEach(([label, data, expected], i) => {
        const t = newTask(o);
        toVerifying(o, t.task_id);
        const id = signedImport(o, data, `case${i}.xml`);
        const verdict = recordFromImport(db, dir, t.task_id, "tests", id, { capability: cap(o, "verification_worker", t.task_id, "verifier-1") }, fp);
        expect(verdict.outcome, label).toBe(expected === "failed" && label === "timeout" ? "timed_out" : expected);
        const e = evaluateEligibility(db, dir, t.task_id, fp);
        expect(e.checksPassing, label).toBe(false);
        expect(e.blockers.join(" "), label).toMatch(/tests: (failed|timed_out|skipped|not_run)/);
      });
    });
  });
});

describe("S3B campaigns", () => {
  it("an empty pass is NOT_RUN, never PASSED; a pass passes only when every check it requires has current passing evidence", async () => {
    const w = await world();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const fp = repositoryFingerprint(db);
      const t = newTask(o, "A3");
      toVerifying(o, t.task_id);
      const status = () => Object.fromEntries(planCampaigns(db, dir, t.task_id, fp).map((c) => [c.passClass, c.status]));
      expect(status()).toEqual({ FUNCTIONAL: "NOT_RUN", ADVERSARIAL: "NOT_RUN", SYSTEM_ASSURANCE: "NOT_RUN" });
      const worker = cap(o, "verification_worker", t.task_id, "verifier-1");
      for (const check of ["scope", "lint", "typecheck"]) {
        appendEvidence(db, dir, t.task_id, { origin: "machine", kind: "check_result", checkId: check, outcome: "passed", environment: ENV }, { capability: worker }, fp);
      }
      expect(status().FUNCTIONAL).toBe("INCOMPLETE"); // `tests` still has no evidence
      recordFromImport(db, dir, t.task_id, "tests", signedImport(o, JUNIT_OK(), "ok.xml"), { capability: worker }, fp);
      expect(status()).toEqual({ FUNCTIONAL: "PASSED", ADVERSARIAL: "NOT_RUN", SYSTEM_ASSURANCE: "NOT_RUN" }); // one passing pass does not make the others pass
      appendEvidence(db, dir, t.task_id, { origin: "machine", kind: "check_result", checkId: "adversarial_review", outcome: "failed" }, { capability: cap(o, "adversarial_reviewer", t.task_id, "red-team") }, fp);
      expect(status().ADVERSARIAL).toBe("FAILED");
    });
  });

  it("evidence is invalidated when the environment changes, and says so explicitly", async () => {
    const w = await world();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const fp = repositoryFingerprint(db);
      const t = newTask(o);
      toVerifying(o, t.task_id);
      const worker = cap(o, "verification_worker", t.task_id, "verifier-1");
      recordFromImport(db, dir, t.task_id, "tests", signedImport(o, JUNIT_OK(), "ok.xml"), { capability: worker }, fp);
      expect(planCampaigns(db, dir, t.task_id, fp, { environment: ENV }).find((c) => c.passClass === "FUNCTIONAL")!.checks.find((c) => c.checkId === "tests")!.state).toBe("current");
      const changed = { node: "24" };
      expect(evaluateEligibility(db, dir, t.task_id, fp, undefined, changed).blockers.join(" ")).toMatch(/tests: evidence is stale \(the environment/);
      expect(invalidateEvidence(db, dir, t.task_id, { capability: worker }, fp, { environment: changed })).toEqual(["tests"]);
      expect(planCampaigns(db, dir, t.task_id, fp, { environment: changed }).find((c) => c.passClass === "FUNCTIONAL")!.checks.find((c) => c.checkId === "tests")).toMatchObject({ outcome: "invalidated" });
      expect(db.prepare("SELECT outcome FROM sentinel_evidence WHERE check_id = 'tests' ORDER BY seq").all()).toEqual([{ outcome: "passed" }, { outcome: "invalidated" }]); // history stays
    });
  });
});

describe("S3B trust and binding", () => {
  it("a quarantined, forged or wrong-revision artifact cannot back a check; code modified after the run cannot approve a changed artifact", async () => {
    const w = await world();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const fp = repositoryFingerprint(db);
      const t = newTask(o);
      toVerifying(o, t.task_id);
      const worker = cap(o, "verification_worker", t.task_id, "verifier-1");
      const revision = (db.prepare("SELECT processed_oid AS oid FROM history_checkpoints WHERE ref_key = 'HEAD'").get() as { oid: string }).oid;
      // unsigned: quarantined
      const unsigned = importEvidence(db, dir, { format: "junit", data: JUNIT_OK(), artifactName: "u.xml", revision, command: "npm test", environment: ENV, verifier: "ci-main" }, { actor: CI });
      expect(unsigned.trust).toBe("quarantined");
      expect(() => recordFromImport(db, dir, t.task_id, "tests", unsigned.import_id, { capability: worker }, fp)).toThrow(/quarantined artifact is a claim/);
      // a genuine signature over DIFFERENT bytes (an edited artifact) is invalid and quarantined
      const key = addVerifier(dir, { id: "ci-main", actor: ADMIN });
      const original = JUNIT_OK();
      const edited = Buffer.from(original.toString("utf8").replace("returns a user", "returns a USER"));
      const forged = importEvidence(db, dir, { format: "junit", data: edited, artifactName: "e.xml", revision, command: "npm test", environment: ENV, verifier: "ci-main", signature: signArtifact(key.keyHex, original, { format: "junit", revision, command: "npm test", environment: ENV, verifier: "ci-main" }) }, { actor: CI });
      expect([forged.signature_status, forged.trust]).toEqual(["invalid", "quarantined"]);
      expect(() => recordFromImport(db, dir, t.task_id, "tests", forged.import_id, { capability: worker }, fp)).toThrow(/quarantined/);
      // a quarantined import cannot be accepted when its signature was invalid
      // (covered in H4); a valid import of the CURRENT code backs the check
      const good = signedImport(o, JUNIT_OK(), "good.xml");
      expect(recordFromImport(db, dir, t.task_id, "tests", good, { capability: worker }, fp).outcome).toBe("passed");
      void sha;
    });
    // the code changes after the run: the evidence no longer stands and a run of the OLD revision cannot back a check of the NEW code
    let oldImport = "";
    await withStore(w.repo, w.home, (o) => { oldImport = (o.store.db.prepare("SELECT import_id AS id FROM evidence_imports WHERE trust = 'signed' LIMIT 1").get() as { id: string }).id; });
    writeFileSync(join(w.repo, "src/api.ts"), "export const a = 2;\n");
    commitAll(w.repo, "change after the run");
    await refresh(w.repo, w.home, { history: "backfill" });
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const t2 = newTask(o);
      toVerifying(o, t2.task_id);
      expect(() => recordFromImport(db, dir, t2.task_id, "tests", oldImport, { capability: cap(o, "verification_worker", t2.task_id, "verifier-1") }, repositoryFingerprint(db))).toThrow(/not made on the code|no longer applies/);
    });
  });
});

describe("S3B adapters", () => {
  it("parses Playwright, vitest and pytest output, and never reads a flaky or interrupted run as green", () => {
    const pw = JSON.stringify({ suites: [{ title: "login", file: "e2e/login.spec.ts", specs: [
      { title: "signs in", file: "e2e/login.spec.ts", tests: [{ status: "expected", results: [{ status: "passed", duration: 10 }] }] },
      { title: "signs out", file: "e2e/login.spec.ts", tests: [{ status: "flaky", results: [{ status: "failed" }, { status: "passed" }] }] },
      { title: "slow", file: "e2e/login.spec.ts", tests: [{ status: "unexpected", results: [{ status: "timedOut" }] }] },
      { title: "cut", file: "e2e/login.spec.ts", tests: [{ status: "unexpected", results: [{ status: "interrupted" }] }] }
    ] }] });
    const n = parseEvidence("playwright", pw);
    expect(n.results.map((r) => r.outcome)).toEqual(["passed", "failed", "timed_out", "error"]);
    expect(n.partial).toBe(true);
    expect(() => parseEvidence("playwright", "{not json")).toThrow();
    expect(() => parseEvidence("playwright", JSON.stringify({ nope: 1 }))).toThrow(/Playwright/);
    const vt = parseEvidence("vitest", JSON.stringify({ numFailedTestSuites: 0, testResults: [{ name: "src/a.test.ts", status: "passed", assertionResults: [{ title: "x", status: "passed" }] }] }));
    expect([vt.format, vt.results[0]!.outcome]).toEqual(["vitest", "passed"]);
    const py = parseEvidence("pytest", `<testsuites><testsuite name="pytest" tests="1"><testcase classname="tests.test_a" name="test_x" file="tests/test_a.py"/></testsuite></testsuites>`);
    expect([py.format, py.results[0]!.file]).toEqual(["pytest", "tests/test_a.py"]);
    expect(() => parseEvidence("pytest", "<!DOCTYPE x [<!ENTITY a \"b\">]><testsuite/>")).toThrow();
  });
});

describe("S3B traceability, selection and run enforcement", () => {
  it("links requirement -> behavior -> test -> evidence and reports what is not covered", async () => {
    const w = await world();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const fp = repositoryFingerprint(db);
      const t = newTask(o, "A1", ["users can be fetched", "an empty id is rejected", "audit trail is written"]);
      toVerifying(o, t.task_id);
      addTraceLink(db, t.task_id, { requirementIx: 0, behavior: "fetchUser returns a user", testPath: "src/api.test.ts", testName: "returns a user", checkId: "tests" }, "arch");
      addTraceLink(db, t.task_id, { requirementIx: 1, behavior: "empty id handled", testPath: "src/api.test.ts", testName: "no such test", checkId: "tests" }, "arch");
      expect(() => addTraceLink(db, t.task_id, { requirementIx: 9, behavior: "x", testPath: "src/api.test.ts", checkId: "tests" }, "arch")).toThrow(/requirementIx/);
      expect(() => addTraceLink(db, t.task_id, { requirementIx: 0, behavior: "x", testPath: "../etc/passwd", checkId: "tests" }, "arch")).toThrow(/repository-relative/);
      expect(traceabilityReport(db, dir, t.task_id, fp).requirements.map((r) => r.status)).toEqual(["unverified", "unverified", "uncovered"]); // no evidence yet
      recordFromImport(db, dir, t.task_id, "tests", signedImport(o, JUNIT_OK(), "ok.xml"), { capability: cap(o, "verification_worker", t.task_id, "verifier-1") }, fp);
      const report = traceabilityReport(db, dir, t.task_id, fp);
      expect(report.requirements.map((r) => r.status)).toEqual(["verified", "unverified", "uncovered"]); // a link to a test absent from the evidence is NOT verified
      expect(report.requirements[1]!.links[0]!.result).toBe("not_in_evidence");
      expect(report.missingCoverage).toHaveLength(2);
    });
  });

  it("explains test selection (proof, unknown areas) and keeps a hidden dynamic dependency through the policy sample; the dry run runs nothing", async () => {
    const w = await world();
    writeFileSync(join(w.repo, "src/api.ts"), "export const a = 2;\n");
    commitAll(w.repo, "change api");
    await refresh(w.repo, w.home, { history: "backfill" });
    await withStore(w.repo, w.home, async (o) => {
      const { db, dir } = o.store;
      // the task is bound to the FIRST commit, so the change above is "since the base"
      const first = (db.prepare("SELECT commit_oid AS oid FROM git_commits ORDER BY author_time LIMIT 1").get() as { oid: string }).oid;
      const t = createTask(db, dir, { title: "t", requester: CI, profile: "A3", scope: ["src/"], sourceFingerprint: repositoryFingerprint(db), baseRevision: first });
      const sandbox = (await probeCapabilities()).result;
      const plan = planVerification(db, dir, t.task_id, repositoryFingerprint(db), sandbox);
      const selected = plan.selection!.selected.map((s) => s.path);
      expect(selected).toContain("src/api.test.ts");
      expect(selected).not.toContain("src/lazy.test.ts"); // the dynamic dependency is invisible to static edges...
      expect(plan.selection!.sample.map((s) => s.path)).toContain("src/lazy.test.ts"); // ...and policy A3's sample keeps it
      expect(plan.explanation.join(" ")).toMatch(/policy A3 adds a sample/);
      expect(plan.campaigns.every((c) => c.status === "NOT_RUN")).toBe(true);
    });
  });

  it("running repository tests fails closed without full OS enforcement; the dry run, explain and import paths stay available", async () => {
    const w = await world();
    const boot = await runCli(w.repo, ["memory", "operator", "add", "root", "--roles", "propose,approve,verify,admin", "--yes", "--json"], w.home);
    const env = { ENGBRAIN_OPERATOR: "root", ENGBRAIN_OPERATOR_TOKEN: (JSON.parse(boot.stdout) as { token: string }).token };
    await runCli(w.repo, ["refresh", "--history=backfill"], w.home);
    const sandbox = (await probeCapabilities()).result;
    expect(() => refuseRunIfUnenforceable(sandbox)).toThrow(/network egress denial|CPU, memory/);
    expect(() => refuseRunIfUnenforceable({ verified: false, detail: "none", checks: [] })).toThrow(/file-write confinement/);
    const made = JSON.parse((await runCli(w.repo, ["sentinel", "plan", "--title", "Verify api", "--scope", "src/", "--profile", "A2", "--json"], w.home, env)).stdout) as { id: string };
    const dry = await runCli(w.repo, ["sentinel", "verify", made.id, "--dry-run", "--json"], w.home);
    expect(dry.code).toBe(0);
    expect(dry.stdout).toMatch(/"permitted": false/);
    expect((await runCli(w.repo, ["sentinel", "verify", made.id, "--explain"], w.home)).stdout).toMatch(/no repository code was run/);
    const run = await runCli(w.repo, ["sentinel", "verify", made.id, "--run"], w.home, env);
    expect(run.code).toBe(3); // refused
    expect(run.stderr).toMatch(/cannot enforce/);
    expect((await runCli(w.repo, ["sentinel", "verify", made.id, "--run"], w.home)).code).toBe(3); // and an unauthenticated caller is refused first
    expect((await runCli(w.repo, ["sentinel", "trace", made.id], w.home)).code).toBe(0);
  });
});

describe("S3B parallel and interrupted verification", () => {
  it("two workers never take the same queued item, an interrupted worker's item is re-queued after its lease expires, and approvals cannot duplicate", async () => {
    const w = await world();
    let id = "";
    await withStore(w.repo, w.home, (o) => {
      id = newTask(o).task_id;
      enqueueWork(o.store.db, id, "campaign:FUNCTIONAL");
      enqueueWork(o.store.db, id, "campaign:ADVERSARIAL");
      claimTask(o.store.db, id, "worker-a", 1);
    });
    const taken: number[] = [];
    await Promise.all([0, 1].map(() => withStore(w.repo, w.home, (o) => { const item = dequeueWork(o.store.db); if (item !== null) { taken.push(item.itemId); } })));
    expect(new Set(taken).size).toBe(2); // each got a distinct item; none twice
    await withStore(w.repo, w.home, async (o) => {
      expect(dequeueWork(o.store.db)).toBeNull();
      await new Promise((r) => setTimeout(r, 1500)); // worker-a died: its one-second lease expires
      expect(resumeInfo(o.store.db, id).requeued).toBe(2);
      expect(dequeueWork(o.store.db)).not.toBeNull(); // the work is not lost
      expect(() => assureTask(o.store.db, o.store.dir, id, cap(o, "assurance_controller", id, "assurance-1"), repositoryFingerprint(o.store.db))).toThrow(/ASSURANCE_REVIEW/); // and nothing is approved by recovery
    });
  });
});

describe("S3B independent-review regressions", () => {
  it("an import backs only a test-backed check of a fitting format, only once; scope and review checks can never be import-backed", async () => {
    const w = await world();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const fp = repositoryFingerprint(db);
      const t = newTask(o, "A3");
      toVerifying(o, t.task_id);
      const worker = cap(o, "verification_worker", t.task_id, "verifier-1");
      const id = signedImport(o, JUNIT_OK(), "one.xml");
      for (const check of ["scope", "build", "reproducible_build", "independent_review", "adversarial_review", "dependency_review", "security_review"]) {
        expect(() => recordFromImport(db, dir, t.task_id, check, id, { capability: worker }, fp), check).toThrow(/cannot be backed by an imported artifact/);
      }
      const vitest = signedImport(o, Buffer.from(JSON.stringify({ numTotalTests: 1, numFailedTests: 0, numFailedTestSuites: 0, testResults: [{ name: "src/api.test.ts", status: "passed", assertionResults: [{ title: "x", status: "passed" }] }] })), "v.json", "vitest");
      expect(() => recordFromImport(db, dir, t.task_id, "fuzz", vitest, { capability: worker }, fp)).toThrow(/cannot back fuzz/); // a unit-test artifact is not a fuzz run
      expect(() => recordFromImport(db, dir, t.task_id, "lint", id, { capability: worker }, fp)).toThrow(/cannot back lint/); // a junit file is not a lint report
      expect(recordFromImport(db, dir, t.task_id, "tests", id, { capability: worker }, fp).outcome).toBe("passed");
      expect(() => recordFromImport(db, dir, t.task_id, "unit_tests", id, { capability: worker }, fp)).toThrow(/already recorded for tests/); // one artifact, one check
    });
  });

  it("traceability needs the check itself to be passing; evidence dies when its import is rejected or the declared environment moves", async () => {
    const w = await world();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const fp = repositoryFingerprint(db);
      const t = newTask(o, "A1", ["users can be fetched"]);
      toVerifying(o, t.task_id);
      addTraceLink(db, t.task_id, { requirementIx: 0, behavior: "fetch", testPath: "src/api.test.ts", testName: "returns a user", checkId: "tests" }, "arch");
      expect(() => addTraceLink(db, t.task_id, { requirementIx: 0, behavior: "x", testPath: "src/api.test.ts", checkId: "scope" }, "arch")).toThrow(/test-backed check/);
      // test A passed but test B failed in the same import: the CHECK failed, so the requirement is not verified
      const mixed = signedImport(o, JUNIT_OK(`<testcase name="broken" file="src/api.test.ts"><failure message="no"/></testcase>`), "mixed.xml");
      const worker = cap(o, "verification_worker", t.task_id, "verifier-1");
      expect(recordFromImport(db, dir, t.task_id, "tests", mixed, { capability: worker }, fp).outcome).toBe("failed");
      expect(traceabilityReport(db, dir, t.task_id, fp).requirements[0]!.status).not.toBe("verified");
      // a passing run, later rejected by an operator, no longer stands
      const t2 = newTask(o, "A1", ["users can be fetched"]);
      toVerifying(o, t2.task_id);
      const good = signedImport(o, JUNIT_OK(`<testcase name="extra" file="src/api.test.ts"/>`), "good.xml");
      const w2 = cap(o, "verification_worker", t2.task_id, "verifier-1");
      recordFromImport(db, dir, t2.task_id, "tests", good, { capability: w2 }, fp);
      expect(checkStanding(db, dir, t2.task_id, "tests", fp)).toMatchObject({ state: "current", outcome: "passed" });
      rejectEvidence(db, good, { actor: ADMIN });
      expect(checkStanding(db, dir, t2.task_id, "tests", fp)).toMatchObject({ state: "stale" });
      expect(checkStanding(db, dir, t2.task_id, "tests", fp).blocker).toMatch(/import behind this evidence no longer applies/);
      // the store's environment assumption changes after the run: stale without anyone passing an environment
      const t3 = newTask(o, "A1");
      toVerifying(o, t3.task_id);
      const envRun = signedImport(o, JUNIT_OK(`<testcase name="env" file="src/api.test.ts"/>`), "env.xml");
      recordFromImport(db, dir, t3.task_id, "tests", envRun, { capability: cap(o, "verification_worker", t3.task_id, "verifier-1") }, fp);
      setEnvironment(db, "node", "22", { actor: ADMIN });
      expect(checkStanding(db, dir, t3.task_id, "tests", fp).state).toBe("current");
      setEnvironment(db, "node", "24", { actor: ADMIN });
      expect(checkStanding(db, dir, t3.task_id, "tests", fp).state).toBe("environment_changed");
    });
  });

  it("every selected test must be in the run, or the check is incomplete", async () => {
    const w = await world();
    writeFileSync(join(w.repo, "src/api.ts"), "export const a = 2;\n");
    commitAll(w.repo, "change api");
    await refresh(w.repo, w.home, { history: "backfill" });
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const first = (db.prepare("SELECT commit_oid AS oid FROM git_commits ORDER BY author_time LIMIT 1").get() as { oid: string }).oid;
      const t = createTask(db, dir, { title: "t", requester: CI, profile: "A1", scope: ["src/"], sourceFingerprint: repositoryFingerprint(db), baseRevision: first });
      toVerifying(o, t.task_id);
      const onlyLazy = Buffer.from(`<testsuite name="s" tests="1"><testcase name="loads api at runtime" file="src/lazy.test.ts"/></testsuite>`);
      const verdict = recordFromImport(db, dir, t.task_id, "tests", signedImport(o, onlyLazy, "lazy.xml"), { capability: cap(o, "verification_worker", t.task_id, "verifier-1") }, repositoryFingerprint(db));
      expect(verdict.outcome).toBe("incomplete");
      expect(verdict.reasons.join(" ")).toMatch(/selected tests are not in the run: src\/api.test.ts/);
    });
  });

  it("report-level errors and totals that disagree with the listed results mark an artifact partial; a failure is never hidden behind a skip", () => {
    const pw = (extra: object) => JSON.stringify({ suites: [{ title: "s", file: "e.spec.ts", specs: [{ title: "ok", file: "e.spec.ts", tests: [{ status: "expected", results: [{ status: "passed" }] }] }] }], ...extra });
    expect(parseEvidence("playwright", pw({})).partial).toBe(false);
    expect(parseEvidence("playwright", pw({ errors: [{ message: "global setup failed" }] })).partial).toBe(true);
    expect(parseEvidence("playwright", pw({ stats: { unexpected: 2 } })).partial).toBe(true);
    const jest = (extra: object) => JSON.stringify({ numFailedTestSuites: 0, testResults: [{ name: "a.test.ts", status: "passed", assertionResults: [{ title: "x", status: "passed" }] }], ...extra });
    expect(parseEvidence("jest", jest({ numTotalTests: 1, numFailedTests: 0 })).partial).toBe(false);
    expect(parseEvidence("jest", jest({ numTotalTests: 5 })).partial).toBe(true);
    expect(parseEvidence("jest", jest({ numFailedTests: 3 })).partial).toBe(true);
    expect(parseEvidence("junit", `<testsuite name="s"><testcase name="a"><failure message="x"/><skipped/></testcase></testsuite>`).results[0]!.outcome).toBe("failed");
  });
});
