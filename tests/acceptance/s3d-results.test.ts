import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  addVerifier, appendEvidence, assuranceDetail, createTask, decideEquivalent, evaluateEligibility, getTask, importEvidence, issueCapability, planCampaigns, proposeMemoryCandidate, recordFormalResult,
  recordFromImport, recordMutationRun, recordRepro, recordUnsupported, repositoryFingerprint, signArtifact, transitionTask, updatePolicy, type Actor, type EvidenceFormat, type Role
} from "@engbrain/core";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, engbrainHome, makeGitRepo } from "../helpers/env.js";
import { commitAll } from "../helpers/dag-fixture.js";
import { refresh, withStore, type Opened } from "../helpers/h1.js";

afterAll(cleanupTempDirs);

const ADMIN: Actor = { id: "alice", roles: ["propose", "approve", "verify", "admin"] };
const APPROVER: Actor = { id: "carol", roles: ["propose", "approve"] };
const CI: Actor = { id: "ci-bot", roles: ["propose"] };
const ENV = { node: "22" };
const MODEL_SHA = "a".repeat(64);
const json = (v: unknown): Buffer => Buffer.from(JSON.stringify(v));

async function world(extraChecks: string[] = []): Promise<{ repo: string; home: string }> {
  const repo = makeGitRepo({}, false);
  const home = engbrainHome();
  writeFileSync(join(repo, "package.json"), JSON.stringify({ name: "w" }));
  mkdirSync(join(repo, "src"), { recursive: true });
  writeFileSync(join(repo, "src/api.ts"), "export const a = 1;\n");
  writeFileSync(join(repo, "src/api.test.ts"), "import { a } from \"./api\";\nit(\"returns a user\", () => { a; });\n");
  commitAll(repo, "one");
  await refresh(repo, home, { history: "backfill" }, true);
  if (extraChecks.length > 0) {
    await withStore(repo, home, (o) => { updatePolicy(o.store.dir, ADMIN, { extraChecks: { A1: extraChecks } }); });
  }
  return { repo, home };
}

const cap = (o: Opened, role: Role, taskId: string, principal: string): string => issueCapability(o.store.dir, { role, taskId, principal, ttlSeconds: 3600, issuer: ADMIN, epoch: getTask(o.store.db, taskId).cap_epoch });
const head = (o: Opened): string => (o.store.db.prepare("SELECT processed_oid AS oid FROM history_checkpoints WHERE ref_key = 'HEAD'").get() as { oid: string }).oid;

/** A1 task driven into VERIFYING (builder `builder-1`, plan approved by `carol`). */
function verifyingTask(o: Opened): string {
  const { db, dir } = o.store;
  const fp = repositoryFingerprint(db);
  const id = createTask(db, dir, { title: "Harden the api", requester: CI, profile: "A1", scope: ["src/"], sourceFingerprint: fp, baseRevision: head(o) }).task_id;
  const T = (to: Parameters<typeof transitionTask>[3], who: Parameters<typeof transitionTask>[4]) => transitionTask(db, dir, id, to, who, to === "CONTEXT_READY" ? { sourceFingerprint: fp } : {});
  T("CONTEXT_READY", { capability: cap(o, "architect", id, "arch") });
  T("SPECIFICATION_READY", { capability: cap(o, "architect", id, "arch") });
  T("PLAN_APPROVED", { operator: APPROVER });
  T("IMPLEMENTING", { capability: cap(o, "builder", id, "builder-1") });
  T("IMPLEMENTED", { capability: cap(o, "builder", id, "builder-1") });
  T("VERIFYING", { capability: cap(o, "verification_worker", id, "verifier-1") });
  return id;
}

/** A signed import bound to the current checkpoint revision. */
function signedImport(o: Opened, format: EvidenceFormat, data: Buffer, name: string): string {
  const { db, dir } = o.store;
  const revision = head(o);
  let policy: { verifiers: Array<{ id: string; keyHex: string }> } = { verifiers: [] };
  try {
    policy = JSON.parse(readFileSync(join(dir, "evidence-policy.json"), "utf8")) as typeof policy;
  } catch {
    // no policy yet
  }
  const key = policy.verifiers.find((v) => v.id === "ci-main")?.keyHex ?? addVerifier(dir, { id: "ci-main", actor: ADMIN }).keyHex;
  const claim = { format, revision, command: "npm run assure", environment: ENV, verifier: "ci-main" };
  const row = importEvidence(db, dir, { format, data, artifactName: name, revision, command: "npm run assure", environment: ENV, verifier: "ci-main", signature: signArtifact(key, data, claim) }, { actor: CI });
  expect(row.trust, `${name} should import as signed`).toBe("signed");
  return row.import_id;
}

const stryker = (statuses: string[]) => json({
  schemaVersion: "1", thresholds: { high: 80, low: 60 }, framework: { name: "StrykerJS", version: "8.2.6" },
  files: { "src/api.ts": { language: "typescript", source: "export const a = 1;\n", mutants: statuses.map((status, i) => ({ id: String(i + 1), mutatorName: "ArithmeticOperator", status, location: { start: { line: 1, column: 1 }, end: { line: 1, column: 5 } } })) } }
});
const passStatus = (o: Opened, id: string, pass: string): string => planCampaigns(o.store.db, o.store.dir, id, repositoryFingerprint(o.store.db)).find((c) => c.passClass === pass)!.status;

describe("S3D mutation results", () => {
  it("a surviving mutant fails mutation_tests, the run never claims proof or 100%, and only a non-builder approver may call a mutant equivalent", async () => {
    const w = await world(["mutation_tests"]);
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const fp = repositoryFingerprint(db);
      const id = verifyingTask(o);
      const imp = signedImport(o, "stryker", stryker(["Killed", "Killed", "Killed", "Killed", "Killed", "Survived"]), "mutation.json");
      const run = recordMutationRun(db, id, imp);
      expect(run.summary).toEqual({ killed: 5, survived: 1, equivalent: 0, inconclusive: 0 });
      expect(run.scorePct).toBeLessThan(100);
      const verdict = recordFromImport(db, dir, id, "mutation_tests", imp, { capability: cap(o, "verification_worker", id, "verifier-1") }, fp);
      expect(verdict.outcome).toBe("failed");
      expect(verdict.reasons.join(" ")).toMatch(/1 mutant\(s\) survived/);
      expect(passStatus(o, id, "ADVERSARIAL")).toBe("FAILED");
      expect(db.prepare("SELECT claims_proof AS p, score_pct AS s FROM sentinel_mutation_runs WHERE run_id = ?").get(run.runId)).toMatchObject({ p: 0 });
      expect(() => db.prepare("INSERT INTO sentinel_mutation_runs (run_id, task_id, import_id, killed, survived, equivalent, inconclusive, score_pct, claims_proof, at) VALUES ('mr_x', ?, ?, 6, 0, 0, 0, 100, 1, 'now')").run(id, imp)).toThrow(/CHECK/);
      // equivalence is a human decision with a basis, never the builder's
      const key = (db.prepare("SELECT mutant_key AS k FROM sentinel_mutants WHERE run_id = ? AND status = 'survived'").get(run.runId) as { k: string }).k;
      expect(() => decideEquivalent(db, run.runId, key, { id: "builder-1", roles: ["approve"] }, "the mutated branch is unreachable for any input")).toThrow(/builder cannot approve/);
      expect(() => decideEquivalent(db, run.runId, key, CI, "the mutated branch is unreachable for any input")).toThrow(/lacks the approve role/);
      expect(() => decideEquivalent(db, run.runId, key, APPROVER, "eh")).toThrow(/basis/);
      decideEquivalent(db, run.runId, key, APPROVER, "the mutated branch is unreachable for any input");
      expect(db.prepare("SELECT status, decided_by AS by FROM sentinel_mutants WHERE run_id = ? AND mutant_key = ?").get(run.runId, key)).toEqual({ status: "equivalent", by: "carol" });
      expect(() => decideEquivalent(db, run.runId, key, APPROVER, "the mutated branch is unreachable for any input")).toThrow(/only a surviving or inconclusive/);
    });
  });

  it("all mutants killed passes with the 'not proof' reason; too few mutants is incomplete; a JUnit file cannot back mutation_tests", async () => {
    const w = await world(["mutation_tests"]);
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const fp = repositoryFingerprint(db);
      const id = verifyingTask(o);
      const worker = { capability: cap(o, "verification_worker", id, "verifier-1") };
      const junit = signedImport(o, "junit", Buffer.from(`<testsuite name="m" tests="1"><testcase name="mutants" file="src/api.test.ts"/></testsuite>`), "mutation.xml");
      expect(() => recordFromImport(db, dir, id, "mutation_tests", junit, worker, fp)).toThrow(/a junit artifact cannot back mutation_tests/);
      const few = signedImport(o, "stryker", stryker(["Killed", "Killed"]), "few.json");
      expect(recordFromImport(db, dir, id, "mutation_tests", few, worker, fp).outcome).toBe("incomplete");
      const all = signedImport(o, "stryker", stryker(["Killed", "Killed", "Killed", "Killed", "Killed", "Killed"]), "all.json");
      const run = recordMutationRun(db, id, all);
      expect(run.scorePct).toBe(100);
      const verdict = recordFromImport(db, dir, id, "mutation_tests", all, worker, fp);
      expect(verdict.outcome).toBe("passed");
      expect(verdict.reasons).toContain("not proof: a mutation score shows test sensitivity only");
      expect((db.prepare("SELECT claims_proof AS p FROM sentinel_mutation_runs WHERE run_id = ?").get(run.runId) as { p: number }).p).toBe(0);
      expect(passStatus(o, id, "ADVERSARIAL")).toBe("PASSED");
    });
  });
});

describe("S3D formal results", () => {
  it("Z3 unsat is a scoped, model-only pass once its assumptions are recorded; a TLA+ counterexample fails", async () => {
    const w = await world(["formal_verification"]);
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const fp = repositoryFingerprint(db);
      const id = verifyingTask(o);
      const worker = { capability: cap(o, "verification_worker", id, "verifier-1") };
      const unsat = signedImport(o, "z3", json({ tool: "z3", version: "4.13.0", specVersion: "1", modelSha256: MODEL_SHA, result: "unsat" }), "ledger.smt2.json");
      expect(() => recordFormalResult(db, id, unsat, { assumptions: [], applicability: { paths: ["src/api.ts"], baseRevision: head(o) } })).toThrow(/assumptions/);
      const formal = recordFormalResult(db, id, unsat, { assumptions: ["balances are bounded by 2^31", "at most 3 concurrent writers"], applicability: { paths: ["src/api.ts"], baseRevision: head(o) } });
      expect(formal.verdict).toEqual({ outcome: "passed", reasons: ["model only: not an application-wide proof"] });
      expect(db.prepare("SELECT scope, claims_application_proof AS proof, result FROM sentinel_formal WHERE formal_id = ?").get(formal.formalId)).toEqual({ scope: "model_only", proof: 0, result: "scoped_success" });
      const verdict = recordFromImport(db, dir, id, "formal_verification", unsat, worker, fp);
      expect(verdict.outcome).toBe("passed");
      expect(verdict.reasons).toContain("model only: not an application-wide proof");
      expect(passStatus(o, id, "SYSTEM_ASSURANCE")).toBe("PASSED");

      const t2 = verifyingTask(o);
      const cex = signedImport(o, "tla", json({ tool: "tlc", version: "2.18", specVersion: "1", modelSha256: MODEL_SHA, result: "counterexample", trace: [{ balance: 10 }, { balance: -5 }] }), "ledger.tla.json");
      expect(recordFormalResult(db, t2, cex, { assumptions: ["2 accounts"], applicability: { paths: ["src/api.ts"], baseRevision: head(o) } }).verdict.outcome).toBe("failed");
      expect(recordFromImport(db, dir, t2, "formal_verification", cex, { capability: cap(o, "verification_worker", t2, "verifier-1") }, fp).outcome).toBe("failed");
      expect(passStatus(o, t2, "SYSTEM_ASSURANCE")).toBe("FAILED");
      expect(JSON.parse((db.prepare("SELECT counterexample_json AS c FROM sentinel_formal WHERE task_id = ?").get(t2) as { c: string }).c)).toEqual([{ balance: 10 }, { balance: -5 }]);

      // a model success with no recorded assumptions is not counted
      const t3 = verifyingTask(o);
      const bare = signedImport(o, "z3", json({ tool: "z3", version: "4.13.0", specVersion: "2", modelSha256: MODEL_SHA, result: "unsat" }), "bare.json");
      expect(recordFromImport(db, dir, t3, "formal_verification", bare, { capability: cap(o, "verification_worker", t3, "verifier-1") }, fp).outcome).toBe("incomplete");
    });
  });

  it("a missing solver is recorded as unsupported (not_run) and the pass is never PASSED", async () => {
    const w = await world(["formal_verification"]);
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const fp = repositoryFingerprint(db);
      const id = verifyingTask(o);
      const worker = { capability: cap(o, "verification_worker", id, "verifier-1") };
      recordUnsupported(db, dir, id, "formal_verification", worker, fp, { reason: "z3 is not installed on this machine" });
      const row = db.prepare("SELECT outcome, payload_json AS p FROM sentinel_evidence WHERE task_id = ? AND check_id = 'formal_verification'").get(id) as { outcome: string; p: string };
      expect(row.outcome).toBe("not_run");
      expect(JSON.parse(row.p)).toMatchObject({ unsupported: true, reason: "z3 is not installed on this machine" });
      expect(passStatus(o, id, "SYSTEM_ASSURANCE")).toBe("INCOMPLETE");
      expect(evaluateEligibility(db, dir, id, fp).blockers.join(" ")).toMatch(/formal_verification: not_run/);
      // even a "passed" outcome that carries the unsupported marker cannot make the pass PASSED
      appendEvidence(db, dir, id, { origin: "machine", kind: "check_result", checkId: "formal_verification", outcome: "passed", payload: { unsupported: true, reason: "stub" } }, worker, fp);
      expect(passStatus(o, id, "SYSTEM_ASSURANCE")).toBe("INCOMPLETE");
      expect(() => recordUnsupported(db, dir, id, "formal_verification", worker, fp, { adapterId: "nope", reason: "x" })).toThrow(/no such adapter/);
    });
  });
});

describe("S3D adversarial results", () => {
  it("a planted auth bypass (semgrep ERROR) fails auth_boundary_tests and blocks eligibility; security_review stays reviewer-recorded", async () => {
    const w = await world(["auth_boundary_tests"]);
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const fp = repositoryFingerprint(db);
      const id = verifyingTask(o);
      const worker = { capability: cap(o, "verification_worker", id, "verifier-1") };
      const report = signedImport(o, "semgrep_json", json({
        version: "1.80.0", errors: [],
        results: [{ check_id: "auth.missing-middleware", path: "src/api.ts", start: { line: 1, col: 1 }, end: { line: 1, col: 20 }, extra: { severity: "ERROR", message: "route handler skips the auth middleware" } }]
      }), "semgrep.json");
      expect(() => recordFromImport(db, dir, id, "security_review", report, worker, fp)).toThrow(/cannot be backed by an imported artifact/);
      const verdict = recordFromImport(db, dir, id, "auth_boundary_tests", report, worker, fp);
      expect(verdict).toMatchObject({ outcome: "failed" });
      expect(verdict.reasons.join(" ")).toMatch(/1 error-level findings/);
      const e = evaluateEligibility(db, dir, id, fp);
      expect(e.checksPassing).toBe(false);
      expect(e.blockers).toContain("auth_boundary_tests: failed");
      expect(passStatus(o, id, "ADVERSARIAL")).toBe("FAILED");
    });
  });

  it("a race log with seed 7 fails concurrency_tests and yields a reproduction holding the seed", async () => {
    const w = await world(["concurrency_tests"]);
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const fp = repositoryFingerprint(db);
      const id = verifyingTask(o);
      const imp = signedImport(o, "race_log", json({ tool: "loom", version: "0.7.2", seed: 7, schedule: ["t1: read balance", "t2: read balance", "t1: write balance", "t2: write balance"], violation: "lost update: balance decremented once" }), "race.json");
      expect(recordFromImport(db, dir, id, "concurrency_tests", imp, { capability: cap(o, "verification_worker", id, "verifier-1") }, fp).outcome).toBe("failed");
      const race = assuranceDetail(db, imp)!.race!;
      const sha = (db.prepare("SELECT artifact_sha256 AS s FROM evidence_imports WHERE import_id = ?").get(imp) as { s: string }).s;
      const reproId = recordRepro(db, id, { importId: imp, seed: race.seed, minimizedInput: race.schedule.join(" | "), shrinkSteps: null, artifactHashes: [sha], tool: { name: "loom", version: "0.7.2" }, replayHint: "LOOM_SEED=7 cargo test lost_update" });
      expect(db.prepare("SELECT seed, import_id AS imp FROM sentinel_repro WHERE repro_id = ?").get(reproId)).toEqual({ seed: "7", imp });
      expect(passStatus(o, id, "ADVERSARIAL")).toBe("FAILED");
    });
  });

  it("a shrunk property counterexample fails property_tests and yields a reproduction with its shrink steps; it is proposed to memory as a candidate only, once", async () => {
    const w = await world(["property_tests"]);
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const fp = repositoryFingerprint(db);
      const id = verifyingTask(o);
      const imp = signedImport(o, "fastcheck", json({ tool: "fast-check", version: "3.20.0", property: "transfer keeps the total", seed: 42, numRuns: 100, failed: true, counterexample: [1000, -3], shrunk: [1, -1], shrinkPath: "17:3:1:0" }), "fc.json");
      const verdict = recordFromImport(db, dir, id, "property_tests", imp, { capability: cap(o, "verification_worker", id, "verifier-1") }, fp);
      expect(verdict.outcome).toBe("failed");
      const p = assuranceDetail(db, imp)!.property!;
      expect(p.shrinkSteps).toBeGreaterThan(0);
      const sha = (db.prepare("SELECT artifact_sha256 AS s FROM evidence_imports WHERE import_id = ?").get(imp) as { s: string }).s;
      const reproId = recordRepro(db, id, { importId: imp, seed: p.seed, minimizedInput: p.shrunk, shrinkSteps: p.shrinkSteps, artifactHashes: [sha], tool: { name: "fast-check", version: "3.20.0" }, replayHint: "fc.assert(prop, { seed: 42, path: \"17:3:1:0\" })" });
      expect((db.prepare("SELECT shrink_steps AS n FROM sentinel_repro WHERE repro_id = ?").get(reproId) as { n: number }).n).toBeGreaterThan(0);
      expect(() => recordRepro(db, id, { importId: imp, seed: null, minimizedInput: null, shrinkSteps: null, artifactHashes: [], tool: { name: "fast-check" }, replayHint: null })).toThrow(/seed or a minimized input/);

      const memory = proposeMemoryCandidate(db, reproId, CI);
      expect(memory.status).toBe("candidate");
      expect(memory.approver).toBeNull();
      expect((db.prepare("SELECT memory_candidate_id AS m FROM sentinel_repro WHERE repro_id = ?").get(reproId) as { m: string }).m).toBe(memory.record_id);
      expect(() => proposeMemoryCandidate(db, reproId, CI)).toThrow(/already proposed/);
      expect(() => db.prepare("UPDATE sentinel_repro SET memory_candidate_id = 'mem_0000000000000000' WHERE repro_id = ?").run(reproId)).toThrow(/immutable/);
    });
  });
});
