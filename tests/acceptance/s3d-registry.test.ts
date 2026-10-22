import { createHash } from "node:crypto";
import { createTask, getTask, issueCapability, transitionTask, type Actor, type Role } from "@engbrain/core";
import { afterAll, describe, expect, it } from "vitest";
import { adapterStatus, registerAdapter, requireIsolation, setAdapterStatus, unsupportedTechniques } from "../../packages/core/src/sentinel/assurance/adapters.js";
import { allowTarget, assertTargetAllowed, listHypotheses, proposeHypothesis, setHypothesisStatus } from "../../packages/core/src/sentinel/assurance/hypotheses.js";
import { approveInvariant, candidateTestsFor, listInvariants } from "../../packages/core/src/sentinel/assurance/invariants.js";
import { consumeQuota, remainingQuota, setQuota } from "../../packages/core/src/sentinel/assurance/quotas.js";
import { cleanupTempDirs, engbrainHome, makeGitRepo } from "../helpers/env.js";
import { withStore, type Opened } from "../helpers/h1.js";

afterAll(cleanupTempDirs);

const ADMIN: Actor = { id: "alice", roles: ["propose", "approve", "verify", "admin"] };
const APPROVER: Actor = { id: "carol", roles: ["propose", "approve"] };
const REQUESTER: Actor = { id: "req", roles: ["propose"] };
const FP = createHash("sha256").update("tree-v1").digest("hex");
const VERIFIED = { verified: true, detail: "probe passed", checks: [] };
const UNVERIFIED = { verified: false, detail: "sandbox-exec is not available on this platform", checks: [] };

async function setup(): Promise<{ repo: string; home: string }> {
  const repo = makeGitRepo({ "a.ts": "export const a = 1;\n" });
  const home = engbrainHome();
  await withStore(repo, home, () => undefined, true);
  return { repo, home };
}
const cap = (o: Opened, role: Role, taskId: string, principal: string): string => issueCapability(o.store.dir, { role, taskId, principal, ttlSeconds: 3600, issuer: ADMIN, epoch: getTask(o.store.db, taskId).cap_epoch });

/** A task driven to IMPLEMENTING: `arch` acted as architect, `carol` approved the plan, `builder-1` is the builder. */
function implementingTask(o: Opened): string {
  const { db, dir } = o.store;
  const id = createTask(db, dir, { title: "Ledger transfers", requester: REQUESTER, profile: "A1", scope: ["src/ledger/"], sourceFingerprint: FP }).task_id;
  transitionTask(db, dir, id, "CONTEXT_READY", { capability: cap(o, "architect", id, "arch") });
  transitionTask(db, dir, id, "SPECIFICATION_READY", { capability: cap(o, "architect", id, "arch") });
  transitionTask(db, dir, id, "PLAN_APPROVED", { operator: APPROVER });
  transitionTask(db, dir, id, "IMPLEMENTING", { capability: cap(o, "builder", id, "builder-1") });
  return id;
}

describe("S3D adapter registry: unsupported techniques stay visible, isolation and egress are enforced", () => {
  it("reports unregistered and unsupported techniques and refuses unverified isolation or network access", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db } = o.store;
      // nothing registered: every technique is visibly unregistered
      expect(unsupportedTechniques(db, "linux").map((t) => t.state)).toEqual(Array(9).fill("unregistered"));
      expect(() => registerAdapter(db, APPROVER, { technique: "property", tool: "fast-check", version: "3.0.0", license: "MIT", platforms: ["linux"], isolation: "sandbox", needsNetwork: false })).toThrow(/admin/);
      const fc = registerAdapter(db, ADMIN, { technique: "property", tool: "fast-check", version: "3.0.0", license: "MIT", platforms: ["linux", "darwin"], isolation: "sandbox", needsNetwork: false });
      const stryker = registerAdapter(db, ADMIN, { technique: "mutation", tool: "stryker", version: "8.0.0", license: "Apache-2.0", platforms: ["linux"], isolation: "container", needsNetwork: false });
      registerAdapter(db, ADMIN, { technique: "formal", tool: "tlc", version: "2.18", license: "MIT", platforms: ["linux"], isolation: "vm", needsNetwork: false, status: "unsupported", reason: "no JVM in the sandbox" });
      const scanner = registerAdapter(db, ADMIN, { technique: "supply_chain", tool: "osv-scanner", version: "1.0.0", license: "Apache-2.0", platforms: ["darwin"], isolation: "sandbox", needsNetwork: true });
      expect(() => registerAdapter(db, ADMIN, { technique: "fuzz", tool: "x", version: "1", license: "MIT", platforms: ["linux"], isolation: "none", needsNetwork: false, status: "disabled" })).toThrow(/say why/);

      expect(adapterStatus(db, "property", "darwin")).toMatchObject({ state: "available", adapter: { tool: "fast-check" } });
      expect(adapterStatus(db, "mutation", "darwin")).toMatchObject({ state: "unsupported", adapter: null });
      expect(adapterStatus(db, "formal", "linux")).toMatchObject({ state: "unsupported", reason: expect.stringMatching(/no JVM/) });
      expect(adapterStatus(db, "fuzz", "linux")).toMatchObject({ state: "unregistered", adapter: null });
      const gaps = unsupportedTechniques(db, "darwin");
      expect(gaps.map((g) => g.technique)).toEqual(["mutation", "fuzz", "race", "fault_injection", "sast", "auth_boundary", "formal"]);
      expect(gaps.find((g) => g.technique === "mutation")!.state).toBe("unsupported");
      expect(gaps.find((g) => g.technique === "sast")!.state).toBe("unregistered");

      // isolation that is not verified is refused; verified isolation passes; network access is always refused
      expect(() => requireIsolation(fc, UNVERIFIED)).toThrow(/sandbox isolation and it is not verified/);
      expect(() => requireIsolation(stryker, UNVERIFIED)).toThrow(/container isolation/);
      expect(() => requireIsolation(fc, VERIFIED)).not.toThrow();
      expect(() => requireIsolation(scanner, VERIFIED)).toThrow(/no egress/);
      // a disabled adapter drops out and is refused
      const disabled = setAdapterStatus(db, ADMIN, fc.adapter_id, "disabled", "licence review pending");
      expect(adapterStatus(db, "property", "darwin").state).toBe("unsupported");
      expect(() => requireIsolation(disabled, VERIFIED)).toThrow(/disabled/);
      expect(() => setAdapterStatus(db, ADMIN, fc.adapter_id, "unsupported", "")).toThrow(/say why/);
      // identity is immutable in the store itself
      expect(() => db.prepare("UPDATE sentinel_adapters SET needs_network = 0 WHERE adapter_id = ?").run(scanner.adapter_id)).toThrow(/immutable/);
    });
  });
});

describe("S3D targets and hypotheses: only allowlisted local targets", () => {
  it("refuses external targets, requires an allowlisted target and enforces legal status moves", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const id = implementingTask(o);
      for (const bad of ["https://example.com/api", "10.0.0.1", "/etc", "/etc/passwd", "example.com/x", "localhost:8080", "~/secrets", "../outside", "fixtures/../../etc", "fixtures\\x"]) {
        expect(() => allowTarget(db, id, bad, "fixture", APPROVER), bad).toThrow(/repository fixture or a local process/);
        expect(() => assertTargetAllowed(db, id, bad), bad).toThrow(/repository fixture or a local process/);
      }
      expect(() => allowTarget(db, id, "fixtures/ledger.json", "fixture", { id: "builder-1", roles: ["approve"] })).toThrow(/builder cannot/);
      expect(() => allowTarget(db, id, "fixtures/ledger.json", "fixture", { id: "arch", roles: ["approve"] })).toThrow(/agent role/);
      expect(() => allowTarget(db, id, "fixtures/ledger.json", "fixture", REQUESTER)).toThrow(/approve role/);
      expect(allowTarget(db, id, "fixtures/ledger.json", "fixture", APPROVER)).toMatchObject({ target: "fixtures/ledger.json" });
      allowTarget(db, id, "ledger-worker", "local_process", APPROVER);
      expect(assertTargetAllowed(db, id, "ledger-worker")).toBe("local_process");
      expect(() => assertTargetAllowed(db, id, "fixtures/other.json")).toThrow(/not on this task's allowlist/);
      expect(() => db.prepare("UPDATE sentinel_target_allowlist SET target = 'https://evil' WHERE task_id = ?").run(id)).toThrow(/append-only/);

      const adv = { capability: cap(o, "adversarial_reviewer", id, "adv-1") };
      const hyp = { failureMode: "duplicate_request" as const, statement: "a duplicated transfer request credits twice", target: "fixtures/ledger.json" };
      expect(() => proposeHypothesis(db, dir, id, { ...hyp, target: "fixtures/other.json" }, adv)).toThrow(/not on this task's allowlist/);
      expect(() => proposeHypothesis(db, dir, id, { ...hyp, target: "https://example.com" }, adv)).toThrow(/not a URL|a URL/);
      expect(() => proposeHypothesis(db, dir, id, hyp, { capability: cap(o, "builder", id, "builder-1") })).toThrow(/capability token is invalid/);
      expect(() => proposeHypothesis(db, dir, id, hyp, { operator: APPROVER })).toThrow(/needs a capability/);
      const h = proposeHypothesis(db, dir, id, hyp, adv);
      expect(h).toMatchObject({ status: "proposed", proposed_by: "adv-1", target: "fixtures/ledger.json" });

      const vw = { capability: cap(o, "verification_worker", id, "verifier-1") };
      expect(() => setHypothesisStatus(db, dir, h.hyp_id, "confirmed", vw)).toThrow(/illegal hypothesis move proposed -> confirmed/);
      expect(setHypothesisStatus(db, dir, h.hyp_id, "testing", vw).status).toBe("testing");
      expect(setHypothesisStatus(db, dir, h.hyp_id, "refuted", vw).status).toBe("refuted");
      expect(() => setHypothesisStatus(db, dir, h.hyp_id, "testing", vw)).toThrow(/illegal/);
      expect(() => db.prepare("UPDATE sentinel_hypotheses SET target = 'https://evil' WHERE hyp_id = ?").run(h.hyp_id)).toThrow(/immutable/);
      expect(listHypotheses(db, id).map((r) => r.status)).toEqual(["refuted"]);
    });
  });
});

describe("S3D invariants: approved once, never edited, candidate tests are read-only", () => {
  it("only an independent approver approves; the stored invariant is immutable; candidates leave it unchanged", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db } = o.store;
      const id = implementingTask(o);
      const input = { kind: "ledger_balance" as const, statement: "the sum of all account balances is unchanged by any transfer" };
      expect(() => approveInvariant(db, id, input, { id: "builder-1", roles: ["approve"] })).toThrow(/builder cannot/);
      expect(() => approveInvariant(db, id, input, { id: "arch", roles: ["approve"] })).toThrow(/agent role/);
      expect(() => approveInvariant(db, id, input, REQUESTER)).toThrow(/approve role/);
      const inv = approveInvariant(db, id, input, APPROVER);
      expect(inv.statement_sha256).toBe(createHash("sha256").update(input.statement).digest("hex"));
      expect(() => db.prepare("UPDATE sentinel_invariants SET statement = 'anything goes' WHERE invariant_id = ?").run(inv.invariant_id)).toThrow(/never changes/);
      expect(() => db.prepare("DELETE FROM sentinel_invariants WHERE invariant_id = ?").run(inv.invariant_id)).toThrow(/never deleted/);

      const before = JSON.stringify(db.prepare("SELECT * FROM sentinel_invariants").all());
      const frozen = Object.freeze({ ...inv });
      const tests = candidateTestsFor(frozen);
      expect(tests.length).toBeGreaterThan(0);
      expect(tests.every((t) => t.invariantId === inv.invariant_id && t.statementSha256 === inv.statement_sha256 && t.spec.includes(input.statement))).toBe(true);
      expect(JSON.stringify(db.prepare("SELECT * FROM sentinel_invariants").all())).toBe(before);
      expect(frozen).toEqual(inv);
      for (const kind of ["idempotency", "monotonic_state", "acl_denial", "custom"] as const) {
        expect(candidateTestsFor({ ...inv, kind }).every((t) => t.name.startsWith(`${kind}:`))).toBe(true);
      }
      expect(() => candidateTestsFor({ ...inv, statement: "tampered" })).toThrow(/does not match its approved hash/);

      const next = approveInvariant(db, id, { ...input, statement: "balances sum to zero across the ledger", supersedes: inv.invariant_id }, APPROVER);
      expect(() => approveInvariant(db, id, { ...input, supersedes: inv.invariant_id }, APPROVER)).toThrow(/already superseded/);
      expect(listInvariants(db, id).map((r) => [r.invariant_id, r.superseded])).toEqual([[next.invariant_id, false], [inv.invariant_id, true]]);
    });
  });
});

describe("S3D quotas: fail closed, never overrun, never raised", () => {
  it("refuses consumption without a quota, refuses overruns, and the store refuses a raised maximum", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db } = o.store;
      const id = implementingTask(o);
      expect(() => consumeQuota(db, id, "fuzz", { runs: 1, cases: 1, seconds: 1 })).toThrow(/no fuzz quota/);
      expect(remainingQuota(db, id, "fuzz")).toBeNull();
      expect(() => setQuota(db, id, "fuzz", { maxRuns: 2, maxCases: 100, maxSeconds: 60 }, { id: "builder-1", roles: ["approve"] })).toThrow(/builder cannot/);
      expect(() => setQuota(db, id, "fuzz", { maxRuns: -1, maxCases: 100, maxSeconds: 60 }, APPROVER)).toThrow(/whole number/);
      setQuota(db, id, "fuzz", { maxRuns: 2, maxCases: 100, maxSeconds: 60 }, APPROVER);
      expect(() => setQuota(db, id, "fuzz", { maxRuns: 50, maxCases: 1000, maxSeconds: 600 }, APPROVER)).toThrow(/already set/);
      expect(consumeQuota(db, id, "fuzz", { runs: 1, cases: 60, seconds: 30 }).remaining).toEqual({ runs: 1, cases: 40, seconds: 30 });
      expect(() => consumeQuota(db, id, "fuzz", { runs: 1, cases: 41, seconds: 1 })).toThrow(/overrun \(cases\)/);
      expect(remainingQuota(db, id, "fuzz")!.remaining).toEqual({ runs: 1, cases: 40, seconds: 30 }); // a refused call consumed nothing
      expect(consumeQuota(db, id, "fuzz", { runs: 1, cases: 40, seconds: 30 }).remaining).toEqual({ runs: 0, cases: 0, seconds: 0 });
      expect(() => consumeQuota(db, id, "fuzz", { runs: 1, cases: 0, seconds: 0 })).toThrow(/overrun \(runs\)/);
      expect(() => db.prepare("UPDATE sentinel_quotas SET max_runs = 1000 WHERE task_id = ?").run(id)).toThrow(/never raised or refunded/);
      expect(() => db.prepare("UPDATE sentinel_quotas SET used_runs = 0 WHERE task_id = ?").run(id)).toThrow(/never raised or refunded/);
    });
  });
});
