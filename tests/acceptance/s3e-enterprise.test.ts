import { createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import {
  activeExceptions, addMemory, appendEvidence, approveException, approveMemory, approveTask, assertIndependentApproval, assuranceReport, assureTask, buildManifest, createTask, decide, evaluateRecord,
  exportReport, getTask, grant, issueCapability, parseNewMemory, recordIncidentReview, registerVerifierKey, requestException, requiredChecks, revokeException, revokeGrant, revokeVerifierKey,
  signatureValid, transitionTask, updatePolicy, verifyDecisionChain, verifyEd25519, verifyManifest, type Actor, type EvidenceOutcome, type Role
} from "@engbrain/core";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, engbrainHome, makeGitRepo } from "../helpers/env.js";
import { refresh, withStore, type Opened } from "../helpers/h1.js";

afterAll(cleanupTempDirs);

// Everything here is execution-free: check results are recorded machine evidence, nothing is run, merged, pushed, released or deployed.
const ADMIN: Actor = { id: "alice", roles: ["propose", "approve", "verify", "admin"] };
const CAROL: Actor = { id: "carol", roles: ["approve"] };
const DAVE: Actor = { id: "dave", roles: ["approve"] };
const EVE: Actor = { id: "eve", roles: ["approve"] }; // may approve as an operator, but holds no approver grant
const VERA: Actor = { id: "vera", roles: ["verify"] };
const REQ: Actor = { id: "req", roles: ["propose"] };
const BUILDER_OP: Actor = { id: "builder-1", roles: ["approve", "verify"] };
const sha = (s: string): string => createHash("sha256").update(s).digest("hex");
/** The trusted caller's source fingerprint: a digest over the exact file contents. */
const fpOf = (files: Record<string, string>): string => sha(JSON.stringify(Object.entries(files).sort()));
const SOURCE = {
  "src/payments/transfer.ts": "export function transfer(from: Account, to: Account, cents: number) { if (cents <= 0) throw new Error('bad amount'); ledger.debit(from, cents); ledger.credit(to, cents); }\n",
  "src/payments/transfer.test.ts": "it('never double-charges', () => {});\n"
};
const FP = fpOf(SOURCE);
const ENV = { os: "darwin", node: "22", toolchain: "tsc-5" };
const ARTIFACTS = { "dist/payments.tgz": sha("payments build 1") };
const A3_CHECKS: Record<string, Role> = {
  scope: "verification_worker", tests: "verification_worker", lint: "verification_worker", typecheck: "verification_worker", dependency_review: "verification_worker",
  security_review: "reviewer", adversarial_review: "adversarial_reviewer"
};

async function setup(files: Record<string, string> = { "a.ts": "export const a = 1;\n" }, index = false): Promise<{ repo: string; home: string }> {
  const repo = makeGitRepo(files);
  const home = engbrainHome();
  if (index) {
    await refresh(repo, home, { history: "backfill" }, true);
  } else {
    await withStore(repo, home, () => undefined, true);
  }
  return { repo, home };
}
const cap = (o: Opened, role: Role, taskId: string, principal: string): string => issueCapability(o.store.dir, { role, taskId, principal, ttlSeconds: 3600, issuer: ADMIN, epoch: getTask(o.store.db, taskId).cap_epoch });
const T = (o: Opened, id: string, to: Parameters<typeof transitionTask>[3], who: Parameters<typeof transitionTask>[4]) => transitionTask(o.store.db, o.store.dir, id, to, who);

function grantApprovers(o: Opened): void {
  grant(o.store.db, ADMIN, "carol", "approver", "src/payments/");
  grant(o.store.db, ADMIN, "dave", "second_approver", "*");
}

/** A synthetic high-risk transaction fix (A3) driven to VERIFYING. */
function verifyingTask(o: Opened, profile: "A1" | "A3" = "A3"): string {
  const t = createTask(o.store.db, o.store.dir, { title: "Fix double-charge in transfer", requester: REQ, profile, scope: ["src/payments/"], requirements: ["a transfer debits exactly once"], sourceFingerprint: FP });
  const id = t.task_id;
  T(o, id, "CONTEXT_READY", { capability: cap(o, "architect", id, "arch") });
  T(o, id, "SPECIFICATION_READY", { capability: cap(o, "architect", id, "arch") });
  T(o, id, "PLAN_APPROVED", { operator: CAROL });
  T(o, id, "IMPLEMENTING", { capability: cap(o, "builder", id, "builder-1") });
  T(o, id, "IMPLEMENTED", { capability: cap(o, "builder", id, "builder-1") });
  T(o, id, "VERIFYING", { capability: cap(o, "verification_worker", id, "verifier-1") });
  return id;
}
function record(o: Opened, id: string, check: string, outcome: EvidenceOutcome, payload: Record<string, unknown> = {}): void {
  const role = A3_CHECKS[check] ?? "verification_worker";
  const principal = role === "reviewer" ? "rev-1" : role === "adversarial_reviewer" ? "red-team" : "verifier-1";
  appendEvidence(o.store.db, o.store.dir, id, { origin: "machine", kind: "check_result", checkId: check, outcome, payload }, { capability: cap(o, role, id, principal) }, FP);
}
/** Functional, adversarial and system-assurance evidence for every A3 check. */
function passAll(o: Opened, id: string, except: string[] = []): void {
  for (const check of Object.keys(A3_CHECKS).filter((c) => !except.includes(c))) {
    record(o, id, check, "passed", { pass: check === "adversarial_review" ? "ADVERSARIAL" : ["security_review", "dependency_review"].includes(check) ? "SYSTEM_ASSURANCE" : "FUNCTIONAL" });
  }
}

interface Eligible { id: string; manifestId: string; bodySha: string; signature: string; verifierKey: KeyObject }
/** The whole happy path: evidence, assurance, two independent granted approvals, a verifier key, a manifest and a verifier signature over it. */
function eligibleTask(o: Opened, approvers: Actor[] = [CAROL, DAVE]): Eligible {
  const { db, dir } = o.store;
  grantApprovers(o);
  const id = verifyingTask(o);
  passAll(o, id);
  T(o, id, "ASSURANCE_REVIEW", { capability: cap(o, "verification_worker", id, "verifier-1") });
  expect(assureTask(db, dir, id, cap(o, "assurance_controller", id, "assure-1"), FP).state).toBe("APPROVAL_REQUIRED");
  for (const a of approvers) {
    approveTask(db, dir, id, a, FP);
  }
  const keys = generateKeyPairSync("ed25519");
  registerVerifierKey(db, ADMIN, { principal: "sig-verifier", publicKeyPem: keys.publicKey.export({ type: "spki", format: "pem" }).toString(), notAfter: new Date(Date.now() + 30 * 86_400_000) });
  const manifest = buildManifest(db, dir, id, VERA, FP, ENV, undefined, { artifacts: ARTIFACTS });
  const signature = sign(null, Buffer.from(manifest.body_sha256), keys.privateKey).toString("hex");
  return { id, manifestId: manifest.manifest_id, bodySha: manifest.body_sha256, signature, verifierKey: keys.privateKey };
}
const sigs = (e: Eligible) => ({ signatures: [{ principal: "sig-verifier", signatureHex: e.signature }], artifacts: ARTIFACTS });

describe("S3E proof-carrying manifest and assurance controller", () => {
  it("a synthetic high-risk transaction fix is ELIGIBLE only for the exact source: one byte or one environment change is STALE_EVIDENCE", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const e = eligibleTask(o);
      expect(getTask(db, e.id).state).toBe("ELIGIBLE_FOR_APPROVAL");
      expect(verifyManifest(db, dir, e.manifestId, FP, ENV, { artifacts: ARTIFACTS })).toMatchObject({ ok: true, problems: [] });
      const body = JSON.parse((db.prepare("SELECT body_json FROM sentinel_manifests WHERE manifest_id = ?").get(e.manifestId) as { body_json: string }).body_json) as Record<string, any>;
      expect(body["fingerprints"]["source"]).toBe(FP);
      expect(body["requiredChecks"]).toEqual(requiredChecks(dir, "A3", ["src/payments/"]));
      expect(body["campaigns"].map((c: { status: string }) => c.status)).toEqual(["PASSED", "PASSED", "PASSED"]); // functional, adversarial and system assurance
      expect(JSON.stringify(body)).not.toMatch(/PRIVATE KEY/);
      const ok = decide(db, dir, e.id, FP, ENV, undefined, sigs(e));
      expect(ok.outcome).toBe("ELIGIBLE_FOR_APPROVAL");
      expect(ok.independentApprovers).toEqual(["carol", "dave"]);
      expect(ok.note).toMatch(/NO authority to merge, push, publish, release or deploy/);
      // one byte of source changes after verification
      const fp2 = fpOf({ ...SOURCE, "src/payments/transfer.ts": `${SOURCE["src/payments/transfer.ts"]} ` });
      const stale = decide(db, dir, e.id, fp2, ENV, undefined, sigs(e));
      expect(stale.outcome).toBe("STALE_EVIDENCE");
      expect(stale.reasons.join(" ")).toMatch(/source changed after the manifest/);
      // the environment changes
      expect(decide(db, dir, e.id, FP, { ...ENV, node: "24" }, undefined, sigs(e)).outcome).toBe("STALE_EVIDENCE");
      // nothing about the verdict was written back as authority; the decision log is an intact hash chain
      expect(getTask(db, e.id).state).toBe("ELIGIBLE_FOR_APPROVAL");
      expect(verifyDecisionChain(db)).toMatchObject({ ok: true, decisions: 3 });
    });
  });

  it("deleting or modifying a test, changing the policy, or adding evidence after verification makes the evidence stale and blocks eligibility", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const e = eligibleTask(o);
      const { "src/payments/transfer.test.ts": _removed, ...withoutTest } = SOURCE;
      expect(decide(db, dir, e.id, fpOf(withoutTest), ENV, undefined, sigs(e)).outcome).toBe("STALE_EVIDENCE"); // test deleted
      expect(decide(db, dir, e.id, fpOf({ ...SOURCE, "src/payments/transfer.test.ts": "it.skip('never double-charges', () => {});\n" }), ENV, undefined, sigs(e)).outcome).toBe("STALE_EVIDENCE"); // test modified
      expect(decide(db, dir, e.id, FP, ENV, undefined, sigs(e)).outcome).toBe("ELIGIBLE_FOR_APPROVAL");
      updatePolicy(dir, ADMIN, { evidenceMaxAgeHours: { A3: 12 } }); // the policy changes after verification
      const afterPolicy = decide(db, dir, e.id, FP, ENV, undefined, sigs(e));
      expect(afterPolicy.outcome).toBe("STALE_EVIDENCE");
      expect(afterPolicy.reasons.join(" ")).toMatch(/policy changed/);
      expect(verifyManifest(db, dir, e.manifestId, FP, ENV).problems.join(" ")).toMatch(/policy changed after the manifest/);
    });
    const w2 = await setup();
    await withStore(w2.repo, w2.home, (o) => {
      const { db, dir } = o.store;
      const e = eligibleTask(o);
      record(o, e.id, "tests", "passed"); // late evidence: the manifest (and the approvals) no longer describe the evidence
      const d = decide(db, dir, e.id, FP, ENV, undefined, sigs(e));
      expect(d.outcome).toBe("STALE_EVIDENCE");
      expect(d.reasons.join(" ")).toMatch(/evidence was recorded after the manifest/);
    });
  });

  it("forged verifier signatures, swapped artifact digests, forged approval MACs, forged manifests and builder self-approval are rejected", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const e = eligibleTask(o);
      // a signature by a key that was never registered, and a bit-flipped signature
      const rogue = generateKeyPairSync("ed25519");
      const forged = sign(null, Buffer.from(e.bodySha), rogue.privateKey).toString("hex");
      expect(signatureValid(db, "sig-verifier", e.bodySha, forged)).toBe(false);
      expect(decide(db, dir, e.id, FP, ENV, undefined, { signatures: [{ principal: "sig-verifier", signatureHex: forged }], artifacts: ARTIFACTS }).outcome).toBe("BLOCKED");
      const flipped = `${e.signature.slice(0, -2)}${e.signature.endsWith("00") ? "01" : "00"}`;
      expect(decide(db, dir, e.id, FP, ENV, undefined, { signatures: [{ principal: "sig-verifier", signatureHex: flipped }], artifacts: ARTIFACTS }).outcome).toBe("BLOCKED");
      expect(verifyEd25519(rogue.publicKey.export({ type: "spki", format: "pem" }).toString(), e.bodySha, forged)).toBe(true); // the crypto works; only the registry decides trust
      // a missing signature on A3 is not eligible either
      expect(decide(db, dir, e.id, FP, ENV, undefined, { artifacts: ARTIFACTS }).outcome).toBe("APPROVAL_REQUIRED");
      // a swapped build artifact
      const swapped = decide(db, dir, e.id, FP, ENV, undefined, { ...sigs(e), artifacts: { "dist/payments.tgz": sha("trojan build") } });
      expect(swapped.outcome).toBe("BLOCKED");
      expect(swapped.reasons.join(" ")).toMatch(/dist\/payments\.tgz: digest does not match/);
      // private keys and self-registration are refused; a revoked key stops verifying
      const priv = rogue.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
      expect(() => registerVerifierKey(db, ADMIN, { principal: "x", publicKeyPem: priv, notAfter: new Date(Date.now() + 86_400_000) })).toThrow(/PUBLIC key/);
      expect(() => registerVerifierKey(db, ADMIN, { principal: "alice", publicKeyPem: rogue.publicKey.export({ type: "spki", format: "pem" }).toString(), notAfter: new Date(Date.now() + 86_400_000) })).toThrow(/its own verifier key/);
      expect(() => registerVerifierKey(db, CAROL, { principal: "x", publicKeyPem: rogue.publicKey.export({ type: "spki", format: "pem" }).toString(), notAfter: new Date(Date.now() + 86_400_000) })).toThrow(/admin/);
      // builder self-approval is denied at every layer
      expect(() => approveTask(db, dir, e.id, BUILDER_OP, FP)).toThrow(/builder cannot approve/);
      expect(() => assertIndependentApproval(db, getTask(db, e.id), "builder-1")).toThrow(/builder cannot approve/);
      expect(() => assertIndependentApproval(db, getTask(db, e.id), "verifier-1")).toThrow(/agent role/);
      const builderKey = generateKeyPairSync("ed25519");
      registerVerifierKey(db, ADMIN, { principal: "builder-1", publicKeyPem: builderKey.publicKey.export({ type: "spki", format: "pem" }).toString(), notAfter: new Date(Date.now() + 86_400_000) });
      const selfSigned = decide(db, dir, e.id, FP, ENV, undefined, { signatures: [{ principal: "builder-1", signatureHex: sign(null, Buffer.from(e.bodySha), builderKey.privateKey).toString("hex") }], artifacts: ARTIFACTS });
      expect(selfSigned.outcome).toBe("BLOCKED");
      expect(selfSigned.reasons.join(" ")).toMatch(/builder cannot sign/);
      expect(decide(db, dir, e.id, FP, ENV, undefined, sigs(e)).outcome).toBe("ELIGIBLE_FOR_APPROVAL");
      // a forged approval row (raw INSERT with a made-up MAC) is detected
      const head = (db.prepare("SELECT hash FROM sentinel_evidence WHERE task_id = ? ORDER BY seq DESC LIMIT 1").get(e.id) as { hash: string }).hash;
      const policy = (db.prepare("SELECT policy_hash AS p FROM sentinel_approvals WHERE task_id = ? LIMIT 1").get(e.id) as { p: string }).p;
      db.prepare("INSERT INTO sentinel_approvals (approval_id, task_id, approver, at, task_revision, source_fingerprint, policy_hash, evidence_head, status, mac) VALUES (?, ?, 'mallory', ?, 1, ?, ?, ?, 'active', ?)")
        .run("ap_forged000000000", e.id, new Date().toISOString(), FP, policy, head, "0".repeat(64));
      const forgedApproval = decide(db, dir, e.id, FP, ENV, undefined, sigs(e));
      expect(forgedApproval.outcome).toBe("BLOCKED");
      expect(forgedApproval.reasons.join(" ")).toMatch(/forged or altered MAC/);
    });
    const w2 = await setup();
    await withStore(w2.repo, w2.home, (o) => {
      const { db, dir } = o.store;
      const e = eligibleTask(o);
      // a forged, later manifest (raw INSERT; it cannot carry a valid MAC) becomes the latest and blocks
      const row = db.prepare("SELECT * FROM sentinel_manifests WHERE manifest_id = ?").get(e.manifestId) as Record<string, unknown>;
      db.prepare("INSERT INTO sentinel_manifests (manifest_id, task_id, task_revision, base_rev, proposed_rev, verified_rev, dirty_hash, source_fingerprint, env_fingerprint, policy_hash, evidence_head, body_json, body_sha256, created_by, at, mac) VALUES (@manifest_id, @task_id, @task_revision, @base_rev, @proposed_rev, @verified_rev, @dirty_hash, @source_fingerprint, @env_fingerprint, @policy_hash, @evidence_head, @body_json, @body_sha256, @created_by, @at, @mac)")
        .run({ ...row, manifest_id: "mf_forged00000000", at: new Date(Date.now() + 1000).toISOString(), mac: "f".repeat(64) });
      const d = decide(db, dir, e.id, FP, ENV, undefined, sigs(e));
      expect(d.outcome).toBe("BLOCKED");
      expect(d.reasons.join(" ")).toMatch(/MAC does not verify/);
      // a revoked verifier key no longer verifies anything
      const keyId = (db.prepare("SELECT key_id FROM sentinel_verifier_keys WHERE principal = 'sig-verifier'").get() as { key_id: string }).key_id;
      revokeVerifierKey(db, ADMIN, keyId);
      expect(signatureValid(db, "sig-verifier", e.bodySha, e.signature)).toBe(false);
    });
  });

  it("a skipped check, an unsupported tool, or a single approver where two are required is never ELIGIBLE", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      grantApprovers(o);
      const skipped = verifyingTask(o);
      passAll(o, skipped, ["lint"]);
      record(o, skipped, "lint", "skipped");
      buildManifest(db, dir, skipped, VERA, FP, ENV);
      const d1 = decide(db, dir, skipped, FP, ENV);
      expect(d1.outcome).toBe("INCOMPLETE");
      expect(d1.reasons.join(" ")).toMatch(/lint: skipped/);
      const unsupported = verifyingTask(o);
      passAll(o, unsupported, ["typecheck"]);
      record(o, unsupported, "typecheck", "passed", { unsupported: true, reason: "unsupported tool on this platform" }); // a "pass" from an unsupported tool is not a pass
      buildManifest(db, dir, unsupported, VERA, FP, ENV);
      const d2 = decide(db, dir, unsupported, FP, ENV);
      expect(d2.outcome).toBe("INCOMPLETE");
      expect(d2.unmeasured.join(" ")).toMatch(/typecheck: the tool or platform is unsupported/);
      const notRun = verifyingTask(o);
      passAll(o, notRun, ["adversarial_review"]);
      buildManifest(db, dir, notRun, VERA, FP, ENV);
      expect(decide(db, dir, notRun, FP, ENV).unmeasured).toContain("adversarial_review: not run");
    });
    const w2 = await setup();
    await withStore(w2.repo, w2.home, (o) => {
      const { db, dir } = o.store;
      const e = eligibleTask(o, [CAROL]); // A3 needs two
      expect(getTask(db, e.id).state).toBe("APPROVAL_REQUIRED");
      const d = decide(db, dir, e.id, FP, ENV, undefined, sigs(e));
      expect(d.outcome).toBe("APPROVAL_REQUIRED");
      expect(d.reasons.join(" ")).toMatch(/1 of 2 independent, granted approvals/);
      // a second operator approval WITHOUT an approver grant does not count either
      approveTask(db, dir, e.id, EVE, FP);
      expect(getTask(db, e.id).state).toBe("ELIGIBLE_FOR_APPROVAL"); // the task layer counts it ...
      const withEve = decide(db, dir, e.id, FP, ENV, undefined, sigs(e));
      expect(withEve.outcome).toBe("APPROVAL_REQUIRED"); // ... the enterprise controller does not
      expect(withEve.reasons.join(" ")).toMatch(/eve holds no active approver\/second_approver grant/);
      // revoking a grant withdraws an approval that counted
      grant(db, ADMIN, "eve", "approver", "src/");
      expect(decide(db, dir, e.id, FP, ENV, undefined, sigs(e)).outcome).toBe("ELIGIBLE_FOR_APPROVAL");
      const carolGrant = (db.prepare("SELECT grant_id FROM sentinel_principal_grants WHERE principal = 'carol'").get() as { grant_id: string }).grant_id;
      revokeGrant(db, ADMIN, carolGrant);
      expect(decide(db, dir, e.id, FP, ENV, undefined, sigs(e)).outcome).toBe("APPROVAL_REQUIRED");
      expect(() => grant(db, ADMIN, "alice", "approver", "*")).toThrow(/to themselves/);
      expect(() => grant(db, CAROL, "dave", "approver", "*")).toThrow(/admin/);
    });
  });

  it("an exception never removes a check or makes it pass, mandatory checks cannot be excepted, and the approver must be a granted second person", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      updatePolicy(dir, ADMIN, { extraChecks: { A1: ["fuzz"] } }); // the institution adds a check to A1
      grant(db, ADMIN, "carol", "approver", "*");
      const id = verifyingTask(o, "A1");
      for (const c of ["scope", "tests", "lint"]) {
        record(o, id, c, "passed");
      }
      buildManifest(db, dir, id, VERA, FP, ENV);
      expect(decide(db, dir, id, FP, ENV).outcome).toBe("INCOMPLETE"); // fuzz never ran
      const expires = new Date(Date.now() + 7 * 86_400_000);
      expect(() => requestException(db, dir, id, "tests", REQ, "tests are slow, accept the risk", expires)).toThrow(/never waivable/);
      expect(() => requestException(db, dir, id, "scope", REQ, "scope check is noisy, accept it", expires)).toThrow(/never waivable/);
      const ex = requestException(db, dir, id, "fuzz", REQ, "fuzzing infra unavailable this week; covered by property tests", expires);
      expect(ex.status).toBe("requested");
      expect(() => approveException(db, dir, ex.exception_id, { id: "req", roles: ["approve"] })).toThrow(/requester cannot approve/);
      expect(() => approveException(db, dir, ex.exception_id, BUILDER_OP)).toThrow(/builder cannot approve/);
      expect(() => approveException(db, dir, ex.exception_id, CAROL)).toThrow(/exception_approver grant/);
      const g = grant(db, ADMIN, "frank", "exception_approver", "src/payments/");
      approveException(db, dir, ex.exception_id, { id: "frank", roles: ["approve"] });
      expect(activeExceptions(db, id)).toHaveLength(1);
      expect(requiredChecks(dir, "A1", ["src/payments/"])).toContain("fuzz"); // still required
      const d = decide(db, dir, id, FP, ENV);
      expect(d.outcome).toBe("APPROVAL_REQUIRED"); // never ELIGIBLE, never "passed"
      expect(d.reasons.join(" ")).toMatch(/fuzz: not_run — NOT passed; risk accepted by exception/);
      // the approver's grant is revoked: the exception stops counting
      revokeGrant(db, ADMIN, g.grant_id);
      const after = decide(db, dir, id, FP, ENV);
      expect(after.outcome).toBe("INCOMPLETE");
      expect(after.reasons.join(" ")).toMatch(/no longer counts/);
      revokeException(db, dir, ex.exception_id, CAROL);
      expect(activeExceptions(db, id)).toHaveLength(0);
    });
  });

  it("every affected confirmed incident must be reviewed before eligibility", async () => {
    const w = await setup(SOURCE, true);
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const bug = addMemory(db, parseNewMemory({
        kind: "bug", title: "transfer debited twice on retry", body: "INC-2041: a retried transfer debited the source account twice.", origin: "human",
        evidence: { type: "incident", pointers: [{ kind: "file", path: "src/payments/transfer.ts" }, { kind: "incident", ref: "INC-2041" }] }
      }), { actor: ADMIN });
      approveMemory(db, bug.record_id, { actor: ADMIN, evaluate: (row) => evaluateRecord(db, row, new Date().toISOString()) });
      const e = eligibleTask(o);
      const d = decide(db, dir, e.id, FP, ENV, undefined, sigs(e));
      expect(d.outcome).toBe("APPROVAL_REQUIRED");
      expect(d.reasons.join(" ")).toMatch(new RegExp(`affected incident ${bug.record_id} .* has not been reviewed`));
      expect(() => recordIncidentReview(db, e.id, bug.record_id, null, BUILDER_OP, "not_applicable")).toThrow(/builder cannot review/);
      expect(() => recordIncidentReview(db, e.id, bug.record_id, null, VERA, "covered")).toThrow(/names the regression test/);
      recordIncidentReview(db, e.id, bug.record_id, null, VERA, "not_covered");
      const nc = decide(db, dir, e.id, FP, ENV, undefined, sigs(e));
      expect(nc.outcome).toBe("APPROVAL_REQUIRED");
      expect(nc.unmeasured.join(" ")).toMatch(/no regression test covers it/);
      recordIncidentReview(db, e.id, bug.record_id, "src/payments/transfer.test.ts", VERA, "covered");
      expect(decide(db, dir, e.id, FP, ENV, undefined, sigs(e)).outcome).toBe("ELIGIBLE_FOR_APPROVAL");
    });
  });
});

describe("S3E classification-aware export and the assurance report", () => {
  it("exports are redacted by classification; a revoked or out-of-scope grant leaks nothing and is audited", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const e = eligibleTask(o);
      decide(db, dir, e.id, FP, ENV, undefined, sigs(e));
      const xena = grant(db, ADMIN, "xena", "exporter", "src/");
      grant(db, ADMIN, "audrey", "auditor", "*");
      grant(db, ADMIN, "otto", "exporter", "src/other/"); // a grant for a different part of the repository
      const internal = exportReport(db, { id: "xena", roles: [] }, e.id, "restricted");
      expect(internal.classification).toBe("internal"); // an exporter is cleared to internal, whatever it asks for
      expect(Object.keys(internal.content)).toEqual(expect.arrayContaining(["summary", "checks"]));
      expect(internal.content).not.toHaveProperty("scope_and_people");
      expect(internal.json).not.toMatch(/Fix double-charge|src\/payments|carol|builder-1/);
      expect(internal.redactions).toEqual(["scope_and_people (confidential)", "risk_acceptance_and_incidents (restricted)"]);
      const full = exportReport(db, { id: "audrey", roles: [] }, e.id, "restricted");
      expect(full.content).toHaveProperty("scope_and_people");
      expect(full.json).toMatch(/Fix double-charge/);
      expect(full.json).not.toMatch(/PRIVATE KEY|sentinel-key/);
      const pub = exportReport(db, { id: "audrey", roles: [] }, e.id, "public");
      expect(Object.keys(pub.content)).not.toContain("checks");
      expect(() => exportReport(db, { id: "otto", roles: [] }, e.id, "public")).toThrow(/export refused/);
      revokeGrant(db, ADMIN, xena.grant_id);
      let leaked: unknown = null;
      try {
        leaked = exportReport(db, { id: "xena", roles: [] }, e.id, "public");
      } catch (err) {
        expect((err as Error).message).toMatch(/export refused/);
        expect((err as Error).message).not.toMatch(/double-charge|payments/);
      }
      expect(leaked).toBeNull();
      const audit = db.prepare("SELECT principal, classification, content_sha256 AS sha, redactions_json AS r FROM sentinel_export_audit ORDER BY at, rowid").all() as Array<{ principal: string; classification: string; sha: string; r: string }>;
      expect(audit.map((a) => a.principal)).toEqual(["xena", "audrey", "audrey", "otto", "xena"]);
      expect(audit[0]!.sha).toBe(internal.sha256);
      expect(audit[4]).toMatchObject({ sha: sha("") });
      expect(audit[4]!.r).toMatch(/refused/);
    });
  });

  it("the report lists what is not certified, not formally proved, not executed and unsupported, and that the review was a Claude agent", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const e = eligibleTask(o);
      const before = (db.prepare("SELECT COUNT(*) AS n FROM sentinel_decisions").get() as { n: number }).n;
      const { json, text } = assuranceReport(db, dir, e.id, FP, ENV, undefined, sigs(e));
      expect((db.prepare("SELECT COUNT(*) AS n FROM sentinel_decisions").get() as { n: number }).n).toBe(before); // read-only
      expect(json.decision.outcome).toBe("ELIGIBLE_FOR_APPROVAL");
      expect(json.verified.manifestOk).toBe(true);
      expect(json.verified.passingChecks).toEqual(Object.keys(A3_CHECKS).sort());
      expect(json.notCertified.join(" ")).toMatch(/not industry certifications/);
      expect(json.notFormallyProved.join(" ")).toMatch(/formally proved/);
      expect(json.notExecuted.join(" ")).toMatch(/executes nothing/);
      expect(json.unsupportedPlatforms).toEqual(["Linux: untested", "Windows: untested", "Node 24: untested"]);
      expect(json.independentReview).toMatch(/Claude agent, not Codex/);
      for (const heading of ["WHAT WAS VERIFIED", "NOT CERTIFIED", "NOT FORMALLY PROVED", "NOT EXECUTED", "UNSUPPORTED / UNTESTED PLATFORMS", "INDEPENDENT REVIEW"]) {
        expect(text).toContain(heading);
      }
      const staleText = assuranceReport(db, dir, e.id, sha("other tree"), ENV, undefined, sigs(e)).text;
      expect(staleText).toMatch(/Outcome: STALE_EVIDENCE/);
      expect(staleText).toMatch(/does NOT verify/);
    });
  });
});

describe("S3E tables refuse raw edits", () => {
  it("raw UPDATE and DELETE on every v12 table is refused by its trigger", async () => {
    const w = await setup();
    await withStore(w.repo, w.home, (o) => {
      const { db, dir } = o.store;
      const e = eligibleTask(o);
      decide(db, dir, e.id, FP, ENV, undefined, sigs(e));
      grant(db, ADMIN, "audrey", "auditor", "*");
      exportReport(db, { id: "audrey", roles: [] }, e.id, "internal");
      const now = new Date().toISOString();
      db.prepare("INSERT INTO sentinel_exceptions (exception_id, task_id, check_id, requested_by, approved_by, risk_statement, at, expires_at, status, mac) VALUES ('ex_raw', ?, 'fuzz', 'req', NULL, 'risk', ?, ?, 'requested', 'x')").run(e.id, now, now);
      db.prepare("INSERT INTO sentinel_incident_reviews (task_id, incident_ref, test_path, reviewed_by, outcome, at) VALUES (?, 'mem_x', NULL, 'vera', 'not_applicable', ?)").run(e.id, now);
      const refused: Array<[string, RegExp]> = [
        ["UPDATE sentinel_manifests SET body_sha256 = body_sha256", /immutable/],
        ["DELETE FROM sentinel_manifests", /never deleted/],
        ["UPDATE sentinel_verifier_keys SET public_key_pem = 'x'", /can only be revoked/],
        ["DELETE FROM sentinel_verifier_keys", /never deleted/],
        ["UPDATE sentinel_principal_grants SET role = 'auditor'", /only be revoked/],
        ["DELETE FROM sentinel_principal_grants", /never deleted/],
        ["UPDATE sentinel_exceptions SET check_id = 'tests'", /requested -> active -> revoked/],
        ["DELETE FROM sentinel_exceptions", /never deleted/],
        ["UPDATE sentinel_decisions SET outcome = 'ELIGIBLE_FOR_APPROVAL'", /append-only/],
        ["DELETE FROM sentinel_decisions", /append-only/],
        ["UPDATE sentinel_incident_reviews SET outcome = 'covered'", /append-only/],
        ["DELETE FROM sentinel_incident_reviews", /append-only/],
        ["UPDATE sentinel_export_audit SET content_sha256 = 'x'", /append-only/],
        ["DELETE FROM sentinel_export_audit", /append-only/]
      ];
      for (const [sql, message] of refused) {
        expect(() => db.prepare(sql).run(), sql).toThrow(message);
      }
      // the only legal transitions: a key and a grant can be revoked once, never revived
      db.prepare("UPDATE sentinel_verifier_keys SET status = 'revoked'").run();
      expect(() => db.prepare("UPDATE sentinel_verifier_keys SET status = 'active'").run()).toThrow(/can only be revoked/);
      db.prepare("UPDATE sentinel_principal_grants SET revoked_at = ?").run(now);
      expect(() => db.prepare("UPDATE sentinel_principal_grants SET revoked_at = NULL").run()).toThrow(/only be revoked, once/);
      expect(verifyDecisionChain(db).ok).toBe(true);
    });
  });
});
