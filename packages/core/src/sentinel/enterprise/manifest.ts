import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import type Database from "better-sqlite3";
import { EngbrainError } from "../../errors.js";
import { requireRole, type Actor } from "../../memory/operators.js";
import { findSecretIn } from "../../memory/records.js";
import { planCampaigns } from "../campaigns.js";
import { controllerKey, hmacHex } from "../capabilities.js";
import { policyHash, requiredChecks } from "../policy.js";
import { evaluateEligibility, getTask } from "../tasks.js";

/**
 * Proof-carrying change manifest (Sentinel 3E). One immutable row per build: the exact source, environment and policy it was computed for, the evidence head it saw, the campaigns and
 * eligibility at that moment and the artifact digests it vouches for, as canonical JSON (sorted keys) with its SHA-256 and an HMAC under the controller key. `verifyManifest` re-derives
 * everything against the repository as it is NOW: a manifest is stale as soon as the source, the environment, the policy or the evidence moves, and tampered when the body, hash or MAC disagree.
 * A manifest certifies nothing by itself and grants no authority to merge, push, release or deploy.
 */
const sha = (s: string): string => createHash("sha256").update(s).digest("hex");
const clock = (now?: Date): Date => now ?? new Date();
const DIGEST = /^[0-9a-f]{64}$/;

/** Canonical JSON: object keys sorted at every depth, no whitespace. Arrays keep their order. */
export function canonicalJson(value: unknown): string {
  const norm = (v: unknown): unknown => {
    if (Array.isArray(v)) {
      return v.map(norm);
    }
    if (typeof v === "object" && v !== null) {
      return Object.fromEntries(Object.keys(v).sort().map((k) => [k, norm((v as Record<string, unknown>)[k])]));
    }
    return v;
  };
  return JSON.stringify(norm(value));
}

/** The head of the task's evidence log, exactly as the task layer computes it (genesis when empty). */
export function evidenceHead(db: Database.Database, taskId: string): string {
  const row = db.prepare("SELECT hash FROM sentinel_evidence WHERE task_id = ? ORDER BY seq DESC LIMIT 1").get(taskId) as { hash: string } | undefined;
  return row?.hash ?? sha(`genesis:${taskId}`);
}

function cleanEnv(env: Readonly<Record<string, string>>): Record<string, string> {
  const entries = Object.entries(env);
  if (entries.length > 40 || entries.some(([k, v]) => typeof v !== "string" || !/^[A-Za-z0-9_.:-]{1,60}$/.test(k) || v.length > 200 || /[\p{Cc}\p{Cf}]/u.test(v))) {
    throw new EngbrainError("POLICY_REFUSED", "the environment is at most 40 simple key/value pairs (values up to 200 plain characters)");
  }
  if (findSecretIn(env) !== null) {
    throw new EngbrainError("POLICY_REFUSED", "the environment looks like it contains a secret: it is never written into a manifest");
  }
  return Object.fromEntries(entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
}
export const envFingerprint = (env: Readonly<Record<string, string>>): string => sha(canonicalJson(cleanEnv(env)));

function cleanArtifacts(artifacts: Readonly<Record<string, string>>): Record<string, string> {
  const entries = Object.entries(artifacts);
  if (entries.length > 50 || entries.some(([k, v]) => !/^[A-Za-z0-9_.:@/-]{1,200}$/.test(k) || typeof v !== "string" || !DIGEST.test(v))) {
    throw new EngbrainError("POLICY_REFUSED", "artifacts are at most 50 name -> sha256 (64 lowercase hex) pairs");
  }
  return Object.fromEntries(entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
}

export interface SentinelManifestRow {
  manifest_id: string; task_id: string; task_revision: number; base_rev: string | null; proposed_rev: string | null; verified_rev: string | null; dirty_hash: string | null; source_fingerprint: string;
  env_fingerprint: string; policy_hash: string; evidence_head: string; body_json: string; body_sha256: string; created_by: string; at: string; mac: string;
}
const manifestMac = (storeDir: string, m: Pick<SentinelManifestRow, "manifest_id" | "task_id" | "body_sha256" | "created_by" | "at">, create = false): string =>
  hmacHex(storeDir, JSON.stringify(["manifest", m.manifest_id, m.task_id, m.body_sha256, m.created_by, m.at]), create);

export function buildManifest(db: Database.Database, storeDir: string, taskId: string, actor: Actor, currentFingerprint: string, env: Readonly<Record<string, string>>, now?: Date, options: { artifacts?: Readonly<Record<string, string>> } = {}): SentinelManifestRow {
  requireRole(actor, "verify");
  const at = clock(now);
  const environment = cleanEnv(env);
  const artifacts = cleanArtifacts(options.artifacts ?? {});
  return db.transaction((): SentinelManifestRow => {
    const task = getTask(db, taskId);
    if (actor.id === task.builder_principal) {
      throw new EngbrainError("POLICY_REFUSED", "the builder cannot build the manifest that vouches for its own work");
    }
    if (!DIGEST.test(currentFingerprint) || currentFingerprint !== task.source_fingerprint) {
      throw new EngbrainError("POLICY_REFUSED", "the source changed since the task's fingerprint was recorded: a manifest is built only for the task's exact source");
    }
    const scope = JSON.parse(task.scope_json) as string[];
    const checkpoint = db.prepare("SELECT processed_oid AS oid, overlay_hash AS overlay FROM history_checkpoints WHERE ref_key = 'HEAD'").get() as { oid: string | null; overlay: string | null } | undefined;
    const eligibility = evaluateEligibility(db, storeDir, taskId, currentFingerprint, at);
    const campaigns = planCampaigns(db, storeDir, taskId, currentFingerprint, { now: at });
    const proposed = checkpoint?.oid ?? null;
    const policy = policyHash(storeDir);
    const head = evidenceHead(db, taskId);
    const openFindings = db.prepare("SELECT finding_id AS id, severity, title FROM sentinel_findings WHERE task_id = ? AND disposition = 'open' ORDER BY at").all(taskId) as Array<{ id: string; severity: string; title: string }>;
    const approvals = db.prepare("SELECT approver, at FROM sentinel_approvals WHERE task_id = ? AND status = 'active' AND source_fingerprint = ? AND policy_hash = ? AND evidence_head = ? ORDER BY at").all(taskId, currentFingerprint, policy, head) as Array<{ approver: string; at: string }>;
    const verifiers = db.prepare("SELECT DISTINCT check_id AS checkId, verifier FROM sentinel_evidence WHERE task_id = ? AND origin = 'machine' AND source_fingerprint = ? ORDER BY check_id, verifier").all(taskId, currentFingerprint) as Array<{ checkId: string | null; verifier: string }>;
    const evidenceHashes = db.prepare("SELECT check_id AS checkId, outcome, hash FROM sentinel_evidence WHERE task_id = ? AND origin = 'machine' AND source_fingerprint = ? ORDER BY seq").all(taskId, currentFingerprint) as Array<{ checkId: string | null; outcome: string; hash: string }>;
    const body = {
      v: 1, taskId, taskRevision: task.revision, profile: task.profile, state: task.state, builder: task.builder_principal, requester: task.requester,
      revisions: { base: task.base_revision, proposed, verified: eligibility.checksPassing ? proposed : null, dirtyOverlayHash: checkpoint?.overlay ?? null },
      fingerprints: { source: currentFingerprint, environment: sha(canonicalJson(environment)), policy, evidenceHead: head },
      environment, artifacts, scope, requirements: JSON.parse(task.requirements_json) as string[], components: JSON.parse(task.components_json) as string[],
      requiredChecks: requiredChecks(storeDir, task.profile, scope),
      campaigns: campaigns.map((c) => ({ passClass: c.passClass, status: c.status, checks: c.checks.map((s) => ({ checkId: s.checkId, outcome: s.outcome, state: s.state })) })),
      eligibility: { checksPassing: eligibility.checksPassing, blockers: eligibility.blockers, stale: eligibility.stale, approvalsValid: eligibility.approvalsValid, approvalsNeeded: eligibility.approvalsNeeded },
      evidence: evidenceHashes, verifiers, approvals, unresolvedRisks: openFindings,
      createdBy: actor.id, at: at.toISOString(),
      note: "A manifest is a record of evidence, not a certification; it grants no permission to merge, push, release or deploy."
    };
    const bodyJson = canonicalJson(body);
    if (bodyJson.length > 262_144 || findSecretIn(body) !== null) {
      throw new EngbrainError("POLICY_REFUSED", "the manifest is too large or looks like it contains a secret");
    }
    const id = `mf_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
    const base = { manifest_id: id, task_id: taskId, body_sha256: sha(bodyJson), created_by: actor.id, at: at.toISOString() };
    const row: SentinelManifestRow = {
      ...base, task_revision: task.revision, base_rev: task.base_revision, proposed_rev: proposed, verified_rev: body.revisions.verified, dirty_hash: checkpoint?.overlay ?? null, source_fingerprint: currentFingerprint,
      env_fingerprint: body.fingerprints.environment, policy_hash: policy, evidence_head: head, body_json: bodyJson, mac: manifestMac(storeDir, base, true)
    };
    db.prepare(
      `INSERT INTO sentinel_manifests (manifest_id, task_id, task_revision, base_rev, proposed_rev, verified_rev, dirty_hash, source_fingerprint, env_fingerprint, policy_hash, evidence_head, body_json, body_sha256, created_by, at, mac)
       VALUES (@manifest_id, @task_id, @task_revision, @base_rev, @proposed_rev, @verified_rev, @dirty_hash, @source_fingerprint, @env_fingerprint, @policy_hash, @evidence_head, @body_json, @body_sha256, @created_by, @at, @mac)`
    ).run(row);
    return row;
  }).immediate();
}

export function getManifest(db: Database.Database, manifestId: string): SentinelManifestRow {
  const row = db.prepare("SELECT * FROM sentinel_manifests WHERE manifest_id = ?").get(manifestId) as SentinelManifestRow | undefined;
  if (row === undefined) {
    throw new EngbrainError("INVALID_ROOT", "no such manifest");
  }
  return row;
}

export function latestManifest(db: Database.Database, taskId: string): SentinelManifestRow | null {
  return (db.prepare("SELECT * FROM sentinel_manifests WHERE task_id = ? ORDER BY at DESC, rowid DESC LIMIT 1").get(taskId) as SentinelManifestRow | undefined) ?? null;
}

export interface ManifestVerification { ok: boolean; tampered: boolean; stale: boolean; problems: string[] }

/**
 * Tampering (bad hash, bad MAC, columns that disagree with the body, a swapped artifact digest) is reported separately from staleness (source, environment, policy or evidence moved on).
 * Pass the artifact digests recomputed NOW in `options.artifacts` to bind the manifest to the actual artifacts.
 */
export function verifyManifest(db: Database.Database, storeDir: string, manifestId: string, currentFingerprint: string, env: Readonly<Record<string, string>>, options: { artifacts?: Readonly<Record<string, string>> } = {}): ManifestVerification {
  const m = getManifest(db, manifestId);
  const tampered: string[] = [];
  const stale: string[] = [];
  let body: Record<string, any> = {};
  try {
    body = JSON.parse(m.body_json) as Record<string, any>;
  } catch {
    tampered.push("the manifest body is not JSON");
  }
  let macOk = false;
  try {
    controllerKey(storeDir);
    const expected = Buffer.from(manifestMac(storeDir, m), "hex");
    const given = Buffer.from(/^[0-9a-f]{64}$/.test(m.mac) ? m.mac : "", "hex");
    macOk = given.length === expected.length && timingSafeEqual(given, expected);
  } catch {
    macOk = false;
  }
  if (sha(m.body_json) !== m.body_sha256 || canonicalJson(body) !== m.body_json) {
    tampered.push("the manifest body does not match its sha256 (tampered)");
  }
  if (!macOk) {
    tampered.push("the manifest MAC does not verify (tampered or forged)");
  }
  const f = (body["fingerprints"] ?? {}) as Record<string, unknown>;
  if (body["taskId"] !== m.task_id || f["source"] !== m.source_fingerprint || f["environment"] !== m.env_fingerprint || f["policy"] !== m.policy_hash || f["evidenceHead"] !== m.evidence_head) {
    tampered.push("the manifest columns disagree with its signed body (tampered)");
  }
  if (options.artifacts !== undefined) {
    const recorded = (body["artifacts"] ?? {}) as Record<string, string>;
    const current = cleanArtifacts(options.artifacts);
    for (const name of [...new Set([...Object.keys(recorded), ...Object.keys(current)])].sort()) {
      if (recorded[name] !== current[name]) {
        tampered.push(`artifact ${name}: digest does not match the manifest (swapped or rebuilt artifact)`);
      }
    }
  }
  if (m.source_fingerprint !== currentFingerprint) {
    stale.push("the source changed after the manifest was built");
  }
  let envNow: string | null = null;
  try {
    envNow = envFingerprint(env);
  } catch {
    envNow = null;
  }
  if (envNow !== m.env_fingerprint) {
    stale.push("the environment changed after the manifest was built");
  }
  if (m.policy_hash !== policyHash(storeDir)) {
    stale.push("the policy changed after the manifest was built");
  }
  if (m.evidence_head !== evidenceHead(db, m.task_id)) {
    stale.push("evidence was recorded after the manifest was built");
  }
  return { ok: tampered.length === 0 && stale.length === 0, tampered: tampered.length > 0, stale: stale.length > 0, problems: [...tampered, ...stale] };
}
