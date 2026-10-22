import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { chmodSync, existsSync, lstatSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type Database from "better-sqlite3";
import { EngbrainError } from "../errors.js";
import { currentGenerationId } from "../store/generations.js";
import { changedPathsSince } from "../impact/impactEngine.js";
import { makeEvalContext, type EvalContext } from "../memory/evaluate.js";
import { requireRole, withLock, type Actor } from "../memory/operators.js";
import { prep } from "../memory/prepared.js";
import { findSecretIn } from "../memory/records.js";
import { EVIDENCE_FORMATS, parseEvidence, type EvidenceFormat } from "./importers.js";

/**
 * Imported CI/test evidence. An unsigned artifact is a CLAIM: it is stored QUARANTINED and can approve nothing. It becomes usable only when
 *   (a) its HMAC-SHA256 signature verifies against a verifier registered in the local provenance policy AND it declares a source revision that is in the history ledger, a command and an environment (`signed`), or
 *   (b) an operator with the verify role explicitly accepts it (a human decision; an artifact with an INVALID signature can never be accepted).
 * A vendor-reported "passed" without that provenance is never promoted. Even usable evidence only counts while it applies: its revision must lie on the current line of history, the files it was
 * bound to must be unchanged and its declared environment must still match the recorded one. Usable evidence never approves memory by itself: it is one input a verifier checks.
 */
export const EVIDENCE_POLICY_FILE = "evidence-policy.json";
export const EVIDENCE_MAX_BYTES = 20 * 1024 * 1024;

export interface Verifier { id: string; keyHex: string; addedBy: string; addedAt: string }
export interface EvidencePolicy { verifiers: Verifier[] }

export function loadEvidencePolicy(storeDir: string): EvidencePolicy {
  const path = join(storeDir, EVIDENCE_POLICY_FILE);
  if (!existsSync(path)) {
    return { verifiers: [] };
  }
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 65_536) {
    throw new EngbrainError("STORE_UNSAFE_PATH", "evidence-policy.json is not a regular file of reasonable size");
  }
  try {
    const doc = JSON.parse(readFileSync(path, "utf8")) as Partial<EvidencePolicy>;
    return { verifiers: (Array.isArray(doc.verifiers) ? doc.verifiers : []).filter((v): v is Verifier => typeof v?.id === "string" && typeof v.keyHex === "string" && /^[0-9a-f]{64}$/.test(v.keyHex)) };
  } catch {
    throw new EngbrainError("INVALID_CONFIG", "evidence-policy.json is not valid");
  }
}

/** The hash of the policy file bytes (empty policy included): a handoff expires when it changes. */
export function evidencePolicyHash(storeDir: string): string {
  const path = join(storeDir, EVIDENCE_POLICY_FILE);
  return createHash("sha256").update(existsSync(path) ? readFileSync(path) : "").digest("hex");
}

/** Registers a verifier and returns its signing key (shown once; CI keeps it). The key is stored in the 0600 policy file because verification needs it. */
export function addVerifier(storeDir: string, input: { id: string; actor: Actor; now?: Date }): { id: string; keyHex: string } {
  requireRole(input.actor, "admin");
  if (!/^[a-z0-9][a-z0-9._-]{0,39}$/.test(input.id)) {
    throw new EngbrainError("INVALID_ROOT", "verifier ids are lowercase letters, digits, . _ - (at most 40)");
  }
  return withLock(storeDir, () => {
    const policy = loadEvidencePolicy(storeDir);
    if (policy.verifiers.some((v) => v.id === input.id)) {
      throw new EngbrainError("POLICY_REFUSED", "that verifier already exists");
    }
    const keyHex = randomBytes(32).toString("hex");
    policy.verifiers.push({ id: input.id, keyHex, addedBy: input.actor.id, addedAt: (input.now ?? new Date()).toISOString() });
    const path = join(storeDir, EVIDENCE_POLICY_FILE);
    const temp = `${path}.tmp-${process.pid}`;
    writeFileSync(temp, `${JSON.stringify(policy, null, 2)}\n`, { mode: 0o600 });
    renameSync(temp, path);
    try {
      chmodSync(path, 0o600);
    } catch {
      // not supported everywhere
    }
    return { id: input.id, keyHex };
  }, EVIDENCE_POLICY_FILE);
}

/** The provenance a signature vouches for: the artifact bytes AND where, how and by whom it was produced, so a genuine artifact cannot be re-imported under a different revision, command, environment or format. */
export interface SignedClaim { format: EvidenceFormat; revision: string; command: string; environment: Record<string, string>; verifier: string }
const canonicalClaim = (data: Buffer, c: SignedClaim): string => JSON.stringify(["engbrain-evidence-v1", createHash("sha256").update(data).digest("hex"), c.format, c.revision, c.command, Object.entries(c.environment).sort(([a], [b]) => (a < b ? -1 : 1)), c.verifier]);
export const signArtifact = (keyHex: string, data: Buffer, claim: SignedClaim): string => createHmac("sha256", Buffer.from(keyHex, "hex")).update(canonicalClaim(data, claim)).digest("hex");

export interface ImportInput {
  format: EvidenceFormat;
  data: Buffer;
  artifactName: string;
  revision?: string;
  tree?: string;
  command?: string;
  environment?: Record<string, string>;
  verifier?: string;
  signature?: string;
  /** Absolute paths written by the test runner under this root are made repository-relative. */
  repoRoot?: string;
}

export type EvidenceTrust = "quarantined" | "signed" | "accepted" | "rejected";
export interface ImportRow {
  import_id: string; format: EvidenceFormat; artifact_name: string; artifact_sha256: string; artifact_size: number; source_revision: string | null; source_tree: string | null; command: string | null;
  environment_json: string; verifier: string | null; signature_status: "none" | "valid" | "invalid"; trust: EvidenceTrust; provenance_json: string; imported_at: string; imported_by: string;
  total: number; passed: number; failed: number; skipped: number; timed_out: number; errors: number; partial: number; warnings_json: string; decided_by: string | null; decided_at: string | null;
}

const clean = (v: string, max: number, what: string): string => {
  if (v.length < 1 || v.length > max || /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(v)) {
    throw new EngbrainError("POLICY_REFUSED", `${what} must be 1-${max} characters without control or invisible formatting characters`);
  }
  return v;
};
const OID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;

/** Parses and stores an artifact. Nothing is stored if parsing fails. Everything lands QUARANTINED unless the signature and provenance policy say otherwise. */
export function importEvidence(db: Database.Database, storeDir: string, input: ImportInput, ctx: { actor: Actor; now?: () => Date }): ImportRow {
  requireRole(ctx.actor, "propose");
  if (!EVIDENCE_FORMATS.includes(input.format)) {
    throw new EngbrainError("POLICY_REFUSED", `format must be one of ${EVIDENCE_FORMATS.join(", ")}`);
  }
  if (input.data.length > EVIDENCE_MAX_BYTES) {
    throw new EngbrainError("POLICY_REFUSED", "the artifact is larger than 20 MiB");
  }
  if (input.data.subarray(0, 8192).includes(0)) {
    throw new EngbrainError("POLICY_REFUSED", "the artifact looks binary");
  }
  const artifactName = clean(input.artifactName, 200, "artifact name");
  if (input.revision !== undefined && !OID.test(input.revision)) {
    throw new EngbrainError("POLICY_REFUSED", "revision must be a full commit id");
  }
  const environment: Record<string, string> = {};
  for (const [k, v] of Object.entries(input.environment ?? {}).slice(0, 20)) {
    environment[clean(k, 60, "environment key")] = clean(v, 200, "environment value");
  }
  const command = input.command === undefined ? null : clean(input.command, 300, "command");
  const verifier = input.verifier === undefined ? null : clean(input.verifier, 40, "verifier");
  const tree = input.tree === undefined ? null : clean(input.tree, 100, "tree");
  if (findSecretIn({ environment, command, verifier, artifactName, tree }) !== null) {
    throw new EngbrainError("POLICY_REFUSED", "the provenance fields look like they contain a secret");
  }
  const normalized = parseEvidence(input.format, input.data.toString("utf8"), input.repoRoot === undefined ? {} : { repoRoot: input.repoRoot }); // throws with a clear reason; nothing has been stored yet
  const sha = createHash("sha256").update(input.data).digest("hex");
  const now = (ctx.now ?? (() => new Date()))().toISOString();
  return db.transaction((): ImportRow => {
    const reasons: string[] = [];
    const inLedger = input.revision !== undefined && db.prepare("SELECT 1 FROM git_commits WHERE commit_oid = ? AND ingest_complete = 1 AND published = 1").get(input.revision) !== undefined;
    if (input.revision === undefined) {
      reasons.push("no source revision declared: the artifact cannot be tied to any code");
    } else if (!inLedger) {
      reasons.push("the declared source revision is not in the history ledger (run `engbrain refresh`)");
    }
    if (command === null) {
      reasons.push("no command declared");
    }
    if (Object.keys(environment).length === 0) {
      reasons.push("no environment declared");
    }
    if (verifier === null) {
      reasons.push("no verifier identity declared");
    }
    let signature: "none" | "valid" | "invalid" = "none";
    if (input.signature !== undefined) {
      const policy = loadEvidencePolicy(storeDir);
      const v = policy.verifiers.find((x) => x.id === verifier);
      if (v === undefined || !/^[0-9a-f]{64}$/.test(input.signature)) {
        signature = "invalid";
        reasons.push("a signature was supplied but the verifier is not registered in the provenance policy, or the signature is malformed");
      } else {
        const claim: SignedClaim | null = input.revision !== undefined && command !== null && verifier !== null ? { format: input.format, revision: input.revision, command, environment, verifier } : null;
        signature = claim !== null && timingSafeEqual(Buffer.from(signArtifact(v.keyHex, input.data, claim), "hex"), Buffer.from(input.signature, "hex")) ? "valid" : "invalid";
        if (signature === "invalid") {
          reasons.push("the signature does NOT match the artifact and its declared revision, command, environment, verifier and format: possibly forged, altered or re-labelled");
        }
      }
    } else {
      reasons.push("unsigned");
    }
    const duplicate = db.prepare("SELECT import_id FROM evidence_imports WHERE artifact_sha256 = ? AND format = ? AND source_revision IS ? AND command IS ? AND verifier IS ? AND environment_json = ? AND signature_status = ?")
      .get(sha, input.format, input.revision ?? null, command, verifier, JSON.stringify(environment), signature) as { import_id: string } | undefined;
    if (duplicate !== undefined) {
      throw new EngbrainError("POLICY_REFUSED", `this exact artifact with the same provenance was already imported as ${duplicate.import_id}`);
    }
    const trust: EvidenceTrust = signature === "valid" && inLedger && command !== null && Object.keys(environment).length > 0 ? "signed" : "quarantined";
    const id = `ev_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
    const count = (o: string): number => normalized.results.filter((r) => r.outcome === o).length;
    db.prepare(
      `INSERT INTO evidence_imports (import_id, format, artifact_name, artifact_sha256, artifact_size, source_revision, source_tree, command, environment_json, verifier, signature_status, trust, provenance_json,
         imported_at, imported_by, total, passed, failed, skipped, timed_out, errors, partial, warnings_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(id, input.format, artifactName, sha, input.data.length, input.revision ?? null, tree, command, JSON.stringify(environment), verifier, signature, trust, JSON.stringify(reasons), now, ctx.actor.id,
      normalized.results.length, count("passed"), count("failed"), count("skipped"), count("timed_out"), count("error"), normalized.partial ? 1 : 0, JSON.stringify(normalized.warnings.slice(0, 20)));
    // bind to the files as they are NOW, but only when the declared revision is the one currently indexed on a clean tree (otherwise the binding would be a guess)
    const generationId = currentGenerationId(db);
    const generation = generationId === null ? undefined : db.prepare("SELECT revision FROM generations WHERE id = ?").get(generationId) as { revision: string | null } | undefined;
    const overlay = (db.prepare("SELECT overlay_hash AS o FROM history_checkpoints WHERE ref_key = 'HEAD'").get() as { o: string | null } | undefined)?.o ?? null;
    const bind = (file: string | null): string | null => file === null || generationId === null || input.revision === undefined || generation?.revision !== input.revision || overlay !== null
      ? null : (db.prepare("SELECT content_hash AS h FROM generation_files WHERE generation_id = ? AND path = ? AND content_hash IS NOT NULL").get(generationId, file) as { h: string } | undefined)?.h ?? null;
    const ir = db.prepare("INSERT INTO evidence_results (import_id, ordinal, suite, name, file, outcome, duration_ms, message, file_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
    normalized.results.forEach((r, i) => ir.run(id, i, r.suite, r.name, r.file, r.outcome, r.durationMs, r.message, bind(r.file)));
    const ic = db.prepare("INSERT INTO evidence_coverage (import_id, ordinal, file, test_name, lines_found, lines_hit, hit_lines_json) VALUES (?, ?, ?, ?, ?, ?, ?)");
    normalized.coverage.forEach((c, i) => ic.run(id, i, c.file, c.testName, c.linesFound, c.linesHit, JSON.stringify(c.hitLines)));
    const iff = db.prepare("INSERT INTO evidence_findings (import_id, ordinal, tool, rule, level, file, line, message) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    normalized.findings.forEach((f, i) => iff.run(id, i, f.tool, f.rule, f.level, f.file, f.line, f.message));
    return db.prepare("SELECT * FROM evidence_imports WHERE import_id = ?").get(id) as ImportRow;
  }).immediate();
}

const getImport = (db: Database.Database, id: string): ImportRow => {
  const row = db.prepare("SELECT * FROM evidence_imports WHERE import_id = ?").get(id) as ImportRow | undefined;
  if (row === undefined) {
    throw new EngbrainError("INVALID_ROOT", "no such evidence import");
  }
  return row;
};

/** An operator with the verify role accepts evidence that declares a source revision in the ledger. An artifact whose signature was INVALID can never be accepted. */
export function acceptEvidence(db: Database.Database, id: string, ctx: { actor: Actor; now?: () => Date }): ImportRow {
  requireRole(ctx.actor, "verify");
  return db.transaction((): ImportRow => {
    const row = getImport(db, id);
    if (row.signature_status === "invalid") {
      throw new EngbrainError("POLICY_REFUSED", "this artifact carried an invalid signature: it is treated as forged and cannot be accepted");
    }
    if (row.trust !== "quarantined" && row.trust !== "signed") {
      throw new EngbrainError("POLICY_REFUSED", `only quarantined or signed evidence can be accepted (this is ${row.trust})`);
    }
    if (row.source_revision === null || db.prepare("SELECT 1 FROM git_commits WHERE commit_oid = ? AND ingest_complete = 1 AND published = 1").get(row.source_revision) === undefined) {
      throw new EngbrainError("POLICY_REFUSED", "evidence that is not tied to a revision in the history ledger cannot be accepted");
    }
    db.prepare("UPDATE evidence_imports SET trust = 'accepted', decided_by = ?, decided_at = ? WHERE import_id = ?").run(ctx.actor.id, (ctx.now ?? (() => new Date()))().toISOString(), id);
    return getImport(db, id);
  }).immediate();
}

export function rejectEvidence(db: Database.Database, id: string, ctx: { actor: Actor; now?: () => Date }): ImportRow {
  requireRole(ctx.actor, "verify");
  return db.transaction((): ImportRow => {
    getImport(db, id);
    db.prepare("UPDATE evidence_imports SET trust = 'rejected', decided_by = ?, decided_at = ? WHERE import_id = ?").run(ctx.actor.id, (ctx.now ?? (() => new Date()))().toISOString(), id);
    return getImport(db, id);
  }).immediate();
}

export type EvidenceStanding = "applies" | "stale" | "unknown" | "out_of_scope" | "quarantined" | "rejected";
export interface EvidenceStandingResult { state: EvidenceStanding; reasons: string[] }

/** Whether imported evidence may be relied on NOW. Quarantined and rejected evidence never applies; usable evidence goes stale when its bound files or its environment change, never retroactively. */
export function evidenceStanding(db: Database.Database, row: ImportRow, ctx: EvalContext): EvidenceStandingResult {
  if (row.trust === "rejected") {
    return { state: "rejected", reasons: ["rejected by an operator"] };
  }
  if (row.trust === "quarantined") {
    return { state: "quarantined", reasons: (JSON.parse(row.provenance_json) as string[]).slice(0, 6) };
  }
  if (row.source_revision === null || ctx.checkpoint?.oid == null || !ctx.knownCommit(row.source_revision)) {
    return { state: "unknown", reasons: ["its source revision is not on a known line of history (run `engbrain refresh`)"] };
  }
  if (!(ctx.reachable()?.has(row.source_revision) ?? false)) {
    return { state: "out_of_scope", reasons: ["its source revision is not an ancestor of the current checkpoint (another branch)"] };
  }
  const stale: string[] = [];
  const generationId = currentGenerationId(db);
  const bound = db.prepare("SELECT DISTINCT file, file_hash AS h FROM evidence_results WHERE import_id = ? AND file_hash IS NOT NULL LIMIT 2000").all(row.import_id) as Array<{ file: string; h: string }>;
  for (const b of bound) {
    const current = generationId === null ? undefined : (prep(db, "SELECT content_hash AS h FROM generation_files WHERE generation_id = ? AND path = ? AND content_hash IS NOT NULL").get(generationId, b.file) as { h: string } | undefined)?.h;
    if (current === undefined) {
      stale.push(`${b.file} no longer exists`);
    } else if (current !== b.h) {
      stale.push(`${b.file} changed since this evidence was recorded`);
    }
  }
  // Results that could not be bound to file content at import (the run was for another revision, the tree was dirty, or the result named no file) are only trustworthy while the code is
  // exactly the revision they ran on. Otherwise they are judged by what the ledger recorded as changed since, and a result with no file at all cannot be scoped: it is stale.
  const checkpointRow = prep(db, "SELECT processed_oid AS oid, overlay_hash AS o FROM history_checkpoints WHERE ref_key = 'HEAD'").get() as { oid: string | null; o: string | null } | undefined;
  const atRevision = checkpointRow?.oid === row.source_revision && checkpointRow?.o === null;
  if (!atRevision) {
    const unbound = prep(db, "SELECT DISTINCT file FROM evidence_results WHERE import_id = ? AND file_hash IS NULL LIMIT 2000").all(row.import_id) as Array<{ file: string | null }>;
    if ((unbound.length === 0 && bound.length === 0) || unbound.some((u) => u.file === null)) {
      stale.push("the code is no longer the revision this run used, and some results name no file, so they cannot be scoped to unchanged code");
    } else {
      const moved = new Set(changedPathsSince(db, row.source_revision).paths);
      for (const u of unbound) {
        if (moved.has(u.file!)) {
          stale.push(`${u.file} changed after the revision this run used`);
        }
      }
      if (checkpointRow?.o !== null && checkpointRow?.o !== undefined) {
        stale.push("the working tree has uncommitted changes that this run did not see");
      }
    }
  }
  for (const [k, v] of Object.entries(JSON.parse(row.environment_json) as Record<string, string>)) {
    const current = prep(db, "SELECT value FROM memory_environment WHERE key = ? ORDER BY id DESC LIMIT 1").get(k) as { value: string } | undefined;
    if (current !== undefined && current.value !== v) {
      stale.push(`environment "${k}" is now "${current.value}", the run used "${v}"`);
    }
  }
  return stale.length > 0 ? { state: "stale", reasons: stale.slice(0, 10) } : { state: "applies", reasons: [] };
}

export interface EvidenceSummary {
  id: string; format: string; artifactName: string; artifactSha256: string; sourceRevision: string | null; verifier: string | null; command: string | null; environment: Record<string, string>;
  signature: string; trust: EvidenceTrust; standing: EvidenceStanding; reasons: string[]; counts: { total: number; passed: number; failed: number; skipped: number; timedOut: number; errors: number };
  partial: boolean; warnings: string[]; importedAt: string; importedBy: string; decidedBy: string | null;
}

const summarize = (row: ImportRow, standing: EvidenceStandingResult): EvidenceSummary => ({
  id: row.import_id, format: row.format, artifactName: row.artifact_name, artifactSha256: row.artifact_sha256, sourceRevision: row.source_revision, verifier: row.verifier, command: row.command,
  environment: JSON.parse(row.environment_json) as Record<string, string>, signature: row.signature_status, trust: row.trust, standing: standing.state, reasons: standing.reasons,
  counts: { total: row.total, passed: row.passed, failed: row.failed, skipped: row.skipped, timedOut: row.timed_out, errors: row.errors }, partial: row.partial === 1,
  warnings: JSON.parse(row.warnings_json) as string[], importedAt: row.imported_at, importedBy: row.imported_by, decidedBy: row.decided_by
});

export function listEvidence(db: Database.Database, options: { limit?: number; now?: () => Date } = {}): EvidenceSummary[] {
  const nowIso = (options.now ?? (() => new Date()))().toISOString();
  return db.transaction(() => {
    const ctx = makeEvalContext(db, nowIso);
    return (db.prepare("SELECT * FROM evidence_imports ORDER BY imported_at DESC, import_id LIMIT ?").all(Math.min(Math.max(1, options.limit ?? 50), 200)) as ImportRow[]).map((r) => summarize(r, evidenceStanding(db, r, ctx)));
  })();
}

export interface EvidenceDetail extends EvidenceSummary {
  results: Array<{ suite: string | null; name: string; file: string | null; outcome: string; durationMs: number | null; message: string | null; bound: boolean }>;
  coverage: Array<{ file: string; testName: string | null; linesFound: number; linesHit: number }>;
  findings: Array<{ tool: string | null; rule: string | null; level: string | null; file: string | null; line: number | null; message: string | null }>;
  resultsTruncated: boolean;
}

export function showEvidence(db: Database.Database, id: string, options: { limit?: number; now?: () => Date } = {}): EvidenceDetail | null {
  const nowIso = (options.now ?? (() => new Date()))().toISOString();
  const limit = Math.min(Math.max(1, options.limit ?? 100), 500);
  return db.transaction((): EvidenceDetail | null => {
    const row = db.prepare("SELECT * FROM evidence_imports WHERE import_id = ?").get(id) as ImportRow | undefined;
    if (row === undefined) {
      return null;
    }
    const base = summarize(row, evidenceStanding(db, row, makeEvalContext(db, nowIso)));
    const results = db.prepare("SELECT suite, name, file, outcome, duration_ms AS d, message, file_hash AS h FROM evidence_results WHERE import_id = ? ORDER BY ordinal LIMIT ?").all(id, limit + 1) as Array<{ suite: string | null; name: string; file: string | null; outcome: string; d: number | null; message: string | null; h: string | null }>;
    return {
      ...base, resultsTruncated: results.length > limit,
      results: results.slice(0, limit).map((r) => ({ suite: r.suite, name: r.name, file: r.file, outcome: r.outcome, durationMs: r.d, message: r.message, bound: r.h !== null })),
      coverage: db.prepare("SELECT file, test_name AS testName, lines_found AS linesFound, lines_hit AS linesHit FROM evidence_coverage WHERE import_id = ? ORDER BY ordinal LIMIT ?").all(id, limit) as EvidenceDetail["coverage"],
      findings: db.prepare("SELECT tool, rule, level, file, line, message FROM evidence_findings WHERE import_id = ? ORDER BY ordinal LIMIT ?").all(id, limit) as EvidenceDetail["findings"]
    };
  })();
}

/**
 * Does USABLE evidence that still applies show this test passing? Used to gate `verified` on CI evidence: the memory record must carry an artifact whose sha256 is a signed or accepted,
 * COMPLETE (not partial) import that still applies, in which the named test case of the named file passed (a pointer without a title needs every test of that file to pass).
 */
export function ciEvidenceSupports(db: Database.Database, evidenceJson: string, nowIso: string): boolean {
  const ctx = makeEvalContext(db, nowIso);
  const evidence = JSON.parse(evidenceJson) as { pointers?: Array<{ kind: string; path?: string | null; ref?: string | null }>; artifacts?: Array<{ sha256?: string }> };
  const tests = (evidence.pointers ?? []).filter((p) => p.kind === "test" && typeof p.path === "string").map((p) => ({ path: p.path as string, ref: p.ref ?? null }));
  const artifacts = (evidence.artifacts ?? []).filter((a) => typeof a.sha256 === "string");
  return tests.length > 0 && artifacts.some((a) => {
    const rows = db.prepare("SELECT * FROM evidence_imports WHERE artifact_sha256 = ? AND trust IN ('signed', 'accepted') AND partial = 0").all(a.sha256) as ImportRow[];
    return rows.some((row) => evidenceStanding(db, row, ctx).state === "applies" && tests.every((t) => {
      const where = t.ref === null ? "file = ?" : "name = ? AND file = ?";
      const args = t.ref === null ? [row.import_id, t.path] : [row.import_id, t.ref, t.path];
      const passed = db.prepare(`SELECT COUNT(*) AS n FROM evidence_results WHERE import_id = ? AND outcome = 'passed' AND ${where}`).get(...args) as { n: number };
      const notPassed = db.prepare(`SELECT COUNT(*) AS n FROM evidence_results WHERE import_id = ? AND outcome != 'passed' AND ${where}`).get(...args) as { n: number };
      return passed.n > 0 && notPassed.n === 0; // a skipped, failed, timed-out or errored case of the same name is not a pass
    }));
  });
}

export const VERIFICATION_LIMITS = { imports: 200, resultsPerImport: 200, results: 500 } as const;
export interface VerificationStatus {
  /** Failures and errors first, so truncation can never hide a failing test behind passing ones. */
  usable: Array<{ test: string; file: string | null; outcome: string; import: string; standing: string }>;
  perImport: Array<{ import: string; standing: string; partial: boolean; counts: { total: number; passed: number; failed: number; skipped: number; timedOut: number; errors: number } }>;
  quarantined: number;
  imports: number;
  truncated: boolean;
}

/** Outcomes of signed or accepted evidence, each with the standing of the import it came from; quarantined and rejected imports are only counted. Truncation is stated, never silent. */
export function verificationStatus(db: Database.Database, options: { file?: string; now?: () => Date } = {}): VerificationStatus {
  const nowIso = (options.now ?? (() => new Date()))().toISOString();
  return db.transaction((): VerificationStatus => {
    const ctx = makeEvalContext(db, nowIso);
    const usable: VerificationStatus["usable"] = [];
    const perImport: VerificationStatus["perImport"] = [];
    let truncated = false;
    const total = (db.prepare("SELECT COUNT(*) AS n FROM evidence_imports").get() as { n: number }).n;
    const quarantined = (db.prepare("SELECT COUNT(*) AS n FROM evidence_imports WHERE trust IN ('quarantined', 'rejected')").get() as { n: number }).n;
    const rows = db.prepare("SELECT * FROM evidence_imports WHERE trust IN ('signed', 'accepted') ORDER BY imported_at DESC, import_id LIMIT ?").all(VERIFICATION_LIMITS.imports + 1) as ImportRow[];
    truncated = rows.length > VERIFICATION_LIMITS.imports;
    for (const row of rows.slice(0, VERIFICATION_LIMITS.imports)) {
      const standing = evidenceStanding(db, row, ctx);
      perImport.push({ import: row.import_id, standing: standing.state, partial: row.partial === 1, counts: { total: row.total, passed: row.passed, failed: row.failed, skipped: row.skipped, timedOut: row.timed_out, errors: row.errors } });
      const order = "ORDER BY (outcome = 'passed'), ordinal LIMIT ?";
      const results = (options.file === undefined
        ? db.prepare(`SELECT name, file, outcome FROM evidence_results WHERE import_id = ? ${order}`).all(row.import_id, VERIFICATION_LIMITS.resultsPerImport + 1)
        : db.prepare(`SELECT name, file, outcome FROM evidence_results WHERE import_id = ? AND file = ? ${order}`).all(row.import_id, options.file, VERIFICATION_LIMITS.resultsPerImport + 1)) as Array<{ name: string; file: string | null; outcome: string }>;
      truncated = truncated || results.length > VERIFICATION_LIMITS.resultsPerImport;
      for (const r of results.slice(0, VERIFICATION_LIMITS.resultsPerImport)) {
        usable.push({ test: r.name, file: r.file, outcome: r.outcome, import: row.import_id, standing: standing.state });
      }
    }
    usable.sort((a, b) => Number(a.outcome === "passed") - Number(b.outcome === "passed"));
    truncated = truncated || usable.length > VERIFICATION_LIMITS.results;
    return { usable: usable.slice(0, VERIFICATION_LIMITS.results), perImport, quarantined, imports: total, truncated };
  })();
}
