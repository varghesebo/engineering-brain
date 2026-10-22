import type Database from "better-sqlite3";
import { createHash } from "node:crypto";
import { EngbrainError } from "../errors.js";
import { sha256Hex } from "../hash.js";

export interface ExtractorRef {
  id: string;
  version: string;
  /** Path suffixes the extractor applies to; omitted = every file. Recorded with the generation (see view `applicable_facts`). */
  extensions?: readonly string[] | undefined;
}

export interface ManifestRow {
  path: string;
  contentHash: string | null;
  size: number | null;
  mtimeNs: string | null;
  ctimeNs: string | null;
  inode: string | null;
  excludedReason: string | null;
}

export type FaultPoint = "pre-facts" | "mid-facts" | "pre-manifest" | "pre-publish" | "mid-publish" | "ledger-pre-batch" | "ledger-mid-batch" | "ledger-post-batch" | "pre-checkpoint";
export type FaultHook = (point: FaultPoint) => void;

export function extractorSetHash(extractors: readonly ExtractorRef[]): string {
  return sha256Hex(extractors.map((e) => `${e.id}@${e.version}:${[...(e.extensions ?? [])].sort().join(",")}`).sort().join("\n"));
}

export function currentGenerationId(db: Database.Database): number | null {
  const row = db.prepare("SELECT current_generation_id AS id FROM store_meta WHERE singleton = 1").get() as { id: number | null } | undefined;
  return row?.id ?? null;
}

export function createBuildingGeneration(
  db: Database.Database,
  input: { parentId: number | null; revision: string | null; branchLabel: string | null; extractors: readonly ExtractorRef[]; resolverVersion?: string | null; now: Date }
): number {
  return db.transaction(() => {
    const result = db
      .prepare(
        `INSERT INTO generations (parent_id, revision, branch_label, extractor_set_hash, status, created_at, resolver_version)
         VALUES (?, ?, ?, ?, 'building', ?, ?)`
      )
      .run(input.parentId, input.revision, input.branchLabel, extractorSetHash(input.extractors), input.now.toISOString(), input.resolverVersion ?? null);
    const id = Number(result.lastInsertRowid);
    const insert = db.prepare("INSERT INTO generation_extractors (generation_id, extractor_id, extractor_version) VALUES (?, ?, ?)");
    const insertExtension = db.prepare("INSERT INTO generation_extractor_extensions (generation_id, extractor_id, extractor_version, extension) VALUES (?, ?, ?, ?)");
    for (const extractor of input.extractors) {
      insert.run(id, extractor.id, extractor.version);
      for (const extension of extractor.extensions ?? []) {
        insertExtension.run(id, extractor.id, extractor.version, extension);
      }
    }
    return id;
  }).immediate();
}

export function insertManifest(db: Database.Database, generationId: number, rows: readonly ManifestRow[]): void {
  const insert = db.prepare(
    `INSERT INTO generation_files (generation_id, path, content_hash, size, mtime_ns, ctime_ns, inode, excluded_reason)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  );
  db.transaction(() => {
    for (const row of rows) {
      insert.run(generationId, row.path, row.contentHash, row.size, row.mtimeNs, row.ctimeNs, row.inode, row.excludedReason);
    }
  }).immediate();
}

/**
 * Hash over the whole manifest, in database (binary) order. Two checkouts at the same commit with different
 * uncommitted code get different fingerprints. Always computed from the database so build and validate agree.
 */
export function computeSourceFingerprint(db: Database.Database, generationId: number): string {
  const rows = db
    .prepare("SELECT path, content_hash AS hash, excluded_reason AS reason FROM generation_files WHERE generation_id = ? ORDER BY path")
    .iterate(generationId) as IterableIterator<{ path: string; hash: string | null; reason: string | null }>;
  const hasher = createHash("sha256");
  for (const row of rows) {
    hasher.update(`${row.path}\0${row.hash ?? `!${row.reason ?? ""}`}\n`);
  }
  return hasher.digest("hex");
}

/** Applicable (path, extractor) pairs of the generation that have no fact: a file must be covered by every extractor that applies to it. */
function missingFactCount(db: Database.Database, generationId: number): number {
  return (db.prepare(
    `SELECT COUNT(*) AS n FROM applicable_facts af
     WHERE af.generation_id = ?
       AND NOT EXISTS (
         SELECT 1 FROM file_facts ff
         WHERE ff.content_hash = af.content_hash AND ff.extractor_id = af.extractor_id AND ff.extractor_version = af.extractor_version
       )`
  ).get(generationId) as { n: number }).n;
}

export interface ValidationResult {
  ok: boolean;
  problems: string[];
}

/** Checks a generation is internally complete before it may be published (and powers `status --check`). */
/**
 * `deep` (default) also runs SQLite's whole-database `foreign_key_check` and `quick_check`. Publication passes `deep: false`: foreign keys
 * are enforced at write time and the generation-specific checks below (fact coverage, edge counts, fingerprint) always run; the deep checks
 * scan the entire file (seconds on a large store), so they belong to `status --check`.
 */
export function validateGeneration(db: Database.Database, generationId: number, expectedFingerprint?: string, options: { deep?: boolean } = {}): ValidationResult {
  const problems: string[] = [];
  const row = db.prepare("SELECT status, source_fingerprint AS fp FROM generations WHERE id = ?").get(generationId) as
    | { status: string; fp: string | null }
    | undefined;
  if (row === undefined) {
    return { ok: false, problems: ["generation does not exist"] };
  }
  const missing = missingFactCount(db, generationId);
  if (missing > 0) {
    problems.push(`${missing} manifest entries lack facts`);
  }
  const resolver = (db.prepare("SELECT resolver_version AS v FROM generations WHERE id = ?").get(generationId) as { v: string | null }).v;
  if (resolver !== null) {
    const refs = db
      .prepare(
        `SELECT COUNT(*) AS n FROM applicable_facts af
         JOIN syntax_refs sr ON sr.content_hash = af.content_hash AND sr.extractor_id = af.extractor_id AND sr.extractor_version = af.extractor_version
         WHERE af.generation_id = ?`
      )
      .get(generationId) as { n: number };
    const edges = db.prepare("SELECT COUNT(*) AS n FROM graph_edges WHERE generation_id = ? AND family = 'module'").get(generationId) as { n: number };
    if (refs.n !== edges.n) {
      problems.push(`module edges (${edges.n}) do not match syntactic references (${refs.n})`);
    }
  }
  const fingerprint = computeSourceFingerprint(db, generationId);
  const expected = expectedFingerprint ?? row.fp;
  if (expected !== null && expected !== undefined && expected !== fingerprint) {
    problems.push("manifest fingerprint does not match");
  }
  if (options.deep !== false) {
    const fkViolations = db.pragma("foreign_key_check") as unknown[];
    if (fkViolations.length > 0) {
      problems.push(`${fkViolations.length} foreign key violations`);
    }
    const quick = db.pragma("quick_check", { simple: true });
    if (quick !== "ok") {
      problems.push("sqlite quick_check failed");
    }
  }
  return { ok: problems.length === 0, problems };
}

/**
 * Publication is ONE transaction: the generation becomes complete and store_meta points at it together.
 * Readers (WAL snapshots) see the old or the new generation entirely, never a mixture. A crash before commit
 * leaves the previous generation current and the new one `building` (abandoned on next recovery).
 */
export function publishGeneration(
  db: Database.Database,
  generationId: number,
  input: { fingerprint: string; now: Date; fault?: FaultHook | undefined; /** Runs inside the publication transaction, so its writes commit or roll back together with it. */ inTransaction?: ((db: Database.Database) => void) | undefined }
): void {
  db.transaction(() => {
    const stamp = input.now.toISOString();
    const updated = db
      .prepare(
        `UPDATE generations SET status = 'complete', source_fingerprint = ?, completed_at = ?, hash_verified_at = ?
         WHERE id = ? AND status = 'building'`
      )
      .run(input.fingerprint, stamp, stamp, generationId);
    if (updated.changes !== 1) {
      throw new EngbrainError("INTEGRITY_FAILED", "generation is not in the building state");
    }
    input.fault?.("mid-publish");
    db.prepare("UPDATE store_meta SET current_generation_id = ? WHERE singleton = 1").run(generationId);
    input.fault?.("pre-checkpoint");
    input.inTransaction?.(db);
  }).immediate();
}

/** Marks generations left `building` by a crashed run as abandoned. Caller must hold the writer lock. */
export function markAbandoned(db: Database.Database): number {
  return db.prepare("UPDATE generations SET status = 'abandoned' WHERE status = 'building'").run().changes;
}

export function discardGeneration(db: Database.Database, generationId: number): void {
  db.prepare("DELETE FROM generations WHERE id = ? AND status = 'building'").run(generationId);
}

export interface SnapshotInfo {
  generationId: number;
  revision: string | null;
  branchLabel: string | null;
  sourceFingerprint: string | null;
  completedAt: string | null;
  includedFiles: number;
  excludedFiles: number;
}

/** Reads the current generation's summary inside one read transaction (consistent WAL snapshot). */
export function readCurrentSnapshot(db: Database.Database): SnapshotInfo | null {
  return db.transaction((): SnapshotInfo | null => {
    const id = currentGenerationId(db);
    if (id === null) {
      return null;
    }
    const gen = db
      .prepare("SELECT revision, branch_label AS branch, source_fingerprint AS fp, completed_at AS done FROM generations WHERE id = ?")
      .get(id) as { revision: string | null; branch: string | null; fp: string | null; done: string | null };
    const counts = db
      .prepare(
        `SELECT SUM(content_hash IS NOT NULL) AS inc, SUM(content_hash IS NULL) AS exc FROM generation_files WHERE generation_id = ?`
      )
      .get(id) as { inc: number | null; exc: number | null };
    return {
      generationId: id,
      revision: gen.revision,
      branchLabel: gen.branch,
      sourceFingerprint: gen.fp,
      completedAt: gen.done,
      includedFiles: counts.inc ?? 0,
      excludedFiles: counts.exc ?? 0
    };
  })();
}
