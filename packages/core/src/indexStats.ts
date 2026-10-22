import type Database from "better-sqlite3";
import { statSync } from "node:fs";
import { CODE_EXTRACTOR_LIKE, supportedCodeExtensions } from "./codeExtractor.js";
import { languageForPath } from "./inventory.js";
import { extname } from "node:path";

export interface ChangedFiles {
  added: number;
  modified: number;
  deleted: number;
  renamed: number;
}

export interface GenerationSummary {
  generationId: number;
  files: { included: number; excluded: number };
  byLanguage: Record<string, number>;
  /** Parser coverage over included files, as recorded by the code extractor of this generation. */
  parser: { ok: number; error: number; skipped: number };
  symbols: number;
  exportedSymbols: number;
  edges: { total: number; byResolution: Record<string, number> };
  diagnostics: number;
  /** Changes relative to the parent generation (null for the first generation). */
  changed: ChangedFiles | null;
}

function one(db: Database.Database, sql: string, ...params: unknown[]): number {
  return Number((db.prepare(sql).get(...params) as { n: number | null }).n ?? 0);
}

export function changedSince(db: Database.Database, parentId: number, generationId: number): ChangedFiles {
  const added = db.prepare(
    `SELECT n.path AS path, n.content_hash AS hash FROM generation_files n
     LEFT JOIN generation_files o ON o.generation_id = ? AND o.path = n.path AND o.content_hash IS NOT NULL
     WHERE n.generation_id = ? AND n.content_hash IS NOT NULL AND o.path IS NULL`
  ).all(parentId, generationId) as Array<{ path: string; hash: string }>;
  const deleted = db.prepare(
    `SELECT o.path AS path, o.content_hash AS hash FROM generation_files o
     LEFT JOIN generation_files n ON n.generation_id = ? AND n.path = o.path AND n.content_hash IS NOT NULL
     WHERE o.generation_id = ? AND o.content_hash IS NOT NULL AND n.path IS NULL`
  ).all(generationId, parentId) as Array<{ path: string; hash: string }>;
  const modified = one(
    db,
    `SELECT COUNT(*) AS n FROM generation_files n JOIN generation_files o ON o.generation_id = ? AND o.path = n.path
     WHERE n.generation_id = ? AND n.content_hash IS NOT NULL AND o.content_hash IS NOT NULL AND n.content_hash != o.content_hash`,
    parentId, generationId
  );
  // a rename = an added path whose content equals a deleted path's content (paired one-to-one)
  const removedByHash = new Map<string, number>();
  for (const d of deleted) {
    removedByHash.set(d.hash, (removedByHash.get(d.hash) ?? 0) + 1);
  }
  let renamed = 0;
  for (const a of added) {
    const left = removedByHash.get(a.hash) ?? 0;
    if (left > 0) {
      removedByHash.set(a.hash, left - 1);
      renamed += 1;
    }
  }
  return { added: added.length - renamed, modified, deleted: deleted.length - renamed, renamed };
}

export function summarizeGeneration(db: Database.Database, generationId: number): GenerationSummary {
  const parent = (db.prepare("SELECT parent_id AS p FROM generations WHERE id = ?").get(generationId) as { p: number | null } | undefined)?.p ?? null;
  // Language labels are derived from the PATH at read time: facts are content-keyed and carry no path-dependent data.
  const byLanguage: Record<string, number> = {};
  const supported = supportedCodeExtensions();
  let unsupported = 0;
  for (const row of db.prepare("SELECT path FROM generation_files WHERE generation_id = ? AND content_hash IS NOT NULL").all(generationId) as Array<{ path: string }>) {
    const key = languageForPath(row.path) ?? "unknown";
    byLanguage[key] = (byLanguage[key] ?? 0) + 1;
    if (!supported.has(extname(row.path).toLowerCase())) {
      unsupported += 1;
    }
  }
  // Parser coverage: files a code extractor APPLIES to are ok or error; every other included file is unsupported (no fact is stored for it).
  const parser = { ok: 0, error: 0, skipped: unsupported };
  const statusRows = db.prepare(
    `SELECT ff.parse_status AS status, COUNT(*) AS n
     FROM applicable_facts af
     JOIN file_facts ff ON ff.content_hash = af.content_hash AND ff.extractor_id = af.extractor_id AND ff.extractor_version = af.extractor_version
     WHERE af.extractor_id LIKE ? AND af.generation_id = ?
     GROUP BY ff.parse_status`
  ).all(CODE_EXTRACTOR_LIKE, generationId) as Array<{ status: "ok" | "error" | "skipped"; n: number }>;
  for (const row of statusRows) {
    if (row.status === "ok" || row.status === "error") {
      parser[row.status] += row.n;
    }
  }
  const edgeRows = db.prepare("SELECT resolution, COUNT(*) AS n FROM module_edges WHERE generation_id = ? GROUP BY resolution").all(generationId) as Array<{ resolution: string; n: number }>;
  const byResolution = Object.fromEntries(edgeRows.map((r) => [r.resolution, r.n]));
  return {
    generationId,
    files: {
      included: one(db, "SELECT COUNT(*) AS n FROM generation_files WHERE generation_id = ? AND content_hash IS NOT NULL", generationId),
      excluded: one(db, "SELECT COUNT(*) AS n FROM generation_files WHERE generation_id = ? AND content_hash IS NULL", generationId)
    },
    byLanguage,
    parser,
    symbols: one(db, "SELECT COUNT(*) AS n FROM symbol_occurrences WHERE generation_id = ? AND kind != 'module' AND extractor_id LIKE 'code:%'", generationId),
    exportedSymbols: one(db, "SELECT COUNT(*) AS n FROM symbol_occurrences WHERE generation_id = ? AND exported = 1 AND extractor_id LIKE 'code:%'", generationId),
    edges: { total: edgeRows.reduce((sum, r) => sum + r.n, 0), byResolution },
    diagnostics: one(
      db,
      `SELECT COUNT(*) AS n FROM applicable_facts af
       JOIN fact_diagnostics fd ON fd.content_hash = af.content_hash AND fd.extractor_id = af.extractor_id AND fd.extractor_version = af.extractor_version
       WHERE af.generation_id = ?`,
      generationId
    ),
    changed: parent === null ? null : changedSince(db, parent, generationId)
  };
}

/** Database size including WAL/SHM, measured from the filesystem (not estimated). */
export function databaseSizeBytes(dbPath: string): number {
  let total = 0;
  for (const suffix of ["", "-wal", "-shm"]) {
    try {
      total += statSync(dbPath + suffix).size;
    } catch {
      // file absent
    }
  }
  return total;
}

/** Peak resident set size of this process in MiB (libuv reports kilobytes on every platform). */
export function peakRssMiB(): number {
  return Math.round(process.resourceUsage().maxRSS / 1024);
}
