import type Database from "better-sqlite3";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { EngbrainError } from "../errors.js";

export interface Migration {
  version: number;
  name: string;
  /** Runs inside a transaction. Forward-only: there are no down migrations (restore the pre-migration backup instead). */
  up(db: Database.Database): void;
}

/**
 * v1 holds only what Foundation uses. symbols / syntax_refs / resolutions / evidence arrive as later
 * migrations with the stages that need them (no tables built "just in case").
 */
const SCHEMA_V1 = `
CREATE TABLE generations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  parent_id INTEGER REFERENCES generations(id) ON DELETE SET NULL,
  revision TEXT,
  branch_label TEXT,
  source_fingerprint TEXT,
  extractor_set_hash TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('building', 'complete', 'abandoned')),
  created_at TEXT NOT NULL,
  completed_at TEXT,
  hash_verified_at TEXT
);

CREATE TABLE store_meta (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  install_id TEXT NOT NULL,
  repository_id TEXT NOT NULL,
  worktree_id TEXT NOT NULL,
  root_realpath TEXT NOT NULL,
  history_key TEXT,
  current_generation_id INTEGER REFERENCES generations(id),
  created_at TEXT NOT NULL
);

CREATE TABLE generation_extractors (
  generation_id INTEGER NOT NULL REFERENCES generations(id) ON DELETE CASCADE,
  extractor_id TEXT NOT NULL,
  extractor_version TEXT NOT NULL,
  PRIMARY KEY (generation_id, extractor_id, extractor_version)
) WITHOUT ROWID;

CREATE TABLE generation_files (
  generation_id INTEGER NOT NULL REFERENCES generations(id) ON DELETE CASCADE,
  path TEXT NOT NULL,
  content_hash TEXT,
  size INTEGER,
  mtime_ns TEXT,
  ctime_ns TEXT,
  inode TEXT,
  excluded_reason TEXT,
  PRIMARY KEY (generation_id, path),
  CHECK ((content_hash IS NULL) = (excluded_reason IS NOT NULL))
) WITHOUT ROWID;
CREATE INDEX idx_generation_files_hash ON generation_files(content_hash);

CREATE TABLE file_facts (
  content_hash TEXT NOT NULL,
  extractor_id TEXT NOT NULL,
  extractor_version TEXT NOT NULL,
  language TEXT,
  parse_status TEXT NOT NULL CHECK (parse_status IN ('ok', 'error', 'skipped')),
  attrs_json TEXT,
  PRIMARY KEY (content_hash, extractor_id, extractor_version)
) WITHOUT ROWID;

-- Invariants enforced by the database itself, not only by application code.
CREATE TRIGGER store_meta_current_must_be_complete
BEFORE UPDATE OF current_generation_id ON store_meta
WHEN NEW.current_generation_id IS NOT NULL
 AND (SELECT status FROM generations WHERE id = NEW.current_generation_id) IS NOT 'complete'
BEGIN
  SELECT RAISE(ABORT, 'current generation must be complete');
END;

CREATE TRIGGER generation_complete_is_terminal
BEFORE UPDATE OF status ON generations
WHEN OLD.status = 'complete' AND NEW.status IS NOT 'complete'
BEGIN
  SELECT RAISE(ABORT, 'a complete generation cannot change status');
END;

CREATE TRIGGER generation_files_insert_only_while_building
BEFORE INSERT ON generation_files
WHEN (SELECT status FROM generations WHERE id = NEW.generation_id) IS NOT 'building'
BEGIN
  SELECT RAISE(ABORT, 'manifest is writable only while its generation is building');
END;

CREATE TRIGGER generation_files_immutable_update
BEFORE UPDATE ON generation_files
BEGIN
  SELECT RAISE(ABORT, 'manifest rows are immutable');
END;

CREATE TRIGGER generation_extractors_insert_only_while_building
BEFORE INSERT ON generation_extractors
WHEN (SELECT status FROM generations WHERE id = NEW.generation_id) IS NOT 'building'
BEGIN
  SELECT RAISE(ABORT, 'extractor set is writable only while its generation is building');
END;
`;

export const MIGRATIONS: readonly Migration[] = [
  { version: 1, name: "foundation schema", up: (db) => db.exec(SCHEMA_V1) }
];

export interface MigrationResult {
  from: number;
  to: number;
  backupPath: string | null;
}

export function latestVersion(migrations: readonly Migration[] = MIGRATIONS): number {
  return migrations.reduce((max, migration) => Math.max(max, migration.version), 0);
}

export function currentVersion(db: Database.Database): number {
  return Number(db.pragma("user_version", { simple: true }));
}

/**
 * Forward-only migrations. A store from a NEWER engbrain is refused (no downgrade). Before upgrading a store
 * that already has a schema, a consistent backup is written with VACUUM INTO (rollback = restore that file).
 */
export function applyMigrations(
  db: Database.Database,
  options: { backupDir: string; migrations?: readonly Migration[]; now?: () => Date }
): MigrationResult {
  const migrations = [...(options.migrations ?? MIGRATIONS)].sort((a, b) => a.version - b.version);
  const target = latestVersion(migrations);
  const from = currentVersion(db);
  if (from > target) {
    throw new EngbrainError(
      "STORE_NEWER_SCHEMA",
      `store schema v${from} is newer than this engbrain supports (v${target}); upgrade engbrain, downgrades are not supported`
    );
  }
  if (from === target) {
    return { from, to: target, backupPath: null };
  }
  let backupPath: string | null = null;
  if (from > 0) {
    mkdirSync(options.backupDir, { recursive: true, mode: 0o700 });
    const stamp = (options.now ?? (() => new Date()))().toISOString().replace(/[:.]/g, "-");
    backupPath = join(options.backupDir, `store-v${from}-${stamp}.db`);
    db.prepare("VACUUM INTO ?").run(backupPath);
  }
  for (const migration of migrations) {
    if (migration.version <= from) {
      continue;
    }
    db.transaction(() => {
      migration.up(db);
      db.pragma(`user_version = ${migration.version}`);
    }).immediate();
  }
  return { from, to: target, backupPath };
}
