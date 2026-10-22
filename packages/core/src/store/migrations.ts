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

/**
 * v2 (Phase 2A): content-derived code facts. Keyed by the same immutable fact key as `file_facts` and cascade with it.
 * Nothing here contains a file path: where a file lives is the generation manifest's business, so identical bytes share facts.
 */
const SCHEMA_V2 = `
CREATE TABLE symbols (
  content_hash TEXT NOT NULL,
  extractor_id TEXT NOT NULL,
  extractor_version TEXT NOT NULL,
  local_id INTEGER NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('module', 'namespace', 'function', 'class', 'constructor', 'method', 'interface', 'type', 'enum', 'variable')),
  name TEXT NOT NULL,
  qualified_name TEXT NOT NULL,
  parent_local_id INTEGER,
  symbol_key TEXT NOT NULL,
  start_line INTEGER NOT NULL,
  start_col INTEGER NOT NULL,
  end_line INTEGER NOT NULL,
  end_col INTEGER NOT NULL,
  start_byte INTEGER NOT NULL,
  end_byte INTEGER NOT NULL,
  signature_fingerprint TEXT,
  exported INTEGER NOT NULL CHECK (exported IN (0, 1)),
  export_name TEXT,
  anonymous INTEGER NOT NULL CHECK (anonymous IN (0, 1)),
  parameters_json TEXT,
  PRIMARY KEY (content_hash, extractor_id, extractor_version, local_id),
  FOREIGN KEY (content_hash, extractor_id, extractor_version) REFERENCES file_facts (content_hash, extractor_id, extractor_version) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE INDEX idx_symbols_name ON symbols(name);
CREATE INDEX idx_symbols_key ON symbols(symbol_key);

CREATE TABLE syntax_refs (
  content_hash TEXT NOT NULL,
  extractor_id TEXT NOT NULL,
  extractor_version TEXT NOT NULL,
  local_id INTEGER NOT NULL,
  ref_kind TEXT NOT NULL CHECK (ref_kind IN ('import', 'export_from', 'require', 'dynamic_import')),
  target_text TEXT,
  names_json TEXT,
  line INTEGER NOT NULL,
  PRIMARY KEY (content_hash, extractor_id, extractor_version, local_id),
  FOREIGN KEY (content_hash, extractor_id, extractor_version) REFERENCES file_facts (content_hash, extractor_id, extractor_version) ON DELETE CASCADE
) WITHOUT ROWID;

CREATE TABLE exports (
  content_hash TEXT NOT NULL,
  extractor_id TEXT NOT NULL,
  extractor_version TEXT NOT NULL,
  local_id INTEGER NOT NULL,
  export_kind TEXT NOT NULL CHECK (export_kind IN ('named', 'default', 'reexport', 'reexport_all', 'reexport_namespace', 'commonjs')),
  export_name TEXT,
  local_name TEXT,
  symbol_local_id INTEGER,
  source_text TEXT,
  line INTEGER NOT NULL,
  PRIMARY KEY (content_hash, extractor_id, extractor_version, local_id),
  FOREIGN KEY (content_hash, extractor_id, extractor_version) REFERENCES file_facts (content_hash, extractor_id, extractor_version) ON DELETE CASCADE
) WITHOUT ROWID;

CREATE TABLE symbol_relations (
  content_hash TEXT NOT NULL,
  extractor_id TEXT NOT NULL,
  extractor_version TEXT NOT NULL,
  local_id INTEGER NOT NULL,
  symbol_local_id INTEGER NOT NULL,
  relation TEXT NOT NULL CHECK (relation IN ('extends', 'implements')),
  target_text TEXT,
  line INTEGER NOT NULL,
  PRIMARY KEY (content_hash, extractor_id, extractor_version, local_id),
  FOREIGN KEY (content_hash, extractor_id, extractor_version) REFERENCES file_facts (content_hash, extractor_id, extractor_version) ON DELETE CASCADE
) WITHOUT ROWID;

CREATE TABLE symbol_refs (
  content_hash TEXT NOT NULL,
  extractor_id TEXT NOT NULL,
  extractor_version TEXT NOT NULL,
  local_id INTEGER NOT NULL,
  symbol_local_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  line INTEGER NOT NULL,
  PRIMARY KEY (content_hash, extractor_id, extractor_version, local_id),
  FOREIGN KEY (content_hash, extractor_id, extractor_version) REFERENCES file_facts (content_hash, extractor_id, extractor_version) ON DELETE CASCADE
) WITHOUT ROWID;

CREATE TABLE fact_diagnostics (
  content_hash TEXT NOT NULL,
  extractor_id TEXT NOT NULL,
  extractor_version TEXT NOT NULL,
  local_id INTEGER NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('error', 'warning', 'info')),
  code TEXT NOT NULL,
  message TEXT NOT NULL,
  line INTEGER NOT NULL,
  col INTEGER NOT NULL,
  PRIMARY KEY (content_hash, extractor_id, extractor_version, local_id),
  FOREIGN KEY (content_hash, extractor_id, extractor_version) REFERENCES file_facts (content_hash, extractor_id, extractor_version) ON DELETE CASCADE
) WITHOUT ROWID;
`;

/** v3 (Phase 2A): path-dependent module relationships and extractor applicability, scoped to the generation that recorded them. */
const SCHEMA_V3 = `
ALTER TABLE generations ADD COLUMN resolver_version TEXT;

-- Which path suffixes each extractor of a generation applies to (no rows = applies to every file). Facts are keyed by content only,
-- so this is what stops a file the extractor does not apply to from "inheriting" facts of an identical-bytes file elsewhere.
CREATE TABLE generation_extractor_extensions (
  generation_id INTEGER NOT NULL REFERENCES generations(id) ON DELETE CASCADE,
  extractor_id TEXT NOT NULL,
  extractor_version TEXT NOT NULL,
  extension TEXT NOT NULL,
  PRIMARY KEY (generation_id, extractor_id, extractor_version, extension)
) WITHOUT ROWID;

-- The ONE place a path is joined to facts: (generation, path, content, extractor) for every extractor that applies to that path.
CREATE VIEW applicable_facts AS
SELECT gf.generation_id AS generation_id, gf.path AS path, gf.content_hash AS content_hash, ge.extractor_id AS extractor_id, ge.extractor_version AS extractor_version
FROM generation_files gf
JOIN generation_extractors ge ON ge.generation_id = gf.generation_id
WHERE gf.content_hash IS NOT NULL
  AND (
    NOT EXISTS (SELECT 1 FROM generation_extractor_extensions x WHERE x.generation_id = ge.generation_id AND x.extractor_id = ge.extractor_id AND x.extractor_version = ge.extractor_version)
    OR EXISTS (SELECT 1 FROM generation_extractor_extensions x WHERE x.generation_id = ge.generation_id AND x.extractor_id = ge.extractor_id AND x.extractor_version = ge.extractor_version
               AND substr(lower(gf.path), -length(x.extension)) = x.extension)
  );

-- A symbol OCCURRENCE is a content-derived symbol seen at a path in a generation (only where the extractor applies to the path).
CREATE VIEW symbol_occurrences AS
SELECT af.generation_id AS generation_id, af.path AS path, s.*
FROM applicable_facts af
JOIN symbols s ON s.content_hash = af.content_hash AND s.extractor_id = af.extractor_id AND s.extractor_version = af.extractor_version;

-- The generation-scoped graph. Content-derived structure (CONTAINS / DEFINES / EXPORTS) is NOT stored here: it is served from the
-- facts, so nothing is copied per generation. Path-dependent edges are materialised once per generation and never updated.
CREATE TABLE graph_edges (
  generation_id INTEGER NOT NULL REFERENCES generations(id) ON DELETE CASCADE,
  edge_id INTEGER NOT NULL,
  family TEXT NOT NULL CHECK (family IN ('module', 'symbol', 'package')),
  edge_kind TEXT NOT NULL CHECK (edge_kind IN ('CONTAINS', 'DEFINES', 'IMPORTS', 'EXPORTS', 'RE_EXPORTS', 'REFERENCES', 'EXTENDS', 'IMPLEMENTS', 'DEPENDS_ON', 'CALLS')),
  import_style TEXT CHECK (import_style IN ('import', 'export_from', 'require', 'dynamic_import')),
  ordinal INTEGER NOT NULL,
  src_kind TEXT NOT NULL CHECK (src_kind IN ('package', 'file', 'symbol')),
  src_path TEXT NOT NULL,
  src_symbol TEXT,
  dst_kind TEXT NOT NULL CHECK (dst_kind IN ('package', 'file', 'symbol', 'external', 'unknown')),
  dst_path TEXT,
  dst_symbol TEXT,
  dst_name TEXT,
  dst_package TEXT,
  mechanism TEXT NOT NULL CHECK (mechanism IN ('tree_sitter_syntax', 'scip', 'compiler', 'observed', 'inferred')),
  resolution TEXT NOT NULL CHECK (resolution IN ('resolved', 'external', 'unresolved', 'ambiguous', 'dynamic', 'syntactic_only')),
  reason TEXT NOT NULL,
  start_line INTEGER,
  end_line INTEGER,
  extractor TEXT NOT NULL,
  detail TEXT,
  PRIMARY KEY (generation_id, edge_id)
) WITHOUT ROWID;
CREATE INDEX idx_graph_edges_src ON graph_edges(generation_id, src_path, src_symbol, edge_kind);
CREATE INDEX idx_graph_edges_dst ON graph_edges(generation_id, dst_path, dst_symbol, edge_kind);
CREATE INDEX idx_graph_edges_module ON graph_edges(generation_id, family, src_path, ordinal);
CREATE INDEX idx_graph_edges_external ON graph_edges(generation_id, dst_package) WHERE dst_package IS NOT NULL;

CREATE TABLE graph_packages (
  generation_id INTEGER NOT NULL REFERENCES generations(id) ON DELETE CASCADE,
  dir TEXT NOT NULL,
  name TEXT NOT NULL,
  PRIMARY KEY (generation_id, dir)
) WITHOUT ROWID;

CREATE TRIGGER graph_edges_insert_only_while_building
BEFORE INSERT ON graph_edges
WHEN (SELECT status FROM generations WHERE id = NEW.generation_id) IS NOT 'building'
BEGIN
  SELECT RAISE(ABORT, 'graph edges are writable only while their generation is building');
END;

CREATE TRIGGER graph_edges_immutable_update
BEFORE UPDATE ON graph_edges
BEGIN
  SELECT RAISE(ABORT, 'graph edges are immutable');
END;

CREATE TRIGGER graph_packages_insert_only_while_building
BEFORE INSERT ON graph_packages
WHEN (SELECT status FROM generations WHERE id = NEW.generation_id) IS NOT 'building'
BEGIN
  SELECT RAISE(ABORT, 'graph packages are writable only while their generation is building');
END;

-- 2A's module relationships are the module family of the graph, kept under their original name and columns.
CREATE VIEW module_edges AS
SELECT generation_id, src_path AS from_path, ordinal, import_style AS edge_kind, dst_name AS specifier, dst_path AS resolved_path, resolution, reason, start_line AS line
FROM graph_edges WHERE family = 'module';

-- Node view for ad-hoc SQL and validation (traversals use the indexed edge columns directly).
CREATE VIEW graph_nodes AS
SELECT generation_id, 'pkg:' || dir AS node_key, 'package' AS kind, name, dir AS path, NULL AS symbol_key FROM graph_packages
UNION ALL
SELECT generation_id, 'file:' || path, 'file', path, path, NULL FROM generation_files WHERE content_hash IS NOT NULL
UNION ALL
SELECT generation_id, 'sym:' || path || '#' || symbol_key, kind, qualified_name, path, symbol_key FROM symbol_occurrences WHERE kind != 'module'
UNION ALL
SELECT DISTINCT generation_id, 'ext:' || dst_package, 'external', dst_package, NULL, NULL FROM graph_edges WHERE dst_kind = 'external' AND dst_package IS NOT NULL;
`;

/**
 * v4 (Phase H1): the Git commit ledger. Git is the source of commit identity; content hashes + extractor versions identify parsed facts.
 * Commit metadata (subject) is UNTRUSTED description, stored truncated, never evidence. Nothing here is generation-scoped: ledger rows are facts about
 * Git objects and stay valid whichever branch is checked out; what a reader may SEE is bounded by `history_checkpoints.processed_oid`.
 */
const SCHEMA_V4 = `
CREATE TABLE git_commits (
  commit_oid TEXT PRIMARY KEY,
  object_format TEXT NOT NULL CHECK (object_format IN ('sha1', 'sha256')),
  tree_oid TEXT NOT NULL,
  author_time INTEGER,
  committer_time INTEGER,
  availability TEXT NOT NULL CHECK (availability IN ('full', 'shallow_boundary', 'oversized')),
  subject TEXT NOT NULL,
  changes_truncated INTEGER NOT NULL DEFAULT 0 CHECK (changes_truncated IN (0, 1)),
  ingest_complete INTEGER NOT NULL DEFAULT 0 CHECK (ingest_complete IN (0, 1)),
  /** 1 once a refresh that covers this commit has PUBLISHED; ledger rows of an unpublished or failed run are never visible to readers. */
  published INTEGER NOT NULL DEFAULT 0 CHECK (published IN (0, 1)),
  first_run_id INTEGER
);

CREATE TABLE commit_parents (
  commit_oid TEXT NOT NULL REFERENCES git_commits(commit_oid) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  parent_oid TEXT NOT NULL,
  PRIMARY KEY (commit_oid, ordinal)
) WITHOUT ROWID;
CREATE INDEX idx_commit_parents_parent ON commit_parents(parent_oid);

CREATE TABLE blob_hashes (
  blob_oid TEXT PRIMARY KEY,
  object_format TEXT NOT NULL,
  content_hash TEXT,
  size INTEGER,
  excluded_reason TEXT,
  CHECK ((content_hash IS NULL) != (excluded_reason IS NULL))
);

CREATE TABLE commit_changes (
  commit_oid TEXT NOT NULL REFERENCES git_commits(commit_oid) ON DELETE CASCADE,
  parent_ordinal INTEGER NOT NULL,
  path TEXT NOT NULL,
  old_path TEXT,
  change_kind TEXT NOT NULL CHECK (change_kind IN ('added', 'modified', 'deleted', 'renamed', 'copied', 'type_changed')),
  old_blob TEXT,
  new_blob TEXT,
  old_content_hash TEXT,
  new_content_hash TEXT,
  rename_score INTEGER,
  excluded_reason TEXT,
  PRIMARY KEY (commit_oid, parent_ordinal, path)
) WITHOUT ROWID;
CREATE INDEX idx_commit_changes_new_hash ON commit_changes(new_content_hash) WHERE new_content_hash IS NOT NULL;
CREATE INDEX idx_commit_changes_old_hash ON commit_changes(old_content_hash) WHERE old_content_hash IS NOT NULL;

CREATE TABLE commit_symbol_deltas (
  commit_oid TEXT NOT NULL REFERENCES git_commits(commit_oid) ON DELETE CASCADE,
  parent_ordinal INTEGER NOT NULL,
  path TEXT NOT NULL,
  delta TEXT NOT NULL CHECK (delta IN ('added', 'removed', 'signature_changed')),
  kind TEXT NOT NULL,
  name TEXT NOT NULL,
  qualified_name TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  signature_fingerprint TEXT,
  candidate_rename_of TEXT,
  PRIMARY KEY (commit_oid, parent_ordinal, path, delta, kind, qualified_name, ordinal)
) WITHOUT ROWID;

CREATE TABLE refresh_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ref_key TEXT NOT NULL,
  from_oid TEXT,
  to_oid TEXT,
  history_mode TEXT NOT NULL CHECK (history_mode IN ('none', 'backfill')),
  status TEXT NOT NULL CHECK (status IN ('running', 'complete', 'failed', 'cancelled')),
  generation_id INTEGER,
  overlay_hash TEXT,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  stats_json TEXT
);

CREATE TABLE history_checkpoints (
  ref_key TEXT PRIMARY KEY,
  processed_oid TEXT,
  generation_id INTEGER,
  run_id INTEGER,
  history_partial INTEGER NOT NULL CHECK (history_partial IN (0, 1)),
  overlay_hash TEXT,
  branch_label TEXT,
  updated_at TEXT NOT NULL
);

CREATE TABLE lineage_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER NOT NULL,
  ref_key TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('baseline', 'advance', 'switch', 'rewrite', 'unrelated', 'head_unborn', 'base_missing')),
  old_oid TEXT,
  new_oid TEXT,
  fork_oid TEXT,
  detail_json TEXT,
  observed_at TEXT NOT NULL
);
`;

/**
 * v5 (Phase H2): the feature/capability graph. `fact_entities` holds RAW content-derived detections (no paths, keyed like every fact). The generation-scoped tables
 * hold what the builder made of them for one snapshot (entities with provenance and certainty, edges, coverage gaps, discovered feature flows, feature lineage) and
 * are insert-only while their generation is building. `feature_claims` holds proposed/approved statements: it is versioned by evidence fingerprint, not generation.
 */
const FEATURE_TABLES = ["feature_entities", "feature_edges", "feature_gaps", "features", "feature_members", "feature_lineage"] as const;
const featureTriggers = FEATURE_TABLES.map((table) => `
CREATE TRIGGER ${table}_insert_only_while_building
BEFORE INSERT ON ${table}
WHEN (SELECT status FROM generations WHERE id = NEW.generation_id) IS NOT 'building'
BEGIN
  SELECT RAISE(ABORT, '${table} is writable only while its generation is building');
END;
CREATE TRIGGER ${table}_immutable_update
BEFORE UPDATE ON ${table}
WHEN (SELECT status FROM generations WHERE id = OLD.generation_id) IS NOT 'building'
BEGIN
  SELECT RAISE(ABORT, '${table} is immutable once its generation is published');
END;`).join("\n");

const SCHEMA_V5 = `
CREATE TABLE fact_entities (
  content_hash TEXT NOT NULL,
  extractor_id TEXT NOT NULL,
  extractor_version TEXT NOT NULL,
  local_id INTEGER NOT NULL,
  role TEXT NOT NULL,
  kind TEXT NOT NULL,
  key TEXT,
  name TEXT NOT NULL,
  method TEXT,
  target TEXT,
  dynamic INTEGER NOT NULL CHECK (dynamic IN (0, 1)),
  receiver TEXT,
  handler TEXT,
  start_line INTEGER NOT NULL,
  end_line INTEGER NOT NULL,
  attrs_json TEXT,
  PRIMARY KEY (content_hash, extractor_id, extractor_version, local_id),
  FOREIGN KEY (content_hash, extractor_id, extractor_version) REFERENCES file_facts (content_hash, extractor_id, extractor_version) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE INDEX idx_fact_entities_role ON fact_entities(role);

CREATE TABLE feature_entities (
  generation_id INTEGER NOT NULL REFERENCES generations(id) ON DELETE CASCADE,
  entity_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  role TEXT NOT NULL,
  key TEXT,
  name TEXT NOT NULL,
  path TEXT,
  start_line INTEGER,
  end_line INTEGER,
  package_dir TEXT,
  mechanism TEXT NOT NULL,
  certainty TEXT NOT NULL,
  trust TEXT NOT NULL,
  content_hash TEXT,
  extractor TEXT,
  valid_from_generation INTEGER NOT NULL,
  attrs_json TEXT,
  PRIMARY KEY (generation_id, entity_id)
) WITHOUT ROWID;
CREATE INDEX idx_feature_entities_path ON feature_entities(generation_id, path);
CREATE INDEX idx_feature_entities_kind_key ON feature_entities(generation_id, kind, key);

CREATE TABLE feature_edges (
  generation_id INTEGER NOT NULL REFERENCES generations(id) ON DELETE CASCADE,
  edge_id INTEGER NOT NULL,
  src_entity TEXT NOT NULL,
  dst_entity TEXT NOT NULL,
  relation TEXT NOT NULL,
  certainty TEXT NOT NULL,
  mechanism TEXT NOT NULL,
  reason TEXT NOT NULL,
  evidence_path TEXT,
  evidence_line INTEGER,
  attrs_json TEXT,
  PRIMARY KEY (generation_id, edge_id)
) WITHOUT ROWID;
CREATE INDEX idx_feature_edges_src ON feature_edges(generation_id, src_entity);
CREATE INDEX idx_feature_edges_dst ON feature_edges(generation_id, dst_entity);

CREATE TABLE feature_gaps (
  generation_id INTEGER NOT NULL REFERENCES generations(id) ON DELETE CASCADE,
  gap_id INTEGER NOT NULL,
  kind TEXT NOT NULL,
  entity_id TEXT,
  path TEXT,
  line INTEGER,
  detail TEXT NOT NULL,
  PRIMARY KEY (generation_id, gap_id)
) WITHOUT ROWID;
CREATE INDEX idx_feature_gaps_entity ON feature_gaps(generation_id, entity_id) WHERE entity_id IS NOT NULL;

CREATE TABLE features (
  generation_id INTEGER NOT NULL REFERENCES generations(id) ON DELETE CASCADE,
  feature_id TEXT NOT NULL,
  name TEXT NOT NULL,
  source TEXT NOT NULL,
  root_entity TEXT NOT NULL,
  member_count INTEGER NOT NULL,
  summary_json TEXT NOT NULL,
  PRIMARY KEY (generation_id, feature_id)
) WITHOUT ROWID;

CREATE TABLE feature_members (
  generation_id INTEGER NOT NULL REFERENCES generations(id) ON DELETE CASCADE,
  feature_id TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  role TEXT NOT NULL,
  hops INTEGER NOT NULL,
  PRIMARY KEY (generation_id, feature_id, entity_id)
) WITHOUT ROWID;
CREATE INDEX idx_feature_members_entity ON feature_members(generation_id, entity_id);

CREATE TABLE feature_lineage (
  generation_id INTEGER NOT NULL REFERENCES generations(id) ON DELETE CASCADE,
  id INTEGER NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('added', 'removed', 'renamed', 'split', 'merged', 'ambiguous')),
  old_ids_json TEXT NOT NULL,
  new_ids_json TEXT NOT NULL,
  basis TEXT NOT NULL,
  certainty TEXT NOT NULL,
  PRIMARY KEY (generation_id, id)
) WITHOUT ROWID;

CREATE TABLE feature_claims (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  statement_hash TEXT NOT NULL,
  /** hash(statement, sorted evidence references): the SAME statement with DIFFERENT evidence is a different claim (nobody can squat a statement with bogus evidence). */
  identity_hash TEXT NOT NULL,
  statement TEXT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('model', 'human')),
  source_detail TEXT,
  trust TEXT NOT NULL CHECK (trust IN ('candidate', 'approved', 'retired')),
  evidence_json TEXT NOT NULL,
  scope_fingerprint TEXT,
  created_at TEXT NOT NULL,
  approved_by TEXT,
  approved_at TEXT,
  retired_at TEXT,
  retired_reason TEXT
);
CREATE UNIQUE INDEX idx_feature_claims_identity ON feature_claims(identity_hash) WHERE trust != 'retired';
${featureTriggers}
`;

/**
 * v6 (Phase H3): temporal engineering memory. Records are APPEND-ONLY evidence-backed statements (observations, claims, decisions, findings, bugs, fixes, test evidence, rejected
 * approaches). Two independent time axes: `valid_from/valid_to` (when the statement is true in the world) and `recorded_at/superseded_at` (when the store learned it, and when a later
 * record replaced it). Content columns are immutable (a trigger refuses changes); only the standing columns (status, approval, supersession) move, each transition leaving an event.
 * Whether a record still APPLIES is computed at read time from its invalidation predicates, its branch lineage and its expiry, never trusted from a stored flag.
 */
const SCHEMA_V6 = `
CREATE TABLE memory_records (
  record_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('observation', 'claim', 'decision', 'finding', 'bug', 'fix', 'test_evidence', 'rejected_approach')),
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  origin TEXT NOT NULL CHECK (origin IN ('human', 'model', 'ci', 'import')),
  origin_detail TEXT,
  status TEXT NOT NULL CHECK (status IN ('candidate', 'approved', 'verified', 'stale', 'rejected')),
  proposer TEXT NOT NULL,
  approver TEXT,
  approved_at TEXT,
  verified_by TEXT,
  verified_at TEXT,
  rejected_reason TEXT,
  valid_from TEXT NOT NULL,
  valid_to TEXT,
  recorded_at TEXT NOT NULL,
  superseded_at TEXT,
  superseded_by TEXT,
  expires_at TEXT,
  binding_revision TEXT,
  binding_branch TEXT,
  binding_overlay TEXT,
  binding_generation INTEGER,
  scope_json TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  invalidation_json TEXT NOT NULL,
  content_hash TEXT NOT NULL
);
CREATE INDEX idx_memory_records_kind ON memory_records(kind, status);
CREATE INDEX idx_memory_records_recorded ON memory_records(recorded_at);

CREATE TABLE memory_pointers (
  record_id TEXT NOT NULL REFERENCES memory_records(record_id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  kind TEXT NOT NULL,
  path TEXT,
  ref TEXT,
  content_hash TEXT,
  extra_json TEXT,
  PRIMARY KEY (record_id, ordinal)
) WITHOUT ROWID;
CREATE INDEX idx_memory_pointers_path ON memory_pointers(path) WHERE path IS NOT NULL;
CREATE INDEX idx_memory_pointers_ref ON memory_pointers(ref) WHERE ref IS NOT NULL;

CREATE TABLE memory_links (
  record_id TEXT NOT NULL REFERENCES memory_records(record_id) ON DELETE CASCADE,
  rel TEXT NOT NULL CHECK (rel IN ('fixes', 'caused_by', 'verifies', 'supersedes', 'related_to', 'rejects', 'substantiated_by')),
  target_id TEXT NOT NULL,
  PRIMARY KEY (record_id, rel, target_id)
) WITHOUT ROWID;
CREATE INDEX idx_memory_links_target ON memory_links(target_id);

CREATE TABLE memory_events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  record_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  at TEXT NOT NULL,
  actor TEXT NOT NULL,
  detail_json TEXT
);
CREATE INDEX idx_memory_events_record ON memory_events(record_id);

CREATE TABLE memory_environment (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  recorded_at TEXT NOT NULL,
  recorded_by TEXT NOT NULL
);
CREATE INDEX idx_memory_environment_key ON memory_environment(key, id);

CREATE TRIGGER memory_records_content_immutable
BEFORE UPDATE ON memory_records
WHEN NEW.kind IS NOT OLD.kind OR NEW.title IS NOT OLD.title OR NEW.body IS NOT OLD.body OR NEW.origin IS NOT OLD.origin OR NEW.origin_detail IS NOT OLD.origin_detail
  OR NEW.proposer IS NOT OLD.proposer OR NEW.valid_from IS NOT OLD.valid_from OR NEW.valid_to IS NOT OLD.valid_to OR NEW.recorded_at IS NOT OLD.recorded_at OR NEW.expires_at IS NOT OLD.expires_at
  OR NEW.binding_revision IS NOT OLD.binding_revision OR NEW.binding_branch IS NOT OLD.binding_branch OR NEW.binding_overlay IS NOT OLD.binding_overlay OR NEW.binding_generation IS NOT OLD.binding_generation
  OR NEW.scope_json IS NOT OLD.scope_json OR NEW.evidence_json IS NOT OLD.evidence_json OR NEW.invalidation_json IS NOT OLD.invalidation_json OR NEW.content_hash IS NOT OLD.content_hash
BEGIN
  SELECT RAISE(ABORT, 'memory record content is immutable: supersede it with a new record');
END;
CREATE TRIGGER memory_records_standing_transitions
BEFORE UPDATE ON memory_records
WHEN (OLD.approver IS NOT NULL AND NEW.approver IS NOT OLD.approver)
  OR (OLD.verified_by IS NOT NULL AND NEW.verified_by IS NOT OLD.verified_by)
  OR (OLD.superseded_at IS NOT NULL AND (NEW.superseded_at IS NOT OLD.superseded_at OR NEW.superseded_by IS NOT OLD.superseded_by))
  OR (OLD.rejected_reason IS NOT NULL AND NEW.rejected_reason IS NOT OLD.rejected_reason)
  OR (OLD.status = 'rejected' AND NEW.status != 'rejected')
  OR (OLD.status = 'verified' AND NEW.status NOT IN ('verified', 'rejected', 'stale'))
  OR (OLD.status = 'approved' AND NEW.status NOT IN ('approved', 'verified', 'rejected', 'stale'))
  OR (OLD.status = 'candidate' AND NEW.status NOT IN ('candidate', 'approved', 'rejected'))
  OR (OLD.status = 'stale' AND NEW.status NOT IN ('stale', 'rejected'))
BEGIN
  SELECT RAISE(ABORT, 'illegal memory status transition or rewrite of an approval');
END;
CREATE TRIGGER memory_events_no_delete_while_record_exists
BEFORE DELETE ON memory_events
WHEN EXISTS (SELECT 1 FROM memory_records WHERE record_id = OLD.record_id)
BEGIN
  SELECT RAISE(ABORT, 'events of an existing record cannot be deleted');
END;
CREATE TRIGGER memory_pointers_immutable BEFORE UPDATE ON memory_pointers BEGIN SELECT RAISE(ABORT, 'memory pointers are immutable'); END;
CREATE TRIGGER memory_links_immutable BEFORE UPDATE ON memory_links BEGIN SELECT RAISE(ABORT, 'memory links are immutable'); END;
CREATE TRIGGER memory_events_immutable BEFORE UPDATE ON memory_events BEGIN SELECT RAISE(ABORT, 'memory events are immutable'); END;
CREATE TRIGGER memory_environment_immutable BEFORE UPDATE ON memory_environment BEGIN SELECT RAISE(ABORT, 'environment history is immutable'); END;
`;

/**
 * v7 (Phase H4): imported CI/test evidence and agent handoffs. An import is QUARANTINED by default (an unsigned assertion about test results is a claim, not evidence); only a verifier
 * signature under the local provenance policy, or an operator's explicit acceptance, makes it usable, and even then it never approves anything by itself. Result rows are immutable; only the
 * trust of an import can move. Handoffs are compact, expiring packets for another agent or session; they reference, they do not copy.
 */
const SCHEMA_V7 = `
CREATE TABLE evidence_imports (
  import_id TEXT PRIMARY KEY,
  format TEXT NOT NULL CHECK (format IN ('junit', 'lcov', 'cobertura', 'sarif', 'jest', 'vitest', 'playwright', 'pytest')),
  artifact_name TEXT NOT NULL,
  artifact_sha256 TEXT NOT NULL,
  artifact_size INTEGER NOT NULL,
  source_revision TEXT,
  source_tree TEXT,
  command TEXT,
  environment_json TEXT NOT NULL,
  verifier TEXT,
  signature_status TEXT NOT NULL CHECK (signature_status IN ('none', 'valid', 'invalid')),
  trust TEXT NOT NULL CHECK (trust IN ('quarantined', 'signed', 'accepted', 'rejected')),
  provenance_json TEXT NOT NULL,
  imported_at TEXT NOT NULL,
  imported_by TEXT NOT NULL,
  total INTEGER NOT NULL,
  passed INTEGER NOT NULL,
  failed INTEGER NOT NULL,
  skipped INTEGER NOT NULL,
  timed_out INTEGER NOT NULL,
  errors INTEGER NOT NULL,
  partial INTEGER NOT NULL CHECK (partial IN (0, 1)),
  warnings_json TEXT NOT NULL,
  decided_by TEXT,
  decided_at TEXT
);
CREATE INDEX idx_evidence_imports_sha ON evidence_imports(artifact_sha256);
CREATE INDEX idx_evidence_imports_revision ON evidence_imports(source_revision);

CREATE TABLE evidence_results (
  import_id TEXT NOT NULL REFERENCES evidence_imports(import_id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  suite TEXT,
  name TEXT NOT NULL,
  file TEXT,
  outcome TEXT NOT NULL CHECK (outcome IN ('passed', 'failed', 'skipped', 'timed_out', 'error')),
  duration_ms INTEGER,
  message TEXT,
  file_hash TEXT,
  PRIMARY KEY (import_id, ordinal)
) WITHOUT ROWID;
CREATE INDEX idx_evidence_results_file ON evidence_results(file) WHERE file IS NOT NULL;
CREATE INDEX idx_evidence_results_name ON evidence_results(name);

CREATE TABLE evidence_coverage (
  import_id TEXT NOT NULL REFERENCES evidence_imports(import_id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  file TEXT NOT NULL,
  test_name TEXT,
  lines_found INTEGER NOT NULL,
  lines_hit INTEGER NOT NULL,
  hit_lines_json TEXT,
  PRIMARY KEY (import_id, ordinal)
) WITHOUT ROWID;
CREATE INDEX idx_evidence_coverage_file ON evidence_coverage(file);

CREATE TABLE evidence_findings (
  import_id TEXT NOT NULL REFERENCES evidence_imports(import_id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  tool TEXT,
  rule TEXT,
  level TEXT,
  file TEXT,
  line INTEGER,
  message TEXT,
  PRIMARY KEY (import_id, ordinal)
) WITHOUT ROWID;

CREATE TRIGGER evidence_imports_immutable
BEFORE UPDATE ON evidence_imports
WHEN NEW.import_id IS NOT OLD.import_id OR NEW.format IS NOT OLD.format OR NEW.artifact_name IS NOT OLD.artifact_name OR NEW.artifact_sha256 IS NOT OLD.artifact_sha256 OR NEW.artifact_size IS NOT OLD.artifact_size
  OR NEW.source_revision IS NOT OLD.source_revision OR NEW.source_tree IS NOT OLD.source_tree OR NEW.command IS NOT OLD.command OR NEW.environment_json IS NOT OLD.environment_json
  OR NEW.verifier IS NOT OLD.verifier OR NEW.signature_status IS NOT OLD.signature_status OR NEW.imported_at IS NOT OLD.imported_at OR NEW.imported_by IS NOT OLD.imported_by OR NEW.total IS NOT OLD.total
  OR NEW.passed IS NOT OLD.passed OR NEW.failed IS NOT OLD.failed OR NEW.skipped IS NOT OLD.skipped OR NEW.timed_out IS NOT OLD.timed_out OR NEW.errors IS NOT OLD.errors OR NEW.partial IS NOT OLD.partial
  OR NEW.warnings_json IS NOT OLD.warnings_json OR NEW.provenance_json IS NOT OLD.provenance_json
  OR (OLD.trust = 'rejected' AND NEW.trust != 'rejected')
  OR (OLD.trust = 'accepted' AND NEW.trust NOT IN ('accepted', 'rejected'))
  OR (OLD.trust = 'signed' AND NEW.trust NOT IN ('signed', 'accepted', 'rejected'))
  OR (OLD.trust = 'quarantined' AND NEW.trust NOT IN ('quarantined', 'accepted', 'rejected'))
BEGIN
  SELECT RAISE(ABORT, 'imported evidence is immutable: only its trust can be decided (never upgraded to signed after the fact), and a rejection is final');
END;
CREATE TRIGGER evidence_imports_no_delete BEFORE DELETE ON evidence_imports BEGIN SELECT RAISE(ABORT, 'imported evidence is never deleted'); END;
CREATE TRIGGER evidence_results_immutable BEFORE UPDATE ON evidence_results BEGIN SELECT RAISE(ABORT, 'imported results are immutable'); END;
CREATE TRIGGER evidence_results_no_delete BEFORE DELETE ON evidence_results BEGIN SELECT RAISE(ABORT, 'imported results are immutable'); END;
CREATE TRIGGER evidence_coverage_immutable BEFORE UPDATE ON evidence_coverage BEGIN SELECT RAISE(ABORT, 'imported coverage is immutable'); END;
CREATE TRIGGER evidence_coverage_no_delete BEFORE DELETE ON evidence_coverage BEGIN SELECT RAISE(ABORT, 'imported coverage is immutable'); END;
CREATE TRIGGER evidence_findings_immutable BEFORE UPDATE ON evidence_findings BEGIN SELECT RAISE(ABORT, 'imported findings are immutable'); END;
CREATE TRIGGER evidence_findings_no_delete BEFORE DELETE ON evidence_findings BEGIN SELECT RAISE(ABORT, 'imported findings are immutable'); END;

CREATE TABLE handoffs (
  handoff_id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  author TEXT NOT NULL,
  task TEXT NOT NULL,
  scope_json TEXT NOT NULL,
  references_json TEXT NOT NULL,
  hypotheses_json TEXT NOT NULL,
  blockers_json TEXT NOT NULL,
  pending_evidence_json TEXT NOT NULL,
  context_packet_hash TEXT,
  revision TEXT,
  branch TEXT,
  generation_id INTEGER,
  source_fingerprint TEXT,
  worktree_id TEXT,
  policy_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'superseded', 'closed')),
  content_hash TEXT NOT NULL
);
CREATE INDEX idx_handoffs_status ON handoffs(status, created_at);
CREATE TRIGGER handoffs_content_immutable
BEFORE UPDATE ON handoffs
WHEN NEW.task IS NOT OLD.task OR NEW.scope_json IS NOT OLD.scope_json OR NEW.references_json IS NOT OLD.references_json OR NEW.hypotheses_json IS NOT OLD.hypotheses_json OR NEW.blockers_json IS NOT OLD.blockers_json
  OR NEW.revision IS NOT OLD.revision OR NEW.source_fingerprint IS NOT OLD.source_fingerprint OR NEW.policy_hash IS NOT OLD.policy_hash OR NEW.author IS NOT OLD.author OR NEW.content_hash IS NOT OLD.content_hash OR NEW.expires_at IS NOT OLD.expires_at
  OR NEW.worktree_id IS NOT OLD.worktree_id OR NEW.branch IS NOT OLD.branch OR NEW.pending_evidence_json IS NOT OLD.pending_evidence_json OR NEW.context_packet_hash IS NOT OLD.context_packet_hash OR NEW.generation_id IS NOT OLD.generation_id OR NEW.created_at IS NOT OLD.created_at
  OR (OLD.status != 'active' AND NEW.status != OLD.status)
BEGIN
  SELECT RAISE(ABORT, 'a handoff is immutable: write a new one');
END;
`;


const SCHEMA_V8 = `
-- Sentinel 3A: durable task state, append-only evidence and events, approvals and execution authorizations. One store: this extends the Hive evidence tables, it is not a second truth database.
CREATE TABLE sentinel_tasks (
  task_id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  requester TEXT NOT NULL,
  title TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('CREATED','CONTEXT_READY','SPECIFICATION_READY','PLAN_APPROVED','IMPLEMENTING','IMPLEMENTED','VERIFYING','FINDINGS_REPORTED','REPAIRING','REVERIFYING','ASSURANCE_REVIEW','APPROVAL_REQUIRED','ELIGIBLE_FOR_APPROVAL','BLOCKED','FAILED','CANCELLED')),
  revision INTEGER NOT NULL,
  profile TEXT NOT NULL CHECK (profile IN ('A1','A2','A3','A4')),
  policy_hash TEXT NOT NULL,
  source_fingerprint TEXT NOT NULL,
  worktree_id TEXT,
  scope_json TEXT NOT NULL,
  requirements_json TEXT NOT NULL,
  components_json TEXT NOT NULL,
  builder_principal TEXT,
  budgets_json TEXT NOT NULL,
  blocked_reason TEXT,
  claimed_by TEXT,
  lease_expires TEXT,
  lease_hash TEXT,
  base_revision TEXT,
  cap_epoch INTEGER NOT NULL DEFAULT 0,
  seal TEXT NOT NULL DEFAULT '',
  checkpoint_json TEXT,
  updated_at TEXT NOT NULL
);
CREATE TABLE sentinel_task_events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL REFERENCES sentinel_tasks(task_id),
  at TEXT NOT NULL,
  kind TEXT NOT NULL,
  from_state TEXT,
  to_state TEXT,
  actor TEXT NOT NULL,
  role TEXT,
  revision INTEGER NOT NULL,
  payload_json TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL,
  mac TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_sentinel_events_task ON sentinel_task_events(task_id, seq);
CREATE TABLE sentinel_evidence (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL REFERENCES sentinel_tasks(task_id),
  at TEXT NOT NULL,
  origin TEXT NOT NULL CHECK (origin IN ('machine', 'agent_note')),
  kind TEXT NOT NULL,
  check_id TEXT,
  outcome TEXT NOT NULL CHECK (outcome IN ('passed', 'failed', 'skipped', 'timed_out', 'incomplete', 'not_run', 'invalidated')),
  verifier TEXT NOT NULL,
  source_fingerprint TEXT NOT NULL,
  policy_hash TEXT NOT NULL,
  environment_json TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL,
  mac TEXT NOT NULL
);
CREATE INDEX idx_sentinel_evidence_task ON sentinel_evidence(task_id, check_id, seq);
CREATE TABLE sentinel_approvals (
  approval_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL REFERENCES sentinel_tasks(task_id),
  approver TEXT NOT NULL,
  at TEXT NOT NULL,
  task_revision INTEGER NOT NULL,
  source_fingerprint TEXT NOT NULL,
  policy_hash TEXT NOT NULL,
  evidence_head TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  mac TEXT NOT NULL DEFAULT ''
);
CREATE TABLE sentinel_exec_auth (
  auth_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL REFERENCES sentinel_tasks(task_id),
  authorized_by TEXT NOT NULL,
  at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  source_fingerprint TEXT NOT NULL,
  policy_hash TEXT NOT NULL,
  runs_left INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  mac TEXT NOT NULL DEFAULT ''
);
CREATE TABLE sentinel_queue (
  item_id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL REFERENCES sentinel_tasks(task_id),
  kind TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'done', 'dropped'))
);
CREATE TRIGGER sentinel_events_append_only_u BEFORE UPDATE ON sentinel_task_events BEGIN SELECT RAISE(ABORT, 'sentinel events are append-only'); END;
CREATE TRIGGER sentinel_events_append_only_d BEFORE DELETE ON sentinel_task_events BEGIN SELECT RAISE(ABORT, 'sentinel events are append-only'); END;
CREATE TRIGGER sentinel_evidence_append_only_u BEFORE UPDATE ON sentinel_evidence BEGIN SELECT RAISE(ABORT, 'sentinel evidence is append-only'); END;
CREATE TRIGGER sentinel_evidence_append_only_d BEFORE DELETE ON sentinel_evidence BEGIN SELECT RAISE(ABORT, 'sentinel evidence is append-only'); END;
CREATE TRIGGER sentinel_approvals_immutable BEFORE UPDATE ON sentinel_approvals
WHEN NEW.approval_id IS NOT OLD.approval_id OR NEW.task_id IS NOT OLD.task_id OR NEW.approver IS NOT OLD.approver OR NEW.at IS NOT OLD.at OR NEW.task_revision IS NOT OLD.task_revision OR NEW.source_fingerprint IS NOT OLD.source_fingerprint
  OR NEW.policy_hash IS NOT OLD.policy_hash OR NEW.evidence_head IS NOT OLD.evidence_head OR (OLD.status = 'revoked' AND NEW.status != 'revoked')
BEGIN SELECT RAISE(ABORT, 'an approval is immutable; it can only be revoked'); END;
CREATE TRIGGER sentinel_exec_auth_immutable BEFORE UPDATE ON sentinel_exec_auth
WHEN NEW.auth_id IS NOT OLD.auth_id OR NEW.task_id IS NOT OLD.task_id OR NEW.authorized_by IS NOT OLD.authorized_by OR NEW.at IS NOT OLD.at OR NEW.expires_at IS NOT OLD.expires_at
  OR NEW.source_fingerprint IS NOT OLD.source_fingerprint OR NEW.policy_hash IS NOT OLD.policy_hash OR (OLD.status = 'revoked' AND NEW.status != 'revoked') OR NEW.runs_left > OLD.runs_left
BEGIN SELECT RAISE(ABORT, 'an execution authorization can only be used up or revoked'); END;
CREATE TRIGGER sentinel_exec_auth_no_delete BEFORE DELETE ON sentinel_exec_auth BEGIN SELECT RAISE(ABORT, 'authorizations are never deleted'); END;
CREATE TRIGGER sentinel_events_ordered BEFORE INSERT ON sentinel_task_events WHEN NEW.seq > 0 AND NEW.seq <= COALESCE((SELECT MAX(seq) FROM sentinel_task_events), 0) BEGIN SELECT RAISE(ABORT, 'sentinel events cannot be replaced or back-filled'); END;
CREATE TRIGGER sentinel_evidence_ordered BEFORE INSERT ON sentinel_evidence WHEN NEW.seq > 0 AND NEW.seq <= COALESCE((SELECT MAX(seq) FROM sentinel_evidence), 0) BEGIN SELECT RAISE(ABORT, 'sentinel evidence cannot be replaced or back-filled'); END;
CREATE TRIGGER sentinel_approvals_no_delete BEFORE DELETE ON sentinel_approvals BEGIN SELECT RAISE(ABORT, 'approvals are never deleted'); END;
CREATE TRIGGER sentinel_tasks_no_delete BEFORE DELETE ON sentinel_tasks BEGIN SELECT RAISE(ABORT, 'tasks are never deleted'); END;
CREATE TRIGGER sentinel_tasks_identity_immutable BEFORE UPDATE ON sentinel_tasks
WHEN NEW.task_id IS NOT OLD.task_id OR NEW.created_at IS NOT OLD.created_at OR NEW.requester IS NOT OLD.requester OR NEW.profile IS NOT OLD.profile OR NEW.scope_json IS NOT OLD.scope_json OR NEW.revision < OLD.revision
  OR NEW.policy_hash IS NOT OLD.policy_hash OR NEW.base_revision IS NOT OLD.base_revision OR (OLD.builder_principal IS NOT NULL AND NEW.builder_principal IS NOT OLD.builder_principal) OR NEW.cap_epoch < OLD.cap_epoch
  OR (OLD.state IN ('FAILED', 'CANCELLED') AND NEW.state IS NOT OLD.state)
BEGIN SELECT RAISE(ABORT, 'task identity, scope and profile are immutable; a terminal task cannot be reopened'); END;
`;

const SCHEMA_V9 = `
-- Sentinel 3B: campaign plans (three structurally distinct passes) and requirement -> behavior -> test -> evidence links.
CREATE TABLE sentinel_trace (
  link_id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL REFERENCES sentinel_tasks(task_id),
  at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  requirement_ix INTEGER NOT NULL,
  behavior TEXT NOT NULL,
  test_path TEXT NOT NULL,
  test_name TEXT,
  check_id TEXT NOT NULL
);
CREATE INDEX idx_sentinel_trace_task ON sentinel_trace(task_id, requirement_ix);
CREATE TRIGGER sentinel_trace_append_only_u BEFORE UPDATE ON sentinel_trace BEGIN SELECT RAISE(ABORT, 'trace links are append-only'); END;
CREATE TRIGGER sentinel_trace_append_only_d BEFORE DELETE ON sentinel_trace BEGIN SELECT RAISE(ABORT, 'trace links are append-only'); END;
`;

const SCHEMA_V10 = `
-- Sentinel 3C: authorized worktrees (with a baseline of every file), review findings with evidence references, and bounded repair budgets.
CREATE TABLE sentinel_worktrees (
  task_id TEXT PRIMARY KEY REFERENCES sentinel_tasks(task_id),
  path TEXT NOT NULL,
  baseline_json TEXT NOT NULL,
  authorized_by TEXT NOT NULL,
  at TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked'))
);
CREATE TABLE sentinel_findings (
  finding_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL REFERENCES sentinel_tasks(task_id),
  at TEXT NOT NULL,
  source_role TEXT NOT NULL,
  source_principal TEXT NOT NULL,
  provider TEXT,
  severity TEXT NOT NULL CHECK (severity IN ('blocking', 'advisory')),
  title TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  reproduction TEXT NOT NULL,
  check_id TEXT,
  disposition TEXT NOT NULL CHECK (disposition IN ('open', 'fixed', 'rejected', 'accepted_risk')),
  disposition_by TEXT,
  disposition_reason TEXT,
  disposition_at TEXT
);
CREATE INDEX idx_sentinel_findings_task ON sentinel_findings(task_id, disposition);
CREATE TRIGGER sentinel_findings_identity BEFORE UPDATE ON sentinel_findings
WHEN NEW.finding_id IS NOT OLD.finding_id OR NEW.task_id IS NOT OLD.task_id OR NEW.at IS NOT OLD.at OR NEW.source_role IS NOT OLD.source_role OR NEW.source_principal IS NOT OLD.source_principal
  OR NEW.severity IS NOT OLD.severity OR NEW.title IS NOT OLD.title OR NEW.evidence_json IS NOT OLD.evidence_json OR NEW.reproduction IS NOT OLD.reproduction OR NEW.check_id IS NOT OLD.check_id
  OR (OLD.disposition != 'open' AND NEW.disposition IS NOT OLD.disposition)
BEGIN SELECT RAISE(ABORT, 'a finding is immutable; only its disposition can be decided, once'); END;
CREATE TRIGGER sentinel_findings_no_delete BEFORE DELETE ON sentinel_findings BEGIN SELECT RAISE(ABORT, 'findings are never deleted'); END;
CREATE TABLE sentinel_repair (
  task_id TEXT PRIMARY KEY REFERENCES sentinel_tasks(task_id),
  budget_json TEXT NOT NULL,
  iterations INTEGER NOT NULL DEFAULT 0,
  tokens INTEGER NOT NULL DEFAULT 0,
  cost_micro INTEGER NOT NULL DEFAULT 0,
  elapsed_ms INTEGER NOT NULL DEFAULT 0,
  signatures_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE sentinel_repair_keys (task_id TEXT NOT NULL, iteration_key TEXT NOT NULL, PRIMARY KEY (task_id, iteration_key)) WITHOUT ROWID;
`;

export const MIGRATIONS: readonly Migration[] = [
  { version: 1, name: "foundation schema", up: (db) => db.exec(SCHEMA_V1) },
  { version: 2, name: "content-derived code facts", up: (db) => db.exec(SCHEMA_V2) },
  { version: 3, name: "module relationships", up: (db) => db.exec(SCHEMA_V3) },
  { version: 4, name: "git commit ledger", up: (db) => db.exec(SCHEMA_V4) },
  { version: 5, name: "feature graph", up: (db) => db.exec(SCHEMA_V5) },
  { version: 6, name: "temporal memory", up: (db) => db.exec(SCHEMA_V6) },
  { version: 7, name: "evidence import and handoffs", up: (db) => db.exec(SCHEMA_V7) },
  { version: 8, name: "sentinel tasks, evidence and approvals", up: (db) => db.exec(SCHEMA_V8) },
  {
    version: 9, name: "sentinel campaigns and traceability", up: (db) => {
      // v7/v8 were extended in place before any release: a store made by an EARLIER development build would lack the new CHECK values and crash later, so refuse it with a clear instruction
      const ddl = (name: string): string => (db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?").get(name) as { sql: string } | undefined)?.sql ?? "";
      if (!ddl("sentinel_evidence").includes("'invalidated'") || !ddl("evidence_imports").includes("'playwright'")) {
        throw new EngbrainError("INVALID_CONFIG", "this store was created by an earlier development build of schema v7/v8 and cannot be upgraded in place: run `engbrain uninstall --purge --yes` and `engbrain init`");
      }
      db.exec(SCHEMA_V9);
    }
  },
  { version: 10, name: "sentinel worktrees, findings and repair budgets", up: (db) => db.exec(SCHEMA_V10) }
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
