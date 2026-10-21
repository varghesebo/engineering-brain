import { lstatSync, readdirSync } from "node:fs";
import { join } from "node:path";
import type { HardenedGit } from "@engbrain/security";
import { type AuditLog } from "./audit.js";
import { createExclusionMatcher, type ExclusionMatcher } from "./exclusions.js";
import { EngbrainError } from "./errors.js";
import { readRegularFileBounded } from "./fsSafe.js";
import { sha256Hex } from "./hash.js";
import type { GitInfo } from "./identity.js";
import { inventoryExtractor, type Extractor } from "./inventory.js";
import { collisionKey, resolveUnderRoot, toStorePath } from "./paths.js";
import { scanForSecrets } from "./secretScan.js";
import { collectGarbage } from "./store/gc.js";
import {
  computeSourceFingerprint, createBuildingGeneration, currentGenerationId, discardGeneration, extractorSetHash,
  insertManifest, markAbandoned, publishGeneration, validateGeneration, type FaultHook, type ManifestRow
} from "./store/generations.js";
import { acquireWriterLock, type LockOptions } from "./store/lock.js";
import type { Store } from "./store/store.js";

const FACT_BATCH_SIZE = 500;
const BINARY_SNIFF_BYTES = 8192;

export interface IndexOptions {
  store: Store;
  git: GitInfo;
  /** Required when `git.isGit`. */
  hardenedGit: HardenedGit | null;
  audit?: AuditLog;
  extractor?: Extractor;
  lock?: LockOptions;
  /** Test hook: called at named points so crashes/aborts can be injected. Not exposed by the CLI. */
  fault?: FaultHook;
  now?: () => Date;
}

export interface IndexStats {
  candidates: number;
  included: number;
  excluded: number;
  excludedByReason: Record<string, number>;
  missing: number;
  /** Times the extractor actually ran (the "reprocessed" count). */
  extractorRuns: number;
  /** Included files whose facts already existed (content-addressed reuse). */
  factsReused: number;
  recoveredAbandoned: number;
  gcGenerationsRemoved: number;
  gcFactsRemoved: number;
  durationMs: number;
}

export interface IndexResult {
  generationId: number;
  /** True when nothing changed and the current generation was kept (no new generation published). */
  unchanged: boolean;
  revision: string | null;
  sourceFingerprint: string;
  stats: IndexStats;
}

interface Candidate {
  /** Normalised (NFC, forward slash) key stored in the manifest. */
  storePath: string;
  /** The name exactly as listed on disk; used to OPEN the file (NFC and NFD names differ on Linux). */
  rawPath: string;
  /** Excluded before reading (e.g. symlink found while walking). */
  preExcluded?: string;
}

/** Verifies, once per directory, that every parent component of a path is a real directory (not a symlink). */
class DirectoryGuard {
  private readonly verdicts = new Map<string, "ok" | "symlink" | "missing">();

  constructor(private readonly root: string) {}

  check(relativeDirectory: string): "ok" | "symlink" | "missing" {
    if (relativeDirectory === "") {
      return "ok";
    }
    const known = this.verdicts.get(relativeDirectory);
    if (known !== undefined) {
      return known;
    }
    const cut = relativeDirectory.lastIndexOf("/");
    const parent = this.check(cut === -1 ? "" : relativeDirectory.slice(0, cut));
    let verdict: "ok" | "symlink" | "missing" = parent;
    if (parent === "ok") {
      try {
        const stat = lstatSync(join(this.root, ...relativeDirectory.split("/")));
        verdict = stat.isSymbolicLink() ? "symlink" : stat.isDirectory() ? "ok" : "missing";
      } catch {
        verdict = "missing";
      }
    }
    this.verdicts.set(relativeDirectory, verdict);
    return verdict;
  }
}

/**
 * Builds and atomically publishes a new generation. Flow:
 *   lock -> recover crashed runs -> create `building` generation -> facts (batched txs, immutable, unreferenced
 *   until publication) -> manifest -> validate -> publish (single tx) -> GC.
 * Hashing always covers every included file; only the extractor is skipped for known content.
 */
export async function indexRepository(options: IndexOptions): Promise<IndexResult> {
  const { store } = options;
  const started = Date.now();
  const now = options.now ?? ((): Date => new Date());
  const config = store.config();
  const extractor = options.extractor ?? inventoryExtractor;
  const matcher = createExclusionMatcher(config.exclude);
  const lock = await acquireWriterLock(store.dir, options.lock);
  let generationId: number | null = null;
  try {
    const recoveredAbandoned = markAbandoned(store.db);
    const parentId = currentGenerationId(store.db);
    options.audit?.record("index_start", { parentGeneration: parentId, extractor: `${extractor.id}@${extractor.version}` });

    generationId = createBuildingGeneration(store.db, {
      parentId,
      revision: options.git.revision,
      branchLabel: options.git.branchLabel,
      extractors: [{ id: extractor.id, version: extractor.version }],
      now: now()
    });
    options.fault?.("pre-facts");

    const candidates = await enumerateCandidates(options, matcher);
    const outcome = buildFactsAndRows(options, candidates, matcher, config.maxFileBytes, extractor);

    options.fault?.("pre-manifest");
    insertManifest(store.db, generationId, outcome.rows);
    const fingerprint = computeSourceFingerprint(store.db, generationId);

    const unchanged = isUnchanged(store, parentId, fingerprint, options.git, extractor);
    if (unchanged && parentId !== null) {
      discardGeneration(store.db, generationId);
      const gc = collectGarbage(store.db, config.generationsToKeep);
      return finish(options, parentId, true, fingerprint, outcome, recoveredAbandoned, gc, started);
    }

    const validation = validateGeneration(store.db, generationId, fingerprint);
    if (!validation.ok) {
      throw new EngbrainError("INTEGRITY_FAILED", `generation failed validation: ${validation.problems.join("; ")}`);
    }
    options.fault?.("pre-publish");
    publishGeneration(store.db, generationId, { fingerprint, now: now(), fault: options.fault });
    const gc = collectGarbage(store.db, config.generationsToKeep);
    return finish(options, generationId, false, fingerprint, outcome, recoveredAbandoned, gc, started);
  } catch (error) {
    options.audit?.record("index_failed", { code: error instanceof EngbrainError ? error.code : "ERROR" });
    throw error;
  } finally {
    lock.release();
  }
}

function isUnchanged(store: Store, parentId: number | null, fingerprint: string, git: GitInfo, extractor: Extractor): boolean {
  if (parentId === null) {
    return false;
  }
  const parent = store.db
    .prepare("SELECT revision, branch_label AS branch, source_fingerprint AS fp, extractor_set_hash AS ext FROM generations WHERE id = ?")
    .get(parentId) as { revision: string | null; branch: string | null; fp: string | null; ext: string };
  return (
    parent.fp === fingerprint &&
    parent.revision === git.revision &&
    parent.branch === git.branchLabel &&
    parent.ext === extractorSetHash([{ id: extractor.id, version: extractor.version }])
  );
}

function finish(
  options: IndexOptions,
  generationId: number,
  unchanged: boolean,
  fingerprint: string,
  outcome: BuildOutcome,
  recoveredAbandoned: number,
  gc: { generationsRemoved: number; factsRemoved: number },
  started: number
): IndexResult {
  const stats: IndexStats = {
    candidates: outcome.candidates,
    included: outcome.included,
    excluded: outcome.excluded,
    excludedByReason: outcome.excludedByReason,
    missing: outcome.missing,
    extractorRuns: outcome.extractorRuns,
    factsReused: outcome.factsReused,
    recoveredAbandoned,
    gcGenerationsRemoved: gc.generationsRemoved,
    gcFactsRemoved: gc.factsRemoved,
    durationMs: Date.now() - started
  };
  options.audit?.record("index_end", {
    generation: generationId, unchanged, included: stats.included, excluded: stats.excluded,
    extractorRuns: stats.extractorRuns, durationMs: stats.durationMs
  });
  return { generationId, unchanged, revision: options.git.revision, sourceFingerprint: fingerprint, stats };
}

async function enumerateCandidates(options: IndexOptions, matcher: ExclusionMatcher): Promise<Candidate[]> {
  const seen = new Map<string, Candidate>();
  const add = (candidate: Candidate): void => {
    seen.set(candidate.rawPath, candidate); // keyed by the on-disk name: NFC/NFD twins stay distinct so the collision is DETECTED
  };
  if (options.git.isGit) {
    const git = options.hardenedGit;
    if (git === null) {
      throw new EngbrainError("GIT_UNAVAILABLE", "git is required to list files in a git repository");
    }
    const listings = await Promise.all([
      git.run(options.git.root, ["ls-files", "-z"]),
      git.run(options.git.root, ["ls-files", "-z", "--others", "--exclude-standard"])
    ]);
    for (const listing of listings) {
      for (const raw of listing.split("\0")) {
        if (raw === "") {
          continue;
        }
        const normalized = toStorePath(raw);
        add(
          normalized.ok && !raw.includes("\uFFFD")
            ? { storePath: normalized.path, rawPath: raw }
            : { storePath: raw, rawPath: raw, preExcluded: normalized.ok ? "invalid_path" : normalized.reason }
        );
      }
    }
  } else {
    walk(options.git.root, "", matcher, add);
  }
  const byKey = (a: Candidate, b: Candidate): number =>
    a.storePath < b.storePath ? -1 : a.storePath > b.storePath ? 1 : a.rawPath < b.rawPath ? -1 : a.rawPath > b.rawPath ? 1 : 0;
  return [...seen.values()].sort(byKey);
}

function walk(root: string, relative: string, matcher: ExclusionMatcher, add: (candidate: Candidate) => void): void {
  const directory = relative === "" ? root : join(root, ...relative.split("/"));
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const rel = relative === "" ? entry.name : `${relative}/${entry.name}`;
    if (entry.isSymbolicLink()) {
      add({ storePath: rel, rawPath: rel, preExcluded: "symlink" });
    } else if (entry.isDirectory()) {
      if (!matcher.excludesDirectory(entry.name)) {
        walk(root, rel, matcher, add);
      }
    } else {
      const normalized = toStorePath(rel);
      add(normalized.ok ? { storePath: normalized.path, rawPath: rel } : { storePath: rel, rawPath: rel, preExcluded: normalized.reason });
    }
  }
}

interface BuildOutcome {
  rows: ManifestRow[];
  candidates: number;
  included: number;
  excluded: number;
  excludedByReason: Record<string, number>;
  missing: number;
  extractorRuns: number;
  factsReused: number;
}

interface PendingFact {
  hash: string;
  language: string | null;
  parseStatus: string;
  attrsJson: string;
}

function excludedRow(path: string, reason: string): ManifestRow {
  return { path, contentHash: null, size: null, mtimeNs: null, ctimeNs: null, inode: null, excludedReason: reason };
}

function buildFactsAndRows(
  options: IndexOptions,
  candidates: Candidate[],
  matcher: ExclusionMatcher,
  maxFileBytes: number,
  extractor: Extractor
): BuildOutcome {
  const db = options.store.db;
  const hasFact = db.prepare("SELECT 1 FROM file_facts WHERE content_hash = ? AND extractor_id = ? AND extractor_version = ?");
  const insertFact = db.prepare(
    "INSERT OR IGNORE INTO file_facts (content_hash, extractor_id, extractor_version, language, parse_status, attrs_json) VALUES (?, ?, ?, ?, ?, ?)"
  );
  const outcome: BuildOutcome = {
    rows: [], candidates: candidates.length, included: 0, excluded: 0, excludedByReason: {}, missing: 0, extractorRuns: 0, factsReused: 0
  };
  const pending: PendingFact[] = [];
  const queuedHashes = new Set<string>();
  let batches = 0;
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const keys = new Set<string>();
  const directories = new DirectoryGuard(options.git.root);

  const exclude = (path: string, reason: string): void => {
    outcome.rows.push(excludedRow(path, reason));
    outcome.excluded += 1;
    outcome.excludedByReason[reason] = (outcome.excludedByReason[reason] ?? 0) + 1;
  };
  const flush = (): void => {
    if (pending.length === 0) {
      return;
    }
    db.transaction(() => {
      for (const fact of pending) {
        insertFact.run(fact.hash, extractor.id, extractor.version, fact.language, fact.parseStatus, fact.attrsJson);
      }
    }).immediate();
    pending.length = 0;
    batches += 1;
    if (batches === 1) {
      options.fault?.("mid-facts");
    }
  };

  for (const candidate of candidates) {
    const path = candidate.storePath;
    if (candidate.preExcluded !== undefined) {
      exclude(path, candidate.preExcluded);
      continue;
    }
    const key = collisionKey(path);
    if (keys.has(key)) {
      exclude(path, "path_collision");
      continue;
    }
    keys.add(key);
    const pathReason = matcher.excludesPath(path);
    if (pathReason !== null) {
      exclude(path, pathReason);
      continue;
    }
    const absolute = resolveUnderRoot(options.git.root, candidate.rawPath);
    if (absolute === null) {
      exclude(path, "invalid_path");
      continue;
    }
    const cut = candidate.rawPath.lastIndexOf("/");
    const parentVerdict = directories.check(cut === -1 ? "" : candidate.rawPath.slice(0, cut));
    if (parentVerdict !== "ok") {
      if (parentVerdict === "symlink") {
        exclude(path, "symlink");
      } else {
        outcome.missing += 1;
      }
      continue;
    }
    let stat;
    try {
      stat = lstatSync(absolute);
    } catch {
      outcome.missing += 1;
      continue;
    }
    if (stat.isSymbolicLink()) {
      exclude(path, "symlink");
      continue;
    }
    if (!stat.isFile()) {
      exclude(path, "not_regular"); // FIFOs, sockets, devices, directories (submodules): never opened
      continue;
    }
    const read = readRegularFileBounded(absolute, maxFileBytes);
    if (read.kind === "missing") {
      outcome.missing += 1;
      continue;
    }
    if (read.kind === "excluded") {
      exclude(path, read.reason);
      continue;
    }
    const { data } = read.file;
    if (data.subarray(0, BINARY_SNIFF_BYTES).includes(0)) {
      exclude(path, "binary_content");
      continue;
    }
    let text: string;
    try {
      text = decoder.decode(data);
    } catch {
      exclude(path, "invalid_utf8");
      continue;
    }
    const detector = scanForSecrets(text);
    if (detector !== null) {
      exclude(path, `secret:${detector}`);
      continue;
    }
    const hash = sha256Hex(data);
    outcome.rows.push({
      path, contentHash: hash, size: read.file.size, mtimeNs: read.file.mtimeNs, ctimeNs: read.file.ctimeNs,
      inode: read.file.inode, excludedReason: null
    });
    outcome.included += 1;
    if (queuedHashes.has(hash) || hasFact.get(hash, extractor.id, extractor.version) !== undefined) {
      outcome.factsReused += 1;
      continue;
    }
    const fact = extractor.extract({ path, data });
    outcome.extractorRuns += 1;
    queuedHashes.add(hash);
    pending.push({ hash, language: fact.language, parseStatus: fact.parseStatus, attrsJson: JSON.stringify(fact.attrs) });
    if (pending.length >= FACT_BATCH_SIZE) {
      flush();
    }
  }
  flush();
  return outcome;
}
