import { lstatSync } from "node:fs";
import type { HardenedGit } from "@engbrain/security";
import { createInspectContext, enumerateCandidates, inspectCandidate, type Candidate } from "./candidates.js";
import type { Extractor } from "./extractor.js";
import { DEFAULT_EXTRACTORS } from "./defaultExtractors.js";
import { RESOLVER_VERSION } from "./moduleResolver.js";
import { extractorSetHash } from "./store/generations.js";
import { createExclusionMatcher } from "./exclusions.js";
import type { GitInfo } from "./identity.js";
import { resolveUnderRoot } from "./paths.js";
import { currentGenerationId } from "./store/generations.js";
import type { Store } from "./store/store.js";

/**
 * Freshness is reported at exactly the strength it was established (docs/incremental-indexing.md):
 *  hash_verified  every candidate file was re-read and its content hash and exclusion status equal the manifest
 *  heuristic      git file list + stat tuple (size, mtime, ctime, inode) agree with the manifest; metadata can miss edits
 *  stale          a difference was found (listed, bounded)
 *  unknown        no generation, or the check could not run
 * A file watcher is never used as proof of freshness.
 */
export type FreshnessLevel = "hash_verified" | "heuristic" | "stale" | "unknown";

export interface FreshnessReport {
  level: FreshnessLevel;
  basis: string;
  generationId: number | null;
  indexedRevision: string | null;
  currentRevision: string | null;
  revisionChanged: boolean;
  sourceFingerprint: string | null;
  /** True when the running build would extract or resolve differently than the build that published this generation. */
  indexerChanged: boolean;
  added: string[];
  modified: string[];
  deleted: string[];
  /** True when the lists were cut at `LIST_LIMIT`. */
  truncated: boolean;
}

const LIST_LIMIT = 50;

interface ManifestEntry {
  path: string;
  contentHash: string | null;
  excludedReason: string | null;
  size: number | null;
  mtimeNs: string | null;
  ctimeNs: string | null;
  inode: string | null;
}

function cap(list: string[]): [string[], boolean] {
  return [list.slice(0, LIST_LIMIT), list.length > LIST_LIMIT];
}

function heuristicDiff(root: string, manifest: Map<string, ManifestEntry>, candidates: Candidate[], excluded: (p: string) => boolean) {
  const added: string[] = [];
  const modified: string[] = [];
  const deleted: string[] = [];
  const seen = new Set<string>();
  for (const candidate of candidates) {
    const entry = manifest.get(candidate.storePath);
    seen.add(candidate.storePath);
    if (entry === undefined) {
      if (candidate.preExcluded === undefined && !excluded(candidate.storePath)) {
        added.push(candidate.storePath);
      }
      continue;
    }
    if (entry.contentHash === null) {
      continue; // excluded when indexed; nothing to compare without reading it
    }
    const absolute = resolveUnderRoot(root, candidate.rawPath);
    try {
      const stat = absolute === null ? null : lstatSync(absolute, { bigint: true });
      if (
        stat === null || !stat.isFile() || Number(stat.size) !== entry.size || stat.mtimeNs.toString() !== entry.mtimeNs ||
        stat.ctimeNs.toString() !== entry.ctimeNs || stat.ino.toString() !== entry.inode
      ) {
        modified.push(candidate.storePath);
      }
    } catch {
      deleted.push(candidate.storePath);
    }
  }
  for (const [path, entry] of manifest) {
    if (!seen.has(path) && entry.contentHash !== null) {
      deleted.push(path);
    }
  }
  return { added, modified, deleted };
}

function verifiedDiff(store: Store, git: GitInfo, manifest: Map<string, ManifestEntry>, candidates: Candidate[]) {
  const config = store.config();
  const ctx = createInspectContext(git.root, createExclusionMatcher(config.exclude), config.maxFileBytes);
  const added: string[] = [];
  const modified: string[] = [];
  const deleted: string[] = [];
  const seen = new Set<string>();
  for (const candidate of candidates) {
    const result = inspectCandidate(ctx, candidate);
    const entry = manifest.get(candidate.storePath);
    if (result.kind === "missing") {
      if (entry !== undefined) {
        deleted.push(candidate.storePath);
      }
      continue;
    }
    seen.add(candidate.storePath);
    if (entry === undefined) {
      added.push(candidate.storePath);
    } else if (result.kind === "excluded") {
      if (entry.excludedReason !== result.reason) {
        modified.push(candidate.storePath);
      }
    } else if (entry.contentHash !== result.row.contentHash) {
      modified.push(candidate.storePath);
    }
  }
  for (const path of manifest.keys()) {
    if (!seen.has(path)) {
      deleted.push(path);
    }
  }
  return { added, modified, deleted };
}

export async function checkFreshness(
  store: Store, git: GitInfo, hardenedGit: HardenedGit | null, options: { verify: boolean; extractors?: readonly Extractor[] }
): Promise<FreshnessReport> {
  const generationId = currentGenerationId(store.db);
  const empty = { added: [], modified: [], deleted: [], truncated: false };
  if (generationId === null) {
    return { level: "unknown", basis: "no published generation", generationId: null, indexedRevision: null, currentRevision: git.revision, revisionChanged: false, sourceFingerprint: null, indexerChanged: false, ...empty };
  }
  const gen = store.db.prepare("SELECT revision, source_fingerprint AS fp, extractor_set_hash AS ext, resolver_version AS res FROM generations WHERE id = ?").get(generationId) as {
    revision: string | null; fp: string | null; ext: string; res: string | null;
  };
  const extractors = (options.extractors ?? DEFAULT_EXTRACTORS).map((e) => ({ id: e.id, version: e.version, extensions: e.extensions }));
  const rows = store.db.prepare(
    "SELECT path, content_hash AS contentHash, excluded_reason AS excludedReason, size, mtime_ns AS mtimeNs, ctime_ns AS ctimeNs, inode FROM generation_files WHERE generation_id = ?"
  ).all(generationId) as ManifestEntry[];
  const manifest = new Map(rows.map((r) => [r.path, r]));
  const indexerChanged = gen.ext !== extractorSetHash(extractors) || gen.res !== RESOLVER_VERSION;
  const base = { generationId, indexedRevision: gen.revision, currentRevision: git.revision, revisionChanged: gen.revision !== git.revision, sourceFingerprint: gen.fp, indexerChanged };

  const matcher = createExclusionMatcher(store.config().exclude);
  let candidates: Candidate[];
  try {
    candidates = await enumerateCandidates(git, hardenedGit, matcher);
  } catch {
    return { level: "unknown", basis: "could not list repository files", ...base, ...empty };
  }
  const diff = options.verify
    ? verifiedDiff(store, git, manifest, candidates)
    : heuristicDiff(git.root, manifest, candidates, (p) => matcher.excludesPath(p) !== null);
  const [added, a] = cap(diff.added);
  const [modified, m] = cap(diff.modified);
  const [deleted, d] = cap(diff.deleted);
  const changed = diff.added.length + diff.modified.length + diff.deleted.length > 0 || base.revisionChanged || indexerChanged;
  const basis = (options.verify
    ? "every candidate file re-read and compared by content hash"
    : "git file list and stat tuple (size, mtime, ctime, inode); metadata cannot prove content is unchanged") +
    (indexerChanged ? "; the extractor set or resolver version of this build differs from the one that built the index (re-index)" : "");
  return { level: changed ? "stale" : options.verify ? "hash_verified" : "heuristic", basis, ...base, added, modified, deleted, truncated: a || m || d };
}
