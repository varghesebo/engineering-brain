import type Database from "better-sqlite3";
import { isCodeExtractorId } from "../codeExtractor.js";
import { evaluateContent } from "../contentPolicy.js";
import type { ExclusionMatcher } from "../exclusions.js";
import { extractorApplies, type Extractor } from "../extractor.js";
import { FactWriter } from "../factWriter.js";
import { toStorePath } from "../paths.js";
import type { FaultHook } from "../store/generations.js";
import { GitHistory, HISTORY_LIMITS, type RawChange, type RawCommit } from "./gitHistory.js";

export interface IngestDeps {
  db: Database.Database;
  history: GitHistory;
  matcher: ExclusionMatcher;
  maxFileBytes: number;
  extractors: readonly Extractor[];
  objectFormat: "sha1" | "sha256";
  /** Commits whose ancestry a shallow clone cut off: recorded, but their changes are UNKNOWN (never "everything added"). */
  shallow: ReadonlySet<string>;
  runId: number;
  fault?: FaultHook | undefined;
  /** Checked between batches: true stops cleanly (budget, cancellation); finished batches stay, the rest resumes later. */
  shouldStop?: (() => boolean) | undefined;
  /** Counts only, never source text. */
  onProgress?: ((done: number, total: number) => void) | undefined;
}

export interface IngestStats {
  commitsIngested: number;
  commitsAlreadyKnown: number;
  changes: number;
  blobsRead: number;
  blobsReused: number;
  extractorRuns: number;
  symbolDeltas: number;
  truncatedCommits: number;
  stoppedEarly: boolean;
}

export const emptyIngestStats = (): IngestStats => ({ commitsIngested: 0, commitsAlreadyKnown: 0, changes: 0, blobsRead: 0, blobsReused: 0, extractorRuns: 0, symbolDeltas: 0, truncatedCommits: 0, stoppedEarly: false });

interface BlobVerdict { hash: string | null; reason: string | null; size: number | null }
interface SymbolRow { kind: string; name: string; qualifiedName: string; signature: string | null }
interface Delta { delta: "added" | "removed" | "signature_changed"; kind: string; name: string; qualifiedName: string; ordinal: number; signature: string | null; candidateRenameOf: string | null }

/** Why a changed path (or a mode) is never read; the same exclusion policy `index` applies, so history never holds what the working tree index refuses. */
export function pathExclusion(matcher: ExclusionMatcher, path: string, mode: string): { storePath: string | null; reason: string | null } {
  const stored = toStorePath(path);
  if (!stored.ok) {
    // legal in git, unsafe for a working tree (a colon, a trailing dot...): still RECORDED, never read, and flagged
    return { storePath: path.normalize("NFC"), reason: "unsafe_path" };
  }
  if (mode === "120000") {
    return { storePath: stored.path, reason: "symlink" };
  }
  if (mode === "160000") {
    return { storePath: stored.path, reason: "submodule" };
  }
  return { storePath: stored.path, reason: matcher.excludesPath(stored.path) };
}

/**
 * Symbol additions, removals and signature changes between two versions of one file, by (kind, qualified name, ordinal among identical ones).
 * A removed/added pair is offered as a rename CANDIDATE only when exactly one removed and exactly one added symbol of the same kind share a signature
 * fingerprint; any ambiguity yields no candidate. It is never asserted.
 */
export function diffSymbols(before: readonly SymbolRow[], after: readonly SymbolRow[]): Delta[] {
  const group = (rows: readonly SymbolRow[]): Map<string, SymbolRow[]> => {
    const map = new Map<string, SymbolRow[]>();
    for (const row of rows) {
      const key = `${row.kind}\0${row.qualifiedName}`;
      map.set(key, [...(map.get(key) ?? []), row]);
    }
    return map;
  };
  const was = group(before);
  const now = group(after);
  const deltas: Delta[] = [];
  for (const key of new Set([...was.keys(), ...now.keys()])) {
    const old = was.get(key) ?? [];
    const next = now.get(key) ?? [];
    for (let i = 0; i < Math.max(old.length, next.length); i += 1) {
      const o = old[i];
      const n = next[i];
      if (o === undefined && n !== undefined) {
        deltas.push({ delta: "added", kind: n.kind, name: n.name, qualifiedName: n.qualifiedName, ordinal: i, signature: n.signature, candidateRenameOf: null });
      } else if (n === undefined && o !== undefined) {
        deltas.push({ delta: "removed", kind: o.kind, name: o.name, qualifiedName: o.qualifiedName, ordinal: i, signature: o.signature, candidateRenameOf: null });
      } else if (o !== undefined && n !== undefined && o.signature !== n.signature) {
        deltas.push({ delta: "signature_changed", kind: n.kind, name: n.name, qualifiedName: n.qualifiedName, ordinal: i, signature: n.signature, candidateRenameOf: null });
      }
    }
  }
  const added = deltas.filter((d) => d.delta === "added");
  const removed = deltas.filter((d) => d.delta === "removed");
  for (const a of added) {
    if (a.signature === null) {
      continue;
    }
    const sameAdded = added.filter((x) => x.kind === a.kind && x.signature === a.signature);
    const sameRemoved = removed.filter((x) => x.kind === a.kind && x.signature === a.signature);
    if (sameAdded.length === 1 && sameRemoved.length === 1) {
      a.candidateRenameOf = sameRemoved[0]!.qualifiedName;
    }
  }
  return deltas.sort((x, y) => (x.qualifiedName < y.qualifiedName ? -1 : x.qualifiedName > y.qualifiedName ? 1 : x.delta < y.delta ? -1 : x.delta > y.delta ? 1 : x.ordinal - y.ordinal));
}

interface PreparedChange extends RawChange {
  storePath: string | null;
  oldStorePath: string | null;
  newReason: string | null;
  oldReason: string | null;
}

/**
 * Ingests commits (given parents-first) into the ledger in batches. Each batch is ONE transaction that also marks its commits complete, so a killed run
 * never leaves a half-recorded commit and a resumed run redoes only unfinished batches. A blob already resolved (blob oid -> content hash) is neither
 * read nor re-parsed; facts are content-addressed and shared with the working-tree index.
 */
export async function ingestCommits(deps: IngestDeps, oids: readonly string[], batchSize = 100): Promise<IngestStats> {
  const stats = emptyIngestStats();
  const { db } = deps;
  const known = db.prepare("SELECT availability FROM git_commits WHERE commit_oid = ? AND ingest_complete = 1");
  // a commit recorded as a shallow boundary is NOT done once the repository is no longer shallow there: its changes were never recorded
  const pending = oids.filter((oid) => {
    const row = known.get(oid) as { availability: string } | undefined;
    return row === undefined || (row.availability === "shallow_boundary" && !deps.shallow.has(oid));
  });
  stats.commitsAlreadyKnown = oids.length - pending.length;
  const writer = new FactWriter(db, deps.extractors);
  await writer.prepare();
  const codeExtractors = deps.extractors.filter((e) => isCodeExtractorId(e.id));
  const symbolCache = new Map<string, SymbolRow[]>();
  const symbolsOf = (hash: string, extractor: Extractor): SymbolRow[] => {
    const key = `${hash}\0${extractor.id}\0${extractor.version}`;
    let rows = symbolCache.get(key);
    if (rows === undefined) {
      rows = db.prepare(
        "SELECT kind, name, qualified_name AS qualifiedName, signature_fingerprint AS signature FROM symbols WHERE content_hash = ? AND extractor_id = ? AND extractor_version = ? AND kind != 'module' ORDER BY local_id"
      ).all(hash, extractor.id, extractor.version) as SymbolRow[];
      if (symbolCache.size > 5000) {
        symbolCache.clear();
      }
      symbolCache.set(key, rows);
    }
    return rows;
  };
  const blobRow = db.prepare("SELECT content_hash AS hash, excluded_reason AS reason, size FROM blob_hashes WHERE blob_oid = ?");
  const insertBlob = db.prepare("INSERT OR IGNORE INTO blob_hashes (blob_oid, object_format, content_hash, size, excluded_reason) VALUES (?, ?, ?, ?, ?)");

  for (let start = 0; start < pending.length; ) {
    if (deps.shouldStop?.() === true) {
      stats.stoppedEarly = true;
      break;
    }
    deps.fault?.("ledger-pre-batch");
    const slice = pending.slice(start, start + batchSize);
    let batchChanges = 0; // bounds memory: a batch ends early once it holds this many changes (a single commit is bounded by the per-commit cap)
    let consumed = 0;
    const commits = await deps.history.readCommits(slice);
    const byOid = new Map(commits.map((c) => [c.oid, c]));
    const perCommit: Array<{ commit: RawCommit; availability: "full" | "shallow_boundary" | "oversized"; parents: string[]; diffs: Array<{ ordinal: number; changes: PreparedChange[]; truncated: boolean }> }> = [];
    const toResolve = new Map<string, string>(); // blob oid -> a path it has (extractor applicability)
    for (const oid of slice) {
      if (batchChanges > HISTORY_LIMITS.maxBatchChanges) {
        break;
      }
      consumed += 1;
      const commit = byOid.get(oid);
      if (commit === undefined) {
        continue; // not a commit object (or vanished): nothing to record
      }
      const oversized = commit.parents.length > HISTORY_LIMITS.maxParents;
      const boundary = deps.shallow.has(oid);
      const parents = commit.parents.slice(0, HISTORY_LIMITS.maxParents);
      const diffs: Array<{ ordinal: number; changes: PreparedChange[]; truncated: boolean }> = [];
      if (!oversized && !boundary) {
        const targets: Array<{ ordinal: number; parent: string | null }> = parents.length === 0 ? [{ ordinal: -1, parent: null }] : parents.map((parent, ordinal) => ({ ordinal, parent }));
        let room = HISTORY_LIMITS.maxChangesPerCommit; // shared across the parents of one commit
        for (const target of targets) {
          if (room <= 0) {
            diffs.push({ ordinal: target.ordinal, changes: [], truncated: true });
            continue;
          }
          const raw = await deps.history.diffTree(oid, target.parent);
          if (raw.changes.length > room) {
            raw.changes.length = room;
            raw.truncated = true;
          }
          room -= raw.changes.length;
          batchChanges += raw.changes.length;
          const changes = raw.changes.map((c): PreparedChange => {
            const next = pathExclusion(deps.matcher, c.path, c.newMode);
            const prior = pathExclusion(deps.matcher, c.oldPath ?? c.path, c.oldMode);
            return {
              ...c, storePath: next.storePath, oldStorePath: c.oldPath === null ? null : prior.storePath,
              newReason: c.newBlob === null ? null : next.reason, oldReason: c.oldBlob === null ? null : prior.reason
            };
          });
          for (const c of changes) {
            if (c.newBlob !== null && c.newReason === null && c.storePath !== null) {
              toResolve.set(c.newBlob, c.storePath);
            }
            if (c.oldBlob !== null && c.oldReason === null && (c.oldStorePath ?? c.storePath) !== null) {
              toResolve.set(c.oldBlob, (c.oldStorePath ?? c.storePath)!);
            }
          }
          diffs.push({ ordinal: target.ordinal, changes, truncated: raw.truncated });
        }
      }
      perCommit.push({ commit, availability: oversized ? "oversized" : boundary ? "shallow_boundary" : "full", parents, diffs });
    }

    // resolve blob oid -> content hash, reading a blob only if nothing is known about it or its facts are missing
    const verdicts = new Map<string, BlobVerdict>();
    const toRead: string[] = [];
    for (const [blob, path] of toResolve) {
      const row = blobRow.get(blob) as { hash: string | null; reason: string | null; size: number | null } | undefined;
      if (row !== undefined && (row.hash === null || writer.hasAllFacts(row.hash, path))) {
        verdicts.set(blob, { hash: row.hash, reason: row.reason, size: row.size });
        stats.blobsReused += 1;
      } else {
        toRead.push(blob);
      }
    }
    const fresh: Array<{ blob: string; verdict: BlobVerdict }> = [];
    if (toRead.length > 0) {
      const sizes = await deps.history.blobSizes(toRead);
      const readable = toRead.filter((blob) => {
        const size = sizes.get(blob);
        if (size === undefined || size === null) {
          verdicts.set(blob, { hash: null, reason: "missing_object", size: null });
          fresh.push({ blob, verdict: verdicts.get(blob)! });
          return false;
        }
        if (size > deps.maxFileBytes) {
          verdicts.set(blob, { hash: null, reason: "too_large", size });
          fresh.push({ blob, verdict: verdicts.get(blob)! });
          return false;
        }
        return true;
      });
      const bodies = await deps.history.readBlobs(readable, sizes);
      for (const blob of readable) {
        const data = bodies.get(blob);
        stats.blobsRead += 1;
        const verdict: BlobVerdict = { hash: null, reason: "missing_object", size: sizes.get(blob) ?? null };
        if (data !== undefined) {
          const checked = evaluateContent(data);
          if (checked.kind === "excluded") {
            verdict.reason = checked.reason;
          } else {
            verdict.hash = checked.hash;
            verdict.reason = null;
            if (writer.add(checked.hash, toResolve.get(blob)!, data)) {
              stats.extractorRuns += 1;
            }
          }
        }
        verdicts.set(blob, verdict);
        fresh.push({ blob, verdict });
      }
      writer.flush();
    }

    const insertCommit = db.prepare(
      "INSERT OR IGNORE INTO git_commits (commit_oid, object_format, tree_oid, author_time, committer_time, availability, subject, changes_truncated, ingest_complete, first_run_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)"
    );
    const insertParent = db.prepare("INSERT OR IGNORE INTO commit_parents (commit_oid, ordinal, parent_oid) VALUES (?, ?, ?)");
    const insertChange = db.prepare(
      `INSERT OR IGNORE INTO commit_changes (commit_oid, parent_ordinal, path, old_path, change_kind, old_blob, new_blob, old_content_hash, new_content_hash, rename_score, excluded_reason)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );
    const insertDelta = db.prepare(
      `INSERT OR IGNORE INTO commit_symbol_deltas (commit_oid, parent_ordinal, path, delta, kind, name, qualified_name, ordinal, signature_fingerprint, candidate_rename_of)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );
    db.transaction(() => {
      for (const { blob, verdict } of fresh) {
        if (verdict.reason !== "missing_object") { // "not available now" (partial or shallow repository) is not a property of the blob: never cached
          insertBlob.run(blob, deps.objectFormat, verdict.hash, verdict.size, verdict.reason);
        }
      }
      let first = true;
      for (const { commit, availability, parents, diffs } of perCommit) {
        let truncated = diffs.some((d) => d.truncated);
        db.prepare("DELETE FROM git_commits WHERE commit_oid = ? AND (ingest_complete = 0 OR availability = 'shallow_boundary')").run(commit.oid);
        insertCommit.run(commit.oid, deps.objectFormat, commit.tree, commit.authorTime, commit.committerTime, availability, commit.subject, truncated ? 1 : 0, deps.runId);
        parents.forEach((parent, ordinal) => insertParent.run(commit.oid, ordinal, parent));
        for (const diff of diffs) {
          for (const c of diff.changes) {
            if (c.storePath === null) {
              continue;
            }
            // a side's hash is recorded only when that side is read-eligible: a sensitive, symlink or unsafe path never carries a hash, even if the same blob was resolved elsewhere
            const oldVerdict = c.oldBlob === null || c.oldReason !== null ? undefined : verdicts.get(c.oldBlob);
            const newVerdict = c.newBlob === null || c.newReason !== null ? undefined : verdicts.get(c.newBlob);
            const reason = c.newReason ?? c.oldReason ?? (newVerdict?.reason ?? oldVerdict?.reason ?? null);
            const inserted = insertChange.run(commit.oid, diff.ordinal, c.storePath, c.oldStorePath, c.kind, c.oldBlob, c.newBlob, oldVerdict?.hash ?? null, newVerdict?.hash ?? null, c.renameScore, reason);
            if (inserted.changes === 0) {
              truncated = true; // two paths normalised to the same key: the list is incomplete and says so
              continue;
            }
            stats.changes += 1;
            const extractor = codeExtractors.find((e) => extractorApplies(e, c.storePath!));
            const wasHash = oldVerdict?.hash ?? null;
            const nowHash = newVerdict?.hash ?? null;
            // symbol deltas only when BOTH versions that exist are known: an excluded or unreadable side would otherwise turn every symbol into an "addition"
            const bothKnown = (c.oldBlob === null || wasHash !== null) && (c.newBlob === null || nowHash !== null);
            if (extractor !== undefined && bothKnown && (wasHash !== null || nowHash !== null) && c.kind !== "type_changed") {
              const deltas = diffSymbols(wasHash === null ? [] : symbolsOf(wasHash, extractor), nowHash === null ? [] : symbolsOf(nowHash, extractor));
              for (const d of deltas) {
                insertDelta.run(commit.oid, diff.ordinal, c.storePath, d.delta, d.kind, d.name, d.qualifiedName, d.ordinal, d.signature, d.candidateRenameOf);
                stats.symbolDeltas += 1;
              }
            }
          }
        }
        if (truncated) {
          db.prepare("UPDATE git_commits SET changes_truncated = 1 WHERE commit_oid = ?").run(commit.oid);
          stats.truncatedCommits += 1;
        }
        if (first) {
          first = false;
          deps.fault?.("ledger-mid-batch");
        }
        stats.commitsIngested += 1;
      }
    }).immediate();
    deps.fault?.("ledger-post-batch");
    start += Math.max(1, consumed);
    deps.onProgress?.(Math.min(start, pending.length), pending.length);
  }
  return stats;
}
