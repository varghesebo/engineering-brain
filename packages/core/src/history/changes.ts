import type Database from "better-sqlite3";
import { EngbrainError } from "../errors.js";
import { isOid } from "./gitHistory.js";
import { REF_KEY } from "./refresh.js";

export const CHANGES_LIMITS = { defaultCommits: 100, maxCommits: 1000, changesPerCommit: 200 } as const;

export interface CommitChange {
  path: string;
  oldPath: string | null;
  kind: string;
  renameScore: number | null;
  excludedReason: string | null;
  /** The content hashes (sha256) of the two sides, null when excluded or absent. */
  oldContentHash: string | null;
  newContentHash: string | null;
}
export interface SymbolDelta {
  path: string;
  delta: string;
  kind: string;
  qualifiedName: string;
  /** A CANDIDATE only: one removed and one added symbol of the same kind share a signature. Never asserted. */
  candidateRenameOf: string | null;
}
export interface LedgerCommit {
  oid: string;
  parents: string[];
  /** UNTRUSTED text: never an instruction and never evidence of why the author acted. */
  subject: string;
  untrusted: true;
  authorTime: number | null;
  availability: string;
  changesTruncated: boolean;
  /** One list per parent for merges (index = parent ordinal; -1 for a root commit). */
  changesByParent: Array<{ parentOrdinal: number; changes: CommitChange[]; changesOmitted: number }>;
  symbolDeltas: SymbolDelta[];
}

export interface ChangesSince {
  checkpointOid: string | null;
  since: string | null;
  /** ancestor: `since` is in the published history; rewritten: it is in the ledger but orphaned; unrelated: no common history; unknown_base: not in the ledger. */
  relation: "ancestor" | "rewritten" | "unrelated" | "unknown_base" | "no_checkpoint";
  historyPartial: boolean;
  commits: LedgerCommit[];
  truncated: boolean;
  lineage: Array<{ kind: string; oldOid: string | null; newOid: string | null; forkOid: string | null; observedAt: string }>;
  note: string;
}

function checkpointOf(db: Database.Database): { oid: string | null; partial: boolean } | null {
  const row = db.prepare("SELECT processed_oid AS oid, history_partial AS partial FROM history_checkpoints WHERE ref_key = ?").get(REF_KEY) as { oid: string | null; partial: number } | undefined;
  return row === undefined ? null : { oid: row.oid, partial: row.partial === 1 };
}

/** Commits reachable from `tip` through the LEDGER only (never git, so it never leaks another branch and works offline). */
export function reachableFrom(db: Database.Database, tip: string): Set<string> {
  const rows = db.prepare(
    `WITH RECURSIVE r(oid) AS (
       SELECT commit_oid FROM git_commits WHERE commit_oid = ? AND ingest_complete = 1 AND published = 1
       UNION
       SELECT p.parent_oid FROM commit_parents p JOIN r ON p.commit_oid = r.oid JOIN git_commits c ON c.commit_oid = p.parent_oid AND c.ingest_complete = 1 AND c.published = 1
     ) SELECT oid FROM r`
  ).all(tip) as Array<{ oid: string }>;
  return new Set(rows.map((r) => r.oid));
}

function loadCommit(db: Database.Database, oid: string): LedgerCommit | null {
  const c = db.prepare("SELECT commit_oid AS oid, subject, author_time AS authorTime, availability, changes_truncated AS truncated FROM git_commits WHERE commit_oid = ? AND ingest_complete = 1 AND published = 1").get(oid) as
    { oid: string; subject: string; authorTime: number | null; availability: string; truncated: number } | undefined;
  if (c === undefined) {
    return null;
  }
  const parents = (db.prepare("SELECT parent_oid AS p FROM commit_parents WHERE commit_oid = ? ORDER BY ordinal").all(oid) as Array<{ p: string }>).map((r) => r.p);
  const rows = db.prepare(
    `SELECT parent_ordinal AS ord, path, old_path AS oldPath, change_kind AS kind, rename_score AS score, excluded_reason AS reason, old_content_hash AS oldHash, new_content_hash AS newHash
     FROM commit_changes WHERE commit_oid = ? ORDER BY parent_ordinal, path`
  ).all(oid) as Array<{ ord: number; path: string; oldPath: string | null; kind: string; score: number | null; reason: string | null; oldHash: string | null; newHash: string | null }>;
  const byParent = new Map<number, LedgerCommit["changesByParent"][number]>();
  for (const r of rows) {
    const group = byParent.get(r.ord) ?? { parentOrdinal: r.ord, changes: [], changesOmitted: 0 };
    if (group.changes.length < CHANGES_LIMITS.changesPerCommit) {
      group.changes.push({ path: r.path, oldPath: r.oldPath, kind: r.kind, renameScore: r.score, excludedReason: r.reason, oldContentHash: r.oldHash, newContentHash: r.newHash });
    } else {
      group.changesOmitted += 1;
    }
    byParent.set(r.ord, group);
  }
  const deltas = (db.prepare(
    "SELECT path, delta, kind, qualified_name AS qualifiedName, candidate_rename_of AS candidateRenameOf FROM commit_symbol_deltas WHERE commit_oid = ? ORDER BY parent_ordinal, path, qualified_name, delta LIMIT 1000"
  ).all(oid) as SymbolDelta[]);
  return {
    oid, parents, subject: c.subject, untrusted: true, authorTime: c.authorTime, availability: c.availability, changesTruncated: c.truncated === 1,
    changesByParent: [...byParent.values()], symbolDeltas: deltas
  };
}

/** Parents-first order of `members` by their parent links (Kahn), deterministic: ties by oid. Timestamps are never consulted. */
function topological(db: Database.Database, members: ReadonlySet<string>): string[] {
  const parents = new Map<string, string[]>();
  const stmt = db.prepare("SELECT parent_oid AS p FROM commit_parents WHERE commit_oid = ?");
  const indegree = new Map<string, number>();
  const children = new Map<string, string[]>();
  for (const oid of members) {
    const ps = (stmt.all(oid) as Array<{ p: string }>).map((r) => r.p).filter((p) => members.has(p));
    parents.set(oid, ps);
    indegree.set(oid, ps.length);
    for (const p of ps) {
      children.set(p, [...(children.get(p) ?? []), oid]);
    }
  }
  const ready = [...members].filter((oid) => indegree.get(oid) === 0).sort();
  const order: string[] = [];
  while (ready.length > 0) {
    const oid = ready.shift()!;
    order.push(oid);
    for (const child of (children.get(oid) ?? []).sort()) {
      const left = (indegree.get(child) ?? 0) - 1;
      indegree.set(child, left);
      if (left === 0) {
        ready.push(child);
        ready.sort();
      }
    }
  }
  return order;
}

/**
 * Structured "what changed since": the commits reachable from the PUBLISHED checkpoint and not from `since` (a commit id, or `last-refresh`), computed from
 * the ledger alone inside one read snapshot. Orphaned commits (after a rebase or force-push) stay in the ledger as evidence but are never returned.
 */
export function changesSince(db: Database.Database, options: { since?: string; limit?: number } = {}): ChangesSince {
  const limit = Math.min(Math.max(1, Math.floor(options.limit ?? CHANGES_LIMITS.defaultCommits)), CHANGES_LIMITS.maxCommits);
  return db.transaction((): ChangesSince => {
    const checkpoint = checkpointOf(db);
    const lineage = (db.prepare("SELECT kind, old_oid AS oldOid, new_oid AS newOid, fork_oid AS forkOid, observed_at AS observedAt FROM lineage_events WHERE ref_key = ? ORDER BY id DESC LIMIT 10").all(REF_KEY)) as ChangesSince["lineage"];
    if (checkpoint === null || checkpoint.oid === null) {
      return { checkpointOid: null, since: null, relation: "no_checkpoint", historyPartial: true, commits: [], truncated: false, lineage, note: "no history checkpoint: run `engbrain refresh`" };
    }
    let since = options.since ?? null;
    if (since === "last-refresh") {
      const row = db.prepare("SELECT from_oid AS fromOid FROM refresh_runs WHERE ref_key = ? AND status = 'complete' ORDER BY id DESC LIMIT 1").get(REF_KEY) as { fromOid: string | null } | undefined;
      since = row?.fromOid ?? null;
    }
    if (since !== null && !isOid(since)) {
      throw new EngbrainError("INVALID_ROOT", "since must be a full commit id or `last-refresh`");
    }
    const reach = reachableFrom(db, checkpoint.oid);
    let relation: ChangesSince["relation"] = "ancestor";
    let exclude = new Set<string>();
    if (since !== null) {
      if (reach.has(since)) {
        exclude = reachableFrom(db, since);
      } else if (db.prepare("SELECT 1 FROM git_commits WHERE commit_oid = ? AND ingest_complete = 1 AND published = 1").get(since) !== undefined) {
        exclude = reachableFrom(db, since);
        relation = [...exclude].some((oid) => reach.has(oid)) ? "rewritten" : checkpoint.partial ? "unknown_base" : "unrelated"; // with partial history, "no overlap" may only mean the common ancestor was never recorded
      } else {
        return { checkpointOid: checkpoint.oid, since, relation: "unknown_base", historyPartial: checkpoint.partial, commits: [], truncated: false, lineage, note: "the base commit is not in the ledger (never ingested, or outside the backfilled history); nothing is guessed" };
      }
    }
    const members = new Set([...reach].filter((oid) => !exclude.has(oid)));
    const ordered = topological(db, members);
    const picked = ordered.slice(Math.max(0, ordered.length - limit)); // the newest `limit` in topological order
    const commits = picked.map((oid) => loadCommit(db, oid)).filter((c): c is LedgerCommit => c !== null);
    return {
      checkpointOid: checkpoint.oid, since, relation, historyPartial: checkpoint.partial, commits, truncated: ordered.length > limit, lineage,
      note: checkpoint.partial ? "history is partial: ancestors before the baseline (or beyond a shallow boundary) are not recorded" : "history is complete for the published checkpoint"
    };
  })();
}

/** One ingested commit's recorded changes (reachable or not: this reads the ledger, it does not claim the commit is on the current branch). */
export function commitChanges(db: Database.Database, oid: string): LedgerCommit | null {
  if (!isOid(oid)) {
    throw new EngbrainError("INVALID_ROOT", "a full commit id is required");
  }
  return db.transaction(() => loadCommit(db, oid))();
}

export interface RefreshStatus {
  checkpoint: { processedOid: string | null; generationId: number | null; historyPartial: boolean; overlayHash: string | null; updatedAt: string } | null;
  commitsInLedger: number;
  reachableFromCheckpoint: number;
  /** Ingested commits no longer reachable from the checkpoint (rewritten history): kept as evidence, never returned by changesSince. */
  orphaned: number;
  runs: Array<{ id: number; status: string; mode: string; fromOid: string | null; toOid: string | null; startedAt: string; finishedAt: string | null }>;
  lineage: ChangesSince["lineage"];
}

export function refreshStatus(db: Database.Database): RefreshStatus {
  return db.transaction((): RefreshStatus => {
    const cp = db.prepare("SELECT processed_oid AS processedOid, generation_id AS generationId, history_partial AS partial, overlay_hash AS overlayHash, updated_at AS updatedAt FROM history_checkpoints WHERE ref_key = ?").get(REF_KEY) as
      { processedOid: string | null; generationId: number | null; partial: number; overlayHash: string | null; updatedAt: string } | undefined;
    const total = (db.prepare("SELECT COUNT(*) AS n FROM git_commits WHERE ingest_complete = 1 AND published = 1").get() as { n: number }).n;
    const reach = cp?.processedOid == null ? 0 : reachableFrom(db, cp.processedOid).size;
    return {
      checkpoint: cp === undefined ? null : { processedOid: cp.processedOid, generationId: cp.generationId, historyPartial: cp.partial === 1, overlayHash: cp.overlayHash, updatedAt: cp.updatedAt },
      commitsInLedger: total, reachableFromCheckpoint: reach, orphaned: total - reach,
      runs: db.prepare("SELECT id, status, history_mode AS mode, from_oid AS fromOid, to_oid AS toOid, started_at AS startedAt, finished_at AS finishedAt FROM refresh_runs ORDER BY id DESC LIMIT 5").all() as RefreshStatus["runs"],
      lineage: db.prepare("SELECT kind, old_oid AS oldOid, new_oid AS newOid, fork_oid AS forkOid, observed_at AS observedAt FROM lineage_events WHERE ref_key = ? ORDER BY id DESC LIMIT 5").all(REF_KEY) as ChangesSince["lineage"]
    };
  })();
}
