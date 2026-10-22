import type Database from "better-sqlite3";
import type { HardenedGit } from "@engbrain/security";
import { createExclusionMatcher } from "../exclusions.js";
import { EngbrainError } from "../errors.js";
import { DEFAULT_EXTRACTORS } from "../defaultExtractors.js";
import { indexRepository, type IndexOptions, type IndexResult } from "../indexer.js";
import { GitHistory } from "./gitHistory.js";
import { emptyIngestStats, ingestCommits, type IngestStats } from "./ledger.js";
import { computeOverlayHash } from "./overlay.js";

export const REF_KEY = "HEAD";
export type LineageKind = "baseline" | "advance" | "switch" | "rewrite" | "unrelated" | "head_unborn" | "base_missing";
export type HistoryMode = "none" | "backfill";

export interface RefreshOptions extends Omit<IndexOptions, "hooks"> {
  history?: HistoryMode;
  /** Most commits ingested in this run (default 5,000 for backfill, unbounded for new commits). */
  maxCommits?: number;
  batchSize?: number;
  timeBudgetMs?: number;
  /** Aborting stops between batches and abandons the run without publishing; the next refresh resumes. */
  signal?: AbortSignal;
  onProgress?: (done: number, total: number) => void;
}

export interface RefreshResult {
  index: IndexResult;
  runId: number;
  lineage: LineageKind;
  forkOid: string | null;
  fromOid: string | null;
  headOid: string | null;
  /** The commit the published checkpoint now covers (HEAD unless a budget stopped ingestion early). */
  processedOid: string | null;
  historyPartial: boolean;
  ingest: IngestStats;
  overlayHash: string | null;
  stopReason: "commit_budget" | "time_budget" | null;
  /** Commits that were reachable and unseen but not ingested this run (budget): a later run continues. */
  remaining: number;
  durationMs: number;
}

export class RefreshCancelled extends Error {
  constructor() {
    super("refresh cancelled; finished batches are kept and the next refresh resumes");
    this.name = "RefreshCancelled";
  }
}

interface Checkpoint { processedOid: string | null; historyPartial: boolean; branchLabel: string | null }

const readCheckpoint = (db: Database.Database): Checkpoint | null => {
  const row = db.prepare("SELECT processed_oid AS processedOid, history_partial AS partial, branch_label AS branch FROM history_checkpoints WHERE ref_key = ?").get(REF_KEY) as { processedOid: string | null; partial: number; branch: string | null } | undefined;
  return row === undefined ? null : { processedOid: row.processedOid, historyPartial: row.partial === 1, branchLabel: row.branch };
};

/** Ingested and still valid: a shallow-boundary commit stops counting once the repository is no longer shallow there (its changes were never recorded). */
const isComplete = (db: Database.Database, oid: string, shallow: ReadonlySet<string>): boolean => {
  const row = db.prepare("SELECT availability FROM git_commits WHERE commit_oid = ? AND ingest_complete = 1").get(oid) as { availability: string } | undefined;
  return row !== undefined && (row.availability !== "shallow_boundary" || shallow.has(oid));
};

interface Plan {
  lineage: LineageKind;
  forkOid: string | null;
  /** Parents-first. The first group is the new-commit work (advance/baseline), then older unseen commits when backfilling. */
  advance: string[];
  older: string[];
  extraPartial: boolean;
}

/**
 * Decides what to ingest from the published checkpoint and the current HEAD, using GRAPH relationships only (never timestamps):
 *   no checkpoint -> baseline; same -> nothing; checkpoint is an ancestor of HEAD -> advance (processed..HEAD);
 *   otherwise the checkpoint is orphaned: a rewrite/switch, with the merge base as fork (or `unrelated`); checkpoint object gone -> base_missing.
 */
async function planRefresh(db: Database.Database, history: GitHistory, head: string, checkpoint: Checkpoint | null, branchChanged: boolean, mode: HistoryMode, shallow: ReadonlySet<string>): Promise<Plan> {
  const known = (oids: string[]): string[] => oids.filter((oid) => !isComplete(db, oid, shallow));
  let lineage: LineageKind;
  let fork: string | null = null;
  let advance: string[];
  let extraPartial = false;
  const processed = checkpoint?.processedOid ?? null;
  if (processed === null) {
    lineage = "baseline";
    advance = known([head]);
    extraPartial = true;
  } else if (processed === head) {
    lineage = "advance";
    advance = [];
  } else if (!(await history.hasCommit(processed))) {
    lineage = "base_missing";
    advance = known([head]);
    extraPartial = true;
  } else if (await history.isAncestor(processed, head)) {
    lineage = "advance";
    advance = known((await history.listCommits(head, [processed])).map((c) => c.oid));
  } else {
    fork = await history.mergeBase(processed, head);
    lineage = fork === null ? "unrelated" : branchChanged ? "switch" : "rewrite";
    advance = fork === null ? known([head]) : known((await history.listCommits(head, [fork])).map((c) => c.oid));
    extraPartial = fork === null;
  }
  let older: string[] = [];
  if (mode === "backfill") {
    const taken = new Set(advance);
    older = (await history.listCommits(head)).map((c) => c.oid).filter((oid) => !taken.has(oid) && !isComplete(db, oid, shallow));
  }
  return { lineage, forkOid: fork, advance, older, extraPartial };
}

/**
 * `engbrain refresh`: under ONE writer lock, ingest new reachable commits into the ledger, build the current working-tree generation with the existing
 * indexer, and publish both atomically: in the same transaction that makes the generation current, the history checkpoint advances. Readers therefore see
 * the previous checkpoint until the whole run is published. A killed or failed run leaves finished commit batches (idempotent, skipped next time) and no
 * partial visible state. `history: "backfill"` additionally ingests older unseen commits, oldest first, up to `maxCommits` per run (resumable).
 */
export async function refreshRepository(options: RefreshOptions): Promise<RefreshResult> {
  const started = Date.now();
  const { store, git, hardenedGit } = options;
  if (!git.isGit || hardenedGit === null) {
    throw new EngbrainError("GIT_UNAVAILABLE", "refresh needs a git repository and git on PATH");
  }
  const db = store.db;
  const mode: HistoryMode = options.history ?? "none";
  const history = new GitHistory(hardenedGit as HardenedGit, git.root);
  const extractors = options.extractors ?? DEFAULT_EXTRACTORS;
  const config = store.config();
  const matcher = createExclusionMatcher(config.exclude);
  const now = options.now ?? ((): Date => new Date());
  const state = {
    runId: 0, lineage: "advance" as LineageKind, forkOid: null as string | null, fromOid: null as string | null, processedOid: null as string | null, partial: true,
    lineageDetail: null as string | null, branchLabel: git.branchLabel, ingest: emptyIngestStats(), overlayHash: null as string | null, stopReason: null as RefreshResult["stopReason"], remaining: 0
  };
  const head = git.revision;
  const deadline = options.timeBudgetMs === undefined ? null : started + options.timeBudgetMs;

  let index: IndexResult;
  try {
    index = await indexRepository({
    ...options,
    extractors,
    hooks: {
      beforeBuild: async () => {
        const checkpoint = readCheckpoint(db);
        state.fromOid = checkpoint?.processedOid ?? null;
        state.partial = checkpoint?.historyPartial ?? true;
        db.prepare("UPDATE refresh_runs SET status = 'failed', finished_at = ? WHERE status = 'running'").run(now().toISOString()); // a run that was killed cannot still be running: we hold the writer lock
        state.runId = Number(db.prepare(
          "INSERT INTO refresh_runs (ref_key, from_oid, to_oid, history_mode, status, started_at) VALUES (?, ?, ?, ?, 'running', ?)"
        ).run(REF_KEY, state.fromOid, head, mode, now().toISOString()).lastInsertRowid);
        if (head === null) {
          state.lineage = "head_unborn";
          state.processedOid = null;
          state.lineageDetail = null;
          return;
        }
        if (await history.hasAlternates()) {
          throw new EngbrainError("POLICY_REFUSED", "this repository borrows objects through objects/info/alternates (they may live anywhere): history ingestion is refused");
        }
        const branchChanged = checkpoint !== null && checkpoint.branchLabel !== git.branchLabel; // the branch at the last PUBLISHED refresh, not whatever a plain `index` saw
        const shallow = await history.shallowBoundaries();
        const plan = await planRefresh(db, history, head, checkpoint, branchChanged, mode, shallow);
        state.lineage = plan.lineage;
        state.forkOid = plan.forkOid;
        state.lineageDetail = JSON.stringify({ newCommits: plan.advance.length, olderUnseen: plan.older.length }); // the lineage EVENT is written at publication, with the checkpoint
        const objectFormat = await history.objectFormat();
        let ingested = 0;
        const limit = options.maxCommits ?? (mode === "backfill" ? 5000 : Number.POSITIVE_INFINITY);
        const deps = {
          db, history, matcher, maxFileBytes: config.maxFileBytes, extractors, objectFormat, shallow, runId: state.runId, fault: options.fault,
          shouldStop: () => {
            if (options.signal?.aborted === true) {
              throw new RefreshCancelled();
            }
            if (deadline !== null && Date.now() > deadline) {
              state.stopReason = "time_budget";
              return true;
            }
            return false;
          },
          onProgress: options.onProgress
        };
        const batch = options.batchSize ?? 100;
        const runGroup = async (oids: string[]): Promise<void> => {
          const room = Math.max(0, limit - ingested);
          const take = oids.slice(0, room);
          if (take.length < oids.length && state.stopReason === null) {
            state.stopReason = "commit_budget";
          }
          const stats = await ingestCommits(deps, take, batch);
          for (const key of Object.keys(stats) as Array<keyof IngestStats>) {
            if (key !== "stoppedEarly") {
              (state.ingest[key] as number) += stats[key] as number;
            }
          }
          ingested += stats.commitsIngested;
        };
        await runGroup(plan.advance);
        if (state.stopReason === null) {
          await runGroup(plan.older);
        }
        // how far the checkpoint may honestly move: the last commit of the new-commit group such that every earlier one is complete (a parents-first prefix)
        let reached: string | null = state.fromOid;
        let advanceDone = true;
        for (const oid of plan.advance) {
          if (!isComplete(db, oid, shallow)) {
            advanceDone = false;
            break;
          }
        }
        if (advanceDone) {
          reached = head;
        } else {
          const prefix = plan.advance.findIndex((oid) => !isComplete(db, oid, shallow));
          reached = prefix > 0 ? plan.advance[prefix - 1]! : state.fromOid;
        }
        state.processedOid = reached;
        const unseenOlder = mode === "backfill" ? plan.older.filter((oid) => !isComplete(db, oid, shallow)).length : null;
        state.remaining = plan.advance.filter((oid) => !isComplete(db, oid, shallow)).length + (unseenOlder ?? 0);
        const finished = mode === "backfill" && advanceDone && unseenOlder === 0 && shallow.size === 0;
        // history is complete only after a backfill that left nothing unseen in a non-shallow repository; it stays complete across later advances
        state.partial = finished ? false : shallow.size > 0 || checkpoint === null || checkpoint.historyPartial || plan.extraPartial;
      },
      beforePublish: async (generationId) => {
        const overlay = await computeOverlayHash(db, history, generationId, head, await history.objectFormat(), matcher, config.maxFileBytes);
        state.overlayHash = overlay.hash;
      },
      inPublish: (tx, generationId) => finishRun(tx, { ...state, headOid: head }, generationId, started, now),
      onUnchanged: (tx, generationId) => finishRun(tx, { ...state, headOid: head }, generationId, started, now)
    }
  });
  } catch (error) {
    if (state.runId !== 0) {
      db.prepare("UPDATE refresh_runs SET status = ?, finished_at = ? WHERE id = ? AND status = 'running'").run(error instanceof RefreshCancelled ? "cancelled" : "failed", now().toISOString(), state.runId);
    }
    throw error;
  }
  return {
    index, runId: state.runId, lineage: state.lineage, forkOid: state.forkOid, fromOid: state.fromOid, headOid: head, processedOid: state.processedOid,
    historyPartial: state.partial, ingest: state.ingest, overlayHash: state.overlayHash, stopReason: state.stopReason, remaining: state.remaining, durationMs: Date.now() - started
  };
}

function finishRun(
  tx: Database.Database,
  state: { runId: number; fromOid: string | null; forkOid: string | null; headOid: string | null; lineageDetail: string | null; branchLabel: string | null; processedOid: string | null; partial: boolean; ingest: IngestStats; overlayHash: string | null; stopReason: string | null; lineage: string; remaining: number },
  generationId: number, started: number, now: () => Date
): void {
  const stamp = now().toISOString();
  tx.prepare("UPDATE refresh_runs SET status = 'complete', generation_id = ?, overlay_hash = ?, finished_at = ?, stats_json = ? WHERE id = ?")
    .run(generationId, state.overlayHash, stamp, JSON.stringify({ ...state.ingest, lineage: state.lineage, stopReason: state.stopReason, remaining: state.remaining, durationMs: Date.now() - started }), state.runId);
  tx.prepare(
    `INSERT INTO history_checkpoints (ref_key, processed_oid, generation_id, run_id, history_partial, overlay_hash, branch_label, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(ref_key) DO UPDATE SET processed_oid = excluded.processed_oid, generation_id = excluded.generation_id, run_id = excluded.run_id,
       history_partial = excluded.history_partial, overlay_hash = excluded.overlay_hash, branch_label = excluded.branch_label, updated_at = excluded.updated_at`
  ).run(REF_KEY, state.processedOid, generationId, state.runId, state.partial ? 1 : 0, state.overlayHash, state.branchLabel, stamp);
  // the lineage event and the visibility of the ingested commits become real only now, in the same transaction as the checkpoint
  tx.prepare("INSERT INTO lineage_events (run_id, ref_key, kind, old_oid, new_oid, fork_oid, detail_json, observed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    .run(state.runId, REF_KEY, state.lineage, state.fromOid, state.headOid, state.forkOid, state.lineageDetail, stamp);
  if (state.processedOid !== null) {
    tx.prepare(
      `WITH RECURSIVE r(oid) AS (
         SELECT commit_oid FROM git_commits WHERE commit_oid = ? AND ingest_complete = 1
         UNION
         SELECT p.parent_oid FROM commit_parents p JOIN r ON p.commit_oid = r.oid JOIN git_commits c ON c.commit_oid = p.parent_oid AND c.ingest_complete = 1 AND c.published = 0
       ) UPDATE git_commits SET published = 1 WHERE commit_oid IN (SELECT oid FROM r)`
    ).run(state.processedOid);
  }
}
