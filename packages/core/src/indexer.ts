import { join } from "node:path";
import type { HardenedGit } from "@engbrain/security";
import { type AuditLog } from "./audit.js";
import { createExclusionMatcher, type ExclusionMatcher } from "./exclusions.js";
import { EngbrainError } from "./errors.js";
import type { GitInfo } from "./identity.js";
import { createInspectContext, enumerateCandidates, inspectCandidate, type Candidate } from "./candidates.js";
import { FactWriter } from "./factWriter.js";
import type { Extractor } from "./extractor.js";
import { isCodeExtractorId } from "./codeExtractor.js";
import { DEFAULT_EXTRACTORS } from "./defaultExtractors.js";
import { databaseSizeBytes, peakRssMiB, summarizeGeneration, type GenerationSummary } from "./indexStats.js";
import { buildGraphEdges, type GraphBuildStats } from "./graphBuilder.js";
import { buildFeatureGraph, type FeatureBuildStats } from "./features/featureBuilder.js";
import { RESOLVER_VERSION } from "./moduleResolver.js";
import { collectGarbage } from "./store/gc.js";
import {
  computeSourceFingerprint, createBuildingGeneration, currentGenerationId, discardGeneration, extractorSetHash,
  insertManifest, markAbandoned, publishGeneration, validateGeneration, type FaultHook, type ManifestRow
} from "./store/generations.js";
import { acquireWriterLock, type LockOptions } from "./store/lock.js";
import type { Store } from "./store/store.js";


export interface IndexOptions {
  store: Store;
  git: GitInfo;
  /** Required when `git.isGit`. */
  hardenedGit: HardenedGit | null;
  audit?: AuditLog;
  /** Defaults to the inventory + TS/JS syntax extractors. */
  extractors?: readonly Extractor[];
  lock?: LockOptions;
  /** Test hook: called at named points so crashes/aborts can be injected. Not exposed by the CLI. */
  fault?: FaultHook;
  now?: () => Date;
  /** Extension points for callers that must do their own work under the same writer lock (the history refresh). All optional. */
  hooks?: IndexHooks;
}

export interface IndexHooks {
  /** After the `building` generation exists and before facts are built. Throwing aborts the run (the generation is abandoned on the next recovery). */
  beforeBuild?: (generationId: number) => Promise<void>;
  /** After validation, immediately before publication. */
  beforePublish?: (generationId: number) => Promise<void>;
  /** INSIDE the publication transaction. */
  inPublish?: (db: import("better-sqlite3").Database, generationId: number) => void;
  /** Inside one transaction when nothing changed and the current generation is kept. */
  onUnchanged?: (db: import("better-sqlite3").Database, generationId: number) => void;
}

export interface IndexStats {
  candidates: number;
  included: number;
  excluded: number;
  excludedByReason: Record<string, number>;
  missing: number;
  /** Distinct blobs for which at least one extractor actually ran (the "reprocessed" count). */
  extractorRuns: number;
  /** Included files whose facts already existed (content-addressed reuse). */
  factsReused: number;
  recoveredAbandoned: number;
  gcGenerationsRemoved: number;
  gcFactsRemoved: number;
  durationMs: number;
  /** Code extractor activity in THIS run (blobs actually parsed; reused facts are not counted here). */
  parser: { parsed: number; failed: number; skipped: number; symbolsExtracted: number; refsExtracted: number };
  /** The path-dependent graph build of THIS run; null when the run kept the existing generation. */
  graph: GraphBuildStats | null;
  /** The feature graph build of THIS run; null when the run kept the existing generation. */
  features: FeatureBuildStats | null;
  /** Measured, not estimated. */
  dbSizeBytes: number;
  peakRssMiB: number;
}

export interface IndexResult {
  generationId: number;
  /** True when nothing changed and the current generation was kept (no new generation published). */
  unchanged: boolean;
  revision: string | null;
  sourceFingerprint: string;
  stats: IndexStats;
  /** What the published (or retained) generation contains: files, languages, parser coverage, symbols, edges, changes. */
  summary: GenerationSummary;
}

export { DEFAULT_EXTRACTORS };

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
  const extractors = options.extractors ?? DEFAULT_EXTRACTORS;
  const extractorRefs = extractors.map((e) => ({ id: e.id, version: e.version, extensions: e.extensions }));
  const matcher = createExclusionMatcher(config.exclude);
  const lock = await acquireWriterLock(store.dir, options.lock);
  let generationId: number | null = null;
  try {
    const recoveredAbandoned = markAbandoned(store.db);
    const parentId = currentGenerationId(store.db);
    options.audit?.record("index_start", { parentGeneration: parentId, extractors: extractors.map((e) => `${e.id}@${e.version}`) });

    generationId = createBuildingGeneration(store.db, {
      parentId,
      revision: options.git.revision,
      branchLabel: options.git.branchLabel,
      extractors: extractorRefs,
      resolverVersion: RESOLVER_VERSION,
      now: now()
    });
    await options.hooks?.beforeBuild?.(generationId);
    options.fault?.("pre-facts");

    const candidates = await enumerateCandidates(options.git, options.hardenedGit, matcher);
    const outcome = await buildFactsAndRows(options, candidates, matcher, config.maxFileBytes, extractors);

    options.fault?.("pre-manifest");
    insertManifest(store.db, generationId, outcome.rows);
    const fingerprint = computeSourceFingerprint(store.db, generationId);

    const unchanged = isUnchanged(store, parentId, fingerprint, options.git, extractorRefs);
    if (unchanged && parentId !== null) {
      discardGeneration(store.db, generationId);
      await options.hooks?.beforePublish?.(parentId); // the kept generation is the one being "published": per-run observations (dirty overlay) must be recomputed, not lost
      if (options.hooks?.onUnchanged !== undefined) {
        const hook = options.hooks.onUnchanged;
        store.db.transaction(() => hook(store.db, parentId)).immediate();
      }
      const gc = collectGarbage(store.db, config.generationsToKeep);
      return finish(options, parentId, true, fingerprint, outcome, recoveredAbandoned, gc, started, null, null);
    }

    const graph = buildGraphEdges(store.db, generationId, options.git.root, parentId);
    const features = buildFeatureGraph(store.db, generationId);
    const validation = validateGeneration(store.db, generationId, fingerprint, { deep: false });
    if (!validation.ok) {
      throw new EngbrainError("INTEGRITY_FAILED", `generation failed validation: ${validation.problems.join("; ")}`);
    }
    await options.hooks?.beforePublish?.(generationId);
    options.fault?.("pre-publish");
    publishGeneration(store.db, generationId, { fingerprint, now: now(), fault: options.fault, inTransaction: options.hooks?.inPublish === undefined ? undefined : (db) => options.hooks!.inPublish!(db, generationId!) });
    const gc = collectGarbage(store.db, config.generationsToKeep);
    return finish(options, generationId, false, fingerprint, outcome, recoveredAbandoned, gc, started, graph, features);
  } catch (error) {
    options.audit?.record("index_failed", { code: error instanceof EngbrainError ? error.code : "ERROR" });
    throw error;
  } finally {
    lock.release();
  }
}

function isUnchanged(store: Store, parentId: number | null, fingerprint: string, git: GitInfo, extractors: Array<{ id: string; version: string; extensions?: readonly string[] | undefined }>): boolean {
  if (parentId === null) {
    return false;
  }
  const parent = store.db
    .prepare("SELECT revision, branch_label AS branch, source_fingerprint AS fp, extractor_set_hash AS ext, resolver_version AS res FROM generations WHERE id = ?")
    .get(parentId) as { revision: string | null; branch: string | null; fp: string | null; ext: string; res: string | null };
  return (
    parent.fp === fingerprint &&
    parent.revision === git.revision &&
    parent.branch === git.branchLabel &&
    parent.ext === extractorSetHash(extractors) &&
    parent.res === RESOLVER_VERSION
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
  started: number,
  graph: GraphBuildStats | null,
  features: FeatureBuildStats | null
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
    durationMs: Date.now() - started,
    parser: outcome.parser,
    graph,
    features,
    dbSizeBytes: databaseSizeBytes(join(options.store.dir, "store.db")),
    peakRssMiB: peakRssMiB()
  };
  options.audit?.record("index_end", {
    generation: generationId, unchanged, included: stats.included, excluded: stats.excluded,
    extractorRuns: stats.extractorRuns, durationMs: stats.durationMs
  });
  return {
    generationId, unchanged, revision: options.git.revision, sourceFingerprint: fingerprint, stats,
    summary: summarizeGeneration(options.store.db, generationId)
  };
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
  parser: IndexStats["parser"];
}

function excludedRow(path: string, reason: string): ManifestRow {
  return { path, contentHash: null, size: null, mtimeNs: null, ctimeNs: null, inode: null, excludedReason: reason };
}

async function buildFactsAndRows(
  options: IndexOptions,
  candidates: Candidate[],
  matcher: ExclusionMatcher,
  maxFileBytes: number,
  extractors: readonly Extractor[]
): Promise<BuildOutcome> {
  const outcome: BuildOutcome = {
    rows: [], candidates: candidates.length, included: 0, excluded: 0, excludedByReason: {}, missing: 0, extractorRuns: 0, factsReused: 0,
    parser: { parsed: 0, failed: 0, skipped: 0, symbolsExtracted: 0, refsExtracted: 0 }
  };
  const writer = new FactWriter(options.store.db, extractors, {
    onBatchFlushed: (batch) => {
      if (batch === 1) {
        options.fault?.("mid-facts");
      }
    }
  });
  await writer.prepare();
  const ctx = createInspectContext(options.git.root, matcher, maxFileBytes);
  const exclude = (path: string, reason: string): void => {
    outcome.rows.push(excludedRow(path, reason));
    outcome.excluded += 1;
    outcome.excludedByReason[reason] = (outcome.excludedByReason[reason] ?? 0) + 1;
  };
  for (const candidate of candidates) {
    const result = inspectCandidate(ctx, candidate);
    if (result.kind === "missing") {
      outcome.missing += 1;
    } else if (result.kind === "excluded") {
      exclude(candidate.storePath, result.reason);
    } else {
      outcome.rows.push(result.row);
      outcome.included += 1;
      if (writer.add(result.row.contentHash!, candidate.storePath, result.data)) {
        outcome.extractorRuns += 1;
      } else {
        outcome.factsReused += 1;
      }
    }
  }
  writer.flush();
  const parser = { parsed: 0, failed: 0, skipped: 0, symbolsExtracted: 0, refsExtracted: 0 };
  for (const [id, tally] of writer.counts) {
    if (isCodeExtractorId(id)) {
      parser.parsed += tally.ok + tally.error;
      parser.failed += tally.error;
      parser.skipped += tally.skipped;
      parser.symbolsExtracted += tally.symbols;
      parser.refsExtracted += tally.refs;
    }
  }
  outcome.parser = parser;
  return outcome;
}
