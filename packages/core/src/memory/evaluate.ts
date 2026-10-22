import { createHash } from "node:crypto";
import type Database from "better-sqlite3";
import { reachableFrom } from "../history/changes.js";
import { currentGenerationId } from "../store/generations.js";
import { prep } from "./prepared.js";
import type { MemoryRow, Predicate } from "./records.js";

/**
 * Whether a record APPLIES right now. Computed at read time from the current published generation, the history ledger and the environment table, never read from a stored flag:
 *   superseded / expired / ended   the record's own time windows
 *   out_of_scope                   recorded on a line of history that is not an ancestor of the current checkpoint (another branch)
 *   unknown                        applicability cannot be established (no ledger entry for its revision, no checkpoint, an environment value never recorded, no index, not yet valid, altered content)
 *   stale                          an invalidation predicate fails, or a model-derived record has lost its independent substantiation
 *   applies                        none of the above
 * Unknown is NOT treated as applies. Retrieval excludes everything but `applies` by default (safe forgetting).
 * One `EvalContext` serves a whole query: the (potentially large) set of commits reachable from the checkpoint is computed once, not once per record.
 */
export type StandingState = "applies" | "stale" | "unknown" | "out_of_scope" | "expired" | "superseded" | "ended";
export interface Standing { state: StandingState; reasons: string[]; warnings: string[] }

interface StoredPointer { kind: string; path: string | null; ref: string | null; contentHash: string | null; signature?: string | null; role?: string; failing?: boolean }

export interface EvalContext {
  db: Database.Database;
  nowIso: string;
  generationId: number | null;
  checkpoint: { oid: string | null; overlay: string | null } | undefined;
  reachable(): Set<string> | null;
  knownCommit(oid: string): boolean;
}

export function makeEvalContext(db: Database.Database, nowIso: string): EvalContext {
  const generationId = currentGenerationId(db);
  const checkpoint = prep(db, "SELECT processed_oid AS oid, overlay_hash AS overlay FROM history_checkpoints WHERE ref_key = 'HEAD'").get() as { oid: string | null; overlay: string | null } | undefined;
  let reach: Set<string> | null | undefined;
  const known = new Map<string, boolean>();
  return {
    db, nowIso, generationId, checkpoint,
    reachable: () => {
      if (reach === undefined) {
        reach = checkpoint?.oid == null ? null : reachableFrom(db, checkpoint.oid);
      }
      return reach;
    },
    knownCommit: (oid) => {
      let k = known.get(oid);
      if (k === undefined) {
        k = prep(db, "SELECT 1 FROM git_commits WHERE commit_oid = ? AND ingest_complete = 1 AND published = 1").get(oid) !== undefined;
        known.set(oid, k);
      }
      return k;
    }
  };
}

/** The hash the record was created with, recomputed from what is stored: any difference means a stored content column was altered behind the immutability trigger. */
export function recomputeContentHash(row: MemoryRow): string {
  return createHash("sha256").update(JSON.stringify({
    kind: row.kind, title: row.title, body: row.body, origin: row.origin, proposer: row.proposer, validFrom: row.valid_from, validTo: row.valid_to,
    scope: JSON.parse(row.scope_json) as unknown, evidence: JSON.parse(row.evidence_json) as unknown, predicates: JSON.parse(row.invalidation_json) as unknown
  })).digest("hex");
}

/** A record derived from model inference (declared origin OR evidence type) needs live, independent substantiation to be authoritative. */
export const needsSubstantiation = (row: MemoryRow): boolean => row.origin === "model" || (JSON.parse(row.evidence_json) as { type?: string }).type === "model_inference";

function substantiated(ctx: EvalContext, row: MemoryRow, depth: number): boolean {
  const targets = prep(ctx.db, "SELECT target_id AS t FROM memory_links WHERE record_id = ? AND rel = 'substantiated_by'").all(row.record_id) as Array<{ t: string }>;
  return targets.some(({ t }) => {
    const other = prep(ctx.db, "SELECT * FROM memory_records WHERE record_id = ?").get(t) as MemoryRow | undefined;
    return other !== undefined && !needsSubstantiation(other) && other.proposer !== row.proposer && (other.status === "approved" || other.status === "verified") && depth < 2 && evaluateInContext(ctx, other, depth + 1).state === "applies";
  });
}

export function evaluateRecord(db: Database.Database, row: MemoryRow, now: string | EvalContext): Standing {
  return evaluateInContext(typeof now === "string" ? makeEvalContext(db, now) : now, row, 0);
}

function evaluateInContext(ctx: EvalContext, row: MemoryRow, depth: number): Standing {
  const { db, nowIso } = ctx;
  const warnings: string[] = [];
  if (row.superseded_at !== null) {
    return { state: "superseded", reasons: [`superseded by ${row.superseded_by ?? "a later record"}`], warnings };
  }
  if (row.expires_at !== null && row.expires_at <= nowIso) {
    return { state: "expired", reasons: [`expired at ${row.expires_at}`], warnings };
  }
  if (row.valid_to !== null && row.valid_to <= nowIso) {
    return { state: "ended", reasons: [`valid until ${row.valid_to}`], warnings };
  }
  if (recomputeContentHash(row) !== row.content_hash) {
    return { state: "unknown", reasons: ["the stored content does not match the hash it was recorded with: the record was altered and is not trusted"], warnings };
  }
  if (row.valid_from > nowIso) {
    return { state: "unknown", reasons: [`not yet valid (valid from ${row.valid_from})`], warnings };
  }
  const generationId = ctx.generationId;
  if (generationId === null) {
    return { state: "unknown", reasons: ["no published index to judge applicability against"], warnings };
  }
  const checkpoint = ctx.checkpoint;
  if (checkpoint?.overlay != null) {
    warnings.push("the working tree has uncommitted changes: the record is judged against the working tree, not the committed revision");
  }
  if (row.binding_revision !== null) {
    if (checkpoint === undefined || checkpoint.oid === null) {
      return { state: "unknown", reasons: ["no history checkpoint: whether this record belongs to the current line of history cannot be established (run `engbrain refresh`)"], warnings };
    }
    if (!ctx.knownCommit(row.binding_revision)) {
      return { state: "unknown", reasons: ["the revision this record was made against is not in the history ledger: its branch cannot be established"], warnings };
    }
    if (!(ctx.reachable()?.has(row.binding_revision) ?? false)) {
      return { state: "out_of_scope", reasons: ["recorded on a different line of history (not an ancestor of the current checkpoint)"], warnings };
    }
  }
  const pointers = (JSON.parse(row.evidence_json) as { pointers: StoredPointer[] }).pointers;
  const predicates = JSON.parse(row.invalidation_json) as Predicate[];
  const stale: string[] = [];
  const unknown: string[] = [];
  const fileHash = prep(db, "SELECT content_hash AS h FROM generation_files WHERE generation_id = ? AND path = ? AND content_hash IS NOT NULL");
  for (const predicate of predicates) {
    if (predicate.type === "environment") {
      const current = prep(db, "SELECT value FROM memory_environment WHERE key = ? ORDER BY id DESC LIMIT 1").get(predicate.key) as { value: string } | undefined;
      if (current === undefined) {
        unknown.push(`environment assumption "${predicate.key}" has no recorded current value`);
      } else if (current.value !== predicate.expect) {
        stale.push(`environment "${predicate.key}" is now "${current.value}", the record assumed "${predicate.expect}"`);
      }
      continue;
    }
    const p = pointers[predicate.pointer];
    if (p === undefined) {
      unknown.push("an invalidation predicate names a pointer that is missing");
      continue;
    }
    if (p.kind === "feature") {
      const entity = prep(db, "SELECT content_hash AS h FROM feature_entities WHERE generation_id = ? AND entity_id = ?").get(generationId, p.ref) as { h: string | null } | undefined;
      if (entity === undefined) {
        stale.push(`feature entity ${p.ref} no longer exists`);
      } else if ((entity.h ?? null) !== (p.contentHash ?? null)) {
        stale.push(`feature entity ${p.ref} changed`);
      }
      continue;
    }
    const current = p.path === null ? undefined : (fileHash.get(generationId, p.path) as { h: string } | undefined)?.h;
    if (current === undefined) {
      stale.push(predicate.type === "test_present" ? `required test file ${p.path} was deleted` : `source ${p.path} was deleted`);
      continue;
    }
    if (current !== p.contentHash) {
      stale.push(predicate.type === "test_present" ? `required test file ${p.path} changed` : `source ${p.path} changed`);
      continue;
    }
    if (p.kind === "symbol") {
      const sym = prep(db, "SELECT signature_fingerprint AS sig FROM symbol_occurrences WHERE generation_id = ? AND path = ? AND qualified_name = ? AND kind != 'module' LIMIT 1").get(generationId, p.path, p.ref) as { sig: string | null } | undefined;
      if (sym === undefined) {
        stale.push(`symbol ${p.ref} no longer exists in ${p.path}`);
      } else if ((sym.sig ?? null) !== (p.signature ?? null)) {
        stale.push(`symbol ${p.ref} changed its signature`);
      }
    }
    if (predicate.type === "test_present" && p.ref !== null) {
      const test = prep(db, "SELECT attrs_json AS a FROM feature_entities WHERE generation_id = ? AND kind = 'test' AND path = ?").get(generationId, p.path) as { a: string | null } | undefined;
      const cases = test?.a == null ? [] : ((JSON.parse(test.a) as { cases?: string[] }).cases ?? []);
      if (!cases.includes(p.ref)) {
        stale.push(`required test case "${p.ref}" no longer exists`);
      }
    }
  }
  if (stale.length === 0 && (row.status === "approved" || row.status === "verified") && needsSubstantiation(row) && !substantiated(ctx, row, depth)) {
    stale.push("its independent substantiation (an approved, non-model record that still applies) is gone");
  }
  if (stale.length > 0) {
    return { state: "stale", reasons: stale, warnings };
  }
  if (unknown.length > 0) {
    return { state: "unknown", reasons: unknown, warnings };
  }
  return { state: "applies", reasons: [], warnings };
}

export type EffectiveStatus = "candidate" | "approved" | "verified" | "stale" | "rejected" | "superseded" | "expired";

/** What a reader should believe: a stored approved/verified standing only counts while the record still applies. */
export function effectiveStatus(row: MemoryRow, standing: Standing): { status: EffectiveStatus; authoritative: boolean } {
  if (row.status === "rejected") {
    return { status: "rejected", authoritative: false };
  }
  if (standing.state === "superseded") {
    return { status: "superseded", authoritative: false };
  }
  if (standing.state === "expired" || standing.state === "ended") {
    return { status: "expired", authoritative: false };
  }
  if (row.status === "candidate") {
    return { status: "candidate", authoritative: false }; // proposed (possibly by a model): never authoritative
  }
  if (row.status === "stale" || standing.state === "stale") {
    return { status: "stale", authoritative: false };
  }
  return { status: row.status, authoritative: standing.state === "applies" };
}
