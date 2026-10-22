import type Database from "better-sqlite3";
import { EngbrainError } from "../errors.js";
import { extractTerms } from "../search.js";
import { currentGenerationId } from "../store/generations.js";
import { estimateJsonTokens } from "../tokens.js";
import { effectiveStatus, evaluateRecord, makeEvalContext, recomputeContentHash, type EffectiveStatus, type EvalContext, type Standing } from "./evaluate.js";
import { requireRole, type Actor } from "./operators.js";
import { prep } from "./prepared.js";
import { findSecretIn, parseIso, type MemoryKind, type MemoryRow } from "./records.js";

export const MEMORY_QUERY_LIMITS = { scan: 2000, results: 100, defaultTokens: 2000, minTokens: 300, maxTokens: 16_000, evidencePaths: 8 } as const;

export interface MemoryItem {
  id: string;
  kind: MemoryKind;
  title: string;
  /** What a reader should believe now (see evaluate.ts). Only `approved`/`verified` records that still apply are authoritative. In a historical view: the status as KNOWN at the as-of recorded time, never authoritative. */
  status: EffectiveStatus;
  storedStatus: string;
  authoritative: boolean;
  label: string;
  standing: Standing["state"];
  reasons: string[];
  warnings: string[];
  validFrom: string;
  validTo: string | null;
  recordedAt: string;
  supersededAt: string | null;
  proposer: string;
  approver: string | null;
  binding: { revision: string | null; branch: string | null };
  evidencePaths: string[];
  commits: string[];
  links: Array<{ rel: string; target: string; direction: "out" | "in" }>;
  score: number;
}

export interface Excluded { stale: number; unknown: number; outOfScope: number; candidates: number; rejected: number; expired: number; superseded: number }
export interface MemorySearch {
  generationId: number | null;
  revision: string | null;
  items: MemoryItem[];
  excluded: Excluded;
  /** True when more matches exist than were returned (scan window, result limit or token budget). */
  truncated: boolean;
  estimatedTokens: number;
  note: string;
}

export interface MemorySearchOptions {
  query?: string;
  kinds?: readonly MemoryKind[];
  includeCandidates?: boolean;
  includeStale?: boolean;
  /** Historical (bitemporal) view: what was true at this time in the world... (strict ISO UTC) */
  asOfValid?: string;
  /** ...as far as the store knew at this time. (strict ISO UTC) */
  asOfRecorded?: string;
  limit?: number;
  maxTokens?: number;
  now?: () => Date;
}

const originLabel = (row: MemoryRow, status: EffectiveStatus): string => {
  if (status === "rejected") {
    return row.kind === "rejected_approach" ? "REJECTED APPROACH: do not propose again without new evidence" : "REJECTED";
  }
  if (row.origin === "model" && status === "candidate") {
    return "INFERRED / PROPOSED by a model: not verified, not authoritative";
  }
  if (status === "candidate") {
    return "PROPOSED: awaiting approval, not authoritative";
  }
  if (status === "stale") {
    return "STALE: its evidence changed or vanished; do not rely on it";
  }
  if (status === "superseded") {
    return "SUPERSEDED by a later record";
  }
  if (status === "expired") {
    return "EXPIRED";
  }
  return status === "verified" ? "VERIFIED against current test/CI evidence" : "APPROVED by an authorised operator";
};

/** The status the store KNEW at `at`, from the immutable event log (a record recorded Monday and approved Wednesday was a candidate on Tuesday). */
function statusAsOf(db: Database.Database, row: MemoryRow, at: string): EffectiveStatus {
  const events = prep(db, "SELECT kind, at FROM memory_events WHERE record_id = ? AND at <= ? ORDER BY event_id").all(row.record_id, at) as Array<{ kind: string; at: string }>;
  let status: EffectiveStatus = "candidate";
  for (const e of events) {
    if (e.kind === "approved") { status = "approved"; }
    else if (e.kind === "verified") { status = "verified"; }
    else if (e.kind === "rejected") { status = "rejected"; }
    else if (e.kind === "superseded") { status = "superseded"; }
  }
  return status;
}

function toItem(ctx: EvalContext, row: MemoryRow, standing: Standing, score: number, historicalAt?: string): MemoryItem {
  const db = ctx.db;
  const eff = historicalAt === undefined ? effectiveStatus(row, standing) : { status: statusAsOf(db, row, historicalAt), authoritative: false };
  const pointers = (JSON.parse(row.evidence_json) as { pointers: Array<{ kind: string; path: string | null; ref: string | null }> }).pointers;
  const links = [
    ...(prep(db, "SELECT rel, target_id AS target FROM memory_links WHERE record_id = ? ORDER BY rel, target_id").all(row.record_id) as Array<{ rel: string; target: string }>).map((l) => ({ ...l, direction: "out" as const })),
    ...(prep(db, "SELECT rel, record_id AS target FROM memory_links WHERE target_id = ? ORDER BY rel, record_id").all(row.record_id) as Array<{ rel: string; target: string }>).map((l) => ({ ...l, direction: "in" as const }))
  ];
  return {
    id: row.record_id, kind: row.kind, title: row.title, status: eff.status, storedStatus: row.status, authoritative: eff.authoritative,
    label: historicalAt === undefined ? originLabel(row, eff.status) : `HISTORICAL VIEW (as recorded by ${historicalAt}): ${originLabel(row, eff.status)}; never authoritative`,
    standing: standing.state, reasons: standing.reasons, warnings: standing.warnings, validFrom: row.valid_from, validTo: row.valid_to, recordedAt: row.recorded_at, supersededAt: row.superseded_at, proposer: row.proposer,
    approver: row.approver, binding: { revision: row.binding_revision, branch: row.binding_branch },
    evidencePaths: [...new Set(pointers.filter((p) => p.path !== null).map((p) => p.path!))].slice(0, MEMORY_QUERY_LIMITS.evidencePaths),
    commits: pointers.filter((p) => p.kind === "commit").map((p) => p.ref!).slice(0, 10), links, score
  };
}

const emptyExcluded = (): Excluded => ({ stale: 0, unknown: 0, outOfScope: 0, candidates: 0, rejected: 0, expired: 0, superseded: 0 });

function snapshot(db: Database.Database): { generationId: number | null; revision: string | null } {
  const generationId = currentGenerationId(db);
  const revision = generationId === null ? null : (db.prepare("SELECT revision FROM generations WHERE id = ?").get(generationId) as { revision: string | null }).revision;
  return { generationId, revision };
}

/** Classifies an evaluated item for retrieval: shown, or excluded (and counted). Default: authoritative records only. */
function admit(item: MemoryItem, options: MemorySearchOptions, excluded: Excluded): boolean {
  if (item.status === "rejected") {
    excluded.rejected += 1;
    return false;
  }
  if (item.status === "superseded") {
    excluded.superseded += 1;
    return false;
  }
  if (item.status === "expired") {
    excluded.expired += 1;
    return false;
  }
  if (item.standing === "out_of_scope") {
    excluded.outOfScope += 1;
    return false;
  }
  if (item.status === "stale" || item.standing === "stale") {
    excluded.stale += 1;
    return options.includeStale === true;
  }
  if (item.standing === "unknown") {
    excluded.unknown += 1;
    return options.includeStale === true;
  }
  if (item.status === "candidate") {
    excluded.candidates += 1;
    return options.includeCandidates === true;
  }
  return item.authoritative;
}

const likeEscape = (t: string): string => `%${t.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;

export function searchMemory(db: Database.Database, options: MemorySearchOptions = {}): MemorySearch {
  const limit = Math.min(Math.max(1, Math.floor(options.limit ?? 20)), MEMORY_QUERY_LIMITS.results);
  const maxTokens = Math.min(Math.max(MEMORY_QUERY_LIMITS.minTokens, Math.floor(options.maxTokens ?? MEMORY_QUERY_LIMITS.defaultTokens)), MEMORY_QUERY_LIMITS.maxTokens);
  const nowIso = (options.now ?? (() => new Date()))().toISOString();
  const asOfRecorded = options.asOfRecorded === undefined ? undefined : parseIso(options.asOfRecorded, "asOfRecorded");
  const asOfValid = options.asOfValid === undefined ? undefined : parseIso(options.asOfValid, "asOfValid");
  const historical = asOfRecorded !== undefined || asOfValid !== undefined;
  return db.transaction((): MemorySearch => {
    const snap = snapshot(db);
    const ctx = makeEvalContext(db, nowIso);
    const where: string[] = [];
    const params: unknown[] = [];
    if (options.kinds !== undefined && options.kinds.length > 0) {
      where.push(`kind IN (${options.kinds.map(() => "?").join(",")})`);
      params.push(...options.kinds);
    }
    // "valid at T" alone means: as the store knows it NOW (so a superseded record and its replacement are not both listed)
    const knownAt = asOfRecorded ?? (asOfValid !== undefined ? nowIso : undefined);
    if (knownAt !== undefined) {
      where.push("recorded_at <= ? AND (superseded_at IS NULL OR superseded_at > ?)");
      params.push(knownAt, knownAt);
    }
    if (asOfValid !== undefined) {
      where.push("valid_from <= ? AND (valid_to IS NULL OR valid_to > ?)");
      params.push(asOfValid, asOfValid);
    }
    const terms = extractTerms(options.query ?? "");
    if (terms.length > 0) {
      where.push(`(${terms.map(() => "(title LIKE ? ESCAPE '\\' OR body LIKE ? ESCAPE '\\')").join(" OR ")})`);
      for (const t of terms) {
        params.push(likeEscape(t), likeEscape(t));
      }
    }
    const base = where.length === 0 ? "" : ` AND ${where.join(" AND ")}`;
    const excluded = emptyExcluded();
    // The scan window is filled ONLY with rows that could be returned: the authority filter runs in SQL, so a flood of candidates, rejected or expired rows can never crowd approved ones out.
    const statuses = historical ? null : ["approved", "verified", ...(options.includeCandidates === true ? ["candidate"] : []), ...(options.includeStale === true ? ["stale"] : [])];
    const live = historical ? "1 = 1" : `status IN (${statuses!.map(() => "?").join(",")}) AND superseded_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`;
    const liveParams = historical ? [] : [...statuses!, nowIso];
    if (!historical) {
      const count = (sql: string, ...extra: unknown[]): number => (prep(db, `SELECT COUNT(*) AS n FROM memory_records WHERE ${sql}${base}`).get(...extra, ...params) as { n: number }).n;
      excluded.rejected = count("status = 'rejected'");
      excluded.superseded = count("superseded_at IS NOT NULL AND status != 'rejected'");
      excluded.expired = count("superseded_at IS NULL AND status != 'rejected' AND expires_at IS NOT NULL AND expires_at <= ?", nowIso);
      if (options.includeCandidates !== true) {
        excluded.candidates = count("status = 'candidate' AND superseded_at IS NULL AND (expires_at IS NULL OR expires_at > ?)", nowIso);
      }
    }
    const rows = db.prepare(`SELECT * FROM memory_records WHERE ${live}${base} ORDER BY recorded_at DESC, record_id LIMIT ?`).all(...liveParams, ...params, MEMORY_QUERY_LIMITS.scan) as MemoryRow[];
    const scored: MemoryItem[] = [];
    for (const row of rows) {
      const hits = terms.reduce((n, t) => n + (row.title.toLowerCase().includes(t) ? 3 : 0) + (row.body.toLowerCase().includes(t) ? 1 : 0), 0);
      const standing = evaluateRecord(db, row, ctx);
      if (historical) {
        scored.push(toItem(ctx, row, standing, hits, asOfRecorded ?? nowIso));
        continue;
      }
      const item = toItem(ctx, row, standing, hits);
      // standing-based exclusions (stale, unknown, other branch) are counted from the evaluated rows; the status-based ones were counted in SQL above
      const before = { ...excluded };
      if (admit(item, options, excluded)) {
        scored.push(item);
      }
      excluded.rejected = before.rejected;
      excluded.superseded = before.superseded;
      excluded.expired = before.expired;
      excluded.candidates = before.candidates;
    }
    scored.sort((a, b) => b.score - a.score || (a.recordedAt < b.recordedAt ? 1 : a.recordedAt > b.recordedAt ? -1 : 0) || (a.id < b.id ? -1 : 1));
    const items: MemoryItem[] = [];
    let truncated = rows.length >= MEMORY_QUERY_LIMITS.scan;
    for (const item of scored.slice(0, limit)) {
      if (estimateJsonTokens([...items, item]) > maxTokens - 300) {
        truncated = true;
        break;
      }
      items.push(item);
    }
    if (scored.length > limit) {
      truncated = true;
    }
    const result: MemorySearch = {
      generationId: snap.generationId, revision: snap.revision, items, excluded, truncated, estimatedTokens: 0,
      note: historical ? "Historical view: records as recorded and valid at the given times, with the status the store KNEW then. Never authoritative; the CURRENT standing is in `standing` and `reasons`."
        : "Authoritative records only (approved/verified and still applying). Excluded counts are listed; candidates, stale and unknown records are never authoritative."
    };
    result.estimatedTokens = estimateJsonTokens(result);
    return result;
  })();
}

export interface RelatedTarget { file?: string; symbol?: string; feature?: string }
export interface RelatedResult {
  generationId: number | null;
  items: Array<MemoryItem & { fixes: MemoryItem[]; verifications: MemoryItem[] }>;
  excluded: Excluded;
  truncated: boolean;
  note: string;
}

function relatedRows(db: Database.Database, kinds: readonly MemoryKind[], target: RelatedTarget): MemoryRow[] {
  const ids = new Set<string>();
  const add = (sql: string, ...params: unknown[]): void => {
    for (const r of prep(db, sql).all(...params) as Array<{ record_id: string }>) {
      ids.add(r.record_id);
    }
  };
  if (target.file !== undefined) {
    add("SELECT DISTINCT record_id FROM memory_pointers WHERE path = ? LIMIT 500", target.file);
    add("SELECT record_id FROM memory_records WHERE EXISTS (SELECT 1 FROM json_each(memory_records.scope_json, '$.paths') WHERE json_each.value = ?) LIMIT 500", target.file); // exact membership, not a substring
  }
  if (target.symbol !== undefined) {
    const cut = target.symbol.lastIndexOf("#");
    add("SELECT DISTINCT record_id FROM memory_pointers WHERE kind = 'symbol' AND path = ? AND ref = ? LIMIT 500", target.symbol.slice(0, cut), target.symbol.slice(cut + 1));
    add("SELECT record_id FROM memory_records WHERE EXISTS (SELECT 1 FROM json_each(memory_records.scope_json, '$.symbols') WHERE json_each.value = ?) LIMIT 500", target.symbol);
  }
  if (target.feature !== undefined) {
    add("SELECT DISTINCT record_id FROM memory_pointers WHERE kind = 'feature' AND ref = ? LIMIT 500", target.feature);
    add("SELECT record_id FROM memory_records WHERE EXISTS (SELECT 1 FROM json_each(memory_records.scope_json, '$.features') WHERE json_each.value = ?) LIMIT 500", target.feature);
  }
  if (ids.size === 0) {
    return [];
  }
  const list = [...ids];
  const rows: MemoryRow[] = [];
  for (let i = 0; i < list.length; i += 100) {
    const chunk = list.slice(i, i + 100);
    rows.push(...(db.prepare(`SELECT * FROM memory_records WHERE record_id IN (${chunk.map(() => "?").join(",")}) AND kind IN (${kinds.map(() => "?").join(",")}) ORDER BY recorded_at DESC, record_id`).all(...chunk, ...kinds) as MemoryRow[]));
  }
  return rows;
}

function related(db: Database.Database, kinds: readonly MemoryKind[], target: RelatedTarget, options: { now?: () => Date; includeStale?: boolean; limit?: number }): RelatedResult {
  const nowIso = (options.now ?? (() => new Date()))().toISOString();
  const limit = Math.min(Math.max(1, Math.floor(options.limit ?? 20)), MEMORY_QUERY_LIMITS.results);
  return db.transaction((): RelatedResult => {
    const ctx = makeEvalContext(db, nowIso);
    const excluded = emptyExcluded();
    const items: RelatedResult["items"] = [];
    let truncated = false;
    const linkedTo = (id: string, rel: string): MemoryItem[] => (prep(db, "SELECT r.* FROM memory_links l JOIN memory_records r ON r.record_id = l.record_id WHERE l.target_id = ? AND l.rel = ? ORDER BY r.recorded_at, r.record_id").all(id, rel) as MemoryRow[])
      .map((r) => toItem(ctx, r, evaluateRecord(db, r, ctx), 0));
    for (const row of relatedRows(db, kinds, target)) {
      const item = toItem(ctx, row, evaluateRecord(db, row, ctx), 0);
      // related lookups show proposed items too (clearly labelled); stale, rejected, expired, superseded and other-branch records are excluded and counted
      if (!admit(item, { includeCandidates: true, includeStale: options.includeStale === true }, excluded)) {
        continue;
      }
      if (items.length >= limit) {
        truncated = true;
        continue;
      }
      const fixes = linkedTo(row.record_id, "fixes");
      items.push({ ...item, fixes, verifications: [...linkedTo(row.record_id, "verifies"), ...fixes.flatMap((f) => linkedTo(f.id, "verifies"))] });
    }
    return {
      generationId: currentGenerationId(db), items, excluded, truncated,
      note: "A stale or unknown verification is shown with its standing: do not treat a fix as verified unless its verification is `verified` and applies."
    };
  })();
}

type RelatedOptions = { now?: () => Date; includeStale?: boolean; limit?: number };
export const relatedBugs = (db: Database.Database, target: RelatedTarget, options: RelatedOptions = {}): RelatedResult => related(db, ["bug", "finding"], target, options);
export const relatedDecisions = (db: Database.Database, target: RelatedTarget, options: RelatedOptions = {}): RelatedResult => related(db, ["decision", "rejected_approach"], target, options);

export interface MemoryDetail extends MemoryItem {
  body: string;
  origin: string;
  originDetail: string | null;
  expiresAt: string | null;
  scope: unknown;
  evidence: unknown;
  events: Array<{ kind: string; at: string; actor: string; detail: unknown }>;
}

const eventsOf = (db: Database.Database, id: string): MemoryDetail["events"] =>
  (prep(db, "SELECT kind, at, actor, detail_json AS d FROM memory_events WHERE record_id = ? ORDER BY event_id").all(id) as Array<{ kind: string; at: string; actor: string; d: string | null }>)
    .map((e) => ({ kind: e.kind, at: e.at, actor: e.actor, detail: e.d === null ? null : JSON.parse(e.d) as unknown }));

export function showMemory(db: Database.Database, id: string, options: { now?: () => Date } = {}): MemoryDetail | null {
  const nowIso = (options.now ?? (() => new Date()))().toISOString();
  return db.transaction((): MemoryDetail | null => {
    const row = db.prepare("SELECT * FROM memory_records WHERE record_id = ?").get(id) as MemoryRow | undefined;
    if (row === undefined) {
      return null;
    }
    const ctx = makeEvalContext(db, nowIso);
    return { ...toItem(ctx, row, evaluateRecord(db, row, ctx), 0), body: row.body, origin: row.origin, originDetail: row.origin_detail, expiresAt: row.expires_at, scope: JSON.parse(row.scope_json) as unknown, evidence: JSON.parse(row.evidence_json) as unknown, events: eventsOf(db, id) };
  })();
}

export interface MemoryProvenance {
  found: boolean;
  item: MemoryItem | null;
  /** `mismatch` means a stored content column no longer matches the hash the record was created with. */
  integrity: "ok" | "mismatch" | null;
  claim: string | null;
  evidenceType: string | null;
  method: string | null;
  environment: Record<string, string>;
  artifacts: unknown[];
  pointers: Array<{ kind: string; path: string | null; ref: string | null; recordedHash: string | null; currentHash: string | null; state: "unchanged" | "changed" | "deleted" | "not_source_bound" }>;
  predicates: Array<{ predicate: unknown; result: "holds" | "fails" | "unknown"; reason: string | null }>;
  commits: Array<{ oid: string; role: string }>;
  proposer: string | null;
  approver: string | null;
  verifiedBy: string | null;
  events: MemoryDetail["events"];
}

/** Full evidence trail of one record: what it points at, whether each pointer still matches, each predicate's current result, who proposed and approved, and every event. */
export function evidenceProvenance(db: Database.Database, id: string, options: { now?: () => Date } = {}): MemoryProvenance {
  const nowIso = (options.now ?? (() => new Date()))().toISOString();
  return db.transaction((): MemoryProvenance => {
    const row = db.prepare("SELECT * FROM memory_records WHERE record_id = ?").get(id) as MemoryRow | undefined;
    const blank: MemoryProvenance = { found: false, item: null, integrity: null, claim: null, evidenceType: null, method: null, environment: {}, artifacts: [], pointers: [], predicates: [], commits: [], proposer: null, approver: null, verifiedBy: null, events: [] };
    if (row === undefined) {
      return blank;
    }
    const ctx = makeEvalContext(db, nowIso);
    const generationId = ctx.generationId;
    const ev = JSON.parse(row.evidence_json) as { claim?: string; type: string; method?: string; environment?: Record<string, string>; artifacts?: unknown[]; pointers: Array<{ kind: string; path: string | null; ref: string | null; contentHash: string | null; role?: string }> };
    const fileHash = (path: string): string | undefined => generationId === null ? undefined : (prep(db, "SELECT content_hash AS h FROM generation_files WHERE generation_id = ? AND path = ? AND content_hash IS NOT NULL").get(generationId, path) as { h: string } | undefined)?.h;
    const pointers = ev.pointers.map((p) => {
      const sourceBound = ["file", "symbol", "test"].includes(p.kind) && p.path !== null;
      const current = sourceBound ? fileHash(p.path!) ?? null : p.kind === "feature" && generationId !== null ? (prep(db, "SELECT content_hash AS h FROM feature_entities WHERE generation_id = ? AND entity_id = ?").get(generationId, p.ref) as { h: string | null } | undefined)?.h ?? null : null;
      const state: MemoryProvenance["pointers"][number]["state"] = !sourceBound && p.kind !== "feature" ? "not_source_bound" : current === null ? "deleted" : current === p.contentHash ? "unchanged" : "changed";
      return { kind: p.kind, path: p.path, ref: p.ref, recordedHash: p.contentHash, currentHash: current, state };
    });
    const predicates = (JSON.parse(row.invalidation_json) as Array<{ type: string; pointer?: number; key?: string; expect?: string }>).map((predicate) => {
      if (predicate.type === "environment") {
        const cur = prep(db, "SELECT value FROM memory_environment WHERE key = ? ORDER BY id DESC LIMIT 1").get(predicate.key) as { value: string } | undefined;
        return { predicate, result: (cur === undefined ? "unknown" : cur.value === predicate.expect ? "holds" : "fails") as "holds" | "fails" | "unknown", reason: cur === undefined ? "no current value recorded" : cur.value === predicate.expect ? null : `now "${cur.value}"` };
      }
      const p = pointers[predicate.pointer ?? -1];
      return { predicate, result: (p === undefined ? "unknown" : p.state === "unchanged" ? "holds" : "fails") as "holds" | "fails" | "unknown", reason: p === undefined ? "missing pointer" : p.state === "unchanged" ? null : `source ${p.state}` };
    });
    return {
      found: true, item: toItem(ctx, row, evaluateRecord(db, row, ctx), 0), integrity: recomputeContentHash(row) === row.content_hash ? "ok" : "mismatch", claim: ev.claim ?? null, evidenceType: ev.type, method: ev.method ?? null,
      environment: ev.environment ?? {}, artifacts: ev.artifacts ?? [], pointers, predicates, commits: ev.pointers.filter((p) => p.kind === "commit").map((p) => ({ oid: p.ref!, role: p.role ?? "related" })),
      proposer: row.proposer, approver: row.approver, verifiedBy: row.verified_by, events: eventsOf(db, id)
    };
  })();
}

export interface StaleReport { generationId: number | null; stale: MemoryItem[]; unknown: MemoryItem[]; outOfScope: MemoryItem[]; truncated: boolean }

/** Records that were approved or verified (or are candidates) but no longer apply, with the reasons: the maintenance view for safe forgetting. */
export function listStale(db: Database.Database, options: { now?: () => Date; limit?: number } = {}): StaleReport {
  const nowIso = (options.now ?? (() => new Date()))().toISOString();
  const limit = Math.min(Math.max(1, Math.floor(options.limit ?? 100)), MEMORY_QUERY_LIMITS.results);
  return db.transaction((): StaleReport => {
    const ctx = makeEvalContext(db, nowIso);
    const report: StaleReport = { generationId: ctx.generationId, stale: [], unknown: [], outOfScope: [], truncated: false };
    const rows = db.prepare("SELECT * FROM memory_records WHERE status IN ('approved', 'verified', 'stale') AND superseded_at IS NULL ORDER BY recorded_at DESC, record_id LIMIT ?").all(MEMORY_QUERY_LIMITS.scan) as MemoryRow[];
    report.truncated = rows.length >= MEMORY_QUERY_LIMITS.scan;
    for (const row of rows) {
      const standing = evaluateRecord(db, row, ctx);
      const bucket = standing.state === "stale" || row.status === "stale" ? report.stale : standing.state === "unknown" ? report.unknown : standing.state === "out_of_scope" ? report.outOfScope : null;
      if (bucket !== null && bucket.length < limit) {
        bucket.push(toItem(ctx, row, standing, 0));
      }
    }
    return report;
  })();
}

/** A compact cross-session summary: identifiers, revision, kind, title and standing only. Full text stays behind `memory show`, so prompts never re-ingest history. */
export function summarizeMemory(db: Database.Database, options: { maxTokens?: number; now?: () => Date } = {}): { generationId: number | null; revision: string | null; lines: string[]; omitted: number; truncated: boolean; excluded: Excluded; estimatedTokens: number } {
  const maxTokens = Math.min(Math.max(MEMORY_QUERY_LIMITS.minTokens, Math.floor(options.maxTokens ?? 800)), MEMORY_QUERY_LIMITS.maxTokens);
  const found = searchMemory(db, { limit: MEMORY_QUERY_LIMITS.results, maxTokens: MEMORY_QUERY_LIMITS.maxTokens, ...(options.now === undefined ? {} : { now: options.now }) });
  const lines: string[] = [];
  let omitted = 0;
  for (const item of found.items) {
    const line = `${item.id}@${(item.binding.revision ?? "-").slice(0, 10)} ${item.kind} [${item.status}] ${item.title}`;
    if (estimateJsonTokens([...lines, line]) > maxTokens - 150) {
      omitted += 1;
    } else {
      lines.push(line);
    }
  }
  const result = { generationId: found.generationId, revision: found.revision, lines, omitted, truncated: found.truncated || omitted > 0, excluded: found.excluded, estimatedTokens: 0 };
  result.estimatedTokens = estimateJsonTokens(result);
  return result;
}

/** Retention: expired observations that no approved/verified record depends on are deleted (with their events and every link that pointed at them). Decisions, bugs, fixes, test evidence and rejected approaches are never expired by GC. */
export function collectMemory(db: Database.Database, ctx: { actor: Actor; now?: () => Date }): { removed: number } {
  requireRole(ctx.actor, "admin");
  const nowIso = (ctx.now ?? (() => new Date()))().toISOString();
  return db.transaction((): { removed: number } => {
    const doomed = (db.prepare(
      `SELECT r.record_id AS id FROM memory_records r WHERE r.kind = 'observation' AND r.expires_at IS NOT NULL AND r.expires_at <= ?
         AND NOT EXISTS (SELECT 1 FROM memory_links l JOIN memory_records d ON d.record_id = l.record_id WHERE l.target_id = r.record_id AND d.status IN ('approved', 'verified'))`
    ).all(nowIso) as Array<{ id: string }>).map((r) => r.id);
    for (const id of doomed) {
      db.prepare("DELETE FROM memory_links WHERE target_id = ?").run(id); // no dangling references to a record that no longer exists
      db.prepare("DELETE FROM memory_records WHERE record_id = ?").run(id); // cascades pointers and the record's own links
      db.prepare("DELETE FROM memory_events WHERE record_id = ?").run(id); // events may only go once their record is gone (a trigger enforces this)
    }
    return { removed: doomed.length };
  }).immediate();
}

/** Export for sharing or backup: a record whose stored content trips the secret scanner ANYWHERE (title, body, evidence, scope, predicates, origin, reason) is WITHHELD and counted. Hashes and pointers only, no source text. */
export function exportMemory(db: Database.Database): { format: 1; generationId: number | null; records: unknown[]; links: unknown[]; withheld: number } {
  return db.transaction(() => {
    const records: unknown[] = [];
    let withheld = 0;
    for (const row of db.prepare("SELECT * FROM memory_records ORDER BY recorded_at, record_id").all() as MemoryRow[]) {
      const scope = JSON.parse(row.scope_json) as unknown;
      const evidence = JSON.parse(row.evidence_json) as unknown;
      const invalidation = JSON.parse(row.invalidation_json) as unknown;
      if (findSecretIn({ title: row.title, body: row.body, origin_detail: row.origin_detail, rejected_reason: row.rejected_reason, scope, evidence, invalidation }) !== null) {
        withheld += 1;
        continue;
      }
      records.push({ ...row, scope, evidence, invalidation, scope_json: undefined, evidence_json: undefined, invalidation_json: undefined });
    }
    const exportedIds = new Set(records.map((r) => (r as { record_id: string }).record_id));
    const links = (db.prepare("SELECT record_id, rel, target_id FROM memory_links ORDER BY record_id, rel, target_id").all() as Array<{ record_id: string; rel: string; target_id: string }>).filter((l) => exportedIds.has(l.record_id) && exportedIds.has(l.target_id));
    return { format: 1 as const, generationId: currentGenerationId(db), records, links, withheld };
  })();
}

export function requireRecord(db: Database.Database, id: string): void {
  if (db.prepare("SELECT 1 FROM memory_records WHERE record_id = ?").get(id) === undefined) {
    throw new EngbrainError("INVALID_ROOT", "no such memory record");
  }
}
