import type Database from "better-sqlite3";
import { currentGenerationId } from "../store/generations.js";
import { fileNodeId, symbolNodeId } from "./featureBuilder.js";

/** Bounded, read-only queries over the PUBLISHED feature graph of the current generation (one read snapshot per call). */
export const QUERY_LIMITS = { list: 100, members: 300, trace: { depth: 6, nodes: 300, edges: 800, fanout: 60 }, gaps: 500 } as const;

export interface NodeRecord {
  id: string;
  kind: string;
  name: string;
  path: string | null;
  startLine: number | null;
  package: string | null;
  mechanism: string | null;
  certainty: string | null;
  trust: string | null;
  validFromGeneration: number | null;
}
export interface FeatureEdgeRecord {
  src: string;
  dst: string;
  relation: string;
  certainty: string;
  mechanism: string;
  reason: string;
  evidencePath: string | null;
  evidenceLine: number | null;
}
export interface GapRecord { kind: string; entityId: string | null; path: string | null; line: number | null; detail: string }

interface Snapshot { generationId: number; revision: string | null; fingerprint: string | null }

function snapshotOf(db: Database.Database): Snapshot | null {
  const g = currentGenerationId(db);
  if (g === null) {
    return null;
  }
  const row = db.prepare("SELECT revision, source_fingerprint AS fp FROM generations WHERE id = ?").get(g) as { revision: string | null; fp: string | null };
  return { generationId: g, revision: row.revision, fingerprint: row.fp };
}

class Reader {
  private readonly statements = new Map<string, Database.Statement>();

  constructor(private readonly db: Database.Database, readonly generationId: number) {}

  /** Prepared statements are cached per reader: a traversal issues thousands of identical lookups. */
  private stmt(sql: string): Database.Statement {
    let s = this.statements.get(sql);
    if (s === undefined) {
      s = this.db.prepare(sql);
      this.statements.set(sql, s);
    }
    return s;
  }

  node(id: string): NodeRecord {
    const row = this.stmt(
      `SELECT entity_id AS id, kind, name, path, start_line AS startLine, package_dir AS package, mechanism, certainty, trust, valid_from_generation AS validFromGeneration
       FROM feature_entities WHERE generation_id = ? AND entity_id = ?`
    ).get(this.generationId, id) as NodeRecord | undefined;
    if (row !== undefined) {
      return row;
    }
    if (id.startsWith("sym:")) {
      const at = id.lastIndexOf("#");
      return { id, kind: "symbol", name: id.slice(at + 1), path: id.slice(4, at), startLine: null, package: null, mechanism: "symbol_resolution", certainty: null, trust: null, validFromGeneration: null };
    }
    return { id, kind: id.startsWith("file:") ? "file" : "unknown", name: id.slice(id.indexOf(":") + 1), path: id.startsWith("file:") ? id.slice(5) : null, startLine: null, package: null, mechanism: null, certainty: null, trust: null, validFromGeneration: null };
  }

  edgesOf(id: string, direction: "forward" | "reverse", limit: number): FeatureEdgeRecord[] {
    const column = direction === "forward" ? "src_entity" : "dst_entity";
    return this.stmt(
      `SELECT src_entity AS src, dst_entity AS dst, relation, certainty, mechanism, reason, evidence_path AS evidencePath, evidence_line AS evidenceLine
       FROM feature_edges INDEXED BY ${direction === "forward" ? "idx_feature_edges_src" : "idx_feature_edges_dst"} WHERE generation_id = ? AND ${column} = ? ORDER BY edge_id LIMIT ?`
    ).all(this.generationId, id, limit) as FeatureEdgeRecord[];
  }

  gapsFor(ids: readonly string[]): GapRecord[] {
    if (ids.length === 0) {
      return [];
    }
    const out: GapRecord[] = [];
    const stmt = this.stmt("SELECT kind, entity_id AS entityId, path, line, detail FROM feature_gaps INDEXED BY idx_feature_gaps_entity WHERE generation_id = ? AND entity_id = ? ORDER BY gap_id");
    for (const id of ids.slice(0, 2000)) {
      out.push(...(stmt.all(this.generationId, id) as GapRecord[]));
    }
    return out;
  }
}

function inSnapshot<T>(db: Database.Database, empty: T, fn: (reader: Reader, snapshot: Snapshot) => T): T {
  return db.transaction((): T => {
    const snapshot = snapshotOf(db);
    return snapshot === null ? empty : fn(new Reader(db, snapshot.generationId), snapshot);
  })();
}

export interface FeatureListItem {
  id: string;
  name: string;
  source: "discovered";
  trust: "discovered";
  rootKind: string;
  members: number;
  kinds: Record<string, number>;
  services: string[];
  confidence: string;
  truncated: boolean;
  gaps: number;
}
export interface FeatureList { generationId: number | null; features: FeatureListItem[]; total: number; truncated: boolean }

export function listFeatures(db: Database.Database, options: { limit?: number; offset?: number; search?: string; rootKind?: string } = {}): FeatureList {
  const limit = Math.min(Math.max(1, Math.floor(options.limit ?? 50)), QUERY_LIMITS.list);
  const offset = Math.max(0, Math.floor(options.offset ?? 0));
  return inSnapshot<FeatureList>(db, { generationId: null, features: [], total: 0, truncated: false }, (r) => {
    const where = ["generation_id = ?"];
    const params: unknown[] = [r.generationId];
    if (options.search !== undefined && options.search !== "") {
      where.push("(name LIKE ? ESCAPE '\\' OR feature_id LIKE ? ESCAPE '\\')");
      const pattern = `%${options.search.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
      params.push(pattern, pattern);
    }
    if (options.rootKind !== undefined) {
      where.push("json_extract(summary_json, '$.rootKind') = ?");
      params.push(options.rootKind);
    }
    const total = (db.prepare(`SELECT COUNT(*) AS n FROM features WHERE ${where.join(" AND ")}`).get(...params) as { n: number }).n;
    const rows = db.prepare(`SELECT feature_id AS id, name, member_count AS members, summary_json AS summary FROM features WHERE ${where.join(" AND ")} ORDER BY feature_id LIMIT ? OFFSET ?`).all(...params, limit, offset) as Array<{ id: string; name: string; members: number; summary: string }>;
    const features = rows.map((row): FeatureListItem => {
      const s = JSON.parse(row.summary) as { rootKind: string; kinds: Record<string, number>; services: string[]; confidence: string; truncated: boolean };
      const gaps = (db.prepare(
        "SELECT COUNT(*) AS n FROM feature_gaps g JOIN feature_members m ON m.generation_id = g.generation_id AND m.entity_id = g.entity_id WHERE m.generation_id = ? AND m.feature_id = ?"
      ).get(r.generationId, row.id) as { n: number }).n;
      return { id: row.id, name: row.name, source: "discovered", trust: "discovered", rootKind: s.rootKind, members: row.members, kinds: s.kinds, services: s.services, confidence: s.confidence, truncated: s.truncated, gaps };
    });
    return { generationId: r.generationId, features, total, truncated: total > offset + limit };
  });
}

export interface FeatureDetail {
  generationId: number | null;
  found: boolean;
  feature: { id: string; name: string; source: string; trust: string; summary: unknown } | null;
  members: Array<NodeRecord & { hops: number; role: string }>;
  edges: FeatureEdgeRecord[];
  gaps: GapRecord[];
  truncated: boolean;
  note: string;
}

export function showFeature(db: Database.Database, id: string, options: { limit?: number } = {}): FeatureDetail {
  const limit = Math.min(Math.max(1, Math.floor(options.limit ?? 100)), QUERY_LIMITS.members);
  return inSnapshot<FeatureDetail>(db, { generationId: null, found: false, feature: null, members: [], edges: [], gaps: [], truncated: false, note: "no index yet" }, (r) => {
    const f = db.prepare("SELECT feature_id AS id, name, source, summary_json AS summary FROM features WHERE generation_id = ? AND feature_id = ?").get(r.generationId, id) as { id: string; name: string; source: string; summary: string } | undefined;
    if (f === undefined) {
      return { generationId: r.generationId, found: false, feature: null, members: [], edges: [], gaps: [], truncated: false, note: "no such feature in the current generation" };
    }
    const rows = db.prepare("SELECT entity_id AS id, role, hops FROM feature_members WHERE generation_id = ? AND feature_id = ? ORDER BY hops, entity_id LIMIT ?").all(r.generationId, id, limit + 1) as Array<{ id: string; role: string; hops: number }>;
    const picked = rows.slice(0, limit);
    const ids = new Set(picked.map((m) => m.id));
    const edges: FeatureEdgeRecord[] = [];
    for (const m of picked) {
      for (const e of r.edgesOf(m.id, "forward", QUERY_LIMITS.trace.fanout)) {
        if (ids.has(e.dst) && edges.length < QUERY_LIMITS.trace.edges) {
          edges.push(e);
        }
      }
    }
    return {
      generationId: r.generationId, found: true, feature: { id: f.id, name: f.name, source: f.source, trust: "discovered", summary: JSON.parse(f.summary) },
      members: picked.map((m) => ({ ...r.node(m.id), hops: m.hops, role: m.role })), edges, gaps: r.gapsFor([...ids]), truncated: rows.length > limit,
      note: "A discovered feature is a deterministic neighbourhood of one entry point over syntactic edges. It is a candidate grouping, not a business-defined feature."
    };
  });
}

export interface TraceResult {
  generationId: number | null;
  start: NodeRecord | null;
  nodes: Array<NodeRecord & { depth: number }>;
  edges: FeatureEdgeRecord[];
  gaps: GapRecord[];
  truncated: { depth: boolean; nodes: boolean; edges: boolean; fanout: boolean };
  /** Other entities the reference also matched (the same `kind:key` in several services): the trace started from the first. */
  alsoMatched: string[];
  note: string;
}

/**
 * Resolves a user-facing reference: an entity id, `kind:key` (e.g. `route:GET /api/users`), `file:path` or `sym:path#qualified`. A `kind:key` that matches
 * several entities (the same route in two services) returns the first by id AND lists the others, so the ambiguity is never silent. null: it does not exist.
 */
export function resolveEntities(db: Database.Database, generationId: number, ref: string): { id: string; others: string[] } | null {
  if (db.prepare("SELECT 1 FROM feature_entities WHERE generation_id = ? AND entity_id = ?").get(generationId, ref) !== undefined) {
    return { id: ref, others: [] };
  }
  if (ref.startsWith("file:")) {
    return db.prepare("SELECT 1 FROM generation_files WHERE generation_id = ? AND path = ? AND content_hash IS NOT NULL").get(generationId, ref.slice(5)) === undefined ? null : { id: ref, others: [] };
  }
  if (ref.startsWith("sym:")) {
    const at = ref.lastIndexOf("#");
    return at <= 4 || db.prepare("SELECT 1 FROM symbol_occurrences WHERE generation_id = ? AND path = ? AND qualified_name = ? AND kind != 'module' LIMIT 1").get(generationId, ref.slice(4, at), ref.slice(at + 1)) === undefined ? null : { id: ref, others: [] };
  }
  const cut = ref.indexOf(":");
  if (cut > 0) {
    const rows = db.prepare("SELECT entity_id AS id FROM feature_entities WHERE generation_id = ? AND kind = ? AND key = ? ORDER BY entity_id LIMIT 11").all(generationId, ref.slice(0, cut), ref.slice(cut + 1)) as Array<{ id: string }>;
    if (rows.length >= 1) {
      return { id: rows[0]!.id, others: rows.slice(1).map((r) => r.id) };
    }
  }
  return null;
}

export const resolveEntity = (db: Database.Database, generationId: number, ref: string): string | null => resolveEntities(db, generationId, ref)?.id ?? null;

export function traceFrom(
  db: Database.Database, ref: string, options: { direction?: "forward" | "reverse" | "both"; depth?: number; maxNodes?: number; maxEdges?: number } = {}
): TraceResult {
  const direction = options.direction ?? "both";
  const maxDepth = Math.min(Math.max(1, Math.floor(options.depth ?? 3)), QUERY_LIMITS.trace.depth);
  const maxNodes = Math.min(Math.max(1, Math.floor(options.maxNodes ?? 100)), QUERY_LIMITS.trace.nodes);
  const maxEdges = Math.min(Math.max(1, Math.floor(options.maxEdges ?? 300)), QUERY_LIMITS.trace.edges);
  const empty: TraceResult = { generationId: null, start: null, nodes: [], edges: [], gaps: [], truncated: { depth: false, nodes: false, edges: false, fanout: false }, alsoMatched: [], note: "no index yet" };
  return inSnapshot<TraceResult>(db, empty, (r) => {
    const resolved = resolveEntities(db, r.generationId, ref);
    if (resolved === null) {
      return { ...empty, generationId: r.generationId, note: "no such entity in the current generation" };
    }
    const startId = resolved.id;
    const truncated = { depth: false, nodes: false, edges: false, fanout: false };
    const depthOf = new Map<string, number>([[startId, 0]]);
    const edges: FeatureEdgeRecord[] = [];
    const seenEdge = new Set<string>();
    let frontier = [startId];
    for (let depth = 1; depth <= maxDepth && frontier.length > 0; depth += 1) {
      const next: string[] = [];
      for (const node of frontier) {
        for (const dir of direction === "both" ? (["forward", "reverse"] as const) : ([direction] as const)) {
          const found = r.edgesOf(node, dir, QUERY_LIMITS.trace.fanout + 1);
          if (found.length > QUERY_LIMITS.trace.fanout) {
            truncated.fanout = true;
          }
          for (const e of found.slice(0, QUERY_LIMITS.trace.fanout)) {
            const key = `${e.src}\0${e.dst}\0${e.relation}`;
            if (seenEdge.has(key)) {
              continue;
            }
            if (edges.length >= maxEdges) {
              truncated.edges = true;
              continue;
            }
            seenEdge.add(key);
            edges.push(e);
            const other = dir === "forward" ? e.dst : e.src;
            if (!depthOf.has(other)) {
              if (depthOf.size >= maxNodes) {
                truncated.nodes = true;
                continue;
              }
              depthOf.set(other, depth);
              next.push(other);
            }
          }
        }
      }
      frontier = next;
    }
    truncated.depth = frontier.length > 0;
    const nodes = [...depthOf].map(([id, depth]) => ({ ...r.node(id), depth }));
    return {
      generationId: r.generationId, start: r.node(startId), nodes, edges, gaps: r.gapsFor([...depthOf.keys()]), truncated, alsoMatched: resolved.others,
      note: (resolved.others.length > 0 ? `The reference matched ${resolved.others.length + 1} entities (the same key in several places); this trace starts from the first by id. ` : "") + "Edges are syntactic and carry their own certainty; an absent edge is not proof of independence. Gaps list what could not be decided."
    };
  });
}

export interface FeatureImpactResult {
  generationId: number | null;
  /** False when the file or symbol is not in the published index (nothing is invented for it). */
  found: boolean;
  target: { file: string | null; symbol: string | null };
  entities: NodeRecord[];
  features: Array<{ id: string; name: string; via: string[] }>;
  reached: Array<NodeRecord & { depth: number; via: string }>;
  truncated: boolean;
  disclaimer: string;
}

const IMPACT_DISCLAIMER = "POTENTIAL STRUCTURAL effects only: feature entities located in the file (or symbol) and what connects to them over deterministic edges. Not proof of behavioural breakage; dynamic routes, events and URLs listed as gaps may hide further dependents.";

export function featureImpact(db: Database.Database, target: { file?: string; symbol?: string }, options: { depth?: number; maxNodes?: number } = {}): FeatureImpactResult {
  const depth = Math.min(Math.max(1, Math.floor(options.depth ?? 2)), 4);
  const maxNodes = Math.min(Math.max(1, Math.floor(options.maxNodes ?? 100)), QUERY_LIMITS.trace.nodes);
  const empty: FeatureImpactResult = { generationId: null, found: false, target: { file: target.file ?? null, symbol: target.symbol ?? null }, entities: [], features: [], reached: [], truncated: false, disclaimer: IMPACT_DISCLAIMER };
  return inSnapshot<FeatureImpactResult>(db, empty, (r) => {
    const startIds: string[] = [];
    let file = target.file ?? null;
    if (target.symbol !== undefined) {
      const cut = target.symbol.lastIndexOf("#");
      file = cut <= 0 ? null : target.symbol.slice(0, cut);
      const known = file !== null && db.prepare("SELECT 1 FROM symbol_occurrences WHERE generation_id = ? AND path = ? AND qualified_name = ? AND kind != 'module' LIMIT 1").get(r.generationId, file, target.symbol.slice(cut + 1)) !== undefined;
      if (!known) {
        return { ...empty, generationId: r.generationId };
      }
      startIds.push(symbolNodeId(file!, target.symbol.slice(cut + 1)));
    }
    if (file !== null) {
      if (target.symbol === undefined && db.prepare("SELECT 1 FROM generation_files WHERE generation_id = ? AND path = ? AND content_hash IS NOT NULL").get(r.generationId, file) === undefined) {
        return { ...empty, generationId: r.generationId };
      }
      for (const row of db.prepare("SELECT entity_id AS id FROM feature_entities WHERE generation_id = ? AND path = ? ORDER BY entity_id LIMIT 200").all(r.generationId, file) as Array<{ id: string }>) {
        startIds.push(row.id);
      }
      startIds.push(fileNodeId(file));
    }
    const entities = startIds.filter((id) => !id.startsWith("sym:") && !id.startsWith("file:")).map((id) => r.node(id));
    const seen = new Map<string, { depth: number; via: string }>();
    let truncated = false;
    let frontier = startIds.map((id) => ({ id, via: id }));
    for (const id of startIds) {
      seen.set(id, { depth: 0, via: id });
    }
    for (let d = 1; d <= depth && frontier.length > 0; d += 1) {
      const next: Array<{ id: string; via: string }> = [];
      for (const { id, via } of frontier) {
        for (const dir of ["forward", "reverse"] as const) {
          for (const e of r.edgesOf(id, dir, QUERY_LIMITS.trace.fanout)) {
            const other = dir === "forward" ? e.dst : e.src;
            if (seen.has(other)) {
              continue;
            }
            if (seen.size >= maxNodes) {
              truncated = true;
              continue;
            }
            seen.set(other, { depth: d, via: `${e.relation} (${e.certainty})` });
            next.push({ id: other, via });
          }
        }
      }
      frontier = next;
    }
    const features = new Map<string, { id: string; name: string; via: string[] }>();
    const memberStmt = db.prepare("SELECT f.feature_id AS id, f.name AS name FROM feature_members m JOIN features f ON f.generation_id = m.generation_id AND f.feature_id = m.feature_id WHERE m.generation_id = ? AND m.entity_id = ? ORDER BY f.feature_id LIMIT 50");
    for (const [id] of seen) {
      for (const f of memberStmt.all(r.generationId, id) as Array<{ id: string; name: string }>) {
        const entry = features.get(f.id) ?? { id: f.id, name: f.name, via: [] };
        if (entry.via.length < 10) {
          entry.via.push(id);
        }
        features.set(f.id, entry);
      }
    }
    return {
      generationId: r.generationId, found: true, target: { file, symbol: target.symbol ?? null }, entities, features: [...features.values()].sort((a, b) => (a.id < b.id ? -1 : 1)),
      reached: [...seen].filter(([, v]) => v.depth > 0).map(([id, v]) => ({ ...r.node(id), depth: v.depth, via: v.via })), truncated, disclaimer: IMPACT_DISCLAIMER
    };
  });
}

export interface ProvenanceRecord {
  generationId: number | null;
  revision: string | null;
  sourceFingerprint: string | null;
  found: boolean;
  feature: { id: string; name: string; source: string; trust: string } | null;
  members: Array<{ id: string; kind: string; name: string; path: string | null; line: number | null; mechanism: string | null; certainty: string | null; contentHash: string | null; extractor: string | null; validFromGeneration: number | null }>;
  lineage: Array<{ kind: string; oldIds: string[]; newIds: string[]; basis: string; certainty: string }>;
  note: string;
}

export function featureProvenance(db: Database.Database, id: string, options: { limit?: number } = {}): ProvenanceRecord {
  const limit = Math.min(Math.max(1, Math.floor(options.limit ?? 100)), QUERY_LIMITS.members);
  const none: ProvenanceRecord = { generationId: null, revision: null, sourceFingerprint: null, found: false, feature: null, members: [], lineage: [], note: "no index yet" };
  return inSnapshot<ProvenanceRecord>(db, none, (r, snap) => {
    const f = db.prepare("SELECT feature_id AS id, name, source FROM features WHERE generation_id = ? AND feature_id = ?").get(r.generationId, id) as { id: string; name: string; source: string } | undefined;
    if (f === undefined) {
      return { ...none, generationId: r.generationId, revision: snap.revision, sourceFingerprint: snap.fingerprint, note: "no such feature in the current generation" };
    }
    const members = (db.prepare(
      `SELECT e.entity_id AS id, e.kind, e.name, e.path, e.start_line AS line, e.mechanism, e.certainty, e.content_hash AS contentHash, e.extractor, e.valid_from_generation AS validFromGeneration
       FROM feature_members m JOIN feature_entities e ON e.generation_id = m.generation_id AND e.entity_id = m.entity_id
       WHERE m.generation_id = ? AND m.feature_id = ? ORDER BY m.hops, e.entity_id LIMIT ?`
    ).all(r.generationId, id, limit) as ProvenanceRecord["members"]);
    const lineage = (db.prepare("SELECT kind, old_ids_json AS o, new_ids_json AS n, basis, certainty FROM feature_lineage WHERE generation_id = ? ORDER BY id").all(r.generationId) as Array<{ kind: string; o: string; n: string; basis: string; certainty: string }>)
      .map((e) => ({ kind: e.kind, oldIds: JSON.parse(e.o) as string[], newIds: JSON.parse(e.n) as string[], basis: e.basis, certainty: e.certainty }))
      .filter((e) => e.oldIds.includes(id) || e.newIds.includes(id));
    return {
      generationId: r.generationId, revision: snap.revision, sourceFingerprint: snap.fingerprint, found: true, feature: { id: f.id, name: f.name, source: f.source, trust: "discovered" }, members, lineage,
      note: "Every member lists the mechanism that produced it, its certainty, the content hash of the source it came from and the generation since which it has existed. Nothing here is a model statement."
    };
  });
}

export function listGaps(db: Database.Database, options: { kind?: string; limit?: number } = {}): { generationId: number | null; gaps: GapRecord[]; total: number; truncated: boolean } {
  const limit = Math.min(Math.max(1, Math.floor(options.limit ?? 100)), QUERY_LIMITS.gaps);
  type Gaps = { generationId: number | null; gaps: GapRecord[]; total: number; truncated: boolean };
  return inSnapshot<Gaps>(db, { generationId: null, gaps: [], total: 0, truncated: false }, (r) => {
    const where = options.kind === undefined ? "" : " AND kind = ?";
    const params = options.kind === undefined ? [r.generationId] : [r.generationId, options.kind];
    const total = (db.prepare(`SELECT COUNT(*) AS n FROM feature_gaps WHERE generation_id = ?${where}`).get(...params) as { n: number }).n;
    const gaps = db.prepare(`SELECT kind, entity_id AS entityId, path, line, detail FROM feature_gaps WHERE generation_id = ?${where} ORDER BY gap_id LIMIT ?`).all(...params, limit) as GapRecord[];
    return { generationId: r.generationId, gaps, total, truncated: total > limit };
  });
}

/** Structural integrity of the published feature graph: edge endpoints exist, members belong to their feature, gaps point at real entities. */
export function validateFeatureGraph(db: Database.Database): { ok: boolean; problems: string[] } {
  return inSnapshot(db, { ok: true, problems: [] as string[] }, (r) => {
    const g = r.generationId;
    const problems: string[] = [];
    const dangling = (column: string): number => (db.prepare(
      `SELECT COUNT(*) AS n FROM feature_edges e WHERE e.generation_id = ? AND e.${column} NOT LIKE 'sym:%' AND e.${column} NOT LIKE 'file:%'
       AND NOT EXISTS (SELECT 1 FROM feature_entities f WHERE f.generation_id = e.generation_id AND f.entity_id = e.${column})`
    ).get(g) as { n: number }).n;
    for (const column of ["src_entity", "dst_entity"]) {
      const n = dangling(column);
      if (n > 0) {
        problems.push(`${n} feature edges have a ${column} that is not an entity`);
      }
    }
    const orphanMembers = (db.prepare("SELECT COUNT(*) AS n FROM feature_members m WHERE m.generation_id = ? AND NOT EXISTS (SELECT 1 FROM features f WHERE f.generation_id = m.generation_id AND f.feature_id = m.feature_id)").get(g) as { n: number }).n;
    if (orphanMembers > 0) {
      problems.push(`${orphanMembers} feature members belong to no feature`);
    }
    const badGaps = (db.prepare("SELECT COUNT(*) AS n FROM feature_gaps x WHERE x.generation_id = ? AND x.entity_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM feature_entities f WHERE f.generation_id = x.generation_id AND f.entity_id = x.entity_id)").get(g) as { n: number }).n;
    if (badGaps > 0) {
      problems.push(`${badGaps} coverage gaps name an entity that does not exist`);
    }
    const invalidCertainty = (db.prepare("SELECT COUNT(*) AS n FROM feature_edges WHERE generation_id = ? AND certainty NOT IN ('resolved','ambiguous','heuristic')").get(g) as { n: number }).n;
    if (invalidCertainty > 0) {
      problems.push(`${invalidCertainty} feature edges have an unknown certainty value`);
    }
    return { ok: problems.length === 0, problems };
  });
}
