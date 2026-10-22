import type Database from "better-sqlite3";
import { EngbrainError } from "./errors.js";
import { currentGenerationId } from "./store/generations.js";

/**
 * Read-only graph queries over the PUBLISHED generation, served from persisted edges and facts (never from the working tree).
 * Every traversal is bounded (depth, nodes, edges, time) and says so when it stopped early; every edge keeps its provenance;
 * and the unresolved boundary a traversal touched is returned, because a missing edge never means "no dependency".
 * `impact` reports POTENTIAL STRUCTURAL effects, not proven behavioural breakage.
 */
export type NodeKind = "package" | "file" | "symbol" | "external" | "unknown";
export type GraphMode = "module" | "symbol" | "all";

export interface NodeRef {
  key: string;
  kind: NodeKind;
  path: string | null;
  symbol: string | null;
  /** Qualified symbol name, file path, package/dependency name. */
  name: string;
}

export interface EdgeRecord {
  edgeId: number;
  kind: string;
  family: string;
  importStyle: string | null;
  src: NodeRef;
  dst: NodeRef;
  mechanism: string;
  resolution: string;
  reason: string;
  line: number | null;
  extractor: string;
  detail: unknown;
}

export interface Budget {
  maxDepth: number;
  maxNodes: number;
  maxEdges: number;
  timeMs: number;
}

export const DEFAULT_BUDGET: Budget = { maxDepth: 3, maxNodes: 500, maxEdges: 2000, timeMs: 2000 };
const HARD_LIMITS: Budget = { maxDepth: 25, maxNodes: 20_000, maxEdges: 100_000, timeMs: 30_000 };

export interface Truncation {
  depth: boolean;
  nodes: boolean;
  edges: boolean;
  time: boolean;
}

export interface TraversalResult {
  generationId: number | null;
  direction: "forward" | "reverse";
  mode: GraphMode;
  start: NodeRef | null;
  nodes: Array<NodeRef & { depth: number }>;
  edges: EdgeRecord[];
  truncated: Truncation;
  /** Unresolved / ambiguous / dynamic edges met while expanding: relationships the index could not decide. */
  unresolvedBoundary: EdgeRecord[];
  unresolvedBoundaryTruncated: boolean;
  budget: Budget;
  note: string;
}

interface EdgeRow {
  edge_id: number; family: string; edge_kind: string; import_style: string | null;
  src_kind: string; src_path: string; src_symbol: string | null;
  dst_kind: string; dst_path: string | null; dst_symbol: string | null; dst_name: string | null; dst_package: string | null;
  mechanism: string; resolution: string; reason: string; start_line: number | null; extractor: string; detail: string | null;
}

const BOUNDARY = new Set(["unresolved", "ambiguous", "dynamic"]);
const BOUNDARY_CAP = 100;

function clampBudget(partial: Partial<Budget> | undefined): Budget {
  const merged = { ...DEFAULT_BUDGET, ...partial };
  return {
    maxDepth: Math.min(Math.max(1, Math.floor(merged.maxDepth)), HARD_LIMITS.maxDepth),
    maxNodes: Math.min(Math.max(1, Math.floor(merged.maxNodes)), HARD_LIMITS.maxNodes),
    maxEdges: Math.min(Math.max(1, Math.floor(merged.maxEdges)), HARD_LIMITS.maxEdges),
    timeMs: Math.min(Math.max(1, Math.floor(merged.timeMs)), HARD_LIMITS.timeMs)
  };
}

const MODE_FAMILIES: Record<GraphMode, string[]> = { module: ["module", "package"], symbol: ["symbol"], all: ["module", "symbol", "package"] };

class Reader {
  private readonly names = new Map<string, string>();
  private readonly statements = new Map<string, Database.Statement>();

  constructor(readonly db: Database.Database, readonly generationId: number) {}

  stmt(sql: string): Database.Statement {
    let s = this.statements.get(sql);
    if (s === undefined) {
      s = this.db.prepare(sql);
      this.statements.set(sql, s);
    }
    return s;
  }

  symbolName(path: string, key: string): string {
    const id = `${path}#${key}`;
    let name = this.names.get(id);
    if (name === undefined) {
      const row = this.stmt("SELECT qualified_name AS q FROM symbol_occurrences WHERE generation_id = ? AND path = ? AND symbol_key = ? LIMIT 1").get(this.generationId, path, key) as { q: string } | undefined;
      name = row?.q ?? key;
      this.names.set(id, name);
    }
    return name;
  }

  node(kind: NodeKind, path: string | null, symbol: string | null, name: string | null, pkg?: string | null): NodeRef {
    switch (kind) {
      case "file": return { key: `file:${path}`, kind, path, symbol: null, name: path ?? "" };
      case "symbol": return { key: `sym:${path}#${symbol}`, kind, path, symbol, name: this.symbolName(path ?? "", symbol ?? "") };
      case "package": return { key: `pkg:${path}`, kind, path, symbol: null, name: path === "" ? "<repository>" : (path ?? "") };
      case "external": return { key: `ext:${pkg ?? name ?? ""}`, kind, path: null, symbol: null, name: pkg ?? name ?? "" };
      default: return { key: `unknown:${name ?? ""}`, kind: "unknown", path: null, symbol: null, name: name ?? "" };
    }
  }

  edge(r: EdgeRow): EdgeRecord {
    return {
      edgeId: r.edge_id, kind: r.edge_kind, family: r.family, importStyle: r.import_style,
      src: this.node(r.src_kind as NodeKind, r.src_path, r.src_symbol, null),
      dst: this.node(r.dst_kind as NodeKind, r.dst_path, r.dst_symbol, r.dst_name, r.dst_package),
      mechanism: r.mechanism, resolution: r.resolution, reason: r.reason, line: r.start_line, extractor: r.extractor,
      detail: r.detail === null ? null : (JSON.parse(r.detail) as unknown)
    };
  }

  /** Edges leaving a node (forward) or arriving at it (reverse), filtered by mode and optional kinds. */
  edgesOf(node: NodeRef, direction: "forward" | "reverse", mode: GraphMode, kinds: readonly string[] | undefined, limit: number): EdgeRow[] {
    const families = MODE_FAMILIES[mode];
    const where = ["generation_id = ?", `family IN (${families.map(() => "?").join(",")})`];
    const params: unknown[] = [this.generationId, ...families];
    if (kinds !== undefined && kinds.length > 0) {
      where.push(`edge_kind IN (${kinds.map(() => "?").join(",")})`);
      params.push(...kinds);
    }
    // The index is named explicitly: with `ORDER BY edge_id LIMIT` the planner otherwise walks the table in rowid order
    // (every edge of every generation) instead of the few rows the (generation, path) index addresses.
    let index = "idx_graph_edges_dst";
    if (direction === "forward") {
      if (node.kind === "external" || node.kind === "unknown") {
        return [];
      }
      index = "idx_graph_edges_src";
      where.push("src_kind = ?", "src_path = ?", "src_symbol IS ?");
      params.push(node.kind, node.path, node.symbol);
    } else if (node.kind === "symbol") {
      where.push("dst_kind = 'symbol'", "dst_path = ?", "dst_symbol = ?");
      params.push(node.path, node.symbol);
    } else if (node.kind === "file") {
      where.push("dst_kind = 'file'", "dst_path = ?");
      params.push(node.path);
    } else if (node.kind === "package") {
      where.push("dst_kind = 'package'", "dst_path = ?");
      params.push(node.path);
    } else if (node.kind === "external") {
      index = "idx_graph_edges_external";
      where.push("dst_kind = 'external'", "dst_package = ?");
      params.push(node.name);
    } else {
      return [];
    }
    return this.stmt(`SELECT * FROM graph_edges INDEXED BY ${index} WHERE ${where.join(" AND ")} ORDER BY edge_id LIMIT ?`).all(...params, limit) as EdgeRow[];
  }
}

function inSnapshot<T>(db: Database.Database, empty: (generationId: null) => T, fn: (reader: Reader) => T): T {
  return db.transaction((): T => {
    const generationId = currentGenerationId(db);
    return generationId === null ? empty(null) : fn(new Reader(db, generationId));
  })();
}

/** What a user can name: a file path, or `path#qualified.name` / `path#key:<symbolKey>` for a symbol. */
export interface NodeSpec {
  file?: string;
  symbol?: string;
  package?: string;
  external?: string;
}

export function resolveNode(db: Database.Database, spec: NodeSpec): NodeRef {
  return inSnapshot<NodeRef>(db, () => { throw new EngbrainError("NOT_INITIALIZED", "no index yet: run `engbrain index`"); }, (r) => {
    if (spec.file !== undefined) {
      const row = r.stmt("SELECT 1 AS x FROM generation_files WHERE generation_id = ? AND path = ? AND content_hash IS NOT NULL").get(r.generationId, spec.file);
      if (row === undefined) {
        throw new EngbrainError("INVALID_ROOT", `file is not in the published index: ${spec.file}`);
      }
      return r.node("file", spec.file, null, null);
    }
    if (spec.symbol !== undefined) {
      const cut = spec.symbol.lastIndexOf("#"); // a path may contain "#", a qualified name or symbol key never does
      if (cut <= 0 || cut === spec.symbol.length - 1) {
        throw new EngbrainError("INVALID_ROOT", "a symbol is written path#qualifiedName (or path#key:<symbolKey>)");
      }
      const path = spec.symbol.slice(0, cut);
      const rest = spec.symbol.slice(cut + 1);
      const byKey = rest.startsWith("key:");
      const rows = r.stmt(
        `SELECT symbol_key AS key, qualified_name AS q, kind FROM symbol_occurrences WHERE generation_id = ? AND path = ? AND ${byKey ? "symbol_key = ?" : "qualified_name = ?"} AND kind != 'module' ORDER BY start_byte`
      ).all(r.generationId, path, byKey ? rest.slice(4) : rest) as Array<{ key: string; q: string; kind: string }>;
      if (rows.length === 0) {
        throw new EngbrainError("INVALID_ROOT", `no such symbol in the published index: ${spec.symbol}`);
      }
      if (rows.length > 1) {
        throw new EngbrainError("INVALID_ROOT", `ambiguous symbol name; use one of: ${rows.map((x) => `${path}#key:${x.key} (${x.kind})`).join(", ")}`);
      }
      return r.node("symbol", path, rows[0]!.key, null);
    }
    if (spec.package !== undefined) {
      const row = r.stmt("SELECT 1 AS x FROM graph_packages WHERE generation_id = ? AND dir = ?").get(r.generationId, spec.package);
      if (row === undefined) {
        throw new EngbrainError("INVALID_ROOT", `no such package directory in the published index: ${spec.package || "(repository root)"}`);
      }
      return r.node("package", spec.package, null, null);
    }
    if (spec.external !== undefined) {
      return r.node("external", null, null, spec.external, spec.external);
    }
    throw new EngbrainError("INVALID_ROOT", "name a node with --file, --symbol, --package or --external");
  });
}

export interface TraversalOptions {
  direction: "forward" | "reverse";
  mode?: GraphMode;
  kinds?: readonly string[];
  budget?: Partial<Budget>;
}

/** Breadth-first, bounded, deterministic traversal. Each node is expanded once; cycles cannot loop. */
export function traverse(db: Database.Database, start: NodeRef, options: TraversalOptions): TraversalResult {
  const mode = options.mode ?? "module";
  const budget = clampBudget(options.budget);
  const empty = (generationId: null): TraversalResult => ({
    generationId, direction: options.direction, mode, start: null, nodes: [], edges: [], truncated: { depth: false, nodes: false, edges: false, time: false },
    unresolvedBoundary: [], unresolvedBoundaryTruncated: false, budget, note: "no index yet"
  });
  return inSnapshot<TraversalResult>(db, empty, (r) => {
    const startedAt = performance.now();
    const truncated: Truncation = { depth: false, nodes: false, edges: false, time: false };
    const depthOf = new Map<string, number>([[start.key, 0]]);
    const nodes: Array<NodeRef & { depth: number }> = [{ ...start, depth: 0 }];
    const edges: EdgeRecord[] = [];
    const boundary: EdgeRecord[] = [];
    let boundaryTruncated = false;
    let frontier: NodeRef[] = [start];
    for (let depth = 0; depth < budget.maxDepth && frontier.length > 0; depth += 1) {
      const next: NodeRef[] = [];
      for (const node of frontier) {
        if (performance.now() - startedAt > budget.timeMs) {
          truncated.time = true;
          break;
        }
        for (const row of r.edgesOf(node, options.direction, mode, options.kinds, budget.maxEdges - edges.length + 1)) {
          if (edges.length >= budget.maxEdges) {
            truncated.edges = true;
            break;
          }
          const edge = r.edge(row);
          edges.push(edge);
          if (BOUNDARY.has(edge.resolution)) {
            if (boundary.length < BOUNDARY_CAP) {
              boundary.push(edge);
            } else {
              boundaryTruncated = true;
            }
          }
          const other = options.direction === "forward" ? edge.dst : edge.src;
          if (other.kind === "unknown" || depthOf.has(other.key)) {
            continue;
          }
          if (nodes.length >= budget.maxNodes) {
            truncated.nodes = true;
            continue;
          }
          depthOf.set(other.key, depth + 1);
          nodes.push({ ...other, depth: depth + 1 });
          next.push(other);
        }
        if (truncated.edges) {
          break;
        }
      }
      frontier = next;
      if (truncated.time || truncated.edges) {
        break;
      }
    }
    if (frontier.length > 0 && !truncated.time && !truncated.edges && nodes.every((n) => n.depth <= budget.maxDepth) && frontier.some((n) => (depthOf.get(n.key) ?? 0) >= budget.maxDepth)) {
      // the frontier at the depth limit may still have unexpanded neighbours
      truncated.depth = frontier.some((n) => r.edgesOf(n, options.direction, mode, options.kinds, 1).length > 0);
    }
    return {
      generationId: r.generationId, direction: options.direction, mode, start, nodes, edges, truncated,
      unresolvedBoundary: boundary, unresolvedBoundaryTruncated: boundaryTruncated, budget,
      note: "Edges come from syntax-level extraction and deterministic resolution. An absent edge does not mean no dependency; see unresolvedBoundary."
    };
  });
}

/** Direct incoming edges to a symbol: who imports it, references it by name, extends or implements it. */
export interface ReferencesResult {
  generationId: number | null;
  references: EdgeRecord[];
  truncated: boolean;
}

export function references(db: Database.Database, symbol: NodeRef, limit = 500): ReferencesResult {
  return inSnapshot<ReferencesResult>(db, (g) => ({ generationId: g, references: [], truncated: false }), (r) => {
    const rows = r.edgesOf(symbol, "reverse", "symbol", ["IMPORTS", "REFERENCES", "EXTENDS", "IMPLEMENTS"], Math.min(limit, HARD_LIMITS.maxEdges) + 1);
    const cap = Math.min(limit, HARD_LIMITS.maxEdges);
    return { generationId: r.generationId, references: rows.slice(0, cap).map((row) => r.edge(row)), truncated: rows.length > cap };
  });
}

export interface PathResult {
  generationId: number | null;
  found: boolean;
  path: EdgeRecord[];
  explored: number;
  truncated: Truncation;
  note: string;
}

/** Shortest known dependency path (fewest edges) from one node to another over resolved edges. Not finding one proves nothing. */
export function shortestPath(db: Database.Database, from: NodeRef, to: NodeRef, options: { mode?: GraphMode; kinds?: readonly string[]; budget?: Partial<Budget> } = {}): PathResult {
  const mode = options.mode ?? "all";
  const budget = clampBudget({ maxDepth: 12, ...options.budget });
  return inSnapshot<PathResult>(db, (g) => ({ generationId: g, found: false, path: [], explored: 0, truncated: { depth: false, nodes: false, edges: false, time: false }, note: "no index yet" }), (r) => {
    const startedAt = performance.now();
    const truncated: Truncation = { depth: false, nodes: false, edges: false, time: false };
    const via = new Map<string, { prev: string; edge: EdgeRecord }>();
    const seen = new Set<string>([from.key]);
    let frontier: NodeRef[] = [from];
    let explored = 0;
    for (let depth = 0; depth < budget.maxDepth && frontier.length > 0; depth += 1) {
      const next: NodeRef[] = [];
      for (const node of frontier) {
        if (performance.now() - startedAt > budget.timeMs) {
          truncated.time = true;
          return { generationId: r.generationId, found: false, path: [], explored, truncated, note: "search stopped: time budget" };
        }
        explored += 1;
        for (const row of r.edgesOf(node, "forward", mode, options.kinds, budget.maxEdges)) {
          if (BOUNDARY.has(row.resolution) || row.resolution === "syntactic_only" || row.dst_kind === "unknown") {
            continue; // only decided relationships can form a path (a name-match reference is not one)
          }
          const edge = r.edge(row);
          if (seen.has(edge.dst.key)) {
            continue;
          }
          if (seen.size >= budget.maxNodes) {
            truncated.nodes = true;
            continue;
          }
          seen.add(edge.dst.key);
          via.set(edge.dst.key, { prev: node.key, edge });
          if (edge.dst.key === to.key) {
            const chain: EdgeRecord[] = [];
            for (let at = to.key; at !== from.key; at = via.get(at)!.prev) {
              chain.unshift(via.get(at)!.edge);
            }
            return { generationId: r.generationId, found: true, path: chain, explored, truncated, note: "shortest by edge count among the decided edges of the selected mode" };
          }
          next.push(edge.dst);
        }
      }
      frontier = next;
      if (frontier.length > 0 && depth === budget.maxDepth - 1) {
        truncated.depth = frontier.some((n) => r.edgesOf(n, "forward", mode, options.kinds, 1).length > 0);
      }
    }
    return { generationId: r.generationId, found: false, path: [], explored, truncated, note: "no path found within the budget; absence of a path is not proof of independence" };
  });
}

export interface CycleResult {
  generationId: number | null;
  cycles: Array<{ size: number; members: string[]; membersTruncated: boolean }>;
  totalCycles: number;
  truncated: boolean;
  note: string;
}

/** Strongly connected components (size > 1, or a self import) of the resolved file-level import graph. Iterative Tarjan: safe on huge cycles. */
export function findCycles(db: Database.Database, options: { maxCycles?: number; maxMembers?: number } = {}): CycleResult {
  const maxCycles = options.maxCycles ?? 50;
  const maxMembers = options.maxMembers ?? 50;
  return inSnapshot<CycleResult>(db, (g) => ({ generationId: g, cycles: [], totalCycles: 0, truncated: false, note: "no index yet" }), (r) => {
    const rows = r.stmt(
      "SELECT src_path AS a, dst_path AS b FROM graph_edges WHERE generation_id = ? AND family = 'module' AND edge_kind IN ('IMPORTS','RE_EXPORTS') AND resolution = 'resolved' AND dst_kind = 'file' ORDER BY src_path, dst_path"
    ).all(r.generationId) as Array<{ a: string; b: string }>;
    const index = new Map<string, number>();
    const names: string[] = [];
    const id = (p: string): number => {
      let v = index.get(p);
      if (v === undefined) {
        v = names.length;
        index.set(p, v);
        names.push(p);
      }
      return v;
    };
    const adjacency: number[][] = [];
    const selfLoops = new Set<number>();
    for (const { a, b } of rows) {
      const from = id(a);
      const to = id(b);
      (adjacency[from] ??= []).push(to);
      adjacency[to] ??= [];
      if (from === to) {
        selfLoops.add(from);
      }
    }
    const n = names.length;
    const order = new Array<number>(n).fill(-1);
    const low = new Array<number>(n).fill(0);
    const onStack = new Array<boolean>(n).fill(false);
    const stack: number[] = [];
    const components: number[][] = [];
    let counter = 0;
    for (let root = 0; root < n; root += 1) {
      if (order[root] !== -1) {
        continue;
      }
      const work: Array<{ v: number; next: number }> = [{ v: root, next: 0 }];
      order[root] = low[root] = counter++;
      stack.push(root);
      onStack[root] = true;
      while (work.length > 0) {
        const frame = work[work.length - 1]!;
        const edges = adjacency[frame.v] ?? [];
        if (frame.next < edges.length) {
          const w = edges[frame.next++]!;
          if (order[w] === -1) {
            order[w] = low[w] = counter++;
            stack.push(w);
            onStack[w] = true;
            work.push({ v: w, next: 0 });
          } else if (onStack[w]) {
            low[frame.v] = Math.min(low[frame.v]!, order[w]!);
          }
        } else {
          if (low[frame.v] === order[frame.v]) {
            const component: number[] = [];
            let w: number;
            do {
              w = stack.pop()!;
              onStack[w] = false;
              component.push(w);
            } while (w !== frame.v);
            if (component.length > 1 || selfLoops.has(component[0]!)) {
              components.push(component);
            }
          }
          work.pop();
          const parent = work[work.length - 1];
          if (parent !== undefined) {
            low[parent.v] = Math.min(low[parent.v]!, low[frame.v]!);
          }
        }
      }
    }
    const described = components
      .map((c) => c.map((v) => names[v]!).sort())
      .sort((x, y) => y.length - x.length || (x[0]! < y[0]! ? -1 : 1));
    return {
      generationId: r.generationId,
      cycles: described.slice(0, maxCycles).map((members) => ({ size: members.length, members: members.slice(0, maxMembers), membersTruncated: members.length > maxMembers })),
      totalCycles: described.length,
      truncated: described.length > maxCycles,
      note: "cycles among RESOLVED file-level imports/re-exports only; unresolved or dynamic imports could hide more"
    };
  });
}

export interface ImpactResult {
  generationId: number | null;
  target: NodeRef | null;
  /** Potential structural effects, grouped by distance from the target (1 = directly depends on it). */
  affected: Array<{ node: NodeRef; distance: number; via: EdgeRecord }>;
  /** Symbols of the target file (or the target and its members) that other code is wired to. */
  usedSymbols: Array<{ symbol: NodeRef; incoming: number }>;
  truncated: Truncation;
  unresolvedBoundary: { dynamicImports: number; unresolvedImports: number; ambiguousImports: number; unresolvedBindings: number; possiblyRelated: EdgeRecord[] };
  budget: Budget;
  disclaimer: string;
}

const IMPACT_DISCLAIMER =
  "POTENTIAL STRUCTURAL effects only: code that statically imports, re-exports, references by name, extends or implements the target (directly or through a chain of importing files). " +
  "This is not proof of behavioural breakage, and dynamic or unresolved imports (counted below) may hide further dependents. Read the code and run tests.";

export function impact(db: Database.Database, target: NodeRef, options: { budget?: Partial<Budget> } = {}): ImpactResult {
  const budget = clampBudget(options.budget);
  return inSnapshot<ImpactResult>(db, (g) => ({
    generationId: g, target: null, affected: [], usedSymbols: [], truncated: { depth: false, nodes: false, edges: false, time: false },
    unresolvedBoundary: { dynamicImports: 0, unresolvedImports: 0, ambiguousImports: 0, unresolvedBindings: 0, possiblyRelated: [] }, budget, disclaimer: IMPACT_DISCLAIMER
  }), (r) => {
    const startedAt = performance.now();
    const truncated: Truncation = { depth: false, nodes: false, edges: false, time: false };
    const affected: ImpactResult["affected"] = [];
    const seen = new Set<string>([target.key]);
    const used = new Map<string, number>();
    const targetFile = target.kind === "file" ? target.path! : target.kind === "symbol" ? target.path! : null;

    // level 1: edges arriving at the target itself (a file), or at the symbol and its members
    let frontier: NodeRef[] = [];
    const record = (edge: EdgeRecord, distance: number): void => {
      const from = edge.src;
      if (edge.dst.kind === "symbol") {
        used.set(edge.dst.key, (used.get(edge.dst.key) ?? 0) + 1);
      }
      if (seen.has(from.key)) {
        return;
      }
      if (affected.length >= budget.maxNodes) {
        truncated.nodes = true;
        return;
      }
      seen.add(from.key);
      affected.push({ node: from, distance, via: edge });
      frontier.push(from);
    };
    let edgesRead = 0;
    /** Time and edge budgets apply to the whole run, not per query: false once either is spent (and says which). */
    const withinBudget = (): boolean => {
      if (performance.now() - startedAt > budget.timeMs) {
        truncated.time = true;
        return false;
      }
      if (edgesRead >= budget.maxEdges) {
        truncated.edges = true;
        return false;
      }
      return true;
    };
    const incoming = (node: NodeRef, kinds?: readonly string[], mode: GraphMode = "all"): EdgeRow[] => {
      const rows = r.edgesOf(node, "reverse", mode, kinds, Math.max(1, budget.maxEdges - edgesRead));
      edgesRead += rows.length;
      return rows;
    };
    const targets: NodeRef[] = [target];
    if (target.kind === "file") {
      for (const row of r.stmt("SELECT symbol_key AS k FROM symbol_occurrences WHERE generation_id = ? AND path = ? AND kind != 'module'").all(r.generationId, target.path) as Array<{ k: string }>) {
        targets.push(r.node("symbol", target.path, row.k, null));
      }
    } else if (target.kind === "symbol") {
      // members: symbols whose ownership chain reaches the target symbol
      const members = r.stmt(
        `WITH RECURSIVE m(local_id) AS (
           SELECT local_id FROM symbol_occurrences WHERE generation_id = ? AND path = ? AND symbol_key = ?
           UNION SELECT s.local_id FROM symbol_occurrences s JOIN m ON s.parent_local_id = m.local_id WHERE s.generation_id = ? AND s.path = ?
         ) SELECT s.symbol_key AS k FROM symbol_occurrences s JOIN m ON s.local_id = m.local_id WHERE s.generation_id = ? AND s.path = ? AND s.symbol_key != ?`
      ).all(r.generationId, target.path, target.symbol, r.generationId, target.path, r.generationId, target.path, target.symbol) as Array<{ k: string }>;
      for (const m of members) {
        targets.push(r.node("symbol", target.path, m.k, null));
      }
    }
    for (const t of targets) {
      if (!withinBudget()) {
        break;
      }
      for (const row of incoming(t)) {
        record(r.edge(row), 1);
      }
    }
    // later levels: files that depend on the affected files, through resolved module edges
    for (let distance = 2; distance <= budget.maxDepth && frontier.length > 0; distance += 1) {
      const level = frontier;
      frontier = [];
      for (const node of level) {
        if (!withinBudget()) {
          frontier = [];
          break;
        }
        const isPackage = node.kind === "package";
        const file = node.kind === "file" || isPackage ? node : r.node("file", node.path, null, null);
        for (const row of incoming(file, isPackage ? ["DEPENDS_ON"] : ["IMPORTS", "RE_EXPORTS"], "module")) {
          record(r.edge(row), distance);
        }
      }
    }
    if (frontier.length > 0 && !truncated.time && !truncated.edges) {
      truncated.depth = true;
    }
    const counts = r.stmt("SELECT resolution, COUNT(*) AS n FROM graph_edges WHERE generation_id = ? AND family = 'module' AND resolution IN ('dynamic','unresolved','ambiguous') GROUP BY resolution").all(r.generationId) as Array<{ resolution: string; n: number }>;
    const count = (k: string): number => counts.find((c) => c.resolution === k)?.n ?? 0;
    const bindings = (r.stmt("SELECT COUNT(*) AS n FROM graph_edges WHERE generation_id = ? AND family = 'symbol' AND edge_kind = 'IMPORTS' AND resolution IN ('unresolved','ambiguous')").get(r.generationId) as { n: number }).n;
    const stem = (targetFile ?? "").split("/").pop()?.replace(/\.[^.]+$/, "") ?? "";
    const related = stem.length >= 3
      ? (r.stmt(
          `SELECT * FROM graph_edges WHERE generation_id = ? AND family = 'module' AND resolution IN ('unresolved','ambiguous') AND dst_name LIKE ? ESCAPE '\\' ORDER BY edge_id LIMIT 50`
        ).all(r.generationId, `%${stem.replace(/[\\%_]/g, (c) => `\\${c}`)}%`) as EdgeRow[]).map((row) => r.edge(row))
      : [];
    return {
      generationId: r.generationId, target, affected: affected.sort((a, b) => a.distance - b.distance || (a.node.key < b.node.key ? -1 : 1)),
      usedSymbols: [...used.entries()].map(([key, n]) => ({ symbol: r.node("symbol", key.slice(4, key.lastIndexOf("#")), key.slice(key.lastIndexOf("#") + 1), null), incoming: n })).sort((a, b) => b.incoming - a.incoming || (a.symbol.key < b.symbol.key ? -1 : 1)),
      truncated, unresolvedBoundary: { dynamicImports: count("dynamic"), unresolvedImports: count("unresolved"), ambiguousImports: count("ambiguous"), unresolvedBindings: bindings, possiblyRelated: related },
      budget, disclaimer: IMPACT_DISCLAIMER
    };
  });
}

export interface GraphStats {
  generationId: number | null;
  nodes: { files: number; symbols: number; packages: number; externals: number; symbolsByKind: Record<string, number> };
  edges: { total: number; byKind: Record<string, number>; byFamily: Record<string, number>; byResolution: Record<string, number> };
  boundary: { unresolved: number; ambiguous: number; dynamic: number; syntacticOnly: number };
  cycles: number;
  highestFanIn: Array<{ path: string; imports: number }>;
  highestFanOut: Array<{ path: string; imports: number }>;
}

export function graphStats(db: Database.Database): GraphStats {
  return inSnapshot<GraphStats>(db, (g) => ({
    generationId: g, nodes: { files: 0, symbols: 0, packages: 0, externals: 0, symbolsByKind: {} }, edges: { total: 0, byKind: {}, byFamily: {}, byResolution: {} },
    boundary: { unresolved: 0, ambiguous: 0, dynamic: 0, syntacticOnly: 0 }, cycles: 0, highestFanIn: [], highestFanOut: []
  }), (r) => {
    const g = r.generationId;
    const one = (sql: string): number => (r.stmt(sql).get(g) as { n: number | null }).n ?? 0;
    const group = (column: string): Record<string, number> =>
      Object.fromEntries((r.stmt(`SELECT ${column} AS k, COUNT(*) AS n FROM graph_edges WHERE generation_id = ? GROUP BY ${column}`).all(g) as Array<{ k: string; n: number }>).map((x) => [x.k, x.n]));
    const byResolution = group("resolution");
    const symbolsByKind = Object.fromEntries((r.stmt("SELECT kind AS k, COUNT(*) AS n FROM symbol_occurrences WHERE generation_id = ? AND kind != 'module' AND extractor_id LIKE 'code:%' GROUP BY kind").all(g) as Array<{ k: string; n: number }>).map((x) => [x.k, x.n]));
    return {
      generationId: g,
      nodes: {
        files: one("SELECT COUNT(*) AS n FROM generation_files WHERE generation_id = ? AND content_hash IS NOT NULL"),
        symbols: Object.values(symbolsByKind).reduce((a, b) => a + b, 0),
        packages: one("SELECT COUNT(*) AS n FROM graph_packages WHERE generation_id = ?"),
        externals: one("SELECT COUNT(DISTINCT dst_package) AS n FROM graph_edges WHERE generation_id = ? AND dst_kind = 'external'"),
        symbolsByKind
      },
      edges: { total: one("SELECT COUNT(*) AS n FROM graph_edges WHERE generation_id = ?"), byKind: group("edge_kind"), byFamily: group("family"), byResolution },
      boundary: { unresolved: byResolution["unresolved"] ?? 0, ambiguous: byResolution["ambiguous"] ?? 0, dynamic: byResolution["dynamic"] ?? 0, syntacticOnly: byResolution["syntactic_only"] ?? 0 },
      cycles: findCycles(db, { maxCycles: 1, maxMembers: 1 }).totalCycles,
      highestFanIn: r.stmt("SELECT dst_path AS path, COUNT(*) AS imports FROM graph_edges WHERE generation_id = ? AND family = 'module' AND resolution = 'resolved' GROUP BY dst_path ORDER BY imports DESC, dst_path LIMIT 5").all(g) as Array<{ path: string; imports: number }>,
      highestFanOut: r.stmt("SELECT src_path AS path, COUNT(*) AS imports FROM graph_edges WHERE generation_id = ? AND family = 'module' AND resolution = 'resolved' GROUP BY src_path ORDER BY imports DESC, src_path LIMIT 5").all(g) as Array<{ path: string; imports: number }>
    };
  });
}

export interface GraphValidation {
  generationId: number | null;
  ok: boolean;
  problems: string[];
  checked: Record<string, number>;
}

/** Structural integrity of the published graph: no dangling endpoints, consistent resolution/destination, contiguous edge ids. */
export function validateGraph(db: Database.Database): GraphValidation {
  return inSnapshot<GraphValidation>(db, (g) => ({ generationId: g, ok: true, problems: [], checked: {} }), (r) => {
    const g = r.generationId;
    const problems: string[] = [];
    const count = (sql: string): number => (r.stmt(sql).get(g, g) as { n: number }).n;
    const total = (r.stmt("SELECT COUNT(*) AS n, MIN(edge_id) AS lo, MAX(edge_id) AS hi FROM graph_edges WHERE generation_id = ?").get(g) as { n: number; lo: number | null; hi: number | null });
    if (total.n > 0 && (total.lo !== 0 || total.hi !== total.n - 1)) {
      problems.push(`edge ids are not contiguous (${total.lo}..${total.hi} for ${total.n} edges)`);
    }
    const danglingSrcFile = count(`SELECT COUNT(*) AS n FROM graph_edges e WHERE e.generation_id = ? AND e.src_kind = 'file' AND NOT EXISTS (SELECT 1 FROM generation_files f WHERE f.generation_id = ? AND f.path = e.src_path AND f.content_hash IS NOT NULL)`);
    if (danglingSrcFile > 0) {
      problems.push(`${danglingSrcFile} edges start at a file that is not in the generation`);
    }
    const danglingDstFile = count(`SELECT COUNT(*) AS n FROM graph_edges e WHERE e.generation_id = ? AND e.dst_kind = 'file' AND NOT EXISTS (SELECT 1 FROM generation_files f WHERE f.generation_id = ? AND f.path = e.dst_path AND f.content_hash IS NOT NULL)`);
    if (danglingDstFile > 0) {
      problems.push(`${danglingDstFile} edges end at a file that is not in the generation`);
    }
    const danglingSrcSymbol = count(`SELECT COUNT(*) AS n FROM graph_edges e WHERE e.generation_id = ? AND e.src_kind = 'symbol' AND NOT EXISTS (SELECT 1 FROM symbol_occurrences s WHERE s.generation_id = ? AND s.path = e.src_path AND s.symbol_key = e.src_symbol)`);
    if (danglingSrcSymbol > 0) {
      problems.push(`${danglingSrcSymbol} edges start at a symbol that does not exist`);
    }
    const danglingDstSymbol = count(`SELECT COUNT(*) AS n FROM graph_edges e WHERE e.generation_id = ? AND e.dst_kind = 'symbol' AND NOT EXISTS (SELECT 1 FROM symbol_occurrences s WHERE s.generation_id = ? AND s.path = e.dst_path AND s.symbol_key = e.dst_symbol)`);
    if (danglingDstSymbol > 0) {
      problems.push(`${danglingDstSymbol} edges end at a symbol that does not exist`);
    }
    const danglingPackage = (r.stmt(
      `SELECT COUNT(*) AS n FROM graph_edges e WHERE e.generation_id = @g AND (
         (e.src_kind = 'package' AND NOT EXISTS (SELECT 1 FROM graph_packages p WHERE p.generation_id = @g AND p.dir = e.src_path))
         OR (e.dst_kind = 'package' AND NOT EXISTS (SELECT 1 FROM graph_packages p WHERE p.generation_id = @g AND p.dir = e.dst_path)))`
    ).get({ g }) as { n: number }).n;
    if (danglingPackage > 0) {
      problems.push(`${danglingPackage} edges refer to a package that is not recorded for the generation`);
    }
    const inconsistent = (r.stmt("SELECT COUNT(*) AS n FROM graph_edges WHERE generation_id = ? AND ((resolution = 'resolved' AND dst_kind NOT IN ('file','symbol','package')) OR (resolution IN ('unresolved','ambiguous','dynamic') AND dst_kind NOT IN ('unknown')) OR (resolution = 'external' AND dst_kind != 'external'))").get(g) as { n: number }).n;
    if (inconsistent > 0) {
      problems.push(`${inconsistent} edges have a destination kind that contradicts their resolution`);
    }
    // completeness: one module edge per syntactic reference of the generation, none missing and none invented
    const refs = count("SELECT COUNT(*) AS n FROM applicable_facts af JOIN syntax_refs sr ON sr.content_hash = af.content_hash AND sr.extractor_id = af.extractor_id AND sr.extractor_version = af.extractor_version WHERE af.generation_id = ? AND ? IS NOT NULL");
    const moduleEdges = (r.stmt("SELECT COUNT(*) AS n FROM graph_edges WHERE generation_id = ? AND family = 'module' AND edge_kind IN ('IMPORTS','RE_EXPORTS')").get(g) as { n: number }).n;
    if (refs !== moduleEdges) {
      problems.push(`module edges (${moduleEdges}) do not match the syntactic references of the generation (${refs})`);
    }
    const unknownKinds = (r.stmt("SELECT COUNT(*) AS n FROM graph_edges WHERE generation_id = ? AND edge_kind IN ('CONTAINS','DEFINES','EXPORTS','CALLS')").get(g) as { n: number }).n;
    if (unknownKinds > 0) {
      problems.push(`${unknownKinds} edges have a kind this build never produces`);
    }
    return { generationId: g, ok: problems.length === 0, problems, checked: { edges: total.n, references: refs } };
  });
}
