import type Database from "better-sqlite3";
import { loadResolverConfig } from "./moduleEdges.js";
import { RESOLVER_VERSION, resolveModule, type ResolvedModule } from "./moduleResolver.js";
import type { ExportFact, ImportedName } from "./extractor.js";

/**
 * Builds the path-dependent part of the graph for a BUILDING generation. Everything content-derived (symbols, exports, relations,
 * references) comes from facts; this step only resolves them against THIS snapshot's paths and configuration:
 *   module edges      file -> file | external | unresolved   (IMPORTS, RE_EXPORTS) - the 2A module relationships
 *   binding edges     file -> exported symbol                 (IMPORTS), following re-export chains with cycle detection
 *   REFERENCES        symbol -> imported target               labelled `syntactic_only`: a name matched an import binding; scope and
 *                                                              shadowing are only partially analysed and NO call target is ever inferred
 *   EXTENDS/IMPLEMENTS symbol -> symbol                       from heritage clauses, resolved through same-file declarations and import bindings
 *   DEPENDS_ON        package -> package | external           aggregated from the resolved module edges
 * Anything that cannot be decided is stored as unresolved / ambiguous / dynamic with a reason; absence of an edge never means "no dependency".
 */
const PATH_PAGE = 500;
const EDGE_BATCH = 5000;
const MAX_REEXPORT_DEPTH = 16;
const MECHANISM = "tree_sitter_syntax";

type Resolution = "resolved" | "external" | "unresolved" | "ambiguous" | "dynamic" | "syntactic_only";
type EdgeKind = "IMPORTS" | "RE_EXPORTS" | "REFERENCES" | "EXTENDS" | "IMPLEMENTS" | "DEPENDS_ON";

type Target =
  | { kind: "symbol"; path: string; symbolKey: string; resolution: "resolved"; reason: string }
  | { kind: "file"; path: string; resolution: "resolved"; reason: string }
  | { kind: "external"; name: string; resolution: "external"; reason: string }
  | { kind: "unknown"; name: string | null; resolution: "unresolved" | "ambiguous" | "dynamic"; reason: string };

interface ExportRow {
  kind: ExportFact["kind"];
  exportName: string | null;
  localName: string | null;
  symbolLocalId: number | null;
  source: string | null;
}

interface RefRow {
  kind: "import" | "export_from" | "require" | "dynamic_import";
  target: string | null;
  names: ImportedName[] | null;
  line: number;
}

interface FileInfo {
  hasCode: boolean;
  symbolKeys: string[];
  symbolKinds: string[];
  /** Top-level (module-owned) declared names -> local ids. */
  topLevel: Map<string, number[]>;
  exports: ExportRow[];
  byExportName: Map<string, ExportRow[]>;
  refs: RefRow[];
  /** local binding name -> where it came from. */
  bindings: Map<string, { spec: string | null; imported: string }>;
  relations: Array<{ symbolLocalId: number; relation: "extends" | "implements"; target: string | null; line: number }>;
  symbolRefs: Array<{ symbolLocalId: number; name: string; line: number }>;
}

const emptyInfo = (): FileInfo => ({
  hasCode: false, symbolKeys: [], symbolKinds: [], topLevel: new Map(), exports: [], byExportName: new Map(), refs: [], bindings: new Map(), relations: [], symbolRefs: []
});

export interface GraphBuildStats {
  edges: number;
  byKind: Record<string, number>;
  byResolution: Record<string, number>;
  packages: number;
  /** Measured wall time of each build phase in milliseconds. */
  phasesMs: { config: number; load: number; moduleEdges: number; symbolEdges: number; packageEdges: number };
  /** Set when unchanged files' edges were carried over from the previous generation instead of recomputed (the result is identical to a clean build). */
  reused: { fromGeneration: number; changedFiles: number } | null;
}

type Lookup =
  | { res: "resolved"; path: string; symbolKey: string | null; reason: string }
  | { res: "ambiguous"; reason: string }
  | { res: "unresolved"; reason: string }
  | { res: "external"; name: string; reason: string };

function packageNameOf(specifier: string, reason: string): string {
  if (reason.startsWith("package:")) {
    return reason.slice("package:".length);
  }
  return specifier.startsWith("node:") ? specifier : `node:${specifier}`;
}

class EdgeSink {
  readonly byKind: Record<string, number> = {};
  readonly byResolution: Record<string, number> = {};
  total = 0;
  private batch: unknown[][] = [];
  private readonly insert: Database.Statement;

  constructor(private readonly db: Database.Database, private readonly generationId: number, table = "graph_edges", startId = 0) {
    this.total = startId;
    this.insert = db.prepare(
      `INSERT INTO ${table} (generation_id, edge_id, family, edge_kind, import_style, ordinal, src_kind, src_path, src_symbol,
         dst_kind, dst_path, dst_symbol, dst_name, dst_package, mechanism, resolution, reason, start_line, end_line, extractor, detail)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );
  }

  add(edge: {
    family: "module" | "symbol" | "package"; kind: EdgeKind; style?: RefRow["kind"]; ordinal: number;
    src: { kind: "package" | "file" | "symbol"; path: string; symbol?: string };
    dst: { kind: "package" | "file" | "symbol" | "external" | "unknown"; path?: string | null; symbol?: string; name?: string | null; package?: string };
    resolution: Resolution; reason: string; line?: number; detail?: Record<string, unknown>;
  }): void {
    this.batch.push([
      this.generationId, this.total, edge.family, edge.kind, edge.style ?? null, edge.ordinal, edge.src.kind, edge.src.path, edge.src.symbol ?? null,
      edge.dst.kind, edge.dst.path ?? null, edge.dst.symbol ?? null, edge.dst.name ?? null, edge.dst.package ?? null, MECHANISM, edge.resolution, edge.reason,
      edge.line ?? null, edge.line ?? null, `graph:${RESOLVER_VERSION}`, edge.detail === undefined ? null : JSON.stringify(edge.detail)
    ]);
    this.total += 1;
    this.byKind[edge.kind] = (this.byKind[edge.kind] ?? 0) + 1;
    this.byResolution[edge.resolution] = (this.byResolution[edge.resolution] ?? 0) + 1;
    if (this.batch.length >= EDGE_BATCH) {
      this.flush();
    }
  }

  flush(): void {
    if (this.batch.length === 0) {
      return;
    }
    const rows = this.batch;
    this.batch = [];
    this.db.transaction(() => {
      for (const row of rows) {
        this.insert.run(...row);
      }
    }).immediate();
  }
}

function loadInfos(db: Database.Database, generationId: number, paths: readonly string[]): Map<string, FileInfo> {
  const infos = new Map<string, FileInfo>();
  const get = (path: string): FileInfo => {
    let info = infos.get(path);
    if (info === undefined) {
      info = emptyInfo();
      infos.set(path, info);
    }
    return info;
  };
  const symbols = db.prepare(
    `SELECT af.path AS path, s.local_id AS id, s.kind AS kind, s.name AS name, s.parent_local_id AS parent, s.symbol_key AS key
     FROM applicable_facts af JOIN symbols s ON s.content_hash = af.content_hash AND s.extractor_id = af.extractor_id AND s.extractor_version = af.extractor_version
     WHERE af.generation_id = ? AND af.extractor_id LIKE 'code:%' AND af.path >= ? AND af.path <= ? ORDER BY af.path, s.local_id`
  );
  const exportsStmt = db.prepare(
    `SELECT af.path AS path, e.export_kind AS kind, e.export_name AS exportName, e.local_name AS localName, e.symbol_local_id AS symbolLocalId, e.source_text AS source
     FROM applicable_facts af JOIN exports e ON e.content_hash = af.content_hash AND e.extractor_id = af.extractor_id AND e.extractor_version = af.extractor_version
     WHERE af.generation_id = ? AND af.path >= ? AND af.path <= ? ORDER BY af.path, e.local_id`
  );
  const refs = db.prepare(
    `SELECT af.path AS path, sr.ref_kind AS kind, sr.target_text AS target, sr.names_json AS names, sr.line AS line
     FROM applicable_facts af JOIN syntax_refs sr ON sr.content_hash = af.content_hash AND sr.extractor_id = af.extractor_id AND sr.extractor_version = af.extractor_version
     WHERE af.generation_id = ? AND af.path >= ? AND af.path <= ? ORDER BY af.path, sr.extractor_id, sr.local_id`
  );
  const relations = db.prepare(
    `SELECT af.path AS path, r.symbol_local_id AS symbolLocalId, r.relation AS relation, r.target_text AS target, r.line AS line
     FROM applicable_facts af JOIN symbol_relations r ON r.content_hash = af.content_hash AND r.extractor_id = af.extractor_id AND r.extractor_version = af.extractor_version
     WHERE af.generation_id = ? AND af.path >= ? AND af.path <= ? ORDER BY af.path, r.local_id`
  );
  const symbolRefs = db.prepare(
    `SELECT af.path AS path, r.symbol_local_id AS symbolLocalId, r.name AS name, r.line AS line
     FROM applicable_facts af JOIN symbol_refs r ON r.content_hash = af.content_hash AND r.extractor_id = af.extractor_id AND r.extractor_version = af.extractor_version
     WHERE af.generation_id = ? AND af.path >= ? AND af.path <= ? ORDER BY af.path, r.local_id`
  );
  for (let i = 0; i < paths.length; i += PATH_PAGE) {
    const from = paths[i]!;
    const to = paths[Math.min(i + PATH_PAGE, paths.length) - 1]!;
    for (const r of symbols.all(generationId, from, to) as Array<{ path: string; id: number; kind: string; name: string; parent: number | null; key: string }>) {
      const info = get(r.path);
      info.hasCode = true;
      info.symbolKeys[r.id] = r.key;
      info.symbolKinds[r.id] = r.kind;
      if (r.parent === 0) {
        const list = info.topLevel.get(r.name);
        if (list === undefined) {
          info.topLevel.set(r.name, [r.id]);
        } else {
          list.push(r.id);
        }
      }
    }
    for (const r of exportsStmt.all(generationId, from, to) as Array<{ path: string } & ExportRow>) {
      const info = get(r.path);
      const row: ExportRow = { kind: r.kind, exportName: r.exportName, localName: r.localName, symbolLocalId: r.symbolLocalId, source: r.source };
      info.exports.push(row);
      const key = r.kind === "default" ? "default" : r.exportName;
      if (key !== null) {
        const list = info.byExportName.get(key);
        if (list === undefined) {
          info.byExportName.set(key, [row]);
        } else {
          list.push(row);
        }
      }
    }
    for (const r of refs.all(generationId, from, to) as Array<{ path: string; kind: RefRow["kind"]; target: string | null; names: string | null; line: number }>) {
      const info = get(r.path);
      const names = r.names === null ? null : (JSON.parse(r.names) as ImportedName[]);
      info.refs.push({ kind: r.kind, target: r.target, names, line: r.line });
      if ((r.kind === "import" || r.kind === "require") && names !== null) {
        for (const n of names) {
          if (!info.bindings.has(n.local)) {
            info.bindings.set(n.local, { spec: r.target, imported: n.imported });
          }
        }
      }
    }
    for (const r of relations.all(generationId, from, to) as Array<{ path: string; symbolLocalId: number; relation: "extends" | "implements"; target: string | null; line: number }>) {
      get(r.path).relations.push({ symbolLocalId: r.symbolLocalId, relation: r.relation, target: r.target, line: r.line });
    }
    for (const r of symbolRefs.all(generationId, from, to) as Array<{ path: string; symbolLocalId: number; name: string; line: number }>) {
      get(r.path).symbolRefs.push({ symbolLocalId: r.symbolLocalId, name: r.name, line: r.line });
    }
  }
  return infos;
}

/** What OTHER files' edges can depend on in a file: its declared symbols, exports, import bindings and import specifiers. Line numbers and own-only facts (heritage, references) are not part of it. */
function surfaceOf(info: FileInfo): string {
  return JSON.stringify([info.hasCode, info.symbolKeys, [...info.topLevel.entries()], info.exports, [...info.bindings.entries()], info.refs.map((r) => [r.kind, r.target, r.names])]);
}

const MAX_REUSE_CHANGED = 200;

/**
 * Unchanged files' edges can be carried over from the previous generation only when nothing that could change them changed: same resolver and extractors, the SAME set of paths
 * (an added or deleted file can resolve other files' specifiers differently), only code files modified (a config file may alter resolution), and every modified file keeps the surface other files
 * can see. Anything else, or any doubt, is a full rebuild. Returns the modified paths, or null.
 */
function planReuse(db: Database.Database, generationId: number, previousId: number | null, manifest: Array<{ path: string; contentHash: string }>, infos: Map<string, FileInfo>): { previousId: number; changed: string[] } | null {
  if (previousId === null) {
    return null;
  }
  const gens = db.prepare("SELECT id, resolver_version AS r, extractor_set_hash AS e FROM generations WHERE id IN (?, ?)").all(generationId, previousId) as Array<{ id: number; r: string | null; e: string }>;
  const now = gens.find((g) => g.id === generationId);
  const prev = gens.find((g) => g.id === previousId);
  if (now === undefined || prev === undefined || now.r !== prev.r || now.e !== prev.e) {
    return null;
  }
  const hasEdges = db.prepare("SELECT 1 FROM graph_edges WHERE generation_id = ? LIMIT 1").get(previousId) !== undefined;
  const prevManifest = db.prepare("SELECT path, content_hash AS h FROM generation_files WHERE generation_id = ? AND content_hash IS NOT NULL").all(previousId) as Array<{ path: string; h: string }>;
  if (!hasEdges || prevManifest.length !== manifest.length) {
    return null;
  }
  const before = new Map(prevManifest.map((r) => [r.path, r.h]));
  const changed: string[] = [];
  for (const m of manifest) {
    const old = before.get(m.path);
    if (old === undefined) {
      return null; // a path appeared or disappeared
    }
    if (old !== m.contentHash) {
      changed.push(m.path);
      if (changed.length > MAX_REUSE_CHANGED) {
        return null;
      }
    }
  }
  for (const path of changed) {
    const fresh = infos.get(path);
    const old = loadInfos(db, previousId, [path]).get(path);
    if (fresh === undefined || old === undefined || !fresh.hasCode || !old.hasCode || surfaceOf(fresh) !== surfaceOf(old)) {
      return null;
    }
  }
  return { previousId, changed };
}

export function buildGraphEdges(db: Database.Database, generationId: number, root: string, previousGenerationId: number | null = null): GraphBuildStats {
  const t0 = performance.now();
  const manifest = db
    .prepare("SELECT path, content_hash AS contentHash FROM generation_files WHERE generation_id = ? AND content_hash IS NOT NULL ORDER BY path")
    .all(generationId) as Array<{ path: string; contentHash: string }>;
  const paths = manifest.map((m) => m.path);
  const config = loadResolverConfig(root, manifest);
  const t1 = performance.now();
  const infos = loadInfos(db, generationId, paths);
  const t2 = performance.now();
  const reuse = planReuse(db, generationId, previousGenerationId, manifest, infos);
  const stageDdl = "CREATE TEMP TABLE IF NOT EXISTS graph_edge_stage AS SELECT * FROM graph_edges WHERE 0";
  if (reuse !== null) {
    db.exec(stageDdl);
    db.exec("DELETE FROM graph_edge_stage");
  }
  const sink = new EdgeSink(db, generationId, reuse === null ? "graph_edges" : "graph_edge_stage");
  /** The files whose edges are computed now: all of them, or only the modified ones when the rest are carried over. */
  const work = reuse === null ? paths : reuse.changed;

  // ---- packages ----
  const packageDirs = [{ dir: "", name: "<repository>" }, ...config.packages.map((p) => ({ dir: p.dir, name: p.name }))];
  const byLength = [...config.packages].sort((a, b) => b.dir.length - a.dir.length);
  const packageOf = (path: string): string => byLength.find((p) => p.dir !== "" && path.startsWith(`${p.dir}/`))?.dir ?? "";
  const insertPackage = db.prepare("INSERT OR IGNORE INTO graph_packages (generation_id, dir, name) VALUES (?, ?, ?)");
  db.transaction(() => packageDirs.forEach((p) => insertPackage.run(generationId, p.dir, p.name))).immediate();

  // ---- pass 1: module edges (resolutions) ----
  const resolutions = new Map<string, ResolvedModule>();
  const resolutionKey = (path: string, spec: string): string => `${path}\0${spec}`;
  const packageDeps = new Map<string, { src: string; dstKind: "package" | "external"; dst: string; count: number }>();
  for (const path of work) {
    const info = infos.get(path);
    if (info === undefined) {
      continue;
    }
    let ordinal = 0;
    for (const ref of info.refs) {
      const resolved = resolveModule(path, ref.target, config);
      if (ref.target !== null) {
        resolutions.set(resolutionKey(path, ref.target), resolved);
      }
      const dstKind = resolved.resolution === "resolved" ? "file" : resolved.resolution === "external" ? "external" : "unknown";
      sink.add({
        family: "module", kind: ref.kind === "export_from" ? "RE_EXPORTS" : "IMPORTS", style: ref.kind, ordinal,
        src: { kind: "file", path }, dst: { kind: dstKind, path: resolved.resolvedPath, name: ref.target, ...(dstKind === "external" && ref.target !== null ? { package: packageNameOf(ref.target, resolved.reason) } : {}) },
        resolution: resolved.resolution, reason: resolved.reason, line: ref.line,
        ...(resolved.resolution === "external" && ref.target !== null ? { detail: { package: packageNameOf(ref.target, resolved.reason) } } : {})
      });
      ordinal += 1;
      const srcPackage = packageOf(path);
      if (resolved.resolution === "resolved" && resolved.resolvedPath !== null) {
        const dstPackage = packageOf(resolved.resolvedPath);
        if (dstPackage !== srcPackage) {
          const key = `${srcPackage}\0p\0${dstPackage}`;
          const entry = packageDeps.get(key);
          packageDeps.set(key, entry === undefined ? { src: srcPackage, dstKind: "package", dst: dstPackage, count: 1 } : { ...entry, count: entry.count + 1 });
        }
      } else if (resolved.resolution === "external" && ref.target !== null) {
        const name = packageNameOf(ref.target, resolved.reason);
        const key = `${srcPackage}\0e\0${name}`;
        const entry = packageDeps.get(key);
        packageDeps.set(key, entry === undefined ? { src: srcPackage, dstKind: "external", dst: name, count: 1 } : { ...entry, count: entry.count + 1 });
      }
    }
  }

  const t3 = performance.now();
  // ---- export lookup (follows re-exports; cycle- and depth-bounded) ----
  const resolveSpec = (from: string, spec: string | null): ResolvedModule | undefined => {
    if (spec === null) {
      return undefined;
    }
    const key = resolutionKey(from, spec);
    let found = resolutions.get(key);
    if (found === undefined) {
      found = resolveModule(from, spec, config); // computed on demand (identical to the value pass 1 would have stored)
      resolutions.set(key, found);
    }
    return found;
  };
  const moduleTarget = (path: string, reason: string): Lookup => ({ res: "resolved", path, symbolKey: null, reason });

  /** Complete (depth 0) lookups are memoised per generation; inner results depend on the resolve set, so they are not. */
  const exportMemo = new Map<string, Lookup>();

  function lookupExport(path: string, name: string, visited: Set<string>, depth: number): Lookup {
    if (depth !== 0) {
      return lookupExportUncached(path, name, visited, depth);
    }
    const key = `${path}\0${name}`;
    let result = exportMemo.get(key);
    if (result === undefined) {
      result = lookupExportUncached(path, name, visited, depth);
      exportMemo.set(key, result);
    }
    return result;
  }

  /**
   * `visited` is ONE resolve set shared by the whole lookup (as in the ES ResolveExport algorithm): each (module, name) pair is
   * explored at most once, so a diamond of `export *` chains costs O(edges) instead of one walk per path.
   */
  function lookupExportUncached(path: string, name: string, visited: Set<string>, depth: number): Lookup {
    const info = infos.get(path);
    if (info === undefined || !info.hasCode) {
      return config.files.has(path) ? moduleTarget(path, "non_code_module") : { res: "unresolved", reason: "target_not_indexed" };
    }
    const visitKey = `${path}\0${name}`;
    if (visited.has(visitKey) || depth > MAX_REEXPORT_DEPTH) {
      return { res: "unresolved", reason: "cyclic_or_too_deep_reexport" };
    }
    const seen = visited.add(visitKey);
    const found: Lookup[] = [];
    for (const row of info.byExportName.get(name) ?? []) {
      if ((row.kind === "named" || row.kind === "default") && row.symbolLocalId !== null && info.symbolKeys[row.symbolLocalId] !== undefined) {
        found.push({ res: "resolved", path, symbolKey: info.symbolKeys[row.symbolLocalId]!, reason: "declared_export" });
      } else if ((row.kind === "named" || row.kind === "default") && row.localName !== null) {
        const binding = info.bindings.get(row.localName);
        found.push(binding === undefined ? { res: "unresolved", reason: "export_of_unknown_local" } : followBinding(path, binding.spec, binding.imported, seen, depth + 1));
      } else if (row.kind === "default") {
        found.push(moduleTarget(path, "default_export_expression"));
      } else if (row.kind === "reexport") {
        found.push(followBinding(path, row.source, row.localName ?? name, seen, depth + 1));
      } else if (row.kind === "reexport_namespace") {
        const r = resolveSpec(path, row.source);
        found.push(r?.resolution === "resolved" && r.resolvedPath !== null ? moduleTarget(r.resolvedPath, "namespace_reexport") : { res: "unresolved", reason: r?.reason ?? "reexport_source_unresolved" });
      } else if (row.kind === "commonjs") {
        const local = row.localName === null ? undefined : info.topLevel.get(row.localName);
        found.push(local !== undefined && local.length === 1 && info.symbolKeys[local[0]!] !== undefined
          ? { res: "resolved", path, symbolKey: info.symbolKeys[local[0]!]!, reason: "commonjs_export" }
          : moduleTarget(path, "commonjs_export"));
      }
    }
    if (found.length === 0 && name === "default") {
      const whole = info.byExportName.get("module.exports") ?? info.byExportName.get("export=");
      if (whole !== undefined) {
        found.push(moduleTarget(path, "commonjs_default"));
      }
    }
    if (found.length === 0 && name !== "default") {
      let undecidable = false;
      for (const star of info.exports.filter((e) => e.kind === "reexport_all")) {
        const r = resolveSpec(path, star.source);
        if (r?.resolution === "resolved" && r.resolvedPath !== null) {
          const result = lookupExport(r.resolvedPath, name, seen, depth + 1);
          if (result.res === "resolved" || result.res === "ambiguous" || result.res === "external") {
            found.push(result);
          } else if (result.reason === "star_reexport_undecidable") {
            undecidable = true;
          }
        } else {
          undecidable = true; // an external, unresolved or dynamic `export *` could supply the name: we cannot say it does not
        }
      }
      if (undecidable) {
        return found.length === 0 ? { res: "unresolved", reason: "star_reexport_undecidable" } : { res: "ambiguous", reason: "star_reexport_undecidable" };
      }
    }
    return combine(found);
  }

  function combine(found: Lookup[]): Lookup {
    const good = found.filter((f) => f.res === "resolved" || f.res === "external");
    if (good.length === 0) {
      return found.find((f) => f.res === "ambiguous") ?? found[0] ?? { res: "unresolved", reason: "export_not_found" };
    }
    const distinct = new Set(good.map((g) => (g.res === "resolved" ? `${g.path}#${g.symbolKey ?? ""}` : `ext:${g.name}`)));
    return distinct.size === 1 ? good[0]! : { res: "ambiguous", reason: `multiple_exports:${[...distinct].sort().join(",")}` };
  }

  function followBinding(from: string, spec: string | null, imported: string, visited: Set<string>, depth: number): Lookup {
    const r = resolveSpec(from, spec);
    if (r === undefined) {
      return { res: "unresolved", reason: spec === null ? "non_literal_specifier" : "specifier_not_resolved" };
    }
    if (r.resolution === "external") {
      return { res: "external", name: packageNameOf(spec ?? "", r.reason), reason: r.reason };
    }
    if (r.resolution !== "resolved" || r.resolvedPath === null) {
      return { res: r.resolution === "ambiguous" ? "ambiguous" : "unresolved", reason: r.reason };
    }
    return imported === "*" || imported === "=" ? moduleTarget(r.resolvedPath, "module_object") : lookupExport(r.resolvedPath, imported, visited, depth);
  }

  const toTarget = (lookup: Lookup, spec: string | null): Target => {
    switch (lookup.res) {
      case "resolved":
        return lookup.symbolKey === null
          ? { kind: "file", path: lookup.path, resolution: "resolved", reason: lookup.reason }
          : { kind: "symbol", path: lookup.path, symbolKey: lookup.symbolKey, resolution: "resolved", reason: lookup.reason };
      case "external":
        return { kind: "external", name: lookup.name, resolution: "external", reason: lookup.reason };
      case "ambiguous":
        return { kind: "unknown", name: spec, resolution: "ambiguous", reason: lookup.reason };
      default:
        return { kind: "unknown", name: spec, resolution: "unresolved", reason: lookup.reason };
    }
  };

  const bindingMemo = new Map<string, Target | undefined>();
  const bindingTarget = (path: string, local: string, info: FileInfo): Target | undefined => {
    const key = `${path}\0${local}`;
    if (bindingMemo.has(key)) {
      return bindingMemo.get(key);
    }
    const binding = info.bindings.get(local);
    const target = binding === undefined ? undefined : toTarget(followBinding(path, binding.spec, binding.imported, new Set(), 0), binding.spec);
    bindingMemo.set(key, target);
    return target;
  };

  const dstOf = (t: Target): { kind: "file" | "symbol" | "external" | "unknown"; path?: string; symbol?: string; name?: string | null; package?: string } =>
    t.kind === "symbol" ? { kind: "symbol", path: t.path, symbol: t.symbolKey } : t.kind === "file" ? { kind: "file", path: t.path }
      : t.kind === "external" ? { kind: "external", name: t.name, package: t.name } : { kind: "unknown", name: t.name };

  // ---- pass 2: symbol-level edges ----
  for (const path of work) {
    const info = infos.get(path);
    if (info === undefined || !info.hasCode) {
      continue;
    }
    let ordinal = 0;
    const owner = (localId: number): { kind: "file" | "symbol"; path: string; symbol?: string } | undefined =>
      localId === 0 ? { kind: "file", path } : info.symbolKeys[localId] === undefined ? undefined : { kind: "symbol", path, symbol: info.symbolKeys[localId]! };

    // import bindings: file -> the symbol (or module) each local name resolves to
    for (const ref of info.refs) {
      if ((ref.kind !== "import" && ref.kind !== "require") || ref.names === null) {
        continue;
      }
      for (const n of ref.names) {
        if (n.imported === "*" || n.imported === "=") {
          continue; // the module-level edge already states this dependency
        }
        const target = toTarget(followBinding(path, ref.target, n.imported, new Set(), 0), ref.target);
        if (target.kind === "external") {
          continue;
        }
        sink.add({
          family: "symbol", kind: "IMPORTS", style: ref.kind, ordinal, src: { kind: "file", path }, dst: dstOf(target),
          resolution: target.resolution, reason: target.reason, line: ref.line, detail: { imported: n.imported, local: n.local }
        });
        ordinal += 1;
      }
    }

    // heritage: EXTENDS / IMPLEMENTS
    for (const rel of info.relations) {
      const src = owner(rel.symbolLocalId);
      if (src === undefined || src.kind !== "symbol") {
        continue;
      }
      const target = heritageTarget(path, info, rel.target);
      sink.add({
        family: "symbol", kind: rel.relation === "extends" ? "EXTENDS" : "IMPLEMENTS", ordinal, src, dst: dstOf(target),
        resolution: target.resolution, reason: target.reason, line: rel.line, detail: { written: rel.target }
      });
      ordinal += 1;
    }

    // references to import-bound names (syntactic only)
    for (const ref of info.symbolRefs) {
      const src = owner(ref.symbolLocalId);
      const target = bindingTarget(path, ref.name, info);
      if (src === undefined || target === undefined) {
        continue;
      }
      sink.add({
        family: "symbol", kind: "REFERENCES", ordinal, src, dst: dstOf(target), resolution: "syntactic_only", reason: "name_matches_import_binding",
        line: ref.line, detail: { name: ref.name, binding: target.resolution, binding_reason: target.reason }
      });
      ordinal += 1;
    }
  }

  const t4 = performance.now();

  function heritageTarget(path: string, info: FileInfo, written: string | null): Target {
    if (written === null) {
      return { kind: "unknown", name: null, resolution: "unresolved", reason: "non_identifier_expression" };
    }
    const parts = written.split(".");
    const head = parts[0]!;
    if (parts.length > 1) {
      const binding = info.bindings.get(head);
      if (binding !== undefined && (binding.imported === "*" || binding.imported === "=") && parts.length === 2) {
        const module = followBinding(path, binding.spec, "*", new Set(), 0);
        if (module.res === "resolved") {
          return toTarget(lookupExport(module.path, parts[1]!, new Set(), 0), binding.spec);
        }
        return toTarget(module, binding.spec);
      }
      return { kind: "unknown", name: written, resolution: "unresolved", reason: "qualified_name_not_resolvable" };
    }
    const declared = (info.topLevel.get(head) ?? []).filter((id) => ["class", "interface", "type", "enum"].includes(info.symbolKinds[id] ?? ""));
    if (declared.length === 1) {
      return { kind: "symbol", path, symbolKey: info.symbolKeys[declared[0]!]!, resolution: "resolved", reason: "declared_in_same_file" };
    }
    if (declared.length > 1) {
      return { kind: "unknown", name: written, resolution: "ambiguous", reason: "multiple_declarations_in_file" };
    }
    return bindingTarget(path, head, info) ?? { kind: "unknown", name: written, resolution: "unresolved", reason: "not_declared_in_file_or_imports" };
  }

  // ---- package-level DEPENDS_ON (aggregated; deterministic order) ----
  let packageSink = sink;
  let reusedFrom: GraphBuildStats["reused"] = null;
  if (reuse !== null) {
    sink.flush();
    reusedFrom = { fromGeneration: reuse.previousId, changedFiles: reuse.changed.length };
    // renumber into the final table in exactly the order a clean build writes: module edges by path, then symbol edges by path, then (below) package edges
    db.transaction(() => {
      db.exec("CREATE TEMP TABLE IF NOT EXISTS graph_changed (path TEXT PRIMARY KEY) WITHOUT ROWID");
      db.exec("DELETE FROM graph_changed");
      const addChanged = db.prepare("INSERT INTO graph_changed (path) VALUES (?)");
      reuse.changed.forEach((p) => addChanged.run(p));
      const cols = "family, edge_kind, import_style, ordinal, src_kind, src_path, src_symbol, dst_kind, dst_path, dst_symbol, dst_name, dst_package, mechanism, resolution, reason, start_line, end_line, extractor, detail";
      db.prepare(
        `INSERT INTO graph_edges (generation_id, edge_id, ${cols})
         SELECT ?, ROW_NUMBER() OVER (ORDER BY CASE family WHEN 'module' THEN 1 ELSE 2 END, src_path, ordinal) - 1, ${cols}
         FROM (SELECT ${cols} FROM graph_edge_stage
               UNION ALL
               SELECT ${cols} FROM graph_edges WHERE generation_id = ? AND family IN ('module', 'symbol') AND src_path NOT IN (SELECT path FROM graph_changed))`
      ).run(generationId, reuse.previousId);
    }).immediate();
    db.exec("DELETE FROM graph_edge_stage");
    // package dependencies are aggregated from the final module edges (carried and recomputed alike); pass 1 only saw the modified files
    packageDeps.clear();
    for (const e of db.prepare("SELECT src_path AS src, resolution, dst_path AS dst, dst_package AS pkg FROM graph_edges WHERE generation_id = ? AND family = 'module' AND resolution IN ('resolved', 'external')").iterate(generationId) as Iterable<{ src: string; resolution: string; dst: string | null; pkg: string | null }>) {
      const srcPackage = packageOf(e.src);
      if (e.resolution === "resolved" && e.dst !== null) {
        const dstPackage = packageOf(e.dst);
        if (dstPackage !== srcPackage) {
          const key = `${srcPackage}\0p\0${dstPackage}`;
          const entry = packageDeps.get(key);
          packageDeps.set(key, entry === undefined ? { src: srcPackage, dstKind: "package", dst: dstPackage, count: 1 } : { ...entry, count: entry.count + 1 });
        }
      } else if (e.resolution === "external" && e.pkg !== null) {
        const key = `${srcPackage}\0e\0${e.pkg}`;
        const entry = packageDeps.get(key);
        packageDeps.set(key, entry === undefined ? { src: srcPackage, dstKind: "external", dst: e.pkg, count: 1 } : { ...entry, count: entry.count + 1 });
      }
    }
    const existing = (db.prepare("SELECT COUNT(*) AS n FROM graph_edges WHERE generation_id = ?").get(generationId) as { n: number }).n;
    packageSink = new EdgeSink(db, generationId, "graph_edges", existing);
  }
  let packageOrdinal = 0;
  for (const dep of [...packageDeps.values()].sort((a, b) => (`${a.src}\0${a.dstKind}\0${a.dst}` < `${b.src}\0${b.dstKind}\0${b.dst}` ? -1 : 1))) {
    packageSink.add({
      family: "package", kind: "DEPENDS_ON", ordinal: packageOrdinal, src: { kind: "package", path: dep.src },
      dst: dep.dstKind === "package" ? { kind: "package", path: dep.dst } : { kind: "external", name: dep.dst, package: dep.dst },
      resolution: dep.dstKind === "package" ? "resolved" : "external", reason: "aggregated_from_imports", detail: { imports: dep.count }
    });
    packageOrdinal += 1;
  }
  packageSink.flush();
  sink.flush();
  const t5 = performance.now();
  const round = (n: number): number => Math.round(n);
  const tally = reusedFrom === null ? { edges: sink.total, byKind: sink.byKind, byResolution: sink.byResolution } : tallyEdges(db, generationId);
  return {
    edges: tally.edges, byKind: tally.byKind, byResolution: tally.byResolution, packages: packageDirs.length, reused: reusedFrom,
    phasesMs: { config: round(t1 - t0), load: round(t2 - t1), moduleEdges: round(t3 - t2), symbolEdges: round(t4 - t3), packageEdges: round(t5 - t4) }
  };
}

function tallyEdges(db: Database.Database, generationId: number): { edges: number; byKind: Record<string, number>; byResolution: Record<string, number> } {
  const byKind: Record<string, number> = {};
  const byResolution: Record<string, number> = {};
  let edges = 0;
  for (const r of db.prepare("SELECT edge_kind AS k, resolution AS r, COUNT(*) AS n FROM graph_edges WHERE generation_id = ? GROUP BY edge_kind, resolution").all(generationId) as Array<{ k: string; r: string; n: number }>) {
    byKind[r.k] = (byKind[r.k] ?? 0) + r.n;
    byResolution[r.r] = (byResolution[r.r] ?? 0) + r.n;
    edges += r.n;
  }
  return { edges, byKind, byResolution };
}
