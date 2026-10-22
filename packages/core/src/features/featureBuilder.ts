import { createHash } from "node:crypto";
import type Database from "better-sqlite3";
import { findTestsFor, TEST_PATH } from "../testDiscovery.js";
import { joinPaths, normalizePath } from "./detectors.js";

/**
 * Builds the feature graph of ONE generation from the content-derived detections (`fact_entities`) plus the source graph (symbols, resolved imports, packages).
 * Deterministic and syntactic: certainty is carried on every entity and edge; a dynamic path or name stays explicitly unknown and becomes a coverage gap; a link is
 * `resolved` only when the evidence supports exactly that claim (otherwise `ambiguous` or `heuristic`). Every limit that drops something records a gap.
 */
export const FEATURE_LIMITS = { entities: 100_000, edges: 400_000, flowHops: 4, flowMembers: 120, flowFanout: 60, uiClientCalls: 25, importDepthFiles: 40, mountDepth: 3, mountsPerRoute: 4, wildcardScan: 500 } as const;

export interface FeatureBuildStats { entities: number; edges: number; gaps: number; features: number; lineage: number; ms: number }

interface Detection {
  path: string; hash: string; role: string; kind: string; key: string | null; name: string; method: string | null; target: string | null;
  dynamic: number; receiver: string | null; handler: string | null; startLine: number; endLine: number; attrs: string | null;
}
interface Entity {
  id: string; kind: string; role: string; key: string | null; name: string; path: string | null; startLine: number | null; endLine: number | null; pkg: string | null;
  mechanism: string; certainty: "static" | "dynamic_unknown" | "heuristic"; trust: "discovered"; hash: string | null; attrs: Record<string, unknown>; handler: string | null; receiver: string | null; validFrom: number;
}
interface Edge { src: string; dst: string; relation: string; certainty: string; mechanism: string; reason: string; path: string | null; line: number | null; attrs?: Record<string, unknown> }
interface Gap { kind: string; entityId: string | null; path: string | null; line: number | null; detail: string }
interface SymbolRange { path: string; qualifiedName: string; kind: string; key: string; startLine: number; endLine: number; exported: boolean; exportName: string | null }
type Range = { path: string; start: number; end: number };

const sha = (text: string): string => createHash("sha256").update(text).digest("hex");
const entityId = (kind: string, identity: string, path: string | null, ordinal: number): string => `${kind}:${sha(`${kind}\0${identity}\0${path ?? ""}\0${ordinal}`).slice(0, 16)}`;
export const symbolNodeId = (path: string, qualifiedName: string): string => `sym:${path}#${qualifiedName}`;
export const fileNodeId = (path: string): string => `file:${path}`;
const lastSegment = (receiver: string | null): string | null => (receiver === null ? null : receiver.split(".").pop()!);
const dirname = (path: string): string => (path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "");

const NEXT_PAGES = /^(?:src\/)?pages\/(.+)\.(?:tsx|jsx|js|ts)$/;
const NEXT_APP_PAGE = /^(?:src\/)?app\/(?:(.+)\/)?page\.(?:tsx|jsx|js|ts)$/;
const NEXT_APP_ROUTE = /^(?:src\/)?app\/(?:(.+)\/)?route\.(?:tsx|jsx|js|ts)$/;
const OPENAPI_YAML = /(^|\/)(openapi|swagger)[^/]*\.ya?ml$/i;
const FORWARD = new Set(["HANDLES_WITH", "RENDERS", "CONSUMES_WITH", "RUNS", "PUBLISHES", "QUERIES", "CALLS_API_FROM_HANDLER", "READS", "WRITES", "EVENT_FLOW", "USES_API_CALL", "CALLS_API"]);
const UPSTREAM = new Set(["CALLS_API", "USES_API_CALL"]);
const ATTACH = new Set(["TESTS", "DOCUMENTS"]);

/** Client path against route path: equal segments, or a `{}` parameter on either side. Returns null for no match, "exact" or "parameter". */
function pathMatch(client: string, route: string): "exact" | "parameter" | null {
  if (client === route) {
    return "exact";
  }
  const a = client.split("/");
  const b = route.split("/");
  if (a.length !== b.length) {
    return null;
  }
  let parameter = false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) {
      if (a[i] === "{}" || b[i] === "{}") {
        parameter = true;
      } else {
        return null;
      }
    }
  }
  return parameter ? "parameter" : "exact";
}

export function buildFeatureGraph(db: Database.Database, generationId: number): FeatureBuildStats {
  const started = Date.now();
  // the predecessor is the previous complete generation ON THE SAME BRANCH: lineage and validity must never mix branches
  const branch = (db.prepare("SELECT branch_label AS b FROM generations WHERE id = ?").get(generationId) as { b: string | null }).b;
  const parentRow = db.prepare("SELECT id FROM generations WHERE status = 'complete' AND id < ? AND branch_label IS ? ORDER BY id DESC LIMIT 1").get(generationId, branch) as { id: number } | undefined;
  const parentId = parentRow?.id ?? null;
  const previousValid = new Map<string, number>();
  if (parentId !== null) {
    for (const row of db.prepare("SELECT entity_id AS id, valid_from_generation AS v FROM feature_entities WHERE generation_id = ?").all(parentId) as Array<{ id: string; v: number }>) {
      previousValid.set(row.id, row.v);
    }
  }
  const packages = (db.prepare("SELECT dir FROM graph_packages WHERE generation_id = ? ORDER BY length(dir) DESC").all(generationId) as Array<{ dir: string }>).map((r) => r.dir);
  const packageOf = (path: string): string => packages.find((d) => d === "" || path === d || path.startsWith(`${d}/`)) ?? "";

  const detections = db.prepare(
    `SELECT af.path AS path, af.content_hash AS hash, fe.role, fe.kind, fe.key, fe.name, fe.method, fe.target,
            fe.dynamic, fe.receiver, fe.handler, fe.start_line AS startLine, fe.end_line AS endLine, fe.attrs_json AS attrs
     FROM applicable_facts af JOIN fact_entities fe ON fe.content_hash = af.content_hash AND fe.extractor_id = af.extractor_id AND fe.extractor_version = af.extractor_version
     WHERE af.generation_id = ? AND af.extractor_id LIKE 'feature:entities:%' ORDER BY af.path, af.extractor_id, fe.local_id`
  ).all(generationId) as Detection[];

  const symbolsByPath = new Map<string, SymbolRange[]>();
  const symbolsOf = (path: string): SymbolRange[] => {
    let list = symbolsByPath.get(path);
    if (list === undefined) {
      list = db.prepare(
        `SELECT path, qualified_name AS qualifiedName, kind, symbol_key AS key, start_line AS startLine, end_line AS endLine, exported, export_name AS exportName
         FROM symbol_occurrences WHERE generation_id = ? AND path = ? AND extractor_id LIKE 'code:%' AND kind != 'module' ORDER BY start_byte`
      ).all(generationId, path).map((r) => ({ ...(r as Omit<SymbolRange, "exported"> & { exported: number }), exported: (r as { exported: number }).exported === 1 })) as SymbolRange[];
      symbolsByPath.set(path, list);
    }
    return list;
  };
  const importStmt = db.prepare(
    "SELECT dst_kind AS dstKind, dst_path AS dstPath, dst_symbol AS dstSymbol, detail FROM graph_edges WHERE generation_id = ? AND family = 'symbol' AND edge_kind = 'IMPORTS' AND src_path = ? AND resolution = 'resolved'"
  );
  const importCache = new Map<string, Map<string, { path: string; symbol: string | null }>>();
  /** Local name bound by an import in `path` -> the file (and symbol) it resolves to; resolved edges only. */
  const importTarget = (path: string, local: string): { path: string; symbol: string | null } | undefined => {
    let map = importCache.get(path);
    if (map === undefined) {
      map = new Map();
      for (const row of importStmt.all(generationId, path) as Array<{ dstKind: string; dstPath: string | null; dstSymbol: string | null; detail: string | null }>) {
        const detail = row.detail === null ? null : (JSON.parse(row.detail) as { local?: string });
        if (detail?.local !== undefined && row.dstPath !== null && (row.dstKind === "symbol" || row.dstKind === "file")) {
          map.set(detail.local, { path: row.dstPath, symbol: row.dstSymbol });
        }
      }
      importCache.set(path, map);
    }
    return map.get(local);
  };
  const symbolByKey = (path: string, key: string): SymbolRange | undefined => symbolsOf(path).find((s) => s.key === key);
  const defaultExportStmt = db.prepare(
    `SELECT ex.local_name AS local FROM applicable_facts af JOIN exports ex ON ex.content_hash = af.content_hash AND ex.extractor_id = af.extractor_id AND ex.extractor_version = af.extractor_version
     WHERE af.generation_id = ? AND af.path = ? AND af.extractor_id LIKE 'code:%' AND ex.export_kind = 'default' LIMIT 1`
  );
  const importedFilesStmt = db.prepare("SELECT DISTINCT dst_path AS p FROM graph_edges WHERE generation_id = ? AND family = 'module' AND edge_kind = 'IMPORTS' AND src_path = ? AND src_kind = 'file' AND resolution = 'resolved' AND dst_kind = 'file' LIMIT ?");

  const entities: Entity[] = [];
  const edges: Edge[] = [];
  const gaps: Gap[] = [];
  const byId = new Map<string, Entity>();
  const ordinals = new Map<string, number>();
  let entityCapHit = false;
  let edgeCapHit = false;
  const addEntity = (e: Omit<Entity, "id" | "validFrom" | "trust"> & { identity: string }): Entity | null => {
    if (entities.length >= FEATURE_LIMITS.entities) {
      entityCapHit = true;
      return null;
    }
    const base = `${e.kind}\0${e.identity}\0${e.path ?? ""}`;
    const ordinal = ordinals.get(base) ?? 0;
    ordinals.set(base, ordinal + 1);
    const id = entityId(e.kind, e.identity, e.path, ordinal);
    const { identity: _identity, ...rest } = e;
    const entity: Entity = { ...rest, id, trust: "discovered", validFrom: previousValid.get(id) ?? generationId };
    entities.push(entity);
    byId.set(id, entity);
    return entity;
  };
  const addEdge = (e: Edge): void => {
    if (edges.length < FEATURE_LIMITS.edges) {
      edges.push(e);
    } else {
      edgeCapHit = true;
    }
  };
  const addGap = (g: Gap): void => void gaps.push(g);
  const attrsOf = (d: Detection): Record<string, unknown> => (d.attrs === null ? {} : (JSON.parse(d.attrs) as Record<string, unknown>));

  // ---- mounts: which prefix a router object is served under (static literals; only the router actually mounted receives it) ----
  const routerReceiversByPath = new Map<string, Set<string>>();
  for (const d of detections) {
    if (d.role === "server_route" && d.receiver !== null) {
      const set = routerReceiversByPath.get(d.path) ?? new Set<string>();
      set.add(lastSegment(d.receiver)!);
      routerReceiversByPath.set(d.path, set);
    }
  }
  interface Mount { fromPath: string; fromReceiver: string; prefix: string; line: number }
  const mountsOf = new Map<string, Mount[]>(); // `${file}\0${router receiver}` -> mounts serving it
  for (const d of detections) {
    if (d.role !== "mount" || d.target === null || d.handler === null || d.receiver === null) {
      continue;
    }
    const head = d.handler.split(".")[0]!;
    const mount: Mount = { fromPath: d.path, fromReceiver: lastSegment(d.receiver)!, prefix: d.target, line: d.startLine };
    let targetPath: string;
    let targetReceiver: string | null = null;
    const imported = importTarget(d.path, head);
    if (imported === undefined) {
      targetPath = d.path;
      targetReceiver = head; // a router declared in the same file
    } else {
      targetPath = imported.path;
      const sym = imported.symbol === null ? undefined : symbolByKey(imported.path, imported.symbol);
      targetReceiver = sym !== undefined ? (sym.exportName === "default" ? (defaultExportStmt.get(generationId, imported.path) as { local: string | null } | undefined)?.local ?? null : sym.qualifiedName) : (defaultExportStmt.get(generationId, imported.path) as { local: string | null } | undefined)?.local ?? null;
    }
    if (targetReceiver === null || !(routerReceiversByPath.get(targetPath)?.has(targetReceiver) ?? false)) {
      addGap({ kind: "mount_target_not_a_router", entityId: null, path: d.path, line: d.startLine, detail: `"${d.handler}" mounted at ${d.target} is not a router object with routes in this snapshot (middleware, or defined where it cannot be resolved): no prefix was applied` });
      continue;
    }
    const key = `${targetPath}\0${targetReceiver}`;
    mountsOf.set(key, [...(mountsOf.get(key) ?? []), mount]);
  }
  const prefixMemo = new Map<string, string[]>();
  const prefixesFor = (path: string, receiver: string | null, depth: number, at: { path: string; line: number } | null): string[] => {
    const key = `${path}\0${receiver ?? ""}`;
    const known = prefixMemo.get(key);
    if (known !== undefined) {
      return known;
    }
    const mounts = receiver === null ? [] : mountsOf.get(key) ?? [];
    let out: string[] = [];
    if (mounts.length > 0 && depth >= FEATURE_LIMITS.mountDepth) {
      addGap({ kind: "mount_chain_too_deep", entityId: null, path: at?.path ?? path, line: at?.line ?? null, detail: `routers are mounted more than ${FEATURE_LIMITS.mountDepth} levels deep: the full URL prefix is unknown` });
      out = [""];
    } else {
      for (const m of mounts) {
        for (const parent of prefixesFor(m.fromPath, m.fromReceiver, depth + 1, { path: m.fromPath, line: m.line })) {
          out.push(joinPaths(parent, m.prefix));
        }
      }
      out = out.length === 0 ? [""] : [...new Set(out)].sort();
      if (out.length > FEATURE_LIMITS.mountsPerRoute) {
        addGap({ kind: "too_many_mount_paths", entityId: null, path, line: null, detail: `a router is mounted at more than ${FEATURE_LIMITS.mountsPerRoute} paths: only the first ${FEATURE_LIMITS.mountsPerRoute} are modelled` });
        out = out.slice(0, FEATURE_LIMITS.mountsPerRoute);
      }
    }
    prefixMemo.set(key, out);
    return out;
  };

  // ---- entities from detections ----
  interface TableInfo { entity: Entity; full: string }
  const ddlTables: TableInfo[] = [];
  const referencedTables = new Map<string, Entity>();
  const routeEntities: Entity[] = [];
  const clientEntities: Entity[] = [];
  const producers: Entity[] = [];
  const consumers: Entity[] = [];
  const uiRoutes: Entity[] = [];
  const queries: Entity[] = [];
  const jobs: Entity[] = [];
  const specOps: Entity[] = [];
  const testFiles = new Map<string, Entity>();
  const nextDirs = new Set<string>();
  const base = (d: Detection): Pick<Entity, "path" | "startLine" | "endLine" | "pkg" | "hash" | "handler" | "receiver"> => ({ path: d.path, startLine: d.startLine, endLine: d.endLine, pkg: packageOf(d.path), hash: d.hash, handler: d.handler, receiver: d.receiver });

  for (const d of detections) {
    if (d.role === "ddl_table") {
      const attrs = attrsOf(d);
      const entity = addEntity({ kind: "db_table", role: "table", key: d.key, name: d.key!, ...base(d), hash: typeof attrs["defHash"] === "string" ? (attrs["defHash"] as string) : d.hash, mechanism: "sql_ddl", certainty: "static", attrs: { schemaQualified: d.key!.includes(".") }, identity: d.key! });
      if (entity !== null) {
        ddlTables.push({ entity, full: d.key! });
      }
    } else if (d.role === "framework_marker" && d.key === "next") {
      nextDirs.add(dirname(d.path));
    }
  }
  const ddlByBare = new Map<string, TableInfo[]>();
  for (const t of ddlTables) {
    const bare = t.full.split(".").pop()!;
    ddlByBare.set(bare, [...(ddlByBare.get(bare) ?? []), t]);
  }

  for (const d of detections) {
    const attrs = attrsOf(d);
    switch (d.role) {
      case "coverage_note":
        addGap({ kind: "detection_truncated", entityId: null, path: d.path, line: null, detail: `detection in this file stopped at a safety limit (${String(attrs["reason"])}): routes, calls or events after that point were not read` });
        break;
      case "server_route": {
        const receiver = lastSegment(d.receiver);
        const prefixes = d.dynamic === 1 || d.receiver === null ? [""] : prefixesFor(d.path, receiver, 0, { path: d.path, line: d.startLine });
        for (const prefix of prefixes) {
          const path = d.dynamic === 1 ? null : joinPaths(prefix, d.target ?? "/");
          const key = path === null ? null : `${d.method} ${path}`;
          const e = addEntity({ kind: "route", role: d.role, key, name: key ?? d.name, ...base(d), mechanism: attrs["style"] === "decorator" ? "decorator_pattern" : "route_pattern", certainty: d.dynamic === 1 ? "dynamic_unknown" : "static", attrs: { ...attrs, method: d.method, ...(prefix === "" ? {} : { mountedAt: prefix }) }, identity: key ?? "dynamic" });
          if (e !== null) {
            routeEntities.push(e);
            if (d.dynamic === 1) {
              addGap({ kind: "dynamic_route", entityId: e.id, path: d.path, line: d.startLine, detail: "the route path is not a literal: which URL it serves is unknown" });
            }
          }
        }
        break;
      }
      case "client_call": {
        const weak = attrs["knownClient"] === false || attrs["maybeBaseUrl"] === true;
        const e = addEntity({ kind: "api_call", role: d.role, key: d.key, name: d.name, ...base(d), mechanism: "client_call_pattern", certainty: d.dynamic === 1 ? "dynamic_unknown" : weak ? "heuristic" : "static", attrs: { ...attrs, method: d.method }, identity: d.key ?? "dynamic" });
        if (e !== null) {
          clientEntities.push(e);
        }
        break;
      }
      case "event_producer":
      case "event_consumer": {
        const messaging = attrs["messagingReceiver"] === true;
        const e = addEntity({ kind: "event", role: d.role, key: d.key, name: d.name, ...base(d), mechanism: "messaging_pattern", certainty: d.dynamic === 1 ? "dynamic_unknown" : messaging ? "static" : "heuristic", attrs: { ...attrs, api: d.method }, identity: `${d.role}:${d.key ?? "dynamic"}` });
        if (e !== null) {
          (d.role === "event_producer" ? producers : consumers).push(e);
        }
        break;
      }
      case "ui_route": {
        const e = addEntity({ kind: "ui_route", role: d.role, key: d.key, name: d.name, ...base(d), mechanism: "ui_route_pattern", certainty: d.dynamic === 1 ? "dynamic_unknown" : "static", attrs, identity: d.key ?? "dynamic" });
        if (e !== null) {
          uiRoutes.push(e);
          if (d.dynamic === 1) {
            addGap({ kind: "dynamic_ui_route", entityId: e.id, path: d.path, line: d.startLine, detail: "the UI route path is not a literal" });
          }
        }
        break;
      }
      case "sql_query":
      case "orm_access": {
        const e = addEntity({ kind: "db_query", role: d.role, key: d.key, name: d.name, ...base(d), mechanism: d.role === "orm_access" ? "orm_pattern" : "sql_literal", certainty: d.role === "orm_access" ? "heuristic" : "static", attrs, identity: d.key ?? "query" });
        if (e !== null) {
          queries.push(e);
        }
        break;
      }
      case "job": {
        const e = addEntity({ kind: "job", role: d.role, key: d.key, name: d.name, ...base(d), mechanism: "job_pattern", certainty: d.dynamic === 1 ? "dynamic_unknown" : "static", attrs, identity: d.key ?? "dynamic" });
        if (e !== null) {
          jobs.push(e);
        }
        break;
      }
      case "spec_operation": {
        const e = addEntity({ kind: "api_operation", role: d.role, key: d.key, name: d.name, ...base(d), mechanism: "openapi_spec", certainty: "static", attrs: { ...attrs, method: d.method }, identity: d.key! });
        if (e !== null) {
          specOps.push(e);
        }
        break;
      }
      case "test_case": {
        if (!TEST_PATH.test(d.path)) {
          break;
        }
        let t = testFiles.get(d.path);
        if (t === undefined) {
          t = addEntity({ kind: "test", role: "test_file", key: d.path, name: d.path, path: d.path, startLine: 1, endLine: 1, pkg: packageOf(d.path), hash: d.hash, handler: null, receiver: null, mechanism: "test_pattern", certainty: "static", attrs: { cases: [] as string[] }, identity: d.path }) ?? undefined;
          if (t !== undefined) {
            testFiles.set(d.path, t);
          }
        }
        const cases = t?.attrs["cases"] as string[] | undefined;
        if (cases !== undefined && cases.length < 50 && d.key !== null) {
          cases.push(d.key.slice(0, 160));
        }
        break;
      }
      default:
        break;
    }
  }

  // ---- file-convention routes (Next.js, only where `next` is a declared dependency) and unsupported spec formats ----
  const inNextApp = (path: string): boolean => [...nextDirs].some((dir) => dir === "" || path === dir || path.startsWith(`${dir}/`));
  const manifest = db.prepare("SELECT path, content_hash AS hash FROM generation_files WHERE generation_id = ? AND content_hash IS NOT NULL ORDER BY path").all(generationId) as Array<{ path: string; hash: string }>;
  const conventionPath = (raw: string | undefined): string | null => {
    const segments = (raw ?? "").split("/").filter((s) => s !== "");
    if (segments.some((s) => s.startsWith("@"))) {
      return null; // a parallel-route slot is not a URL
    }
    const kept = segments.filter((s) => !/^\(.*\)$/.test(s)).map((s, i, all) => (i === all.length - 1 && s === "index" ? "" : s.replace(/^\[\[?\.\.\.[^\]]+\]\]?$/, "*")));
    return normalizePath(`/${kept.join("/")}`);
  };
  for (const { path, hash } of manifest) {
    if (OPENAPI_YAML.test(path)) {
      addGap({ kind: "unsupported_spec_format", entityId: null, path, line: null, detail: "an OpenAPI/Swagger YAML file exists but only JSON specs are read (no YAML parser is bundled)" });
    }
    if (nextDirs.size === 0 || !inNextApp(path)) {
      continue;
    }
    const pageMatch = NEXT_PAGES.exec(path);
    const appPage = NEXT_APP_PAGE.exec(path);
    const appRoute = NEXT_APP_ROUTE.exec(path);
    if (pageMatch !== null && !/(^|\/)_(app|document|error)\b/.test(path)) {
      const isApi = /^(?:src\/)?pages\/api\//.test(path);
      const route = conventionPath(pageMatch[1]);
      if (route !== null) {
        const e = addEntity({ kind: isApi ? "route" : "ui_route", role: isApi ? "server_route" : "ui_route", key: isApi ? `ANY ${route}` : route, name: isApi ? `ANY ${route}` : `ui ${route}`, path, startLine: 1, endLine: 1, pkg: packageOf(path), hash, handler: "default", receiver: null, mechanism: "file_convention", certainty: "static", attrs: { convention: "nextjs_pages", method: isApi ? "ANY" : null }, identity: route });
        if (e !== null) {
          (isApi ? routeEntities : uiRoutes).push(e);
        }
      }
    } else if (appPage !== null) {
      const route = conventionPath(appPage[1]);
      if (route !== null) {
        const e = addEntity({ kind: "ui_route", role: "ui_route", key: route, name: `ui ${route}`, path, startLine: 1, endLine: 1, pkg: packageOf(path), hash, handler: "default", receiver: null, mechanism: "file_convention", certainty: "static", attrs: { convention: "nextjs_app" }, identity: route });
        if (e !== null) {
          uiRoutes.push(e);
        }
      }
    } else if (appRoute !== null) {
      const route = conventionPath(appRoute[1]);
      if (route !== null) {
        for (const sym of symbolsOf(path).filter((s) => s.exported && /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/.test(s.exportName ?? ""))) {
          const e = addEntity({ kind: "route", role: "server_route", key: `${sym.exportName} ${route}`, name: `${sym.exportName} ${route}`, path, startLine: sym.startLine, endLine: sym.endLine, pkg: packageOf(path), hash, handler: sym.qualifiedName, receiver: null, mechanism: "file_convention", certainty: "static", attrs: { convention: "nextjs_app_route", method: sym.exportName }, identity: `${sym.exportName} ${route}` });
          if (e !== null) {
            routeEntities.push(e);
          }
        }
      }
    }
  }

  // ---- helpers over symbols ----
  const resolveHandler = (e: Entity): { node: string; certainty: string; reason: string; range: Range | null } | null => {
    if (e.handler === null || e.path === null) {
      return null;
    }
    const [head, ...rest] = e.handler.split(".");
    const rangeOfSymbol = (s: SymbolRange): Range => ({ path: s.path, start: s.startLine, end: s.endLine });
    // 1) a symbol declared in this file under exactly that name (top level, or `Class.member` when the handler is written that way)
    const exact = symbolsOf(e.path).filter((s) => s.qualifiedName === e.handler);
    if (exact.length === 1) {
      return { node: symbolNodeId(exact[0]!.path, exact[0]!.qualifiedName), certainty: "resolved", reason: "declared_in_file", range: rangeOfSymbol(exact[0]!) };
    }
    if (exact.length > 1) {
      return { node: fileNodeId(e.path), certainty: "ambiguous", reason: "several_symbols_with_that_name", range: null };
    }
    // 2) an import binding of that name (before any member-name guess: an imported `getUser` is not `A.getUser`)
    const imported = importTarget(e.path, head!);
    if (imported !== undefined) {
      if (imported.symbol !== null) {
        const sym = symbolByKey(imported.path, imported.symbol);
        if (sym !== undefined) {
          return { node: symbolNodeId(sym.path, sym.qualifiedName), certainty: "resolved", reason: "imported_binding", range: rangeOfSymbol(sym) };
        }
      }
      if (rest.length > 0) {
        const member = symbolsOf(imported.path).filter((s) => s.exported && s.exportName === rest.join("."));
        if (member.length === 1) {
          return { node: symbolNodeId(member[0]!.path, member[0]!.qualifiedName), certainty: "resolved", reason: "imported_namespace_member", range: rangeOfSymbol(member[0]!) };
        }
      }
      return { node: fileNodeId(imported.path), certainty: "ambiguous", reason: "imported_file_member_unknown", range: null };
    }
    // 3) decorator routes name a method of the enclosing class
    if (e.attrs["style"] === "decorator") {
      const methods = symbolsOf(e.path).filter((s) => s.qualifiedName.endsWith(`.${e.handler}`));
      if (methods.length === 1) {
        return { node: symbolNodeId(methods[0]!.path, methods[0]!.qualifiedName), certainty: "resolved", reason: "controller_method", range: rangeOfSymbol(methods[0]!) };
      }
      if (methods.length > 1) {
        return { node: fileNodeId(e.path), certainty: "ambiguous", reason: "several_methods_with_that_name", range: null };
      }
    }
    return null;
  };
  const rangeOf = (e: Entity): Range | null => {
    if (e.attrs["inline"] === true && e.path !== null && e.startLine !== null && e.endLine !== null) {
      return { path: e.path, start: e.startLine, end: e.endLine };
    }
    return handled.get(e.id)?.range ?? null;
  };

  // ---- edges: handlers ----
  const handled = new Map<string, ReturnType<typeof resolveHandler>>();
  for (const e of [...routeEntities, ...consumers, ...jobs, ...uiRoutes]) {
    if (e.handler === null) {
      continue;
    }
    const target = resolveHandler(e);
    handled.set(e.id, target);
    if (target === null) {
      addGap({ kind: "handler_not_resolved", entityId: e.id, path: e.path, line: e.startLine, detail: `the handler "${e.handler}" is not declared in this file and is not a resolved import` });
      continue;
    }
    const relation = e.kind === "ui_route" ? "RENDERS" : e.kind === "route" ? "HANDLES_WITH" : e.kind === "event" ? "CONSUMES_WITH" : "RUNS";
    addEdge({ src: e.id, dst: target.node, relation, certainty: target.certainty, mechanism: "symbol_resolution", reason: target.reason, path: e.path, line: e.startLine });
  }

  // ---- edges: client calls -> routes ----
  // routes in a segment trie: matching a client path walks its segments (a `{}` on either side widens the step) instead of scanning every route
  interface TrieNode { kids: Map<string, TrieNode>; routes: Entity[] }
  const trie: TrieNode = { kids: new Map(), routes: [] };
  const routesByKey = new Map<string, Entity[]>();
  for (const r of routeEntities) {
    if (r.key === null) {
      continue;
    }
    (routesByKey.get(r.key) ?? routesByKey.set(r.key, []).get(r.key)!).push(r);
    let node = trie;
    for (const seg of r.key.slice(r.key.indexOf(" ") + 1).split("/")) {
      node = node.kids.get(seg) ?? node.kids.set(seg, { kids: new Map(), routes: [] }).get(seg)!;
    }
    node.routes.push(r);
  }
  const lookupRoutes = (path: string): Entity[] => {
    const found: Entity[] = [];
    const walk = (node: TrieNode, segs: string[], i: number): void => {
      if (found.length >= FEATURE_LIMITS.wildcardScan) {
        return;
      }
      if (i === segs.length) {
        found.push(...node.routes);
        return;
      }
      const seg = segs[i]!;
      if (seg === "{}") {
        for (const child of node.kids.values()) {
          walk(child, segs, i + 1);
        }
        return;
      }
      const literal = node.kids.get(seg);
      if (literal !== undefined) {
        walk(literal, segs, i + 1);
      }
      const param = node.kids.get("{}");
      if (param !== undefined) {
        walk(param, segs, i + 1);
      }
    };
    walk(trie, path.split("/"), 0);
    return found.slice(0, FEATURE_LIMITS.wildcardScan);
  };
  for (const c of clientEntities) {
    if (c.key === null) {
      addGap({ kind: "dynamic_client_call", entityId: c.id, path: c.path, line: c.startLine, detail: c.attrs["note"] === "partial_template" ? "the request URL starts with an unknown part: which API it calls is unknown" : "the request URL is not a literal: which API it calls is unknown" });
      continue;
    }
    if (c.attrs["external"] === true) {
      continue; // a call to another host is not a call to a route of this repository
    }
    const space = c.key.indexOf(" ");
    const method = c.key.slice(0, space);
    const path = c.key.slice(space + 1);
    const found = new Map<string, { route: Entity; how: "exact" | "parameter" }>();
    for (const r of lookupRoutes(path)) {
      const rk = r.key!;
      const rMethod = rk.slice(0, rk.indexOf(" "));
      if (method !== "ANY" && rMethod !== "ANY" && rMethod !== method) {
        continue;
      }
      const how = pathMatch(path, rk.slice(rk.indexOf(" ") + 1));
      if (how !== null) {
        found.set(r.id, { route: r, how });
      }
    }
    const candidates = [...found.values()];
    const strongClient = c.certainty === "static" && c.attrs["methodUnknown"] !== true;
    for (const { route, how } of candidates) {
      const sole = candidates.length === 1;
      const exactMethod = route.key!.startsWith(`${method} `);
      const certainty = sole && how === "exact" && exactMethod && strongClient ? "resolved" : sole && how === "exact" && c.certainty !== "dynamic_unknown" ? "heuristic" : "ambiguous";
      addEdge({
        src: c.id, dst: route.id, relation: "CALLS_API", certainty, mechanism: "method_and_path_match",
        reason: !sole ? "several_routes_match" : c.attrs["methodUnknown"] === true ? "request_method_unknown" : c.attrs["maybeBaseUrl"] === true ? "base_url_may_differ" : c.attrs["knownClient"] === false ? "weak_client_signal" : how === "parameter" ? "path_parameter_segment_match" : !exactMethod ? "route_accepts_any_method" : "exact_method_and_path",
        path: c.path, line: c.startLine, attrs: { crossPackage: c.pkg !== route.pkg }
      });
    }
    if (candidates.length === 0 && c.attrs["knownClient"] !== false) {
      addGap({ kind: "client_call_without_route", entityId: c.id, path: c.path, line: c.startLine, detail: `no route in this snapshot serves ${c.key}${c.attrs["maybeBaseUrl"] === true ? " (a baseURL is configured in this file, so the real path may differ)" : ""}` });
    }
  }

  // ---- edges: UI routes -> API calls used by the component ----
  const clientsByPath = new Map<string, Entity[]>();
  for (const c of clientEntities) {
    if (c.path !== null) {
      (clientsByPath.get(c.path) ?? clientsByPath.set(c.path, []).get(c.path)!).push(c);
    }
  }
  for (const u of uiRoutes) {
    if (u.path === null) {
      continue;
    }
    const target = handled.get(u.id);
    const componentRange = target?.range ?? null;
    const componentFile = target?.node.startsWith("sym:") === true ? target.node.slice(4, target.node.lastIndexOf("#")) : target?.node.startsWith("file:") === true ? target.node.slice(5) : u.path;
    let linked = 0;
    for (const c of clientsByPath.get(componentFile) ?? []) {
      const insideComponent = componentRange !== null && c.startLine !== null && c.startLine >= componentRange.start && c.startLine <= componentRange.end;
      if (componentRange !== null && !insideComponent) {
        continue; // another component or helper in the same file: not shown to belong to this route
      }
      if (linked++ < FEATURE_LIMITS.uiClientCalls) {
        addEdge({ src: u.id, dst: c.id, relation: "USES_API_CALL", certainty: insideComponent ? "resolved" : "heuristic", mechanism: "source_range", reason: insideComponent ? "call_inside_component_range" : "component_not_resolved_same_file", path: componentFile, line: c.startLine });
      }
    }
    for (const row of importedFilesStmt.all(generationId, componentFile, FEATURE_LIMITS.importDepthFiles) as Array<{ p: string }>) {
      for (const c of clientsByPath.get(row.p) ?? []) {
        if (linked++ < FEATURE_LIMITS.uiClientCalls) {
          addEdge({ src: u.id, dst: c.id, relation: "USES_API_CALL", certainty: "heuristic", mechanism: "imported_module", reason: "component_file_imports_the_file_with_the_call", path: row.p, line: c.startLine });
        }
      }
    }
  }

  // ---- edges: events (producer -> consumer by literal name) ----
  const consumersByName = new Map<string, Entity[]>();
  for (const c of consumers) {
    if (c.key !== null) {
      (consumersByName.get(c.key) ?? consumersByName.set(c.key, []).get(c.key)!).push(c);
    }
  }
  const producedNames = new Set<string>();
  const messaging = (e: Entity): boolean => e.attrs["messagingReceiver"] === true;
  for (const p of producers) {
    if (p.key === null) {
      addGap({ kind: "dynamic_event_name", entityId: p.id, path: p.path, line: p.startLine, detail: "the event or topic name is not a literal: its consumers are unknown" });
      continue;
    }
    producedNames.add(p.key);
    const targets = consumersByName.get(p.key) ?? [];
    for (const c of targets) {
      addEdge({ src: p.id, dst: c.id, relation: "EVENT_FLOW", certainty: messaging(p) && messaging(c) ? "resolved" : "heuristic", mechanism: "literal_name_match", reason: messaging(p) && messaging(c) ? "same_event_name_on_messaging_receivers" : "same_event_name_but_a_receiver_is_not_messaging_shaped", path: p.path, line: p.startLine, attrs: { crossPackage: p.pkg !== c.pkg } });
    }
    if (targets.length === 0 && messaging(p)) {
      addGap({ kind: "event_without_consumer", entityId: p.id, path: p.path, line: p.startLine, detail: `no consumer of "${p.key}" was found in this snapshot (it may live outside the indexed repository)` });
    }
  }
  for (const c of consumers) {
    if (c.key === null) {
      addGap({ kind: "dynamic_event_name", entityId: c.id, path: c.path, line: c.startLine, detail: "the consumed event or topic name is not a literal: its producers are unknown" });
    } else if (!producedNames.has(c.key) && messaging(c)) {
      addGap({ kind: "event_without_producer", entityId: c.id, path: c.path, line: c.startLine, detail: `no producer of "${c.key}" was found in this snapshot` });
    }
  }

  // ---- edges: calls and queries made inside a handler ----
  const containersByPath = new Map<string, Array<{ e: Entity; range: Range }>>();
  for (const e of [...routeEntities, ...consumers, ...jobs]) {
    const range = rangeOf(e);
    if (range !== null) {
      (containersByPath.get(range.path) ?? containersByPath.set(range.path, []).get(range.path)!).push({ e, range });
    }
  }
  for (const x of [...producers, ...clientEntities, ...queries]) {
    if (x.path === null || x.startLine === null) {
      continue;
    }
    for (const c of containersByPath.get(x.path) ?? []) {
      if (x.startLine >= c.range.start && x.startLine <= c.range.end && c.e.id !== x.id) {
        addEdge({ src: c.e.id, dst: x.id, relation: x.kind === "event" ? "PUBLISHES" : x.kind === "api_call" ? "CALLS_API_FROM_HANDLER" : "QUERIES", certainty: "resolved", mechanism: "source_range", reason: c.e.attrs["inline"] === true ? "inline_handler_range" : "handler_symbol_range", path: x.path, line: x.startLine, attrs: { crossPackage: c.e.pkg !== x.pkg } });
      }
    }
  }

  // ---- edges: queries -> tables (a table is linked `resolved` only where its definition is in the same package; elsewhere it is a weaker claim) ----
  const tableFor = (q: Entity, name: string): Entity => {
    const key = `${q.pkg ?? ""}\0${name}`;
    let t = referencedTables.get(key);
    if (t === undefined) {
      t = addEntity({ kind: "db_table", role: "table", key: name, name, path: null, startLine: null, endLine: null, pkg: q.pkg, hash: null, mechanism: q.mechanism === "orm_pattern" ? "orm_model_reference" : "sql_reference", certainty: "heuristic", attrs: { referencedOnly: true }, handler: null, receiver: null, identity: `ref:${key}` }) ?? undefined;
      if (t !== undefined) {
        referencedTables.set(key, t);
      }
    }
    return t!;
  };
  for (const q of queries) {
    for (const spec of (q.attrs["tables"] as string[] | undefined) ?? []) {
      const access = spec.slice(0, spec.indexOf(":"));
      const name = spec.slice(spec.indexOf(":") + 1);
      const candidates = name.includes(".") ? ddlTables.filter((t) => t.full === name) : ddlByBare.get(name) ?? [];
      const relation = access === "write" ? "WRITES" : "READS";
      const orm = q.mechanism === "orm_pattern";
      if (candidates.length === 0) {
        const t = tableFor(q, name);
        addEdge({ src: q.id, dst: t.id, relation, certainty: "heuristic", mechanism: orm ? "orm_pattern" : "sql_text", reason: "table_referenced_only", path: q.path, line: q.startLine });
        continue;
      }
      const same = candidates.filter((t) => t.entity.pkg === q.pkg);
      const pool = same.length > 0 ? same : candidates;
      for (const t of pool) {
        const certainty = orm ? "heuristic" : pool.length > 1 ? "ambiguous" : same.length > 0 ? "resolved" : "heuristic";
        addEdge({
          src: q.id, dst: t.entity.id, relation, certainty, mechanism: orm ? "orm_pattern" : "sql_text",
          reason: orm ? "orm_model_name_matches_table" : pool.length > 1 ? "several_tables_with_that_name" : same.length > 0 ? "table_defined_in_the_same_package" : "table_defined_in_another_package", path: q.path, line: q.startLine, attrs: { crossPackage: t.entity.pkg !== q.pkg }
        });
      }
    }
  }
  for (const t of referencedTables.values()) {
    addGap({ kind: "table_without_schema", entityId: t.id, path: null, line: null, detail: `table "${t.name}" is referenced by queries in ${t.pkg === "" ? "the repository root" : String(t.pkg)} but no CREATE TABLE for it exists in this snapshot` });
  }

  // ---- edges: tests ----
  const entityFiles = new Map<string, Entity[]>();
  for (const e of [...routeEntities, ...uiRoutes, ...consumers, ...jobs]) {
    if (e.path !== null) {
      (entityFiles.get(e.path) ?? entityFiles.set(e.path, []).get(e.path)!).push(e);
    }
  }
  for (const [path, list] of entityFiles) {
    for (const t of findTestsFor(db, generationId, path, 10)) {
      const testEntity = testFiles.get(t.path);
      if (testEntity === undefined) {
        continue;
      }
      for (const e of list) {
        addEdge({
          src: testEntity.id, dst: e.id, relation: "TESTS", certainty: t.certainty === "resolved" && t.basis === "imports_target" ? "resolved" : "heuristic", mechanism: "import_edge",
          reason: t.basis === "imports_target" ? "test_imports_the_file" : t.basis === "imports_through_chain" ? "test_imports_through_a_chain" : "same_file_name",
          path: t.path, line: null, attrs: { note: "a test that imports code is not evidence that it exercises it" }
        });
      }
    }
  }

  // ---- edges: documented operations <-> implemented routes (a spec only judges routes of the package it lives in) ----
  const specPackages = new Set(specOps.map((o) => o.pkg));
  for (const op of specOps) {
    const routes = routesByKey.get(op.key!) ?? [];
    for (const r of routes) {
      addEdge({ src: op.id, dst: r.id, relation: "DOCUMENTS", certainty: routes.length === 1 ? "resolved" : "ambiguous", mechanism: "method_and_path_match", reason: "spec_operation_matches_route", path: op.path, line: null });
    }
    if (routes.length === 0) {
      addGap({ kind: "spec_operation_without_route", entityId: op.id, path: op.path, line: null, detail: `the specification documents ${op.key} but no route implements it in this snapshot (documentation never replaces code)` });
    }
  }
  const documented = new Set(specOps.map((o) => `${o.pkg}\0${o.key}`));
  for (const r of routeEntities) {
    if (r.key !== null && specPackages.has(r.pkg) && !documented.has(`${r.pkg}\0${r.key}`)) {
      addGap({ kind: "route_not_in_spec", entityId: r.id, path: r.path, line: r.startLine, detail: `${r.key} is implemented but not documented in the OpenAPI specification of its package` });
    }
  }

  // ---- limits are reported, never silent ----
  if (entityCapHit) {
    addGap({ kind: "entity_limit_reached", entityId: null, path: null, line: null, detail: `the feature graph holds at most ${FEATURE_LIMITS.entities} entities: further detections were dropped` });
  }
  if (edgeCapHit) {
    addGap({ kind: "edge_limit_reached", entityId: null, path: null, line: null, detail: `the feature graph holds at most ${FEATURE_LIMITS.edges} edges: further links were dropped` });
  }

  // a referenced-only table has no source of its own: its evidence version is that of the queries that reference it
  const referencingHashes = new Map<string, string[]>();
  for (const e of edges) {
    if ((e.relation === "READS" || e.relation === "WRITES") && byId.get(e.dst)?.hash === null) {
      const h = byId.get(e.src)?.hash;
      if (h !== null && h !== undefined) {
        (referencingHashes.get(e.dst) ?? referencingHashes.set(e.dst, []).get(e.dst)!).push(h);
      }
    }
  }
  for (const [id, hashes] of referencingHashes) {
    byId.get(id)!.hash = sha([...new Set(hashes)].sort().join("\n"));
  }

  // ---- flows (discovered features): a DIRECTED neighbourhood of each route, UI route and job ----
  const adjacency = new Map<string, Array<{ other: string; edge: Edge; forward: boolean }>>();
  for (const e of edges) {
    (adjacency.get(e.src) ?? adjacency.set(e.src, []).get(e.src)!).push({ other: e.dst, edge: e, forward: true });
    (adjacency.get(e.dst) ?? adjacency.set(e.dst, []).get(e.dst)!).push({ other: e.src, edge: e, forward: false });
  }
  const features: Array<{ id: string; name: string; root: string; members: Array<{ id: string; role: string; hops: number }>; summary: Record<string, unknown> }> = [];
  const nameOfNode = (id: string): { kind: string; name: string } => {
    const e = byId.get(id);
    if (e !== undefined) {
      return { kind: e.kind, name: e.name };
    }
    return { kind: id.startsWith("sym:") ? "symbol" : "file", name: id.slice(id.indexOf(":") + 1) };
  };
  for (const root of [...routeEntities, ...uiRoutes, ...jobs]) {
    if (root.key === null) {
      continue;
    }
    // Following a request: down along FORWARD relations; up only to the callers of the root (and their callers); tests and documentation attach to the root.
    // A shared table or event consumer therefore never pulls sibling routes into this flow, and a hub (more links than the fan-out cap) is a member that is not expanded.
    const seen = new Map<string, { hops: number; mode: "down" | "up" | "attach" }>([[root.id, { hops: 0, mode: "down" }]]);
    const hubs: string[] = [];
    let frontier = [root.id];
    let truncated = false;
    let lowest: "resolved" | "partial" = "resolved";
    for (let hop = 1; hop <= FEATURE_LIMITS.flowHops && frontier.length > 0; hop += 1) {
      const next: string[] = [];
      for (const node of frontier) {
        const state = seen.get(node)!;
        const links = adjacency.get(node) ?? [];
        if (links.length > FEATURE_LIMITS.flowFanout && node !== root.id) {
          hubs.push(node);
          continue;
        }
        for (const { other, edge, forward } of links) {
          if (seen.has(other)) {
            continue;
          }
          let mode: "down" | "up" | "attach" | null = null;
          if (state.mode === "down" && forward && FORWARD.has(edge.relation)) {
            mode = "down";
          } else if ((state.mode === "up" || (state.mode === "down" && node === root.id)) && !forward && UPSTREAM.has(edge.relation)) {
            mode = "up";
          } else if (node === root.id && !forward && ATTACH.has(edge.relation)) {
            mode = "attach";
          }
          if (mode === null) {
            continue;
          }
          if (seen.size >= FEATURE_LIMITS.flowMembers) {
            truncated = true;
            continue;
          }
          if (edge.certainty !== "resolved") {
            lowest = "partial";
          }
          seen.set(other, { hops: hop, mode });
          if (mode !== "attach") {
            next.push(other);
          }
        }
      }
      frontier = next;
    }
    const members = [...seen].sort((a, b) => a[1].hops - b[1].hops || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)).map(([id, s]) => ({ id, role: nameOfNode(id).kind, hops: s.hops }));
    const kinds: Record<string, number> = {};
    for (const m of members) {
      kinds[m.role] = (kinds[m.role] ?? 0) + 1;
    }
    const services = [...new Set(members.map((m) => byId.get(m.id)?.pkg).filter((p): p is string => p !== null && p !== undefined))].sort();
    features.push({
      id: `flow:${root.kind}:${root.key}${root.pkg === null || root.pkg === "" ? "" : `@${root.pkg}`}`, name: root.name, root: root.id, members,
      summary: { rootKind: root.kind, rootPath: root.path, kinds, services, confidence: lowest, truncated, hubs: hubs.length, basis: "deterministic, request-directed neighbourhood of the root over feature edges; a candidate grouping, not a business-defined feature" }
    });
  }
  // the same key in the same package from two files: the path disambiguates, never an order-dependent counter
  const idCount = new Map<string, number>();
  for (const f of features) {
    idCount.set(f.id, (idCount.get(f.id) ?? 0) + 1);
  }
  for (const f of features) {
    if ((idCount.get(f.id) ?? 0) > 1) {
      f.id = `${f.id}#${String(f.summary["rootPath"] ?? byId.get(f.root)?.path ?? "")}`;
    }
  }

  // ---- persist ----
  const insertEntity = db.prepare(
    `INSERT INTO feature_entities (generation_id, entity_id, kind, role, key, name, path, start_line, end_line, package_dir, mechanism, certainty, trust, content_hash, extractor, valid_from_generation, attrs_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );
  const insertEdge = db.prepare(
    `INSERT INTO feature_edges (generation_id, edge_id, src_entity, dst_entity, relation, certainty, mechanism, reason, evidence_path, evidence_line, attrs_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );
  const insertGap = db.prepare("INSERT INTO feature_gaps (generation_id, gap_id, kind, entity_id, path, line, detail) VALUES (?, ?, ?, ?, ?, ?, ?)");
  const insertFeature = db.prepare("INSERT INTO features (generation_id, feature_id, name, source, root_entity, member_count, summary_json) VALUES (?, ?, ?, 'discovered', ?, ?, ?)");
  const insertMember = db.prepare("INSERT INTO feature_members (generation_id, feature_id, entity_id, role, hops) VALUES (?, ?, ?, ?, ?)");
  const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
  const sortedEntities = [...entities].sort((a, b) => cmp(a.id, b.id));
  const edgeKey = (e: Edge): string => `${e.src}\0${e.dst}\0${e.relation}\0${String(e.line ?? 0).padStart(9, "0")}\0${e.reason}`;
  const sortedEdges = [...edges].sort((a, b) => cmp(edgeKey(a), edgeKey(b)));
  const gapKey = (g: Gap): string => `${g.kind}\0${g.entityId ?? ""}\0${g.path ?? ""}\0${String(g.line ?? 0).padStart(9, "0")}\0${g.detail}`;
  const sortedGaps = [...gaps].sort((a, b) => cmp(gapKey(a), gapKey(b)));
  db.transaction(() => {
    for (const e of sortedEntities) {
      insertEntity.run(generationId, e.id, e.kind, e.role, e.key, e.name, e.path, e.startLine, e.endLine, e.pkg, e.mechanism, e.certainty, e.trust, e.hash, "feature:entities", e.validFrom, Object.keys(e.attrs).length === 0 ? null : JSON.stringify(e.attrs));
    }
    sortedEdges.forEach((e, i) => insertEdge.run(generationId, i, e.src, e.dst, e.relation, e.certainty, e.mechanism, e.reason, e.path, e.line, e.attrs === undefined ? null : JSON.stringify(e.attrs)));
    sortedGaps.forEach((g, i) => insertGap.run(generationId, i, g.kind, g.entityId, g.path, g.line, g.detail));
    for (const f of features.sort((a, b) => cmp(a.id, b.id))) {
      insertFeature.run(generationId, f.id, f.name, f.root, f.members.length, JSON.stringify(f.summary));
      for (const m of f.members) {
        insertMember.run(generationId, f.id, m.id, m.role, m.hops);
      }
    }
  }).immediate();
  const lineage = recordFeatureLineage(db, generationId, parentId);
  return { entities: entities.length, edges: edges.length, gaps: gaps.length, features: features.length, lineage, ms: Date.now() - started };
}

/**
 * What happened to flow features between the previous generation ON THE SAME BRANCH and this one, judged by HANDLER identity (the path + qualified name of a handling symbol), never by name:
 *  - the STRONG identity of a feature is the handler of its root entry point; one removed + one added sharing it is a `renamed` feature, one removed whose handler now serves
 *    several added features is a `split`;
 *  - a feature that now contains the root handlers of several removed features (different handlers) is a `merged` result;
 *  - any other overlap of the wider handler sets that fits none of these patterns is reported `ambiguous`, never guessed;
 *  - no overlap at all is plainly `added` or `removed`.
 */
function recordFeatureLineage(db: Database.Database, generationId: number, parentId: number | null): number {
  if (parentId === null) {
    return 0;
  }
  const sets = (g: number, strongOnly: boolean): Map<string, Set<string>> => {
    const map = new Map<string, Set<string>>();
    const rows = db.prepare(
      `SELECT fm.feature_id AS id, fe.dst_entity AS node FROM feature_members fm
       JOIN feature_edges fe ON fe.generation_id = fm.generation_id AND fe.src_entity = fm.entity_id AND fe.relation IN ('HANDLES_WITH', 'RENDERS', 'CONSUMES_WITH', 'RUNS')
       ${strongOnly ? "JOIN features f ON f.generation_id = fm.generation_id AND f.feature_id = fm.feature_id AND f.root_entity = fm.entity_id" : ""}
       WHERE fm.generation_id = ? AND fe.dst_entity LIKE 'sym:%'`
    ).all(g) as Array<{ id: string; node: string }>;
    for (const row of rows) {
      map.set(row.id, (map.get(row.id) ?? new Set()).add(row.node));
    }
    return map;
  };
  const ids = (g: number): Set<string> => new Set((db.prepare("SELECT feature_id AS id FROM features WHERE generation_id = ?").all(g) as Array<{ id: string }>).map((r) => r.id));
  const oldIds = ids(parentId);
  const newIds = ids(generationId);
  const removed = [...oldIds].filter((id) => !newIds.has(id)).sort();
  const added = [...newIds].filter((id) => !oldIds.has(id)).sort();
  if (removed.length === 0 && added.length === 0) {
    return 0;
  }
  const oldStrong = sets(parentId, true);
  const newStrong = sets(generationId, true);
  const oldWide = sets(parentId, false);
  const newWide = sets(generationId, false);
  const overlaps = (a: Set<string> | undefined, b: Set<string> | undefined): boolean => a !== undefined && b !== undefined && [...a].some((x) => b.has(x));
  const subset = (a: Set<string> | undefined, b: Set<string> | undefined): boolean => a !== undefined && b !== undefined && a.size > 0 && [...a].every((x) => b.has(x));
  const strongLinks = new Map<string, string[]>(removed.map((r) => [r, added.filter((a) => overlaps(oldStrong.get(r), newStrong.get(a)))]));
  const strongBack = new Map<string, string[]>(added.map((a) => [a, removed.filter((r) => (strongLinks.get(r) ?? []).includes(a))]));
  const events: Array<{ kind: string; old: string[]; next: string[]; basis: string; certainty: string }> = [];
  const doneOld = new Set<string>();
  const doneNew = new Set<string>();
  const ambiguousNew = new Set<string>(); // new features named by an ambiguous event may be named by several of them
  for (const r of removed) {
    const to = strongLinks.get(r) ?? [];
    if (to.length === 1 && (strongBack.get(to[0]!) ?? []).length === 1) {
      events.push({ kind: "renamed", old: [r], next: to, basis: "the entry point's handler symbol is unchanged", certainty: "heuristic" });
      doneOld.add(r);
      doneNew.add(to[0]!);
    } else if (to.length > 1 && to.every((a) => (strongBack.get(a) ?? []).length === 1)) {
      events.push({ kind: "split", old: [r], next: to, basis: "the entry point's handler symbol now serves several features", certainty: "heuristic" });
      doneOld.add(r);
      to.forEach((x) => doneNew.add(x));
    }
  }
  for (const a of added) {
    if (doneNew.has(a)) {
      continue;
    }
    const sources = removed.filter((r) => !doneOld.has(r) && subset(oldStrong.get(r), newWide.get(a)) && !overlaps(oldStrong.get(r), newStrong.get(a)));
    const distinct = new Set(sources.map((r) => [...(oldStrong.get(r) ?? [])].sort().join("|")));
    if (sources.length > 1 && distinct.size === sources.length) {
      events.push({ kind: "merged", old: sources, next: [a], basis: "the new feature contains the entry-point handlers of several removed features", certainty: "heuristic" });
      sources.forEach((r) => doneOld.add(r));
      doneNew.add(a);
    }
  }
  for (const r of removed) {
    if (doneOld.has(r)) {
      continue;
    }
    const to = added.filter((a) => !doneNew.has(a) && (overlaps(oldStrong.get(r), newStrong.get(a)) || overlaps(oldWide.get(r), newWide.get(a))));
    if (to.length === 0) {
      events.push({ kind: "removed", old: [r], next: [], basis: "no feature shares its handler symbols", certainty: "resolved" });
    } else {
      events.push({ kind: "ambiguous", old: [r], next: to, basis: "overlapping handler symbols that form no one-to-one, split or merge pattern: identity cannot be decided", certainty: "ambiguous" });
      to.forEach((x) => ambiguousNew.add(x));
    }
    doneOld.add(r);
  }
  for (const a of added) {
    if (!doneNew.has(a) && !ambiguousNew.has(a)) {
      events.push({ kind: "added", old: [], next: [a], basis: "no previous feature shares its handler symbols", certainty: "resolved" });
    }
  }
  const insert = db.prepare("INSERT INTO feature_lineage (generation_id, id, kind, old_ids_json, new_ids_json, basis, certainty) VALUES (?, ?, ?, ?, ?, ?, ?)");
  db.transaction(() => events.forEach((e, i) => insert.run(generationId, i, e.kind, JSON.stringify(e.old), JSON.stringify(e.next), e.basis, e.certainty))).immediate();
  return events.length;
}
