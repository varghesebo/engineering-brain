import {
  EngbrainError, findCycles, graphStats, impact, references, resolveNode, shortestPath, Store, traverse, validateGraph,
  type EdgeRecord, type GraphMode, type NodeRef, type NodeSpec, type Truncation
} from "@engbrain/core";
import type { CliContext } from "../context.js";
import { EXIT, printable, printJsonOrText, type Io } from "../output.js";
import { toRepoPath } from "../paths.js";

export type GraphAction = "stats" | "dependencies" | "dependents" | "references" | "path" | "impact" | "cycles" | "validate";
export const GRAPH_ACTIONS = new Set<string>(["stats", "dependencies", "dependents", "references", "path", "impact", "cycles", "validate"]);

export interface GraphOptions {
  file: string | undefined;
  symbol: string | undefined;
  package: string | undefined;
  external: string | undefined;
  from: string | undefined;
  to: string | undefined;
  depth: number | undefined;
  limit: number | undefined;
  mode: GraphMode | undefined;
  kinds: string[] | undefined;
}

/** `src/a.ts`, `src/a.ts#Class.method`, `pkg:packages/lib`, `ext:lodash`. */
function parseSpec(context: CliContext, io: Io, text: string): NodeSpec {
  if (text.startsWith("pkg:")) {
    return { package: text.slice(4) };
  }
  if (text.startsWith("ext:")) {
    return { external: text.slice(4) };
  }
  const cut = text.lastIndexOf("#");
  return cut === -1
    ? { file: toRepoPath(context.root, io.cwd, text) }
    : { symbol: `${toRepoPath(context.root, io.cwd, text.slice(0, cut))}#${text.slice(cut + 1)}` };
}

function specFromFlags(context: CliContext, io: Io, o: GraphOptions): NodeSpec {
  if (o.file !== undefined) {
    return { file: toRepoPath(context.root, io.cwd, o.file) };
  }
  if (o.symbol !== undefined) {
    return parseSpec(context, io, o.symbol.includes("#") ? o.symbol : `${o.symbol}`);
  }
  if (o.package !== undefined) {
    return { package: o.package };
  }
  if (o.external !== undefined) {
    return { external: o.external };
  }
  throw new EngbrainError("INVALID_ROOT", "name a node with --file <path>, --symbol <path#name>, --package <dir> or --external <name>");
}

const where = (n: NodeRef): string => (n.kind === "symbol" ? `${n.path}#${n.name}` : n.kind === "file" ? n.path ?? "" : `${n.kind}:${n.name}`);

function edgeLine(e: EdgeRecord): string {
  const loc = e.line === null ? "" : `:${e.line}`;
  const source = e.src.kind === "file" || e.src.kind === "symbol" ? `${e.src.path}${loc}` : e.src.key;
  return `${source}  ${e.kind}[${e.resolution}${e.reason === "" ? "" : `: ${e.reason}`}]  ${where(e.src)} -> ${where(e.dst)}`;
}

function truncationText(t: Truncation): string {
  const hit = (Object.keys(t) as Array<keyof Truncation>).filter((k) => t[k]);
  return hit.length === 0 ? "" : `\n  TRUNCATED by: ${hit.join(", ")} (raise --depth/--limit, or narrow the question)`;
}

export async function graphCommand(io: Io, context: CliContext, json: boolean, action: GraphAction, o: GraphOptions): Promise<number> {
  const store = await Store.open({ root: context.root, git: context.git, hardenedGit: context.hardenedGit, installId: context.installId });
  try {
    const budget = { ...(o.depth === undefined ? {} : { maxDepth: o.depth }), ...(o.limit === undefined ? {} : { maxNodes: o.limit }) };
    switch (action) {
      case "stats": {
        const s = graphStats(store.db);
        const kinds = Object.entries(s.edges.byKind).map(([k, v]) => `${k} ${v}`).join(", ") || "none";
        const res = Object.entries(s.edges.byResolution).map(([k, v]) => `${k} ${v}`).join(", ") || "none";
        printJsonOrText(io, json, { ...s }, [
          s.generationId === null ? "no index yet: run `engbrain index`" : `graph of generation ${s.generationId}`,
          `  nodes: ${s.nodes.files} files, ${s.nodes.symbols} symbols, ${s.nodes.packages} packages, ${s.nodes.externals} external dependencies`,
          `  edges: ${s.edges.total} (${kinds})`,
          `  resolution: ${res}`,
          `  undecided relationships: ${s.boundary.unresolved} unresolved, ${s.boundary.ambiguous} ambiguous, ${s.boundary.dynamic} dynamic; ${s.boundary.syntacticOnly} name-match references (syntactic only)`,
          `  import cycles: ${s.cycles}`,
          ...s.highestFanIn.slice(0, 3).map((x) => `  most imported: ${printable(x.path)} (${x.imports})`)
        ].join("\n"));
        return EXIT.ok;
      }
      case "dependencies":
      case "dependents": {
        const start = resolveNode(store.db, specFromFlags(context, io, o));
        const mode: GraphMode = o.mode ?? (start.kind === "symbol" ? "symbol" : "module");
        const result = traverse(store.db, start, { direction: action === "dependencies" ? "forward" : "reverse", mode, ...(o.kinds === undefined ? {} : { kinds: o.kinds }), budget });
        const lines = [
          `${action} of ${printable(where(start))}  (mode ${mode}, depth ${result.budget.maxDepth})`,
          ...result.nodes.slice(1).map((n) => `  depth ${n.depth}  ${n.kind.padEnd(8)} ${printable(where(n))}`),
          `  ${result.nodes.length - 1} nodes, ${result.edges.length} edges`,
          ...(result.unresolvedBoundary.length === 0 ? [] : [`  undecided relationships met (${result.unresolvedBoundary.length}${result.unresolvedBoundaryTruncated ? "+" : ""}):`, ...result.unresolvedBoundary.slice(0, 10).map((e) => `    ${printable(edgeLine(e))}`)])
        ];
        printJsonOrText(io, json, { ...result }, lines.join("\n") + truncationText(result.truncated));
        return EXIT.ok;
      }
      case "references": {
        const symbol = resolveNode(store.db, specFromFlags(context, io, o));
        const result = references(store.db, symbol, o.limit ?? 500);
        printJsonOrText(io, json, { symbol, ...result }, [
          `references to ${printable(where(symbol))}`,
          ...result.references.map((e) => `  ${printable(edgeLine(e))}`),
          `  ${result.references.length} references${result.truncated ? " (truncated; use --limit)" : ""}. A reference by NAME is syntactic only; no call targets are inferred.`
        ].join("\n"));
        return EXIT.ok;
      }
      case "path": {
        if (o.from === undefined || o.to === undefined) {
          throw new EngbrainError("INVALID_ROOT", "path needs --from <node> and --to <node>");
        }
        const from = resolveNode(store.db, parseSpec(context, io, o.from));
        const to = resolveNode(store.db, parseSpec(context, io, o.to));
        const result = shortestPath(store.db, from, to, { mode: o.mode ?? "all", ...(o.kinds === undefined ? {} : { kinds: o.kinds }), budget });
        printJsonOrText(io, json, { from, to, ...result }, [
          result.found ? `path from ${printable(where(from))} to ${printable(where(to))} (${result.path.length} edges)` : `no path found from ${printable(where(from))} to ${printable(where(to))} (${result.explored} nodes explored)`,
          ...result.path.map((e) => `  ${printable(edgeLine(e))}`),
          `  ${result.note}`
        ].join("\n") + truncationText(result.truncated));
        return result.found ? EXIT.ok : EXIT.error;
      }
      case "impact": {
        const target = resolveNode(store.db, specFromFlags(context, io, o));
        const result = impact(store.db, target, { budget });
        const b = result.unresolvedBoundary;
        printJsonOrText(io, json, { ...result }, [
          `potential structural impact of changing ${printable(where(target))}`,
          ...result.affected.map((a) => `  distance ${a.distance}  ${a.node.kind.padEnd(7)} ${printable(where(a.node))}   via ${a.via.kind}[${a.via.resolution}]`),
          ...(result.usedSymbols.length === 0 ? [] : ["  most used symbols:", ...result.usedSymbols.slice(0, 5).map((u) => `    ${printable(where(u.symbol))} (${u.incoming} incoming)`)]),
          `  ${result.affected.length} potentially affected nodes`,
          `  not decidable: ${b.dynamicImports} dynamic imports, ${b.unresolvedImports} unresolved imports, ${b.ambiguousImports} ambiguous imports, ${b.unresolvedBindings} imported names with no decidable export in this index${b.possiblyRelated.length > 0 ? `; ${b.possiblyRelated.length} undecided imports mention a similar name` : ""}`,
          `  ${result.disclaimer}`
        ].join("\n") + truncationText(result.truncated));
        return EXIT.ok;
      }
      case "cycles": {
        const result = findCycles(store.db, o.limit === undefined ? {} : { maxCycles: o.limit });
        printJsonOrText(io, json, { ...result }, [
          `${result.totalCycles} import cycle${result.totalCycles === 1 ? "" : "s"} among resolved file-level imports`,
          ...result.cycles.map((c) => `  size ${c.size}: ${c.members.map(printable).join(" <-> ")}${c.membersTruncated ? " …" : ""}`),
          `  ${result.note}`
        ].join("\n"));
        return EXIT.ok;
      }
      case "validate": {
        const result = validateGraph(store.db);
        printJsonOrText(io, json, { ...result }, result.ok ? `graph valid (${result.checked["edges"] ?? 0} edges checked)` : `graph INVALID:\n${result.problems.map((p) => `  - ${p}`).join("\n")}`);
        return result.ok ? EXIT.ok : EXIT.error;
      }
    }
  } finally {
    store.close();
  }
}
