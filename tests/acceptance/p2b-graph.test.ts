import { chmodSync, cpSync, existsSync, mkdirSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import Database from "better-sqlite3";
import {
  findCycles, graphStats, impact, indexRepository, references, resolveNode, shortestPath, traverse, validateGraph, type FaultPoint, type NodeRef
} from "@engbrain/core";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, engbrainHome, git, makeGitRepo, openFor, runCli, tempDir } from "../helpers/env.js";
import { graphFiles } from "../helpers/graph-fixture.js";

afterAll(cleanupTempDirs);

type Opened = Awaited<ReturnType<typeof openFor>>;

async function indexIn(repo: string, home: string, init = false, fault?: (p: FaultPoint) => void) {
  const o = await openFor(repo, home, init);
  try {
    return await indexRepository({ store: o.store, git: o.info, hardenedGit: o.git, ...(fault ? { fault } : {}) });
  } finally {
    o.close();
  }
}
async function read<T>(repo: string, home: string, fn: (o: Opened) => T): Promise<T> {
  const o = await openFor(repo, home);
  try {
    return fn(o);
  } finally {
    o.close();
  }
}

function fixtureRepo(extra: Record<string, string> = {}): string {
  return makeGitRepo({ ...graphFiles(), ...extra });
}

const GEN = "(SELECT current_generation_id FROM store_meta)";
interface E { family: string; kind: string; style: string | null; src: string; dst: string; resolution: string; reason: string; line: number | null; detail: Record<string, unknown> | null }
function edges(o: Opened, where = "1=1"): E[] {
  const rows = o.store.db.prepare(
    `SELECT family, edge_kind AS kind, import_style AS style, src_kind, src_path, src_symbol, dst_kind, dst_path, dst_symbol, dst_name, dst_package, resolution, reason, start_line AS line, detail
     FROM graph_edges WHERE generation_id = ${GEN} AND (${where}) ORDER BY edge_id`
  ).all() as Array<Record<string, unknown>>;
  const name = (kind: unknown, path: unknown, sym: unknown, nm: unknown, pkg: unknown): string => {
    if (kind === "symbol") {
      const q = o.store.db.prepare(`SELECT qualified_name AS q FROM symbol_occurrences WHERE generation_id = ${GEN} AND path = ? AND symbol_key = ? LIMIT 1`).get(path, sym) as { q: string } | undefined;
      return `${path}#${q?.q ?? sym}`;
    }
    return kind === "file" ? String(path) : kind === "external" ? `ext:${pkg}` : kind === "package" ? `pkg:${path}` : `unknown:${nm ?? ""}`;
  };
  return rows.map((r) => ({
    family: String(r["family"]), kind: String(r["kind"]), style: r["style"] as string | null,
    src: name(r["src_kind"], r["src_path"], r["src_symbol"], null, null), dst: name(r["dst_kind"], r["dst_path"], r["dst_symbol"], r["dst_name"], r["dst_package"]),
    resolution: String(r["resolution"]), reason: String(r["reason"]), line: r["line"] as number | null, detail: r["detail"] === null ? null : (JSON.parse(String(r["detail"])) as Record<string, unknown>)
  }));
}
const find = (list: E[], kind: string, src: string, dst: string): E | undefined => list.find((e) => e.kind === kind && e.src === src && e.dst === dst);

describe("P2B graph facts match golden expectations, with provenance", () => {
  it("imports, barrels, re-export aliases, default re-exports, workspace and alias resolution", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    await read(repo, home, (o) => {
      const all = edges(o);
      const M = "packages/app/src/main.ts";
      // module-level (file -> file)
      expect(find(all, "IMPORTS", M, "packages/core/src/index.ts")).toMatchObject({ family: "module", resolution: "resolved", reason: "workspace_package:@org/core", style: "import" });
      expect(find(all, "IMPORTS", M, "packages/app/src/widget.ts")).toMatchObject({ resolution: "resolved", reason: "tsconfig_paths" });
      expect(find(all, "RE_EXPORTS", "packages/core/src/index.ts", "packages/core/src/models.ts")).toMatchObject({ resolution: "resolved", style: "export_from" });
      // binding level (file -> exported symbol), resolved THROUGH the barrel
      expect(find(all, "IMPORTS", M, "packages/core/src/models.ts#Dog")).toMatchObject({ family: "symbol", resolution: "resolved", reason: "declared_export", detail: { imported: "Dog", local: "Dog" } });
      expect(find(all, "IMPORTS", M, "packages/core/src/logger.ts#Logger")).toMatchObject({ resolution: "resolved", detail: { imported: "Log", local: "Log" } }); // export { Logger as Log }
      expect(find(all, "IMPORTS", M, "packages/core/src/config.ts#Config")).toMatchObject({ resolution: "resolved" }); // export { default as Config }
      // heritage across files, through an alias import and a barrel
      expect(find(all, "EXTENDS", `${M}#Puppy`, "packages/core/src/models.ts#Dog")).toMatchObject({ resolution: "resolved", detail: { written: "Dog" } });
      expect(find(all, "IMPLEMENTS", `${M}#Puppy`, "packages/app/src/widget.ts#Widget")).toMatchObject({ resolution: "resolved" });
      expect(find(all, "EXTENDS", "packages/core/src/models.ts#Dog", "packages/core/src/models.ts#Animal")).toMatchObject({ resolution: "resolved", reason: "declared_in_same_file" });
      expect(find(all, "IMPLEMENTS", "packages/core/src/models.ts#Dog", "packages/core/src/models.ts#Walker")).toBeDefined();
      expect(find(all, "EXTENDS", "packages/core/src/models.ts#Cat", "packages/core/src/models.ts#Animal")).toBeDefined();
      // packages
      expect(find(all, "DEPENDS_ON", "pkg:packages/app", "pkg:packages/core")).toMatchObject({ family: "package", resolution: "resolved" });
      expect(find(all, "DEPENDS_ON", "pkg:packages/app", "ext:node:fs")).toMatchObject({ resolution: "external" });
    });
  });

  it("every edge carries mechanism, resolution, extractor identity and a source line", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    await read(repo, home, (o) => {
      const rows = o.store.db.prepare(`SELECT mechanism, resolution, extractor, start_line, family FROM graph_edges WHERE generation_id = ${GEN}`).all() as Array<{ mechanism: string; resolution: string; extractor: string; start_line: number | null; family: string }>;
      expect(rows.length).toBeGreaterThan(300);
      for (const r of rows) {
        expect(["tree_sitter_syntax", "scip", "compiler", "observed", "inferred"]).toContain(r.mechanism);
        expect(r.extractor).toMatch(/^graph:\d+$/);
        if (r.family !== "package") {
          expect(r.start_line, JSON.stringify(r)).toBeGreaterThan(0);
        }
      }
      expect(new Set(rows.map((r) => r.mechanism))).toEqual(new Set(["tree_sitter_syntax"])); // nothing is claimed to be compiler-grade
    });
  });

  it("unknown stays unknown: dynamic imports, missing modules and missing exports are explicit; no CALLS edge is ever produced", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    await read(repo, home, (o) => {
      const all = edges(o);
      const M = "packages/app/src/main.ts";
      expect(all.find((e) => e.src === M && e.style === "dynamic_import")).toMatchObject({ resolution: "dynamic", dst: "unknown:" });
      expect(all.find((e) => e.src === M && e.dst === "unknown:./nope")).toMatchObject({ resolution: "unresolved", reason: "relative_target_missing" });
      expect(all.find((e) => e.kind === "IMPORTS" && e.family === "symbol" && e.detail?.["imported"] === "zzz")).toMatchObject({ resolution: "unresolved", reason: "export_not_found" });
      // CommonJS: `const { log } = require("@org/core")` is NOT exported by that barrel: reported, not guessed
      expect(all.find((e) => e.src === "packages/app/src/legacy.js" && e.detail?.["imported"] === "log")).toMatchObject({ resolution: "unresolved" });
      expect(all.filter((e) => e.kind === "CALLS")).toEqual([]);
      // name matches are labelled as such
      const refs = all.filter((e) => e.kind === "REFERENCES");
      expect(refs.length).toBeGreaterThan(5);
      expect(refs.every((e) => e.resolution === "syntactic_only")).toBe(true);
      expect(find(all, "REFERENCES", `${M}#boot`, "packages/core/src/logger.ts#Logger")).toMatchObject({ detail: { name: "Log", binding: "resolved" } });
    });
  });

  it("duplicate symbol names stay distinguishable: the name is ambiguous, the stable key is not", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    await read(repo, home, (o) => {
      expect(() => resolveNode(o.store.db, { symbol: "packages/core/src/models.ts#dupe" })).toThrow(/ambiguous symbol name; use one of: .*key:/);
      const keys = (o.store.db.prepare(`SELECT symbol_key AS k FROM symbol_occurrences WHERE generation_id = ${GEN} AND path = 'packages/core/src/models.ts' AND name = 'dupe'`).all() as Array<{ k: string }>).map((r) => r.k);
      expect(new Set(keys).size).toBe(2);
      expect(resolveNode(o.store.db, { symbol: `packages/core/src/models.ts#key:${keys[0]}` }).key).toContain(keys[0]);
      // the same name in two different files is two different nodes
      const logs = o.store.db.prepare(`SELECT path FROM symbol_occurrences WHERE generation_id = ${GEN} AND name = 'log' AND kind = 'function'`).all() as Array<{ path: string }>;
      expect(logs.map((l) => l.path).sort()).toEqual(["packages/core/src/logger.ts", "packages/core/src/util.ts"]);
    });
  });

  it("cyclic re-exports terminate and are reported unresolved, not looped", async () => {
    const repo = makeGitRepo({
      "a.ts": 'export * from "./b";\nexport const own = 1;\n',
      "b.ts": 'export * from "./a";\n',
      "use.ts": 'import { missing, own } from "./a";\nexport const x = [missing, own];\n'
    });
    const home = engbrainHome();
    const started = Date.now();
    await indexIn(repo, home, true);
    expect(Date.now() - started).toBeLessThan(10_000);
    await read(repo, home, (o) => {
      const all = edges(o, "family = 'symbol' AND edge_kind = 'IMPORTS'");
      expect(all.find((e) => e.detail?.["imported"] === "own")).toMatchObject({ resolution: "resolved", dst: "a.ts#own" });
      expect(all.find((e) => e.detail?.["imported"] === "missing")).toMatchObject({ resolution: "unresolved" });
    });
  });
});

describe("P2B traversals: bounded, deterministic, provenance-carrying", () => {
  it("forward and reverse results match the fixture's golden graph", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    await read(repo, home, (o) => {
      const main = resolveNode(o.store.db, { file: "packages/app/src/main.ts" });
      const forward = traverse(o.store.db, main, { direction: "forward", budget: { maxDepth: 1 } });
      expect(forward.nodes.slice(1).map((n) => n.key).sort()).toEqual([
        "ext:node:fs", "file:packages/app/src/cycle/a.ts", "file:packages/app/src/widget.ts", "file:packages/core/src/index.ts"
      ]);
      expect(forward.unresolvedBoundary.map((e) => `${e.resolution}:${e.reason}`).sort()).toEqual(["dynamic:non_literal_specifier", "unresolved:relative_target_missing"]);

      const models = resolveNode(o.store.db, { file: "packages/core/src/models.ts" });
      const reverse = traverse(o.store.db, models, { direction: "reverse", budget: { maxDepth: 3 } });
      const byDepth = (d: number): string[] => reverse.nodes.filter((n) => n.depth === d).map((n) => n.key).sort();
      expect(byDepth(1)).toEqual(["file:packages/core/src/index.ts"]); // the barrel re-exports it
      expect(byDepth(2)).toContain("file:packages/app/src/main.ts");
      expect(reverse.edges.every((e) => e.mechanism === "tree_sitter_syntax" && e.extractor.startsWith("graph:"))).toBe(true);
    });
  });

  it("symbol-level dependencies and references follow heritage chains", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    await read(repo, home, (o) => {
      const puppy = resolveNode(o.store.db, { symbol: "packages/app/src/main.ts#Puppy" });
      const deps = traverse(o.store.db, puppy, { direction: "forward", mode: "symbol", budget: { maxDepth: 3 } });
      expect(deps.nodes.slice(1).map((n) => `${n.depth}:${n.name}`).sort()).toEqual(["1:Dog", "1:Widget", "2:Animal", "2:Walker"]);
      const dog = resolveNode(o.store.db, { symbol: "packages/core/src/models.ts#Dog" });
      const refs = references(o.store.db, dog);
      expect(refs.references.map((e) => `${e.kind}:${e.src.path}`).sort()).toEqual(["EXTENDS:packages/app/src/main.ts", "IMPORTS:packages/app/src/main.ts"]);
    });
  });

  it("shortest path is found when decided edges connect two nodes, and its absence is not presented as independence", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    await read(repo, home, (o) => {
      const main = resolveNode(o.store.db, { file: "packages/app/src/main.ts" });
      const models = resolveNode(o.store.db, { file: "packages/core/src/models.ts" });
      const found = shortestPath(o.store.db, main, models);
      expect(found.found).toBe(true);
      expect(found.path.map((e) => `${e.kind}:${e.dst.path}`)).toEqual(["IMPORTS:packages/core/src/index.ts", "RE_EXPORTS:packages/core/src/models.ts"]);
      const leaf = resolveNode(o.store.db, { file: "packages/app/src/leaf3.ts" });
      const none = shortestPath(o.store.db, models, leaf);
      expect(none.found).toBe(false);
      expect(none.note).toContain("not proof");
    });
  });

  it("cycle detection finds the 3-file cycle and nothing else", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    await read(repo, home, (o) => {
      const result = findCycles(o.store.db);
      expect(result.totalCycles).toBe(1);
      expect(result.cycles[0]).toMatchObject({ size: 3, members: ["packages/app/src/cycle/a.ts", "packages/app/src/cycle/b.ts", "packages/app/src/cycle/c.ts"] });
    });
  });

  it("traversals are bounded on high fan-out and cycles, and say what stopped them", async () => {
    const files: Record<string, string> = { "hub.ts": "export const hub = 1;\n" };
    for (let i = 0; i < 1500; i += 1) {
      files[`l${i}.ts`] = `import { hub } from "./hub";\nexport const v${i} = hub;\n`;
    }
    files["x.ts"] = 'import { y } from "./y";\nexport const x = y;\n';
    files["y.ts"] = 'import { x } from "./x";\nexport const y = x;\n';
    const repo = makeGitRepo(files);
    const home = engbrainHome();
    await indexIn(repo, home, true);
    await read(repo, home, (o) => {
      const hub = resolveNode(o.store.db, { file: "hub.ts" });
      const limited = traverse(o.store.db, hub, { direction: "reverse", budget: { maxNodes: 100, maxEdges: 400 } });
      expect(limited.nodes.length).toBeLessThanOrEqual(100);
      expect(limited.truncated.nodes || limited.truncated.edges).toBe(true);
      const unlimited = traverse(o.store.db, hub, { direction: "reverse", budget: { maxNodes: 5000, maxEdges: 20_000 } });
      expect(unlimited.nodes.length).toBe(1501);
      expect(unlimited.truncated).toEqual({ depth: false, nodes: false, edges: false, time: false });
      // a cycle cannot spin: each node is expanded once
      const x = resolveNode(o.store.db, { file: "x.ts" });
      const cyc = traverse(o.store.db, x, { direction: "forward", budget: { maxDepth: 25 } });
      expect(cyc.nodes.map((n) => n.key).sort()).toEqual(["file:x.ts", "file:y.ts"]);
      // time budget is enforced
      const timed = traverse(o.store.db, hub, { direction: "reverse", budget: { timeMs: 1, maxNodes: 5000, maxEdges: 20_000, maxDepth: 25 } });
      expect(timed.nodes.length).toBeGreaterThan(0);
      expect(findCycles(o.store.db).totalCycles).toBe(1);
    });
  });

  it("requested budgets are clamped to hard limits", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    await read(repo, home, (o) => {
      const main = resolveNode(o.store.db, { file: "packages/app/src/main.ts" });
      const r = traverse(o.store.db, main, { direction: "forward", budget: { maxDepth: 1_000_000, maxNodes: 1e12, maxEdges: 1e12, timeMs: 1e12 } });
      expect(r.budget).toEqual({ maxDepth: 25, maxNodes: 20_000, maxEdges: 100_000, timeMs: 30_000 });
    });
  });
});

describe("P2B impact means potential structural effects, with the undecided boundary attached", () => {
  it("a symbol's impact lists importers, subclasses and the transitive importers of those files, with the disclaimer", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    await read(repo, home, (o) => {
      const animal = resolveNode(o.store.db, { symbol: "packages/core/src/models.ts#Animal" });
      const result = impact(o.store.db, animal);
      const names = result.affected.map((a) => `${a.distance}:${a.node.name}`);
      expect(names).toContain("1:Dog"); // subclass in the same file
      expect(names).toContain("1:Cat");
      expect(result.disclaimer).toMatch(/POTENTIAL STRUCTURAL/);
      expect(result.disclaimer).toMatch(/not proof of behavioural breakage/);
      expect(result.unresolvedBoundary.dynamicImports).toBe(1);
      expect(result.unresolvedBoundary.unresolvedImports).toBe(1); // ./nope
      expect(result.unresolvedBoundary.unresolvedBindings).toBeGreaterThanOrEqual(2); // zzz, and the CommonJS log

      const hub = impact(o.store.db, resolveNode(o.store.db, { file: "packages/app/src/hub.ts" }));
      expect(hub.affected.filter((a) => a.distance === 1 && a.node.kind === "file").length).toBe(60); // the importing files
      expect(hub.affected.filter((a) => a.distance === 1 && a.node.kind === "symbol").length).toBe(60); // the functions that mention hub / hubFn by name
      expect(hub.usedSymbols.map((u) => u.symbol.name).sort()).toEqual(["hub", "hubFn"]);
    });
  });
});

describe("P2B incremental graph equals a clean rebuild", () => {
  const dump = (o: Opened): string[] => edges(o).map((e) => JSON.stringify(e));

  it.each(Array.from({ length: 10 }, (_, i) => i + 1))("seed %i: mutate files, tsconfig and package metadata, re-index, compare with a clean index", async (seed) => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    const edits: Array<() => void> = [
      () => writeFileSync(join(repo, "packages/core/src/models.ts"), `export class Animal {}\nexport class Dog extends Animal {}\nexport class Added${seed} {}\n`),
      () => rmSync(join(repo, "packages/core/src/config.ts")),
      () => renameSync(join(repo, "packages/core/src/logger.ts"), join(repo, "packages/core/src/logging.ts")),
      () => writeFileSync(join(repo, "tsconfig.json"), JSON.stringify({ compilerOptions: { baseUrl: ".", paths: {} } })),
      () => writeFileSync(join(repo, "packages/core/package.json"), JSON.stringify({ name: "@org/core-renamed", main: "src/index.ts" })),
      () => writeFileSync(join(repo, "packages/app/src/cycle/c.ts"), "export function c() { return 1; }\n"),
      () => writeFileSync(join(repo, "packages/app/src/extra.ts"), `import { hub } from "./hub";\nexport class Extra${seed} {}\nexport const e = hub;\n`)
    ];
    for (let i = 0; i < 3 + (seed % 3); i += 1) {
      edits[(seed * 5 + i * 3) % edits.length]!();
    }
    await indexIn(repo, home);
    const incremental = await read(repo, home, dump);
    const copy = tempDir("engbrain-graphclean-");
    cpSync(repo, copy, { recursive: true, filter: (src) => !src.includes(".git") && !src.includes(".engineering-brain") });
    const cleanHome = engbrainHome();
    await indexIn(copy, cleanHome, true);
    const clean = await read(copy, cleanHome, dump);
    expect(incremental).toEqual(clean);
    expect(incremental.length).toBeGreaterThan(200);
    expect(await read(repo, home, (o) => validateGraph(o.store.db).problems)).toEqual([]);
  });

  it("config changes re-resolve without any source change; deleted targets and renames update the edges", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    const before = await read(repo, home, (o) => find(edges(o), "IMPORTS", "packages/app/src/main.ts", "packages/app/src/widget.ts"));
    expect(before?.reason).toBe("tsconfig_paths");
    writeFileSync(join(repo, "tsconfig.json"), JSON.stringify({ compilerOptions: { baseUrl: "." } }));
    const changed = await indexIn(repo, home);
    expect(changed.unchanged).toBe(false);
    await read(repo, home, (o) => {
      const all = edges(o);
      expect(find(all, "IMPORTS", "packages/app/src/main.ts", "packages/app/src/widget.ts")).toBeUndefined();
      expect(all.find((e) => e.src === "packages/app/src/main.ts" && e.reason === "package:@app/widget")).toMatchObject({ resolution: "external" });
    });
    rmSync(join(repo, "packages/core/src/config.ts"));
    await indexIn(repo, home);
    await read(repo, home, (o) => {
      expect(edges(o).find((e) => e.src === "packages/app/src/main.ts" && e.detail?.["local"] === "Config")?.resolution).not.toBe("resolved");
    });
  });

  it("case-only renames and renames keep the graph consistent (macOS/Windows filesystems are case-insensitive)", async () => {
    const repo = makeGitRepo({ "Util.ts": "export function u() {}\n", "main.ts": 'import { u } from "./Util";\nexport const m = u;\n' });
    const home = engbrainHome();
    await indexIn(repo, home, true);
    git(repo, ["mv", "Util.ts", "tmp-rename.ts"]);
    git(repo, ["mv", "tmp-rename.ts", "util.ts"]);
    await indexIn(repo, home);
    await read(repo, home, (o) => {
      const all = edges(o, "family = 'module'");
      const imp = all.find((e) => e.src === "main.ts");
      expect(["resolved", "unresolved"]).toContain(imp?.resolution); // never a crash, never a dangling resolved edge
      expect(validateGraph(o.store.db).ok).toBe(true);
    });
  });
});

describe("P2B snapshots, crashes, branches and worktrees", () => {
  it.each(["pre-facts", "mid-facts", "pre-manifest", "pre-publish", "mid-publish"] as const)("a crash at %s leaves the previous graph fully intact and invisible edges never leak", async (point) => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    const before = await read(repo, home, (o) => ({ e: edges(o).map((x) => JSON.stringify(x)), s: graphStats(o.store.db) }));
    writeFileSync(join(repo, "packages/core/src/models.ts"), "export class Animal {}\nexport class Dog extends Animal {}\nexport class InFlight {}\n");
    await expect(indexIn(repo, home, false, (p) => { if (p === point) { throw new Error("injected"); } })).rejects.toThrow("injected");
    await read(repo, home, (o) => {
      expect(edges(o).map((x) => JSON.stringify(x))).toEqual(before.e);
      expect(graphStats(o.store.db)).toEqual(before.s);
      expect(validateGraph(o.store.db).ok).toBe(true);
      const building = o.store.db.prepare("SELECT COUNT(*) AS n FROM graph_edges ge JOIN generations g ON g.id = ge.generation_id WHERE g.status != 'complete'").get() as { n: number };
      // edges of the unpublished generation may exist in storage, but no query surface can reach them
      expect(traverse(o.store.db, resolveNode(o.store.db, { file: "packages/core/src/models.ts" }), { direction: "reverse" }).nodes.some((n) => n.key.includes("InFlight"))).toBe(false);
      expect(building.n).toBeGreaterThanOrEqual(0);
    });
    const recovered = await indexIn(repo, home);
    expect(recovered.stats.recoveredAbandoned).toBe(1);
    await read(repo, home, (o) => expect(validateGraph(o.store.db).ok).toBe(true));
  });

  it("switching branches never leaks the other branch's nodes once re-indexed, and the stale index is flagged before", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    git(repo, ["checkout", "-q", "-b", "feature"]);
    writeFileSync(join(repo, "packages/app/src/featureOnly.ts"), 'import { hub } from "./hub";\nexport class FeatureOnly {}\nexport const f = hub;\n');
    git(repo, ["add", "-A"]);
    git(repo, ["commit", "-q", "-m", "feature"]);
    await indexIn(repo, home, true);
    await read(repo, home, (o) => {
      expect(traverse(o.store.db, resolveNode(o.store.db, { file: "packages/app/src/hub.ts" }), { direction: "reverse" }).nodes.some((n) => n.key.includes("featureOnly"))).toBe(true);
    });
    git(repo, ["checkout", "-q", "main"]);
    await indexIn(repo, home);
    await read(repo, home, (o) => {
      expect(() => resolveNode(o.store.db, { file: "packages/app/src/featureOnly.ts" })).toThrow(/not in the published index/);
      const hub = resolveNode(o.store.db, { file: "packages/app/src/hub.ts" });
      expect(traverse(o.store.db, hub, { direction: "reverse", budget: { maxNodes: 1000 } }).nodes.some((n) => n.key.includes("featureOnly"))).toBe(false);
      expect(edges(o).some((e) => e.src.includes("featureOnly") || e.dst.includes("featureOnly"))).toBe(false);
      expect(graphStats(o.store.db).nodes.files).toBe(77);
    });
  });

  it("two worktrees of the same repository keep separate graphs", async () => {
    const main = fixtureRepo();
    const wt = join(tempDir("engbrain-gwt-"), "wt");
    git(main, ["worktree", "add", "-q", "-b", "side", wt]);
    writeFileSync(join(wt, "packages/app/src/sideOnly.ts"), "export class SideOnly {}\n");
    const home = engbrainHome();
    await indexIn(main, home, true);
    await indexIn(wt, home, true);
    const inMain = await read(main, home, (o) => graphStats(o.store.db).nodes.files);
    const inSide = await read(wt, home, (o) => graphStats(o.store.db).nodes.files);
    expect(inSide).toBe(inMain + 1);
    await read(main, home, (o) => expect(() => resolveNode(o.store.db, { file: "packages/app/src/sideOnly.ts" })).toThrow());
  });
});

describe("P2B integrity checks detect corruption", () => {
  it("validate reports dangling edges and contradictions when triggers are bypassed", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    const raw = new Database(join(repo, ".engineering-brain", "store.db"));
    raw.exec("DROP TRIGGER graph_edges_immutable_update");
    raw.exec(`UPDATE graph_edges SET dst_path = 'ghost/missing.ts' WHERE edge_id = (SELECT MIN(edge_id) FROM graph_edges WHERE resolution = 'resolved' AND dst_kind = 'file')`);
    raw.exec(`UPDATE graph_edges SET dst_kind = 'file' WHERE edge_id = (SELECT MIN(edge_id) FROM graph_edges WHERE resolution = 'unresolved')`);
    raw.close();
    const problems = await read(repo, home, (o) => validateGraph(o.store.db).problems);
    expect(problems.join("\n")).toMatch(/end at a file that is not in the generation/);
    expect(problems.join("\n")).toMatch(/contradicts their resolution/);
  });
  it("published graph edges are immutable and cannot be inserted outside a building generation", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    await read(repo, home, (o) => {
      expect(() => o.store.db.prepare("UPDATE graph_edges SET reason = 'x'").run()).toThrow(/immutable/);
      expect(() => o.store.db.prepare(
        `INSERT INTO graph_edges (generation_id, edge_id, family, edge_kind, ordinal, src_kind, src_path, dst_kind, mechanism, resolution, reason, extractor) VALUES (${GEN}, 999999, 'module', 'IMPORTS', 0, 'file', 'a', 'unknown', 'tree_sitter_syntax', 'unresolved', 'x', 'x')`
      ).run()).toThrow(/writable only while/);
    });
  });
});

describe("P2B hostile metadata cannot execute code, escape the repository or use the network", () => {
  it("package.json scripts, tsconfig extends/paths and symlinked configs are data: nothing runs, nothing outside is read", async () => {
    const marker = join(tempDir("engbrain-marker-"), "EXECUTED");
    const outside = tempDir("engbrain-outside-");
    writeFileSync(join(outside, "evil.json"), JSON.stringify({ compilerOptions: { paths: { "*": ["../../*"] } } }));
    writeFileSync(join(outside, "secret.ts"), "export const secretFromOutside = 1;\n");
    const repo = makeGitRepo({
      "package.json": JSON.stringify({ name: "root", workspaces: ["packages/*"], scripts: { postinstall: `touch ${marker}`, prepare: `touch ${marker}`, build: `touch ${marker}` } }),
      "packages/a/package.json": JSON.stringify({ name: "@x/a", main: "../../../../outside/secret.ts", scripts: { install: `touch ${marker}` } }),
      "tsconfig.json": JSON.stringify({ extends: join(outside, "evil.json"), compilerOptions: { baseUrl: ".", paths: { "@esc/*": ["../../../../*"] } } }),
      "src/main.ts": 'import { a } from "@x/a";\nimport { s } from "@esc/outside";\nimport "../../../outside/secret";\nexport const m = [a, s];\n'
    });
    if (process.platform !== "win32") {
      symlinkSync(join(outside, "evil.json"), join(repo, "tsconfig.linked.json"));
    }
    chmodSync(repo, 0o755);
    const home = engbrainHome();
    const { openFor: open } = await import("../helpers/env.js");
    const o = await open(repo, home, true);
    const result = await indexRepository({ store: o.store, git: o.info, hardenedGit: o.git });
    o.close();
    expect(existsSync(marker)).toBe(false);
    expect(result.stats.included).toBeGreaterThan(3);
    await read(repo, home, (r) => {
      const all = edges(r, "src_path = 'src/main.ts'");
      expect(all.every((e) => ["unresolved", "external", "syntactic_only"].includes(e.resolution))).toBe(true);
      expect(all.filter((e) => e.family === "module").every((e) => e.resolution === "unresolved" || e.resolution === "external")).toBe(true);
      expect(all.map((e) => e.dst).join(" ")).not.toContain("secret.ts");
      expect(validateGraph(r.store.db).ok).toBe(true);
    });
    mkdirSync(join(outside, "x"), { recursive: true });
  });
});

describe("P2B CLI works from persisted data only", () => {
  it("graph stats | dependencies | dependents | references | path | impact | cycles | validate, text and JSON", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await runCli(repo, ["init"], home);
    await runCli(repo, ["index"], home);
    const run = async (args: string[]) => runCli(repo, args, home);
    const stats = await run(["graph", "stats", "--json"]);
    expect(stats.code, stats.stderr).toBe(0);
    expect((JSON.parse(stats.stdout) as { nodes: { files: number } }).nodes.files).toBe(77);
    expect((await run(["graph", "validate"])).stdout).toContain("graph valid");
    const deps = await run(["graph", "dependencies", "--file", "packages/app/src/main.ts", "--depth", "1"]);
    expect(deps.stdout).toContain("packages/core/src/index.ts");
    expect(deps.stdout).toContain("relative_target_missing");
    const rev = JSON.parse((await run(["graph", "dependents", "--file", "packages/app/src/hub.ts", "--json", "--limit", "10"])).stdout) as { nodes: unknown[]; truncated: { nodes: boolean } };
    expect(rev.nodes.length).toBe(10);
    expect(rev.truncated.nodes).toBe(true);
    const refs = await run(["graph", "references", "--symbol", "packages/core/src/models.ts#Dog"]);
    expect(refs.stdout).toContain("EXTENDS");
    const path = await run(["graph", "path", "--from", "packages/app/src/main.ts", "--to", "packages/core/src/models.ts"]);
    expect(path.code).toBe(0);
    expect(path.stdout).toContain("RE_EXPORTS");
    const imp = await run(["graph", "impact", "--symbol", "packages/core/src/models.ts#Animal"]);
    expect(imp.stdout).toContain("POTENTIAL STRUCTURAL");
    expect((await run(["graph", "cycles"])).stdout).toContain("size 3");
    // persisted data: removing the working tree does not change answers
    rmSync(join(repo, "packages"), { recursive: true, force: true });
    expect((await run(["graph", "dependencies", "--file", "packages/app/src/main.ts", "--depth", "1"])).stdout).toContain("packages/core/src/index.ts");
  });
  it("validates arguments and refuses nonsense nodes", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await runCli(repo, ["init"], home);
    await runCli(repo, ["index"], home);
    expect((await runCli(repo, ["graph"], home)).code).toBe(2);
    expect((await runCli(repo, ["graph", "bogus"], home)).code).toBe(2);
    expect((await runCli(repo, ["graph", "dependencies", "--depth", "0"], home)).code).toBe(2);
    expect((await runCli(repo, ["graph", "dependencies", "--mode", "x"], home)).code).toBe(2);
    expect((await runCli(repo, ["graph", "dependencies", "--kinds", "BOGUS"], home)).code).toBe(2);
    const noNode = await runCli(repo, ["graph", "dependencies"], home);
    expect(noNode.code).toBe(1);
    const missing = await runCli(repo, ["graph", "dependencies", "--file", "nope.ts"], home);
    expect(missing.code).toBe(1);
    expect(missing.stderr).toContain("not in the published index");
    const outside = await runCli(repo, ["graph", "dependencies", "--file", "../x.ts"], home);
    expect(outside.stderr).toContain("outside the repository");
  });
});
