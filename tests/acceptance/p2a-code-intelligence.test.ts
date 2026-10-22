import { mkdirSync, renameSync, rmSync, symlinkSync, utimesSync, writeFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import {
  checkFreshness, findModuleEdges, findSymbols, indexRepository, type Extractor, type FaultPoint, type SymbolRecord
} from "@engbrain/core";
import { installNetworkGuard } from "@engbrain/security";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, engbrainHome, git, makeGitRepo, openFor, runCli, tempDir, writeFiles } from "../helpers/env.js";
import { p2aExcluded, p2aFiles } from "../helpers/p2a-fixture.js";

afterAll(cleanupTempDirs);

async function indexIn(repo: string, home: string, init = false, extra: { fault?: (p: FaultPoint) => void; extractors?: readonly Extractor[] } = {}) {
  const o = await openFor(repo, home, init);
  try {
    const result = await indexRepository({ store: o.store, git: o.info, hardenedGit: o.git, ...(extra.fault ? { fault: extra.fault } : {}), ...(extra.extractors ? { extractors: extra.extractors } : {}) });
    return { result, store: o.store, info: o.info };
  } finally {
    o.close();
  }
}

/** Runs a read against the persisted store, as a reader (separate handle) would. */
async function read<T>(repo: string, home: string, fn: (o: Awaited<ReturnType<typeof openFor>>) => T | Promise<T>): Promise<T> {
  const o = await openFor(repo, home);
  try {
    return await fn(o);
  } finally {
    o.close();
  }
}

function fixtureRepo(): string {
  const repo = makeGitRepo(p2aFiles());
  writeFiles(repo, p2aExcluded()); // untracked: indexing must still exclude them
  return repo;
}

const names = (rows: SymbolRecord[]): string[] => rows.map((r) => `${r.kind}:${r.qualifiedName}`);

describe("P2A symbols are extracted and persisted", () => {
  it("JavaScript, TypeScript, JSX and TSX symbols come back from persisted SQLite storage", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    await read(repo, home, ({ store }) => {
      const at = (file: string) => names(findSymbols(store.db, { file }).rows);
      expect(at("src/legacy.js")).toEqual(["function:legacy"]); // JS (CommonJS)
      expect(at("src/auth/refreshToken.ts")).toEqual([
        "function:refreshToken", "function:refreshToken.sign", "function:refreshToken.wrap", "class:TokenStore", "constructor:TokenStore.constructor", "method:TokenStore.put"
      ]);
      expect(at("src/components/App.tsx")).toContain("function:App"); // TSX
      expect(at("src/components/Button.jsx")).toEqual(["function:Button"]); // JSX
      expect(at("packages/lib/src/index.ts")).toEqual(["function:libFn", "variable:LIB_VERSION"]);
    });
  });

  it("nested symbols keep correct ownership (parent chain)", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    await read(repo, home, ({ store }) => {
      const rows = findSymbols(store.db, { file: "src/auth/refreshToken.ts" }).rows;
      const parent = (q: string): string | null => rows.find((r) => r.qualifiedName === q)?.parent ?? "MISSING";
      expect(parent("refreshToken.sign")).toBe("refreshToken");
      expect(parent("refreshToken.wrap")).toBe("refreshToken");
      expect(parent("TokenStore.put")).toBe("TokenStore");
      expect(parent("TokenStore.constructor")).toBe("TokenStore");
      expect(parent("refreshToken")).toBe(""); // owned by the module
    });
  });

  it("default exports, aliased re-exports, export-all and namespace re-exports are represented", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    await read(repo, home, ({ store }) => {
      const exportsOf = (path: string) =>
        (store.db.prepare(
          `SELECT e.export_kind AS kind, e.export_name AS name, e.local_name AS local, e.source_text AS source
           FROM generation_files gf JOIN exports e ON e.content_hash = gf.content_hash
           WHERE gf.generation_id = (SELECT current_generation_id FROM store_meta) AND gf.path = ? ORDER BY e.local_id`
        ).all(path) as Array<{ kind: string; name: string | null; local: string | null; source: string | null }>).map((e) => `${e.kind}:${e.name ?? "-"}<-${e.local ?? "-"}@${e.source ?? ""}`);
      expect(exportsOf("src/index.ts")).toEqual(["reexport_all:-<--@./auth", "reexport:utilHelper<-helper@./util", "reexport_namespace:constants<--@./constants"]);
      expect(exportsOf("src/auth/index.ts")).toEqual(["reexport:refreshToken<-refreshToken@./refreshToken", "reexport:Session<-default@./session"]);
      expect(exportsOf("src/auth/session.ts")).toEqual(["default:default<-Session@"]);
      expect(exportsOf("src/components/App.tsx")).toEqual(["named:App<-App@", "default:default<-App@"]);
      expect(exportsOf("src/legacy.js")).toEqual(["commonjs:legacy<-legacy@", "commonjs:extra<--@"]);
    });
  });

  it("anonymous exports and callbacks are handled safely; duplicate names stay distinguishable", async () => {
    const repo = makeGitRepo({
      "anon.ts": "export default function () {}\nsetTimeout(function () {}, 1);\n[1].map((x) => x);\n",
      "dup1.ts": "export function same() {}\nexport function same() {}\n",
      "dup2.ts": "export function same() {}\n"
    });
    const home = engbrainHome();
    await indexIn(repo, home, true);
    await read(repo, home, ({ store }) => {
      expect(findSymbols(store.db, { file: "anon.ts" }).rows).toEqual([expect.objectContaining({ name: "default", anonymous: true, exported: true })]);
      const same = findSymbols(store.db, { search: "same" }).rows;
      expect(same.length).toBe(3);
      expect(new Set(same.map((s) => `${s.path}#${s.symbolKey}`)).size).toBe(3);
      expect(findSymbols(store.db, { file: "dup1.ts" }).rows.map((s) => s.symbolKey).reduce((u, k) => u.add(k), new Set<string>()).size).toBe(2);
    });
  });

  it("search is a safe substring match (LIKE metacharacters are literal) and results are bounded", async () => {
    const repo = makeGitRepo({ "a.ts": "export function a_b() {}\nexport function axb() {}\nexport function pct() {}\n" });
    const home = engbrainHome();
    await indexIn(repo, home, true);
    await read(repo, home, ({ store }) => {
      expect(names(findSymbols(store.db, { search: "a_b" }).rows)).toEqual(["function:a_b"]); // `_` is not a wildcard
      expect(findSymbols(store.db, { search: "%" }).rows).toEqual([]);
      expect(findSymbols(store.db, { search: "' OR 1=1 --" }).rows).toEqual([]);
      const limited = findSymbols(store.db, { limit: 2 });
      expect(limited.rows.length).toBe(2);
      expect(limited.truncated).toBe(true);
    });
  });
});

describe("P2A module relationships", () => {
  it("relative, alias, workspace, builtin and package imports are classified; barrels and requires are edges", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    await read(repo, home, ({ store }) => {
      const edge = (from: string, spec: string) => findModuleEdges(store.db, { from }).rows.find((e) => e.specifier === spec)!;
      expect(edge("src/auth/refreshToken.ts", "../util")).toMatchObject({ resolution: "resolved", resolvedPath: "src/util.ts" });
      expect(edge("src/auth/refreshToken.ts", "@app/constants")).toMatchObject({ resolution: "resolved", resolvedPath: "src/constants.ts", reason: "tsconfig_paths" });
      expect(edge("src/auth/refreshToken.ts", "@org/lib")).toMatchObject({ resolution: "resolved", resolvedPath: "packages/lib/src/index.ts" });
      expect(edge("src/auth/refreshToken.ts", "node:fs")).toMatchObject({ resolution: "external", reason: "node_builtin" });
      expect(edge("src/auth/refreshToken.ts", "lodash")).toMatchObject({ resolution: "external", reason: "package:lodash" });
      expect(edge("src/index.ts", "./auth")).toMatchObject({ kind: "export_from", resolvedPath: "src/auth/index.ts" }); // barrel
      expect(edge("src/legacy.js", "./util")).toMatchObject({ kind: "require", resolvedPath: "src/util.ts" });
      expect(edge("src/components/App.tsx", "./Button")).toMatchObject({ resolvedPath: "src/components/Button.jsx" });
    });
  });

  it("dynamic imports resolve only when the target is a literal; otherwise they stay unknown", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    await read(repo, home, ({ store }) => {
      const edges = findModuleEdges(store.db, { from: "src/dynamic.ts" }).rows;
      expect(edges.find((e) => e.kind === "dynamic_import" && e.specifier === "./util")).toMatchObject({ resolution: "resolved", resolvedPath: "src/util.ts" });
      expect(edges.find((e) => e.kind === "dynamic_import" && e.specifier === null)).toMatchObject({ resolution: "dynamic", resolvedPath: null });
      expect(edges.find((e) => e.kind === "require")).toMatchObject({ resolvedPath: "src/constants.ts" });
    });
  });

  it("missing targets are unresolved and colliding module families are ambiguous (never guessed)", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    await read(repo, home, ({ store }) => {
      expect(findModuleEdges(store.db, { from: "src/missing.ts" }).rows[0]).toMatchObject({ resolution: "unresolved", resolvedPath: null, reason: "relative_target_missing" });
      expect(findModuleEdges(store.db, { from: "src/useAmbiguous.ts" }).rows[0]).toMatchObject({ resolution: "ambiguous", resolvedPath: null });
    });
  });

  it("circular imports index fine and both directions resolve", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    await read(repo, home, ({ store }) => {
      expect(findModuleEdges(store.db, { from: "src/circular/a.ts" }).rows[0]).toMatchObject({ resolvedPath: "src/circular/b.ts" });
      expect(findModuleEdges(store.db, { from: "src/circular/b.ts" }).rows[0]).toMatchObject({ resolvedPath: "src/circular/a.ts" });
    });
  });

  it("reverse lookup answers 'who imports this file' from persisted edges", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    await read(repo, home, ({ store }) => {
      const importers = findModuleEdges(store.db, { to: "src/util.ts" }).rows.map((e) => e.from).sort();
      expect(importers).toEqual(["src/auth/refreshToken.ts", "src/dynamic.ts", "src/index.ts", "src/legacy.js"]);
    });
  });
});

describe("P2A exclusions, unsupported languages and diagnostics", () => {
  it("excluded files never reach the source index (no manifest entry with content, no symbols, no edges)", async () => {
    const repo = fixtureRepo();
    writeFiles(repo, { "src/secretive.ts": `export function leakedSymbol() {}\nconst k = "${["AK", "IA", "ABCDEFGH", "IJKLMNOP"].join("")}";\n` });
    const home = engbrainHome();
    const { result } = await indexIn(repo, home, true);
    expect(result.stats.excludedByReason).toEqual({ sensitive_path: 2, "secret:aws_access_key_id": 1 }); // node_modules/ and dist/ are pruned, not enumerated
    await read(repo, home, ({ store }) => {
      expect(findSymbols(store.db, { search: "leakedSymbol" }).rows).toEqual([]);
      expect(findSymbols(store.db, { search: "pkg" }).rows).toEqual([]);
      expect(findSymbols(store.db, { search: "built" }).rows).toEqual([]);
      expect(findModuleEdges(store.db, { from: "src/secretive.ts" }).rows).toEqual([]);
      const included = store.db.prepare("SELECT path FROM generation_files WHERE content_hash IS NOT NULL").all() as Array<{ path: string }>;
      expect(included.map((r) => r.path).filter((p) => /node_modules|dist\/|\.env|\.pem|secretive/.test(p))).toEqual([]);
    });
  });

  it("unsupported languages are counted as unsupported and never crash indexing", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    const { result } = await indexIn(repo, home, true);
    expect(result.summary.parser.skipped).toBe(6); // json x4 (incl. package.json/tsconfig), markdown, python
    expect(result.summary.byLanguage).toMatchObject({ python: 1, markdown: 1, json: 4 });
    await read(repo, home, ({ store }) => expect(findSymbols(store.db, { file: "scripts/tool.py" }).rows).toEqual([]));
  });

  it("a syntax error yields persisted diagnostics, keeps the rest of the repository intact, and corrupts nothing", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    const { result } = await indexIn(repo, home, true);
    expect(result.summary.parser.error).toBe(1);
    expect(result.summary.diagnostics).toBeGreaterThan(0);
    await read(repo, home, ({ store }) => {
      const diag = store.db.prepare(
        `SELECT fd.code AS code, fd.line AS line FROM generation_files gf JOIN fact_diagnostics fd ON fd.content_hash = gf.content_hash
         WHERE gf.path = 'src/broken.ts' AND gf.generation_id = (SELECT current_generation_id FROM store_meta)`
      ).all() as Array<{ code: string; line: number }>;
      expect(diag.length).toBeGreaterThan(0);
      expect(diag[0]?.code).toMatch(/^syntax_/);
      expect(names(findSymbols(store.db, { file: "src/broken.ts" }).rows)).toContain("function:fine");
      expect(findSymbols(store.db, { file: "src/util.ts" }).rows.length).toBe(2);
      expect(store.db.pragma("integrity_check", { simple: true })).toBe("ok");
    });
  });

  it("an extractor that throws is contained: that file gets an error fact and the run still publishes", async () => {
    const repo = makeGitRepo({ "a.ts": "export const a = 1;\n", "b.ts": "export const b = 2;\n" });
    const exploding: Extractor = {
      id: "exploding", version: "1",
      extract: ({ path }) => { if (path === "b.ts") { throw new Error("internal detail must not leak"); } return { language: "typescript", parseStatus: "ok", attrs: {} }; }
    };
    const home = engbrainHome();
    const { result } = await indexIn(repo, home, true, { extractors: [exploding] });
    expect(result.stats.included).toBe(2);
    expect(result.unchanged).toBe(false);
    await read(repo, home, ({ store }) => {
      const rows = store.db.prepare("SELECT parse_status AS s, attrs_json AS a FROM file_facts WHERE extractor_id = 'exploding' ORDER BY content_hash").all() as Array<{ s: string; a: string }>;
      expect(rows.map((r) => r.s).sort()).toEqual(["error", "ok"]);
      expect(JSON.stringify(rows)).not.toContain("internal detail");
    });
  });
});

describe("P2A incremental indexing", () => {
  it("re-indexing without changes reuses every cached fact and parses nothing", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    const first = await indexIn(repo, home, true);
    expect(first.result.stats.parser.parsed).toBeGreaterThan(10);
    const second = await indexIn(repo, home);
    expect(second.result.unchanged).toBe(true);
    expect(second.result.stats.extractorRuns).toBe(0);
    expect(second.result.stats.parser).toMatchObject({ parsed: 0, failed: 0, skipped: 0 });
    expect(second.result.generationId).toBe(first.result.generationId);
  });

  it("modifying one file reparses only that file and updates its symbols, leaving every other fact untouched", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    const first = await indexIn(repo, home, true);
    const others = await read(repo, home, ({ store }) => findSymbols(store.db, { limit: 5000 }).rows.filter((r) => r.path !== "src/util.ts"));
    writeFileSync(join(repo, "src/util.ts"), "export function helper(v: string): string { return v.trim(); }\nexport function brandNew(n: number): number { return n; }\n");
    const second = await indexIn(repo, home);
    expect(second.result.unchanged).toBe(false);
    expect(second.result.stats.extractorRuns).toBe(1);
    expect(second.result.stats.parser.parsed).toBe(1);
    expect(second.result.stats.factsReused).toBe(first.result.stats.included - 1);
    expect(second.result.summary.changed).toEqual({ added: 0, modified: 1, deleted: 0, renamed: 0 });
    await read(repo, home, ({ store }) => {
      expect(names(findSymbols(store.db, { file: "src/util.ts" }).rows)).toEqual(["function:helper", "function:brandNew"]);
      const after = findSymbols(store.db, { limit: 5000 }).rows.filter((r) => r.path !== "src/util.ts");
      expect(after).toEqual(others); // byte-identical rows for every untouched file
    });
  });

  it("deleting a file removes its active symbols and turns its importers' edges into unresolved ones; history is retained", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    const first = await indexIn(repo, home, true);
    rmSync(join(repo, "src/util.ts"));
    const second = await indexIn(repo, home);
    expect(second.result.summary.changed).toEqual({ added: 0, modified: 0, deleted: 1, renamed: 0 });
    await read(repo, home, ({ store }) => {
      expect(findSymbols(store.db, { file: "src/util.ts" }).rows).toEqual([]);
      expect(findSymbols(store.db, { search: "helper" }).rows).toEqual([]);
      expect(findModuleEdges(store.db, { from: "src/auth/refreshToken.ts" }).rows.find((e) => e.specifier === "../util")).toMatchObject({ resolution: "unresolved", resolvedPath: null });
      expect(findModuleEdges(store.db, { to: "src/util.ts" }).rows).toEqual([]);
      // the previous generation still holds the old occurrences (retained snapshot)
      const old = store.db.prepare("SELECT COUNT(*) AS n FROM symbol_occurrences WHERE generation_id = ? AND path = 'src/util.ts'").get(first.result.generationId) as { n: number };
      expect(old.n).toBeGreaterThan(0);
    });
  });

  it("renaming a file reuses its facts, is counted as a rename, and relationships follow once importers are updated", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    renameSync(join(repo, "src/util.ts"), join(repo, "src/helpers.ts"));
    const renamed = await indexIn(repo, home);
    expect(renamed.result.summary.changed).toEqual({ added: 0, modified: 0, deleted: 0, renamed: 1 });
    expect(renamed.result.stats.extractorRuns).toBe(0); // same bytes, no reparse
    await read(repo, home, ({ store }) => {
      expect(names(findSymbols(store.db, { file: "src/helpers.ts" }).rows)).toEqual(["function:helper", "function:unused"]);
      expect(findModuleEdges(store.db, { from: "src/legacy.js" }).rows[0]).toMatchObject({ resolution: "unresolved" }); // importer still points at the old path
    });
    writeFileSync(join(repo, "src/legacy.js"), 'const { helper } = require("./helpers");\nfunction legacy(a, b) { return helper(a) + b; }\nmodule.exports = { legacy };\nexports.extra = 1;\n');
    await indexIn(repo, home);
    await read(repo, home, ({ store }) => {
      expect(findModuleEdges(store.db, { from: "src/legacy.js" }).rows[0]).toMatchObject({ resolution: "resolved", resolvedPath: "src/helpers.ts" });
    });
  });

  it("changing a tsconfig re-resolves relationships even though no source file changed", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    writeFileSync(join(repo, "tsconfig.json"), JSON.stringify({ compilerOptions: { baseUrl: ".", paths: {} } }));
    const next = await indexIn(repo, home);
    expect(next.result.unchanged).toBe(false);
    await read(repo, home, ({ store }) => {
      expect(findModuleEdges(store.db, { from: "src/auth/refreshToken.ts" }).rows.find((e) => e.specifier === "@app/constants")).toMatchObject({ resolution: "external" });
    });
  });
});

describe("P2A branches, dirty trees and interruption", () => {
  it("branch switching never leaks the other branch's symbols once re-indexed, and is flagged stale before", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    git(repo, ["checkout", "-q", "-b", "feature"]);
    writeFileSync(join(repo, "src/featureOnly.ts"), "export function onlyOnFeature() {}\n");
    git(repo, ["add", "-A"]);
    git(repo, ["commit", "-q", "-m", "feature"]);
    await indexIn(repo, home, true);
    await read(repo, home, ({ store }) => expect(findSymbols(store.db, { search: "onlyOnFeature" }).rows.length).toBe(1));

    git(repo, ["checkout", "-q", "main"]);
    const stale = await read(repo, home, async (o) => checkFreshness(o.store, o.info, o.git, { verify: false }));
    expect(stale.level).toBe("stale");
    expect(stale.revisionChanged).toBe(true);
    expect(stale.deleted).toContain("src/featureOnly.ts");

    await indexIn(repo, home);
    await read(repo, home, ({ store }) => {
      expect(findSymbols(store.db, { search: "onlyOnFeature" }).rows).toEqual([]);
      expect(findModuleEdges(store.db, { from: "src/featureOnly.ts" }).rows).toEqual([]);
    });
  });

  it("dirty worktree changes (modified and untracked) are indexed at the same revision with a different fingerprint", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    const clean = await indexIn(repo, home, true);
    writeFileSync(join(repo, "src/util.ts"), "export function helper(v: string): string { return v; }\nexport function dirtyEdit() {}\n");
    writeFileSync(join(repo, "src/untrackedNew.ts"), "export function brandNewUntracked() {}\n");
    const dirty = await indexIn(repo, home);
    expect(dirty.result.revision).toBe(clean.result.revision);
    expect(dirty.result.sourceFingerprint).not.toBe(clean.result.sourceFingerprint);
    await read(repo, home, ({ store }) => {
      expect(findSymbols(store.db, { search: "dirtyEdit" }).rows.length).toBe(1);
      expect(findSymbols(store.db, { search: "brandNewUntracked" }).rows.length).toBe(1);
    });
  });

  it.each(["pre-facts", "mid-facts", "pre-manifest", "pre-publish", "mid-publish"] as const)("an interruption at %s preserves the last valid symbols and edges", async (point) => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    const before = await read(repo, home, ({ store }) => ({ s: findSymbols(store.db, { limit: 5000 }), e: findModuleEdges(store.db, { limit: 5000 }) }));
    writeFileSync(join(repo, "src/util.ts"), "export function helper(v: string): string { return v; }\nexport function inFlight() {}\n");
    await expect(indexIn(repo, home, false, { fault: (p) => { if (p === point) { throw new Error("injected"); } } })).rejects.toThrow("injected");
    await read(repo, home, ({ store }) => {
      const after = { s: findSymbols(store.db, { limit: 5000 }), e: findModuleEdges(store.db, { limit: 5000 }) };
      expect(after).toEqual(before);
      expect(findSymbols(store.db, { search: "inFlight" }).rows).toEqual([]);
      expect(store.db.pragma("integrity_check", { simple: true })).toBe("ok");
    });
    const recovered = await indexIn(repo, home);
    expect(recovered.result.stats.recoveredAbandoned).toBe(1);
    await read(repo, home, ({ store }) => expect(findSymbols(store.db, { search: "inFlight" }).rows.length).toBe(1));
  });
});

describe("P2A clean and incremental indexing are equivalent", () => {
  function dumpCode(store: Awaited<ReturnType<typeof openFor>>["store"]): { symbols: string[]; edges: string[]; exports: string[]; fingerprint: string } {
    const g = "(SELECT current_generation_id FROM store_meta)";
    const symbols = (store.db.prepare(`SELECT path, kind, qualified_name AS q, start_byte AS sb, end_byte AS eb, exported AS ex, symbol_key AS k FROM symbol_occurrences WHERE generation_id = ${g} AND extractor_id LIKE 'code:%' ORDER BY path, start_byte, local_id`).all() as Array<Record<string, unknown>>).map((r) => JSON.stringify(r));
    const edges = (store.db.prepare(`SELECT from_path, ordinal, edge_kind, specifier, resolved_path, resolution, reason FROM module_edges WHERE generation_id = ${g} ORDER BY from_path, ordinal`).all() as Array<Record<string, unknown>>).map((r) => JSON.stringify(r));
    const exps = (store.db.prepare(`SELECT gf.path AS p, e.export_kind AS k, e.export_name AS n, e.local_name AS l, e.source_text AS s FROM generation_files gf JOIN exports e ON e.content_hash = gf.content_hash WHERE gf.generation_id = ${g} ORDER BY gf.path, e.local_id`).all() as Array<Record<string, unknown>>).map((r) => JSON.stringify(r));
    const fp = (store.db.prepare(`SELECT source_fingerprint AS f FROM generations WHERE id = ${g}`).get() as { f: string }).f;
    return { symbols, edges, exports: exps, fingerprint: fp };
  }

  it.each(Array.from({ length: 12 }, (_, i) => i + 1))("seed %i: mutate, index incrementally, compare to a clean index of the same tree", async (seed) => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    // deterministic mutations
    const pick = (n: number): number => (seed * 31 + n * 17) % 7;
    const edits: Array<() => void> = [
      () => writeFileSync(join(repo, "src/util.ts"), `export function helper(v: string): string { return v; }\nexport function mutated${seed}(): number { return ${seed}; }\n`),
      () => writeFileSync(join(repo, "src/added.ts"), `import { helper } from "./util";\nexport const added${seed} = helper("x");\n`),
      () => rmSync(join(repo, "src/constants.ts")),
      () => renameSync(join(repo, "src/circular/b.ts"), join(repo, "src/circular/bb.ts")),
      () => writeFileSync(join(repo, "src/components/App.tsx"), `export const App = () => <div>${seed}</div>;\n`),
      () => rmSync(join(repo, "docs/readme.md")),
      () => writeFileSync(join(repo, "src/auth/session.ts"), `export default class Session { start(id: string): void {} stop${seed}(): void {} }\n`)
    ];
    for (let i = 0; i < 3 + (seed % 3); i += 1) {
      edits[pick(i)]!();
    }
    await indexIn(repo, home);
    const incremental = await read(repo, home, ({ store }) => dumpCode(store));

    // clean index of the same working-tree state (non-git walk => independent enumeration path)
    const copy = tempDir("engbrain-clean-");
    const { cpSync } = await import("node:fs");
    cpSync(repo, copy, { recursive: true, filter: (src) => !src.includes(".git") && !src.includes(".engineering-brain") });
    const cleanHome = engbrainHome();
    await indexIn(copy, cleanHome, true);
    const clean = await read(copy, cleanHome, ({ store }) => dumpCode(store));
    expect(incremental.symbols).toEqual(clean.symbols);
    expect(incremental.edges).toEqual(clean.edges);
    expect(incremental.exports).toEqual(clean.exports);
    expect(incremental.fingerprint).toBe(clean.fingerprint);
    expect(incremental.symbols.length).toBeGreaterThan(10);
  });
});

describe("P2A freshness is reported at the strength it was established", () => {
  it("heuristic when clean, stale with the changed path when modified, hash_verified only after a full re-read", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    const check = (verify: boolean) => read(repo, home, async (o) => checkFreshness(o.store, o.info, o.git, { verify }));
    expect((await check(false)).level).toBe("heuristic");
    const verified = await check(true);
    expect(verified.level).toBe("hash_verified");
    expect(verified.basis).toContain("content hash");

    writeFileSync(join(repo, "src/util.ts"), "export function helper(v: string): string { return v.toUpperCase(); }\n");
    writeFileSync(join(repo, "src/fresh.ts"), "export const fresh = 1;\n");
    rmSync(join(repo, "src/constants.ts"));
    for (const verify of [false, true]) {
      const report = await check(verify);
      expect(report.level, `verify=${verify}`).toBe("stale");
      expect(report.modified).toContain("src/util.ts");
      expect(report.added).toContain("src/fresh.ts");
      expect(report.deleted).toContain("src/constants.ts");
    }
  });

  it("a same-size edit with the modification time restored is caught by the verified check (and by ctime in the heuristic)", async () => {
    const repo = makeGitRepo({ "a.ts": "export const aaaa = 1;\n" });
    const home = engbrainHome();
    await indexIn(repo, home, true);
    const path = join(repo, "a.ts");
    const { mtime, atime } = statSync(path);
    writeFileSync(path, "export const bbbb = 1;\n"); // same length
    utimesSync(path, atime, mtime);
    const verified = await read(repo, home, async (o) => checkFreshness(o.store, o.info, o.git, { verify: true }));
    expect(verified.level).toBe("stale");
    expect(verified.modified).toEqual(["a.ts"]);
  });

  it("`index --check` exits 0 only when hash-verified, and `status` reports parser coverage, revision and fingerprint from persisted data", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await runCli(repo, ["init"], home);
    await runCli(repo, ["index"], home);
    const ok = await runCli(repo, ["index", "--check"], home);
    expect(ok.code, ok.stderr).toBe(0);
    expect(ok.stdout).toContain("hash_verified");
    writeFileSync(join(repo, "src/util.ts"), "export function helper() {}\n");
    const stale = await runCli(repo, ["index", "--check", "--json"], home);
    expect(stale.code).toBe(1);
    expect((JSON.parse(stale.stdout) as { level: string; modified: string[] }).modified).toEqual(["src/util.ts"]);
    await runCli(repo, ["index"], home);
    const status = JSON.parse((await runCli(repo, ["status", "--json"], home)).stdout) as {
      summary: { parser: { ok: number; error: number; skipped: number }; symbols: number }; freshness: { level: string }; generation: { revision: string | null; sourceFingerprint: string | null };
    };
    expect(status.summary.parser).toMatchObject({ error: 1, skipped: 6 });
    expect(status.summary.symbols).toBeGreaterThan(20);
    expect(status.generation.revision).toMatch(/^[0-9a-f]{40}$/);
    expect(status.generation.sourceFingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(status.freshness.level).toBe("heuristic");
  });
});

describe("P2A CLI uses persisted data and reports measured statistics", () => {
  it("symbols and imports read the database, not the working tree", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await runCli(repo, ["init"], home);
    await runCli(repo, ["index"], home);
    rmSync(join(repo, "src/auth/refreshToken.ts")); // gone from disk, still in the published index
    const symbols = JSON.parse((await runCli(repo, ["symbols", "--file", "src/auth/refreshToken.ts", "--json"], home)).stdout) as { symbols: Array<{ name: string }> };
    expect(symbols.symbols.map((s) => s.name)).toContain("refreshToken");
    const search = await runCli(repo, ["symbols", "--search", "refreshToken"], home);
    expect(search.stdout).toContain("src/auth/refreshToken.ts:6:8");
    const imports = JSON.parse((await runCli(repo, ["imports", "--to", "src/util.ts", "--json"], home)).stdout) as { edges: Array<{ from: string }> };
    expect(imports.edges.map((e) => e.from)).toContain("src/auth/refreshToken.ts");
  });

  it("`index --stats` prints every required statistic, all measured", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await runCli(repo, ["init"], home);
    const run = await runCli(repo, ["index", "--stats"], home);
    for (const needle of ["discovered", "indexed", "excluded", "parsed", "facts reused", "symbols", "module relationships", "unresolved", "with errors", "took", "database:", "peak memory"]) {
      expect(run.stdout, needle).toContain(needle);
    }
    const json = JSON.parse((await runCli(repo, ["index", "--json"], home)).stdout) as { stats: { dbSizeBytes: number; peakRssMiB: number; durationMs: number } };
    expect(json.stats.dbSizeBytes).toBeGreaterThan(0);
    expect(json.stats.peakRssMiB).toBeGreaterThan(0);
  });

  it("validates arguments and refuses paths outside the repository", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await runCli(repo, ["init"], home);
    await runCli(repo, ["index"], home);
    expect((await runCli(repo, ["symbols", "--kind", "bogus"], home)).code).toBe(2);
    expect((await runCli(repo, ["symbols", "--limit", "0"], home)).code).toBe(2);
    expect((await runCli(repo, ["imports", "--resolution", "bogus"], home)).code).toBe(2);
    for (const bad of ["../outside.ts", "/etc/passwd", "../../.."]) {
      const run = await runCli(repo, ["symbols", "--file", bad], home);
      expect(run.code, bad).toBe(1);
      expect(run.stderr).toContain("outside the repository");
    }
  });
});

describe("P2A hostile paths and configuration cannot escape the repository", () => {
  it("symlinks to outside code are excluded; traversal specifiers and escaping tsconfig/package settings resolve to nothing", async () => {
    const outside = tempDir("engbrain-outside-");
    writeFileSync(join(outside, "leak.ts"), "export function leakedFromOutside() {}\n");
    mkdirSync(join(outside, "dir"));
    writeFileSync(join(outside, "dir", "inner.ts"), "export function leakedInner() {}\n");
    writeFileSync(join(outside, "evil-tsconfig.json"), JSON.stringify({ compilerOptions: { baseUrl: ".", paths: { "@evil/*": ["*"] } } }));
    const repo = makeGitRepo({
      "tsconfig.json": JSON.stringify({ extends: "../../../../etc/passwd", compilerOptions: { baseUrl: ".", paths: { "@escape/*": ["../../../../outside/*"], "@up/*": ["../*"] } } }),
      "package.json": JSON.stringify({ name: "root", workspaces: ["packages/*"] }),
      "packages/p/package.json": JSON.stringify({ name: "p", main: "../../../escape.ts" }),
      "src/a.ts": 'import "../../../../etc/passwd";\nimport "@escape/leak";\nimport "@up/anything";\nimport "p";\nimport "https://evil.example/x.js";\nimport "/abs/path";\nexport const a = 1;\n'
    });
    if (process.platform !== "win32") {
      symlinkSync(join(outside, "leak.ts"), join(repo, "linked.ts"));
      symlinkSync(join(outside, "dir"), join(repo, "linkeddir"));
      symlinkSync(join(outside, "evil-tsconfig.json"), join(repo, "tsconfig.evil.json"));
    }
    const home = engbrainHome();
    const { result } = await indexIn(repo, home, true);
    await read(repo, home, ({ store }) => {
      expect(findSymbols(store.db, { search: "leaked" }).rows).toEqual([]);
      const edges = findModuleEdges(store.db, { from: "src/a.ts" }).rows;
      expect(edges.every((e) => e.resolvedPath === null)).toBe(true);
      expect(edges.map((e) => `${e.specifier}:${e.resolution}`)).toEqual([
        "../../../../etc/passwd:unresolved", "@escape/leak:unresolved", "@up/anything:unresolved", "p:unresolved", "https://evil.example/x.js:unresolved", "/abs/path:unresolved"
      ]);
    });
    if (process.platform !== "win32") {
      expect(result.stats.excludedByReason["symlink"]).toBe(3);
    }
  });
});

describe("P2A local indexing performs no network operations", () => {
  it("index, symbols, imports, status and --check make zero network attempts (in-process guard)", async () => {
    const guard = installNetworkGuard();
    try {
      const repo = fixtureRepo();
      const home = engbrainHome();
      for (const args of [["init"], ["index", "--stats"], ["symbols", "--search", "refresh"], ["imports", "--file", "src/index.ts"], ["status", "--check"], ["index", "--check"]]) {
        const run = await runCli(repo, args, home);
        expect(run.code, `${args.join(" ")}: ${run.stderr}`).toBe(0);
      }
      expect(guard.attempts).toEqual([]);
    } finally {
      guard.uninstall();
    }
    mkdirSync(dirname(join(tempDir(), "x")), { recursive: true });
    rmSync(join(tempDir(), "none"), { force: true });
  });
});

describe("P2A review regressions (end to end)", () => {
  const cp = async (from: string, to: string): Promise<void> => {
    const { cpSync } = await import("node:fs");
    cpSync(from, to, { recursive: true, filter: (src) => !src.includes(".git") && !src.includes(".engineering-brain") });
  };

  it("identical bytes under different extensions never poison each other, in either indexing order, and clean == incremental", async () => {
    const same = "export function important() {}\nexport const value = 1;\n";
    const jsx = "export function Comp() { return <b/>; }\n";
    const repo = makeGitRepo({ "docs/snippet.txt": same, "src/real.ts": same, "src/a.js": jsx, "src/b.jsx": jsx, "src/c.ts": "export const only = 1;\n" });
    const home = engbrainHome();
    const first = await indexIn(repo, home, true);
    await read(repo, home, ({ store }) => {
      expect(names(findSymbols(store.db, { file: "src/real.ts" }).rows)).toEqual(["function:important", "variable:value"]);
      expect(findSymbols(store.db, { file: "docs/snippet.txt" }).rows).toEqual([]); // unsupported: no code facts
      expect(names(findSymbols(store.db, { file: "src/a.js" }).rows)).toEqual(["function:Comp"]);
      expect(names(findSymbols(store.db, { file: "src/b.jsx" }).rows)).toEqual(["function:Comp"]);
    });
    expect(first.result.summary.parser).toMatchObject({ ok: 4, error: 0, skipped: 1 });

    // add the unsupported twin AFTER the supported one, then index a clean copy: same facts either way
    writeFileSync(join(repo, "notes.txt"), same);
    await indexIn(repo, home);
    const clean = tempDir("engbrain-twin-");
    await cp(repo, clean);
    const cleanHome = engbrainHome();
    await indexIn(clean, cleanHome, true);
    const dump = (r: string, h: string) => read(r, h, ({ store }) => findSymbols(store.db, { limit: 5000 }).rows.map((s) => `${s.path}|${s.qualifiedName}|${s.startByte}`));
    expect(await dump(repo, home)).toEqual(await dump(clean, cleanHome));
    expect((await dump(repo, home)).filter((x) => x.startsWith("src/real.ts")).length).toBe(2);
  });

  it("files named like excluded directories are indexed identically in git and non-git trees", async () => {
    const repo = makeGitRepo({ "scripts/build": "export const buildScript = 1;\n", "scripts/dist": "x\n", "src/ok.ts": "export const ok = 1;\n" });
    const home = engbrainHome();
    const gitRun = await indexIn(repo, home, true);
    const plain = tempDir("engbrain-plain2-");
    await cp(repo, plain);
    const plainRun = await indexIn(plain, engbrainHome(), true);
    expect(gitRun.result.sourceFingerprint).toBe(plainRun.result.sourceFingerprint);
    expect(gitRun.result.stats.included).toBe(3);
  });

  it("`index --check` and `status` say the index is stale when this build would extract differently (extractor/resolver version change)", async () => {
    const repo = fixtureRepo();
    const home = engbrainHome();
    await indexIn(repo, home, true);
    const ok = await read(repo, home, async (o) => checkFreshness(o.store, o.info, o.git, { verify: true }));
    expect(ok.level).toBe("hash_verified");
    expect(ok.indexerChanged).toBe(false);
    // simulate an index built by an older resolver / extractor set, as after an upgrade or a v1 -> v3 migration
    const db = (await import("better-sqlite3")).default;
    const raw = new db(join(repo, ".engineering-brain", "store.db"));
    raw.prepare("UPDATE generations SET resolver_version = '0'").run();
    raw.close();
    const stale = await read(repo, home, async (o) => checkFreshness(o.store, o.info, o.git, { verify: true }));
    expect(stale.level).toBe("stale");
    expect(stale.indexerChanged).toBe(true);
    expect(stale.basis).toContain("re-index");
    const cli = await runCli(repo, ["index", "--check"], home);
    expect(cli.code).toBe(1);
    expect(cli.stdout).toContain("engbrain index");
    const reindex = await indexIn(repo, home);
    expect(reindex.result.unchanged).toBe(false); // the unchanged-shortcut also refuses to keep an index built by a different resolver
  });

  it("untrusted text cannot drive the terminal: control characters in specifiers and paths are shown as escapes", async () => {
    const esc = "\u001b]0;PWNED\u0007\u001b[2J";
    const repo = makeGitRepo({ "a.ts": `import x from "./${esc}evil";\nexport const a = 1;\n` });
    const home = engbrainHome();
    await runCli(repo, ["init"], home);
    await runCli(repo, ["index"], home);
    const text = await runCli(repo, ["imports", "--file", "a.ts"], home);
    expect(text.stdout).not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/);
    expect(text.stdout).toContain("\\u{1b}");
    const json = JSON.parse((await runCli(repo, ["imports", "--file", "a.ts", "--json"], home)).stdout) as { edges: Array<{ specifier: string }> };
    expect(json.edges[0]?.specifier).toContain("PWNED"); // JSON keeps the exact data (it is escaped by the JSON encoder)
  });

  it("ambient `.d.ts` declarations, namespaces and `import = require` are indexed from a real repository", async () => {
    const repo = makeGitRepo({
      "types/api.d.ts": "export declare class Client { send(): void }\nexport declare function connect(): Client;\n",
      "src/legacy.ts": 'import fs = require("fs");\nexport namespace Util { export function helper() {} }\n'
    });
    const home = engbrainHome();
    await indexIn(repo, home, true);
    await read(repo, home, ({ store }) => {
      expect(findSymbols(store.db, { file: "types/api.d.ts", exportedOnly: true }).rows.map((s) => s.name)).toEqual(["Client", "connect"]);
      expect(findModuleEdges(store.db, { from: "src/legacy.ts" }).rows[0]).toMatchObject({ kind: "require", resolution: "external", reason: "node_builtin" });
    });
  });
});

describe("Gate 0 fixture: malformed TSX", () => {
  it("a broken .tsx file yields diagnostics and partial facts while valid TSX alongside it is unaffected", async () => {
    const repo = makeGitRepo({
      "ui/Good.tsx": "export const Good = () => <section><b>ok</b></section>;\n",
      "ui/Bad.tsx": "export const Before = () => <div/>;\nexport const Bad = () => <div><span></div>;\nexport function After() { return 1; }\n"
    });
    const home = engbrainHome();
    const { result } = await indexIn(repo, home, true);
    expect(result.summary.parser).toMatchObject({ ok: 1, error: 1 });
    await read(repo, home, ({ store }) => {
      expect(names(findSymbols(store.db, { file: "ui/Good.tsx" }).rows)).toEqual(["function:Good"]);
      expect(findSymbols(store.db, { file: "ui/Bad.tsx" }).rows.map((r) => r.name)).toContain("Before");
      const diag = store.db.prepare(
        `SELECT COUNT(*) AS n FROM applicable_facts af JOIN fact_diagnostics fd ON fd.content_hash = af.content_hash AND fd.extractor_id = af.extractor_id AND fd.extractor_version = af.extractor_version
         WHERE af.generation_id = (SELECT current_generation_id FROM store_meta) AND af.path = 'ui/Bad.tsx'`
      ).get() as { n: number };
      expect(diag.n).toBeGreaterThan(0);
      expect(store.db.pragma("integrity_check", { simple: true })).toBe("ok");
    });
  });
});
