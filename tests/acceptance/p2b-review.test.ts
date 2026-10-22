import { impact, indexRepository, resolveNode, shortestPath, validateGraph } from "@engbrain/core";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, engbrainHome, makeGitRepo, openFor, runCli } from "../helpers/env.js";

afterAll(cleanupTempDirs);

type Opened = Awaited<ReturnType<typeof openFor>>;

async function indexed(files: Record<string, string>): Promise<{ repo: string; home: string }> {
  const repo = makeGitRepo(files);
  const home = engbrainHome();
  const o = await openFor(repo, home, true);
  try {
    await indexRepository({ store: o.store, git: o.info, hardenedGit: o.git });
  } finally {
    o.close();
  }
  return { repo, home };
}

async function read<T>(ctx: { repo: string; home: string }, fn: (o: Opened) => T): Promise<T> {
  const o = await openFor(ctx.repo, ctx.home);
  try {
    return fn(o);
  } finally {
    o.close();
  }
}

interface Row { kind: string; src: string; dstPath: string | null; resolution: string; reason: string }
function rows(o: Opened, kind: string): Row[] {
  return o.store.db.prepare(
    `SELECT edge_kind AS kind, src_path || '#' || COALESCE((SELECT qualified_name FROM symbol_occurrences s WHERE s.generation_id = e.generation_id AND s.path = e.src_path AND s.symbol_key = e.src_symbol LIMIT 1), '') AS src,
            dst_path AS dstPath, resolution, reason
     FROM graph_edges e WHERE generation_id = (SELECT current_generation_id FROM store_meta) AND edge_kind = ? ORDER BY edge_id`
  ).all(kind) as Row[];
}

describe("P2B review regressions", () => {
  it("a heritage name declared by an enclosing scope is not the import of the same name", async () => {
    const ctx = await indexed({
      "base.ts": "export class Base {}\n",
      "a.ts": [
        "import { Base } from \"./base\";",
        "export class Real extends Base {}",
        "export function viaParam(Base: any) { class FromParam extends Base {} return FromParam; }",
        "export function viaLocal() { class Base {} class FromLocal extends Base {} return FromLocal; }"
      ].join("\n")
    });
    const extendsEdges = await read(ctx, (o) => rows(o, "EXTENDS"));
    const by = (name: string): Row => extendsEdges.find((e) => e.src === `a.ts#${name}`)!;
    expect(by("Real").resolution).toBe("resolved");
    expect(by("Real").dstPath).toBe("base.ts");
    expect(by("viaParam.FromParam").resolution).not.toBe("resolved");
    expect(by("viaLocal.FromLocal").resolution).not.toBe("resolved");
  });

  it("arrow parameters, loop variables and catch bindings shadow an import", async () => {
    const ctx = await indexed({
      "lib.ts": "export const Item = 1;\n",
      "use.ts": [
        "import { Item } from \"./lib\";",
        "export function shadowed(xs: number[]) {",
        "  xs.map((Item) => Item + 1);",
        "  for (const Item of xs) { void Item; }",
        "  try { xs.length; } catch (Item) { void Item; }",
        "}",
        "export function real() { return Item; }"
      ].join("\n")
    });
    const refs = await read(ctx, (o) => rows(o, "REFERENCES"));
    expect(refs.map((r) => r.src)).toEqual(["use.ts#real"]);
  });

  it("export * diamonds resolve in linear time and an undecidable star branch is never reported as resolved", async () => {
    // 7 levels x 8 parallel branches: 8^7 (about 2 million) distinct paths to the leaf, within the 16-hop re-export bound
    const levels = 7;
    const width = 8;
    const files: Record<string, string> = { "leaf.ts": "export const target = 1;\n" };
    for (let i = 0; i < levels; i += 1) {
      const next = i === levels - 1 ? "./leaf" : `./a${i + 1}`;
      files[`a${i}.ts`] = Array.from({ length: width }, (_, k) => `export * from "./b${i}_${k}";`).join("\n") + "\n";
      for (let k = 0; k < width; k += 1) {
        files[`b${i}_${k}.ts`] = `export * from "${next}";\n`;
      }
    }
    files["user.ts"] = "import { target, absent } from \"./a0\";\nexport const v = [target, absent];\n";
    files["open.ts"] = "export * from \"some-external-package\";\nexport * from \"./leaf\";\n";
    files["user2.ts"] = "import { missing } from \"./open\";\nexport const w = missing;\n";
    const startedAt = Date.now();
    const ctx = await indexed(files);
    expect(Date.now() - startedAt).toBeLessThan(30_000);
    const imports = await read(ctx, (o) => o.store.db.prepare(
      "SELECT src_path AS src, dst_path AS dst, resolution, reason, detail FROM graph_edges WHERE family = 'symbol' AND edge_kind = 'IMPORTS' AND src_path IN ('user.ts','user2.ts')"
    ).all() as Array<{ src: string; dst: string | null; resolution: string; reason: string; detail: string }>);
    const named = (src: string, local: string) => imports.find((e) => e.src === src && (JSON.parse(e.detail) as { local: string }).local === local)!;
    expect(named("user.ts", "target").resolution).toBe("resolved");
    expect(named("user.ts", "target").dst).toBe("leaf.ts");
    expect(named("user2.ts", "missing").resolution).toBe("unresolved");
    expect(named("user2.ts", "missing").reason).toBe("star_reexport_undecidable");
  }, 120_000);

  it("impact honours its edge budget and reports truncation", async () => {
    const files: Record<string, string> = { "hub.ts": "export const hub = 1;\n" };
    for (let i = 0; i < 30; i += 1) {
      files[`m${i}.ts`] = `import { hub } from "./hub";\nexport const x${i} = hub;\n`;
    }
    const ctx = await indexed(files);
    const result = await read(ctx, (o) => impact(o.store.db, resolveNode(o.store.db, { file: "hub.ts" }), { budget: { maxEdges: 5 } }));
    expect(result.truncated.edges).toBe(true);
    expect(result.affected.length).toBeLessThan(30);
  });

  it("package impact follows DEPENDS_ON between packages", async () => {
    const ctx = await indexed({
      "package.json": JSON.stringify({ name: "root", workspaces: ["packages/*"] }),
      "packages/lib/package.json": JSON.stringify({ name: "@w/lib", main: "src/index.ts" }),
      "packages/lib/src/index.ts": "export const lib = 1;\n",
      "packages/app/package.json": JSON.stringify({ name: "@w/app" }),
      "packages/app/src/main.ts": "import { lib } from \"@w/lib\";\nexport const app = lib;\n"
    });
    const result = await read(ctx, (o) => impact(o.store.db, resolveNode(o.store.db, { package: "packages/lib" })));
    expect(result.affected.map((a) => a.node.key)).toContain("pkg:packages/app");
  });

  it("shortestPath does not treat a name-match reference as a decided edge", async () => {
    const ctx = await indexed({
      "b.ts": "export function f() {}\n",
      "a.ts": "import { f } from \"./b\";\nexport function g() { return f(); }\n"
    });
    const outcome = await read(ctx, (o) => shortestPath(o.store.db, resolveNode(o.store.db, { symbol: "a.ts#g" }), resolveNode(o.store.db, { symbol: "b.ts#f" }), { mode: "symbol" }));
    expect(outcome.found).toBe(false);
  });

  it("a file path containing # is still a valid symbol path", async () => {
    const ctx = await indexed({ "dir#x/a.ts": "export function hello() {}\n" });
    const node = await read(ctx, (o) => resolveNode(o.store.db, { symbol: "dir#x/a.ts#hello" }));
    expect(node.path).toBe("dir#x/a.ts");
  });

  it("edge lookups use the (generation, path) index, not a table scan", async () => {
    const ctx = await indexed({ "a.ts": "export const a = 1;\n" });
    const plan = await read(ctx, (o) => o.store.db.prepare(
      "EXPLAIN QUERY PLAN SELECT * FROM graph_edges INDEXED BY idx_graph_edges_dst WHERE generation_id = ? AND family IN ('module') AND dst_kind = 'file' AND dst_path = ? ORDER BY edge_id LIMIT 5"
    ).all(1, "a.ts") as Array<{ detail: string }>);
    expect(plan.map((p) => p.detail).join(" ")).toContain("idx_graph_edges_dst");
    expect(plan.map((p) => p.detail).join(" ")).not.toMatch(/SCAN graph_edges(?! USING)/);
  });

  it("edge kinds that are not served are rejected explicitly and the graph validates as complete", async () => {
    const repo = makeGitRepo({ "a.ts": "export const a = 1;\n" });
    const home = engbrainHome();
    await runCli(repo, ["init"], home);
    await runCli(repo, ["index"], home);
    const rejected = await runCli(repo, ["graph", "dependencies", "--file", "a.ts", "--kinds", "CALLS"], home);
    expect(rejected.code).toBe(2);
    expect(rejected.stderr).toMatch(/not served/);
    const ctx = { repo, home };
    const v = await read(ctx, (o) => validateGraph(o.store.db));
    expect(v.ok).toBe(true);
    expect(v.problems).toEqual([]);
  });
});
