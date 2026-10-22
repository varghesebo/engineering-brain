import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { codeExtractors } from "../src/codeExtractor.js";
import { extractorApplies } from "../src/extractor.js";
import type { ExtractedFact } from "../src/extractor.js";
import { sha256Hex } from "../src/hash.js";
import { createExclusionMatcher } from "../src/exclusions.js";
import { loadResolverConfig } from "../src/moduleEdges.js";
import { resolveModule, type ResolverConfig } from "../src/moduleResolver.js";

beforeAll(async () => {
  await Promise.all(codeExtractors.map((e) => e.prepare?.()));
});
const run = (path: string, source: string): ExtractedFact => codeExtractors.find((e) => extractorApplies(e, path))!.extract({ path, data: Buffer.from(source) });
const sym = (f: ExtractedFact): string[] => (f.symbols ?? []).map((s) => `${s.kind}:${s.qualifiedName || "<module>"}${s.exported ? "!" : ""}`);
const exp = (f: ExtractedFact): string[] => (f.exports ?? []).map((e) => `${e.kind}:${e.exportName ?? "-"}<-${e.localName ?? "-"}`);

describe("review fix: ambient declarations (.d.ts) are not dropped", () => {
  it("export declare class/const/function/namespace/enum produce exported symbols and exports", () => {
    const f = run("types.d.ts", [
      "export declare class C { m(): void }", "export declare const v: number;", "export declare function g(a: string): void;",
      "export declare namespace N { function inner(): void }", "export declare enum E { A }", "declare module \"m\" { export function bar(): void }", "declare const hidden: number;"
    ].join("\n"));
    expect(sym(f)).toEqual(expect.arrayContaining(["class:C!", "method:C.m", "variable:v!", "function:g!", "namespace:N!", "enum:E!", "variable:hidden"]));
    expect(exp(f)).toEqual(["named:C<-C", "named:v<-v", "named:g<-g", "named:N<-N", "named:E<-E"]);
    expect(exp(f)).not.toContain("named:bar<-bar"); // declared INSIDE an ambient module, not a file export
  });
});

describe("review fix: exports inside namespaces are not module-level exports", () => {
  it("namespace members are scoped, and exported only relative to an exported owner", () => {
    const f = run("ns.ts", "export namespace N { export function inner() {} function hidden() {} }\nnamespace Private { export function leaked() {} }");
    expect(exp(f)).toEqual(["named:N<-N"]);
    expect(sym(f)).toEqual(expect.arrayContaining(["namespace:N!", "function:N.inner!", "function:N.hidden", "namespace:Private", "function:Private.leaked"]));
    expect(sym(f)).not.toContain("function:Private.leaked!"); // exported only within a namespace that is itself private
  });
});

describe("review fix: import = require and export =", () => {
  it("`import x = require()` is a literal require, `export =` is a commonjs export", () => {
    const f = run("c.ts", 'import fs2 = require("fs");\nimport dyn = require("./local");\nconst foo = 1;\nexport = foo;');
    expect((f.refs ?? []).map((r) => `${r.kind}:${r.target}`)).toEqual(["require:fs", "require:./local"]);
    expect(f.refs?.[0]?.names).toEqual([{ imported: "=", local: "fs2" }]);
    expect(exp(f)).toEqual(["commonjs:export=<-foo"]);
  });
});

describe("review fix: no literal values leak into facts", () => {
  it("destructured parameter names omit defaults and literals", () => {
    const f = run("p.ts", 'function f({ token = "LITERAL_VALUE_xyz", x }, [b = 42, ...r], plain = "ANOTHER_LITERAL") {}');
    const params = f.symbols?.find((s) => s.name === "f")?.parameters;
    expect(params).toEqual([
      { name: "{token,x}", optional: false, rest: false, hasDefault: false },
      { name: "[b,r]", optional: false, rest: false, hasDefault: false },
      { name: "plain", optional: false, rest: false, hasDefault: true }
    ]);
    expect(JSON.stringify(f)).not.toContain("LITERAL_VALUE_xyz");
    expect(JSON.stringify(f)).not.toContain("ANOTHER_LITERAL");
    expect(JSON.stringify(f)).not.toContain("42");
  });
});

describe("review fix: assorted extraction gaps", () => {
  it("inline type-literal members in signatures are not method symbols (interface members still are)", () => {
    const f = run("t.ts", "function f(o: { cb(): void }): { ret(): void } {}\ninterface I { m(): void }");
    expect(sym(f)).toEqual(["module:<module>", "function:f", "interface:I", "method:I.m"]);
  });
  it("destructured exports and `export default <identifier>` are linked", () => {
    const f = run("d.ts", "export const { a, b: c } = obj;\nfunction foo() {}\nexport default foo;");
    expect(exp(f)).toEqual(["named:a<-a", "named:c<-c", "default:default<-foo"]);
    expect(sym(f)).toContain("function:foo!");
    expect(f.symbols?.find((s) => s.name === "foo")?.exportName).toBe("default");
  });
  it("when the symbol limit is hit, export facts never point at the wrong symbol", () => {
    const src = Array.from({ length: 5001 }, (_, i) => `export function f${i}() {}`).join("\n");
    const f = run("cap.ts", src);
    expect(f.symbols?.length).toBe(5000);
    const last = f.exports?.[f.exports.length - 1];
    for (const e of f.exports ?? []) {
      if (e.symbolIndex !== null) {
        expect(f.symbols?.[e.symbolIndex]?.name).toBe(e.localName);
      }
    }
    expect(last).toBeDefined();
  });
  it("JavaScript files may contain JSX (they use the tsx grammar)", () => {
    const f = run("a.js", "export function A() { return <div className=\"x\" />; }");
    expect(f.parseStatus).toBe("ok");
    expect(sym(f)).toContain("function:A!");
  });
  it("positions: columns are UTF-16 units, byte offsets UTF-8, after multi-byte text on the same line", () => {
    const src = "const s = '日本語'; export function f() {}";
    const f = run("u.ts", src);
    const s = f.symbols?.find((x) => x.name === "f")!;
    expect(s.startColumn).toBe(src.indexOf("function"));
    expect(Buffer.from(src).subarray(s.startByte, s.endByte).toString()).toBe("function f() {}");
    expect(s.startByte).toBeGreaterThan(s.startColumn); // 3-byte characters make bytes exceed UTF-16 columns
  });
});

describe("review fix: path-independent facts (the grammar is part of the extractor identity)", () => {
  it("each extension maps to exactly one extractor, and unsupported paths map to none", () => {
    const applies = (path: string): string[] => codeExtractors.filter((e) => extractorApplies(e, path)).map((e) => e.id);
    expect(applies("a.ts")).toEqual(["code:ts-wasm:typescript"]);
    expect(applies("a.mts")).toEqual(["code:ts-wasm:typescript"]);
    for (const path of ["a.tsx", "a.jsx", "a.js", "a.mjs", "a.cjs"]) {
      expect(applies(path), path).toEqual(["code:ts-wasm:tsx"]);
    }
    for (const path of ["a.txt", "a.md", "a.json", "a.py", "A.TS.bak"]) {
      expect(applies(path), path).toEqual([]);
    }
    expect(applies("UPPER.TS")).toEqual(["code:ts-wasm:typescript"]); // extension match is case-insensitive
  });
});

describe("review fix: resolver", () => {
  const cfg = (files: string[], extra: Partial<ResolverConfig> = {}): ResolverConfig => ({ files: new Set(files), tsconfigs: [], packages: [], ...extra });
  it("a workspace package can never shadow a Node builtin", () => {
    const c = cfg(["pkgs/fsfake/index.ts"], { packages: [{ name: "fs", dir: "pkgs/fsfake", entries: [] }] });
    expect(resolveModule("a.ts", "fs", c)).toMatchObject({ resolution: "external", reason: "node_builtin" });
    expect(resolveModule("a.ts", "fs/promises", c).reason).toBe("node_builtin");
  });
  it("duplicate workspace package names are ambiguous, never silently the first", () => {
    const c = cfg(["a/index.ts", "b/index.ts"], { packages: [{ name: "@acme/ui", dir: "a", entries: [] }, { name: "@acme/ui", dir: "b", entries: [] }] });
    expect(resolveModule("x.ts", "@acme/ui", c)).toEqual({ resolution: "ambiguous", resolvedPath: null, reason: "duplicate_workspace_package:@acme/ui:a,b" });
  });
  it("a catch-all `*` paths mapping with no target falls through to normal resolution (react stays external)", () => {
    const c = cfg(["src/a.ts"], { tsconfigs: [{ dir: "", baseUrl: ".", paths: [{ pattern: "*", targets: ["types/*"] }] }] });
    expect(resolveModule("src/a.ts", "react", c)).toEqual({ resolution: "external", resolvedPath: null, reason: "package:react" });
    expect(resolveModule("src/a.ts", "fs", c).reason).toBe("node_builtin");
  });
  it("a specific paths mapping whose target is missing is still reported (it names something the repo claims to provide)", () => {
    const c = cfg(["src/a.ts"], { tsconfigs: [{ dir: "", baseUrl: ".", paths: [{ pattern: "@app/*", targets: ["nowhere/*"] }] }] });
    expect(resolveModule("src/a.ts", "@app/x", c).reason).toBe("tsconfig_paths_target_missing");
  });
  it("an extensionless specifier never resolves to a .json file (an explicit one does)", () => {
    const c = cfg(["src/both.ts", "src/both.json", "src/data.json"]);
    expect(resolveModule("src/m.ts", "./both", c)).toMatchObject({ resolution: "resolved", resolvedPath: "src/both.ts" });
    expect(resolveModule("src/m.ts", "./data", c).resolution).toBe("unresolved");
    expect(resolveModule("src/m.ts", "./data.json", c).resolvedPath).toBe("src/data.json");
  });
  it("resolution stays fast with thousands of bare imports against thousands of packages", () => {
    const packages = Array.from({ length: 2000 }, (_, i) => ({ name: `@w/p${i}`, dir: `p/${i}`, entries: [] }));
    const c = cfg([], { packages });
    const started = performance.now();
    for (let i = 0; i < 20_000; i += 1) {
      resolveModule("a.ts", `pkg-${i}/deep/path`, c);
    }
    expect(performance.now() - started).toBeLessThan(1500);
  });
});

describe("review fix: resolver configuration is verified against the manifest and capped", () => {
  const dir = mkdtempSync(join(tmpdir(), "engbrain-cfg-"));
  const put = (path: string, text: string): { path: string; contentHash: string } => {
    mkdirSync(join(dir, path, ".."), { recursive: true });
    writeFileSync(join(dir, path), text);
    return { path, contentHash: sha256Hex(Buffer.from(text)) };
  };
  it("a config file whose bytes differ from the manifest hash aborts instead of mixing snapshots", () => {
    const entry = put("tsconfig.json", '{"compilerOptions":{"baseUrl":"."}}');
    writeFileSync(join(dir, "tsconfig.json"), '{"compilerOptions":{"baseUrl":"src"}}'); // changed after the manifest was written
    expect(() => loadResolverConfig(dir, [entry])).toThrow(/changed while indexing/);
  });
  it("path patterns are capped so a hostile tsconfig cannot make resolution slow", () => {
    const paths = Object.fromEntries(Array.from({ length: 5000 }, (_, i) => [`@p${i}/*`, [`src/${i}/*`]]));
    const entry = put("tsconfig.json", JSON.stringify({ compilerOptions: { baseUrl: ".", paths } }));
    expect(loadResolverConfig(dir, [entry]).tsconfigs[0]?.paths.length).toBe(1000);
  });
  it("only packages declared as workspaces count: package.json `workspaces` globs, pnpm-workspace.yaml, negations", () => {
    const manifest = [
      put("package.json", JSON.stringify({ name: "root", workspaces: ["packages/*", "!packages/ignored"] })),
      put("packages/a/package.json", JSON.stringify({ name: "@w/a", main: "src/index.ts" })),
      put("packages/ignored/package.json", JSON.stringify({ name: "@w/ignored" })),
      put("examples/react/package.json", JSON.stringify({ name: "react" })),
      put("stray/package.json", JSON.stringify({ name: "stray-pkg" }))
    ];
    const names = loadResolverConfig(dir, manifest).packages.map((p) => p.name);
    expect(names).toEqual(["@w/a"]);
    const pnpm = [
      put("pnpm-workspace.yaml", "packages:\n  - 'apps/*'\n  - \"libs/**\" # comment\nother:\n  - nope/*\n"),
      put("apps/web/package.json", JSON.stringify({ name: "web" })),
      put("libs/x/y/package.json", JSON.stringify({ name: "xy" })),
      put("nope/z/package.json", JSON.stringify({ name: "nope" }))
    ];
    expect(loadResolverConfig(dir, pnpm).packages.map((p) => p.name).sort()).toEqual(["web", "xy"]);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("review fix: directory-name exclusions apply to directories, consistently", () => {
  it("a FILE named like an excluded directory is a normal file; `.git` stays excluded at any position", () => {
    const m = createExclusionMatcher();
    expect(m.excludesPath("scripts/build")).toBeNull();
    expect(m.excludesPath("scripts/dist")).toBeNull();
    expect(m.excludesPath("build/out.js")).toBe("excluded_directory");
    expect(m.excludesPath("a/node_modules/x/index.js")).toBe("excluded_directory");
    expect(m.excludesPath("sub/.git")).toBe("excluded_directory");
    expect(m.excludesPath("sub/.GIT/config")).toBe("excluded_directory");
  });
});
