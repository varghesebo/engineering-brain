import { beforeAll, describe, expect, it } from "vitest";
import { codeExtractors, createCodeExtractors } from "../src/codeExtractor.js";
import { extractorApplies } from "../src/extractor.js";
import type { ExtractedFact, LanguageAdapter } from "../src/extractor.js";

beforeAll(async () => {
  await Promise.all(codeExtractors.map((e) => e.prepare?.()));
});

/** Runs the code extractor that applies to the path; a path no grammar supports yields no fact at all (reported here as "skipped"). */
const run = (path: string, source: string): ExtractedFact => {
  const extractor = codeExtractors.find((e) => extractorApplies(e, path));
  return extractor === undefined
    ? { language: null, parseStatus: "skipped", attrs: { reason: "no_extractor_applies" } }
    : extractor.extract({ path, data: Buffer.from(source) });
};
const sym = (f: ExtractedFact): string[] =>
  (f.symbols ?? []).map((s) => `${s.kind}:${s.qualifiedName || "<module>"}${s.exported ? "!" : ""}`);
const parentOf = (f: ExtractedFact, q: string): string | null => {
  const s = f.symbols?.find((x) => x.qualifiedName === q);
  return s === undefined || s.parentIndex === null ? null : f.symbols?.[s.parentIndex]?.qualifiedName ?? null;
};

describe("declarations, ownership and kinds", () => {
  it("extracts module, function, class, constructor, method, interface, type, enum, variable, namespace", () => {
    const f = run("a.ts", [
      "export function alpha(a: number, b?: string): boolean { return true; }",
      "export class Svc { constructor(private s: S) {} handle(req: Req): Res { return res; } static make() {} }",
      "interface Shape { area(): number }",
      "export type Id = string;",
      "enum Color { Red }",
      "export const arrow = (x: number) => x + 1;",
      "const plain = 5;",
      "namespace Outer { export function inNs() {} }"
    ].join("\n"));
    expect(f.parseStatus).toBe("ok");
    expect(sym(f)).toEqual([
      "module:<module>", "function:alpha!", "class:Svc!", "constructor:Svc.constructor", "method:Svc.handle", "method:Svc.make",
      "interface:Shape", "method:Shape.area", "type:Id!", "enum:Color", "function:arrow!", "variable:plain",
      "namespace:Outer", "function:Outer.inNs"
    ]);
  });

  it("retains correct ownership for nested functions, methods and namespaces", () => {
    const f = run("n.ts", [
      "export function outer() { function inner() { const deep = () => 1; } const local = function () {}; }",
      "class K { m() { function inM() {} } }"
    ].join("\n"));
    expect(sym(f)).toEqual(expect.arrayContaining(["function:outer!", "function:outer.inner", "function:outer.inner.deep", "function:outer.local", "class:K", "method:K.m", "function:K.m.inM"]));
    expect(parentOf(f, "outer.inner")).toBe("outer");
    expect(parentOf(f, "outer.inner.deep")).toBe("outer.inner");
    expect(parentOf(f, "K.m.inM")).toBe("K.m");
    expect(parentOf(f, "outer")).toBe("");
    expect(f.symbols?.[0]).toMatchObject({ kind: "module", parentIndex: null });
  });

  it("records parameters: optional, rest, defaults, destructuring, single-param arrows", () => {
    const f = run("p.ts", [
      "function f(a: number, b?: string, { c, d }: P = {}, ...r: number[]) {}",
      "const g = x => x;",
      "const h = (a = 1) => a;"
    ].join("\n"));
    const params = (q: string) => f.symbols?.find((s) => s.qualifiedName === q)?.parameters;
    expect(params("f")).toEqual([
      { name: "a", optional: false, rest: false, hasDefault: false },
      { name: "b", optional: true, rest: false, hasDefault: false },
      { name: "{c,d}", optional: false, rest: false, hasDefault: true },
      { name: "r", optional: false, rest: true, hasDefault: false }
    ]);
    expect(params("g")).toEqual([{ name: "x", optional: false, rest: false, hasDefault: false }]);
    expect(params("h")?.[0]?.hasDefault).toBe(true);
  });

  it("anonymous functions in call arguments are not declarations and do not crash", () => {
    const f = run("cb.ts", "setTimeout(function () {}, 1); [1].map((x) => x); export const run = () => { return () => 2; };");
    expect(sym(f)).toEqual(["module:<module>", "function:run!"]);
  });

  it("duplicate names stay distinguishable by deterministic symbol keys", () => {
    const f = run("d.ts", "function same() {}\nfunction same() {}\nclass A { m() {} m(x: number) {} }");
    const keys = (f.symbols ?? []).filter((s) => s.name === "same" || s.name === "m").map((s) => s.symbolKey);
    expect(new Set(keys).size).toBe(keys.length);
    expect(keys.length).toBe(4);
    expect(run("d.ts", "function same() {}\nfunction same() {}\nclass A { m() {} m(x: number) {} }")).toEqual(f);
  });

  it("signature fingerprints ignore the name and whitespace but notice signature changes", () => {
    const fp = (src: string): string | null | undefined => run("x.ts", src).symbols?.[1]?.signatureFingerprint;
    expect(fp("export function one(a: number,\n  b: string): boolean { return true; }")).toBe(fp("export function two(a: number, b: string): boolean { return false; }"));
    expect(fp("export function one(a: number): void {}")).not.toBe(fp("export function one(a: string): void {}"));
  });
});

describe("exports and re-exports", () => {
  it("represents named, default, aliased, re-exports, export-all and namespace re-exports", () => {
    const f = run("e.ts", [
      "export function a() {}",
      "function b() {}",
      "const c = 1;",
      "export { b, c as renamed };",
      'export { x as y } from "./m";',
      'export * from "./all";',
      'export * as ns from "./q";',
      "export default class Main {}"
    ].join("\n"));
    const ex = (f.exports ?? []).map((e) => `${e.kind}:${e.exportName ?? "-"}<-${e.localName ?? "-"}${e.source === null ? "" : `@${e.source}`}`);
    expect(ex).toEqual([
      "named:a<-a", "named:b<-b", "named:renamed<-c", "reexport:y<-x@./m", "reexport_all:-<--@./all", "reexport_namespace:ns<--@./q", "default:default<-Main"
    ]);
    const names = Object.fromEntries((f.symbols ?? []).map((s) => [s.qualifiedName, `${s.exported}:${s.exportName ?? "-"}`]));
    expect(names["b"]).toBe("true:b"); // `export { b }` marks the earlier declaration exported
    expect(names["c"]).toBe("true:renamed");
    expect(names["Main"]).toBe("true:default");
    expect((f.exports ?? []).find((e) => e.exportName === "b")?.symbolIndex).not.toBeNull();
  });

  it("anonymous default exports of functions, classes and arrows are real symbols named `default`", () => {
    for (const src of ["export default function () {}", "export default () => 1;", "export default class {}"]) {
      const f = run("anon.ts", src);
      const s = f.symbols?.find((x) => x.name === "default");
      expect(s, src).toMatchObject({ anonymous: true, exported: true, exportName: "default" });
    }
    expect(run("expr.ts", "const v = 1; export default v;").exports).toEqual([
      expect.objectContaining({ kind: "default", localName: "v", symbolIndex: 1 }) // linked to the module-level declaration
    ]);
  });

  it("CommonJS exports are recorded as commonjs exports", () => {
    const f = run("c.js", "function a() {}\nmodule.exports = { a, b: foo, c() {} };\nexports.d = 1;\nmodule.exports.e = function () {};");
    expect((f.exports ?? []).map((e) => `${e.kind}:${e.exportName}`)).toEqual(["commonjs:a", "commonjs:b", "commonjs:c", "commonjs:d", "commonjs:e"]);
    const single = run("s.js", "module.exports = function () {};");
    expect(single.exports).toEqual([expect.objectContaining({ kind: "commonjs", exportName: "module.exports" })]);
  });
});

describe("imports, requires and unknown targets", () => {
  it("records import bindings, side-effect imports, export-from, require and dynamic imports; unknown targets are NULL", () => {
    const f = run("r.ts", [
      'import d, { a as b, c } from "./m";',
      'import * as ns from "./n";',
      'import type { T } from "../types";',
      'import "./side";',
      'const r = require("./r");',
      "const r2 = require(name);",
      'const e = await import("./e");',
      "const g = await import(path);",
      "const h = await import(`./tpl/${x}`);"
    ].join("\n"));
    const refs = (f.refs ?? []).map((r) => `${r.kind}:${r.target}`);
    expect(refs).toEqual(["import:./m", "import:./n", "import:../types", "import:./side", "require:./r", "require:null", "dynamic_import:./e", "dynamic_import:null", "dynamic_import:null"]);
    expect(f.refs?.[0]?.names).toEqual([{ imported: "default", local: "d" }, { imported: "a", local: "b" }, { imported: "c", local: "c" }]);
    expect(f.refs?.[1]?.names).toEqual([{ imported: "*", local: "ns" }]);
    expect(f.refs?.[3]?.names).toEqual([]);
  });

  it("finds require/dynamic import inside function bodies and expressions", () => {
    const f = run("lazy.ts", 'export function load() { return import("./lazy"); }\nfunction x() { return require("./y"); }');
    expect((f.refs ?? []).map((r) => `${r.kind}:${r.target}`)).toEqual(["dynamic_import:./lazy", "require:./y"]);
  });
});

describe("JSX, TSX, JavaScript flavours", () => {
  it("parses JSX/TSX components", () => {
    expect(sym(run("c.tsx", "export const App = () => <div/>;\nexport function View(): JSX.Element { return <p/>; }"))).toEqual(["module:<module>", "function:App!", "function:View!"]);
    expect(sym(run("c.jsx", "export default function Page() { return <main>{[1].map(i => <i key={i}/>)}</main>; }"))).toContain("function:Page!");
  });
  it("parses ESM and CommonJS JavaScript", () => {
    expect(sym(run("m.mjs", "export default function main() {}"))).toContain("function:main!");
    expect(sym(run("x.cjs", "function legacy(a, b) { return a + b; }\nmodule.exports = { legacy };"))).toContain("function:legacy");
  });
});

describe("locations", () => {
  it("records 1-based lines, columns and UTF-8 byte ranges (including multi-byte text)", () => {
    const source = '// héllo wörld 日本\nexport function f() {}\n';
    const f = run("u.ts", source);
    const s = f.symbols?.find((x) => x.name === "f");
    expect(s).toMatchObject({ startLine: 2, endLine: 2, startColumn: 7 });
    const bytes = Buffer.from(source);
    expect(bytes.subarray(s!.startByte, s!.endByte).toString()).toBe("function f() {}");
  });
});

describe("errors, diagnostics and hostile input", () => {
  it("syntax errors give diagnostics without echoing source, partial facts, and no crash", () => {
    const f = run("bad.ts", 'export function ok() {}\nexport function broken( {{{ secret = "do-not-echo" \nexport class After {}');
    expect(f.parseStatus).toBe("error");
    expect(f.diagnostics?.length).toBeGreaterThan(0);
    expect(JSON.stringify(f.diagnostics)).not.toContain("do-not-echo");
    expect(sym(f)).toContain("function:ok!");
  });
  it("unsupported languages get NO extractor and therefore no fact (nothing cached that a supported path could inherit)", () => {
    for (const path of ["README.md", "data.json", "main.py", "x.go"]) {
      expect(codeExtractors.some((e) => extractorApplies(e, path)), path).toBe(false);
    }
  });
  it("unsupported languages are skipped, not failed", () => {
    for (const path of ["README.md", "data.json", "main.py", "x.go"]) {
      expect(run(path, "anything").parseStatus).toBe("skipped");
    }
  });
  it("contains adapter exceptions as error facts", () => {
    const exploding: LanguageAdapter = {
      id: "boom", version: "1", grammars: [{ id: "g", extensions: [".boom"] }], prepare: async () => undefined,
      extract: () => { throw new Error("secret internal detail"); }
    };
    const f = createCodeExtractors([exploding])[0]!.extract({ path: "a.boom", data: Buffer.from("x") });
    expect(f.parseStatus).toBe("error");
    expect(JSON.stringify(f)).not.toContain("secret internal detail");
  });
  it("hostile shapes finish quickly: deep nesting, huge lines, noise, many declarations and imports", () => {
    const cases: Array<[string, string]> = [
      ["deep.ts", `${"(".repeat(3000)}1${")".repeat(3000)};`],
      ["blocks.ts", `${"{".repeat(2000)}${"}".repeat(2000)}`],
      ["minified.js", `var a=${"function(){return 1}+".repeat(20000)}1;`],
      ["many.ts", Array.from({ length: 8000 }, (_, i) => `export function f${i}() {}`).join("\n")],
      ["noise.ts", "}{)(][;,".repeat(100_000)],
      ["imports.ts", Array.from({ length: 8000 }, (_, i) => `import x${i} from "./m${i}";`).join("\n")],
      ["nested-fns.ts", `${"function f(){".repeat(500)}${"}".repeat(500)}`]
    ];
    for (const [path, source] of cases) {
      const started = performance.now();
      const f = run(path, source);
      expect(performance.now() - started, path).toBeLessThan(6000);
      expect(["ok", "error"]).toContain(f.parseStatus);
    }
  });
  it("caps symbols and says so", () => {
    const f = run("cap.ts", Array.from({ length: 6000 }, (_, i) => `export function f${i}() {}`).join("\n"));
    expect(f.symbols?.length).toBe(5000);
    expect(f.parseStatus).toBe("error");
    expect(f.diagnostics?.some((d) => d.code === "limits_exceeded")).toBe(true);
  });
});

describe("determinism and adapter versioning", () => {
  it("same bytes give identical facts", () => {
    const src = 'import { a } from "./a";\nexport class K { m() {} }\nexport const f = () => 1;';
    expect(run("d.ts", src)).toEqual(run("d.ts", src));
  });
  it("extractor version derives from adapter versions so upgrades never mix facts", () => {
    const stub = (version: string): LanguageAdapter => ({ id: "x", version, grammars: [{ id: "g", extensions: [".x"] }], prepare: async () => undefined, extract: () => ({ language: null, parseStatus: "ok", attrs: {} }) });
    expect(createCodeExtractors([stub("1")])[0]!.version).not.toBe(createCodeExtractors([stub("2")])[0]!.version);
    // the parser and grammar package versions are part of the extractor version, so upgrading either never reuses old facts
    expect(codeExtractors.map((e) => e.version)).toEqual([expect.stringMatching(/^\d+\+wts\d+\.\d+\.\d+\+tst\d+\.\d+\.\d+$/), expect.stringMatching(/^\d+\+wts\d+\.\d+\.\d+\+tst\d+\.\d+\.\d+$/)]);
    expect(codeExtractors.map((e) => e.id)).toEqual(["code:ts-wasm:typescript", "code:ts-wasm:tsx"]);
  });
});
