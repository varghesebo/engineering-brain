import { beforeAll, describe, expect, it } from "vitest";
import { codeExtractors } from "../src/codeExtractor.js";
import { extractorApplies, type ExtractedFact } from "../src/extractor.js";

beforeAll(async () => {
  await Promise.all(codeExtractors.map((e) => e.prepare?.()));
});
const run = (path: string, source: string): ExtractedFact => codeExtractors.find((e) => extractorApplies(e, path))!.extract({ path, data: Buffer.from(source) });
const rels = (f: ExtractedFact): string[] => (f.relations ?? []).map((r) => `${f.symbols?.[r.symbolIndex]?.qualifiedName}:${r.relation}:${r.target}`);
const refs = (f: ExtractedFact): string[] => (f.symbolRefs ?? []).map((r) => `${f.symbols?.[r.symbolIndex]?.qualifiedName || "<module>"}->${r.name}`);

describe("graph facts: heritage", () => {
  it("records extends/implements targets as written (identifier, dotted, generic), NULL for expressions", () => {
    const f = run("a.ts", [
      "class A<T> extends ns.Base<T> implements I, J<string>, K.L {}",
      "interface Iface extends P, Q<number> {}",
      "abstract class D extends (mixin(E)) {}",
      "class Plain {}"
    ].join("\n"));
    expect(rels(f)).toEqual(["A:extends:ns.Base", "A:implements:I", "A:implements:J", "A:implements:K.L", "Iface:extends:P", "Iface:extends:Q", "D:extends:null"]);
  });
  it("heritage targets are not also counted as body references", () => {
    const f = run("b.ts", 'import { Base } from "./base";\nclass C extends Base { m() { return 1; } }');
    expect(rels(f)).toEqual(["C:extends:Base"]);
    expect(refs(f)).toEqual([]);
  });
});

describe("graph facts: references to import-bound names", () => {
  it("records uses inside the owning symbol, deduplicated per symbol, with module-level uses owned by the module", () => {
    const f = run("c.ts", [
      'import { helper, Other as O } from "./h";',
      'import * as ns from "./n";',
      'import def from "./d";',
      "export function run(x: helper.T) { helper(x); helper(2); return ns.thing(O, def); }",
      "const top = helper(1);"
    ].join("\n"));
    expect(refs(f)).toEqual(expect.arrayContaining(["run->helper", "run->ns", "run->O", "run->def", "<module>->helper"]));
    expect(refs(f).filter((r) => r === "run->helper").length).toBe(1);
  });
  it("does not count binding sites, property names, or unrelated identifiers", () => {
    const f = run("d.ts", [
      'import { a } from "./a";',
      "function shadow(a: number) { return a; }",
      "function viaDestructure({ a }: { a: number }) { return 1; }",
      "function prop(o: { a: number }) { return o.a; }",
      "function use() { return a; }"
    ].join("\n"));
    const list = refs(f);
    expect(list).toContain("use->a");
    expect(list.filter((r) => r.startsWith("shadow") || r.startsWith("viaDestructure") || r.startsWith("prop"))).toEqual([]);
  });
  it("CommonJS require bindings are import bindings and keep their names on the ref", () => {
    const f = run("e.js", 'const fs = require("fs");\nconst { join, resolve: res } = require("path");\nfunction go() { return join(fs, res); }');
    expect((f.refs ?? []).map((r) => `${r.kind}:${r.target}:${(r.names ?? []).map((n) => `${n.imported}>${n.local}`).join("|")}`)).toEqual([
      "require:fs:*>fs", "require:path:join>join|resolve>res"
    ]);
    expect(refs(f)).toEqual(expect.arrayContaining(["go->join", "go->fs", "go->res"]));
    expect((f.refs ?? []).length).toBe(2); // no duplicate ref from the generic call handler
  });
  it("JSX component usage and type-position usage count as references", () => {
    const f = run("f.tsx", 'import { Button } from "./Button";\nimport type { Props } from "./types";\nexport const App = (p: Props) => <Button />;');
    expect(refs(f)).toEqual(expect.arrayContaining(["App->Button", "App->Props"]));
  });
  it("caps references per symbol and says so", () => {
    const names = Array.from({ length: 80 }, (_, i) => `n${i}`);
    const f = run("g.ts", `import { ${names.join(", ")} } from "./m";\nexport function big() { ${names.map((n) => `${n}();`).join(" ")} }`);
    expect((f.symbolRefs ?? []).length).toBe(40);
    expect(f.diagnostics?.some((d) => d.code === "limits_exceeded")).toBe(true);
  });
});
