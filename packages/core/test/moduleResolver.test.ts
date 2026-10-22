import { describe, expect, it } from "vitest";
import { parseJsonc, resolveModule, type ResolverConfig } from "../src/moduleResolver.js";

const cfg = (files: string[], extra: Partial<ResolverConfig> = {}): ResolverConfig => ({ files: new Set(files), tsconfigs: [], packages: [], ...extra });
const r = (from: string, spec: string | null, config: ResolverConfig) => resolveModule(from, spec, config);

describe("relative resolution", () => {
  const config = cfg(["src/a.ts", "src/b.tsx", "src/util/index.ts", "src/lib.js", "src/types.d.ts", "src/data.json", "src/c/index.js", "x.ts"]);
  it("resolves extensionless specifiers, directory indexes and parent paths", () => {
    expect(r("src/main.ts", "./a", config)).toMatchObject({ resolution: "resolved", resolvedPath: "src/a.ts", reason: "relative" });
    expect(r("src/main.ts", "./util", config).resolvedPath).toBe("src/util/index.ts");
    expect(r("src/main.ts", "./util/", config).resolvedPath).toBe("src/util/index.ts");
    expect(r("src/deep/x.ts", "../a", config).resolvedPath).toBe("src/a.ts");
    expect(r("src/c/main.js", "./", config).resolvedPath).toBe("src/c/index.js");
    expect(r("src/main.ts", "./data.json", config).resolvedPath).toBe("src/data.json");
    expect(r("src/main.ts", "./lib", config).resolvedPath).toBe("src/lib.js");
    expect(r("src/main.ts", "./types", config).resolvedPath).toBe("src/types.d.ts");
  });
  it("maps ESM-style .js specifiers to TypeScript sources, preferring the source", () => {
    const both = cfg(["src/a.ts", "src/a.js", "src/b.tsx"]);
    expect(r("src/m.ts", "./a.js", both)).toMatchObject({ resolution: "resolved", resolvedPath: "src/a.ts" });
    expect(r("src/m.ts", "./b.jsx", both).resolvedPath).toBe("src/b.tsx");
  });
  it("is ambiguous only when different module families collide, never guessed", () => {
    const amb = cfg(["src/x.ts", "src/x.tsx"]);
    expect(r("src/m.ts", "./x", amb)).toEqual({ resolution: "ambiguous", resolvedPath: null, reason: "candidates:src/x.ts,src/x.tsx" });
    const shadow = cfg(["src/x.ts", "src/x.js"]);
    expect(r("src/m.ts", "./x", shadow).resolution).toBe("resolved");
  });
  it("reports missing targets and repository escapes as unresolved with a reason", () => {
    const config2 = cfg(["a.ts"]);
    expect(r("a.ts", "./nope", config2)).toEqual({ resolution: "unresolved", resolvedPath: null, reason: "relative_target_missing" });
    expect(r("src/a.ts", "../../../../etc/passwd", config2)).toMatchObject({ resolution: "unresolved", reason: "outside_repository" });
    expect(r("a.ts", "..", config2)).toMatchObject({ resolution: "unresolved", reason: "outside_repository" });
  });
});

describe("dynamic, external and unsupported specifiers", () => {
  const config = cfg(["a.ts"]);
  it("a non-literal target is dynamic: explicitly unknown, never resolved", () => {
    expect(r("a.ts", null, config)).toEqual({ resolution: "dynamic", resolvedPath: null, reason: "non_literal_specifier" });
  });
  it("packages and Node builtins are external, with the package name", () => {
    expect(r("a.ts", "lodash/fp", config)).toEqual({ resolution: "external", resolvedPath: null, reason: "package:lodash" });
    expect(r("a.ts", "@scope/pkg/sub", config).reason).toBe("package:@scope/pkg");
    expect(r("a.ts", "node:fs", config).reason).toBe("node_builtin");
    expect(r("a.ts", "fs", config).reason).toBe("node_builtin");
    expect(r("a.ts", "fs/promises", config).reason).toBe("node_builtin");
  });
  it("urls, absolute paths, package imports and empty specifiers are unresolved, not guessed", () => {
    for (const [spec, reason] of [["https://x.example/a.js", "unsupported_specifier"], ["/etc/passwd", "unsupported_specifier"], ["file:///x", "unsupported_specifier"], ["data:text/javascript,1", "unsupported_specifier"], ["#internal", "unsupported_package_imports"], ["", "empty_specifier"]] as const) {
      expect(r("a.ts", spec, config), spec).toMatchObject({ resolution: "unresolved", reason });
    }
  });
});

describe("tsconfig paths and baseUrl", () => {
  const files = ["src/a.ts", "src/shared/x.ts", "packages/app/src/p.ts", "packages/app/src/util.ts", "other/o.ts"];
  const root = { dir: "", baseUrl: ".", paths: [{ pattern: "@app/*", targets: ["src/*"] }, { pattern: "@x", targets: ["src/shared/x.ts"] }, { pattern: "@missing/*", targets: ["nowhere/*"] }] };
  it("applies paths with a wildcard, an exact pattern, and reports a missing target", () => {
    const c = cfg(files, { tsconfigs: [root] });
    expect(r("src/a.ts", "@app/shared/x", c)).toMatchObject({ resolution: "resolved", resolvedPath: "src/shared/x.ts", reason: "tsconfig_paths" });
    expect(r("src/a.ts", "@x", c).resolvedPath).toBe("src/shared/x.ts");
    expect(r("src/a.ts", "@missing/y", c)).toMatchObject({ resolution: "unresolved", reason: "tsconfig_paths_target_missing" });
  });
  it("uses the most specific pattern", () => {
    const c = cfg(files, { tsconfigs: [{ dir: "", baseUrl: ".", paths: [{ pattern: "@app/*", targets: ["nowhere/*"] }, { pattern: "@app/shared/*", targets: ["src/shared/*"] }] }] });
    expect(r("src/a.ts", "@app/shared/x", c).resolvedPath).toBe("src/shared/x.ts");
  });
  it("applies the NEAREST tsconfig by directory", () => {
    const nested = { dir: "packages/app", baseUrl: "packages/app", paths: [{ pattern: "@/*", targets: ["src/*"] }] };
    const c = cfg(files, { tsconfigs: [root, nested] });
    expect(r("packages/app/src/p.ts", "@/util", c).resolvedPath).toBe("packages/app/src/util.ts");
    expect(r("src/a.ts", "@/util", c).resolution).toBe("external"); // not visible outside that package
  });
  it("baseUrl resolves non-relative specifiers before treating them as packages", () => {
    const c = cfg(files, { tsconfigs: [{ dir: "", baseUrl: "src", paths: [] }] });
    expect(r("other/o.ts", "shared/x", c)).toMatchObject({ resolution: "resolved", resolvedPath: "src/shared/x.ts", reason: "tsconfig_baseUrl" });
  });
  it("a paths target that escapes the repository can never resolve", () => {
    const c = cfg(files, { tsconfigs: [{ dir: "", baseUrl: ".", paths: [{ pattern: "@evil/*", targets: ["../../outside/*"] }] }] });
    expect(r("src/a.ts", "@evil/secret", c)).toMatchObject({ resolution: "unresolved" });
  });
});

describe("workspace packages", () => {
  const packages = [{ name: "@org/lib", dir: "packages/lib", entries: ["src/main"] }, { name: "plain", dir: "packages/plain", entries: [] }];
  const files = ["packages/lib/src/main.ts", "packages/lib/src/sub/thing.ts", "packages/plain/index.ts"];
  it("resolves a package entry, a deep import, and a package without main via index", () => {
    const c = cfg(files, { packages });
    expect(r("a.ts", "@org/lib", c)).toMatchObject({ resolution: "resolved", resolvedPath: "packages/lib/src/main.ts", reason: "workspace_package:@org/lib" });
    expect(r("a.ts", "@org/lib/sub/thing", c).resolvedPath).toBe("packages/lib/src/sub/thing.ts");
    expect(r("a.ts", "plain", c).resolvedPath).toBe("packages/plain/index.ts");
  });
  it("a workspace package whose entry is missing is unresolved, not external", () => {
    expect(r("a.ts", "@org/lib/missing", cfg(files, { packages }))).toMatchObject({ resolution: "unresolved", reason: "workspace_package_entry_not_found" });
  });
});

describe("parseJsonc", () => {
  it("accepts comments and trailing commas, preserves strings that look like comments", () => {
    expect(parseJsonc('{ // c\n "a": "http://x//y", /* b */ "b": [1, 2,], }')).toEqual({ a: "http://x//y", b: [1, 2] });
  });
  it("returns null for garbage and never throws", () => {
    for (const bad of ["{", "not json", "", "{'a':1}"]) {
      expect(parseJsonc(bad)).toBeNull();
    }
  });
  it("handles hostile input in bounded time", () => {
    const started = performance.now();
    parseJsonc(`${"/*".repeat(50_000)}`);
    parseJsonc(`{"a":"${"\\\\".repeat(100_000)}"}`);
    parseJsonc("[".repeat(100_000));
    expect(performance.now() - started).toBeLessThan(2000);
  });
});
