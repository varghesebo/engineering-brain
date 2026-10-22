import { builtinModules } from "node:module";
import { posix } from "node:path";

/**
 * Deterministic, syntax-level module resolution (no compiler, no node_modules lookup, no code execution).
 * Every outcome is labelled: resolved / external / unresolved / ambiguous / dynamic. A relationship is never
 * guessed: when the rules cannot decide, it is `unresolved` or `ambiguous` with a reason.
 */
/** Version of the resolver AND the graph build that consumes it; a change forces every generation to be rebuilt. */
export const RESOLVER_VERSION = "3";

export type Resolution = "resolved" | "external" | "unresolved" | "ambiguous" | "dynamic";
export interface ResolvedModule {
  resolution: Resolution;
  resolvedPath: string | null;
  reason: string;
}

export interface PathMapping {
  pattern: string;
  targets: string[];
}

export interface TsConfigScope {
  /** Directory of the tsconfig/jsconfig (store path, "" = repository root). */
  dir: string;
  /** Resolved baseUrl as a store path, or null when not set. */
  baseUrl: string | null;
  paths: PathMapping[];
}

export interface WorkspacePackage {
  name: string;
  dir: string;
  entries: string[];
}

export interface ResolverConfig {
  files: ReadonlySet<string>;
  tsconfigs: readonly TsConfigScope[];
  packages: readonly WorkspacePackage[];
}

/** Extensionless specifiers never resolve to .json (TypeScript does not); an explicit `./data.json` still does (exact match). */
const SOURCE_EXTENSIONS = [".ts", ".tsx", ".d.ts", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"] as const;
/** Extensions that are the same module in different clothes (source + compiled output): not ambiguous with each other. */
const GROUP: Record<string, string> = {
  ".ts": "ts", ".d.ts": "ts", ".js": "ts", ".tsx": "tsx", ".jsx": "tsx", ".mts": "mts", ".mjs": "mts", ".cts": "cts", ".cjs": "cts", ".json": "json"
};
const JS_TO_TS: Record<string, string[]> = {
  ".js": [".ts", ".tsx", ".d.ts"], ".jsx": [".tsx"], ".mjs": [".mts", ".d.mts"], ".cjs": [".cts", ".d.cts"]
};
const BUILTINS = new Set(builtinModules.map((m) => m.replace(/^node:/, "")));

function extensionOf(path: string): string {
  const base = posix.basename(path);
  if (base.endsWith(".d.ts")) {
    return ".d.ts";
  }
  return posix.extname(base);
}

function join(base: string, ...parts: string[]): string {
  const joined = posix.normalize(posix.join(base === "" ? "." : base, ...parts));
  return joined === "." ? "" : joined;
}

const escapes = (path: string): boolean => path === ".." || path.startsWith("../");

interface Found {
  path: string;
  ambiguousWith: string[];
}

/** First level that has any existing candidate wins; within it the first candidate wins unless a different module family also exists. */
function tryFile(base: string, files: ReadonlySet<string>): Found | null {
  if (escapes(base)) {
    return null;
  }
  const levels: string[][] = [];
  const ext = extensionOf(base);
  const mapped = JS_TO_TS[ext];
  const stem = base.slice(0, base.length - ext.length);
  levels.push([...(mapped ?? []).map((m) => stem + m), base]);
  levels.push(SOURCE_EXTENSIONS.map((e) => base + e));
  levels.push(SOURCE_EXTENSIONS.map((e) => join(base, `index${e}`)));
  for (const level of levels) {
    const existing = level.filter((candidate, i) => files.has(candidate) && level.indexOf(candidate) === i);
    const winner = existing[0];
    if (winner === undefined) {
      continue;
    }
    const winnerGroup = GROUP[extensionOf(winner)];
    const different = existing.filter((c) => GROUP[extensionOf(c)] !== winnerGroup);
    return { path: winner, ambiguousWith: different };
  }
  return null;
}

function outcomeFor(found: Found | null, reasonWhenFound: string, reasonWhenMissing: string): ResolvedModule {
  if (found === null) {
    return { resolution: "unresolved", resolvedPath: null, reason: reasonWhenMissing };
  }
  if (found.ambiguousWith.length > 0) {
    return { resolution: "ambiguous", resolvedPath: null, reason: `candidates:${[found.path, ...found.ambiguousWith].sort().join(",")}` };
  }
  return { resolution: "resolved", resolvedPath: found.path, reason: reasonWhenFound };
}

function scopeFor(fromDir: string, scopes: readonly TsConfigScope[]): TsConfigScope | null {
  let best: TsConfigScope | null = null;
  for (const scope of scopes) {
    const inside = scope.dir === "" || fromDir === scope.dir || fromDir.startsWith(`${scope.dir}/`);
    if (inside && (best === null || scope.dir.length > best.dir.length)) {
      best = scope;
    }
  }
  return best;
}

function matchPattern(pattern: string, specifier: string): string | null {
  const star = pattern.indexOf("*");
  if (star === -1) {
    return pattern === specifier ? "" : null;
  }
  const prefix = pattern.slice(0, star);
  const suffix = pattern.slice(star + 1);
  if (specifier.length >= prefix.length + suffix.length && specifier.startsWith(prefix) && specifier.endsWith(suffix)) {
    return specifier.slice(prefix.length, specifier.length - suffix.length);
  }
  return null;
}

function viaTsConfig(specifier: string, fromDir: string, config: ResolverConfig): ResolvedModule | null {
  const scope = scopeFor(fromDir, config.tsconfigs);
  if (scope === null) {
    return null;
  }
  const base = scope.baseUrl ?? scope.dir;
  let best: { mapping: PathMapping; captured: string; specificity: number } | null = null;
  for (const mapping of scope.paths) {
    const captured = matchPattern(mapping.pattern, specifier);
    const specificity = mapping.pattern.indexOf("*") === -1 ? mapping.pattern.length + 1 : mapping.pattern.indexOf("*");
    if (captured !== null && (best === null || specificity > best.specificity)) {
      best = { mapping, captured, specificity };
    }
  }
  if (best !== null) {
    for (const target of best.mapping.targets) {
      const found = tryFile(join(base, target.replace("*", best.captured)), config.files);
      if (found !== null) {
        return outcomeFor(found, "tsconfig_paths", "tsconfig_paths_target_missing");
      }
    }
    // A catch-all `"*"` mapping is a fallback by design (typings folders etc.): TypeScript continues with normal resolution.
    if (best.mapping.pattern !== "*") {
      return { resolution: "unresolved", resolvedPath: null, reason: "tsconfig_paths_target_missing" };
    }
  }
  if (scope.baseUrl !== null) {
    const found = tryFile(join(scope.baseUrl, specifier), config.files);
    if (found !== null) {
      return outcomeFor(found, "tsconfig_baseUrl", "tsconfig_baseUrl_target_missing");
    }
  }
  return null;
}

function packageName(specifier: string): string {
  const parts = specifier.split("/");
  return specifier.startsWith("@") ? parts.slice(0, 2).join("/") : (parts[0] ?? specifier);
}

const packageIndexCache = new WeakMap<readonly WorkspacePackage[], Map<string, WorkspacePackage[]>>();

function packageIndex(packages: readonly WorkspacePackage[]): Map<string, WorkspacePackage[]> {
  let index = packageIndexCache.get(packages);
  if (index === undefined) {
    index = new Map();
    for (const pkg of packages) {
      const list = index.get(pkg.name);
      if (list === undefined) {
        index.set(pkg.name, [pkg]);
      } else {
        list.push(pkg);
      }
    }
    packageIndexCache.set(packages, index);
  }
  return index;
}

function viaWorkspace(specifier: string, config: ResolverConfig): ResolvedModule | null {
  if (config.packages.length === 0) {
    return null;
  }
  const index = packageIndex(config.packages);
  // longest package-name prefix at a segment boundary, by map lookup (not a scan over every package)
  const segments = specifier.split("/");
  for (let take = segments.length; take >= 1; take -= 1) {
    const name = segments.slice(0, take).join("/");
    const matches = index.get(name);
    if (matches === undefined) {
      continue;
    }
    if (matches.length > 1) {
      return { resolution: "ambiguous", resolvedPath: null, reason: `duplicate_workspace_package:${name}:${matches.map((m) => m.dir || ".").sort().join(",")}` };
    }
    const match = matches[0]!;
    const sub = specifier === match.name ? "" : specifier.slice(match.name.length + 1);
    const candidates = sub === "" ? [...match.entries, "src/index", "index"] : [sub, `src/${sub}`];
    for (const candidate of candidates) {
      const found = tryFile(join(match.dir, candidate), config.files);
      if (found !== null) {
        return outcomeFor(found, `workspace_package:${match.name}`, "workspace_package_entry_not_found");
      }
    }
    return { resolution: "unresolved", resolvedPath: null, reason: "workspace_package_entry_not_found" };
  }
  return null;
}

export function resolveModule(fromPath: string, specifier: string | null, config: ResolverConfig): ResolvedModule {
  if (specifier === null) {
    return { resolution: "dynamic", resolvedPath: null, reason: "non_literal_specifier" };
  }
  if (specifier === "") {
    return { resolution: "unresolved", resolvedPath: null, reason: "empty_specifier" };
  }
  const fromDir = posix.dirname(fromPath) === "." ? "" : posix.dirname(fromPath);
  if (specifier === "." || specifier === ".." || specifier.startsWith("./") || specifier.startsWith("../")) {
    const target = join(fromDir, specifier);
    if (escapes(target)) {
      return { resolution: "unresolved", resolvedPath: null, reason: "outside_repository" };
    }
    return outcomeFor(tryFile(target, config.files), "relative", "relative_target_missing");
  }
  if (specifier.startsWith("/") || /^[a-z][a-z0-9+.-]*:/i.test(specifier) && !specifier.startsWith("node:")) {
    return { resolution: "unresolved", resolvedPath: null, reason: "unsupported_specifier" };
  }
  if (specifier.startsWith("#")) {
    return { resolution: "unresolved", resolvedPath: null, reason: "unsupported_package_imports" };
  }
  const bareName = packageName(specifier);
  if (specifier.startsWith("node:") || BUILTINS.has(specifier) || BUILTINS.has(bareName)) {
    // Node builtins win over any workspace package or alias that happens to share the name
    return { resolution: "external", resolvedPath: null, reason: "node_builtin" };
  }
  const viaConfig = viaTsConfig(specifier, fromDir, config);
  if (viaConfig !== null) {
    return viaConfig;
  }
  const viaPackage = viaWorkspace(specifier, config);
  if (viaPackage !== null) {
    return viaPackage;
  }
  return { resolution: "external", resolvedPath: null, reason: `package:${bareName}` };
}

/** Tolerant JSON-with-comments reader for tsconfig files. Returns null on anything it cannot parse. Never evaluates code. */
export function parseJsonc(text: string): unknown {
  let out = "";
  let inString = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i]!;
    const next = text[i + 1];
    if (inString) {
      out += ch;
      if (ch === "\\") {
        out += text[i + 1] ?? "";
        i += 1;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }
    if (ch === '"') {
      inString = true;
      out += ch;
    } else if (ch === "/" && next === "/") {
      while (i < text.length && text[i] !== "\n") {
        i += 1;
      }
      out += "\n";
    } else if (ch === "/" && next === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) {
        i += 1;
      }
      i += 1;
    } else {
      out += ch;
    }
  }
  try {
    return JSON.parse(out.replace(/,(\s*[}\]])/g, "$1")) as unknown;
  } catch {
    return null;
  }
}
