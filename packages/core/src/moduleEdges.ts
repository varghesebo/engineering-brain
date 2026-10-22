import { posix } from "node:path";
import picomatch from "picomatch";
import { EngbrainError } from "./errors.js";
import { readRegularFileBounded } from "./fsSafe.js";
import { sha256Hex } from "./hash.js";
import { parseJsonc, type PathMapping, type ResolverConfig, type TsConfigScope, type WorkspacePackage } from "./moduleResolver.js";
import { resolveUnderRoot } from "./paths.js";

const CONFIG_MAX_BYTES = 256 * 1024;
/** A hostile repository must not be able to make resolution arbitrarily slow: configuration sizes are capped. */
const MAX_PATH_PATTERNS = 1000;
const MAX_WORKSPACE_PACKAGES = 2000;
const MAX_WORKSPACE_GLOBS = 100;
const EXTENDS_MAX_DEPTH = 5;

type Json = Record<string, unknown>;
const isObject = (value: unknown): value is Json => typeof value === "object" && value !== null && !Array.isArray(value);
const dirOf = (path: string): string => (posix.dirname(path) === "." ? "" : posix.dirname(path));
const joinStore = (base: string, relative: string): string => {
  const joined = posix.normalize(posix.join(base === "" ? "." : base, relative));
  return joined === "." ? "" : joined;
};

interface ConfigReader {
  /** Reads a config file only if its bytes still match the manifest hash (so edges never mix with a different snapshot); throws if they changed. */
  read(path: string): Json | null;
  readText(path: string): string | null;
}

function makeReader(root: string, hashes: ReadonlyMap<string, string>): ConfigReader {
  const readBytes = (path: string): Buffer | null => {
    const absolute = resolveUnderRoot(root, path);
    const expected = hashes.get(path);
    if (absolute === null || expected === undefined) {
      return null;
    }
    const result = readRegularFileBounded(absolute, CONFIG_MAX_BYTES);
    if (result.kind !== "ok") {
      return null;
    }
    if (sha256Hex(result.file.data) !== expected) {
      // the file changed after the manifest was written: edges built from it would belong to a different snapshot
      throw new EngbrainError("INTEGRITY_FAILED", "a configuration file changed while indexing; run the index again");
    }
    return result.file.data;
  };
  return {
    read(path) {
      const data = readBytes(path);
      if (data === null) {
        return null;
      }
      const parsed = parseJsonc(data.toString("utf8"));
      return isObject(parsed) ? parsed : null;
    },
    readText(path) {
      return readBytes(path)?.toString("utf8") ?? null;
    }
  };
}

/** Effective compilerOptions.paths/baseUrl for one tsconfig, following RELATIVE `extends` inside the repository only. */
function loadScope(path: string, reader: ConfigReader, files: ReadonlySet<string>): TsConfigScope | null {
  let baseUrl: string | null = null;
  let paths: PathMapping[] = [];
  let pathsBase = dirOf(path);
  const chain: string[] = [];
  let current: string | null = path;
  for (let depth = 0; current !== null && depth < EXTENDS_MAX_DEPTH; depth += 1) {
    const json = reader.read(current);
    if (json === null) {
      break;
    }
    chain.push(current);
    const options = isObject(json["compilerOptions"]) ? json["compilerOptions"] : {};
    const parentDir = dirOf(current);
    if (baseUrl === null && typeof options["baseUrl"] === "string") {
      baseUrl = joinStore(parentDir, options["baseUrl"]);
    }
    if (paths.length === 0 && isObject(options["paths"])) {
      paths = Object.entries(options["paths"]).slice(0, MAX_PATH_PATTERNS)
        .filter((entry): entry is [string, unknown[]] => Array.isArray(entry[1]))
        .map(([pattern, targets]) => ({ pattern, targets: targets.filter((t): t is string => typeof t === "string") }));
      pathsBase = parentDir;
    }
    const parent = json["extends"];
    current = null;
    if (typeof parent === "string" && (parent.startsWith("./") || parent.startsWith("../"))) {
      const candidate = joinStore(parentDir, parent.endsWith(".json") ? parent : `${parent}.json`);
      current = files.has(candidate) && !chain.includes(candidate) ? candidate : null;
    }
  }
  if (chain.length === 0) {
    return null;
  }
  // `paths` without baseUrl are relative to the config that declared them
  return { dir: dirOf(path), baseUrl: baseUrl ?? (paths.length > 0 ? pathsBase : null), paths };
}

function entriesOf(json: Json): string[] {
  const out: string[] = [];
  for (const key of ["main", "module", "types", "typings"]) {
    const value = json[key];
    if (typeof value === "string" && !value.startsWith("/") && !value.includes("..")) {
      out.push(value.replace(/^\.\//, ""));
    }
  }
  return out;
}

/** Glob list from a root package.json `workspaces` field (array or `{ packages }`). */
function workspaceGlobsOf(json: Json): string[] {
  const field = json["workspaces"];
  const list = Array.isArray(field) ? field : isObject(field) && Array.isArray(field["packages"]) ? field["packages"] : [];
  return list.filter((g): g is string => typeof g === "string" && g.length > 0 && g.length < 200).slice(0, MAX_WORKSPACE_GLOBS);
}

/** Minimal reader for pnpm-workspace.yaml: the `packages:` list of plain or quoted globs. No YAML evaluation of any kind. */
function pnpmGlobsOf(text: string): string[] {
  const out: string[] = [];
  let inPackages = false;
  for (const line of text.split(/\r?\n/).slice(0, 500)) {
    if (/^packages\s*:/.test(line)) {
      inPackages = true;
    } else if (/^\S/.test(line)) {
      inPackages = false;
    } else if (inPackages) {
      const match = /^\s*-\s*["']?([^"'#\s]+)["']?\s*(#.*)?$/.exec(line);
      if (match?.[1] !== undefined && out.length < MAX_WORKSPACE_GLOBS) {
        out.push(match[1]);
      }
    }
  }
  return out;
}

/**
 * A package.json only counts as a workspace package when a workspace root (package.json `workspaces` or pnpm-workspace.yaml)
 * declares a glob matching its directory. Without that, a stray package.json (an example, a fixture, a template) could shadow
 * a real npm package of the same name for the whole repository.
 */
function declaredWorkspaces(reader: ConfigReader, manifest: ReadonlyArray<{ path: string }>): Array<{ dir: string; isMatch: (relativeDir: string) => boolean }> {
  const roots: Array<{ dir: string; isMatch: (relativeDir: string) => boolean }> = [];
  for (const { path } of manifest) {
    const base = posix.basename(path);
    let globs: string[] = [];
    if (base === "package.json") {
      const json = reader.read(path);
      globs = json === null ? [] : workspaceGlobsOf(json);
    } else if (base === "pnpm-workspace.yaml") {
      globs = pnpmGlobsOf(reader.readText(path) ?? "");
    }
    if (globs.length > 0) {
      const positive = globs.filter((g) => !g.startsWith("!"));
      const negative = globs.filter((g) => g.startsWith("!")).map((g) => g.slice(1));
      const include = picomatch(positive, { dot: true });
      const exclude = negative.length > 0 ? picomatch(negative, { dot: true }) : () => false;
      roots.push({ dir: dirOf(path), isMatch: (rel) => include(rel) && !exclude(rel) });
    }
  }
  return roots;
}

/** Builds resolver inputs from the generation's own manifest, so resolution reflects exactly this snapshot. */
export function loadResolverConfig(
  root: string, manifest: ReadonlyArray<{ path: string; contentHash: string }>
): ResolverConfig {
  const files = new Set(manifest.map((m) => m.path));
  const hashes = new Map(manifest.map((m) => [m.path, m.contentHash]));
  const reader = makeReader(root, hashes);
  const scopes: TsConfigScope[] = [];
  const packages: WorkspacePackage[] = [];
  const workspaceRoots = declaredWorkspaces(reader, manifest);
  for (const { path } of manifest) {
    const base = posix.basename(path);
    if (base === "tsconfig.json" || base === "jsconfig.json") {
      const scope = loadScope(path, reader, files);
      if (scope !== null) {
        scopes.push(scope);
      }
    } else if (base === "package.json" && packages.length < MAX_WORKSPACE_PACKAGES) {
      const dir = dirOf(path);
      const declared = workspaceRoots.some((r) => r.dir !== dir && (r.dir === "" || dir.startsWith(`${r.dir}/`)) && r.isMatch(r.dir === "" ? dir : dir.slice(r.dir.length + 1)));
      if (!declared) {
        continue;
      }
      const json = reader.read(path);
      if (json !== null && typeof json["name"] === "string" && json["name"].length > 0 && json["name"].length < 214) {
        packages.push({ name: json["name"], dir, entries: entriesOf(json) });
      }
    }
  }
  return { files, tsconfigs: scopes, packages };
}
