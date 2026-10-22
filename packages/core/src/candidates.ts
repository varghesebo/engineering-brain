import { lstatSync, readdirSync } from "node:fs";
import { join } from "node:path";
import type { HardenedGit } from "@engbrain/security";
import { evaluateContent } from "./contentPolicy.js";
import { EngbrainError } from "./errors.js";
import type { ExclusionMatcher } from "./exclusions.js";
import { readRegularFileBounded, type FileSnapshot } from "./fsSafe.js";
import type { GitInfo } from "./identity.js";
import { collisionKey, resolveUnderRoot, toStorePath } from "./paths.js";
import type { ManifestRow } from "./store/generations.js";

export interface Candidate {
  /** Normalised (NFC, forward slash) key stored in the manifest. */
  storePath: string;
  /** The name exactly as listed on disk; used to OPEN the file (NFC and NFD names differ on Linux). */
  rawPath: string;
  /** Excluded before reading (e.g. symlink found while walking). */
  preExcluded?: string;
}

/** Verifies, once per directory, that every parent component of a path is a real directory (not a symlink). */
export class DirectoryGuard {
  private readonly verdicts = new Map<string, "ok" | "symlink" | "missing">();

  constructor(private readonly root: string) {}

  check(relativeDirectory: string): "ok" | "symlink" | "missing" {
    if (relativeDirectory === "") {
      return "ok";
    }
    const known = this.verdicts.get(relativeDirectory);
    if (known !== undefined) {
      return known;
    }
    const cut = relativeDirectory.lastIndexOf("/");
    const parent = this.check(cut === -1 ? "" : relativeDirectory.slice(0, cut));
    let verdict: "ok" | "symlink" | "missing" = parent;
    if (parent === "ok") {
      try {
        const stat = lstatSync(join(this.root, ...relativeDirectory.split("/")));
        verdict = stat.isSymbolicLink() ? "symlink" : stat.isDirectory() ? "ok" : "missing";
      } catch {
        verdict = "missing";
      }
    }
    this.verdicts.set(relativeDirectory, verdict);
    return verdict;
  }
}

export async function enumerateCandidates(git: GitInfo, hardenedGit: HardenedGit | null, matcher: ExclusionMatcher): Promise<Candidate[]> {
  const seen = new Map<string, Candidate>();
  const add = (candidate: Candidate): void => {
    seen.set(candidate.rawPath, candidate); // keyed by the on-disk name: NFC/NFD twins stay distinct so the collision is DETECTED
  };
  if (git.isGit) {
    const runner = hardenedGit;
    if (runner === null) {
      throw new EngbrainError("GIT_UNAVAILABLE", "git is required to list files in a git repository");
    }
    const listings = await Promise.all([
      runner.run(git.root, ["ls-files", "-z"]),
      runner.run(git.root, ["ls-files", "-z", "--others", "--exclude-standard"])
    ]);
    for (const listing of listings) {
      for (const raw of listing.split("\0")) {
        if (raw === "") {
          continue;
        }
        const normalized = toStorePath(raw);
        // Files under excluded directories (node_modules, dist, .git, ...) are pruned exactly like the plain directory
        // walk does: not enumerated, not recorded. Otherwise the manifest would depend on HOW the tree was listed.
        if (normalized.ok && matcher.excludesPath(normalized.path) === "excluded_directory") {
          continue;
        }
        add(
          normalized.ok && !raw.includes("\uFFFD")
            ? { storePath: normalized.path, rawPath: raw }
            : { storePath: raw, rawPath: raw, preExcluded: normalized.ok ? "invalid_path" : normalized.reason }
        );
      }
    }
  } else {
    walk(git.root, "", matcher, add);
  }
  const byKey = (a: Candidate, b: Candidate): number =>
    a.storePath < b.storePath ? -1 : a.storePath > b.storePath ? 1 : a.rawPath < b.rawPath ? -1 : a.rawPath > b.rawPath ? 1 : 0;
  return [...seen.values()].sort(byKey);
}

function walk(root: string, relative: string, matcher: ExclusionMatcher, add: (candidate: Candidate) => void): void {
  const directory = relative === "" ? root : join(root, ...relative.split("/"));
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const rel = relative === "" ? entry.name : `${relative}/${entry.name}`;
    if (entry.isSymbolicLink()) {
      add({ storePath: rel, rawPath: rel, preExcluded: "symlink" });
    } else if (entry.isDirectory()) {
      if (!matcher.excludesDirectory(entry.name)) {
        walk(root, rel, matcher, add);
      }
    } else {
      const normalized = toStorePath(rel);
      add(normalized.ok ? { storePath: normalized.path, rawPath: rel } : { storePath: rel, rawPath: rel, preExcluded: normalized.reason });
    }
  }
}


export type Inspection =
  | { kind: "excluded"; reason: string }
  | { kind: "missing" }
  | { kind: "file"; row: ManifestRow; data: Buffer; file: FileSnapshot };

export interface InspectContext {
  root: string;
  matcher: ExclusionMatcher;
  maxFileBytes: number;
  directories: DirectoryGuard;
  /** Case/normalisation collision keys seen so far in this pass (order-dependent by design: sorted candidates). */
  seenKeys: Set<string>;
}

export function createInspectContext(root: string, matcher: ExclusionMatcher, maxFileBytes: number): InspectContext {
  return { root, matcher, maxFileBytes, directories: new DirectoryGuard(root), seenKeys: new Set() };
}

/**
 * The single policy for deciding what a candidate path is: excluded (with a reason), missing, or an included file with its
 * bytes and content hash. Used by indexing and by hash-verified freshness checks so both always agree.
 */
export function inspectCandidate(ctx: InspectContext, candidate: Candidate): Inspection {
  const path = candidate.storePath;
  if (candidate.preExcluded !== undefined) {
    return { kind: "excluded", reason: candidate.preExcluded };
  }
  const key = collisionKey(path);
  if (ctx.seenKeys.has(key)) {
    return { kind: "excluded", reason: "path_collision" };
  }
  ctx.seenKeys.add(key);
  const pathReason = ctx.matcher.excludesPath(path);
  if (pathReason !== null) {
    return { kind: "excluded", reason: pathReason };
  }
  const absolute = resolveUnderRoot(ctx.root, candidate.rawPath);
  if (absolute === null) {
    return { kind: "excluded", reason: "invalid_path" };
  }
  const cut = candidate.rawPath.lastIndexOf("/");
  const parentVerdict = ctx.directories.check(cut === -1 ? "" : candidate.rawPath.slice(0, cut));
  if (parentVerdict !== "ok") {
    return parentVerdict === "symlink" ? { kind: "excluded", reason: "symlink" } : { kind: "missing" };
  }
  let stat;
  try {
    stat = lstatSync(absolute);
  } catch {
    return { kind: "missing" };
  }
  if (stat.isSymbolicLink()) {
    return { kind: "excluded", reason: "symlink" };
  }
  if (!stat.isFile()) {
    return { kind: "excluded", reason: "not_regular" }; // FIFOs, sockets, devices, directories (submodules): never opened
  }
  const read = readRegularFileBounded(absolute, ctx.maxFileBytes);
  if (read.kind === "missing") {
    return { kind: "missing" };
  }
  if (read.kind === "excluded") {
    return { kind: "excluded", reason: read.reason };
  }
  const verdict = evaluateContent(read.file.data);
  if (verdict.kind === "excluded") {
    return { kind: "excluded", reason: verdict.reason };
  }
  return {
    kind: "file", data: read.file.data, file: read.file,
    row: { path, contentHash: verdict.hash, size: read.file.size, mtimeNs: read.file.mtimeNs, ctimeNs: read.file.ctimeNs, inode: read.file.inode, excludedReason: null }
  };
}
