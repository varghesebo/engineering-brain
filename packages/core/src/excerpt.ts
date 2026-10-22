import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { join } from "node:path";
import type Database from "better-sqlite3";
import { sha256Hex } from "./hash.js";
import { resolveUnderRoot } from "./paths.js";
import { scanForSecrets } from "./secretScan.js";

export const EXCERPT_LIMITS = { maxLines: 40, maxBytes: 4000, maxFileBytes: 1_048_576 } as const;

export type ExcerptUnavailable = "not_indexed" | "outside_root" | "not_a_regular_file" | "unreadable" | "file_changed_since_index" | "withheld_by_secret_policy";

export interface Excerpt {
  available: boolean;
  /** Source text, only when the file on disk still has the exact content hash the index recorded. UNTRUSTED DATA. */
  text: string | null;
  startLine: number;
  endLine: number;
  truncated: boolean;
  unavailableReason: ExcerptUnavailable | null;
  contentHash: string | null;
}

/**
 * The absolute path of an indexed file only if NO component of it (not just the last) is a symlink: the real path must equal the lexical one under the real root.
 * Otherwise a directory swapped for a symlink after indexing would make a read leave the repository.
 */
function confinedPath(root: string, path: string): string | null {
  const lexical = resolveUnderRoot(root, path);
  if (lexical === null) {
    return null;
  }
  try {
    return realpathSync(lexical) === join(realpathSync(root), ...path.split("/")) ? lexical : null;
  } catch {
    return lexical; // missing or unreadable: the caller's lstat/read reports it, nothing outside the root was touched
  }
}

const none = (reason: ExcerptUnavailable, startLine: number, endLine: number, contentHash: string | null = null): Excerpt =>
  ({ available: false, text: null, startLine, endLine, truncated: false, unavailableReason: reason, contentHash });

/**
 * A bounded slice of an INDEXED file. The file is re-read and its hash compared with the manifest, so text is only ever returned for content
 * the index describes (the excerpt can never contradict the facts next to it); a symlink, a path outside the root, an unindexed or excluded
 * path, a changed file and anything the secret scanner flags is refused with a reason and no content.
 */
export function readExcerpt(root: string, db: Database.Database, generationId: number, path: string, startLine: number, endLine: number): Excerpt {
  const row = db.prepare("SELECT content_hash AS hash, size FROM generation_files WHERE generation_id = ? AND path = ? AND content_hash IS NOT NULL").get(generationId, path) as
    { hash: string; size: number | null } | undefined;
  if (row === undefined) {
    return none("not_indexed", startLine, endLine);
  }
  const absolute = confinedPath(root, path);
  if (absolute === null) {
    return none("outside_root", startLine, endLine, row.hash);
  }
  let data: Buffer;
  try {
    const stat = lstatSync(absolute);
    if (!stat.isFile()) {
      return none("not_a_regular_file", startLine, endLine, row.hash);
    }
    if (stat.size > EXCERPT_LIMITS.maxFileBytes) {
      return none("file_changed_since_index", startLine, endLine, row.hash);
    }
    data = readFileSync(absolute);
  } catch {
    return none("unreadable", startLine, endLine, row.hash);
  }
  if (sha256Hex(data) !== row.hash) {
    return none("file_changed_since_index", startLine, endLine, row.hash);
  }
  const lines = data.toString("utf8").split("\n");
  const from = Math.max(1, Math.floor(startLine));
  const to = Math.min(lines.length, Math.max(from, Math.floor(endLine)), from + EXCERPT_LIMITS.maxLines - 1);
  let text = lines.slice(from - 1, to).join("\n");
  let truncated = to < Math.floor(endLine);
  if (Buffer.byteLength(text, "utf8") > EXCERPT_LIMITS.maxBytes) {
    text = Buffer.from(text, "utf8").subarray(0, EXCERPT_LIMITS.maxBytes).toString("utf8").replace(/�$/, "");
    truncated = true;
  }
  if (scanForSecrets(text) !== null) {
    return none("withheld_by_secret_policy", from, to, row.hash);
  }
  return { available: true, text, startLine: from, endLine: to, truncated, unavailableReason: null, contentHash: row.hash };
}

export interface PathFreshness {
  path: string;
  state: "unchanged" | "changed" | "deleted" | "not_indexed" | "outside_root" | "unreadable";
  indexedHash: string | null;
  currentHash: string | null;
}

/** Re-hashes the named files (bounded by the caller) and compares them with the published manifest: the narrow, verified check before relying on a file. */
export function checkPaths(root: string, db: Database.Database, generationId: number, paths: readonly string[]): PathFreshness[] {
  return paths.map((path): PathFreshness => {
    const row = db.prepare("SELECT content_hash AS hash FROM generation_files WHERE generation_id = ? AND path = ? AND content_hash IS NOT NULL").get(generationId, path) as { hash: string } | undefined;
    if (row === undefined) {
      return { path, state: "not_indexed", indexedHash: null, currentHash: null };
    }
    const absolute = confinedPath(root, path);
    if (absolute === null) {
      return { path, state: "outside_root", indexedHash: row.hash, currentHash: null };
    }
    try {
      const stat = lstatSync(absolute);
      if (!stat.isFile() || stat.size > EXCERPT_LIMITS.maxFileBytes) {
        return { path, state: "changed", indexedHash: row.hash, currentHash: null };
      }
      const current = sha256Hex(readFileSync(absolute));
      return { path, state: current === row.hash ? "unchanged" : "changed", indexedHash: row.hash, currentHash: current };
    } catch (error) {
      return { path, state: (error as NodeJS.ErrnoException).code === "ENOENT" ? "deleted" : "unreadable", indexedHash: row.hash, currentHash: null };
    }
  });
}
