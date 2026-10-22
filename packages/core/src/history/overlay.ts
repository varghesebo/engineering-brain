import type Database from "better-sqlite3";
import { sha256Hex } from "../hash.js";
import { evaluateContent } from "../contentPolicy.js";
import type { ExclusionMatcher } from "../exclusions.js";
import { toStorePath } from "../paths.js";
import { GitHistory } from "./gitHistory.js";

/**
 * The dirty overlay: how the working tree differs from HEAD, as ONE hash, kept apart from commits (uncommitted state never gets a commit id).
 * It is computed EXACTLY, by content: every indexed file's sha256 (from the published manifest) is compared with the sha256 of HEAD's blob for that path.
 * Git's own change detection (`ls-files --modified`, `status`) is deliberately NOT used: it compares through attribute filters, which would execute
 * repository-configured programs. HEAD blobs are read with `cat-file` (no filters) once and cached by blob id, so later refreshes read only blobs that changed.
 * Files the exclusion policy keeps out of the index are not part of the overlay. Returns null for a clean tree.
 * BASIS: raw bytes. A checkout that git converts (`eol=` attributes, autocrlf, clean/smudge filters) differs byte-wise from the blob, so such a tree can report an overlay
 * that `git status` would not; the result says so through `basis`.
 */
export async function computeOverlayHash(
  db: Database.Database, history: GitHistory, generationId: number, headOid: string | null, objectFormat: "sha1" | "sha256", matcher: ExclusionMatcher, maxFileBytes: number
): Promise<{ hash: string | null; paths: number; headBlobsRead: number; basis: "raw_bytes" }> {
  const head = new Map<string, { mode: string; oid: string }>();
  if (headOid !== null) {
    for (const entry of await history.listTree(headOid)) {
      const stored = toStorePath(entry.path);
      if (stored.ok && entry.mode !== "120000" && entry.mode !== "160000") {
        head.set(stored.path, entry);
      }
    }
  }
  const disk = new Map<string, string>();
  for (const row of db.prepare("SELECT path, content_hash AS hash FROM generation_files WHERE generation_id = ? AND content_hash IS NOT NULL").iterate(generationId) as Iterable<{ path: string; hash: string }>) {
    disk.set(row.path, row.hash);
  }
  // HEAD blobs we need a content hash for: tracked paths that are indexed on disk, or absent from disk but not excluded by path policy (possible deletions)
  const cached = db.prepare("SELECT content_hash AS hash FROM blob_hashes WHERE blob_oid = ?");
  const needed: string[] = [];
  for (const [path, entry] of head) {
    if ((disk.has(path) || matcher.excludesPath(path) === null) && cached.get(entry.oid) === undefined) {
      needed.push(entry.oid);
    }
  }
  const unique = [...new Set(needed)];
  const insert = db.prepare("INSERT OR IGNORE INTO blob_hashes (blob_oid, object_format, content_hash, size, excluded_reason) VALUES (?, ?, ?, ?, ?)");
  let headBlobsRead = 0;
  if (unique.length > 0) {
    const sizes = await history.blobSizes(unique);
    const readable = unique.filter((oid) => typeof sizes.get(oid) === "number" && sizes.get(oid)! <= maxFileBytes);
    const bodies = await history.readBlobs(readable, sizes);
    headBlobsRead = bodies.size;
    db.transaction(() => {
      for (const oid of unique) {
        const body = bodies.get(oid);
        if (body === undefined) {
          if (typeof sizes.get(oid) === "number") {
            insert.run(oid, objectFormat, null, sizes.get(oid), "too_large"); // a property of the blob and the configured cap; "missing" is not cached
          }
          continue;
        }
        const verdict = evaluateContent(body);
        insert.run(oid, objectFormat, verdict.kind === "ok" ? verdict.hash : null, body.length, verdict.kind === "ok" ? null : verdict.reason);
      }
    }).immediate();
  }
  const headHash = (oid: string): string | null => (cached.get(oid) as { hash: string | null } | undefined)?.hash ?? null;
  const entries: string[] = [];
  for (const [path, hash] of disk) {
    const tracked = head.get(path);
    if (tracked === undefined || headHash(tracked.oid) !== hash) {
      entries.push(`${path}\0${hash}`); // untracked, or content differs from HEAD
    }
  }
  for (const [path, entry] of head) {
    if (!disk.has(path) && matcher.excludesPath(path) === null && headHash(entry.oid) !== null) {
      entries.push(`${path}\0deleted`); // tracked and indexable at HEAD, absent from the working tree
    }
  }
  if (entries.length === 0) {
    return { hash: null, paths: 0, headBlobsRead, basis: "raw_bytes" };
  }
  return { hash: sha256Hex(entries.sort().join("\n")), paths: entries.length, headBlobsRead, basis: "raw_bytes" };
}
