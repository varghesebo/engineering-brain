import { readFileSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { GitError, type HardenedGit } from "@engbrain/security";

export const OID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
export const isOid = (text: string): boolean => OID.test(text);
const ZERO = /^0+$/;

export const HISTORY_LIMITS = { maxParents: 16, maxChangesPerCommit: 5000, maxBatchChanges: 20_000, maxSubject: 200, readBatchBytes: 32 * 1024 * 1024, readBatchBlobs: 200, diffBufferBytes: 64 * 1024 * 1024 } as const;

export interface RawCommit {
  oid: string;
  tree: string;
  parents: string[];
  authorTime: number | null;
  committerTime: number | null;
  /** UNTRUSTED description: first line, control characters removed, truncated. Never evidence. */
  subject: string;
}

export type ChangeKind = "added" | "modified" | "deleted" | "renamed" | "copied" | "type_changed";

export interface RawChange {
  kind: ChangeKind;
  path: string;
  oldPath: string | null;
  oldMode: string;
  newMode: string;
  oldBlob: string | null;
  newBlob: string | null;
  renameScore: number | null;
}

const KIND_BY_STATUS: Record<string, ChangeKind> = { A: "added", M: "modified", D: "deleted", R: "renamed", C: "copied", T: "type_changed" };

/** Control, format (zero-width, bidirectional, tag characters, BOM, soft hyphen) and line/paragraph separator characters are removed: the subject is shown to people and models. */
const UNSAFE_TEXT = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu;

export function parseCommitObject(oid: string, body: string): RawCommit | null {
  const headerEnd = body.indexOf("\n\n");
  const header = headerEnd === -1 ? body : body.slice(0, headerEnd);
  const message = headerEnd === -1 ? "" : body.slice(headerEnd + 2);
  let tree: string | null = null;
  const parents: string[] = [];
  let authorTime: number | null = null;
  let committerTime: number | null = null;
  for (const line of header.split("\n")) {
    if (line.startsWith("tree ")) {
      tree = line.slice(5).trim();
    } else if (line.startsWith("parent ")) {
      parents.push(line.slice(7).trim());
    } else if (line.startsWith("author ") || line.startsWith("committer ")) {
      const match = /(\d+) [+-]\d{4}$/.exec(line);
      const time = match?.[1] === undefined ? null : Number(match[1]);
      if (line.startsWith("author ")) {
        authorTime = time;
      } else {
        committerTime = time;
      }
    }
  }
  if (tree === null || !isOid(tree) || !parents.every(isOid)) {
    return null;
  }
  const subject = (message.split("\n")[0] ?? "").replace(UNSAFE_TEXT, " ").replace(/\s+/g, " ").trim().slice(0, HISTORY_LIMITS.maxSubject);
  return { oid, tree, parents, authorTime, committerTime, subject };
}

/** `diff-tree -r -z --raw` output: `:old new oldBlob newBlob STATUS\0path\0[path2\0]`. Returns the changes and whether the cap cut the list. */
export function parseRawDiff(output: Buffer): { changes: RawChange[]; truncated: boolean } {
  const parts = output.toString("utf8").split("\0");
  const changes: RawChange[] = [];
  let truncated = false;
  for (let i = 0; i < parts.length; ) {
    const meta = parts[i]!;
    if (!meta.startsWith(":")) {
      i += 1;
      continue;
    }
    const [oldMode = "", newMode = "", oldBlob = "", newBlob = "", status = ""] = meta.slice(1).split(" ");
    const letter = status[0] ?? "";
    const kind = KIND_BY_STATUS[letter];
    const twoPaths = letter === "R" || letter === "C";
    const first = parts[i + 1];
    const second = twoPaths ? parts[i + 2] : undefined;
    i += twoPaths ? 3 : 2;
    if (kind === undefined || first === undefined || (twoPaths && second === undefined)) {
      continue;
    }
    if (changes.length >= HISTORY_LIMITS.maxChangesPerCommit) {
      truncated = true;
      break;
    }
    const score = status.length > 1 ? Number(status.slice(1)) : null;
    changes.push({
      kind, path: twoPaths ? second! : first, oldPath: twoPaths ? first : null, oldMode, newMode,
      oldBlob: ZERO.test(oldBlob) ? null : oldBlob, newBlob: ZERO.test(newBlob) ? null : newBlob, renameScore: Number.isFinite(score) ? score : null
    });
  }
  return { changes, truncated };
}

/** Parses `cat-file --batch` output (`<oid> <type> <size>\n<bytes>\n` per object, `<oid> missing\n` for absent ones). */
export function parseBatch(output: Buffer): Array<{ oid: string; type: string; data: Buffer } | { oid: string; type: "missing" }> {
  const out: Array<{ oid: string; type: string; data: Buffer } | { oid: string; type: "missing" }> = [];
  let at = 0;
  while (at < output.length) {
    const newline = output.indexOf(0x0a, at);
    if (newline === -1) {
      break;
    }
    const [oid = "", type = "", sizeText = ""] = output.subarray(at, newline).toString("utf8").split(" ");
    if (type === "missing") {
      out.push({ oid, type: "missing" });
      at = newline + 1;
      continue;
    }
    const size = Number(sizeText);
    if (!Number.isInteger(size) || size < 0 || newline + 1 + size > output.length) {
      break;
    }
    out.push({ oid, type, data: output.subarray(newline + 1, newline + 1 + size) });
    at = newline + 1 + size + 1;
  }
  return out;
}

/**
 * Read-only walker over the commit DAG, built only on hardened git (fixed argument lists, object ids validated, no `log`, no pager, no external diff,
 * no hooks, replace refs ignored). It never writes to the repository and never executes anything the repository configures.
 */
export class GitHistory {
  constructor(private readonly git: HardenedGit, readonly root: string) {}

  private async text(args: string[]): Promise<string> {
    return (await this.git.run(this.root, args)).trim();
  }

  async objectFormat(): Promise<"sha1" | "sha256"> {
    return (await this.text(["rev-parse", "--show-object-format"])) === "sha256" ? "sha256" : "sha1";
  }

  async isShallow(): Promise<boolean> {
    return (await this.text(["rev-parse", "--is-shallow-repository"])) === "true";
  }

  /** Commits whose parents were cut off by a shallow clone: their ancestry is UNKNOWN, not absent. */
  async shallowBoundaries(): Promise<Set<string>> {
    if (!(await this.isShallow())) {
      return new Set();
    }
    const location = await this.text(["rev-parse", "--git-path", "shallow"]);
    try {
      return new Set(readFileSync(isAbsolute(location) ? location : resolve(this.root, location), "utf8").split("\n").map((l) => l.trim()).filter(isOid));
    } catch {
      return new Set();
    }
  }

  /** `objects/info/alternates` lets a repository borrow objects from any directory: history ingestion is refused when it exists. */
  async hasAlternates(): Promise<boolean> {
    const common = await this.text(["rev-parse", "--git-common-dir"]);
    try {
      readFileSync(join(isAbsolute(common) ? common : resolve(this.root, common), "objects", "info", "alternates"));
      return true;
    } catch {
      return false;
    }
  }

  async resolveCommit(ref: string): Promise<string | null> {
    if (ref.startsWith("-") || ref.includes("\0")) {
      return null;
    }
    try {
      const oid = await this.text(["rev-parse", "--verify", "--quiet", `${ref}^{commit}`]);
      return isOid(oid) ? oid : null;
    } catch {
      return null;
    }
  }

  async hasCommit(oid: string): Promise<boolean> {
    if (!isOid(oid)) {
      return false;
    }
    try {
      await this.git.run(this.root, ["cat-file", "-e", `${oid}^{commit}`]);
      return true;
    } catch (error) {
      if (error instanceof GitError && error.exitCode !== null) {
        return false;
      }
      throw error;
    }
  }

  async isAncestor(ancestor: string, descendant: string): Promise<boolean> {
    try {
      await this.git.run(this.root, ["merge-base", "--is-ancestor", ancestor, descendant]);
      return true;
    } catch (error) {
      if (error instanceof GitError && error.exitCode === 1) {
        return false;
      }
      throw error;
    }
  }

  async mergeBase(a: string, b: string): Promise<string | null> {
    try {
      const oid = await this.text(["merge-base", a, b]);
      return isOid(oid) ? oid : null;
    } catch (error) {
      if (error instanceof GitError && error.exitCode === 1) {
        return null;
      }
      throw error;
    }
  }

  /** Reachable commits, parents before children (topological, NOT by timestamp), each with the parent ids git reports. */
  async listCommits(head: string, exclude: readonly string[] = []): Promise<Array<{ oid: string; parents: string[] }>> {
    const out = await this.text(["rev-list", "--topo-order", "--reverse", "--parents", head, ...exclude.filter(isOid).map((oid) => `^${oid}`)]);
    return out === "" ? [] : out.split("\n").map((line) => {
      const [oid = "", ...parents] = line.split(" ");
      return { oid, parents };
    }).filter((c) => isOid(c.oid));
  }

  async readCommits(oids: readonly string[]): Promise<RawCommit[]> {
    if (oids.length === 0) {
      return [];
    }
    const output = await this.git.runBuffer(this.root, ["cat-file", "--batch"], { input: `${oids.join("\n")}\n` });
    const commits: RawCommit[] = [];
    for (const object of parseBatch(output)) {
      if (object.type === "commit" && "data" in object) {
        const commit = parseCommitObject(object.oid, object.data.toString("utf8"));
        if (commit !== null) {
          commits.push(commit);
        }
      }
    }
    return commits;
  }

  /** Per-parent raw diff with rename detection (`parent` null: the root commit against the empty tree). */
  async diffTree(commit: string, parent: string | null): Promise<{ changes: RawChange[]; truncated: boolean }> {
    const args = parent === null
      ? ["diff-tree", "-r", "-z", "--raw", "--no-abbrev", "--no-commit-id", "--root", commit]
      : ["diff-tree", "-r", "-z", "-M", "--raw", "--no-abbrev", parent, commit];
    try {
      return parseRawDiff(await this.git.runBuffer(this.root, args, { maxBufferBytes: HISTORY_LIMITS.diffBufferBytes }));
    } catch (error) {
      if (error instanceof GitError && error.code === "GIT_OUTPUT_TOO_LARGE") {
        return { changes: [], truncated: true }; // a commit too large to list is recorded as truncated, never allowed to wedge the refresh
      }
      throw error;
    }
  }

  /** The blobs of a tree as `path -> blob oid` (files only; symlinks and submodules carry their mode). */
  async listTree(treeish: string): Promise<Array<{ mode: string; oid: string; path: string }>> {
    const output = (await this.git.runBuffer(this.root, ["ls-tree", "-r", "-z", "--full-tree", treeish], { maxBufferBytes: HISTORY_LIMITS.diffBufferBytes })).toString("utf8");
    return output.split("\0").filter((l) => l !== "").map((entry) => {
      const tab = entry.indexOf("\t");
      const [mode = "", , oid = ""] = entry.slice(0, tab).split(" ");
      return { mode, oid, path: entry.slice(tab + 1) };
    });
  }

  async blobSizes(oids: readonly string[]): Promise<Map<string, number | null>> {
    const sizes = new Map<string, number | null>();
    if (oids.length === 0) {
      return sizes;
    }
    const output = (await this.git.runBuffer(this.root, ["cat-file", "--batch-check"], { input: `${oids.join("\n")}\n` })).toString("utf8");
    for (const line of output.split("\n")) {
      const [oid = "", type = "", size = ""] = line.split(" ");
      if (oid !== "") {
        sizes.set(oid, type === "blob" ? Number(size) : null);
      }
    }
    return sizes;
  }

  /** Reads blobs in bounded groups (count and bytes). Absent or non-blob objects are omitted. */
  async readBlobs(oids: readonly string[], sizes: ReadonlyMap<string, number | null>): Promise<Map<string, Buffer>> {
    const blobs = new Map<string, Buffer>();
    let group: string[] = [];
    let bytes = 0;
    const flush = async (): Promise<void> => {
      if (group.length === 0) {
        return;
      }
      const output = await this.git.runBuffer(this.root, ["cat-file", "--batch"], { input: `${group.join("\n")}\n`, maxBufferBytes: HISTORY_LIMITS.readBatchBytes * 2 });
      for (const object of parseBatch(output)) {
        if (object.type === "blob" && "data" in object) {
          blobs.set(object.oid, Buffer.from(object.data));
        }
      }
      group = [];
      bytes = 0;
    };
    for (const oid of oids) {
      const size = sizes.get(oid) ?? 0;
      if (group.length >= HISTORY_LIMITS.readBatchBlobs || bytes + size > HISTORY_LIMITS.readBatchBytes) {
        await flush();
      }
      group.push(oid);
      bytes += size ?? 0;
    }
    await flush();
    return blobs;
  }
}
