import { lstatSync, readFileSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join, parse, resolve } from "node:path";
import { GitError, type HardenedGit } from "@engbrain/security";
import { EngbrainError } from "./errors.js";
import { sha256Hex } from "./hash.js";

export interface GitInfo {
  isGit: boolean;
  /** Real path of the work tree root (git toplevel), or the start dir when not in a git work tree. */
  root: string;
  /** HEAD commit, null when there are no commits yet or the directory is not a repository. */
  revision: string | null;
  /** Informational label only. Null when detached or not a repository. Never used as a key. */
  branchLabel: string | null;
  isShallow: boolean;
  isLinkedWorktree: boolean;
  /**
   * Advisory hash of the root-commit set. Null for non-git dirs, repos with no commits, and shallow clones
   * (their root commits are not real). Used only to detect a store that was copied to a different history.
   */
  historyKey: string | null;
}

function isNotARepository(error: unknown): boolean {
  return error instanceof GitError && error.code === "GIT_FAILED" && /not a git repository/i.test(error.message);
}

async function optional(git: HardenedGit, cwd: string, args: string[]): Promise<string | null> {
  try {
    return (await git.run(cwd, args)).trim();
  } catch (error) {
    if (error instanceof GitError && error.code === "GIT_FAILED") {
      return null;
    }
    throw error;
  }
}

/** Facts for a directory treated as non-git (also used when the git binary is unavailable). */
export function nonGitInfo(startDir: string, homeDir: string = homedir()): GitInfo {
  let root: string;
  try {
    root = realpathSync.native(resolve(startDir));
    if (!statSync(root).isDirectory()) {
      throw new Error("not a directory");
    }
  } catch {
    throw new EngbrainError("INVALID_ROOT", "root directory does not exist or is not a directory");
  }
  if (root === parse(root).root || root === safeRealpath(homeDir)) {
    throw new EngbrainError(
      "INVALID_ROOT",
      "refusing to index a filesystem root or home directory that is not a git work tree; pass --root <project directory>"
    );
  }
  return { isGit: false, root, revision: null, branchLabel: null, isShallow: false, isLinkedWorktree: false, historyKey: null };
}

function safeRealpath(path: string): string | null {
  try {
    return realpathSync.native(path);
  } catch {
    return null;
  }
}

/**
 * Resolves the repository root and git facts using only hardened, read-only git. A hostile repo's config is
 * never honoured for execution. Anything unexpected (e.g. ownership refusal) surfaces as an error and is NOT
 * silently treated as "not a git repository".
 */
export async function readGitInfo(startDir: string, git: HardenedGit, homeDir: string = homedir()): Promise<GitInfo> {
  let start: string;
  try {
    start = realpathSync.native(resolve(startDir));
    if (!statSync(start).isDirectory()) {
      throw new Error("not a directory");
    }
  } catch {
    throw new EngbrainError("INVALID_ROOT", "root directory does not exist or is not a directory");
  }

  let layout: string[];
  try {
    const out = await git.run(start, [
      "rev-parse", "--is-inside-work-tree", "--show-toplevel", "--path-format=absolute",
      "--absolute-git-dir", "--git-common-dir", "--is-shallow-repository"
    ]);
    layout = out.split("\n");
  } catch (error) {
    if (isNotARepository(error)) {
      return nonGitInfo(start, homeDir);
    }
    throw new EngbrainError("GIT_UNAVAILABLE", error instanceof Error ? error.message : "git failed");
  }
  if (layout[0] !== "true") {
    return nonGitInfo(start, homeDir);
  }
  const [, toplevel, gitDir, commonDir, shallow] = layout;
  if (toplevel === undefined || gitDir === undefined || commonDir === undefined) {
    throw new EngbrainError("GIT_UNAVAILABLE", "unexpected rev-parse output");
  }
  const root = realpathSync.native(toplevel);
  // A repository config can set core.worktree to redirect the "top level" (e.g. to a parent or unrelated
  // directory). A genuine work tree root contains its own `.git` entry (directory, or file for worktrees/submodules).
  if (!gitEntryBelongsToWorkTree(root, gitDir)) {
    throw new EngbrainError("INVALID_ROOT", "the work tree root's .git entry is not this repository's git directory (core.worktree redirect?); refusing to index it");
  }
  const isShallow = shallow === "true";
  const revision = await optional(git, root, ["rev-parse", "--verify", "-q", "HEAD^{commit}"]);
  const branchLabel = revision === null ? null : await optional(git, root, ["symbolic-ref", "-q", "--short", "HEAD"]);
  let historyKey: string | null = null;
  if (revision !== null && !isShallow) {
    const roots = await optional(git, root, ["rev-list", "--max-parents=0", "HEAD"]);
    if (roots !== null && roots !== "") {
      historyKey = sha256Hex(roots.split("\n").sort().join("\n"));
    }
  }
  return {
    isGit: true,
    root,
    revision: revision === "" ? null : revision,
    branchLabel: branchLabel === "" ? null : branchLabel,
    isShallow,
    isLinkedWorktree: realpathSync.native(gitDir) !== realpathSync.native(commonDir),
    historyKey
  };
}

/**
 * The `.git` entry at the work-tree root must BE this repository's git directory: a directory that resolves to it,
 * or a `gitdir:` file (linked worktrees, submodules) that points at it. Merely existing is not enough: a redirect
 * to a directory that has its own, different `.git` must be refused too.
 */
function gitEntryBelongsToWorkTree(root: string, absoluteGitDir: string): boolean {
  const entry = join(root, ".git");
  try {
    const expected = realpathSync.native(absoluteGitDir);
    if (lstatSync(entry).isDirectory()) {
      return realpathSync.native(entry) === expected;
    }
    const match = /^gitdir:\s*(.+)\s*$/m.exec(readFileSync(entry, "utf8").slice(0, 4096));
    return match?.[1] !== undefined && realpathSync.native(resolve(root, match[1])) === expected;
  } catch {
    return false;
  }
}

/** True when anything under `.engineering-brain/` is tracked by git (a hostile repo could ship a store). */
export async function isStoreTrackedByGit(git: HardenedGit, root: string): Promise<boolean> {
  // `:(icase)` because on case-insensitive filesystems `.ENGINEERING-BRAIN` is the same directory.
  const out = await git.run(root, ["ls-files", "-z", "--", ":(icase).engineering-brain"]);
  return out.length > 0;
}
