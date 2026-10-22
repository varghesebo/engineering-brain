import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { join, relative } from "node:path";
import type Database from "better-sqlite3";
import { EngbrainError } from "../errors.js";
import { requireRole, type Actor } from "../memory/operators.js";
import { TEST_PATH } from "../testDiscovery.js";
import { assertCanApprove, getTask, recordScopeCheck, systemBlock, type Who } from "./tasks.js";

/**
 * Authorized worktrees. A Builder (an agent you run yourself) edits files inside one worktree; this module records a baseline of EVERY file when the worktree is authorized, and later compares the
 * tree with it: changes outside the authorized scope, changes to existing tests or policy (which could hide a failure), and changes the builder did not declare (another actor, a concurrent edit).
 * It DETECTS and BLOCKS; it never overwrites a file, and it cannot stop a Builder with filesystem access from writing: preventing that needs an OS sandbox (see docs).
 */
export const WORKTREE_LIMITS = { files: 50_000, fileBytes: 5 * 1024 * 1024 } as const;
const SKIP_DIRS = new Set([".git", "node_modules", ".engineering-brain", "dist", "coverage", ".next"]);

/** path -> sha256 (or `large:<bytes>` for oversized files). Symlinks are not followed or recorded. */
export function snapshotTree(root: string): Map<string, string> {
  const out = new Map<string, string>();
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (out.size >= WORKTREE_LIMITS.files) {
        throw new EngbrainError("POLICY_REFUSED", `the worktree has more than ${WORKTREE_LIMITS.files} files`);
      }
      const full = join(dir, entry.name);
      if (entry.isSymbolicLink()) {
        continue;
      }
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) {
          walk(full);
        }
      } else if (entry.isFile()) {
        const size = lstatSync(full).size;
        out.set(relative(root, full).split("\\").join("/"), size > WORKTREE_LIMITS.fileBytes ? `large:${size}` : createHash("sha256").update(readFileSync(full)).digest("hex"));
      }
    }
  };
  walk(root);
  return out;
}

/** An existing test, a test/CI configuration or the tool's own policy files: changing them could hide a failure. A NEW test file is not protected. */
export const isProtectedPath = (path: string): boolean =>
  TEST_PATH.test(path) || /(^|\/)(jest|vitest|playwright|pytest|tox|karma)[^/]*\.(c|m)?(js|ts|json|ini|toml|cfg)$/i.test(path) || /(^|\/)\.github\//.test(path) || /(^|\/)(sentinel-policy|operators|evidence-policy)\.json$/.test(path);

export function authorizeWorktree(db: Database.Database, id: string, actor: Actor, worktreePath: string, mainRoot: string, now?: Date): { files: number } {
  requireRole(actor, "approve");
  let real: string;
  try {
    real = realpathSync(worktreePath);
  } catch {
    throw new EngbrainError("POLICY_REFUSED", "the worktree path does not exist");
  }
  if (!lstatSync(real).isDirectory()) {
    throw new EngbrainError("POLICY_REFUSED", "the worktree must be a directory");
  }
  if (real === realpathSync(mainRoot)) {
    throw new EngbrainError("POLICY_REFUSED", "the worktree must be a separate (throwaway) directory, not your main working tree");
  }
  return db.transaction(() => {
    const task = getTask(db, id);
    if (["FAILED", "CANCELLED", "BLOCKED"].includes(task.state)) {
      throw new EngbrainError("POLICY_REFUSED", `a ${task.state} task cannot be given a worktree`);
    }
    assertCanApprove(db, task, actor.id);
    const baseline = snapshotTree(real);
    db.prepare("INSERT OR REPLACE INTO sentinel_worktrees (task_id, path, baseline_json, authorized_by, at, status) VALUES (?, ?, ?, ?, ?, 'active')")
      .run(id, real, JSON.stringify([...baseline.entries()]), actor.id, (now ?? new Date()).toISOString());
    return { files: baseline.size };
  }).immediate();
}

export interface WorktreeReport {
  added: string[]; modified: string[]; deleted: string[];
  /** Changes outside the authorized scope. */
  unauthorized: string[];
  /** Existing tests / test config / policy modified or deleted. */
  protectedChanges: string[];
  /** Changes the builder did not declare: another actor or a concurrent edit touched the tree. */
  undeclared: string[];
  ok: boolean;
}

export function checkWorktree(db: Database.Database, id: string, declaredPaths?: readonly string[]): WorktreeReport {
  const task = getTask(db, id);
  const row = db.prepare("SELECT path, baseline_json AS b, status FROM sentinel_worktrees WHERE task_id = ?").get(id) as { path: string; b: string; status: string } | undefined;
  if (row === undefined || row.status !== "active") {
    throw new EngbrainError("POLICY_REFUSED", "this task has no active authorized worktree");
  }
  const baseline = new Map(JSON.parse(row.b) as Array<[string, string]>);
  const current = snapshotTree(row.path);
  const scope = JSON.parse(task.scope_json) as string[];
  const inScope = (p: string): boolean => scope.some((s) => p === s || (s.endsWith("/") ? p.startsWith(s) : p.startsWith(`${s}/`)));
  const added = [...current.keys()].filter((p) => !baseline.has(p)).sort();
  const deleted = [...baseline.keys()].filter((p) => !current.has(p)).sort();
  const modified = [...current.keys()].filter((p) => baseline.has(p) && baseline.get(p) !== current.get(p)).sort();
  const changed = [...added, ...modified, ...deleted];
  const unauthorized = changed.filter((p) => !inScope(p));
  const protectedChanges = [...modified, ...deleted].filter(isProtectedPath);
  const declared = declaredPaths === undefined ? null : new Set(declaredPaths);
  const undeclared = declared === null ? [] : changed.filter((p) => !declared.has(p));
  return { added, modified, deleted, unauthorized, protectedChanges, undeclared, ok: unauthorized.length === 0 && protectedChanges.length === 0 && undeclared.length === 0 };
}

/**
 * Applies a worktree check to the task: out-of-scope changes fail the mandatory `scope` check, a change to an existing test or policy opens a BLOCKING finding (a person must disposition it), and an
 * undeclared change pauses the task (BLOCKED, nothing overwritten). Returns what was found.
 */
export function enforceWorktree(db: Database.Database, storeDir: string, id: string, who: Who, currentFingerprint: string, declaredPaths?: readonly string[], now?: Date): WorktreeReport {
  const report = checkWorktree(db, id, declaredPaths);
  const task = getTask(db, id);
  if (task.state === "VERIFYING" || task.state === "REVERIFYING" || task.state === "ASSURANCE_REVIEW") {
    recordScopeCheck(db, storeDir, id, [...report.added, ...report.modified, ...report.deleted], who, currentFingerprint, now);
  }
  if (report.protectedChanges.length > 0) {
    const existing = db.prepare("SELECT 1 FROM sentinel_findings WHERE task_id = ? AND title = 'protected files changed' AND disposition = 'open'").get(id);
    if (existing === undefined) {
      db.prepare(
        `INSERT INTO sentinel_findings (finding_id, task_id, at, source_role, source_principal, provider, severity, title, evidence_json, reproduction, check_id, disposition)
         VALUES (?, ?, ?, 'controller', 'controller', NULL, 'blocking', 'protected files changed', ?, ?, 'scope', 'open')`
      ).run(`fd_${createHash("sha256").update(`${id}:${report.protectedChanges.join(",")}`).digest("hex").slice(0, 16)}`, id, (now ?? new Date()).toISOString(),
        JSON.stringify({ kind: "worktree", paths: report.protectedChanges.slice(0, 50) }), "compare the worktree with the baseline recorded when it was authorized (sentinel worktree check)");
    }
  }
  if (report.undeclared.length > 0) {
    systemBlock(db, storeDir, id, `the tree changed outside what the builder declared (${report.undeclared.slice(0, 5).join(", ")}): paused, nothing was overwritten`, now);
  }
  return report;
}
