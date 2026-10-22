import { createHash, randomUUID } from "node:crypto";
import { closeSync, lstatSync, openSync, readdirSync, readlinkSync, readSync, realpathSync } from "node:fs";
import { join, relative } from "node:path";
import type Database from "better-sqlite3";
import { EngbrainError } from "../errors.js";
import { requireRole, type Actor } from "../memory/operators.js";
import { TEST_PATH } from "../testDiscovery.js";
import { assertCanApprove, getTask, recordScopeCheck, systemBlock, withdrawApprovals, type Who } from "./tasks.js";

/**
 * Authorized worktrees. A Builder (an agent you run yourself) edits files inside one worktree; this module records a baseline of EVERY file when the worktree is authorized, and later compares the
 * tree with it: changes outside the authorized scope, changes to existing tests or policy (which could hide a failure), and changes the builder did not declare (another actor, a concurrent edit).
 * It DETECTS and BLOCKS; it never overwrites a file, and it cannot stop a Builder with filesystem access from writing: preventing that needs an OS sandbox (see docs).
 */
export const WORKTREE_LIMITS = { files: 50_000, fileBytes: 256 * 1024 * 1024 } as const;
/** Skipped at any depth: version-control and dependency directories. Build output directories are skipped only at the top level, so `tests/dist/...` is still watched. */
const SKIP_ANYWHERE = new Set([".git", "node_modules", ".engineering-brain"]);
const SKIP_TOP_LEVEL = new Set(["dist", "coverage", ".next"]);

function hashFile(full: string, size: number): string {
  if (size > WORKTREE_LIMITS.fileBytes) {
    throw new EngbrainError("POLICY_REFUSED", `a file is larger than ${WORKTREE_LIMITS.fileBytes} bytes and cannot be snapshotted: ${full}`);
  }
  const hash = createHash("sha256");
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  const fd = openSync(full, "r");
  try {
    for (let read = readSync(fd, buffer, 0, buffer.length, null); read > 0; read = readSync(fd, buffer, 0, buffer.length, null)) {
      hash.update(buffer.subarray(0, read));
    }
  } finally {
    closeSync(fd);
  }
  return hash.digest("hex");
}

/** path -> sha256 of the whole file; a symlink is recorded as `symlink:<target>` (never followed), so adding or retargeting one is visible. */
export function snapshotTree(root: string): Map<string, string> {
  const out = new Map<string, string>();
  const walk = (dir: string, depth: number): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (out.size >= WORKTREE_LIMITS.files) {
        throw new EngbrainError("POLICY_REFUSED", `the worktree has more than ${WORKTREE_LIMITS.files} files`);
      }
      const full = join(dir, entry.name);
      const rel = relative(root, full).split("\\").join("/");
      if (entry.isSymbolicLink()) {
        out.set(rel, `symlink:${readlinkSync(full)}`);
      } else if (entry.isDirectory()) {
        if (!SKIP_ANYWHERE.has(entry.name) && !(depth === 0 && SKIP_TOP_LEVEL.has(entry.name))) {
          walk(full, depth + 1);
        }
      } else if (entry.isFile()) {
        out.set(rel, hashFile(full, lstatSync(full).size));
      }
    }
  };
  walk(root, 0);
  return out;
}

const CONFIG_LIKE = /(^|\/)(jest|vitest|playwright|pytest|tox|karma|babel|tsconfig|\.eslintrc|eslint\.config|setupTests|setup-tests|conftest|testUtils|test-utils|test-helpers|testHelpers|Makefile)[^/]*$/i;
const TEST_SUPPORT_DIR = /(^|\/)(__mocks__|__snapshots__|__fixtures__|fixtures|snapshots)\//i;

/** An existing test, test configuration, test helper or fixture, build/test script file or the tool's own policy files: changing one could hide a failure. A NEW plain test file is not protected. */
export const isProtectedPath = (path: string): boolean =>
  TEST_PATH.test(path) || CONFIG_LIKE.test(path) || TEST_SUPPORT_DIR.test(path) || /(^|\/)package\.json$/.test(path) || /(^|\/)\.github\//.test(path) || /(^|\/)(sentinel-policy|operators|evidence-policy)\.json$/.test(path);
/** A NEW file that could change how tests run (a config, a mock, a setup file, a symlink) is as risky as editing an existing one. */
export const isRiskyNewPath = (path: string, value: string): boolean => value.startsWith("symlink:") || (isProtectedPath(path) && !TEST_PATH.test(path));

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
    if (db.prepare("SELECT 1 FROM sentinel_worktrees WHERE task_id = ? AND status = 'active'").get(id) !== undefined) {
      throw new EngbrainError("POLICY_REFUSED", "this task already has an active worktree: revoke it before authorizing another (re-authorizing would absorb earlier tampering into the baseline)");
    }
    db.prepare("DELETE FROM sentinel_worktrees WHERE task_id = ? AND status = 'revoked'").run(id);
    const baseline = snapshotTree(real);
    db.prepare("INSERT INTO sentinel_worktrees (task_id, path, baseline_json, authorized_by, at, status) VALUES (?, ?, ?, ?, ?, 'active')")
      .run(id, real, JSON.stringify([...baseline.entries()]), actor.id, (now ?? new Date()).toISOString());
    return { files: baseline.size };
  }).immediate();
}

/** Revokes the worktree authorization (done automatically when a task is cancelled): no further check or enforcement runs against it. */
export function revokeWorktree(db: Database.Database, id: string): void {
  db.prepare("UPDATE sentinel_worktrees SET status = 'revoked' WHERE task_id = ?").run(id);
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
  const protectedChanges = [...new Set([...modified, ...deleted].filter(isProtectedPath).concat(added.filter((p) => isRiskyNewPath(p, current.get(p) ?? ""))))].sort();
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
  db.transaction(() => {
    if (report.protectedChanges.length > 0 && db.prepare("SELECT 1 FROM sentinel_findings WHERE task_id = ? AND title = 'protected files changed' AND disposition = 'open'").get(id) === undefined) {
      db.prepare(
        `INSERT INTO sentinel_findings (finding_id, task_id, at, source_role, source_principal, provider, severity, title, evidence_json, reproduction, check_id, disposition)
         VALUES (?, ?, ?, 'controller', 'controller', NULL, 'blocking', 'protected files changed', ?, ?, NULL, 'open')`
      ).run(`fd_${randomUUID().replace(/-/g, "").slice(0, 16)}`, id, (now ?? new Date()).toISOString(), JSON.stringify({ kind: "worktree", paths: report.protectedChanges.slice(0, 50) }), "compare the worktree with the baseline recorded when it was authorized (sentinel worktree check)");
      withdrawApprovals(db, storeDir, id, "protected files changed", now);
    }
  }).immediate();
  if (report.undeclared.length > 0) {
    systemBlock(db, storeDir, id, `the tree changed outside what the builder declared (${report.undeclared.slice(0, 5).join(", ")}): paused, nothing was overwritten`, now);
  }
  return report;
}
