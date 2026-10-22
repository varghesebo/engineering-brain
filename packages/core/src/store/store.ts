import type Database from "better-sqlite3";
import { randomUUID } from "node:crypto";
import { chmodSync, lstatSync, mkdirSync, readdirSync, type Stats } from "node:fs";
import { join } from "node:path";
import { HardenedGit } from "@engbrain/security";
import { DEFAULT_CONFIG, loadConfig, type EngbrainConfig } from "../config.js";
import { EngbrainError } from "../errors.js";
import { assertNoSymlinksIn, createFileExclusiveNoFollow, detectFilesystemKind } from "../fsSafe.js";
import { isStoreTrackedByGit, type GitInfo } from "../identity.js";
import { openDatabase } from "./db.js";
import { applyMigrations, currentVersion, latestVersion, type MigrationResult } from "./migrations.js";

export const STORE_DIR_NAME = ".engineering-brain";

export interface StoreMeta {
  installId: string;
  repositoryId: string;
  worktreeId: string;
  rootRealpath: string;
  historyKey: string | null;
  currentGenerationId: number | null;
  createdAt: string;
}

export interface StoreContext {
  root: string;
  git: GitInfo;
  /** Null when git is unavailable (non-git directories still work). */
  hardenedGit: HardenedGit | null;
  installId: string;
  now?: () => Date;
}

interface MetaRow {
  install_id: string;
  repository_id: string;
  worktree_id: string;
  root_realpath: string;
  history_key: string | null;
  current_generation_id: number | null;
  created_at: string;
}

/**
 * One store per worktree at `<root>/.engineering-brain/`. The store lives in a directory a cloned repo could
 * try to pre-populate, so every open re-checks: directory/db are real (not symlinks), not tracked by git,
 * owned by this user (POSIX), created by THIS install, and bound to THIS root.
 */
export class Store {
  private constructor(
    readonly db: Database.Database,
    readonly dir: string,
    readonly meta: StoreMeta,
    readonly migration: MigrationResult,
    /**
     * True when the repository's root-commit set differs from the one recorded at init (history rewritten, or a
     * different repository now lives at this path). The store is NOT refused: it is already bound to this install
     * and path, and facts are content-addressed. Callers must tell the user; the next stage flags stale reads.
     */
    readonly historyChanged: boolean = false
  ) {}

  static storeDir(root: string): string {
    return join(root, STORE_DIR_NAME);
  }

  static dbPath(root: string): string {
    return join(Store.storeDir(root), "store.db");
  }

  static async init(context: StoreContext): Promise<Store> {
    const dir = Store.storeDir(context.root);
    if (detectFilesystemKind(context.root) === "network") {
      throw new EngbrainError("NETWORK_FILESYSTEM", "the repository is on a network filesystem; SQLite WAL needs a local filesystem");
    }
    assertCanonicalStoreName(context.root);
    await assertNotTracked(context);
    const existing = lstatOrNull(dir);
    if (existing !== null) {
      if (!existing.isDirectory() || existing.isSymbolicLink()) {
        throw new EngbrainError("STORE_UNSAFE_PATH", `${STORE_DIR_NAME} exists but is not a regular directory`);
      }
      if (lstatOrNull(Store.dbPath(context.root)) !== null) {
        throw new EngbrainError("ALREADY_INITIALIZED", "this repository already has an engbrain store");
      }
    } else {
      mkdirSync(dir, { mode: 0o700 });
    }
    assertNoSymlinksIn(dir, STORE_DIR_NAME);
    chmodBestEffort(dir, 0o700);
    createFileExclusiveNoFollow(join(dir, ".gitignore"), "*\n");
    writeDefaultConfigIfAbsent(join(dir, "config.json"));

    const db = openDatabase(Store.dbPath(context.root), { create: true });
    try {
      const migration = applyMigrations(db, { backupDir: join(dir, "backups"), ...(context.now ? { now: context.now } : {}) });
      const createdAt = (context.now ?? (() => new Date()))().toISOString();
      db.prepare(
        `INSERT INTO store_meta (singleton, install_id, repository_id, worktree_id, root_realpath, history_key, created_at)
         VALUES (1, ?, ?, ?, ?, ?, ?)`
      ).run(context.installId, randomUUID(), randomUUID(), context.root, context.git.historyKey, createdAt);
      chmodBestEffort(Store.dbPath(context.root));
      return new Store(db, dir, readMeta(db), migration);
    } catch (error) {
      db.close();
      throw error;
    }
  }

  /** The on-disk checks shared by every way of opening an existing store (directory and file are real, not tracked, owned by this user). */
  private static async verifyOnDisk(context: StoreContext): Promise<string> {
    const dir = Store.storeDir(context.root);
    const dirStat = lstatOrNull(dir);
    if (dirStat === null) {
      throw new EngbrainError("NOT_INITIALIZED", "no engbrain store here; run `engbrain init`");
    }
    if (dirStat.isSymbolicLink() || !dirStat.isDirectory()) {
      throw new EngbrainError("STORE_UNSAFE_PATH", `${STORE_DIR_NAME} is not a regular directory`);
    }
    assertCanonicalStoreName(context.root);
    assertNoSymlinksIn(dir, STORE_DIR_NAME);
    await assertNotTracked(context);
    const dbStat = lstatOrNull(Store.dbPath(context.root));
    if (dbStat === null) {
      throw new EngbrainError("NOT_INITIALIZED", "no engbrain store here; run `engbrain init`");
    }
    if (dbStat.isSymbolicLink() || !dbStat.isFile()) {
      throw new EngbrainError("STORE_UNSAFE_PATH", "store database is not a regular file");
    }
    if (typeof process.getuid === "function" && dbStat.uid !== process.getuid()) {
      throw new EngbrainError("STORE_OWNER_MISMATCH", "store database is owned by a different user");
    }
    return dir;
  }

  static async open(context: StoreContext): Promise<Store> {
    const dir = await Store.verifyOnDisk(context);
    const db = openDatabase(Store.dbPath(context.root));
    try {
      const meta = readMetaOrFail(db); // identity checks BEFORE any write (migrations) to a file that may be foreign
      if (meta.installId !== context.installId) {
        throw new EngbrainError("STORE_OWNER_MISMATCH", "this store was not created by this installation; refusing to use it");
      }
      if (meta.rootRealpath !== context.root) {
        throw new EngbrainError("STORE_ROOT_MISMATCH", "this store belongs to a different directory (moved or copied); refusing to use it");
      }
      const migration = applyMigrations(db, { backupDir: join(dir, "backups"), ...(context.now ? { now: context.now } : {}) });
      let historyChanged = false;
      let current = meta;
      if (context.git.historyKey !== null && meta.historyKey !== context.git.historyKey) {
        historyChanged = meta.historyKey !== null;
        db.prepare("UPDATE store_meta SET history_key = ? WHERE singleton = 1").run(context.git.historyKey);
        current = { ...meta, historyKey: context.git.historyKey };
      }
      return new Store(db, dir, current, migration, historyChanged);
    } catch (error) {
      db.close();
      throw error;
    }
  }

  /**
   * A strictly read-only handle for readers (the MCP server): the same identity and location checks as `open`, but the database is opened
   * read-only with `query_only`, nothing is migrated, repaired or updated, and a store that needs a migration is refused (run `engbrain index`).
   */
  static async openReadOnly(context: StoreContext): Promise<Store> {
    const dir = await Store.verifyOnDisk(context);
    const db = openDatabase(Store.dbPath(context.root), { readonly: true });
    try {
      db.pragma("query_only = ON");
      const meta = readMetaOrFail(db);
      if (meta.installId !== context.installId) {
        throw new EngbrainError("STORE_OWNER_MISMATCH", "this store was not created by this installation; refusing to use it");
      }
      if (meta.rootRealpath !== context.root) {
        throw new EngbrainError("STORE_ROOT_MISMATCH", "this store belongs to a different directory (moved or copied); refusing to use it");
      }
      const version = currentVersion(db);
      if (version !== latestVersion()) {
        throw new EngbrainError("STORE_NEEDS_MIGRATION", `store schema v${version} differs from this build's v${latestVersion()}; run \`engbrain index\` to upgrade it (readers never migrate)`);
      }
      return new Store(db, dir, meta, { from: version, to: version, backupPath: null });
    } catch (error) {
      db.close();
      throw error;
    }
  }

  config(): EngbrainConfig {
    return loadConfig(join(this.dir, "config.json"));
  }

  close(): void {
    this.db.close();
  }
}

function writeDefaultConfigIfAbsent(path: string): void {
  createFileExclusiveNoFollow(path, `${JSON.stringify(DEFAULT_CONFIG, null, 2)}\n`);
}

async function assertNotTracked(context: StoreContext): Promise<void> {
  if (context.git.isGit && context.hardenedGit !== null && (await isStoreTrackedByGit(context.hardenedGit, context.root))) {
    throw new EngbrainError("STORE_TRACKED_BY_GIT", `${STORE_DIR_NAME} is tracked by git; refusing to use a store shipped inside a repository`);
  }
}

/** Refuses a case-variant of the store directory name (e.g. `.ENGINEERING-BRAIN`) next to or instead of the real one. */
function assertCanonicalStoreName(root: string): void {
  const folded = STORE_DIR_NAME.toLowerCase();
  const variants = readdirSync(root).filter((name) => name !== STORE_DIR_NAME && name.normalize("NFC").toLowerCase() === folded);
  if (variants.length > 0) {
    throw new EngbrainError("STORE_UNSAFE_PATH", `found ${variants[0]?.slice(0, 40)}: a letter-case variant of ${STORE_DIR_NAME}; refusing to use it`);
  }
}

function readMetaOrFail(db: Database.Database): StoreMeta {
  try {
    return readMeta(db);
  } catch (error) {
    if (error instanceof EngbrainError) {
      throw error;
    }
    throw new EngbrainError("INTEGRITY_FAILED", "store database is unreadable or not an engbrain store");
  }
}

function lstatOrNull(path: string): Stats | null {
  try {
    return lstatSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return null;
    }
    throw error;
  }
}

function chmodBestEffort(path: string, mode = 0o600): void {
  try {
    chmodSync(path, mode);
  } catch {
    // not supported on every platform/filesystem
  }
}

function readMeta(db: Database.Database): StoreMeta {
  const row = db.prepare("SELECT * FROM store_meta WHERE singleton = 1").get() as MetaRow | undefined;
  if (row === undefined) {
    throw new EngbrainError("INTEGRITY_FAILED", "store has no identity row");
  }
  return {
    installId: row.install_id,
    repositoryId: row.repository_id,
    worktreeId: row.worktree_id,
    rootRealpath: row.root_realpath,
    historyKey: row.history_key,
    currentGenerationId: row.current_generation_id,
    createdAt: row.created_at
  };
}
