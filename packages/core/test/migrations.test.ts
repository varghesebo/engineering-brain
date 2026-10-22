import Database from "better-sqlite3";
import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, tempDir } from "../../../tests/helpers/env.js";
import { applyMigrations, currentVersion, latestVersion, MIGRATIONS, type Migration } from "../src/store/migrations.js";

afterAll(cleanupTempDirs);

function freshDb(): { db: Database.Database; dir: string } {
  const dir = tempDir();
  return { db: new Database(join(dir, "s.db")), dir };
}

describe("migrations", () => {
  it("creates the v1 schema on an empty database without a backup", () => {
    const { db, dir } = freshDb();
    const result = applyMigrations(db, { backupDir: join(dir, "backups") });
    expect(result).toEqual({ from: 0, to: latestVersion(), backupPath: null });
    expect(currentVersion(db)).toBe(latestVersion());
    const tables = (db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as Array<{ name: string }>).map((t) => t.name);
    expect(tables).toEqual(expect.arrayContaining(["store_meta", "generations", "generation_files", "file_facts", "generation_extractors"]));
    expect(existsSync(join(dir, "backups"))).toBe(false);
  });
  it("is idempotent", () => {
    const { db, dir } = freshDb();
    applyMigrations(db, { backupDir: join(dir, "b") });
    expect(applyMigrations(db, { backupDir: join(dir, "b") })).toMatchObject({ from: latestVersion(), to: latestVersion(), backupPath: null });
  });
  it("backs up an existing store before upgrading and applies only newer migrations", () => {
    const { db, dir } = freshDb();
    applyMigrations(db, { backupDir: join(dir, "backups") });
    db.prepare("INSERT INTO generations (revision, extractor_set_hash, status, created_at) VALUES (NULL, 'h', 'abandoned', 'now')").run();
    const v2: Migration = { version: latestVersion() + 1, name: "test column", up: (d) => d.exec("ALTER TABLE generations ADD COLUMN note TEXT") };
    const before = latestVersion();
    const result = applyMigrations(db, { backupDir: join(dir, "backups"), migrations: [...MIGRATIONS, v2], now: () => new Date("2026-01-02T03:04:05Z") });
    expect(result).toMatchObject({ from: before, to: before + 1 });
    expect(result.backupPath).toContain(`store-v${before}-2026-01-02T03-04-05`);
    expect(readdirSync(join(dir, "backups"))).toHaveLength(1);
    const backup = new Database(result.backupPath!, { readonly: true });
    expect(backup.pragma("user_version", { simple: true })).toBe(latestVersion());
    expect((backup.prepare("SELECT COUNT(*) AS n FROM generations").get() as { n: number }).n).toBe(1);
    expect(() => db.prepare("SELECT note FROM generations").all()).not.toThrow();
  });
  it("rolls a failing migration back atomically", () => {
    const { db, dir } = freshDb();
    applyMigrations(db, { backupDir: join(dir, "b") });
    const bad: Migration = {
      version: latestVersion() + 1, name: "bad",
      up: (d) => { d.exec("CREATE TABLE half_done (x INTEGER)"); throw new Error("boom"); }
    };
    expect(() => applyMigrations(db, { backupDir: join(dir, "b"), migrations: [...MIGRATIONS, bad] })).toThrow("boom");
    expect(currentVersion(db)).toBe(latestVersion());
    expect(db.prepare("SELECT name FROM sqlite_master WHERE name = 'half_done'").get()).toBeUndefined();
  });
  it("refuses a store written by a newer engbrain (no downgrade)", () => {
    const { db, dir } = freshDb();
    applyMigrations(db, { backupDir: join(dir, "b") });
    db.pragma(`user_version = ${latestVersion() + 5}`);
    expect(() => applyMigrations(db, { backupDir: join(dir, "b") })).toThrowError(expect.objectContaining({ code: "STORE_NEWER_SCHEMA" }));
  });
});

describe("Phase 2A migrations preserve existing data (v1 store upgraded to the current schema)", () => {
  it("keeps generations, manifests and facts, adds the code-fact and edge tables, and backs up first", () => {
    const { db, dir } = freshDb();
    applyMigrations(db, { backupDir: join(dir, "b"), migrations: MIGRATIONS.filter((m) => m.version === 1) });
    expect(currentVersion(db)).toBe(1);
    db.prepare("INSERT INTO store_meta (singleton, install_id, repository_id, worktree_id, root_realpath, created_at) VALUES (1, 'i', 'r', 'w', '/x', 'now')").run();
    db.prepare("INSERT INTO generations (id, revision, extractor_set_hash, status, created_at) VALUES (1, 'abc', 'h', 'building', 'now')").run();
    db.prepare("INSERT INTO generation_extractors VALUES (1, 'inventory', '1')").run();
    db.prepare("INSERT INTO generation_files (generation_id, path, content_hash, size) VALUES (1, 'a.ts', 'hash-a', 3)").run();
    db.prepare("INSERT INTO file_facts VALUES ('hash-a', 'inventory', '1', 'typescript', 'ok', '{\"lineCount\":1}')").run();
    db.prepare("UPDATE generations SET status = 'complete', completed_at = 'now' WHERE id = 1").run();
    db.prepare("UPDATE store_meta SET current_generation_id = 1").run();

    const result = applyMigrations(db, { backupDir: join(dir, "b") });
    expect(result).toMatchObject({ from: 1, to: latestVersion() });
    expect(result.backupPath).not.toBeNull();
    expect(db.prepare("SELECT revision, status, resolver_version FROM generations WHERE id = 1").get()).toEqual({ revision: "abc", status: "complete", resolver_version: null });
    expect(db.prepare("SELECT path, content_hash FROM generation_files").all()).toEqual([{ path: "a.ts", content_hash: "hash-a" }]);
    expect(db.prepare("SELECT language, attrs_json FROM file_facts").all()).toEqual([{ language: "typescript", attrs_json: '{"lineCount":1}' }]);
    const objects = (db.prepare("SELECT name FROM sqlite_master WHERE type IN ('table','view')").all() as Array<{ name: string }>).map((o) => o.name);
    expect(objects).toEqual(expect.arrayContaining(["symbols", "syntax_refs", "exports", "fact_diagnostics", "module_edges", "symbol_occurrences", "applicable_facts", "generation_extractor_extensions"]));
    // the v1 data is readable through the new view, and the backup holds the pre-upgrade state
    const backup = new Database(result.backupPath!, { readonly: true });
    expect(backup.pragma("user_version", { simple: true })).toBe(1);
    expect(backup.prepare("SELECT COUNT(*) AS n FROM generations").get()).toEqual({ n: 1 });
    backup.close();
  });
});
