import Database from "better-sqlite3";
import { join } from "node:path";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { cleanupTempDirs, tempDir } from "../../../tests/helpers/env.js";
import { openDatabase } from "../src/store/db.js";
import { createBuildingGeneration, insertManifest, publishGeneration, validateGeneration, computeSourceFingerprint, markAbandoned } from "../src/store/generations.js";
import { applyMigrations } from "../src/store/migrations.js";

afterAll(cleanupTempDirs);

let db: Database.Database;
beforeEach(() => {
  const dir = tempDir();
  db = openDatabase(join(dir, "s.db"), { create: true });
  applyMigrations(db, { backupDir: join(dir, "b") });
  db.prepare("INSERT INTO store_meta (singleton, install_id, repository_id, worktree_id, root_realpath, created_at) VALUES (1,'i','r','w','/x','now')").run();
});

const ext = [{ id: "inventory", version: "1" }];
const row = (path: string, hash: string | null, reason: string | null = null) =>
  ({ path, contentHash: hash, size: hash ? 1 : null, mtimeNs: null, ctimeNs: null, inode: null, excludedReason: reason });

describe("database-enforced snapshot invariants", () => {
  it("uses safe pragmas", () => {
    expect(db.pragma("trusted_schema", { simple: true })).toBe(0);
    expect(db.pragma("foreign_keys", { simple: true })).toBe(1);
    expect(db.pragma("journal_mode", { simple: true })).toBe("wal");
  });
  it("cannot point current_generation at a building generation", () => {
    const id = createBuildingGeneration(db, { parentId: null, revision: null, branchLabel: null, extractors: ext, now: new Date() });
    expect(() => db.prepare("UPDATE store_meta SET current_generation_id = ?").run(id)).toThrow(/must be complete/);
  });
  it("cannot write a manifest into a complete generation, nor edit manifest rows", () => {
    const id = createBuildingGeneration(db, { parentId: null, revision: null, branchLabel: null, extractors: ext, now: new Date() });
    insertManifest(db, id, [row("a.ts", "h1")]);
    db.prepare("INSERT INTO file_facts VALUES ('h1','inventory','1','ts','ok','{}')").run();
    publishGeneration(db, id, { fingerprint: computeSourceFingerprint(db, id), now: new Date() });
    expect(() => insertManifest(db, id, [row("b.ts", "h2")])).toThrow(/writable only while/);
    expect(() => db.prepare("UPDATE generation_files SET content_hash = 'x' WHERE generation_id = ?").run(id)).toThrow(/immutable/);
    expect(() => db.prepare("UPDATE generations SET status = 'building' WHERE id = ?").run(id)).toThrow(/cannot change status/);
  });
  it("manifest rows must be either hashed or excluded, never both/neither", () => {
    const id = createBuildingGeneration(db, { parentId: null, revision: null, branchLabel: null, extractors: ext, now: new Date() });
    expect(() => insertManifest(db, id, [row("a", "h", "secret:x")])).toThrow();
    expect(() => insertManifest(db, id, [row("b", null, null)])).toThrow();
  });
  it("publish is all-or-nothing: a failure after completing rolls the status back", () => {
    const id = createBuildingGeneration(db, { parentId: null, revision: null, branchLabel: null, extractors: ext, now: new Date() });
    expect(() => publishGeneration(db, id, { fingerprint: "f", now: new Date(), fault: () => { throw new Error("crash"); } })).toThrow("crash");
    expect((db.prepare("SELECT status FROM generations WHERE id = ?").get(id) as { status: string }).status).toBe("building");
    expect((db.prepare("SELECT current_generation_id AS c FROM store_meta").get() as { c: number | null }).c).toBeNull();
  });
  it("validation catches manifest entries without facts and a tampered manifest", () => {
    const id = createBuildingGeneration(db, { parentId: null, revision: null, branchLabel: null, extractors: ext, now: new Date() });
    insertManifest(db, id, [row("a.ts", "missing-hash")]);
    const fp = computeSourceFingerprint(db, id);
    expect(validateGeneration(db, id, fp).problems.join()).toMatch(/lack facts/);
    db.prepare("INSERT INTO file_facts VALUES ('missing-hash','inventory','1',NULL,'ok','{}')").run();
    expect(validateGeneration(db, id, fp).ok).toBe(true);
    expect(validateGeneration(db, id, "0".repeat(64)).problems.join()).toMatch(/fingerprint/);
  });
  it("marks only building generations abandoned", () => {
    const a = createBuildingGeneration(db, { parentId: null, revision: null, branchLabel: null, extractors: ext, now: new Date() });
    expect(markAbandoned(db)).toBe(1);
    expect((db.prepare("SELECT status FROM generations WHERE id = ?").get(a) as { status: string }).status).toBe("abandoned");
    expect(markAbandoned(db)).toBe(0);
  });
});
