import { cpSync, renameSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import Database from "better-sqlite3";
import { indexRepository } from "@engbrain/core";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, dumpCurrent, engbrainHome, git, makeGitRepo, openFor, runCli, tempDir } from "../helpers/env.js";
import { generateRepoFiles } from "../helpers/fixtures.js";

afterAll(cleanupTempDirs);

describe("T20 retention and garbage collection", () => {
  it("keeps K generations, sweeps unreferenced facts, and keeps the database size bounded", async () => {
    const home = engbrainHome();
    const repo = makeGitRepo(generateRepoFiles(100, 51));
    const o = await openFor(repo, home, true);
    const sizes: number[] = [];
    for (let g = 0; g < 10; g += 1) {
      writeFileSync(join(repo, "src", "m0", "file0.ts"), `export const churn = ${g};\n`);
      await indexRepository({ store: o.store, git: o.info, hardenedGit: o.git });
      o.store.db.pragma("wal_checkpoint(TRUNCATE)");
      sizes.push(statSync(join(repo, ".engineering-brain", "store.db")).size);
    }
    const complete = o.store.db.prepare("SELECT COUNT(*) AS n FROM generations WHERE status = 'complete'").get() as { n: number };
    expect(complete.n).toBe(3);
    const facts = o.store.db.prepare("SELECT COUNT(*) AS n FROM file_facts").get() as { n: number };
    const referenced = o.store.db
      .prepare("SELECT COUNT(DISTINCT content_hash) AS n FROM generation_files WHERE content_hash IS NOT NULL")
      .get() as { n: number };
    expect(facts.n).toBe(referenced.n); // nothing unreferenced survives
    expect(referenced.n).toBe(100 + 1 + 2); // 101 distinct contents now + 2 older versions of the churned file kept by older generations
    expect(sizes[9]!).toBeLessThan(sizes[0]! * 1.5 + 64 * 1024);
    o.close();
  });

  it("`gc --keep` trims further and is safe to repeat", async () => {
    const home = engbrainHome();
    const repo = makeGitRepo(generateRepoFiles(10, 52));
    await runCli(repo, ["init"], home);
    for (let g = 0; g < 4; g += 1) {
      writeFileSync(join(repo, "src", "m0", "file0.ts"), `export const c = ${g};\n`);
      await runCli(repo, ["index"], home);
    }
    const first = await runCli(repo, ["gc", "--keep", "1", "--json"], home);
    const second = await runCli(repo, ["gc", "--keep", "1", "--json"], home);
    expect((JSON.parse(first.stdout) as { generationsRemoved: number }).generationsRemoved).toBe(2);
    expect(JSON.parse(second.stdout)).toEqual({ generationsRemoved: 0, factsRemoved: 0 });
    expect((await runCli(repo, ["status", "--check"], home)).code).toBe(0);
    expect((await runCli(repo, ["gc", "--keep", "0"], home)).code).toBe(2);
  });
});

describe("T21 repository and worktree identity", () => {
  it("repository with no commits: initialises and indexes; revision and history key are null", async () => {
    const repo = makeGitRepo(generateRepoFiles(3, 61), false);
    const o = await openFor(repo, engbrainHome(), true);
    expect(o.info).toMatchObject({ isGit: true, revision: null, branchLabel: null, historyKey: null });
    const result = await indexRepository({ store: o.store, git: o.info, hardenedGit: o.git });
    expect(result.stats.included).toBe(4); // untracked files are listed and indexed: 3 sources + README
    expect(result.revision).toBeNull();
    o.close();
  });

  it("adopts a history key once the first commit exists (no warning), and flags a later rewrite without refusing", async () => {
    const home = engbrainHome();
    const repo = makeGitRepo(generateRepoFiles(3, 62), false);
    const before = await openFor(repo, home, true);
    expect(before.store.meta.historyKey).toBeNull();
    before.close();
    git(repo, ["add", "-A"]);
    git(repo, ["commit", "-q", "-m", "first"]);
    const adopted = await openFor(repo, home);
    expect(adopted.store.historyChanged).toBe(false);
    expect(adopted.store.meta.historyKey).not.toBeNull();
    adopted.close();
    git(repo, ["commit", "-q", "--amend", "-m", "root rewritten"]); // root commit SHA changes
    const rewritten = await openFor(repo, home);
    expect(rewritten.store.historyChanged).toBe(true);
    rewritten.close();
    const again = await openFor(repo, home);
    expect(again.store.historyChanged).toBe(false); // adopted; only reported once
    again.close();
  });

  it("shallow clone: flagged shallow, no history key, still works", async () => {
    const origin = makeGitRepo(generateRepoFiles(3, 63));
    for (let i = 0; i < 2; i += 1) {
      writeFileSync(join(origin, `extra${i}.ts`), `export const e = ${i};\n`);
      git(origin, ["add", "-A"]);
      git(origin, ["commit", "-q", "-m", `c${i}`]);
    }
    const clone = tempDir("engbrain-shallow-");
    git(clone, ["clone", "-q", "--depth", "1", `file://${origin}`, "."]);
    const o = await openFor(clone, engbrainHome(), true);
    expect(o.info.isShallow).toBe(true);
    expect(o.info.historyKey).toBeNull();
    expect(o.info.revision).not.toBeNull();
    await indexRepository({ store: o.store, git: o.info, hardenedGit: o.git });
    o.close();
  });

  it("detached HEAD has a revision and no branch label; rebase/amend changes the revision but reuses all facts", async () => {
    const home = engbrainHome();
    const repo = makeGitRepo(generateRepoFiles(8, 64));
    const o = await openFor(repo, home, true);
    const first = await indexRepository({ store: o.store, git: o.info, hardenedGit: o.git });
    o.close();

    git(repo, ["commit", "-q", "--amend", "-m", "reworded"]); // also rewrites the root commit
    const amended = await openFor(repo, home);
    expect(amended.store.historyChanged).toBe(true);
    const second = await indexRepository({ store: amended.store, git: amended.info, hardenedGit: amended.git });
    expect(second.revision).not.toBe(first.revision);
    expect(second.stats.extractorRuns).toBe(0);
    expect(second.sourceFingerprint).toBe(first.sourceFingerprint);
    expect(second.unchanged).toBe(false); // a different revision is a different snapshot
    amended.close();

    git(repo, ["checkout", "-q", "--detach"]);
    const detached = await openFor(repo, home);
    expect(detached.info.branchLabel).toBeNull();
    expect(detached.info.revision).toBe(second.revision);
    detached.close();
  });

  it("refuses a store copied into another repository, moved with its directory, or created by another install", async () => {
    const home = engbrainHome();
    const repoA = makeGitRepo(generateRepoFiles(3, 65));
    const repoB = makeGitRepo(generateRepoFiles(3, 66));
    const a = await openFor(repoA, home, true);
    a.close();

    cpSync(join(repoA, ".engineering-brain"), join(repoB, ".engineering-brain"), { recursive: true });
    await expect(openFor(repoB, home)).rejects.toMatchObject({ code: "STORE_ROOT_MISMATCH" });

    const moved = join(tempDir("engbrain-moved-"), "renamed");
    renameSync(repoA, moved);
    await expect(openFor(moved, home)).rejects.toMatchObject({ code: "STORE_ROOT_MISMATCH" });

    renameSync(moved, repoA);
    await expect(openFor(repoA, engbrainHome())).rejects.toMatchObject({ code: "STORE_OWNER_MISMATCH" });
    const ok = await openFor(repoA, home);
    ok.close();
  });

  it("a different repository history at the same path is reported (historyChanged), not silently accepted and not refused", async () => {
    const home = engbrainHome();
    const repo = makeGitRepo(generateRepoFiles(3, 67));
    const a = await openFor(repo, home, true);
    a.close();
    const db = new Database(join(repo, ".engineering-brain", "store.db"));
    db.prepare("UPDATE store_meta SET history_key = 'a-different-history'").run();
    db.close();
    const b = await openFor(repo, home);
    expect(b.store.historyChanged).toBe(true);
    b.close();
    const viaCli = await runCli(repo, ["status"], home);
    expect(viaCli.code).toBe(0);
    expect(viaCli.stdout).not.toContain("history changed"); // already adopted by the previous open; reported once
  });

  it("refuses a store directory that a repository ships (tracked by git)", async () => {
    const home = engbrainHome();
    const repo = makeGitRepo({ "a.ts": "export const a = 1;\n", ".engineering-brain/store.db": "not a database", ".engineering-brain/config.json": "{}" }, false);
    git(repo, ["add", "-f", ".engineering-brain/store.db"]);
    git(repo, ["add", "-A"]);
    git(repo, ["commit", "-q", "-m", "ships a store"]);
    await expect(openFor(repo, home)).rejects.toMatchObject({ code: "STORE_TRACKED_BY_GIT" });
    await expect(openFor(repo, home, true)).rejects.toMatchObject({ code: "STORE_TRACKED_BY_GIT" });
    const viaCli = await runCli(repo, ["index"], home);
    expect(viaCli.code).toBe(1);
    expect(viaCli.stderr).toContain("STORE_TRACKED_BY_GIT");
  });

  it("init twice is refused; non-git directories work; running from a subdirectory finds the repo root", async () => {
    const home = engbrainHome();
    const repo = makeGitRepo(generateRepoFiles(3, 68));
    expect((await runCli(repo, ["init"], home)).code).toBe(0);
    const twice = await runCli(repo, ["init"], home);
    expect(twice.code).toBe(1);
    expect(twice.stderr).toContain("ALREADY_INITIALIZED");
    const sub = await runCli(join(repo, "src"), ["status", "--json"], home);
    expect(sub.code).toBe(0);
    expect((JSON.parse(sub.stdout) as { root: string }).root).toBe(repo);

    const plain = tempDir("engbrain-plain-");
    writeFileSync(join(plain, "a.ts"), "export const a = 1;\n");
    expect((await runCli(plain, ["init"], home)).code).toBe(0);
    const idx = await runCli(plain, ["index", "--json"], home);
    expect((JSON.parse(idx.stdout) as { stats: { included: number } }).stats.included).toBe(1);
    const o = await openFor(plain, home);
    expect(o.info.isGit).toBe(false);
    expect(dumpCurrent(o.store).manifest.map((m) => m[0])).toEqual(["a.ts"]);
    o.close();
  });
});
