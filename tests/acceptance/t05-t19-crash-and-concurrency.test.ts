import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { currentGenerationId, indexRepository, readCurrentSnapshot, validateGeneration, type FaultPoint } from "@engbrain/core";
import Database from "better-sqlite3";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, dumpCurrent, engbrainHome, makeGitRepo, openFor, tempDir } from "../helpers/env.js";
import { generateRepoFiles } from "../helpers/fixtures.js";

afterAll(cleanupTempDirs);

const HERE = dirname(fileURLToPath(import.meta.url));
const CHILD = join(HERE, "..", "helpers", "index-child.mjs");
const BUILT = join(HERE, "..", "..", "packages", "core", "dist", "index.js");
const POINTS: FaultPoint[] = ["pre-facts", "mid-facts", "pre-manifest", "pre-publish", "mid-publish"];

async function waitFor(path: string, ms = 20000): Promise<void> {
  const end = Date.now() + ms;
  while (!existsSync(path)) {
    if (Date.now() > end) {
      throw new Error("child did not reach fault point");
    }
    await new Promise((r) => setTimeout(r, 20));
  }
}

function runChild(root: string, home: string, point = "none", marker = ""): { child: ChildProcess; done: Promise<{ code: number | null; out: string; err: string }> } {
  const child = spawn(process.execPath, [CHILD, root, point, marker], { env: { ...process.env, ENGBRAIN_HOME: home }, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  let err = "";
  child.stdout?.on("data", (d: Buffer) => void (out += d.toString()));
  child.stderr?.on("data", (d: Buffer) => void (err += d.toString()));
  return { child, done: new Promise((resolve) => child.on("exit", (code) => resolve({ code, out, err }))) };
}

describe("built packages are present for child-process tests", () => {
  it("run `npm run build` first", () => {
    expect(existsSync(BUILT)).toBe(true);
  });
});

describe("T5 interrupted indexing never exposes partial state (in-process faults)", () => {
  it.each(POINTS)("fault at %s leaves the previous complete generation current and intact", async (point) => {
    const home = engbrainHome();
    const repo = makeGitRepo(generateRepoFiles(12, 9));
    const first = await openFor(repo, home, true);
    const baseline = await indexRepository({ store: first.store, git: first.info, hardenedGit: first.git });
    const baselineDump = dumpCurrent(first.store);
    first.close();

    writeFileSync(join(repo, "src", "m0", "file0.ts"), "export const changed = 1;\n");
    const crashing = await openFor(repo, home);
    await expect(
      indexRepository({ store: crashing.store, git: crashing.info, hardenedGit: crashing.git, fault: (p) => { if (p === point) { throw new Error(`injected ${p}`); } } })
    ).rejects.toThrow(`injected ${point}`);
    crashing.close();

    const reader = await openFor(repo, home);
    expect(currentGenerationId(reader.store.db)).toBe(baseline.generationId);
    expect(dumpCurrent(reader.store)).toEqual(baselineDump);
    expect(validateGeneration(reader.store.db, baseline.generationId).ok).toBe(true);
    expect(readCurrentSnapshot(reader.store.db)?.generationId).toBe(baseline.generationId);
    reader.close();

    // recovery: next run abandons the half-built generation, publishes, and equals an independent fresh index
    const recover = await openFor(repo, home);
    const result = await indexRepository({ store: recover.store, git: recover.info, hardenedGit: recover.git });
    expect(result.stats.recoveredAbandoned).toBe(1);
    expect(result.stats.extractorRuns).toBeLessThanOrEqual(1);
    const recoveredDump = dumpCurrent(recover.store);
    const left = recover.store.db.prepare("SELECT COUNT(*) AS n FROM generations WHERE status != 'complete'").get() as { n: number };
    expect(left.n).toBe(0);
    recover.close();

    const fresh = await openFor(repo, engbrainHome(), false).catch(() => null);
    expect(fresh).toBeNull(); // different install: a fresh store must be initialised, not opened
    const clean = tempDir("engbrain-fresh-");
    const { cpSync } = await import("node:fs");
    cpSync(repo, clean, { recursive: true, filter: (src) => !src.includes(".engineering-brain") });
    const freshStore = await openFor(clean, engbrainHome(), true);
    await indexRepository({ store: freshStore.store, git: freshStore.info, hardenedGit: freshStore.git });
    expect(recoveredDump.manifest).toEqual(dumpCurrent(freshStore.store).manifest);
    expect(recoveredDump.facts).toEqual(dumpCurrent(freshStore.store).facts);
    freshStore.close();
  });
});

describe("T5/T19 real process killed mid-index (SIGKILL), with a concurrent reader", () => {
  it.each(["pre-publish", "mid-publish", "mid-facts"] as const)("kill at %s: reader keeps seeing the previous generation; stale lock is taken over", async (point) => {
    const home = engbrainHome();
    const repo = makeGitRepo(generateRepoFiles(15, 11));
    const base = await openFor(repo, home, true);
    const baseline = await indexRepository({ store: base.store, git: base.info, hardenedGit: base.git });
    const baselineDump = dumpCurrent(base.store);
    base.close();

    writeFileSync(join(repo, "src", "m1", "file1.ts"), "export const killed = 1;\n");
    const marker = join(tempDir(), "reached");
    const { child, done } = runChild(repo, home, point, marker);
    await waitFor(marker);

    // concurrent reader while the writer is paused mid-build
    const reader = await openFor(repo, home);
    expect(currentGenerationId(reader.store.db)).toBe(baseline.generationId);
    expect(dumpCurrent(reader.store)).toEqual(baselineDump);
    const building = reader.store.db.prepare("SELECT COUNT(*) AS n FROM generations WHERE status = 'building'").get() as { n: number };
    expect(building.n).toBeGreaterThanOrEqual(1); // the build is really in flight...
    expect(readCurrentSnapshot(reader.store.db)?.generationId).toBe(baseline.generationId); // ...but invisible
    reader.close();

    child.kill("SIGKILL");
    await done;
    expect(existsSync(join(repo, ".engineering-brain", "index.lock"))).toBe(true); // dead owner left its lock

    const after = await openFor(repo, home);
    expect(currentGenerationId(after.store.db)).toBe(baseline.generationId);
    expect(dumpCurrent(after.store)).toEqual(baselineDump);
    expect(after.store.db.pragma("integrity_check", { simple: true })).toBe("ok");
    const recovered = await indexRepository({ store: after.store, git: after.info, hardenedGit: after.git, lock: { timeoutMs: 5000 } });
    expect(recovered.stats.recoveredAbandoned).toBeGreaterThanOrEqual(1);
    expect(recovered.generationId).toBeGreaterThan(baseline.generationId);
    expect(validateGeneration(after.store.db, recovered.generationId).ok).toBe(true);
    after.close();
  });
});

describe("T19 concurrency", () => {
  it("two writers racing: exactly one builds at a time, both succeed, no corruption (25 rounds)", async () => {
    const home = engbrainHome();
    const repo = makeGitRepo(generateRepoFiles(10, 13));
    const init = await openFor(repo, home, true);
    init.close();
    for (let round = 0; round < 25; round += 1) {
      writeFileSync(join(repo, "src", "m0", "file0.ts"), `export const round = ${round};\n`);
      const [a, b] = [runChild(repo, home), runChild(repo, home)];
      const [ra, rb] = await Promise.all([a.done, b.done]);
      expect([ra.code, rb.code], `${ra.err}${rb.err}`).toEqual([0, 0]);
      const check = await openFor(repo, home);
      expect(check.store.db.pragma("integrity_check", { simple: true })).toBe("ok");
      expect((check.store.db.prepare("SELECT COUNT(*) AS n FROM generations WHERE status = 'building'").get() as { n: number }).n).toBe(0);
      expect(validateGeneration(check.store.db, currentGenerationId(check.store.db)!).ok).toBe(true);
      check.close();
    }
  }, 180_000);

  it("a writer times out cleanly while another holds the lock, leaving the store untouched", async () => {
    const home = engbrainHome();
    const repo = makeGitRepo(generateRepoFiles(5, 14));
    const first = await openFor(repo, home, true);
    const baseline = await indexRepository({ store: first.store, git: first.info, hardenedGit: first.git });
    const { acquireWriterLock } = await import("@engbrain/core");
    const held = await acquireWriterLock(first.store.dir);
    writeFileSync(join(repo, "new.ts"), "export const n = 1;\n");
    await expect(
      indexRepository({ store: first.store, git: first.info, hardenedGit: first.git, lock: { timeoutMs: 150, pollMs: 20 } })
    ).rejects.toMatchObject({ code: "LOCK_TIMEOUT" });
    held.release();
    expect(currentGenerationId(first.store.db)).toBe(baseline.generationId);
    first.close();
  });

  it("a reader in a separate PROCESS stays consistent while the writer publishes repeatedly (truly concurrent)", async () => {
    const home = engbrainHome();
    const repo = makeGitRepo(generateRepoFiles(60, 15));
    const writer = await openFor(repo, home, true);
    await indexRepository({ store: writer.store, git: writer.info, hardenedGit: writer.git });
    const READER = join(HERE, "..", "helpers", "reader-child.mjs");
    const reader = spawn(process.execPath, [READER, join(repo, ".engineering-brain", "store.db"), "6000"], { stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    reader.stdout?.on("data", (d: Buffer) => void (out += d.toString()));
    const finished = new Promise<number | null>((resolve) => reader.on("exit", resolve));
    await new Promise((r) => setTimeout(r, 300));
    for (let i = 0; i < 40; i += 1) {
      writeFileSync(join(repo, "src", "m0", "file0.ts"), `export const v = ${i};\n`);
      await indexRepository({ store: writer.store, git: writer.info, hardenedGit: writer.git });
    }
    expect(await finished).toBe(0);
    writer.close();
    const result = JSON.parse(out) as { checks: number; inconsistent: number; generations: number[] };
    expect(result.inconsistent).toBe(0);
    expect(result.checks).toBeGreaterThan(100);
    expect(result.generations.length).toBeGreaterThan(2); // the reader really overlapped with publications
  }, 60_000);
});
