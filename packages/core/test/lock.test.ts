import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, tempDir } from "../../../tests/helpers/env.js";
import { acquireWriterLock } from "../src/store/lock.js";

afterAll(cleanupTempDirs);

describe("writer lock", () => {
  it("is exclusive and releasable", async () => {
    const dir = tempDir();
    const first = await acquireWriterLock(dir);
    await expect(acquireWriterLock(dir, { timeoutMs: 150, pollMs: 20 })).rejects.toMatchObject({ code: "LOCK_TIMEOUT" });
    first.release();
    const second = await acquireWriterLock(dir, { timeoutMs: 500 });
    second.release();
    expect(existsSync(join(dir, "index.lock"))).toBe(false);
  });
  it("takes over a lock whose same-host owner process is dead", async () => {
    const dir = tempDir();
    writeFileSync(join(dir, "index.lock"), JSON.stringify({ pid: 424242, host: "h", token: "dead", startedAtMs: Date.now() }));
    const lock = await acquireWriterLock(dir, { host: "h", isProcessAlive: () => false, timeoutMs: 500 });
    expect((JSON.parse(readFileSync(join(dir, "index.lock"), "utf8")) as { token: string }).token).not.toBe("dead");
    lock.release();
  });
  it("does not take over a lock held by a live same-host process", async () => {
    const dir = tempDir();
    writeFileSync(join(dir, "index.lock"), JSON.stringify({ pid: 1, host: "h", token: "live", startedAtMs: Date.now() }));
    await expect(acquireWriterLock(dir, { host: "h", isProcessAlive: () => true, timeoutMs: 150, pollMs: 20 })).rejects.toMatchObject({ code: "LOCK_TIMEOUT" });
    expect(existsSync(join(dir, "index.lock"))).toBe(true);
  });
  it("expires foreign-host locks only by age", async () => {
    const dir = tempDir();
    writeFileSync(join(dir, "index.lock"), JSON.stringify({ pid: 1, host: "other", token: "x", startedAtMs: Date.now() }));
    await expect(acquireWriterLock(dir, { host: "me", timeoutMs: 150, pollMs: 20 })).rejects.toMatchObject({ code: "LOCK_TIMEOUT" });
    writeFileSync(join(dir, "index.lock"), JSON.stringify({ pid: 1, host: "other", token: "x", startedAtMs: Date.now() - 7 * 3_600_000 }));
    const lock = await acquireWriterLock(dir, { host: "me", timeoutMs: 500 });
    lock.release();
  });
  it("release only removes the lock it owns", async () => {
    const dir = tempDir();
    const lock = await acquireWriterLock(dir);
    writeFileSync(join(dir, "index.lock"), JSON.stringify({ pid: 1, host: "h", token: "someone-else", startedAtMs: Date.now() }));
    lock.release();
    expect(existsSync(join(dir, "index.lock"))).toBe(true);
  });
  it("single-threaded sanity: many contenders on a stale lock never overlap (true interleaving is covered by the takeover-hook tests in T22)", async () => {
    const dir = tempDir();
    writeFileSync(join(dir, "index.lock"), JSON.stringify({ pid: 424242, host: "h", token: "dead", startedAtMs: 0 }));
    let held = 0;
    let maxHeld = 0;
    await Promise.all(
      Array.from({ length: 8 }, async () => {
        const lock = await acquireWriterLock(dir, { host: "h", isProcessAlive: (pid) => pid !== 424242, timeoutMs: 5000, pollMs: 5 });
        held += 1;
        maxHeld = Math.max(maxHeld, held);
        await new Promise((resolve) => setTimeout(resolve, 10));
        held -= 1;
        lock.release();
      })
    );
    expect(maxHeld).toBe(1);
  });
});
