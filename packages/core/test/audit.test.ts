import { existsSync, readFileSync, readdirSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, tempDir } from "../../../tests/helpers/env.js";
import { AuditLog } from "../src/audit.js";

afterAll(cleanupTempDirs);

const limits = { maxFileBytes: 1024, maxFiles: 3, retentionDays: 90 };

describe("audit log", () => {
  it("writes content-free JSON lines and refuses content-bearing fields", () => {
    const dir = tempDir();
    const log = new AuditLog(dir, "install-1", limits);
    log.record("index_end", { files: 3, ok: true });
    const line = JSON.parse(readFileSync(join(dir, "audit.log"), "utf8").trim()) as Record<string, unknown>;
    expect(line).toMatchObject({ type: "index_end", files: 3, ok: true });
    for (const key of ["content", "source", "snippet", "text", "body", "data", "secret", "match", "Content"]) {
      expect(() => log.record("x", { [key]: "leak" })).toThrow(/content-free/);
    }
  });
  it("hashes paths with the install salt (stable, not reversible by inspection)", () => {
    const a = new AuditLog(tempDir(), "install-1", limits);
    const b = new AuditLog(tempDir(), "install-2", limits);
    expect(a.hashPath("src/secret-project/app.ts")).toBe(a.hashPath("src/secret-project/app.ts"));
    expect(a.hashPath("src/x.ts")).not.toBe(b.hashPath("src/x.ts"));
    expect(a.hashPath("src/secret-project/app.ts")).not.toContain("secret-project");
  });
  it("truncates long strings", () => {
    const dir = tempDir();
    new AuditLog(dir, "i", limits).record("t", { note: "x".repeat(1000) });
    expect((JSON.parse(readFileSync(join(dir, "audit.log"), "utf8")) as { note: string }).note).toHaveLength(200);
  });
  it("rotates by size and keeps at most maxFiles", () => {
    const dir = tempDir();
    const log = new AuditLog(dir, "i", limits);
    for (let i = 0; i < 60; i += 1) {
      log.record("event", { n: i, pad: "p".repeat(100) });
    }
    const files = readdirSync(dir).filter((f) => f.startsWith("audit.log")).sort();
    expect(files.length).toBeLessThanOrEqual(3);
    expect(files).toContain("audit.log");
    expect(statSync(join(dir, "audit.log")).size).toBeLessThanOrEqual(limits.maxFileBytes);
  });
  it.skipIf(process.platform === "win32")("creates the file with mode 0600", () => {
    const dir = tempDir();
    new AuditLog(dir, "i", limits).record("t");
    expect(statSync(join(dir, "audit.log")).mode & 0o777).toBe(0o600);
  });
  it("prunes logs older than the retention window", () => {
    const dir = tempDir();
    writeFileSync(join(dir, "audit.log.1"), "old\n");
    const old = new Date(Date.now() - 100 * 86_400_000);
    utimesSync(join(dir, "audit.log.1"), old, old);
    writeFileSync(join(dir, "other.txt"), "keep");
    new AuditLog(dir, "i", limits);
    expect(existsSync(join(dir, "audit.log.1"))).toBe(false);
    expect(existsSync(join(dir, "other.txt"))).toBe(true);
  });
});
