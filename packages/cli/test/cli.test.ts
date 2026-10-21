import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, engbrainHome, makeGitRepo, runCli, tempDir } from "../../../tests/helpers/env.js";
import { VERSION } from "../src/main.js";

afterAll(cleanupTempDirs);

describe("engbrain CLI surface", () => {
  it("prints help (exit 0), version, and usage errors with exit code 2", async () => {
    const home = engbrainHome();
    const dir = tempDir();
    const help = await runCli(dir, ["--help"], home);
    expect(help.code).toBe(0);
    expect(help.stdout).toContain("Not available in this build: context, verify, mcp, agents.");
    expect((await runCli(dir, ["--version"], home)).stdout.trim()).toBe(VERSION);
    expect((await runCli(dir, [], home)).code).toBe(2);
    const unknown = await runCli(dir, ["frobnicate"], home);
    expect(unknown.code).toBe(2);
    expect(unknown.stderr).toContain("unknown command");
    expect((await runCli(dir, ["index", "--bogus"], home)).code).toBe(2);
  });

  it("states plainly that later-stage commands are not available, whatever options follow", async () => {
    const home = engbrainHome();
    for (const args of [["verify"], ["verify", "--run", "suite"], ["mcp", "--root", "x"], ["context", "fix auth"], ["agents", "--json"]]) {
      const run = await runCli(tempDir(), args, home);
      expect(run.code, args.join(" ")).toBe(2);
      expect(run.stderr).toContain("not available in this build");
      expect(run.stderr).toContain("Nothing was executed");
    }
  });

  it("commands fail with NOT_INITIALIZED before init, with exit code 1 and a clear message", async () => {
    const home = engbrainHome();
    const repo = makeGitRepo({ "a.ts": "export const a = 1;\n" });
    for (const command of ["index", "status", "gc"]) {
      const run = await runCli(repo, [command], home);
      expect(run.code).toBe(1);
      expect(run.stderr).toContain("NOT_INITIALIZED");
    }
  });

  it("--json output is valid JSON for every command and carries no extra prose on stdout", async () => {
    const home = engbrainHome();
    const repo = makeGitRepo({ "a.ts": "export const a = 1;\n" });
    for (const args of [["init", "--json"], ["index", "--json"], ["status", "--json"], ["status", "--check", "--json"], ["gc", "--json"], ["uninstall", "--json"]]) {
      const run = await runCli(repo, args, home);
      expect(run.code, `${args.join(" ")}: ${run.stderr}`).toBe(0);
      expect(() => JSON.parse(run.stdout), args.join(" ")).not.toThrow();
    }
  });

  it("--root selects the repository directory", async () => {
    const home = engbrainHome();
    const repo = makeGitRepo({ "a.ts": "export const a = 1;\n" });
    const elsewhere = tempDir();
    expect((await runCli(elsewhere, ["init", "--root", repo], home)).code).toBe(0);
    expect((await runCli(elsewhere, ["index", "--root", repo], home)).code).toBe(0);
    const bad = await runCli(elsewhere, ["status", "--root", join(elsewhere, "missing")], home);
    expect(bad.code).toBe(1);
    expect(bad.stderr).toContain("INVALID_ROOT");
  });

  it("validates --keep and refuses to run against an unreadable configuration", async () => {
    const home = engbrainHome();
    const repo = makeGitRepo({ "a.ts": "export const a = 1;\n" });
    await runCli(repo, ["init"], home);
    expect((await runCli(repo, ["gc", "--keep", "abc"], home)).code).toBe(2);
    expect((await runCli(repo, ["gc", "--keep", "21"], home)).code).toBe(2);
    writeFileSync(join(repo, ".engineering-brain", "config.json"), JSON.stringify({ allowNetwork: true }));
    const run = await runCli(repo, ["index"], home);
    expect(run.code).toBe(1);
    expect(run.stderr).toContain("INVALID_CONFIG");
  });

  it("a hostile committed-looking config can add excludes but cannot weaken defaults", async () => {
    const home = engbrainHome();
    const repo = makeGitRepo({ "a.ts": "export const a = 1;\n", "docs/skip.md": "# skip\n", ".env": "X=1\n" });
    await runCli(repo, ["init"], home);
    writeFileSync(join(repo, ".engineering-brain", "config.json"), JSON.stringify({ exclude: ["docs/**"], maxFileBytes: 8_388_608 }));
    const run = await runCli(repo, ["index", "--json"], home);
    const stats = (JSON.parse(run.stdout) as { stats: { included: number; excludedByReason: Record<string, number> } }).stats;
    expect(stats.included).toBe(1);
    expect(stats.excludedByReason).toMatchObject({ config_exclude: 1, sensitive_path: 1 });
  });

  it("never prints raw errors from unexpected failures (only a generic message)", async () => {
    const run = await runCli(tempDir(), ["status", "--root", "\0bad"], engbrainHome());
    expect(run.code).toBe(1);
    expect(run.stderr).not.toContain("    at ");
  });
});
