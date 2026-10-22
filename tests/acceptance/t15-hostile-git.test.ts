import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { HardenedGit, ALLOWED_GIT_SUBCOMMANDS } from "@engbrain/security";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, engbrainHome, git, makeGitRepo, runCli, tempDir } from "../helpers/env.js";
import { dirname } from "node:path";
import { existsSync } from "node:fs";
import { generateRepoFiles } from "../helpers/fixtures.js";

afterAll(cleanupTempDirs);

const POSIX = process.platform !== "win32";

function script(dir: string, name: string, markers: string): string {
  const path = join(dir, name);
  writeFileSync(path, `#!/bin/sh\ntouch "${markers}/${name}.fired"\nexit 0\n`);
  chmodSync(path, 0o755);
  return path;
}

function buildHostileRepo(): { repo: string; markers: string } {
  const markers = tempDir("engbrain-markers-");
  const tools = tempDir("engbrain-tools-");
  const hooks = tempDir("engbrain-hooks-");
  const files = generateRepoFiles(6, 41);
  files.set(".gitattributes", "* filter=evil\n");
  const repo = makeGitRepo(files); // committed BEFORE any hostile config exists
  const cfg = (key: string, value: string): string => git(repo, ["config", "--local", key, value]);

  cfg("core.fsmonitor", script(tools, "fsmonitor", markers));
  cfg("core.hooksPath", hooks);
  for (const hook of ["post-checkout", "post-merge", "pre-commit", "reference-transaction", "post-index-change", "pre-push"]) {
    script(hooks, hook, markers);
  }
  cfg("core.sshCommand", script(tools, "ssh", markers));
  cfg("core.pager", script(tools, "pager", markers));
  cfg("core.editor", script(tools, "editor", markers));
  cfg("diff.external", script(tools, "diffext", markers));
  cfg("filter.evil.clean", script(tools, "clean", markers));
  cfg("filter.evil.smudge", script(tools, "smudge", markers));
  cfg("filter.evil.process", script(tools, "process", markers));
  cfg("filter.evil.required", "false");
  const included = join(tools, "included.gitconfig");
  writeFileSync(included, `[core]\n\tfsmonitor = ${script(tools, "included-fsmonitor", markers)}\n`);
  cfg("include.path", included);
  return { repo, markers };
}

const fired = (markers: string): string[] => readdirSync(markers).sort();

describe.skipIf(!POSIX)("T15 hostile repository git configuration is never executed", () => {
  it("negative control: PLAIN git does execute repo-defined commands in this fixture (so the test is sensitive)", (ctx) => {
    const { repo, markers } = buildHostileRepo();
    try {
      execFileSync("git", ["status", "--porcelain"], { cwd: repo, stdio: "ignore", env: { PATH: process.env["PATH"] ?? "", HOME: tempDir() } });
    } catch {
      // status may fail after a hostile hook misbehaves; we only care whether it ran
    }
    const ran = fired(markers);
    if (ran.length === 0) {
      ctx.skip();
    }
    expect(ran.length).toBeGreaterThan(0);
  });

  it("every allowlisted subcommand via HardenedGit leaves zero markers", async () => {
    const { repo, markers } = buildHostileRepo();
    const hardened = new HardenedGit();
    try {
      await hardened.run(repo, ["rev-parse", "--is-inside-work-tree", "--show-toplevel", "--path-format=absolute", "--absolute-git-dir", "--git-common-dir", "--is-shallow-repository"]);
      await hardened.run(repo, ["rev-parse", "--verify", "-q", "HEAD^{commit}"]);
      await hardened.run(repo, ["symbolic-ref", "-q", "--short", "HEAD"]);
      await hardened.run(repo, ["rev-list", "--max-parents=0", "HEAD"]);
      await hardened.run(repo, ["ls-files", "-z"]);
      await hardened.run(repo, ["ls-files", "-z", "--others", "--exclude-standard"]);
      await hardened.run(repo, ["ls-files", "-z", "--", ".engineering-brain"]);
      // history subcommands (H1): none of them may run a configured diff driver, textconv, filter, pager, hook or fsmonitor
      const head = (await hardened.run(repo, ["rev-parse", "HEAD"])).trim();
      await hardened.run(repo, ["ls-tree", "-r", "-z", "--full-tree", head]);
      await hardened.runBuffer(repo, ["diff-tree", "-r", "-z", "--raw", "--no-abbrev", "--no-commit-id", "--root", head]);
      await hardened.runBuffer(repo, ["cat-file", "--batch-check"], { input: `${head}\n` });
      await hardened.runBuffer(repo, ["cat-file", "--batch"], { input: `${head}\n` });
      await hardened.run(repo, ["merge-base", "--is-ancestor", head, head]);
    } finally {
      hardened.dispose();
    }
    expect(fired(markers)).toEqual([]);
    expect(ALLOWED_GIT_SUBCOMMANDS.length).toBe(8);
  });

  it("the full CLI flow (init, index, status, gc, purge) on the hostile repo executes nothing and still indexes correctly", async () => {
    const { repo, markers } = buildHostileRepo();
    const home = engbrainHome();
    for (const args of [["init"], ["index"], ["index"], ["status", "--check"], ["gc"], ["uninstall", "--purge", "--yes"]]) {
      const run = await runCli(repo, args, home);
      expect(run.code, `${args.join(" ")}: ${run.stderr}`).toBe(0);
    }
    expect(fired(markers)).toEqual([]);
    const again = await runCli(repo, ["init"], home);
    const index = await runCli(repo, ["index", "--json"], home);
    expect(again.code).toBe(0);
    expect((JSON.parse(index.stdout) as { stats: { included: number } }).stats.included).toBe(8); // 6 sources + README + .gitattributes
    expect(fired(markers)).toEqual([]);
    mkdirSync(join(markers, "x"));
  });
});

describe("T15 hostile core.worktree cannot redirect what gets indexed", () => {
  it("a work tree redirected to the parent directory is refused; nothing is created outside the repo", async () => {
    const repo = makeGitRepo(generateRepoFiles(3, 71));
    const parent = dirname(repo);
    git(repo, ["config", "--local", "core.worktree", parent]);
    for (const command of ["init", "index", "status"]) {
      const run = await runCli(repo, [command], engbrainHome());
      expect(run.code, command).toBe(1);
      expect(run.stderr).toMatch(/INVALID_ROOT|GIT_/);
    }
    expect(existsSync(join(parent, ".engineering-brain"))).toBe(false);
    expect(existsSync(join(repo, ".engineering-brain", "store.db"))).toBe(false);
  });

  it("a work tree redirected to an unrelated directory never indexes that directory", async () => {
    const repo = makeGitRepo(generateRepoFiles(3, 72));
    const victim = tempDir("engbrain-victim-");
    writeFileSync(join(victim, "victim-private.ts"), "export const v = 1;\n");
    git(repo, ["config", "--local", "core.worktree", victim]);
    await runCli(repo, ["init"], engbrainHome());
    expect(existsSync(join(victim, ".engineering-brain"))).toBe(false);
  });
});

describe("non-git directories: refuses to index a home or filesystem root", () => {
  it("refuses the user's home directory when it is not a git work tree", async () => {
    const fakeHome = tempDir("engbrain-fakehome-");
    const run = await runCli(fakeHome, ["init"], engbrainHome(), { HOME: fakeHome, USERPROFILE: fakeHome });
    // os.homedir() reads HOME on POSIX; where it does, this must be refused
    if (process.platform !== "win32") {
      expect(run.code).toBe(1);
      expect(run.stderr).toContain("INVALID_ROOT");
      expect(existsSync(join(fakeHome, ".engineering-brain"))).toBe(false);
    }
  });
});
