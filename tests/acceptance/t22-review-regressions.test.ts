import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { acquireWriterLock, createExclusionMatcher, indexRepository, toStorePath, validateConfig } from "@engbrain/core";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, dumpCurrent, engbrainHome, git, makeGitRepo, openFor, runCli, tempDir } from "../helpers/env.js";
import { generateRepoFiles } from "../helpers/fixtures.js";

afterAll(cleanupTempDirs);
const POSIX = process.platform !== "win32";

const sha = (path: string): string => createHash("sha256").update(readFileSync(path)).digest("hex");

function storeBytes(repo: string): string {
  const dir = join(repo, ".engineering-brain");
  return readdirSync(dir).map((n) => { try { return readFileSync(join(dir, n)).toString("latin1"); } catch { return ""; } }).join("\n");
}

describe.skipIf(!POSIX)("review finding 1: letter-case variants and symlinks around the store directory", () => {
  it("a committed .ENGINEERING-BRAIN dir whose files are symlinks to a victim file is refused; the victim is untouched", async () => {
    const victim = join(tempDir("engbrain-victim-"), "victim.txt");
    writeFileSync(victim, "original\n");
    const repo = makeGitRepo({ "a.ts": "export const a = 1;\n" }, false);
    mkdirSync(join(repo, ".ENGINEERING-BRAIN"));
    symlinkSync(victim, join(repo, ".ENGINEERING-BRAIN", ".gitignore"));
    symlinkSync(victim, join(repo, ".ENGINEERING-BRAIN", "audit.log"));
    git(repo, ["add", "-A"]);
    git(repo, ["commit", "-q", "-m", "hostile"]);
    const home = engbrainHome();
    for (const args of [["init"], ["index"], ["status"], ["uninstall", "--purge", "--yes"]]) {
      const run = await runCli(repo, args, home);
      expect(run.code, `${args.join(" ")}: ${run.stdout}`).toBe(1);
      expect(run.stderr).toMatch(/STORE_UNSAFE_PATH|STORE_TRACKED_BY_GIT/);
    }
    expect(readFileSync(victim, "utf8")).toBe("original\n");
    expect(existsSync(join(repo, ".ENGINEERING-BRAIN", ".gitignore"))).toBe(true); // tracked files not deleted
  });

  it("an UNTRACKED case-variant directory is refused too", async () => {
    const repo = makeGitRepo({ "a.ts": "export const a = 1;\n" });
    mkdirSync(join(repo, ".Engineering-Brain"));
    const run = await runCli(repo, ["init"], engbrainHome());
    expect(run.code).toBe(1);
    expect(run.stderr).toContain("STORE_UNSAFE_PATH");
  });

  it("symlinks inside the canonical store directory are refused at init and at open", async () => {
    const victim = join(tempDir("engbrain-victim-"), "victim.txt");
    writeFileSync(victim, "original\n");
    const repo = makeGitRepo({ "a.ts": "export const a = 1;\n" });
    mkdirSync(join(repo, ".engineering-brain"));
    symlinkSync(victim, join(repo, ".engineering-brain", "audit.log"));
    const home = engbrainHome();
    expect((await runCli(repo, ["init"], home)).code).toBe(1);
    expect(readFileSync(victim, "utf8")).toBe("original\n");

    const clean = makeGitRepo({ "a.ts": "export const a = 1;\n" });
    await runCli(clean, ["init"], home);
    symlinkSync(victim, join(clean, ".engineering-brain", "planted.log"));
    const run = await runCli(clean, ["index"], home);
    expect(run.code).toBe(1);
    expect(run.stderr).toContain("STORE_UNSAFE_PATH");
    expect(readFileSync(victim, "utf8")).toBe("original\n");
  });

  it("the store directory is private (0700) even when it pre-existed with looser permissions", async () => {
    const repo = makeGitRepo({ "a.ts": "export const a = 1;\n" });
    mkdirSync(join(repo, ".engineering-brain"), { mode: 0o755 });
    expect((await runCli(repo, ["init"], engbrainHome())).code).toBe(0);
    expect(statSync(join(repo, ".engineering-brain")).mode & 0o777).toBe(0o700);
  });

  it("excludes .GIT / .Engineering-Brain at any depth regardless of case", () => {
    const matcher = createExclusionMatcher();
    for (const path of [".GIT/config", "sub/.Git/HEAD", ".ENGINEERING-BRAIN/store.db", "x/.Engineering-Brain/a"]) {
      expect(matcher.excludesPath(path), path).toBe("excluded_directory");
    }
    expect(matcher.excludesDirectory(".GiT")).toBe(true);
  });
});

describe.skipIf(!POSIX)("review finding 2: a symlinked PARENT directory cannot be followed", () => {
  it("a git-listed path whose parent became a symlink to an outside directory is excluded and never read", async () => {
    const OUTSIDE = "outside-directory-content-must-not-appear-4f2a";
    const outside = tempDir("engbrain-outside-");
    writeFileSync(join(outside, "notes.ts"), `export const x = "${OUTSIDE}";\n`);
    const repo = makeGitRepo({ "d/notes.ts": "export const inside = 1;\n", "ok.ts": "export const ok = 1;\n" });
    execFileSync("rm", ["-rf", join(repo, "d")]);
    symlinkSync(outside, join(repo, "d"));
    const o = await openFor(repo, engbrainHome(), true);
    const result = await indexRepository({ store: o.store, git: o.info, hardenedGit: o.git });
    const dump = dumpCurrent(o.store);
    o.close();
    expect(dump.manifest.find((m) => m[0] === "d/notes.ts")).toEqual(["d/notes.ts", null, "symlink"]);
    expect(result.stats.included).toBe(1);
    expect(storeBytes(repo).includes(OUTSIDE)).toBe(false);
  });
});

describe("review finding 3: repo-supplied glob patterns cannot trigger catastrophic backtracking", () => {
  it("rejects the exponential pattern and unsupported glob syntax", () => {
    for (const bad of ["*a*a*a*a*a*a*a*a*a*a*b", "src/{a,b}/**", "@(a|b)*", "!keep/**", "[abc]*.ts", "a*b*c*d.ts", "x/(y)", "**/*a*a*a*"]) {
      expect(() => validateConfig({ exclude: [bad] }), bad).toThrow(/unsupported glob syntax/);
    }
    for (const good of ["docs/**", "**/*.generated.ts", "vendor/*", "src/legacy-?.ts", "a*b.ts"]) {
      expect(validateConfig({ exclude: [good] }).exclude).toEqual([good]);
    }
  });
  it("the most expensive ACCEPTED pattern stays fast on a long adversarial path", () => {
    const matcher = createExclusionMatcher(["*a*a*b", "**/*a*a*b"]);
    const path = `${"a".repeat(240)}/${"a".repeat(240)}/${"a".repeat(240)}`;
    const started = performance.now();
    for (let i = 0; i < 200; i += 1) {
      matcher.excludesPath(path);
    }
    expect(performance.now() - started).toBeLessThan(2000);
  });
});

describe.skipIf(!POSIX)("review finding 4: FIFOs and other non-regular files never block indexing", () => {
  it("a FIFO in a plain directory is excluded as not_regular and index completes while holding the lock", async () => {
    const dir = tempDir("engbrain-fifo-");
    writeFileSync(join(dir, "a.ts"), "export const a = 1;\n");
    execFileSync("mkfifo", [join(dir, "pipe.ts")]);
    const o = await openFor(dir, engbrainHome(), true);
    const started = Date.now();
    const result = await indexRepository({ store: o.store, git: o.info, hardenedGit: o.git });
    const dump = dumpCurrent(o.store);
    o.close();
    expect(Date.now() - started).toBeLessThan(10_000);
    expect(result.stats.included).toBe(1);
    expect(dump.manifest.find((m) => m[0] === "pipe.ts")?.[2]).toBe("not_regular");
    expect(existsSync(join(dir, ".engineering-brain", "index.lock"))).toBe(false);
  }, 20_000);
});

describe("review finding 5: stale-lock takeover is serialised", () => {
  it("while one contender holds the takeover lock, another cannot acquire the lock", async () => {
    const dir = tempDir();
    writeFileSync(join(dir, "index.lock"), JSON.stringify({ pid: 424242, host: "h", token: "dead", startedAtMs: 0 }));
    let rival: "acquired" | "timed-out" | "pending" = "pending";
    const lock = await acquireWriterLock(dir, {
      host: "h", pid: 1, isProcessAlive: (pid) => pid !== 424242, timeoutMs: 3000, pollMs: 5,
      onStaleJudged: async () => {
        // a rival arrives exactly between the staleness verdict and the takeover
        try {
          (await acquireWriterLock(dir, { host: "h", pid: 2, isProcessAlive: (pid) => pid !== 424242, timeoutMs: 100, pollMs: 5 })).release();
          rival = "acquired";
        } catch {
          rival = "timed-out";
        }
      }
    });
    expect(rival).toBe("timed-out");
    expect((JSON.parse(readFileSync(join(dir, "index.lock"), "utf8")) as { pid: number }).pid).toBe(1);
    lock.release();
    expect(existsSync(join(dir, "index.lock"))).toBe(false);
    expect(readdirSync(dir)).toEqual([]);
  });

  it("a live lock that replaced the stale one mid-takeover is restored, not stolen", async () => {
    const dir = tempDir();
    const path = join(dir, "index.lock");
    writeFileSync(path, JSON.stringify({ pid: 424242, host: "h", token: "dead", startedAtMs: 0 }));
    const live = JSON.stringify({ pid: 7, host: "h", token: "live-owner", startedAtMs: Date.now() });
    await expect(
      acquireWriterLock(dir, {
        host: "h", pid: 1, timeoutMs: 400, pollMs: 5, isProcessAlive: (pid) => pid !== 424242,
        onStaleJudged: () => { writeFileSync(path, live); } // the owner changed the file after the verdict
      })
    ).rejects.toMatchObject({ code: "LOCK_TIMEOUT" });
    expect(JSON.parse(readFileSync(path, "utf8"))).toMatchObject({ token: "live-owner" }); // still held by its owner
    expect(readdirSync(dir).filter((n) => n.includes("stale") || n.includes("takeover"))).toEqual([]);
  });
});

describe.skipIf(!POSIX)("review finding 6: core.worktree redirected to a directory that has its own .git", () => {
  it("a nested repository pointing core.worktree at its enclosing repository is refused", async () => {
    const outer = makeGitRepo({ "outer.ts": "export const o = 1;\n" });
    const inner = join(outer, "inner");
    mkdirSync(inner);
    git(inner, ["init", "-q"]);
    writeFileSync(join(inner, "i.ts"), "export const i = 1;\n");
    git(inner, ["add", "-A"]);
    git(inner, ["commit", "-q", "-m", "inner"]);
    git(inner, ["config", "--local", "core.worktree", "../.."]); // relative to the .git directory: resolves to `outer`
    for (const command of ["init", "index"]) {
      const run = await runCli(inner, [command], engbrainHome());
      expect(run.code, `${command}: ${run.stdout}`).toBe(1);
      expect(run.stderr).toMatch(/INVALID_ROOT|GIT_/);
    }
    expect(existsSync(join(outer, ".engineering-brain"))).toBe(false);
  });

  it("legitimate linked worktrees (a .git FILE pointing at the git dir) still work", async () => {
    const main = makeGitRepo(generateRepoFiles(3, 81));
    const wt = join(tempDir("engbrain-wt-"), "wt");
    git(main, ["worktree", "add", "-q", "-b", "side", wt]);
    expect((await runCli(wt, ["init"], engbrainHome())).code).toBe(0);
  });
});

describe("review finding 8 (Windows reasoning, verified here only at the pure-function level)", () => {
  it("rejects ':' components, drive-relative and stream-like names, and trailing dot or space", () => {
    for (const bad of ["dir/C:foo", "a:b", "C:foo", "x/y:stream", "name.", "dir/name ", "dir./x"]) {
      expect(toStorePath(bad).ok, bad).toBe(false);
    }
    expect(toStorePath("dir/ok.name").ok).toBe(true);
  });
});

describe("review minor: identity is checked before the foreign database is written", () => {
  it("a store from another installation is refused and its file is byte-identical afterwards", async () => {
    const repo = makeGitRepo({ "a.ts": "export const a = 1;\n" });
    const owner = engbrainHome();
    const first = await openFor(repo, owner, true);
    first.close();
    const dbPath = join(repo, ".engineering-brain", "store.db");
    const before = sha(dbPath);
    await expect(openFor(repo, engbrainHome())).rejects.toMatchObject({ code: "STORE_OWNER_MISMATCH" });
    expect(sha(dbPath)).toBe(before);
    expect(readdirSync(join(repo, ".engineering-brain")).filter((n) => n.endsWith("-wal") && statSync(join(repo, ".engineering-brain", n)).size > 0)).toEqual([]);
    expect(dirname(dbPath)).toContain(".engineering-brain");
  });

  it("a non-database file in place of the store gives a clean integrity error, not a stack trace", async () => {
    const repo = makeGitRepo({ "a.ts": "export const a = 1;\n" });
    mkdirSync(join(repo, ".engineering-brain"));
    writeFileSync(join(repo, ".engineering-brain", "store.db"), "this is not a sqlite database");
    const run = await runCli(repo, ["status"], engbrainHome());
    expect(run.code).toBe(1);
    expect(run.stderr).toMatch(/INTEGRITY_FAILED|unexpected failure/);
    expect(run.stderr).not.toContain("    at ");
  });
});
