import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ALLOWED_GIT_SUBCOMMANDS, GitError, HardenedGit, resolveGitBinary } from "../src/git.js";

const created: HardenedGit[] = [];
afterEach(() => {
  for (const git of created.splice(0)) {
    git.dispose();
  }
});

function make(): HardenedGit {
  const git = new HardenedGit();
  created.push(git);
  return git;
}

describe("HardenedGit", () => {
  it("only allows a small read-only subcommand allowlist", async () => {
    expect(ALLOWED_GIT_SUBCOMMANDS).toEqual(["rev-parse", "ls-files", "rev-list", "symbolic-ref", "diff-tree", "cat-file", "merge-base", "ls-tree"]);
    const git = make();
    for (const sub of ["status", "diff", "config", "fetch", "log", "checkout", "hash-object", "show", "blame", "grep", "archive", "replace"]) {
      await expect(git.run(tmpdir(), [sub])).rejects.toMatchObject({ code: "GIT_DISALLOWED" });
    }
    await expect(git.run(tmpdir(), [])).rejects.toMatchObject({ code: "GIT_DISALLOWED" });
  });

  it("rejects config-injection style arguments", async () => {
    const git = make();
    for (const arg of ["-c", "-ccore.fsmonitor=x", "--config=a=b", "--exec-path=/x", "--upload-pack=x", "--git-dir=/x", "--work-tree=/x", "--textconv", "--filters", "--output=/tmp/x", "-Oorder", "--open-files-in-pager", "--no-index", "--ext-diff"]) {
      await expect(git.run(tmpdir(), ["rev-parse", arg])).rejects.toMatchObject({ code: "GIT_DISALLOWED" });
    }
  });

  it("does not use Unix-only /dev/null for hooks or config (Windows-safe)", () => {
    const git = make();
    const args = git.buildGlobalArgs();
    const env = git.buildEnv({ PATH: "/bin" });
    expect(args.join(" ")).not.toContain("/dev/null");
    expect(JSON.stringify(env)).not.toContain("/dev/null");
    expect(args).toContain("core.fsmonitor=false");
    const hooks = args.find((a) => a.startsWith("core.hooksPath="));
    expect(hooks).toBeDefined();
    expect(hooks?.slice("core.hooksPath=".length).startsWith(tmpdir())).toBe(true);
  });

  it("builds a minimal environment: no inherited secrets or git variables", () => {
    const git = make();
    const env = git.buildEnv({
      PATH: "/bin", AWS_SECRET_ACCESS_KEY: "x", GITHUB_TOKEN: "y", GIT_DIR: "/evil", GIT_SSH_COMMAND: "evil", HOME: "/home/real", SystemRoot: "C:\\Windows"
    });
    expect(env["AWS_SECRET_ACCESS_KEY"]).toBeUndefined();
    expect(env["GITHUB_TOKEN"]).toBeUndefined();
    expect(env["GIT_DIR"]).toBeUndefined();
    expect(env["GIT_SSH_COMMAND"]).toBeUndefined();
    expect(env["HOME"]).not.toBe("/home/real");
    expect(env["GIT_CONFIG_NOSYSTEM"]).toBe("1");
    expect(env["GIT_TERMINAL_PROMPT"]).toBe("0");
    expect(env["SystemRoot"]).toBe("C:\\Windows");
  });

  it("removes its scratch directory on dispose", () => {
    const git = new HardenedGit();
    const hooks = git.buildGlobalArgs().find((a) => a.startsWith("core.hooksPath="))!.slice("core.hooksPath=".length);
    git.dispose();
    expect(() => rmSync(hooks)).toThrow();
  });

  it("reports a clear error when not in a repository", async () => {
    const git = make();
    const dir = mkdtempSync(join(tmpdir(), "engbrain-nogit-"));
    try {
      await expect(git.run(dir, ["rev-parse", "--is-inside-work-tree"])).rejects.toBeInstanceOf(GitError);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("resolveGitBinary", () => {
  it("ignores relative and empty PATH entries (a repo cannot plant git in the working directory)", () => {
    expect(resolveGitBinary({ PATH: ".:./bin::relative/dir" }, "linux")).toBeNull();
  });
  it("finds git via an absolute PATH entry", () => {
    const found = resolveGitBinary(process.env, process.platform);
    expect(found).not.toBeNull();
    expect(found?.startsWith("/") || /^[A-Za-z]:\\/.test(found ?? "")).toBe(true);
  });
});
