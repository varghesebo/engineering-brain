import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, engbrainHome, git, makeGitRepo, runCli, tempDir } from "../helpers/env.js";
import { generateRepoFiles } from "../helpers/fixtures.js";

afterAll(cleanupTempDirs);

function treeHash(root: string): string {
  const hash = createHash("sha256");
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
      if (entry.name === ".engineering-brain" || entry.name === ".git") {
        continue;
      }
      const full = join(dir, entry.name);
      hash.update(full.slice(root.length));
      entry.isDirectory() ? walk(full) : hash.update(readFileSync(full));
    }
  };
  walk(root);
  return hash.digest("hex");
}

describe("T13 deletion leaves the source repository intact", () => {
  it("default uninstall keeps knowledge; --purge needs --yes; purge removes only the store", async () => {
    const home = engbrainHome();
    const repo = makeGitRepo(generateRepoFiles(10, 31));
    const before = treeHash(repo);
    await runCli(repo, ["init"], home);
    await runCli(repo, ["index"], home);
    expect(treeHash(repo)).toBe(before);

    const soft = await runCli(repo, ["uninstall"], home);
    expect(soft.code).toBe(0);
    expect(existsSync(join(repo, ".engineering-brain", "store.db"))).toBe(true);

    const refused = await runCli(repo, ["uninstall", "--purge"], home);
    expect(refused.code).toBe(3);
    expect(refused.stderr).toContain("POLICY_REFUSED");
    expect(existsSync(join(repo, ".engineering-brain"))).toBe(true);

    const purged = await runCli(repo, ["uninstall", "--purge", "--yes"], home);
    expect(purged.code).toBe(0);
    expect(existsSync(join(repo, ".engineering-brain"))).toBe(false);
    expect(treeHash(repo)).toBe(before);
    expect(readdirSync(repo).includes("src")).toBe(true);

    const again = await runCli(repo, ["uninstall", "--purge", "--yes"], home);
    expect(again.code).toBe(0); // idempotent
  });

  it("init tolerates a leftover config file and purge refuses a store directory that git tracks", async () => {
    const home = engbrainHome();
    const left = makeGitRepo({ "a.ts": "export const a = 1;\n" });
    mkdirSync(join(left, ".engineering-brain"));
    writeFileSync(join(left, ".engineering-brain", "config.json"), JSON.stringify({ exclude: ["x/**"] }));
    expect((await runCli(left, ["init"], home)).code).toBe(0);
    expect(JSON.parse(readFileSync(join(left, ".engineering-brain", "config.json"), "utf8"))).toEqual({ exclude: ["x/**"] });

    const tracked = makeGitRepo({ "a.ts": "export const a = 1;\n", ".engineering-brain/note.txt": "committed" }, false);
    git(tracked, ["add", "-f", ".engineering-brain/note.txt"]);
    git(tracked, ["add", "-A"]);
    git(tracked, ["commit", "-q", "-m", "tracked store dir"]);
    const run = await runCli(tracked, ["uninstall", "--purge", "--yes"], home);
    expect(run.code).toBe(1);
    expect(run.stderr).toContain("STORE_TRACKED_BY_GIT");
    expect(existsSync(join(tracked, ".engineering-brain", "note.txt"))).toBe(true);
  });

  it.skipIf(process.platform === "win32")("refuses to delete (or use) a store directory that is a symlink, and never touches the target", async () => {
    const home = engbrainHome();
    const repo = makeGitRepo({ "a.ts": "export const a = 1;\n" });
    const outside = tempDir("engbrain-outside-");
    writeFileSync(join(outside, "precious.txt"), "do not delete");
    symlinkSync(outside, join(repo, ".engineering-brain"));
    for (const args of [["uninstall", "--purge", "--yes"], ["init"], ["index"], ["status"]]) {
      const run = await runCli(repo, args, home);
      expect(run.code, args.join(" ")).toBe(1);
      expect(run.stderr).toContain("STORE_UNSAFE_PATH");
    }
    expect(readFileSync(join(outside, "precious.txt"), "utf8")).toBe("do not delete");
    mkdirSync(join(outside, "x"), { recursive: true });
  });
});
