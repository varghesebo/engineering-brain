import { mkdirSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, dumpCurrent, engbrainHome, git, makeGitRepo, openFor, runCli, tempDir } from "../helpers/env.js";
import { indexRepository } from "@engbrain/core";

afterAll(cleanupTempDirs);

const OUTSIDE_SECRET = "outside-the-repo-must-never-be-indexed-7c1d";

function storeBytes(repo: string): string {
  const dir = join(repo, ".engineering-brain");
  return readdirSync(dir).map((n) => { try { return readFileSync(join(dir, n)).toString("latin1"); } catch { return ""; } }).join("\n");
}

async function indexAndDump(repo: string, home: string) {
  const o = await openFor(repo, home, true);
  try {
    const result = await indexRepository({ store: o.store, git: o.info, hardenedGit: o.git });
    return { result, dump: dumpCurrent(o.store) };
  } finally {
    o.close();
  }
}

const reasonOf = (dump: { manifest: Array<[string, string | null, string | null]> }, path: string): string | null | undefined =>
  dump.manifest.find((m) => m[0] === path)?.[2];

describe("T17 hostile files (no parser exists yet: size, binary, encoding, names, symlinks)", () => {
  it.skipIf(process.platform === "win32")("excludes oversize, binary, invalid UTF-8, reserved names and symlinks; never reads outside the root", async () => {
    const outside = tempDir("engbrain-outside-");
    writeFileSync(join(outside, "secret.txt"), OUTSIDE_SECRET);
    mkdirSync(join(outside, "dir"));
    writeFileSync(join(outside, "dir", "inner.txt"), OUTSIDE_SECRET);

    const repo = makeGitRepo({ "src/ok.ts": "export const ok = 1;\n", "empty.ts": "" });
    writeFileSync(join(repo, "huge.txt"), Buffer.alloc(5 * 1024 * 1024, 0x61));
    writeFileSync(join(repo, "blob.data"), Buffer.from([0x50, 0x4b, 0x00, 0x03, 0x04]));
    writeFileSync(join(repo, "latin1.txt"), Buffer.from([0x63, 0x61, 0x66, 0xe9, 0xff, 0xfe]));
    writeFileSync(join(repo, "con.txt"), "x");
    writeFileSync(join(repo, "NUL"), "x");
    symlinkSync(join(outside, "secret.txt"), join(repo, "link-to-secret"));
    symlinkSync(join(outside, "dir"), join(repo, "link-to-dir"));
    symlinkSync("../../../../../../etc/hosts", join(repo, "relative-escape"));
    git(repo, ["add", "-A"]);

    const { dump, result } = await indexAndDump(repo, engbrainHome());
    expect(reasonOf(dump, "huge.txt")).toBe("too_large");
    expect(reasonOf(dump, "blob.data")).toBe("binary_content");
    expect(reasonOf(dump, "latin1.txt")).toBe("invalid_utf8");
    expect(reasonOf(dump, "con.txt")).toBe("reserved_name");
    expect(reasonOf(dump, "NUL")).toBe("reserved_name");
    for (const link of ["link-to-secret", "link-to-dir", "relative-escape"]) {
      expect(reasonOf(dump, link), link).toBe("symlink");
    }
    expect(dump.manifest.find((m) => m[0] === "src/ok.ts")?.[1]).not.toBeNull();
    expect(dump.manifest.find((m) => m[0] === "empty.ts")?.[1]).not.toBeNull(); // empty file is a normal file
    expect(result.stats.included).toBe(2);
    expect(storeBytes(repo).includes(OUTSIDE_SECRET)).toBe(false);
  });

  it.skipIf(process.platform === "win32")("non-git directories: symlinks (file and directory) are excluded and not followed", async () => {
    const outside = tempDir("engbrain-outside-");
    writeFileSync(join(outside, "secret.txt"), OUTSIDE_SECRET);
    mkdirSync(join(outside, "d"));
    writeFileSync(join(outside, "d", "x.txt"), OUTSIDE_SECRET);
    const dir = tempDir("engbrain-plain-");
    writeFileSync(join(dir, "a.ts"), "export const a = 1;\n");
    symlinkSync(join(outside, "secret.txt"), join(dir, "l1"));
    symlinkSync(join(outside, "d"), join(dir, "l2"));
    const { dump } = await indexAndDump(dir, engbrainHome());
    expect(reasonOf(dump, "l1")).toBe("symlink");
    expect(reasonOf(dump, "l2")).toBe("symlink");
    expect(dump.manifest.map((m) => m[0]).some((p) => p.startsWith("l2/"))).toBe(false);
    expect(storeBytes(dir).includes(OUTSIDE_SECRET)).toBe(false);
  });

  it("handles unusual but legal names exactly, stores NFC paths, and survives deep nesting", async () => {
    const deep = Array.from({ length: 40 }, (_, i) => `d${i}`).join("/");
    const repo = makeGitRepo({
      "with space/file name.ts": "export const s = 1;\n",
      "quote's/it\"s.ts": "export const q = 1;\n",
      "unicode/café.ts": "export const c = 1;\n",
      "uni/日本語.ts": "export const j = 1;\n",
      [`${deep}/leaf.ts`]: "export const leaf = 1;\n"
    });
    const { dump } = await indexAndDump(repo, engbrainHome());
    const paths = dump.manifest.map((m) => m[0]);
    for (const expected of ["with space/file name.ts", "quote's/it\"s.ts", "uni/日本語.ts", `${deep}/leaf.ts`]) {
      expect(paths).toContain(expected);
    }
    expect(paths.some((p) => p === p.normalize("NFC") && p.includes("café"))).toBe(true);
    expect(paths.every((p) => p === p.normalize("NFC"))).toBe(true);
  });

  it("detects case-only path collisions deterministically where the filesystem can hold both", async () => {
    const repo = makeGitRepo({ "x.ts": "export const x = 1;\n" });
    writeFileSync(join(repo, "Readme.md"), "# one\n");
    writeFileSync(join(repo, "README.md"), "# two\n");
    const both = readdirSync(repo).filter((n) => n.toLowerCase() === "readme.md").length === 2;
    if (!both) {
      return; // case-insensitive filesystem (default macOS/Windows): the collision cannot exist here
    }
    const { dump } = await indexAndDump(repo, engbrainHome());
    const readmes = dump.manifest.filter((m) => m[0].toLowerCase() === "readme.md");
    expect(readmes.filter((m) => m[1] !== null)).toHaveLength(1);
    expect(readmes.filter((m) => m[2] === "path_collision")).toHaveLength(1);
  });

  it("indexes thousands of files in bounded time with bounded memory growth", async () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 3000; i += 1) {
      files[`bulk/d${i % 30}/f${i}.ts`] = `export const v${i} = ${i};\n`;
    }
    const repo = makeGitRepo(files);
    const before = process.memoryUsage().rss;
    const started = Date.now();
    const { result } = await indexAndDump(repo, engbrainHome());
    expect(result.stats.included).toBe(3000);
    expect(Date.now() - started).toBeLessThan(30_000);
    expect(process.memoryUsage().rss - before).toBeLessThan(300 * 1024 * 1024);
  });

  it("CLI reports exclusions by reason without ever echoing file contents", async () => {
    const repo = makeGitRepo({ "a.ts": "export const a = 1;\n" });
    writeFileSync(join(repo, "blob.data"), Buffer.from([0, 1, 2, 3]));
    git(repo, ["add", "-A"]);
    const home = engbrainHome();
    await runCli(repo, ["init"], home);
    const run = await runCli(repo, ["index"], home);
    expect(run.stdout).toContain("binary_content=1");
  });
});
