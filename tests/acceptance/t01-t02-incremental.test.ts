import { readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { indexRepository } from "@engbrain/core";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, dumpCurrent, engbrainHome, makeGitRepo, openFor, tempDir, writeFiles } from "../helpers/env.js";
import { generateRepoFiles, mulberry32 } from "../helpers/fixtures.js";

afterAll(cleanupTempDirs);

function readTree(root: string): Map<string, string> {
  const files = new Map<string, string>();
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === ".git" || entry.name === ".engineering-brain") {
        continue;
      }
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else {
        files.set(relative(root, full).split("\\").join("/"), readFileSync(full, "utf8"));
      }
    }
  };
  walk(root);
  return files;
}

async function indexOnce(dir: string, home: string, init: boolean) {
  const opened = await openFor(dir, home, init);
  try {
    const result = await indexRepository({ store: opened.store, git: opened.info, hardenedGit: opened.git });
    return { result, dump: dumpCurrent(opened.store) };
  } finally {
    opened.close();
  }
}

describe("T1 initial and incremental indexing are equivalent", () => {
  it.each(Array.from({ length: 20 }, (_, i) => i + 1))("seed %i", async (seed) => {
    const home = engbrainHome();
    const files = generateRepoFiles(30, seed);
    const repo = makeGitRepo(files);
    const before = await indexOnce(repo, home, true);

    // mutate: edit 3, add 2, delete 2, rename 1 (deterministic per seed)
    const random = mulberry32(seed * 7919);
    const paths = [...files.keys()].filter((p) => p.endsWith(".ts"));
    const pick = (): string => paths.splice(Math.floor(random() * paths.length), 1)[0]!;
    for (let i = 0; i < 3; i += 1) {
      const path = pick();
      writeFileSync(join(repo, ...path.split("/")), `${files.get(path)!}// edit ${seed}-${i}\n`);
    }
    writeFiles(repo, { [`src/new/added${seed}a.ts`]: `export const a = ${seed};\n`, [`src/new/added${seed}b.ts`]: "export const b = 2;\n" });
    for (let i = 0; i < 2; i += 1) {
      rmSync(join(repo, ...pick().split("/")));
    }
    const renamed = pick();
    renameSync(join(repo, ...renamed.split("/")), join(repo, "src", `renamed-${seed}.ts`));

    const incremental = await indexOnce(repo, home, false);
    // guard against a vacuous pass: the mutation really changed the index, and only the delta was extracted
    expect(incremental.dump.fingerprint).not.toBe(before.dump.fingerprint);
    expect(incremental.result.stats.extractorRuns).toBeLessThanOrEqual(6);

    // Independent index of the same mutated tree into an empty store (non-git walk path, different history)
    const copy = tempDir("engbrain-copy-");
    writeFiles(copy, readTree(repo));
    const fresh = await indexOnce(copy, engbrainHome(), true);

    expect(incremental.dump.manifest).toEqual(fresh.dump.manifest);
    expect(incremental.dump.facts).toEqual(fresh.dump.facts);
    expect(incremental.dump.fingerprint).toBe(fresh.dump.fingerprint);
  });
});

describe("T2 unchanged files are not reprocessed", () => {
  it("runs the extractor 0 times when nothing changed, and exactly once per changed file", async () => {
    const home = engbrainHome();
    const files = generateRepoFiles(40, 5);
    const repo = makeGitRepo(files);
    const first = await indexOnce(repo, home, true);
    expect(first.result.stats.extractorRuns).toBe(41); // 40 sources + README (all unique contents)
    expect(first.result.unchanged).toBe(false);

    const second = await indexOnce(repo, home, false);
    expect(second.result.unchanged).toBe(true);
    expect(second.result.stats.extractorRuns).toBe(0);
    expect(second.result.generationId).toBe(first.result.generationId);

    writeFileSync(join(repo, "src", "m0", "file0.ts"), "export const changed = true;\n");
    const third = await indexOnce(repo, home, false);
    expect(third.result.unchanged).toBe(false);
    expect(third.result.stats.extractorRuns).toBe(1);
    expect(third.result.stats.factsReused).toBe(40);
    expect(third.result.generationId).toBeGreaterThan(first.result.generationId);
  });

  it("reuses facts for identical content at different paths", async () => {
    const repo = makeGitRepo({ "a.ts": "export const same = 1;\n", "b.ts": "export const same = 1;\n" });
    const { result } = await indexOnce(repo, engbrainHome(), true);
    expect(result.stats.included).toBe(2);
    expect(result.stats.extractorRuns).toBe(1);
    expect(result.stats.factsReused).toBe(1);
  });
});
