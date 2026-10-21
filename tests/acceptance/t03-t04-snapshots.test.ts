import { rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { indexRepository } from "@engbrain/core";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, dumpCurrent, engbrainHome, git, makeGitRepo, openFor, tempDir } from "../helpers/env.js";
import { generateRepoFiles } from "../helpers/fixtures.js";

afterAll(cleanupTempDirs);

async function idx(dir: string, home: string, init = false) {
  const o = await openFor(dir, home, init);
  try {
    const result = await indexRepository({ store: o.store, git: o.info, hardenedGit: o.git });
    return { result, dump: dumpCurrent(o.store), meta: o.store.meta, info: o.info };
  } finally {
    o.close();
  }
}

describe("T3 branch and worktree isolation (foundation part; freshness-on-switch is the next stage)", () => {
  it("keeps linked worktrees in separate stores with separate identities and manifests", async () => {
    const home = engbrainHome();
    const main = makeGitRepo(generateRepoFiles(5, 1));
    const wt = join(tempDir("engbrain-wt-"), "wt2");
    git(main, ["worktree", "add", "-q", "-b", "other", wt]);
    writeFileSync(join(wt, "only-in-other.ts"), "export const other = 1;\n");

    const a = await idx(main, home, true);
    const b = await idx(wt, home, true);
    expect(b.info.isLinkedWorktree).toBe(true);
    expect(a.info.isLinkedWorktree).toBe(false);
    expect(a.meta.worktreeId).not.toBe(b.meta.worktreeId);
    expect(a.meta.repositoryId).not.toBe(b.meta.repositoryId);
    expect(a.dump.manifest.map((m) => m[0])).not.toContain("only-in-other.ts");
    expect(b.dump.manifest.map((m) => m[0])).toContain("only-in-other.ts");
    expect(b.info.branchLabel).toBe("other");
    expect(a.info.branchLabel).toBe("main");
  });

  it("switching branches in place then re-indexing never mixes branch-only files", async () => {
    const home = engbrainHome();
    const repo = makeGitRepo(generateRepoFiles(4, 2));
    git(repo, ["checkout", "-q", "-b", "feature"]);
    writeFileSync(join(repo, "feature-only.ts"), "export const f = 1;\n");
    git(repo, ["add", "-A"]);
    git(repo, ["commit", "-q", "-m", "feature"]);
    const onFeature = await idx(repo, home, true);
    expect(onFeature.dump.manifest.map((m) => m[0])).toContain("feature-only.ts");

    git(repo, ["checkout", "-q", "main"]);
    const onMain = await idx(repo, home);
    expect(onMain.dump.manifest.map((m) => m[0])).not.toContain("feature-only.ts");
    expect(onMain.result.generationId).toBeGreaterThan(onFeature.result.generationId);
    expect(onMain.info.branchLabel).toBe("main");
    expect(onMain.dump.fingerprint).not.toBe(onFeature.dump.fingerprint);
  });
});

describe("T4 dirty working tree is represented", () => {
  it("clean, modified, untracked and deleted trees all yield distinct source fingerprints at the same revision", async () => {
    const home = engbrainHome();
    const repo = makeGitRepo(generateRepoFiles(6, 3));
    const clean = await idx(repo, home, true);

    writeFileSync(join(repo, "src", "m0", "file0.ts"), "export const dirty = 1;\n");
    const modified = await idx(repo, home);
    writeFileSync(join(repo, "untracked.ts"), "export const u = 1;\n");
    const untracked = await idx(repo, home);
    rmSync(join(repo, "src", "m1", "file1.ts"));
    const deleted = await idx(repo, home);

    const prints = [clean, modified, untracked, deleted].map((r) => r.dump.fingerprint);
    expect(new Set(prints).size).toBe(4);
    for (const r of [clean, modified, untracked, deleted]) {
      expect(r.result.revision).toBe(clean.result.revision);
    }
    expect(untracked.dump.manifest.map((m) => m[0])).toContain("untracked.ts");
    expect(deleted.dump.manifest.map((m) => m[0])).not.toContain("src/m1/file1.ts");
  });

  it("two checkouts at the same SHA with different uncommitted edits differ; identical edits match", async () => {
    const base = makeGitRepo(generateRepoFiles(4, 4));
    const cloneA = tempDir("engbrain-cloneA-");
    const cloneB = tempDir("engbrain-cloneB-");
    const cloneC = tempDir("engbrain-cloneC-");
    for (const c of [cloneA, cloneB, cloneC]) {
      git(c, ["clone", "-q", base, "."]);
    }
    writeFileSync(join(cloneA, "README.md"), "# edited by A\n");
    writeFileSync(join(cloneB, "README.md"), "# edited by B\n");
    writeFileSync(join(cloneC, "README.md"), "# edited by A\n");
    const [a, b, c] = [await idx(cloneA, engbrainHome(), true), await idx(cloneB, engbrainHome(), true), await idx(cloneC, engbrainHome(), true)];
    expect(a.result.revision).toBe(b.result.revision);
    expect(a.dump.fingerprint).not.toBe(b.dump.fingerprint);
    expect(a.dump.fingerprint).toBe(c.dump.fingerprint);
  });
});
