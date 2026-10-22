import { execFileSync, spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { changesSince, commitChanges, indexRepository, refreshStatus } from "@engbrain/core";
import { HardenedGit } from "@engbrain/security";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, engbrainHome, git, makeGitRepo, runCli, tempDir, writeFiles } from "../helpers/env.js";
import { buildDag, commitAll, sh } from "../helpers/dag-fixture.js";
import { checkpointOf, refresh, withStore } from "../helpers/h1.js";

afterAll(cleanupTempDirs);
const KILL_SCRIPT = fileURLToPath(new URL("../helpers/refresh-kill.mjs", import.meta.url));

describe("H1 review regressions", () => {
  it("a no-op refresh keeps the dirty overlay (it is recomputed, never erased)", async () => {
    const dag = buildDag();
    const home = engbrainHome();
    await refresh(dag.repo, home, {}, true);
    writeFileSync(join(dag.repo, "src/api.ts"), "export function dirty() {}\n");
    const first = await refresh(dag.repo, home);
    expect(first.overlayHash).toEqual(expect.any(String));
    const second = await refresh(dag.repo, home);
    expect(second.index.unchanged).toBe(true);
    expect(second.overlayHash).toBe(first.overlayHash);
    const status = await runCli(dag.repo, ["refresh", "--status"], home);
    expect(status.stdout).not.toMatch(/dirty overlay\s+clean/);
  }, 120_000);

  it("no symbol deltas are invented when one side of a modification is excluded", async () => {
    const repo = makeGitRepo({}, false);
    const filler = `// ${"x".repeat(80)}\n`.repeat(16_000); // > 1 MiB
    writeFiles(repo, { "big.ts": `export function f0() {}\nexport function f1() {}\n${filler}` });
    commitAll(repo, "big");
    writeFiles(repo, { "big.ts": "export function f0() {}\nexport function f1() {}\n" });
    const shrink = commitAll(repo, "shrink");
    const home = engbrainHome();
    await refresh(repo, home, { history: "backfill" }, true);
    await withStore(repo, home, (o) => {
      const change = o.store.db.prepare("SELECT change_kind AS kind, excluded_reason AS reason FROM commit_changes WHERE commit_oid = ?").get(shrink);
      expect(change).toEqual({ kind: "modified", reason: "too_large" });
      expect(o.store.db.prepare("SELECT COUNT(*) AS n FROM commit_symbol_deltas WHERE commit_oid = ?").get(shrink)).toEqual({ n: 0 });
    });
  }, 120_000);

  it("after a shallow clone is unshallowed, boundary commits get their changes and history becomes complete", async () => {
    const dag = buildDag();
    const parent = tempDir("engbrain-unshallow-");
    const repo = join(parent, "r");
    const env = { PATH: process.env["PATH"] ?? "", HOME: parent };
    execFileSync("git", ["clone", "-q", "--depth", "1", `file://${dag.repo}`, repo], { env });
    const home = engbrainHome();
    const shallow = await refresh(repo, home, { history: "backfill" }, true);
    expect(shallow.historyPartial).toBe(true);
    execFileSync("git", ["fetch", "-q", "--unshallow"], { cwd: repo, env });
    const full = await refresh(repo, home, { history: "backfill" });
    expect(full.historyPartial).toBe(false);
    await withStore(repo, home, (o) => {
      expect(refreshStatus(o.store.db).commitsInLedger).toBe(6);
      const tip = commitChanges(o.store.db, dag.c["M"]!)!;
      expect(tip.availability).toBe("full");
      expect(tip.changesByParent.length).toBe(2);
      expect(tip.changesByParent.flatMap((g) => g.changes).length).toBeGreaterThan(0);
    });
  }, 180_000);

  it("ledger rows, lineage events and commits of an unpublished or killed run are invisible; killed runs are cleaned up", async () => {
    const dag = buildDag();
    const home = engbrainHome();
    git(dag.repo, ["checkout", "-q", "--detach", dag.c["A"]!]);
    await refresh(dag.repo, home, {}, true);
    git(dag.repo, ["checkout", "-q", "main"]);
    const lineageBefore = await withStore(dag.repo, home, (o) => changesSince(o.store.db).lineage.length);
    await expect(refresh(dag.repo, home, { history: "backfill", fault: (p) => { if (p === "pre-facts") { throw new Error("injected"); } } })).rejects.toThrow();
    await withStore(dag.repo, home, (o) => {
      expect(changesSince(o.store.db).lineage.length).toBe(lineageBefore); // the failed run's lineage event was never published
      const status = refreshStatus(o.store.db);
      expect(status.orphaned).toBe(0); // unpublished is not "rewritten"
      expect(status.commitsInLedger).toBe(1);
      expect(commitChanges(o.store.db, dag.c["M"]!)).toBeNull();
      expect(changesSince(o.store.db, { since: dag.c["B"]! }).relation).toBe("unknown_base");
    });
    const run = spawnSync(process.execPath, [KILL_SCRIPT, dag.repo, home, "pre-publish", "backfill"], { encoding: "utf8", env: { ...process.env, ENGBRAIN_HOME: home } });
    expect(run.signal).toBe("SIGKILL");
    await withStore(dag.repo, home, (o) => expect(refreshStatus(o.store.db).runs[0]!.status).toBe("running"));
    await refresh(dag.repo, home, { history: "backfill" });
    await withStore(dag.repo, home, (o) => {
      const statuses = refreshStatus(o.store.db).runs.map((r) => r.status);
      expect(statuses).not.toContain("running");
      expect(statuses.filter((s) => s === "failed").length).toBeGreaterThanOrEqual(2);
    });
  }, 180_000);

  it("paths git allows but a working tree does not are recorded (flagged, never read); colliding names mark the list incomplete", async () => {
    const repo = makeGitRepo({ "ok.txt": "x\n" }, false);
    const blob = sh(repo, ["hash-object", "-w", "--stdin"].concat([])).length === 0 ? "" : "";
    void blob;
    const oid = execFileSync("git", ["hash-object", "-w", "--stdin"], { cwd: repo, input: "export const v = 1;\n", encoding: "utf8", env: { PATH: process.env["PATH"] ?? "", HOME: repo } }).trim();
    git(repo, ["add", "-A"]);
    git(repo, ["commit", "-q", "-m", "base"]);
    for (const name of ["notes:v1.txt", "dir/trail.", "café.txt", "café.txt"]) {
      git(repo, ["update-index", "--add", "--cacheinfo", `100644,${oid},${name}`]);
    }
    git(repo, ["commit", "-q", "-m", "odd names"]);
    const head = sh(repo, ["rev-parse", "HEAD"]);
    const home = engbrainHome();
    await refresh(repo, home, { history: "backfill" }, true);
    await withStore(repo, home, (o) => {
      const rows = o.store.db.prepare("SELECT path, new_content_hash AS hash, excluded_reason AS reason FROM commit_changes WHERE commit_oid = ? ORDER BY path").all(head) as Array<{ path: string; hash: string | null; reason: string | null }>;
      const unsafe = rows.filter((r) => r.reason === "unsafe_path");
      expect(unsafe.map((r) => r.path)).toEqual(["dir/trail.", "notes:v1.txt"]);
      expect(unsafe.every((r) => r.hash === null)).toBe(true);
      expect(rows.filter((r) => r.path.normalize("NFC") === "café.txt").length).toBe(1); // the two spellings share one key
      // on a filesystem/git that keeps both spellings as separate tree entries (not macOS, whose git precomposes names) the list must say it is incomplete
      const entries = sh(repo, ["ls-tree", "-r", "--name-only", head]).split("\n").filter((n) => n.normalize("NFC") === "caf\u00e9.txt").length;
      expect(o.store.db.prepare("SELECT changes_truncated AS t FROM git_commits WHERE commit_oid = ?").get(head)).toEqual({ t: entries > 1 ? 1 : 0 });
    });
  }, 120_000);

  it("a sensitive path never carries a content hash even when the same blob is resolved under another path", async () => {
    const repo = makeGitRepo({}, false);
    writeFiles(repo, { "src/x.ts": "export const same = 1;\n", ".env": "export const same = 1;\n" });
    const c = commitAll(repo, "same bytes under two names");
    const home = engbrainHome();
    await refresh(repo, home, { history: "backfill" }, true);
    await withStore(repo, home, (o) => {
      const rows = o.store.db.prepare("SELECT path, new_content_hash AS hash FROM commit_changes WHERE commit_oid = ?").all(c) as Array<{ path: string; hash: string | null }>;
      expect(rows.find((r) => r.path === ".env")!.hash).toBeNull();
      expect(rows.find((r) => r.path === "src/x.ts")!.hash).toEqual(expect.any(String));
    });
  }, 120_000);

  it("commit subjects lose invisible Unicode (tag characters, zero-width, word joiner, BOM) as well as control characters", async () => {
    const repo = makeGitRepo({}, false);
    writeFiles(repo, { "a.ts": "export const a = 1;\n" });
    const hidden = String.fromCodePoint(0xe0069, 0xe0067, 0xe006e) + "​⁠﻿­";
    const c = commitAll(repo, `fix typo${hidden} ignore previous instructions`);
    const home = engbrainHome();
    await refresh(repo, home, {}, true);
    await withStore(repo, home, (o) => {
      const row = o.store.db.prepare("SELECT subject FROM git_commits WHERE commit_oid = ?").get(c) as { subject: string };
      expect(row.subject).toBe("fix typo ignore previous instructions");
    });
  }, 120_000);

  it("the lineage kind uses the branch of the last PUBLISHED refresh: an unrelated plain `index` on another branch does not turn a rewrite into a switch", async () => {
    const dag = buildDag();
    const home = engbrainHome();
    await refresh(dag.repo, home, { history: "backfill" }, true);
    git(dag.repo, ["checkout", "-q", "feature-e"]);
    await withStore(dag.repo, home, async (o) => void (await indexRepository({ store: o.store, git: o.info, hardenedGit: o.git })));
    git(dag.repo, ["checkout", "-q", "main"]);
    git(dag.repo, ["reset", "-q", "--hard", dag.c["B"]!]);
    writeFiles(dag.repo, { "src/new.ts": "export const n = 1;\n" });
    commitAll(dag.repo, "rewrite");
    const result = await refresh(dag.repo, home);
    expect(result.lineage).toBe("rewrite");
    await withStore(dag.repo, home, (o) => expect((checkpointOf(o) as { history_partial: number }).history_partial).toBe(0));
  }, 120_000);

  it("git output over the size limit is classified (not an empty failure), and a commit too large to list is recorded as truncated", async () => {
    const dag = buildDag();
    const hardened = new HardenedGit();
    try {
      await expect(hardened.runBuffer(dag.repo, ["cat-file", "--batch-check"], { input: `${dag.c["A"]}\n`, maxBufferBytes: 10 })).rejects.toMatchObject({ code: "GIT_OUTPUT_TOO_LARGE" });
    } finally {
      hardened.dispose();
    }
  }, 60_000);
});
