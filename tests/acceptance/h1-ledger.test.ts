import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { changesSince, collectGarbage, commitChanges, indexRepository, RefreshCancelled, refreshRepository, refreshStatus, type FaultPoint, type RefreshOptions } from "@engbrain/core";
import { installNetworkGuard } from "@engbrain/security";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, engbrainHome, git, makeGitRepo, openFor, runCli, tempDir, writeFiles } from "../helpers/env.js";
import { API_V1, buildDag, commitAll, sh } from "../helpers/dag-fixture.js";

afterAll(cleanupTempDirs);

type Opened = Awaited<ReturnType<typeof openFor>>;

async function withStore<T>(repo: string, home: string, fn: (o: Opened) => Promise<T> | T, init = false): Promise<T> {
  const o = await openFor(repo, home, init);
  try {
    return await fn(o);
  } finally {
    o.close();
  }
}

async function refresh(repo: string, home: string, extra: Partial<RefreshOptions> = {}, init = false) {
  return withStore(repo, home, (o) => refreshRepository({ store: o.store, git: o.info, hardenedGit: o.git, ...extra }), init);
}

describe("H1 commit ledger", () => {
  it("H1-1 records every commit once, with correct parents, per-parent changes and renames", async () => {
    const dag = buildDag();
    const home = engbrainHome();
    const result = await refresh(dag.repo, home, { history: "backfill" }, true);
    expect(result.lineage).toBe("baseline");
    expect(result.historyPartial).toBe(false);
    await withStore(dag.repo, home, (o) => {
      const db = o.store.db;
      const commits = db.prepare("SELECT commit_oid AS oid FROM git_commits").all() as Array<{ oid: string }>;
      expect(commits.map((c) => c.oid).sort()).toEqual(Object.values(dag.c).sort());
      const gitParents = new Map(sh(dag.repo, ["rev-list", "--parents", "--all"]).split("\n").map((l) => { const [oid, ...ps] = l.split(" "); return [oid!, ps]; }));
      for (const { oid } of commits) {
        const parents = (db.prepare("SELECT parent_oid AS p FROM commit_parents WHERE commit_oid = ? ORDER BY ordinal").all(oid) as Array<{ p: string }>).map((r) => r.p);
        expect(parents).toEqual(gitParents.get(oid));
      }
      // the root records every file as added against the empty tree
      const root = commitChanges(db, dag.c["A"]!)!;
      expect(root.changesByParent[0]!.parentOrdinal).toBe(-1);
      expect(root.changesByParent[0]!.changes.map((c) => c.kind)).toEqual(["added", "added", "added"]);
      // the merge has one change list PER parent
      const merge = commitChanges(db, dag.c["M"]!)!;
      expect(merge.parents).toEqual([dag.c["D"], dag.c["E"]]);
      expect(merge.changesByParent.map((g) => g.parentOrdinal)).toEqual([0, 1]);
      expect(merge.changesByParent[0]!.changes.map((c) => c.path)).toEqual(["src/extra.ts"]); // relative to the main-line parent: E's file arrives
      // D: file rename with a score, and the renamed function as a CANDIDATE only
      const d = commitChanges(db, dag.c["D"]!)!;
      const renamed = d.changesByParent[0]!.changes.find((c) => c.kind === "renamed")!;
      expect(renamed).toMatchObject({ oldPath: "src/util.ts", path: "src/helpers.ts" });
      expect(renamed.renameScore).toBeGreaterThan(50);
      const added = d.symbolDeltas.find((x) => x.delta === "added" && x.qualifiedName === "fetchUser")!;
      expect(added.candidateRenameOf).toBe("getUser");
      // no duplicate facts per (hash, extractor)
      const dup = db.prepare("SELECT COUNT(*) AS n FROM (SELECT content_hash, extractor_id, extractor_version FROM file_facts GROUP BY 1,2,3 HAVING COUNT(*) > 1)").get() as { n: number };
      expect(dup.n).toBe(0);
    });
  }, 120_000);
});

/** The ledger as comparable data: everything that identifies WHAT was recorded, nothing about when, how, or in which run. */
function ledgerProjection(o: Opened): unknown {
  const db = o.store.db;
  return {
    commits: db.prepare("SELECT commit_oid, tree_oid, availability, subject, changes_truncated FROM git_commits WHERE ingest_complete = 1 ORDER BY commit_oid").all(),
    parents: db.prepare("SELECT commit_oid, ordinal, parent_oid FROM commit_parents ORDER BY commit_oid, ordinal").all(),
    changes: db.prepare("SELECT commit_oid, parent_ordinal, path, old_path, change_kind, old_blob, new_blob, old_content_hash, new_content_hash, rename_score, excluded_reason FROM commit_changes ORDER BY commit_oid, parent_ordinal, path").all(),
    deltas: db.prepare("SELECT * FROM commit_symbol_deltas ORDER BY commit_oid, parent_ordinal, path, delta, kind, qualified_name, ordinal").all()
  };
}

const checkpointOf = (o: Opened): unknown => o.store.db.prepare("SELECT processed_oid, generation_id, history_partial FROM history_checkpoints").get();
const currentGeneration = (o: Opened): unknown => o.store.db.prepare("SELECT current_generation_id AS g FROM store_meta").get();

describe("H1 lineage, gaps and reuse", () => {
  it("repeated refresh is a no-op that matches the prior facts", async () => {
    const dag = buildDag();
    const home = engbrainHome();
    const first = await refresh(dag.repo, home, { history: "backfill" }, true);
    const before = await withStore(dag.repo, home, (o) => ({ ledger: ledgerProjection(o), cp: checkpointOf(o), gen: currentGeneration(o) }));
    const second = await refresh(dag.repo, home, { history: "backfill" });
    expect(second.ingest.commitsIngested).toBe(0);
    expect(second.ingest.blobsRead).toBe(0);
    expect(second.ingest.extractorRuns).toBe(0);
    expect(second.index.unchanged).toBe(true);
    expect(second.lineage).toBe("advance");
    const after = await withStore(dag.repo, home, (o) => ({ ledger: ledgerProjection(o), cp: checkpointOf(o), gen: currentGeneration(o) }));
    expect(after).toEqual(before);
    expect(first.ingest.commitsIngested).toBe(6);
  }, 120_000);

  it("H1-2 rebase / force-push: lineage `rewrite` with the correct fork, orphans excluded, identical blobs not re-extracted", async () => {
    const dag = buildDag();
    const home = engbrainHome();
    await refresh(dag.repo, home, { history: "backfill" }, true);
    // rewrite history: drop C, D and the merge, then re-apply C's change as a NEW commit (same blobs, different commit id)
    git(dag.repo, ["reset", "-q", "--hard", dag.c["B"]!]);
    git(dag.repo, ["cherry-pick", dag.c["C"]!]);
    const rewritten = sh(dag.repo, ["rev-parse", "HEAD"]);
    expect(rewritten).not.toBe(dag.c["C"]);
    const result = await refresh(dag.repo, home);
    expect(result.lineage).toBe("rewrite");
    expect(result.forkOid).toBe(dag.c["B"]);
    expect(result.ingest.commitsIngested).toBe(1);
    expect(result.ingest.blobsRead).toBe(0); // the cherry-picked blobs are already known
    expect(result.ingest.extractorRuns).toBe(0);
    await withStore(dag.repo, home, (o) => {
      const status = refreshStatus(o.store.db);
      expect(status.checkpoint?.processedOid).toBe(rewritten);
      expect(status.commitsInLedger).toBe(7);
      expect(status.orphaned).toBe(4); // C, D, E, M stay as evidence but are no longer reachable
      const orphan = changesSince(o.store.db, { since: dag.c["M"]! });
      expect(orphan.relation).toBe("rewritten");
      expect(orphan.commits.map((c) => c.oid)).toEqual([rewritten]);
      const normal = changesSince(o.store.db, { since: dag.c["B"]! });
      expect(normal.relation).toBe("ancestor");
      expect(normal.commits.map((c) => c.oid)).toEqual([rewritten]);
      expect(changesSince(o.store.db, { since: dag.c["C"]! }).commits.map((c) => c.oid)).toEqual([rewritten]); // C is orphaned: nothing of the old line is returned
      expect(normal.lineage[0]!.kind).toBe("rewrite");
    });
  }, 120_000);

  it("H1-3 shallow clone: partial history, boundary commits with unknown ancestors, nothing invented; a missing checkpoint is `base_missing`", async () => {
    const dag = buildDag();
    const clone = tempDir("engbrain-shallow-");
    execFileSync("git", ["clone", "-q", "--depth", "1", `file://${dag.repo}`, join(clone, "r")], { env: { PATH: process.env["PATH"] ?? "", HOME: clone } });
    const repo = join(clone, "r");
    const home = engbrainHome();
    const result = await refresh(repo, home, { history: "backfill" }, true);
    expect(result.historyPartial).toBe(true);
    await withStore(repo, home, (o) => {
      const rows = o.store.db.prepare("SELECT commit_oid, availability FROM git_commits").all() as Array<{ commit_oid: string; availability: string }>;
      expect(rows).toEqual([{ commit_oid: dag.c["M"], availability: "shallow_boundary" }]);
      const noChanges = o.store.db.prepare("SELECT COUNT(*) AS n FROM commit_changes").get() as { n: number };
      expect(noChanges.n).toBe(0); // the boundary commit's changes are UNKNOWN, not "everything was added"
      const parents = (o.store.db.prepare("SELECT parent_oid FROM commit_parents ORDER BY ordinal").all() as Array<{ parent_oid: string }>).map((r) => r.parent_oid);
      expect(parents).toEqual([dag.c["D"], dag.c["E"]]); // explicit unknown ancestors: recorded ids with no commit rows
      const known = o.store.db.prepare("SELECT COUNT(*) AS n FROM git_commits").get() as { n: number };
      expect(known.n).toBe(1);
    });
    // a checkpoint whose object is gone
    const home2 = engbrainHome();
    await refresh(dag.repo, home2, {}, true);
    await withStore(dag.repo, home2, (o) => void o.store.db.prepare("UPDATE history_checkpoints SET processed_oid = ?").run("1".repeat(40)));
    const missing = await refresh(dag.repo, home2);
    expect(missing.lineage).toBe("base_missing");
    expect(missing.historyPartial).toBe(true);
  }, 120_000);

  it("H1-4 blob reuse: an unchanged blob + extractor version is neither read nor re-extracted across commits and branches", async () => {
    const dag = buildDag();
    const home = engbrainHome();
    const first = await refresh(dag.repo, home, { history: "backfill" }, true);
    const distinct = await withStore(dag.repo, home, (o) => (o.store.db.prepare(
      "SELECT COUNT(DISTINCT blob) AS n FROM (SELECT new_blob AS blob FROM commit_changes WHERE new_content_hash IS NOT NULL UNION SELECT old_blob FROM commit_changes WHERE old_content_hash IS NOT NULL)"
    ).get() as { n: number }).n);
    expect(first.ingest.blobsRead).toBe(distinct); // every distinct blob exactly once
    // a new branch that adds a file with content already known, and a new commit touching nothing new
    git(dag.repo, ["checkout", "-q", "-b", "other", dag.c["A"]!]);
    writeFiles(dag.repo, { "src/copy-of-util.ts": "export const util = 1;\n" });
    commitAll(dag.repo, "same bytes as util.ts");
    const second = await refresh(dag.repo, home);
    expect(second.lineage).toBe("switch"); // HEAD moved to a commit that is not a descendant of the checkpoint, on another branch
    expect(second.ingest.commitsIngested).toBe(1);
    expect(second.ingest.blobsRead).toBe(0); // identical bytes: the blob oid is already known
    expect(second.ingest.extractorRuns).toBe(0);
  }, 120_000);
});
