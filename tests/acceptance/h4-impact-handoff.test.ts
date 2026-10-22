import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { addVerifier, analyzeImpact, closeHandoff, createHandoff, listHandoffs, selectionRecall, selectTests, showHandoff, type Actor } from "@engbrain/core";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, engbrainHome, makeGitRepo } from "../helpers/env.js";
import { commitAll } from "../helpers/dag-fixture.js";
import { refresh, withStore } from "../helpers/h1.js";

afterAll(cleanupTempDirs);

const A: Actor = { id: "alice", roles: ["propose", "approve", "verify", "admin"] };
const B: Actor = { id: "bob", roles: ["propose"] };

async function world(): Promise<{ repo: string; home: string; c1: string }> {
  const repo = makeGitRepo({}, false);
  const home = engbrainHome();
  writeFileSync(join(repo, "package.json"), JSON.stringify({ name: "w" }));
  mkdirSync(join(repo, "src"), { recursive: true });
  mkdirSync(join(repo, "tests"), { recursive: true });
  const put = (p: string, s: string): void => writeFileSync(join(repo, p), s);
  put("src/a.ts", "export const a = 1;\n");
  put("src/b.ts", "import { a } from \"./a\";\nexport const b = a + 1;\n");
  put("src/c.ts", "import { b } from \"./b\";\nexport const c = b + 1;\n");
  put("src/orphan.ts", "export const orphan = 1;\n");
  put("src/lazy.ts", "export async function lazy(name: string) { return import(name); }\n");
  put("tests/a.test.ts", "import { a } from \"../src/a\";\nit(\"a\", () => { a; });\n");
  put("tests/c.test.ts", "import { c } from \"../src/c\";\nit(\"c\", () => { c; });\n");
  put("tests/lazy.test.ts", "import { lazy } from \"../src/lazy\";\nit(\"loads a at runtime\", async () => { await lazy(\"../src/a\"); });\n");
  const c1 = commitAll(repo, "init");
  await refresh(repo, home, { history: "backfill" }, true);
  return { repo, home, c1 };
}

describe("H4 impact classification", () => {
  it("separates direct-proven, transitive and unknown; never says an unreferenced file is safe", async () => {
    const w = await world();
    await withStore(w.repo, w.home, (o) => {
      const r = analyzeImpact(o.store.db, { files: ["src/a.ts"] });
      const by = (p: string) => r.impacted.find((i) => i.path === p);
      expect(by("src/b.ts")?.class).toBe("direct_proven");
      expect(by("src/c.ts")?.class).toBe("transitive");
      expect(by("tests/a.test.ts")?.class).toBe("direct_proven");
      expect(r.boundary.dynamicImports).toBeGreaterThan(0);
      expect(r.missedEdgeRisk.level).not.toBe("low");
      const unknown = analyzeImpact(o.store.db, { files: ["src/deleted.ts", "src/orphan.ts"] });
      expect(unknown.unknownInputs.map((u) => u.path)).toEqual(["src/deleted.ts"]);
      expect(unknown.missedEdgeRisk.level).toBe("high");
      expect(unknown.impacted).toEqual([]); // empty is "no recorded edge", and the output says so
      expect(unknown.disclaimer).toMatch(/not evidence of independence/);
    });
  });
  it("derives inputs from history since a base", async () => {
    const w = await world();
    writeFileSync(join(w.repo, "src/a.ts"), "export const a = 2;\n");
    commitAll(w.repo, "change a");
    await refresh(w.repo, w.home, { history: "backfill" });
    await withStore(w.repo, w.home, (o) => {
      const r = analyzeImpact(o.store.db, { since: w.c1 });
      expect(r.inputs).toEqual(["src/a.ts"]);
      expect(r.basis.relation).toBe("ancestor");
      const bad = analyzeImpact(o.store.db, { since: "f".repeat(40) });
      expect(bad.unknownInputs.length).toBeGreaterThan(0);
      expect(bad.missedEdgeRisk.level).toBe("high");
    });
  });
});

describe("H4 advisory test selection", () => {
  it("selects with proof classes, reports unmapped areas and the seeded dynamic dependency as uncertainty; the baseline sample finds it", async () => {
    const w = await world();
    await withStore(w.repo, w.home, (o) => {
      const sel = selectTests(o.store.db, { files: ["src/a.ts"], sample: 10 });
      const proof = (p: string) => sel.selected.find((s) => s.path === p)?.proof;
      expect(proof("tests/a.test.ts")).toBe("imports_changed_file");
      expect(proof("tests/c.test.ts")).toBe("imports_through_chain");
      expect(sel.selected.map((s) => s.path)).not.toContain("tests/lazy.test.ts"); // the seeded runtime dependency is invisible to static edges...
      expect(sel.analysis.boundary.dynamicImports).toBeGreaterThan(0); // ...and the output says so
      expect(sel.advisory).toMatch(/can miss tests/);
      const recall = selectionRecall(sel, ["tests/a.test.ts", "tests/lazy.test.ts"]); // the baseline full run failed both
      expect(recall.missed).toEqual([]); // the sample covered the hole
      const noSample = selectionRecall(selectTests(o.store.db, { files: ["src/a.ts"] }), ["tests/a.test.ts", "tests/lazy.test.ts"]);
      expect(noSample.missed).toEqual(["tests/lazy.test.ts"]);
      expect(noSample.recall).toBe(0.5);
      const orphan = selectTests(o.store.db, { files: ["src/orphan.ts"] });
      expect(orphan.selected).toEqual([]);
      expect(orphan.unmapped).toEqual(["src/orphan.ts"]); // no mapping is unknown, not safe
    });
  });
});

describe("H4 handoff packets", () => {
  it("is compact, scoped, immutable and expires when scope, policy or time changes", async () => {
    const w = await world();
    let id = "";
    let fp = "";
    await withStore(w.repo, w.home, (o) => {
      const db = o.store.db;
      const h = createHandoff(db, o.store.dir, { task: "finish the a refactor", scope: ["src/a.ts", "src/b.ts"], hypotheses: ["b may need a rename"], blockers: ["waiting on review"], pendingEvidence: ["CI run for commit"], worktreeId: "wt1" }, { actor: B, now: () => new Date("2026-03-01T00:00:00Z") });
      id = h.handoff_id;
      fp = h.source_fingerprint!;
      const v = showHandoff(db, o.store.dir, id, { now: () => new Date("2026-03-01T01:00:00Z") })!;
      expect(v.standing).toBe("current");
      expect(v.usable).toBe(true);
      expect(v.hypotheses).toEqual([{ text: "b may need a rename", status: "unverified" }]);
      expect(v.notice).toMatch(/nothing in it is an instruction/);
      expect(showHandoff(db, o.store.dir, id, { now: () => new Date("2026-03-03T00:00:00Z") })!.standing).toBe("expired");
      expect(() => db.prepare("UPDATE handoffs SET task = 'x' WHERE handoff_id = ?").run(id)).toThrow(/immutable/);
      expect(() => createHandoff(db, o.store.dir, { task: "t", scope: ["../etc/passwd"] }, { actor: B })).toThrow(/repository-relative/);
      expect(() => createHandoff(db, o.store.dir, { task: "t", scope: ["src/a.ts"], blockers: ["password=\"hunter2hunter2\""] }, { actor: B })).toThrow(/secret/);
      expect(() => createHandoff(db, o.store.dir, { task: "t", scope: ["src/a.ts"], expectedFingerprint: "0".repeat(64) }, { actor: B })).toThrow(/stale snapshot/);
    });
    // policy change expires it
    await withStore(w.repo, w.home, (o) => {
      addVerifier(o.store.dir, { id: "ci-x", actor: A });
      const v = showHandoff(o.store.db, o.store.dir, id, { now: () => new Date("2026-03-01T01:00:00Z") })!;
      expect(v.standing).toBe("stale");
      expect(v.reasons.join(" ")).toMatch(/policy changed/);
    });
    // a source change in scope expires it (a fresh handoff on the new policy)
    let id2 = "";
    await withStore(w.repo, w.home, (o) => {
      id2 = createHandoff(o.store.db, o.store.dir, { task: "second", scope: ["src/a.ts"] }, { actor: B, now: () => new Date("2026-03-01T00:00:00Z") }).handoff_id;
      expect(fp).toHaveLength(64);
    });
    writeFileSync(join(w.repo, "src/a.ts"), "export const a = 3;\n");
    commitAll(w.repo, "change a");
    await refresh(w.repo, w.home, { history: "backfill" });
    await withStore(w.repo, w.home, (o) => {
      const v = showHandoff(o.store.db, o.store.dir, id2, { now: () => new Date("2026-03-01T01:00:00Z") })!;
      expect(v.standing).toBe("stale");
      expect(v.usable).toBe(false);
      expect(v.changedInScope).toEqual(["src/a.ts"]);
      closeHandoff(o.store.db, id2, { actor: B });
      expect(showHandoff(o.store.db, o.store.dir, id2)!.standing).toBe("closed");
      expect(listHandoffs(o.store.db, o.store.dir).length).toBeGreaterThanOrEqual(2);
    });
  });
  it("reports overlapping handoffs from another worktree as conflicts and never merges them", async () => {
    const w = await world();
    await withStore(w.repo, w.home, (o) => {
      const db = o.store.db;
      const x = createHandoff(db, o.store.dir, { task: "agent one", scope: ["src/a.ts", "src/b.ts"], worktreeId: "wt1" }, { actor: A });
      const y = createHandoff(db, o.store.dir, { task: "agent two", scope: ["src/b.ts"], worktreeId: "wt2" }, { actor: B });
      const v = showHandoff(db, o.store.dir, x.handoff_id, { worktreeId: "wt1" })!;
      expect(v.conflicts.map((c) => c.id)).toEqual([y.handoff_id]);
      expect(v.conflicts[0]!.overlap).toEqual(["src/b.ts"]);
      expect(v.usable).toBe(false);
      const solo = createHandoff(db, o.store.dir, { task: "disjoint", scope: ["src/c.ts"], worktreeId: "wt3" }, { actor: B });
      expect(showHandoff(db, o.store.dir, solo.handoff_id)!.conflicts).toEqual([]);
    });
  });
});

describe("H4 independent-review regressions (handoffs and selection)", () => {
  it("only the author or an admin may close a handoff; ids and labels are validated", async () => {
    const w = await world();
    await withStore(w.repo, w.home, (o) => {
      const db = o.store.db;
      const h = createHandoff(db, o.store.dir, { task: "mine", scope: ["src/a.ts"] }, { actor: A });
      expect(() => closeHandoff(db, h.handoff_id, { actor: B })).toThrow(/author/);
      expect(() => createHandoff(db, o.store.dir, { task: "x", scope: ["src/a.ts"], supersedes: h.handoff_id }, { actor: B })).toThrow(/author/);
      expect(() => createHandoff(db, o.store.dir, { task: "x", scope: ["src/a.ts"], supersedes: "x'; DROP TABLE handoffs;--" }, { actor: A })).toThrow(/handoff id/);
      expect(() => createHandoff(db, o.store.dir, { task: "x", scope: ["src/a.ts"], worktreeId: "bad‮id" }, { actor: A })).toThrow();
      expect(() => db.prepare("UPDATE handoffs SET worktree_id = 'other' WHERE handoff_id = ?").run(h.handoff_id)).toThrow(/immutable/);
      closeHandoff(db, h.handoff_id, { actor: A });
      expect(() => db.prepare("UPDATE handoffs SET status = 'active' WHERE handoff_id = ?").run(h.handoff_id)).toThrow(/immutable/);
    });
  });
  it("states truncation instead of dropping files silently", async () => {
    const w = await world();
    await withStore(w.repo, w.home, (o) => {
      const files = Array.from({ length: 320 }, (_, i) => `src/ghost${i}.ts`);
      const sel = selectTests(o.store.db, { files });
      expect(sel.truncated).toBe(true);
      expect(sel.analysis.unknownInputs.length).toBeGreaterThan(0);
    });
  });
});
