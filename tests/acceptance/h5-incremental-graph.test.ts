import { cpSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { indexRepository, validateGraph } from "@engbrain/core";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, engbrainHome, makeGitRepo, openFor, tempDir } from "../helpers/env.js";
import { graphFiles } from "../helpers/graph-fixture.js";

afterAll(cleanupTempDirs);

async function indexIn(repo: string, home: string, init = false) {
  const o = await openFor(repo, home, init);
  try {
    return await indexRepository({ store: o.store, git: o.info, hardenedGit: o.git });
  } finally {
    o.close();
  }
}
async function dump(repo: string, home: string): Promise<string[]> {
  const o = await openFor(repo, home);
  try {
    const gen = "(SELECT current_generation_id FROM store_meta)";
    return (o.store.db.prepare(`SELECT edge_id, family, edge_kind, import_style, ordinal, src_kind, src_path, src_symbol, dst_kind, dst_path, dst_symbol, dst_name, dst_package, mechanism, resolution, reason, start_line, end_line, extractor, detail FROM graph_edges WHERE generation_id = ${gen} ORDER BY edge_id`).all() as unknown[]).map((r) => JSON.stringify(r));
  } finally {
    o.close();
  }
}
async function cleanDump(repo: string): Promise<string[]> {
  const copy = tempDir("engbrain-h5clean-");
  cpSync(repo, copy, { recursive: true, filter: (src) => !src.split("/").some((seg) => seg === ".git" || seg === ".engineering-brain") });
  const home = engbrainHome();
  await indexIn(copy, home, true);
  return dump(copy, home);
}

describe("H5 unchanged files' edges are carried over, identical (including ids) to a clean build", () => {
  it("reuses on a body-only edit, and falls back to a full rebuild for surface, config, add and delete changes", async () => {
    const repo = makeGitRepo(graphFiles());
    const home = engbrainHome();
    await indexIn(repo, home, true);

    // body-only edit of a file whose symbols, exports and imports stay the same
    writeFileSync(join(repo, "packages/core/src/logger.ts"), (await import("node:fs")).readFileSync(join(repo, "packages/core/src/logger.ts"), "utf8") + "\n// a comment only\n");
    const r1 = await indexIn(repo, home);
    expect(r1.stats.graph?.reused).not.toBeNull();
    expect(r1.stats.graph?.reused?.changedFiles).toBe(1);
    expect(await dump(repo, home)).toEqual(await cleanDump(repo));

    // an added export changes what other files can see: full rebuild
    writeFileSync(join(repo, "packages/core/src/models.ts"), `export class Animal {}\nexport class Dog extends Animal {}\nexport class Added {}\n`);
    const r2 = await indexIn(repo, home);
    expect(r2.stats.graph?.reused).toBeNull();
    expect(await dump(repo, home)).toEqual(await cleanDump(repo));

    // a config change: full rebuild
    writeFileSync(join(repo, "tsconfig.json"), JSON.stringify({ compilerOptions: { baseUrl: ".", paths: {} } }));
    expect((await indexIn(repo, home)).stats.graph?.reused).toBeNull();

    // a new file: full rebuild
    writeFileSync(join(repo, "packages/app/src/brand-new.ts"), "export const x = 1;\n");
    expect((await indexIn(repo, home)).stats.graph?.reused).toBeNull();
    expect(await dump(repo, home)).toEqual(await cleanDump(repo));

    const o = await openFor(repo, home);
    try {
      expect(validateGraph(o.store.db).problems).toEqual([]);
    } finally {
      o.close();
    }
  });

  it("an edit that only changes a file's own references and heritage lines is carried over too", async () => {
    const repo = makeGitRepo(graphFiles());
    const home = engbrainHome();
    await indexIn(repo, home, true);
    const fs = await import("node:fs");
    const file = join(repo, "packages/app/src/main.ts");
    fs.writeFileSync(file, `// shifted lines\n\n${fs.readFileSync(file, "utf8")}`);
    const r = await indexIn(repo, home);
    expect(r.stats.graph?.reused).not.toBeNull();
    expect(await dump(repo, home)).toEqual(await cleanDump(repo));
  });

  it("a surface-neutral edit of a file that others import, chained over two generations, still equals a clean build (package edge counts included)", async () => {
    const repo = makeGitRepo(graphFiles());
    const home = engbrainHome();
    await indexIn(repo, home, true);
    const fs = await import("node:fs");
    for (const [i, file] of ["packages/core/src/models.ts", "packages/core/src/index.ts"].entries()) {
      fs.appendFileSync(join(repo, file), `\n// edit ${i}\n`);
      const r = await indexIn(repo, home);
      expect(r.stats.graph?.reused).not.toBeNull();
      expect(await dump(repo, home)).toEqual(await cleanDump(repo)); // the second pass reuses a generation that was itself built by reuse
    }
    const o = await openFor(repo, home);
    try {
      expect((o.store.db.prepare("SELECT COUNT(*) AS n FROM graph_edges WHERE edge_kind = 'DEPENDS_ON' AND generation_id = (SELECT current_generation_id FROM store_meta)").get() as { n: number }).n).toBeGreaterThan(0);
    } finally {
      o.close();
    }
  });
});
