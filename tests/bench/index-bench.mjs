// Benchmark for the code-intelligence index on SYNTHETIC repositories. Run after `npm run build`:
//   node tests/bench/index-bench.mjs <fileCount> <workDir>
// Each size should be run in its own process so peak RSS is that scenario's own. Prints one JSON object of MEASURED values.
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync, appendFileSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { assembleContext, searchCode, estimateTokens, checkFreshness, findCycles, findModuleEdges, findSymbols, getInstallId, graphStats, impact, indexRepository, readGitInfo, resolveNode, shortestPath, Store, traverse, validateGraph } from "@engbrain/core";
import { HardenedGit } from "@engbrain/security";

const [, , countArg, workDir] = process.argv;
const count = Number(countArg);
const root = mkdtempSync(join(workDir, `bench-${count}-`));
const t = () => performance.now();

// ---- generate a synthetic repo (deterministic) ----
const g0 = t();
mkdirSync(join(root, "src"), { recursive: true });
writeFileSync(join(root, "tsconfig.json"), JSON.stringify({ compilerOptions: { baseUrl: ".", paths: { "@app/*": ["src/*"] } } }));
for (let i = 0; i < count; i += 1) {
  const dir = `src/m${i % 50}`;
  mkdirSync(join(root, dir), { recursive: true });
  const ext = i % 25 === 0 ? "js" : i % 10 === 0 ? "tsx" : "ts";
  const prev = i > 0 ? `import { fn${i - 1}_0 } from "../m${(i - 1) % 50}/file${i - 1}";\n` : "";
  const prev2 = i > 1 ? `import { Cls${i - 2} } from "@app/m${(i - 2) % 50}/file${i - 2}";\n` : "";
  const dyn = i % 7 === 0 ? `export async function lazy${i}(n: string) { return import(n); }\n` : "";
  // barrel import (resolved through `export *` chains), name references and heritage: the paths the graph builder spends time on
  const viaBarrel = i > 2 ? `import { K${i - 3} } from "../m${(i - 3) % 50}";\n` : "";
  let body = `${prev}${prev2}${viaBarrel}import fs from "node:fs";\nimport lodash from "lodash";\n`;
  for (let f = 0; f < 4; f += 1) {
    body += `export function fn${i}_${f}(a: number, b?: string): number {\n  function inner(x: number) { return x + ${f}; }\n  return inner(a) * 2;\n}\n`;
  }
  const uses = [i > 2 ? `K${i - 3}` : "0", i > 0 ? `fn${i - 1}_0(1)` : "0"].join(", ");
  body += `export const use${i} = [${uses}];\n`;
  body += i > 1 ? `export class Sub${i} extends Cls${i - 2} {}\n` : "";
  body += `export class Cls${i} {\n  constructor(private n: number) {}\n  run(v: number): number { return v + this.n; }\n  stop(): void {}\n}\nexport const K${i} = ${i};\n${dyn}`;
  writeFileSync(join(root, dir, `file${i}.${ext === "js" ? "ts" : ext}`), body);
}
for (let d = 0; d < Math.min(50, count); d += 1) {
  let barrel = "";
  for (let j = d; j < count; j += 50) {
    barrel += `export * from "./file${j}";\n`;
  }
  writeFileSync(join(root, `src/m${d}/index.ts`), barrel);
}
const run = (args) => execFileSync("git", args, { cwd: root, stdio: "ignore", env: { PATH: process.env.PATH, HOME: root, GIT_AUTHOR_NAME: "b", GIT_AUTHOR_EMAIL: "b@example.invalid", GIT_COMMITTER_NAME: "b", GIT_COMMITTER_EMAIL: "b@example.invalid" } });
run(["init", "-q"]); run(["add", "-A"]); run(["commit", "-q", "-m", "bench"]);
const generateMs = Math.round(t() - g0);

// ---- measure ----
process.env.ENGBRAIN_HOME = join(root, "..", `home-${count}`);
mkdirSync(process.env.ENGBRAIN_HOME, { recursive: true });
const git = new HardenedGit();
const info = await readGitInfo(root, git);
const ctx = { root: info.root, git: info, hardenedGit: git, installId: getInstallId() };
const store = await Store.init(ctx);
const out = { files: count, generateMs };

let r0 = t();
let result = await indexRepository({ store, git: info, hardenedGit: git });
out.initial = { ms: Math.round(t() - r0), filesPerSec: Math.round(result.stats.included / ((t() - r0) / 1000)), included: result.stats.included, parsed: result.stats.parser.parsed, failed: result.stats.parser.failed,
  skipped: result.stats.parser.skipped, symbols: result.summary.symbols, edges: result.summary.edges, dbMiB: +(result.stats.dbSizeBytes / 1048576).toFixed(2), peakRssMiB: result.stats.peakRssMiB, graphBuildMs: result.stats.graph?.phasesMs ?? null };

r0 = t();
result = await indexRepository({ store, git: info, hardenedGit: git });
out.unchanged = { ms: Math.round(t() - r0), unchanged: result.unchanged, parsed: result.stats.parser.parsed, extractorRuns: result.stats.extractorRuns };

appendFileSync(join(root, "src/m3/file3.ts"), "export function added(): number { return 1; }\n");
r0 = t();
result = await indexRepository({ store, git: info, hardenedGit: git });
out.oneFileChange = { ms: Math.round(t() - r0), unchanged: result.unchanged, parsed: result.stats.parser.parsed, extractorRuns: result.stats.extractorRuns, factsReused: result.stats.factsReused, changed: result.summary.changed, graphBuildMs: result.stats.graph?.phasesMs ?? null };

// a body-only edit (no change to symbols, exports or imports): unchanged files' graph edges are carried over
appendFileSync(join(root, "src/m3/file3.ts"), "// a comment only\n");
r0 = t();
result = await indexRepository({ store, git: info, hardenedGit: git });
out.oneFileBodyChange = { ms: Math.round(t() - r0), parsed: result.stats.parser.parsed, reused: result.stats.graph?.reused ?? null, graphBuildMs: result.stats.graph?.phasesMs ?? null };

for (const verify of [false, true]) {
  r0 = t();
  const report = await checkFreshness(store, info, git, { verify });
  out[verify ? "freshnessVerified" : "freshnessHeuristic"] = { ms: Math.round(t() - r0), level: report.level };
}

const timings = [];
for (let i = 0; i < 200; i += 1) {
  const q0 = t();
  findSymbols(store.db, { search: `fn${(i * 37) % count}_0`, limit: 20 });
  timings.push(t() - q0);
}
const file = `src/m${5 % 50}/file5.ts`;
const q1 = [];
for (let i = 0; i < 200; i += 1) {
  const q0 = t();
  findSymbols(store.db, { file });
  findModuleEdges(store.db, { from: file });
  q1.push(t() - q0);
}
const p = (a, q) => +[...a].sort((x, y) => x - y)[Math.floor(a.length * q)].toFixed(2);
out.queries = { searchSymbolsMs: { p50: p(timings, 0.5), p95: p(timings, 0.95) }, fileSymbolsAndEdgesMs: { p50: p(q1, 0.5), p95: p(q1, 0.95) } };
// ---- graph (Phase 2B) ----
const time = (fn) => { const t0 = t(); const value = fn(); return [Math.round((t() - t0) * 100) / 100, value]; };
const hubFile = `src/m${(count >> 1) % 50}/file${count >> 1}.ts`;
const [statsMs, gs] = time(() => graphStats(store.db));
const [validateMs, gv] = time(() => validateGraph(store.db));
const [cyclesMs, cyc] = time(() => findCycles(store.db));
const node = resolveNode(store.db, { file: hubFile });
const [depsMs, deps] = time(() => traverse(store.db, node, { direction: "forward", budget: { maxDepth: 3 } }));
const [dependentsMs, dependents] = time(() => traverse(store.db, node, { direction: "reverse", budget: { maxDepth: 3 } }));
const [impactMs, imp] = time(() => impact(store.db, node));
const symNode = resolveNode(store.db, { symbol: `${hubFile}#Cls${count >> 1}` });
const [impactSymMs, impSym] = time(() => impact(store.db, symNode));
const far = resolveNode(store.db, { file: `src/m${((count >> 1) - 5) % 50}/file${(count >> 1) - 5}.ts` });
const [pathMs, pth] = time(() => shortestPath(store.db, node, far));
out.graph = {
  edges: gs.edges.total, byKind: gs.edges.byKind, byResolution: gs.edges.byResolution, cycles: cyc.totalCycles, valid: gv.ok,
  ms: { stats: statsMs, validate: validateMs, cycles: cyclesMs, dependenciesDepth3: depsMs, dependentsDepth3: dependentsMs, impact: impactMs, impactSymbol: impactSymMs, pathFound: pathMs },
  results: { dependencies: deps.nodes.length - 1, dependents: dependents.nodes.length - 1, impactAffected: imp.affected.length, impactSymbolAffected: impSym.affected.length, impactTruncated: imp.truncated, pathFound: pth.found }
};
// ---- context retrieval vs an unassisted scan (Phase 2C) ----
// Baseline: what an agent without the index does in one step: read every source file and substring-search the task words (a grep equivalent, in-process, warm cache).
const taskWords = [`fn${(count >> 1) + 3}_0`, `Cls${(count >> 1) + 3}`];
const walk = (dir, acc = []) => { for (const e of readdirSync(dir, { withFileTypes: true })) { if (e.name === ".git" || e.name === ".engineering-brain") continue; const p = join(dir, e.name); e.isDirectory() ? walk(p, acc) : acc.push(p); } return acc; };
const b0 = t();
const allFiles = walk(root);
let scannedBytes = 0; const matched = [];
for (const f of allFiles) { const text = readFileSync(f, "utf8"); scannedBytes += text.length; if (taskWords.some((w) => text.includes(w))) matched.push(f); }
const baselineMs = Math.round(t() - b0);
const task = `change ${taskWords[0]} in ${taskWords[1]}`;
const ctxTimes = [];
let packet;
for (let i = 0; i < 20; i += 1) { const c0 = t(); packet = assembleContext(store.db, { task, root }); ctxTimes.push(t() - c0); }
const searchTimes = [];
for (let i = 0; i < 50; i += 1) { const c0 = t(); searchCode(store.db, { query: taskWords[0] }); searchTimes.push(t() - c0); }
const firstHit = packet.files[0]?.path ?? null;
out.contextRetrieval = {
  task, calls: 1, assembleMs: { p50: p(ctxTimes, 0.5), p95: p(ctxTimes, 0.95) }, searchCodeMs: { p50: p(searchTimes, 0.5), p95: p(searchTimes, 0.95) },
  packetTokens: packet.budget.estimatedTokens, packetFiles: packet.files.length, firstFile: firstHit, firstFileIsExpected: firstHit !== null && taskWords.some((w) => firstHit.includes(`file${(count >> 1) + 3}.`)),
  baseline: { calls: 1, scanMs: baselineMs, filesRead: allFiles.length, estimatedTokensIfRead: Math.round(scannedBytes / 3), matchedFiles: matched.length }
};
out.finalPeakRssMiB = Math.round(process.resourceUsage().maxRSS / 1024);
out.node = process.version;
out.platform = `${process.platform}-${process.arch}`;
store.close();
git.dispose();
console.log(JSON.stringify(out));
