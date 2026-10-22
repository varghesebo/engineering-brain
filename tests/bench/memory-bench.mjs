// Benchmark for temporal memory on a SYNTHETIC repository. Run after `npm run build`:
//   node tests/bench/memory-bench.mjs <records> <workDir>
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { addMemory, approveMemory, evaluateRecord, getInstallId, listStale, parseNewMemory, readGitInfo, refreshRepository, relatedBugs, searchMemory, Store, summarizeMemory } from "@engbrain/core";
import { HardenedGit } from "@engbrain/security";

const [, , countArg, workDir] = process.argv;
const count = Number(countArg);
const root = mkdtempSync(join(workDir, `mbench-${count}-`));
const env = { PATH: process.env.PATH, HOME: root, GIT_AUTHOR_NAME: "b", GIT_AUTHOR_EMAIL: "b@example.invalid", GIT_COMMITTER_NAME: "b", GIT_COMMITTER_EMAIL: "b@example.invalid", GIT_CONFIG_GLOBAL: join(root, ".gitconfig") };
const run = (args) => execFileSync("git", args, { cwd: root, stdio: "ignore", env });
mkdirSync(join(root, "src"), { recursive: true });
for (let i = 0; i < 50; i += 1) {
  writeFileSync(join(root, `src/m${i}.ts`), `export function fn${i}(a: number) {\n  return a + ${i};\n}\n`);
}
run(["init", "-q", "-b", "main"]); run(["add", "-A"]); run(["commit", "-q", "-m", "bench"]);
process.env.ENGBRAIN_HOME = join(root, "..", `mhome-${count}`);
mkdirSync(process.env.ENGBRAIN_HOME, { recursive: true });
const git = new HardenedGit();
const info = await readGitInfo(root, git);
const store = await Store.init({ root: info.root, git: info, hardenedGit: git, installId: getInstallId() });
await refreshRepository({ store, git: info, hardenedGit: git });
const actor = { id: "bench", roles: ["propose", "approve", "verify", "admin"] };
const t = () => performance.now();
const db = store.db;
const evaluate = (row) => evaluateRecord(db, row, new Date().toISOString());
let t0 = t();
for (let i = 0; i < count; i += 1) {
  const rec = addMemory(db, parseNewMemory({
    kind: i % 3 === 0 ? "decision" : "claim", title: `Decision ${i} about module ${i % 50}`, body: `Recorded reasoning ${i} for module ${i % 50}. ${"detail ".repeat(20)}`, origin: "human",
    evidence: { type: "review", pointers: [{ kind: "file", path: `src/m${i % 50}.ts` }] }
  }), { actor });
  if (i % 2 === 0) { approveMemory(db, rec.record_id, { actor, evaluate }); }
}
const writeMs = Math.round(t() - t0);
const rssAfterWrites = Math.round(process.memoryUsage().rss / 1048576);
if (global.gc) { global.gc(); }
const rssAfterGc = Math.round(process.memoryUsage().rss / 1048576);
const time = (fn, n = 20) => { const xs = []; for (let i = 0; i < n; i += 1) { const a = t(); fn(); xs.push(t() - a); } xs.sort((x, y) => x - y); return { p50: +xs[Math.floor(n / 2)].toFixed(2), p95: +xs[Math.floor(n * 0.95)].toFixed(2) }; };
const out = {
  records: count, rssAfterWrites, rssAfterGc, writeMs, writesPerSec: Math.round(count / (writeMs / 1000)),
  searchMs: time(() => searchMemory(db, { query: "module 7 decision" })), searchEmptyQueryMs: time(() => searchMemory(db, {})),
  relatedMs: time(() => relatedBugs(db, { file: "src/m7.ts" })), summaryMs: time(() => summarizeMemory(db)), staleMs: time(() => listStale(db), 5),
  tokens: searchMemory(db, { query: "module 7 decision" }).estimatedTokens, truncated: searchMemory(db, {}).truncated,
  dbMiB: +(db.prepare("SELECT page_count * page_size AS b FROM pragma_page_count(), pragma_page_size()").get().b / 1048576).toFixed(2), peakRssMiB: Math.round(process.resourceUsage().maxRSS / 1024)
};
console.log(JSON.stringify(out));
store.close();
git.dispose();
