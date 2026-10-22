// Benchmark for the history ledger on a SYNTHETIC repository. Run after `npm run build`:
//   node tests/bench/history-bench.mjs <commits> <files> <workDir>
import { execFileSync } from "node:child_process";
import { appendFileSync, mkdirSync, mkdtempSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { getInstallId, readGitInfo, refreshRepository, Store } from "@engbrain/core";
import { HardenedGit } from "@engbrain/security";

const [, , commitsArg, filesArg, workDir] = process.argv;
const commits = Number(commitsArg);
const files = Number(filesArg);
const root = mkdtempSync(join(workDir, `hbench-${commits}-`));
const env = { PATH: process.env.PATH, HOME: root, GIT_AUTHOR_NAME: "b", GIT_AUTHOR_EMAIL: "b@example.invalid", GIT_COMMITTER_NAME: "b", GIT_COMMITTER_EMAIL: "b@example.invalid", GIT_CONFIG_GLOBAL: join(root, ".gitconfig") };
const run = (args) => execFileSync("git", args, { cwd: root, stdio: "ignore", env });
const t = () => performance.now();

const g0 = t();
run(["init", "-q", "-b", "main"]);
mkdirSync(join(root, "src"), { recursive: true });
for (let i = 0; i < files; i += 1) {
  writeFileSync(join(root, `src/f${i}.ts`), `export function fn${i}(a: number) {\n  return a + ${i};\n}\nexport class C${i} {}\n`);
}
run(["add", "-A"]); run(["commit", "-q", "-m", "root"]);
for (let c = 1; c < commits; c += 1) {
  for (let k = 0; k < 3; k += 1) {
    const i = (c * 7 + k * 13) % files;
    appendFileSync(join(root, `src/f${i}.ts`), `export function extra${c}_${k}(x: number) {\n  return x * ${c};\n}\n`);
  }
  run(["add", "-A"]); run(["commit", "-q", "-m", `commit ${c}`]);
}
const generateMs = Math.round(t() - g0);

process.env.ENGBRAIN_HOME = join(root, "..", `hhome-${commits}`);
mkdirSync(process.env.ENGBRAIN_HOME, { recursive: true });
const git = new HardenedGit();
const info = await readGitInfo(root, git);
const store = await Store.init({ root: info.root, git: info, hardenedGit: git, installId: getInstallId() });
const out = { commits, files, generateMs };
let r0 = t();
const baseline = await refreshRepository({ store, git: info, hardenedGit: git, history: "none" });
out.baseline = { ms: Math.round(t() - r0), ingested: baseline.ingest.commitsIngested, blobsRead: baseline.ingest.blobsRead, partial: baseline.historyPartial };
r0 = t();
const backfill = await refreshRepository({ store, git: info, hardenedGit: git, history: "backfill", maxCommits: commits + 10 });
const ms = t() - r0;
out.backfill = { ms: Math.round(ms), commitsPerSec: Math.round(backfill.ingest.commitsIngested / (ms / 1000)), ingested: backfill.ingest.commitsIngested, changes: backfill.ingest.changes, symbolDeltas: backfill.ingest.symbolDeltas, blobsRead: backfill.ingest.blobsRead, extractorRuns: backfill.ingest.extractorRuns, partial: backfill.historyPartial };
r0 = t();
const again = await refreshRepository({ store, git: info, hardenedGit: git });
out.noop = { ms: Math.round(t() - r0), ingested: again.ingest.commitsIngested, unchanged: again.index.unchanged };
appendFileSync(join(root, "src/f1.ts"), "export const dirty = 1;\n");
writeFileSync(join(root, "src/untracked.ts"), "export const u = 1;\n");
r0 = t();
const dirty = await refreshRepository({ store, git: info, hardenedGit: git });
out.dirtyRefresh = { ms: Math.round(t() - r0), overlay: dirty.overlayHash === null ? null : dirty.overlayHash.slice(0, 12) };
out.dbMiB = +(statSync(join(root, ".engineering-brain", "store.db")).size / 1048576).toFixed(2);
out.peakRssMiB = Math.round(process.resourceUsage().maxRSS / 1024);
out.node = process.version;
store.close();
git.dispose();
console.log(JSON.stringify(out));
