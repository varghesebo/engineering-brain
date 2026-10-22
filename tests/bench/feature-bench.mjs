// Benchmark for the feature graph on a SYNTHETIC multi-service repository. Run after `npm run build`:
//   node tests/bench/feature-bench.mjs <services> <routesPerService> <workDir>
import { execFileSync } from "node:child_process";
import { appendFileSync, mkdirSync, mkdtempSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { featureImpact, getInstallId, indexRepository, listFeatures, readGitInfo, showFeature, Store, traceFrom } from "@engbrain/core";
import { HardenedGit } from "@engbrain/security";

const [, , servicesArg, routesArg, workDir] = process.argv;
const services = Number(servicesArg);
const routes = Number(routesArg);
const root = mkdtempSync(join(workDir, `fbench-${services}x${routes}-`));
const env = { PATH: process.env.PATH, HOME: root, GIT_AUTHOR_NAME: "b", GIT_AUTHOR_EMAIL: "b@example.invalid", GIT_COMMITTER_NAME: "b", GIT_COMMITTER_EMAIL: "b@example.invalid", GIT_CONFIG_GLOBAL: join(root, ".gitconfig") };
const run = (args) => execFileSync("git", args, { cwd: root, stdio: "ignore", env });
const t = () => performance.now();

writeFileSync(join(root, "package.json"), JSON.stringify({ name: "bench", workspaces: ["services/*"] }));
let sql = "";
for (let s = 0; s < services; s += 1) {
  const dir = join(root, `services/s${s}/src`);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(root, `services/s${s}/package.json`), JSON.stringify({ name: `@b/s${s}` }));
  sql += `CREATE TABLE t${s} (id int);\n`;
  let handlers = "";
  let routesSrc = `import express from "express";\nimport { ${Array.from({ length: routes }, (_, r) => `h${r}`).join(", ")} } from "./handlers";\nexport const router = express.Router();\n`;
  let web = "";
  for (let r = 0; r < routes; r += 1) {
    handlers += `export function h${r}(req, res) {\n  db.query("SELECT * FROM t${s} WHERE id = ?");\n  queue.publish("s${s}.e${r % 10}", {});\n  res.json({});\n}\n`;
    routesSrc += `router.get("/s${s}/r${r}", h${r});\n`;
    web += `fetch("/api/s${s}/r${r}");\n`;
  }
  writeFileSync(join(dir, "handlers.ts"), handlers);
  writeFileSync(join(dir, "routes.ts"), routesSrc);
  writeFileSync(join(dir, "consumer.ts"), Array.from({ length: 10 }, (_, e) => `queue.subscribe("s${s}.e${e}", function on${e}() { db.query("INSERT INTO t${s} VALUES (1)"); });`).join("\n"));
  writeFileSync(join(dir, "server.ts"), `import { router } from "./routes";\napp.use("/api", router);\n`);
  writeFileSync(join(root, `services/s${s}/web.tsx`), `export function Page${s}() {\n${web}  return null;\n}\n`);
}
mkdirSync(join(root, "db"), { recursive: true });
writeFileSync(join(root, "db/schema.sql"), sql);
run(["init", "-q", "-b", "main"]); run(["add", "-A"]); run(["commit", "-q", "-m", "bench"]);

process.env.ENGBRAIN_HOME = join(root, "..", `fhome-${services}x${routes}`);
mkdirSync(process.env.ENGBRAIN_HOME, { recursive: true });
const git = new HardenedGit();
const info = await readGitInfo(root, git);
const store = await Store.init({ root: info.root, git: info, hardenedGit: git, installId: getInstallId() });
const out = { services, routesPerService: routes };
let r0 = t();
let result = await indexRepository({ store, git: info, hardenedGit: git });
out.initial = { ms: Math.round(t() - r0), files: result.stats.included, features: result.stats.features, dbMiB: +(statSync(join(root, ".engineering-brain/store.db")).size / 1048576).toFixed(2) };
appendFileSync(join(root, "services/s0/src/handlers.ts"), "export function extra() {}\n");
r0 = t();
result = await indexRepository({ store, git: info, hardenedGit: git });
out.oneFileChange = { ms: Math.round(t() - r0), parsed: result.stats.parser.parsed, extractorRuns: result.stats.extractorRuns, features: result.stats.features };
const time = (fn) => { const t0 = t(); const v = fn(); return [Math.round((t() - t0) * 100) / 100, v]; };
const [listMs, list] = time(() => listFeatures(store.db, { limit: 100 }));
const first = list.features[0]?.id;
const [showMs] = time(() => showFeature(store.db, first));
const [traceMs, tr] = time(() => traceFrom(store.db, "route:GET /api/s0/r0", { depth: 4 }));
const [impactMs] = time(() => featureImpact(store.db, { file: "services/s0/src/handlers.ts" }));
out.queries = { listMs, showMs, traceMs, impactMs, traceNodes: tr.nodes.length, traceTruncated: tr.truncated, totalFeatures: list.total };
out.peakRssMiB = Math.round(process.resourceUsage().maxRSS / 1024);
out.node = process.version;
store.close();
git.dispose();
console.log(JSON.stringify(out));
