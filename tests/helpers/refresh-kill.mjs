// Runs one refresh and SIGKILLs itself at a named fault point (tests only): node refresh-kill.mjs <repo> <home> <point> [history]
import { getInstallId, readGitInfo, refreshRepository, Store } from "@engbrain/core";
import { HardenedGit } from "@engbrain/security";

const [, , repo, home, point, history] = process.argv;
process.env.ENGBRAIN_HOME = home;
const git = new HardenedGit();
const info = await readGitInfo(repo, git, process.env.HOME);
const store = await Store.open({ root: info.root, git: info, hardenedGit: git, installId: getInstallId(process.env) });
await refreshRepository({
  store, git: info, hardenedGit: git, history: history ?? "none", batchSize: 2,
  fault: (p) => { if (p === point) { process.kill(process.pid, "SIGKILL"); } }
});
store.close();
