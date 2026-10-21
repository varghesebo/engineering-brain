// Child process used by crash/concurrency tests. Uses the BUILT packages (run `npm run build` first).
import { writeFileSync } from "node:fs";
import { Store, getInstallId, indexRepository, readGitInfo } from "@engbrain/core";
import { HardenedGit } from "@engbrain/security";

const [, , root, crashPoint, markerPath] = process.argv;
const git = new HardenedGit();
try {
  const info = await readGitInfo(root, git);
  const store = await Store.open({ root: info.root, git: info, hardenedGit: git, installId: getInstallId() });
  const fault =
    crashPoint && crashPoint !== "none"
      ? (point) => {
          if (point === crashPoint) {
            writeFileSync(markerPath, "reached");
            Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 120000); // parent SIGKILLs us here
          }
        }
      : undefined;
  const result = await indexRepository({ store, git: info, hardenedGit: git, fault, lock: { timeoutMs: 20000 } });
  process.stdout.write(`${JSON.stringify({ generationId: result.generationId, unchanged: result.unchanged })}\n`);
  store.close();
} finally {
  git.dispose();
}
