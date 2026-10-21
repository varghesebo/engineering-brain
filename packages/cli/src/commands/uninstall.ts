import { lstatSync, rmSync } from "node:fs";
import { EngbrainError, isStoreTrackedByGit, Store, STORE_DIR_NAME } from "@engbrain/core";
import type { CliContext } from "../context.js";
import { printJsonOrText, type Io } from "../output.js";

/**
 * Default: removes only integration/config blocks engbrain generated. None exist in this build (agent onboarding
 * is a later stage), so nothing is removed and the store is kept. `--purge --yes` deletes the store; the
 * source repository is never touched.
 */
export async function uninstallCommand(io: Io, context: CliContext, json: boolean, purge: boolean, confirmed: boolean): Promise<void> {
  const dir = Store.storeDir(context.root);
  if (!purge) {
    printJsonOrText(
      io, json, { removedIntegrations: 0, purged: false },
      `No generated integration blocks to remove. ${STORE_DIR_NAME}/ was kept (knowledge and audit log). Use --purge --yes to delete it.`
    );
    return;
  }
  if (!confirmed) {
    throw new EngbrainError("POLICY_REFUSED", "--purge deletes all stored knowledge and the audit log; pass --yes to confirm");
  }
  let stat;
  try {
    stat = lstatSync(dir);
  } catch {
    printJsonOrText(io, json, { purged: false }, `Nothing to purge: no ${STORE_DIR_NAME}/ here.`);
    return;
  }
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new EngbrainError("STORE_UNSAFE_PATH", `${STORE_DIR_NAME} is not a regular directory; refusing to delete it`);
  }
  if (context.git.isGit && context.hardenedGit !== null && (await isStoreTrackedByGit(context.hardenedGit, context.root))) {
    throw new EngbrainError("STORE_TRACKED_BY_GIT", `${STORE_DIR_NAME} is tracked by git, so it is part of the repository; refusing to delete it`);
  }
  rmSync(dir, { recursive: true, force: true });
  printJsonOrText(io, json, { purged: true }, `Deleted ${STORE_DIR_NAME}/. Source files were not touched.`);
}
