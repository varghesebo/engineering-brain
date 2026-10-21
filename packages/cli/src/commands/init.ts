import { AuditLog, Store, STORE_DIR_NAME, type EngbrainConfig } from "@engbrain/core";
import type { CliContext } from "../context.js";
import { printJsonOrText, type Io } from "../output.js";

export async function initCommand(io: Io, context: CliContext, json: boolean): Promise<void> {
  const store = await Store.init({ root: context.root, git: context.git, hardenedGit: context.hardenedGit, installId: context.installId });
  try {
    const config: EngbrainConfig = store.config();
    new AuditLog(
      store.dir, context.installId,
      { maxFileBytes: config.auditMaxFileBytes, maxFiles: config.auditMaxFiles, retentionDays: config.auditRetentionDays }
    ).record("init", { repositoryId: store.meta.repositoryId, git: context.git.isGit, shallow: context.git.isShallow });
    printJsonOrText(
      io, json,
      { root: context.root, store: STORE_DIR_NAME, repositoryId: store.meta.repositoryId, worktreeId: store.meta.worktreeId, git: context.git.isGit },
      `Initialized ${STORE_DIR_NAME}/ in ${context.root}\n  repository: ${store.meta.repositoryId}\n  worktree:   ${store.meta.worktreeId}\n` +
        "  mode: strict offline (engbrain makes no network calls; OS-level isolation for child processes: unavailable)"
    );
  } finally {
    store.close();
  }
}
