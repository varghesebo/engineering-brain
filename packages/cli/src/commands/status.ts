import { checkIsolation } from "@engbrain/security";
import { currentGenerationId, detectFilesystemKind, readCurrentSnapshot, Store, validateGeneration } from "@engbrain/core";
import type { CliContext } from "../context.js";
import { EXIT, printJsonOrText, type Io } from "../output.js";

export async function statusCommand(io: Io, context: CliContext, json: boolean, check: boolean): Promise<number> {
  const store = await Store.open({ root: context.root, git: context.git, hardenedGit: context.hardenedGit, installId: context.installId });
  try {
    const snapshot = readCurrentSnapshot(store.db);
    const isolation = checkIsolation();
    let problems: string[] = [];
    if (check) {
      const id = currentGenerationId(store.db);
      problems = id === null ? [] : validateGeneration(store.db, id).problems;
    }
    const value = {
      root: context.root,
      repositoryId: store.meta.repositoryId,
      worktreeId: store.meta.worktreeId,
      git: {
        isGit: context.git.isGit, revision: context.git.revision, branchLabel: context.git.branchLabel,
        shallow: context.git.isShallow, linkedWorktree: context.git.isLinkedWorktree
      },
      schemaVersion: store.migration.to,
      historyChanged: store.historyChanged,
      filesystem: detectFilesystemKind(context.root),
      generation: snapshot,
      offline: { applicationNetworkCalls: "none", osIsolation: isolation.available ? "available" : "unavailable", isolationNote: isolation.reason },
      ...(check ? { integrity: { ok: problems.length === 0, problems } } : {})
    };
    const lines = [
      `root: ${context.root}`,
      `repository: ${store.meta.repositoryId}  worktree: ${store.meta.worktreeId}`,
      `git: ${context.git.isGit ? `revision ${context.git.revision ?? "(none)"} branch ${context.git.branchLabel ?? "(detached/none)"}${context.git.isShallow ? " shallow" : ""}` : "not a git work tree"}`,
      snapshot === null
        ? "generation: none (run `engbrain index`)"
        : `generation ${snapshot.generationId}: ${snapshot.includedFiles} included, ${snapshot.excludedFiles} excluded, completed ${snapshot.completedAt ?? "?"}`,
      ...(store.historyChanged ? ["note: repository history changed since init (root commits rewritten, or a different repository is at this path); run `engbrain index`"] : []),
      "freshness: not checked in this build (hash/heuristic freshness arrives with the Code Intelligence stage)",
      `offline: application makes no network calls; OS isolation for child processes: ${isolation.available ? "available" : "UNAVAILABLE"}`,
      ...(check ? [problems.length === 0 ? "integrity: ok" : `integrity: FAILED - ${problems.join("; ")}`] : [])
    ];
    printJsonOrText(io, json, value, lines.join("\n"));
    return problems.length === 0 ? EXIT.ok : EXIT.error;
  } finally {
    store.close();
  }
}
