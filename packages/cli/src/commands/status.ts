import { checkIsolation } from "@engbrain/security";
import { checkFreshness, currentGenerationId, detectFilesystemKind, readCurrentSnapshot, Store, summarizeGeneration, validateGeneration } from "@engbrain/core";
import type { CliContext } from "../context.js";
import { EXIT, printJsonOrText, type Io } from "../output.js";
import { freshnessText } from "./index.js";

export async function statusCommand(io: Io, context: CliContext, json: boolean, check: boolean): Promise<number> {
  const store = await Store.open({ root: context.root, git: context.git, hardenedGit: context.hardenedGit, installId: context.installId });
  try {
    const snapshot = readCurrentSnapshot(store.db);
    const isolation = checkIsolation();
    const id = currentGenerationId(store.db);
    const summary = id === null ? null : summarizeGeneration(store.db, id);
    const problems = check && id !== null ? validateGeneration(store.db, id).problems : [];
    const freshness = await checkFreshness(store, context.git, context.hardenedGit, { verify: check });
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
      summary,
      freshness,
      offline: { applicationNetworkCalls: "none", osIsolation: isolation.available ? "available" : "unavailable", isolationNote: isolation.reason },
      ...(check ? { integrity: { ok: problems.length === 0, problems } } : {})
    };
    const lines = [
      `root: ${context.root}`,
      `repository: ${store.meta.repositoryId}  worktree: ${store.meta.worktreeId}`,
      `git: ${context.git.isGit ? `revision ${context.git.revision ?? "(none)"} branch ${context.git.branchLabel ?? "(detached/none)"}${context.git.isShallow ? " shallow" : ""}` : "not a git work tree"}`,
      snapshot === null
        ? "index: none (run `engbrain index`)"
        : `index: generation ${snapshot.generationId} at revision ${snapshot.revision ?? "(none)"}, completed ${snapshot.completedAt ?? "?"}\n  source fingerprint (includes uncommitted changes): ${snapshot.sourceFingerprint ?? "?"}`,
      ...(summary === null ? [] : [
        `  files: ${summary.files.included} indexed, ${summary.files.excluded} excluded; languages: ${Object.entries(summary.byLanguage).map(([k, v]) => `${k} ${v}`).join(", ") || "none"}`,
        `  parser coverage: ok ${summary.parser.ok}, with errors ${summary.parser.error}, unsupported ${summary.parser.skipped}${summary.diagnostics > 0 ? ` (${summary.diagnostics} diagnostics)` : ""}`,
        `  code: ${summary.symbols} symbols, ${summary.edges.total} module relationships (unresolved ${summary.edges.byResolution["unresolved"] ?? 0}, ambiguous ${summary.edges.byResolution["ambiguous"] ?? 0}, dynamic ${summary.edges.byResolution["dynamic"] ?? 0})`
      ]),
      ...(store.historyChanged ? ["note: repository history changed since init (root commits rewritten, or a different repository is at this path); run `engbrain index`"] : []),
      freshnessText(freshness),
      `offline: application makes no network calls; OS isolation for child processes: ${isolation.available ? "available" : "UNAVAILABLE"}`,
      ...(check ? [problems.length === 0 ? "integrity: ok" : `integrity: FAILED - ${problems.join("; ")}`] : [])
    ];
    printJsonOrText(io, json, value, lines.join("\n"));
    return problems.length === 0 ? EXIT.ok : EXIT.error;
  } finally {
    store.close();
  }
}
