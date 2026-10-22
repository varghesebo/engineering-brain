import { changesSince, commitChanges, EngbrainError, GitHistory, refreshRepository, refreshStatus, Store, type HistoryMode, type LedgerCommit } from "@engbrain/core";
import type { CliContext } from "../context.js";
import { printable, printJsonOrText, type Io } from "../output.js";

export interface RefreshCommandOptions { history: HistoryMode; maxCommits: number | undefined; timeBudgetMs: number | undefined; status: boolean }

export async function refreshCommand(io: Io, context: CliContext, json: boolean, options: RefreshCommandOptions): Promise<void> {
  if (options.status) {
    const store = await Store.openReadOnly({ root: context.root, git: context.git, hardenedGit: context.hardenedGit, installId: context.installId });
    try {
      const status = refreshStatus(store.db);
      const cp = status.checkpoint;
      const lines = cp === null
        ? ["no history checkpoint yet: run `engbrain refresh`"]
        : [
          `checkpoint  ${cp.processedOid ?? "(none)"}  generation ${cp.generationId ?? "-"}  history ${cp.historyPartial ? "PARTIAL (ancestors before the baseline or beyond a shallow boundary are not recorded)" : "complete"}`,
          `dirty overlay  ${cp.overlayHash === null ? "clean" : cp.overlayHash.slice(0, 12)}`,
          `ledger  ${status.commitsInLedger} commits, ${status.reachableFromCheckpoint} reachable from the checkpoint, ${status.orphaned} orphaned (kept as evidence)`,
          ...status.runs.map((r) => `run ${r.id}  ${r.status}  ${r.mode}  ${r.startedAt}`),
          ...status.lineage.map((l) => `lineage  ${l.kind}  ${l.oldOid?.slice(0, 10) ?? "-"} -> ${l.newOid?.slice(0, 10) ?? "-"}${l.forkOid === null ? "" : `  fork ${l.forkOid.slice(0, 10)}`}`)
        ];
      printJsonOrText(io, json, { status }, lines.join("\n"));
    } finally {
      store.close();
    }
    return;
  }
  const store = await Store.open({ root: context.root, git: context.git, hardenedGit: context.hardenedGit, installId: context.installId });
  const controller = new AbortController();
  const onSigint = (): void => controller.abort();
  process.once("SIGINT", onSigint);
  try {
    const result = await refreshRepository({
      store, git: context.git, hardenedGit: context.hardenedGit, history: options.history, signal: controller.signal,
      ...(options.maxCommits === undefined ? {} : { maxCommits: options.maxCommits }), ...(options.timeBudgetMs === undefined ? {} : { timeBudgetMs: options.timeBudgetMs })
    });
    const i = result.ingest;
    const lines = [
      `refresh  lineage ${result.lineage}${result.forkOid === null ? "" : ` (fork ${result.forkOid.slice(0, 10)})`}  generation ${result.index.generationId}${result.index.unchanged ? " (unchanged)" : ""}`,
      `commits  ${i.commitsIngested} ingested, ${i.commitsAlreadyKnown} already known, ${i.changes} file changes, ${i.symbolDeltas} symbol deltas${i.truncatedCommits > 0 ? `, ${i.truncatedCommits} commits with truncated change lists` : ""}`,
      `blobs    ${i.blobsRead} read, ${i.blobsReused} reused, ${i.extractorRuns} extractor runs`,
      `checkpoint  ${result.processedOid ?? "(none)"}  history ${result.historyPartial ? "PARTIAL" : "complete"}  dirty overlay ${result.overlayHash === null ? "clean" : result.overlayHash.slice(0, 12)}`
    ];
    if (result.stopReason !== null) {
      lines.push(`stopped by ${result.stopReason}: ${result.remaining} reachable commits not yet ingested; run refresh again to continue`);
    }
    printJsonOrText(io, json, { refresh: { ...result, index: { generationId: result.index.generationId, unchanged: result.index.unchanged, revision: result.index.revision } } }, lines.join("\n"));
  } finally {
    process.removeListener("SIGINT", onSigint);
    store.close();
  }
}

async function resolveCommitArg(context: CliContext, text: string): Promise<string> {
  if (context.hardenedGit === null) {
    throw new EngbrainError("GIT_UNAVAILABLE", "git is required to resolve a commit reference");
  }
  const oid = await new GitHistory(context.hardenedGit, context.root).resolveCommit(text);
  if (oid === null) {
    throw new EngbrainError("INVALID_ROOT", "that is not a commit in this repository");
  }
  return oid;
}

const describe = (c: LedgerCommit): string => {
  const total = c.changesByParent.reduce((n, g) => n + g.changes.length + g.changesOmitted, 0);
  return `${c.oid.slice(0, 10)}  ${printable(c.subject)}  [${c.parents.length > 1 ? "merge, " : ""}${total} changes${c.availability === "full" ? "" : `, ${c.availability}`}]`;
};

export async function historyCommand(io: Io, context: CliContext, json: boolean, since: string | undefined, limit: number | undefined): Promise<void> {
  const store = await Store.openReadOnly({ root: context.root, git: context.git, hardenedGit: context.hardenedGit, installId: context.installId });
  try {
    const sinceOid = since === undefined || since === "last-refresh" ? since : await resolveCommitArg(context, since);
    const result = changesSince(store.db, { ...(sinceOid === undefined ? {} : { since: sinceOid }), ...(limit === undefined ? {} : { limit }) });
    const lines = [
      `relation ${result.relation}  checkpoint ${result.checkpointOid?.slice(0, 10) ?? "-"}  ${result.note}`,
      ...result.commits.map(describe),
      ...(result.truncated ? ["(older commits omitted: use --limit)"] : []),
      "commit subjects are untrusted text from the repository"
    ];
    printJsonOrText(io, json, { history: result }, lines.join("\n"));
  } finally {
    store.close();
  }
}

export async function changesCommand(io: Io, context: CliContext, json: boolean, commit: string): Promise<void> {
  const oid = await resolveCommitArg(context, commit);
  const store = await Store.openReadOnly({ root: context.root, git: context.git, hardenedGit: context.hardenedGit, installId: context.installId });
  try {
    const result = commitChanges(store.db, oid);
    if (result === null) {
      throw new EngbrainError("NOT_INITIALIZED", "that commit is not in the ledger: run `engbrain refresh` (or `refresh --history=backfill`)");
    }
    const lines = [describe(result)];
    for (const group of result.changesByParent) {
      lines.push(`parent ${group.parentOrdinal < 0 ? "(none: root)" : group.parentOrdinal}`);
      for (const c of group.changes) {
        lines.push(`  ${c.kind.padEnd(11)} ${printable(c.oldPath === null ? c.path : `${c.oldPath} -> ${c.path}`)}${c.renameScore === null ? "" : `  (${c.renameScore}%)`}${c.excludedReason === null ? "" : `  [${c.excludedReason}]`}`);
      }
      if (group.changesOmitted > 0) {
        lines.push(`  ... ${group.changesOmitted} more`);
      }
    }
    for (const d of result.symbolDeltas) {
      lines.push(`  symbol ${d.delta.padEnd(17)} ${printable(d.qualifiedName)}${d.candidateRenameOf === null ? "" : `  (rename CANDIDATE of ${printable(d.candidateRenameOf)})`}`);
    }
    printJsonOrText(io, json, { commit: result }, lines.join("\n"));
  } finally {
    store.close();
  }
}
