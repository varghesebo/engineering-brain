import { AuditLog, indexRepository, Store } from "@engbrain/core";
import type { CliContext } from "../context.js";
import { printJsonOrText, type Io } from "../output.js";

export async function indexCommand(io: Io, context: CliContext, json: boolean): Promise<void> {
  const store = await Store.open({ root: context.root, git: context.git, hardenedGit: context.hardenedGit, installId: context.installId });
  try {
    const config = store.config();
    const audit = new AuditLog(
      store.dir, context.installId,
      { maxFileBytes: config.auditMaxFileBytes, maxFiles: config.auditMaxFiles, retentionDays: config.auditRetentionDays }
    );
    const result = await indexRepository({ store, git: context.git, hardenedGit: context.hardenedGit, audit });
    const { stats } = result;
    if (store.historyChanged) {
      io.stderr("note: repository history changed since init (root commits rewritten, or a different repository is at this path)\n");
    }
    const headline = result.unchanged ? "No changes; kept generation" : "Published generation";
    const reasons = Object.entries(stats.excludedByReason).map(([reason, count]) => `${reason}=${count}`).join(" ");
    printJsonOrText(
      io, json,
      { generationId: result.generationId, unchanged: result.unchanged, revision: result.revision, sourceFingerprint: result.sourceFingerprint, stats },
      `${headline} ${result.generationId}\n` +
        `  files: ${stats.included} included, ${stats.excluded} excluded${reasons === "" ? "" : ` (${reasons})`}, ${stats.missing} missing\n` +
        `  extractor runs: ${stats.extractorRuns}, facts reused: ${stats.factsReused}\n` +
        `  fingerprint: ${result.sourceFingerprint}\n  took ${stats.durationMs} ms`
    );
  } finally {
    store.close();
  }
}
