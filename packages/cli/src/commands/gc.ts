import { AuditLog, acquireWriterLock, collectGarbage, markAbandoned, Store } from "@engbrain/core";
import type { CliContext } from "../context.js";
import { printJsonOrText, type Io } from "../output.js";

export async function gcCommand(io: Io, context: CliContext, json: boolean, keepOverride: number | null): Promise<void> {
  const store = await Store.open({ root: context.root, git: context.git, hardenedGit: context.hardenedGit, installId: context.installId });
  try {
    const config = store.config();
    const lock = await acquireWriterLock(store.dir);
    try {
      markAbandoned(store.db);
      const result = collectGarbage(store.db, keepOverride ?? config.generationsToKeep);
      new AuditLog(
        store.dir, context.installId,
        { maxFileBytes: config.auditMaxFileBytes, maxFiles: config.auditMaxFiles, retentionDays: config.auditRetentionDays }
      ).record("gc", { generationsRemoved: result.generationsRemoved, factsRemoved: result.factsRemoved });
      printJsonOrText(io, json, { ...result }, `Removed ${result.generationsRemoved} generations and ${result.factsRemoved} unreferenced facts`);
    } finally {
      lock.release();
    }
  } finally {
    store.close();
  }
}
